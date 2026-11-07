//! A `SimHost`'s per-thread procfs: `/proc/self/task` lists each simulated thread still running
//! by its simulated tid (man 5 proc_pid_task), and `/proc/<tid>/comm` and
//! `/proc/self/task/<tid>/comm` hold the name it gave itself, else its creator's (man 5
//! proc_pid_comm), so code that walks its own threads sees the sim's.
#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

fn tasks() -> Vec<i32> {
    let mut tids: Vec<i32> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
        .collect();
    tids.sort();
    tids
}

fn comm(path: String) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn each_running_thread_is_listed_with_its_name() {
    let sim = Sim::builder()
        .host(HostProfile::new().cpus(2).build())
        .build();
    sim.run(|| {
        let root = unsafe { libc::gettid() };
        let (started, finish) = std::sync::mpsc::channel::<()>();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("sim-worker".to_string())
            .spawn(move || {
                tid_tx.send(unsafe { libc::gettid() }).unwrap();
                let _ = finish.recv();
            })
            .unwrap();
        let tid = tid_rx.recv().unwrap();

        assert!(tasks().contains(&root));
        assert!(tasks().contains(&tid));
        assert_eq!(comm(format!("/proc/{tid}/comm")), "sim-worker\n");
        assert_eq!(comm(format!("/proc/self/task/{tid}/comm")), "sim-worker\n");

        drop(started);
        worker.join().unwrap();
        assert!(
            !tasks().contains(&tid),
            "an exited thread is no longer listed"
        );
        assert!(tasks().contains(&root));
    });
}
