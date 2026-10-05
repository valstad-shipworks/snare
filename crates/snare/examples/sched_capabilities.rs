//! Show how the same scheduling code behaves on a privileged versus an unprivileged host, without
//! ever needing real privileges. The sim gates SCHED_FIFO on CAP_SYS_NICE and mlockall on
//! CAP_IPC_LOCK exactly as the kernel does (man 7 capabilities, man 2 sched_setscheduler,
//! man 2 mlockall), so a program's EPERM-handling path can be exercised deterministically.
//!
//! Run with: cargo run -p snare --example sched_capabilities

fn main() {
    #[cfg(target_os = "linux")]
    linux_demo();
    #[cfg(not(target_os = "linux"))]
    println!("sched_capabilities: capability gating is modelled on Linux only");
}

#[cfg(target_os = "linux")]
fn linux_demo() {
    use snare::{EasyBuilder, Sim};

    fn try_realtime() -> (bool, i32, bool, i32) {
        let tid = unsafe { libc::gettid() } as i64;
        let param = libc::sched_param { sched_priority: 80 };
        let fifo = unsafe {
            libc::syscall(
                libc::SYS_sched_setscheduler,
                tid,
                libc::SCHED_FIFO,
                &param as *const libc::sched_param,
            )
        };
        let fifo_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let lock = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        let lock_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        (fifo == 0, fifo_errno, lock == 0, lock_errno)
    }

    for (label, host) in [
        ("privileged ", EasyBuilder::realtime().build()),
        ("unprivileged", EasyBuilder::unprivileged().build()),
    ] {
        Sim::builder().host(host).build().run(|| {
            let (fifo_ok, fifo_errno, lock_ok, lock_errno) = try_realtime();
            let fifo = if fifo_ok {
                "ok".to_string()
            } else {
                format!("errno {fifo_errno}")
            };
            let lock = if lock_ok {
                "ok".to_string()
            } else {
                format!("errno {lock_errno}")
            };
            println!("{label}: SCHED_FIFO={fifo}  mlockall={lock}");
        });
    }
}
