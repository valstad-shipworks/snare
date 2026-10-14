//! The `SimHost` tracefs: instances, synthetic events, hist triggers with the kernel's
//! registration rules, timerlat with a user-space reader on the sim's clock, osnoise samples
//! on a pipe, and the faults a careless teardown raises.
#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use snare::{EasyBuilder, HostProfile, Sim, SimHost, Tracefs, TracefsFault};

const T: &str = "/sys/kernel/tracing";

fn host() -> Arc<SimHost> {
    EasyBuilder::realtime().profile().root(true).build()
}

fn write(path: &str, value: &str) -> std::io::Result<()> {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
}

fn errno(r: std::io::Result<()>) -> i32 {
    r.unwrap_err().raw_os_error().unwrap()
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn no_tracefs_without_the_feature() {
    let host = HostProfile::new().root(true).build();
    Sim::builder().host(host).build().run(|| {
        let e = fs::read_to_string(format!("{T}/available_tracers")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
        assert_eq!(
            fs::create_dir(format!("{T}/instances/x"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    });
}

#[test]
fn unprivileged_reads_but_cannot_write() {
    let host = EasyBuilder::realtime().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            read(&format!("{T}/available_tracers")),
            "timerlat osnoise function nop\n"
        );
        assert_eq!(errno(write(&format!("{T}/tracing_on"), "0")), libc::EACCES);
        assert_eq!(
            unsafe { libc::access(c"/sys/kernel/tracing/tracing_on".as_ptr(), libc::W_OK) },
            -1
        );
        assert_eq!(
            fs::create_dir(format!("{T}/instances/x"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    });
}

#[test]
fn instances_triggers_and_synthetic_events_follow_the_kernel_rules() {
    let host = host();
    let tracefs = host.tracefs().unwrap();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::access(c"/sys/kernel/tracing/tracing_on".as_ptr(), libc::W_OK) }, 0);
        let inst = format!("{T}/instances/noise");
        fs::create_dir(&inst).unwrap();
        assert_eq!(fs::create_dir(&inst).unwrap_err().raw_os_error(), Some(libc::EEXIST));
        assert_eq!(tracefs.instances(), ["noise"]);
        assert!(fs::read_dir(format!("{T}/instances")).unwrap().count() == 1);

        write(&format!("{inst}/tracing_on"), "0").unwrap();
        write(&format!("{inst}/trace_clock"), "mono").unwrap();
        assert!(read(&format!("{inst}/trace_clock")).contains("[mono]"));
        assert_eq!(errno(write(&format!("{inst}/trace_clock"), "sundial")), libc::EINVAL);
        write(&format!("{inst}/tracing_cpumask"), "6").unwrap();
        assert_eq!(read(&format!("{inst}/tracing_cpumask")), "6\n");
        write(&format!("{inst}/buffer_size_kb"), "2048").unwrap();
        assert_eq!(read(&format!("{inst}/buffer_size_kb")), "2048\n");
        assert_eq!(errno(write(&format!("{inst}/current_tracer"), "hwlat")), libc::EINVAL);

        let synth = format!("{T}/synthetic_events");
        write(&synth, "n_irq_duration u64 lat; int irq; unsigned int cpu").unwrap();
        assert_eq!(errno(write(&synth, "n_irq_duration u64 lat; int irq; unsigned int cpu")), libc::EEXIST);
        assert_eq!(errno(write(&synth, "bad u128 x")), libc::EINVAL);
        assert_eq!(tracefs.synthetic_events(), ["n_irq_duration"]);
        assert!(fs::read_dir(format!("{T}/events/synthetic")).unwrap().any(|e| e.unwrap().file_name() == "n_irq_duration"));

        let entry = format!("{inst}/events/irq/irq_handler_entry/trigger");
        let exit = format!("{inst}/events/irq/irq_handler_exit/trigger");
        let synth_hist = format!("{inst}/events/synthetic/n_irq_duration/trigger");
        assert_eq!(errno(write(&entry, "hist:keys=common_cpu,bogus:irqts=common_timestamp")), libc::EINVAL);
        assert!(tracefs.error_log().last().unwrap().contains("Couldn't find field: bogus"));
        write(&entry, "hist:keys=common_cpu,irq:irqts=common_timestamp if common_cpu==1||common_cpu==2").unwrap();
        assert_eq!(errno(write(&entry, "hist:keys=common_cpu,irq:irqts=common_timestamp if common_cpu==1||common_cpu==2")), libc::EEXIST);
        assert_eq!(
            errno(write(&exit, "hist:keys=common_cpu,irq:irqlat=common_timestamp-$nosuch:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,irq,common_cpu)")),
            libc::EINVAL
        );
        assert_eq!(
            errno(write(&exit, "hist:keys=common_cpu,irq:irqlat=common_timestamp-$irqts:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,irq)")),
            libc::EINVAL
        );
        assert!(tracefs.error_log().last().unwrap().contains("Param count mismatch"));
        assert_eq!(
            errno(write(&exit, "hist:keys=common_cpu,irq:irqlat=common_timestamp-$irqts:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,common_cpu,irq)")),
            libc::EINVAL
        );
        assert!(tracefs.error_log().last().unwrap().contains("type doesn't match"));
        write(&exit, "hist:keys=common_cpu,irq:irqlat=common_timestamp-$irqts:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,irq,common_cpu) if common_cpu==1||common_cpu==2").unwrap();
        write(&synth_hist, "hist:keys=cpu,irq,lat.log2:vals=hitcount").unwrap();
        let listing = read(&exit);
        assert!(listing.starts_with("# Available triggers:\n"), "{listing}");
        assert!(listing.contains("hist:keys=common_cpu,irq:vals=hitcount:irqlat=common_timestamp-$irqts:sort=hitcount:size=2048:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,irq,common_cpu) if common_cpu==1||common_cpu==2 [active]"), "{listing}");

        let softirq_entry = format!("{inst}/events/irq/softirq_entry/trigger");
        write(&softirq_entry, "hist:keys=common_cpu,vec:irqts=common_timestamp").unwrap();
        let waking = format!("{inst}/events/sched/sched_waking/trigger");
        assert_eq!(errno(write(&waking, "hist:keys=pid:lat=common_timestamp-$irqts")), libc::EINVAL);
        assert!(tracefs.error_log().last().unwrap().contains("not unique"));
        write(&softirq_entry, "!hist:keys=common_cpu,vec:irqts=common_timestamp").unwrap();

        tracefs.inject("irq/irq_handler_exit", &[("cpu", "1"), ("irq", "133"), ("irqlat", "4000")]);
        tracefs.inject("irq/irq_handler_exit", &[("cpu", "1"), ("irq", "133"), ("irqlat", "4096")]);
        tracefs.inject("irq/irq_handler_exit", &[("cpu", "5"), ("irq", "133"), ("irqlat", "4096")]);
        let hist = read(&format!("{inst}/events/synthetic/n_irq_duration/hist"));
        assert!(hist.contains("# trigger info: hist:keys=cpu,irq,lat.log2:vals=hitcount:sort=hitcount:size=2048 [active]"), "{hist}");
        assert!(hist.contains("{ cpu:          1, irq:        133, lat: ~ 2^12 } hitcount:          2"), "{hist}");
        assert!(hist.contains("Hits: 2\n    Entries: 1\n    Dropped: 0"), "{hist}");
        assert!(!hist.contains("cpu:          5"), "{hist}");

        assert_eq!(errno(write(&entry, "!hist:keys=common_cpu,irq:irqts=common_timestamp if common_cpu==1||common_cpu==2")), libc::EINVAL);
        assert_eq!(errno(write(&synth, "!n_irq_duration")), libc::EBUSY);
        assert_eq!(fs::remove_dir(&inst).unwrap_err().raw_os_error(), Some(libc::EBUSY));
        assert_eq!(tracefs.faults(), [TracefsFault::RemoveWithTriggers { instance: "noise".into() }]);

        write(&synth_hist, "!hist:keys=cpu,irq,lat.log2:vals=hitcount").unwrap();
        write(&exit, "!hist:keys=common_cpu,irq:irqlat=common_timestamp-$irqts:onmatch(irq.irq_handler_entry).trace(n_irq_duration,$irqlat,irq,common_cpu) if common_cpu==1||common_cpu==2").unwrap();
        write(&entry, "!hist:keys=common_cpu,irq:irqts=common_timestamp if common_cpu==1||common_cpu==2").unwrap();
        assert_eq!(errno(write(&entry, "!hist:keys=common_cpu,irq:irqts=common_timestamp if common_cpu==1||common_cpu==2")), libc::ENOENT);
        write(&synth, "!n_irq_duration").unwrap();
        assert!(tracefs.synthetic_events().is_empty());

        write(&entry, "hist:keys=irq").unwrap();
        fs::write(&entry, "hist:keys=common_cpu").unwrap();
        assert_eq!(tracefs.triggers("noise", "irq/irq_handler_entry"), ["hist:keys=common_cpu:vals=hitcount:sort=hitcount:size=2048"]);
        fs::write(&entry, "").unwrap();
        assert!(tracefs.triggers("noise", "irq/irq_handler_entry").is_empty());
        fs::remove_dir(&inst).unwrap();
        assert!(tracefs.instances().is_empty());
    });
}

#[test]
fn wakeup_snapshot_and_context_events() {
    let host = host();
    let tracefs = host.tracefs().unwrap();
    Sim::builder().host(host).build().run(|| {
        let inst = format!("{T}/instances/w");
        fs::create_dir(&inst).unwrap();
        write(&format!("{T}/synthetic_events"), "w_wake u64 lat; pid_t pid; unsigned int cpu; char comm[16]").unwrap();
        write(&format!("{inst}/events/sched/sched_waking/trigger"), "hist:keys=pid,comm:wakets=common_timestamp if comm==\"stmo\"").unwrap();
        write(
            &format!("{inst}/events/sched/sched_switch/trigger"),
            "hist:keys=next_pid,next_comm:wakelat=common_timestamp-$wakets:onmatch(sched.sched_waking).trace(w_wake,$wakelat,next_pid,common_cpu,next_comm):onmax($wakelat).snapshot() if next_comm==\"stmo\"",
        )
        .unwrap();
        write(&format!("{inst}/events/synthetic/w_wake/trigger"), "hist:keys=cpu,comm,lat.log2:vals=hitcount").unwrap();
        write(&format!("{inst}/events/sched/sched_switch/filter"), "common_cpu==1").unwrap();
        write(&format!("{inst}/events/sched/sched_switch/enable"), "1").unwrap();
        assert_eq!(tracefs.enabled_events("w"), ["sched/sched_switch"]);

        tracefs.inject("sched/sched_switch", &[("cpu", "1"), ("prev_comm", "swapper/1"), ("next_comm", "stmo"), ("next_pid", "77"), ("wakelat", "30000")]);
        tracefs.inject("sched/sched_switch", &[("cpu", "2"), ("prev_comm", "x"), ("next_comm", "other"), ("next_pid", "78"), ("wakelat", "1")]);
        tracefs.inject("sched/sched_switch", &[("cpu", "1"), ("prev_comm", "swapper/1"), ("next_comm", "stmo"), ("next_pid", "77"), ("wakelat", "52000")]);
        let hist = read(&format!("{inst}/events/sched/sched_switch/hist"));
        assert!(hist.contains("{ next_pid:         77, next_comm: stmo"), "{hist}");
        assert!(hist.contains("hitcount:          2"), "{hist}");
        assert!(hist.contains("Snapshot taken (see tracing/snapshot).  Details:\n\ttriggering value { onmax($wakelat) }:      52000\n\ttriggered by event with key: { next_pid: 77, next_comm: stmo }"), "{hist}");
        let wake = read(&format!("{inst}/events/synthetic/w_wake/hist"));
        assert!(wake.contains("{ cpu:          1, comm: stmo"), "{wake}");
        assert!(wake.contains("lat: ~ 2^15 } hitcount:          1"), "{wake}");
        assert!(wake.contains("lat: ~ 2^16 } hitcount:          1"), "{wake}");
        let snapshot = read(&format!("{inst}/snapshot"));
        let lines: Vec<&str> = snapshot.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines.len(), 2, "{snapshot}");
        assert!(lines[1].contains("[001]") && lines[1].contains("sched_switch: next_comm=stmo next_pid=77"), "{snapshot}");
        write(&format!("{inst}/snapshot"), "2").unwrap();
        assert!(read(&format!("{inst}/snapshot")).lines().all(|l| l.starts_with('#')));
        let trace = read(&format!("{inst}/trace"));
        assert_eq!(trace.lines().filter(|l| !l.starts_with('#')).count(), 2);

        fs::write(format!("{inst}/events/synthetic/w_wake/trigger"), "").unwrap();
        fs::write(format!("{inst}/events/sched/sched_switch/trigger"), "").unwrap();
        fs::write(format!("{inst}/events/sched/sched_waking/trigger"), "").unwrap();
        write(&format!("{inst}/events/sched/sched_switch/enable"), "0").unwrap();
        write(&format!("{T}/synthetic_events"), "!w_wake").unwrap();
        fs::remove_dir(&inst).unwrap();
        assert!(tracefs.faults().is_empty());
    });
}

fn pin(cpu: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set),
            0
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cpu;
}

fn poll_in(fd: i32, ms: i32) -> i32 {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut p, 1, ms) };
    if rc > 0 { p.revents as i32 } else { rc }
}

fn drain(f: &mut fs::File) -> Vec<String> {
    let mut buf = [0u8; 8192];
    let mut out = Vec::new();
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    String::from_utf8_lossy(&out)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn timerlat_with_a_user_reader_samples_on_the_clock() {
    let host = host();
    let tracefs = host.tracefs().unwrap();
    Sim::builder().host(host).build().run(|| {
        let inst = format!("{T}/instances/tl");
        fs::create_dir(&inst).unwrap();
        let fd_path = format!("{T}/osnoise/per_cpu/cpu3/timerlat_fd");
        assert_eq!(fs::File::open(&fd_path).unwrap_err().raw_os_error(), Some(libc::EINVAL));
        write(&format!("{T}/osnoise/options"), "NO_OSNOISE_WORKLOAD").unwrap();
        assert_eq!(tracefs.osnoise("options"), "DEFAULTS NO_OSNOISE_WORKLOAD NO_PANIC_ON_STOP NO_OSNOISE_PREEMPT_DISABLE NO_OSNOISE_IRQ_DISABLE");
        assert_eq!(errno(write(&format!("{T}/osnoise/options"), "FLUX_CAPACITOR")), libc::EINVAL);
        write(&format!("{T}/osnoise/cpus"), "3-4").unwrap();
        assert_eq!(tracefs.osnoise("cpus"), "3-4");
        assert_eq!(errno(write(&format!("{T}/osnoise/cpus"), "3-99")), libc::EINVAL);
        write(&format!("{T}/osnoise/timerlat_period_us"), "1000").unwrap();
        write(&format!("{T}/osnoise/stop_tracing_total_us"), "20").unwrap();
        write(&format!("{T}/osnoise/print_stack"), "20").unwrap();
        write(&format!("{inst}/current_tracer"), "timerlat").unwrap();
        assert_eq!(tracefs.tracer("tl").as_deref(), Some("timerlat"));

        let mut pipe = fs::File::open(format!("{inst}/per_cpu/cpu3/trace_pipe")).unwrap();
        let pfd = pipe.as_raw_fd();
        unsafe { libc::fcntl(pfd, libc::F_SETFL, libc::fcntl(pfd, libc::F_GETFL) | libc::O_NONBLOCK) };
        assert_eq!(poll_in(pfd, 50), 0, "empty pipe times out on the clock");
        assert!(drain(&mut pipe).is_empty());

        #[cfg(target_os = "linux")]
        assert_eq!(fs::File::open(&fd_path).unwrap_err().raw_os_error(), Some(libc::EPERM));
        pin(3);
        let mut fd = fs::File::open(&fd_path).unwrap();
        assert_eq!(fs::File::open(&fd_path).unwrap_err().raw_os_error(), Some(libc::EBUSY));
        assert_eq!(tracefs.timerlat_readers(), [3]);
        tracefs.set_timerlat(3, 1500, 9000, 12000);
        let t0 = Instant::now();
        let mut byte = [0u8; 1];
        assert_eq!(fd.read(&mut byte).unwrap(), 0);
        let slept = t0.elapsed();
        assert!(slept >= Duration::from_millis(1) && slept < Duration::from_millis(2), "one period of virtual time: {slept:?}");
        assert_eq!(poll_in(pfd, 50) & libc::POLLIN as i32, libc::POLLIN as i32);
        let lines = drain(&mut pipe);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("[003]") && lines[0].contains("#1     context    irq timer_latency      1500 ns"), "{}", lines[0]);
        assert!(lines[1].starts_with("     timerlatu/3-1003") && lines[1].contains("context thread timer_latency      9000 ns"), "{}", lines[1]);
        assert!(lines[2].contains("context user-ret timer_latency     12000 ns"), "{}", lines[2]);

        tracefs.set_timerlat(3, 1500, 25_000, 30_000);
        assert_eq!(fd.read(&mut byte).unwrap(), 0);
        let lines = drain(&mut pipe);
        assert!(lines.iter().any(|l| l.contains("<stack trace>")), "{lines:?}");
        assert!(lines.last().unwrap().contains("stop tracing hit on cpu 3"), "{lines:?}");
        assert_eq!(tracefs.tracing_on("tl"), Some(false));
        assert_eq!(read(&format!("{inst}/tracing_on")), "0\n");
        assert_eq!(fd.read(&mut byte).unwrap(), 0);
        assert!(drain(&mut pipe).is_empty(), "nothing recorded while off");
        write(&format!("{inst}/tracing_on"), "1").unwrap();
        tracefs.set_timerlat(3, 1500, 9000, 12000);
        assert_eq!(fd.read(&mut byte).unwrap(), 0);
        assert_eq!(drain(&mut pipe).len(), 3);

        assert_eq!(fs::remove_dir(&inst).unwrap_err().raw_os_error(), Some(libc::EBUSY), "pipe still open");
        drop(pipe);
        write(&format!("{inst}/current_tracer"), "nop").unwrap();
        assert_eq!(
            tracefs.faults(),
            [TracefsFault::TracerStoppedWithReader { instance: "tl".into(), cpu: 3 }]
        );
        assert_eq!(fd.read(&mut byte).unwrap_err().raw_os_error(), Some(libc::EINTR));
        drop(fd);
        assert!(tracefs.timerlat_readers().is_empty());
        fs::remove_dir(&inst).unwrap();
    });
}

#[test]
fn osnoise_samples_arrive_per_period_of_virtual_time() {
    let host = host();
    let tracefs = host.tracefs().unwrap();
    Sim::builder().host(host).build().run(|| {
        let inst = format!("{T}/instances/hw");
        fs::create_dir(&inst).unwrap();
        write(&format!("{T}/osnoise/options"), "DEFAULTS").unwrap();
        write(&format!("{T}/osnoise/options"), "OSNOISE_IRQ_DISABLE").unwrap();
        write(&format!("{T}/osnoise/cpus"), "2").unwrap();
        write(&format!("{T}/osnoise/period_us"), "1000000").unwrap();
        write(&format!("{T}/osnoise/runtime_us"), "1000000").unwrap();
        tracefs.set_osnoise(2, 7, 4, 1, 0);
        write(&format!("{inst}/current_tracer"), "osnoise").unwrap();
        let mut pipe = fs::File::open(format!("{inst}/trace_pipe")).unwrap();
        let pfd = pipe.as_raw_fd();
        unsafe {
            libc::fcntl(
                pfd,
                libc::F_SETFL,
                libc::fcntl(pfd, libc::F_GETFL) | libc::O_NONBLOCK,
            )
        };
        let t0 = Instant::now();
        assert_eq!(poll_in(pfd, 3500), 0);
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(3500) && waited < Duration::from_millis(3600),
            "{waited:?}"
        );
        let lines = drain(&mut pipe);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines[0].contains("osnoise/2-2002") && lines[0].contains("[002]"),
            "{}",
            lines[0]
        );
        let body = lines[0].split_once(": ").unwrap().1;
        let cols: Vec<&str> = body.split_whitespace().collect();
        assert_eq!(&cols[..2], ["1000000", "7"]);
        assert_eq!(&cols[3..6], ["4", "1", "0"]);
        drop(pipe);
        write(&format!("{inst}/current_tracer"), "nop").unwrap();
        fs::remove_dir(&inst).unwrap();
        assert!(tracefs.faults().is_empty());
    });
}

#[test]
fn a_kernel_without_the_tracers_says_so() {
    let host = EasyBuilder::realtime()
        .profile()
        .root(true)
        .tracefs(Some(
            Tracefs::full()
                .without_tracer("timerlat")
                .without_tracer("osnoise")
                .synthetic_events(false)
                .snapshot(false),
        ))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read(&format!("{T}/available_tracers")), "function nop\n");
        assert_eq!(
            fs::metadata(format!("{T}/osnoise"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            fs::metadata(format!("{T}/synthetic_events"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            fs::metadata(format!("{T}/snapshot"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert!(fs::metadata(format!("{T}/events/sched/sched_switch/hist")).is_ok());
        let inst = format!("{T}/instances/x");
        fs::create_dir(&inst).unwrap();
        assert_eq!(
            errno(write(&format!("{inst}/current_tracer"), "timerlat")),
            libc::EINVAL
        );
        assert_eq!(
            errno(write(
                &format!("{inst}/events/sched/sched_switch/trigger"),
                "hist:keys=next_pid:lat=common_timestamp:onmax($lat).snapshot()"
            )),
            libc::EINVAL
        );
        fs::remove_dir(&inst).unwrap();
    });
}
