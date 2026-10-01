//! Bring a thread up to real-time configuration entirely inside the sim — no privileges, no real
//! scheduler touched. On Linux this is the canonical latency-hygiene sequence: lock memory
//! (man 2 mlockall), switch to SCHED_FIFO (man 2 sched_setscheduler), and pin to an isolated CPU
//! (man 2 sched_setaffinity). On macOS the equivalent is a pthread SCHED_FIFO band
//! (man 3 pthread_setschedparam). Either way it prints one line describing what took effect.
//!
//! Run with: cargo run -p snare --example sched_realtime_thread

fn main() {
    #[cfg(target_os = "linux")]
    linux_demo();
    #[cfg(target_os = "macos")]
    macos_demo();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("sched_realtime_thread: no host scheduling model for this OS");
}

#[cfg(target_os = "linux")]
fn linux_demo() {
    use snare::{EasyBuilder, Sim};

    Sim::builder()
        .host(EasyBuilder::realtime().build())
        .build()
        .run(|| {
            // man 2 mlockall: keep every page resident so no fault ever stalls the RT loop.
            let locked = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0;

            let tid = unsafe { libc::gettid() };
            // man 2 sched_setscheduler via the raw syscall (what a musl binary reaches).
            let param = libc::sched_param { sched_priority: 80 };
            let policy_ok = unsafe {
                libc::syscall(
                    libc::SYS_sched_setscheduler,
                    tid as i64,
                    libc::SCHED_FIFO,
                    &param as *const libc::sched_param,
                )
            } == 0;

            // man 2 sched_setaffinity: pin onto CPU 3, which the realtime preset isolates.
            let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::CPU_ZERO(&mut set);
                libc::CPU_SET(3, &mut set);
            }
            let pinned =
                unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set) }
                    == 0;

            let policy = unsafe { libc::sched_getscheduler(tid) };
            println!(
                "tid {tid}: mlockall={locked} SCHED_FIFO@80={policy_ok} pinned_cpu3={pinned} \
                 policy_readback={policy}"
            );
        });
}

#[cfg(target_os = "macos")]
fn macos_demo() {
    use snare::{HostProfile, Sim};

    Sim::builder()
        .host(HostProfile::new().build())
        .build()
        .run(|| {
            // man 3 pthread_setschedparam: the portable way to request a SCHED_FIFO band; the sim
            // records it deterministically instead of asking the Mach scheduler.
            let me = unsafe { libc::pthread_self() };
            let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
            param.sched_priority = 42;
            let set_ok = unsafe { libc::pthread_setschedparam(me, libc::SCHED_FIFO, &param) } == 0;

            let mut policy: libc::c_int = -1;
            let mut got: libc::sched_param = unsafe { std::mem::zeroed() };
            unsafe { libc::pthread_getschedparam(me, &mut policy, &mut got) };
            println!(
                "pthread SCHED_FIFO set={set_ok} policy_readback={policy} priority={}",
                got.sched_priority
            );
        });
}
