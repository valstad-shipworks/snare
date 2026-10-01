//! Holding `/dev/cpu_dma_latency` open with a 0µs target is how a real-time program stops the CPU
//! entering deep idle states that add wakeup latency. The sim serves the device in-process, so no
//! root and no real hardware are needed. See Documentation/admin-guide/pm/cpuidle.rst and
//! Documentation/power/pm_qos_interface.rst.
//!
//! Run with: cargo run -p snare --example clock_cpu_dma_latency

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Sim};

    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host).build();
    sim.run(|| {
        let fd = unsafe { libc::open(c"/dev/cpu_dma_latency".as_ptr(), libc::O_WRONLY) };
        assert!(fd >= 0, "the sim exposes the PM QoS device");
        let target: i32 = 0;
        let n = unsafe {
            libc::write(fd, (&target as *const i32).cast(), std::mem::size_of::<i32>())
        };
        println!("requested a {target}µs CPU DMA latency cap ({n} bytes written); holding fd open");
        // Closing the fd releases the constraint, as the kernel does on the last writer's close.
        unsafe { libc::close(fd) };
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("clock_cpu_dma_latency is a Linux-only example (/dev/cpu_dma_latency)");
}
