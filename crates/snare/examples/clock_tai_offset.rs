//! CLOCK_TAI leads CLOCK_REALTIME by the kernel's TAI-UTC offset (37s today), the clock
//! `SO_TXTIME` launch times are expressed on. The sim makes the offset a host fact. man 2
//! clock_gettime documents CLOCK_TAI (value 11, <linux/time.h>).
//!
//! Run with: cargo run -p snare --example clock_tai_offset

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Sim};

    fn secs(clk: libc::clockid_t) -> libc::time_t {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(clk, &mut ts) };
        ts.tv_sec
    }

    let host = HostProfile::new().tai_offset(37).build();
    let sim = Sim::builder().host(host).build();
    sim.run(|| {
        let realtime = secs(libc::CLOCK_REALTIME);
        let tai = secs(libc::CLOCK_TAI);
        println!("CLOCK_TAI leads CLOCK_REALTIME by {}s", tai - realtime);
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("clock_tai_offset is a Linux-only example (CLOCK_TAI)");
}
