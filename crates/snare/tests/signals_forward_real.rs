//! `SimBuilder::forward_real_signals`, checked by querying dispositions, never by signalling the
//! test process for real.

use snare::Sim;

#[cfg(unix)]
fn real_sigint() -> libc::sigaction {
    // SAFETY: a query only fills `old`.
    snare::real(|| unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old);
        old
    })
}

#[cfg(unix)]
#[test]
fn forward_real_signals() {
    let before = real_sigint();
    let a = Sim::builder().forward_real_signals().build();
    let forwarding = real_sigint();
    assert_ne!(
        forwarding.sa_sigaction, before.sa_sigaction,
        "a forwarder is installed"
    );
    assert_eq!(forwarding.sa_flags & libc::SA_SIGINFO, libc::SA_SIGINFO);
    let b = Sim::builder().forward_real_signals().build();
    let seen = b.run(|| {
        // SAFETY: as above, inside the sim.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old);
            old
        }
    });
    assert_eq!(
        seen.sa_sigaction, before.sa_sigaction,
        "a sim sees the process's own action"
    );
    drop(a);
    assert_eq!(
        real_sigint().sa_sigaction,
        forwarding.sa_sigaction,
        "still forwarding for b"
    );
    drop(b);
    let after = real_sigint();
    assert_eq!(
        after.sa_sigaction, before.sa_sigaction,
        "restored by the last sim"
    );
    assert_eq!(
        after.sa_flags & !SA_RESTORER,
        before.sa_flags & !SA_RESTORER
    );
}

/// glibc sets `SA_RESTORER` (<asm/signal.h>) on every action it installs on x86 and x86-64, so a
/// restored default carries it where the inherited one did not.
#[cfg(unix)]
const SA_RESTORER: libc::c_int = if cfg!(all(
    target_os = "linux",
    any(target_arch = "x86", target_arch = "x86_64")
)) {
    0x0400_0000
} else {
    0
};

#[cfg(windows)]
#[test]
fn forward_real_signals() {
    let a = Sim::builder().forward_real_signals().build();
    let b = Sim::builder().forward_real_signals().build();
    drop(a);
    drop(b);
    let c = Sim::builder().forward_real_signals().build();
    assert_eq!(
        c.raise_signal(snare::Signal::Interrupt),
        snare::SignalDelivery::DefaultAction
    );
}
