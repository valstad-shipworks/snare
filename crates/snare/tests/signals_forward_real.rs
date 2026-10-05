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
    assert_eq!(after.sa_flags, before.sa_flags);
}

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
