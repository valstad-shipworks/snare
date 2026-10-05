//! fast-talker's hooks under `--cfg snare_global`: once the harness has
//! configured snare, the code under test's `sys_check` and `Counters::read`
//! answer from the simulated host even if it never opened a snare socket.
//! Empty unless the cfg is set. Run with:
//!
//! ```sh
//! RUSTFLAGS='--cfg snare_global' cargo test --features shim,fast-talker-compat --test ft_global
//! ```
#![cfg(all(snare_global, feature = "shim"))]

use snare::fast_talker::counters::Counters;
use snare::fast_talker::sim;
use snare::fast_talker::sys_check::{Check, Status, sys_check};

#[test]
fn harness_setup_routes_fast_talker_to_the_simulated_host() {
    snare::set_privileges(|p| p.root = false);
    let code_under_test = std::thread::spawn(|| {
        let findings = sys_check(&[Check::Elevated]);
        let counters = Counters::read().unwrap();
        (findings, counters)
    });
    let (findings, counters) = code_under_test.join().unwrap();
    assert!(matches!(findings[0].status, Status::Fail { .. }));
    assert_eq!(sim::sys_checks().len(), 1);
    assert!(counters.get("UdpOutDatagrams").is_some());
}
