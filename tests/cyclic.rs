use std::{
    net::SocketAddr,
    sync::{atomic::{AtomicUsize, Ordering}, LazyLock, Mutex},
    time::{Duration, Instant},
};

use snare::*;

#[derive(Clone, Debug)]
struct DummyPacket(Vec<u8>);

impl Packetable for DummyPacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        Some((Self(data.to_vec()), data.len()))
    }
}

#[derive(Default)]
struct CyclicState {
    last_fire: Option<Instant>,
}

static FIRING_DELTAS: LazyLock<Mutex<Vec<Duration>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
static CYCLE_COUNT: LazyLock<AtomicUsize> =
    LazyLock::new(|| AtomicUsize::new(0));

fn record_cycle(state: &mut CyclicState) -> Option<TesterAction<DummyPacket>> {
    let now = Instant::now();
    if let Some(previous) = state.last_fire.replace(now) {
        FIRING_DELTAS
            .lock()
            .unwrap()
            .push(now.saturating_duration_since(previous));
    } else {
        state.last_fire = Some(now);
    }
    Some(TesterAction::Multiple(Vec::new()))
}

fn count_cycle() -> Option<TesterAction<DummyPacket>> {
    CYCLE_COUNT.fetch_add(1, Ordering::SeqCst);
    Some(TesterAction::Multiple(Vec::new()))
}

#[test]
fn send_packet_every_8_ms() {
    register_test();
    FIRING_DELTAS.lock().unwrap().clear();
    let addr = SocketAddr::from(([127, 0, 0, 1], 4300));
    let mut tester = connect_tester::<DummyPacket>(addr)
        .with_stateful_cyclic_action::<CyclicState>(Duration::from_millis(8), record_cycle)
        .until_stateful_condition::<TimerState>(|state| {
            state.poll_elapsed() >= Duration::from_millis(60)
        });
    run_testers!(tester);
    let deltas = FIRING_DELTAS.lock().unwrap().clone();
    assert!(deltas.len() >= 3, "expected multiple cycles, got {}", deltas.len());
    for delta in deltas {
        assert!(delta > Duration::from_millis(0));
        assert!(delta <= Duration::from_millis(80));
    }
}

#[test]
fn stateless_cycles_fire() {
    register_test();
    CYCLE_COUNT.store(0, Ordering::SeqCst);
    let addr = SocketAddr::from(([127, 0, 0, 1], 4301));
    let mut tester = connect_tester::<DummyPacket>(addr)
        .with_cyclic_action(Duration::from_millis(5), count_cycle)
        .until_stateful_condition::<TimerState>(|state| {
            state.poll_elapsed() >= Duration::from_millis(30)
        });
    run_testers!(tester);
    let count = CYCLE_COUNT.load(Ordering::SeqCst);
    assert!(count >= 3, "expected at least 3 cycles, got {}", count);
}
