use std::{cell::RefCell, io, marker::PhantomData, net::SocketAddr, time::{Duration, Instant}};

use anymap2::AnyMap;

use crate::{SocketType, state::{self, wait_for_event}};


pub trait Packetable: Clone + Send + Sync + 'static {
    const CAN_BE_FLATTENED: bool;
    const SOCKET_TYPE: SocketType;

    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Option<(Self, usize)>;

    fn flatten(&self) -> Vec<Self> {
        vec![self.clone()]
    }
}

pub trait StateKey: Default + Send + Sync + 'static {}
impl<T: Default + Send + Sync + 'static> StateKey for T {}

#[derive(Debug, Default)]
pub struct TimerState {
    start_instant: Option<Instant>,
}
impl TimerState {
    pub fn poll_elapsed(&mut self) -> Duration {
        if let Some(start) = self.start_instant {
            Instant::now().duration_since(start)
        } else {
            self.start_instant = Some(Instant::now());
            Duration::from_secs(0)
        }
    }
}

pub enum TesterAction<T: Packetable> {
    Send(SocketAddr, T),
    RaiseSocketError(SocketAddr, io::Error),
    CloseSocket(SocketAddr),
    Multiple(Vec<TesterAction<T>>),
}

pub trait NetTesterInterface {
    fn test(&mut self, data: &[u8], src_addr: SocketAddr) -> Option<usize>;
    fn duration_till_soonest_cycle(&self) -> Option<Duration>;
    fn run_due_cycles(&mut self);
    fn is_finished(&mut self) -> bool;
    fn get_addr(&self) -> SocketAddr;
    fn get_socket_type(&self) -> SocketType;
}

pub struct NetTester<P: Packetable> {
    phantom: PhantomData<P>,
    addr: SocketAddr,
    state: AnyMap,
    tests: Vec<Box<dyn Fn(&mut Self, P, SocketAddr) -> Option<P>>>,
    cycles: Vec<(Duration, RefCell<Instant>, Box<dyn Fn(&mut Self)>)>,
    finish_conditions: Vec<Box<dyn Fn(&mut Self) -> bool>>,
}

impl<P: Packetable> NetTester<P> {
    fn enact_action(& mut self, action: TesterAction<P>) {
        match action {
            TesterAction::Send(addr, pkt) => {
                if P::SOCKET_TYPE == SocketType::Udp {
                    state::send_udp_from_test(self.addr, addr, pkt.encode());
                } else {
                    state::send_tcp_from_test(self.addr, addr, pkt.encode());
                }
            },
            TesterAction::RaiseSocketError(addr, e) => {
                if P::SOCKET_TYPE == SocketType::Udp {
                    state::raise_udp_socket_error_from_test(addr, e);
                } else {
                    state::raise_tcp_socket_error_from_test(addr, e);
                }
            },
            TesterAction::CloseSocket(addr) => {
                state::close_socket_from_test(addr, P::SOCKET_TYPE);
            },
            TesterAction::Multiple(actions) => {
                for act in actions {
                    self.enact_action(act);
                }
            }
        }
    }

    pub(crate) fn duration_till_soonest_cycle(& self) -> Option<Duration> {
        let now = Instant::now();
        let mut min_delta: Option<Duration> = None;
        for (delta, last_run_cell, _) in &self.cycles {
            let last_run = last_run_cell.borrow();
            let next_run = *last_run + *delta;
            if next_run <= now {
                return Some(Duration::from_secs(0));
            } else {
                let time_till_next = next_run - now;
                min_delta = match min_delta {
                    Some(current_min) => Some(std::cmp::min(current_min, time_till_next)),
                    None => Some(time_till_next),
                };
            }
        }
        min_delta
    }

    pub(crate) fn run_due_cycles(& mut self) {
        let now = Instant::now();
        let mut cycles = std::mem::take(&mut self.cycles);
        for (delta, last_run_cell, action) in cycles.iter_mut() {
            let mut last_run = last_run_cell.borrow_mut();
            let next_run = *last_run + *delta;
            if next_run <= now {
                action(self);
                *last_run = now;
            }
        }
        self.cycles = cycles;
    }

    pub fn then_stateful_test<S: StateKey>(mut self, tester: fn(&mut S, P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let storable = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            tester(state, pkt, addr)
        };
        self.tests.push(Box::new(storable));
        self
    }

    pub fn then_test(mut self, tester: fn(P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let stateless = move |_: &mut Self, pkt: P, addr: SocketAddr| tester(pkt, addr);
        self.tests.push(Box::new(stateless));
        self
    }

    pub fn then_edit_state<S: StateKey>(
        mut self,
        editor: fn(&mut S, SocketAddr),
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            editor(state, addr);
            Some(pkt)
        };
        self.tests.push(Box::new(stateful));
        self
    }

    pub fn then_stateful_action<S: StateKey>(
        mut self,
        actor: fn(&mut S, P, SocketAddr) -> TesterAction<P>,
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            let action = actor(state, pkt.clone(), addr);
            slf.enact_action(action);
            Some(pkt)
        };
        self.tests.push(Box::new(stateful));
        self
    }

    pub fn then_action(
        mut self,
        actor: fn(P, SocketAddr) -> TesterAction<P>,
    ) -> NetTester<P> {
        let stateless = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let action = actor(pkt.clone(), addr);
            slf.enact_action(action);
            Some(pkt)
        };
        self.tests.push(Box::new(stateless));
        self
    }

    pub fn with_stateful_cyclic_action<S: StateKey>(
        mut self,
        delta: Duration,
        actor: fn(&mut S) -> Option<TesterAction<P>>,
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            if let Some(action) = actor(state) {
                slf.enact_action(action);
            }
        };
        self.cycles.push((delta, RefCell::new(Instant::now()), Box::new(stateful)));
        self
    }

    pub fn with_cyclic_action(
        mut self,
        delta: Duration,
        actor: fn() -> Option<TesterAction<P>>,
    ) -> NetTester<P> {
        let stateless = move |slf: &mut Self| {
            if let Some(action) = actor() {
                slf.enact_action(action);
            }
        };
        self.cycles.push((delta, RefCell::new(Instant::now()), Box::new(stateless)));
        self
    }

    pub fn with_state<S: StateKey>(
        mut self,
        initializer: fn(&mut S),
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            initializer(state);
        };
        stateful(&mut self);
        self
    }

    pub fn until_condition(
        mut self,
        condition: fn() -> bool,
    ) -> NetTester<P> {
        let cond_box = Box::new(move |_: &mut Self| condition());
        self.finish_conditions.push(cond_box);
        self
    }

    pub fn until_stateful_condition<S: StateKey>(
        mut self,
        condition: fn(&mut S) -> bool,
    ) -> NetTester<P> {
        let cond_box = Box::new(move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            condition(state)
        });
        self.finish_conditions.push(cond_box);
        self
    }

    pub fn peek_state<'a, S: StateKey>(
        &'a self
    ) -> &'a S {
        self.state.get::<S>()
            .expect("State for type was not found")
    }
}

pub fn connect_tester<P: Packetable>(addr: SocketAddr) -> NetTester<P> {
    if P::SOCKET_TYPE == SocketType::Tcp {
        state::add_tcp_listener_state(addr);
    }
    let mut ret = NetTester {
        phantom: PhantomData,
        addr,
        state: AnyMap::new(),
        tests: Vec::new(),
        cycles: Vec::new(),
        finish_conditions: Vec::new(),
    };
    ret.state.entry::<()>().or_insert_with(|| ());
    ret
}

impl <P: Packetable> NetTesterInterface for NetTester<P> {
    fn test(&mut self, data: &[u8], src_addr: SocketAddr) -> Option<usize> {
        if P::SOCKET_TYPE == SocketType::Udp {
            let opt_pkt = P::decode(data).and_then(|(pkt, _)| Some(pkt));
            if let Some(mut pkt) = opt_pkt {
                let mut tests = std::mem::take(&mut self.tests);
                for test in tests.iter_mut() {
                    if let Some(new_pkt) = test(self, pkt, src_addr) {
                        pkt = new_pkt;
                    } else {
                        break;
                    }
                }
                self.tests = tests;
                self.run_due_cycles();
            }
            return None;
        } else {
            let mut offset = 0;
            while offset < data.len() {
                if let Some((mut pkt, read_bytes)) = P::decode(&data[offset..]) {
                    offset += read_bytes;
                    let mut tests = std::mem::take(&mut self.tests);
                    for test in tests.iter_mut() {
                        if let Some(new_pkt) = test(self, pkt, src_addr) {
                            pkt = new_pkt;
                        } else {
                            break;
                        }
                    }
                    self.tests = tests;
                    self.run_due_cycles();
                } else {
                    break;
                }
            }
            return Some(offset);
        }
    }

    fn duration_till_soonest_cycle(& self) -> Option<Duration> {
        NetTester::duration_till_soonest_cycle(self)
    }

    fn run_due_cycles(& mut self) {
        NetTester::run_due_cycles(self);
    }

    fn is_finished(&mut self) -> bool {
        let mut finishe_conditions = std::mem::take(&mut self.finish_conditions);
        if finishe_conditions.is_empty() {
            let has_pending = match P::SOCKET_TYPE {
                SocketType::Udp => state::has_pending_udp_packet(self.addr),
                SocketType::Tcp => state::has_pending_tcp_data(self.addr),
            };
            self.finish_conditions = finishe_conditions;
            return !has_pending;
        }
        for condition in finishe_conditions.iter_mut() {
            if condition(self) {
                self.finish_conditions = finishe_conditions;
                return true
            }
        }
        self.finish_conditions = finishe_conditions;
        false
    }

    fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    fn get_socket_type(&self) -> SocketType {
        P::SOCKET_TYPE
    }
}

#[doc(hidden)]
pub fn _run_testers(mut testers: Vec<&mut dyn NetTesterInterface>) {
    for tester in testers.iter() {
        for other_tester in testers.iter() {
            if std::ptr::eq(*tester, *other_tester) {
                continue;
            }
            assert!(
                tester.get_addr() != other_tester.get_addr() ||
                tester.get_socket_type() != other_tester.get_socket_type(),
                "Overlapping testers detected for addr: {} and socket type: {:?}",
                tester.get_addr(),
                tester.get_socket_type()
            );
        }
    }

    loop {
        for tester in testers.iter_mut() {
            tester.run_due_cycles();
        }

        let mut did_work = false;
        for tester in testers.iter_mut() {
            match tester.get_socket_type() {
                SocketType::Udp => {
                    while let Some(pkt) = state::pop_latest_packet(tester.get_addr()) {
                        did_work = true;
                        tester.test(&pkt.data, pkt.source);
                    }
                }
                SocketType::Tcp => loop {
                    let data = state::peek_tcp_stream_data(tester.get_addr());
                    if data.is_empty() {
                        break;
                    }
                    match tester.test(&data, tester.get_addr()) {
                        Some(used) if used > 0 => {
                            state::consume_tcp_stream_data(tester.get_addr(), used);
                            did_work = true;
                        }
                        _ => break,
                    }
                },
            }
        }

        for tester in testers.iter_mut() {
            if tester.is_finished() {
                return;
            }
        }

        if did_work {
            continue;
        }

        let mut min_duration: Option<Duration> = None;
        for tester in testers.iter() {
            let tester_duration = tester.duration_till_soonest_cycle();
            min_duration = match (min_duration, tester_duration) {
                (Some(current_min), Some(tester_dur)) => Some(std::cmp::min(current_min, tester_dur)),
                (None, Some(tester_dur)) => Some(tester_dur),
                (min, None) => min,
            };
        }

        let duration = min_duration.unwrap_or_else(|| Duration::from_millis(10));
        if duration > Duration::from_secs(0) {
            wait_for_event(Some(duration));
        }
    }
}

#[macro_export]
macro_rules! run_testers {
    ($( $testr:ident ),* $(,)?) => {
        ({
            let mut testers_vec: Vec<&mut dyn NetTesterInterface> = Vec::new();
            $(
                testers_vec.push(&mut $testr);
            )*
            ::std::thread::sleep(::std::time::Duration::from_millis(500));
            $crate::_run_testers(testers_vec);
        });
    };
}
