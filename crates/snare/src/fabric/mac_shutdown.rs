use super::*;

#[derive(Default)]
pub(super) struct State {
    incoming: [Option<Deadline>; 2],
    incoming_due: [Option<Deadline>; 2],
    return_delays: [Duration; 2],
    rst: [Option<Deadline>; 2],
    rst_due: [Option<Deadline>; 2],
    local_closed: [bool; 2],
    probes: [Option<Arc<ShutdownProbe>>; 2],
}

struct ShutdownProbe {
    conn: std::sync::Weak<Conn>,
    end: End,
}

fn other(end: End) -> End {
    match end {
        End::A => End::B,
        End::B => End::A,
    }
}

impl Conn {
    pub(super) fn progress_tcp_shutdown(&self) {
        if self.pair {
            return;
        }
        let mut arm = [[None; 2]; 2];
        let clock = self.regs.shared.clock.as_deref();
        let mut state = self.mac_shutdown.lock().unwrap();
        loop {
            for end in [End::A, End::B] {
                let i = end.index();
                if let Some(original) = state.incoming[i] {
                    let at = self.write_pipe(end).effective_shutdown_arrival(original);
                    if state.incoming_due[i].is_none_or(|old| old.instant() != at.instant()) {
                        state.incoming_due[i] = Some(at);
                        arm[0][i] = Some(at);
                        if let Some(tap) = &self.tap {
                            tap.retarget_reset(other(end).index(), at, state.return_delays[i]);
                        }
                    }
                }
                if let Some(original) = state.rst[i] {
                    let at = self.write_pipe(end).effective_shutdown_arrival(original);
                    if state.rst_due[i].is_none_or(|old| old.instant() != at.instant()) {
                        state.rst_due[i] = Some(at);
                        arm[1][i] = Some(at);
                        if let Some(tap) = &self.tap {
                            tap.defer_reset_receipt(other(end).index(), at);
                        }
                    }
                }
            }
            let incoming = [End::A, End::B].into_iter().filter_map(|end| {
                state.incoming_due[end.index()]
                    .filter(|at| at.passed_on(clock) && self.write_pipe(end).can_arrive())
                    .map(|at| (at, end, false))
            });
            let rst = [End::A, End::B].into_iter().filter_map(|end| {
                state.rst_due[end.index()]
                    .filter(|at| at.passed_on(clock) && self.write_pipe(end).can_arrive())
                    .map(|at| (at, end, true))
            });
            let Some((at, from, reset)) = incoming
                .chain(rst)
                .min_by_key(|(at, _, reset)| (at.instant(), *reset))
            else {
                break;
            };
            let to = other(from);
            if reset {
                state.rst[from.index()] = None;
                state.rst_due[from.index()] = None;
                if !state.local_closed[to.index()] {
                    self.count_shutdown_reset(to, false);
                    self.write_pipe(to).abort_writer();
                    self.write_pipe(from).reset_reader_at(None);
                    state.local_closed[to.index()] = true;
                }
                self.a_to_b.reset_quiet_at(at);
                self.b_to_a.reset_quiet_at(at);
            } else {
                state.incoming[from.index()] = None;
                state.incoming_due[from.index()] = None;
                if state.local_closed[to.index()] {
                    continue;
                }
                state.local_closed[to.index()] = true;
                self.count_shutdown_reset(to, self.write_pipe(to).has_writer());
                self.write_pipe(to).abort_writer();
                let return_delay = state.return_delays[from.index()];
                if let Some(tap) = &self.tap {
                    tap.rst_at(to.index(), at, return_delay);
                }
                let reset_at = at.later(return_delay);
                state.rst[to.index()] = Some(reset_at);
                state.rst_due[to.index()] = None;
            }
        }
        for (stage, pending) in arm.iter_mut().zip([state.incoming, state.rst]) {
            for (at, pending) in stage.iter_mut().zip(pending) {
                if pending.is_none() {
                    *at = None;
                }
            }
        }
        drop(state);
        for at in arm.into_iter().flatten().flatten() {
            at.wake_waiters_quiet_on(self.regs.shared.clock.as_deref());
        }
    }

    fn count_shutdown_reset(&self, end: End, sent: bool) {
        let established = self.read_pipe(end).established_reader();
        self.regs.shared.count_reset(
            self.server.ip(),
            sent,
            [end == End::A && established, end == End::B && established],
        );
    }

    pub(super) fn schedule_read_shutdown_data(&self, end: End, at: Deadline) {
        if self.pair {
            return;
        }
        self.schedule_shutdown_arrival(end, at);
    }

    fn schedule_shutdown_arrival(&self, end: End, at: Deadline) {
        let mut state = self.mac_shutdown.lock().unwrap();
        if state.local_closed[other(end).index()] {
            return;
        }
        let pending = &mut state.incoming[end.index()];
        if pending.is_none_or(|old| at.instant() < old.instant()) {
            *pending = Some(at);
            let due = self.write_pipe(end).effective_shutdown_arrival(at);
            state.incoming_due[end.index()] = Some(due);
            let return_delay = self.delay();
            state.return_delays[end.index()] = return_delay;
            if let Some(tap) = &self.tap {
                tap.discard_acks_from(
                    other(end).index(),
                    due.remaining_on(self.regs.shared.clock.as_deref()),
                    return_delay,
                );
            }
            drop(state);
            due.wake_waiters_quiet_on(self.regs.shared.clock.as_deref());
        }
    }

    pub(super) fn shut_read_tcp(&self, end: End) {
        self.read_pipe(end).shut_read();
        if self.pair {
            return;
        }
        if let Some(at) = self.read_pipe(end).shutdown_arrival() {
            self.schedule_shutdown_arrival(other(end), at);
        }
    }

    pub(super) fn attach_tcp_probe(self: &Arc<Self>, end: End, rec: &Arc<SockRec>) {
        if self.pair {
            return;
        }
        let probe = Arc::new(ShutdownProbe {
            conn: Arc::downgrade(self),
            end,
        });
        rec.set_probe(Arc::downgrade(&probe) as std::sync::Weak<dyn RxProbe>);
        if let Some(tap) = &self.tap {
            tap.watch_probe(Arc::downgrade(&probe) as std::sync::Weak<dyn RxProbe>);
        }
        self.mac_shutdown.lock().unwrap().probes[end.index()] = Some(probe);
    }
}

impl RxProbe for ShutdownProbe {
    fn pending_time(&self) -> bool {
        self.conn.upgrade().is_some_and(|conn| {
            conn.progress_tcp_shutdown();
            let state = conn.mac_shutdown.lock().unwrap();
            let pending = state.incoming.iter().chain(&state.rst).any(Option::is_some);
            drop(state);
            pending || RxProbe::pending_time(conn.read_pipe(self.end))
        })
    }

    fn land(&self) {
        if let Some(conn) = self.conn.upgrade() {
            conn.progress_tcp_shutdown();
            RxProbe::land(conn.read_pipe(self.end));
        }
    }

    fn queued(&self) -> (usize, usize) {
        self.conn.upgrade().map_or((0, 0), |conn| {
            conn.progress_tcp_shutdown();
            RxProbe::queued(conn.read_pipe(self.end))
        })
    }
}
