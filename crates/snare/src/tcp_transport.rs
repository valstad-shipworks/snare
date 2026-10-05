use std::collections::VecDeque;

pub(crate) struct Segment {
    pub(crate) bytes: Vec<u8>,
    pub(crate) mss: usize,
    pub(crate) end: u64,
}

pub(crate) struct TcpTransport {
    pending: VecDeque<Vec<u8>>,
    offset: usize,
    pub(crate) written: u64,
    pub(crate) transmitted: u64,
    received: u64,
    window_end: u64,
    advertised: usize,
    max_window: usize,
    buffer: usize,
    ratio: usize,
    threshold: usize,
    clamp: usize,
    receive_mss: usize,
    advmss: usize,
    initial_mss: usize,
    initial_goal: usize,
    initial_pushes: usize,
    scale: usize,
    gso_max: usize,
    cwnd: usize,
}

impl TcpTransport {
    pub(crate) fn new(buffer: usize, mtu: u32, v6: bool, gso_size: usize) -> Self {
        let header = if v6 { 72 } else { 52 };
        let advmss = (mtu as usize).min(65535).saturating_sub(header).max(1);
        let gso_max = gso_size.saturating_sub(header).max(advmss);
        let space = buffer / 2;
        let mut advertised = if space > advmss {
            space / advmss * advmss
        } else {
            space
        };
        advertised = advertised.min(65535);
        let mut scale = 1;
        while buffer / 2 / scale > 65535 && scale < 128 {
            scale *= 2;
        }
        let initial_mss = advmss.min((advertised / 2).max(1));
        let initial_goal = initial_mss * (gso_max.min(advertised / 2) / initial_mss).max(1);
        Self {
            pending: VecDeque::new(),
            offset: 0,
            written: 0,
            transmitted: 0,
            received: 0,
            window_end: advertised as u64,
            advertised,
            max_window: advertised,
            buffer,
            ratio: 128,
            threshold: space,
            clamp: space,
            receive_mss: initial_goal.min(536),
            advmss,
            initial_mss,
            initial_goal,
            initial_pushes: 2,
            scale,
            gso_max,
            cwnd: 10,
        }
    }

    pub(crate) fn pending_bytes(&self) -> usize {
        self.pending.iter().map(Vec::len).sum::<usize>() - self.offset
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.pending.push_back(bytes.to_vec());
        self.written += bytes.len() as u64;
    }

    pub(crate) fn direct(&mut self, len: usize) -> Option<usize> {
        let mss = self.advmss.min((self.max_window / 2).max(1));
        if !self.pending.is_empty()
            || len > mss
            || len as u64 > self.window_end.saturating_sub(self.transmitted)
        {
            return None;
        }
        self.written += len as u64;
        self.transmitted += len as u64;
        Some(mss)
    }

    pub(crate) fn next(&mut self) -> Option<Segment> {
        let available = self.window_end.saturating_sub(self.transmitted) as usize;
        if available == 0 {
            return None;
        }
        let pending = self.pending_bytes();
        if pending == 0 {
            return None;
        }
        let mss = self.advmss.min((self.max_window / 2).max(1));
        let initial = self.initial_pushes > 0 && pending > self.initial_goal;
        let goal = if initial {
            self.initial_pushes -= 1;
            self.initial_goal
        } else {
            let quota = (self.cwnd / 2).max(1);
            let segments = (self.gso_max / mss).max(1).min(quota);
            mss * segments
        };
        let packet_mss = if initial { self.initial_mss } else { mss };
        let n = goal
            .min(packet_mss * (self.cwnd / 2).max(1))
            .min(available)
            .min(pending);
        let mut bytes = Vec::with_capacity(n);
        while bytes.len() < n {
            let front = self.pending.front().unwrap();
            let take = (n - bytes.len()).min(front.len() - self.offset);
            bytes.extend_from_slice(&front[self.offset..self.offset + take]);
            self.offset += take;
            if self.offset == front.len() {
                self.pending.pop_front();
                self.offset = 0;
            }
        }
        self.transmitted += n as u64;
        Some(Segment {
            bytes,
            mss: packet_mss,
            end: self.transmitted,
        })
    }

    pub(crate) fn arrive(&mut self, len: usize, mss: usize, memory: usize, head: usize) {
        let measured = len.min(mss);
        let previous_mss = self.receive_mss;
        let previous_threshold = self.threshold;
        if measured >= self.receive_mss {
            if measured != self.receive_mss {
                self.ratio = (len.saturating_mul(256) / (len + head)).max(1);
                self.clamp = self.buffer.saturating_mul(self.ratio) / 256;
            }
            self.receive_mss = measured.min(self.advmss);
        }
        if len >= 128 {
            let free = self.buffer.saturating_sub(memory) * self.ratio / 256;
            let room = self.clamp.min(free).saturating_sub(self.threshold);
            self.threshold += room.min((2 * self.advmss).max(2 * len));
        }
        self.received += len as u64;
        if self.receive_mss != previous_mss || self.threshold != previous_threshold {
            self.advertise(memory);
        } else {
            self.advertised = self.window_end.saturating_sub(self.received) as usize;
        }
    }

    pub(crate) fn advertise(&mut self, memory: usize) {
        let allowed = self.buffer.saturating_mul(self.ratio) / 256;
        let full = self.clamp.min(allowed);
        let mss = self.receive_mss.min(full).max(1);
        let mut free = self.buffer.saturating_sub(memory) * self.ratio / 256;
        if free < full / 2 && (free < allowed / 16 || free < mss) {
            free = 0;
        }
        free = free.min(self.threshold);
        let window = if self.scale > 1 {
            free.div_ceil(self.scale) * self.scale
        } else if self.advertised > free || self.advertised <= free.saturating_sub(mss) {
            free / mss * mss
        } else {
            self.advertised
        };
        let end = self.received + window as u64;
        if end.saturating_sub(self.window_end) >= mss.min(allowed / 2).max(1) as u64 {
            self.window_end = end;
        }
        self.advertised = self.window_end.saturating_sub(self.received) as usize;
        self.max_window = self.max_window.max(self.advertised);
    }
}
