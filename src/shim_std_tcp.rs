use std::{
    cmp,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

use crate::state::{
    add_tcp_connection, add_tcp_listener_state, assign_tcp_stream_to_listener,
    clone_tcp_listener_state, find_tcp_listener, is_ip_addr_valid, is_port_available,
    mark_peer_read_shutdown, notify_peer_dropped, pcap_tcp_data, pcap_tcp_fin, pcap_tcp_open,
    release_stream, remove_tcp_connection, remove_tcp_listener_state, reserve_ephemeral_addr,
    wait_for_event, with_tcp_connection, with_tcp_listener_state,
};

#[derive(Debug)]
pub struct ShimStdTcpStream {
    stream_id: usize,
}

#[derive(Debug)]
pub struct ShimStdTcpListener {
    bound_addr: SocketAddr,
}

enum TcpReadStatus {
    Data(Vec<u8>),
    Eof,
    Pending {
        nonblocking: bool,
        timeout: Option<Duration>,
    },
}

impl ShimStdTcpStream {
    #[doc(alias = "std::net::TcpStream::connect")]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let mut last_err = None;
        for target in addr.to_socket_addrs()? {
            match Self::connect_addr(target) {
                Ok(stream) => return Ok(stream),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        }))
    }

    /// Mirrors [`std::net::TcpStream::connect_timeout`] — takes `&SocketAddr`
    /// (not the generic `ToSocketAddrs`) for strict signature parity.
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<Self> {
        if timeout == Duration::from_secs(0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout duration must be non-zero",
            ));
        }
        Self::connect(*addr)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.with_conn(|conn| Ok(conn.peer_addr))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.with_conn(|conn| Ok(conn.local_addr))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.with_conn(|conn| {
            conn.nonblocking = nonblocking;
            Ok(())
        })
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.with_conn(|conn| {
            conn.nodelay = nodelay;
            Ok(())
        })
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.with_conn(|conn| Ok(conn.nodelay))
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.with_conn(|conn| {
            conn.ttl = ttl;
            Ok(())
        })
    }

    pub fn ttl(&self) -> io::Result<u32> {
        self.with_conn(|conn| Ok(conn.ttl))
    }

    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        if let Some(dur) = linger {
            if dur == Duration::from_secs(0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "linger duration must be non-zero",
                ));
            }
        }
        self.with_conn(|conn| {
            conn.linger = linger;
            Ok(())
        })
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        self.with_conn(|conn| Ok(conn.linger))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(d) = timeout {
            if d == Duration::from_secs(0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "timeout duration must be non-zero",
                ));
            }
        }
        self.with_conn(|conn| {
            conn.read_timeout = timeout;
            Ok(())
        })
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.with_conn(|conn| Ok(conn.read_timeout))
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(d) = timeout {
            if d == Duration::from_secs(0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "timeout duration must be non-zero",
                ));
            }
        }
        self.with_conn(|conn| {
            conn.write_timeout = timeout;
            Ok(())
        })
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.with_conn(|conn| Ok(conn.write_timeout))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.with_conn(|conn| Ok(conn.external_error.take()))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        self.with_conn(|conn| {
            conn.ref_count += 1;
            Ok(())
        })?;
        Ok(Self {
            stream_id: self.stream_id,
        })
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let peer = self.with_conn(|conn| {
            match how {
                Shutdown::Both => {
                    conn.read_shutdown = true;
                    conn.write_shutdown = true;
                }
                Shutdown::Read => {
                    conn.read_shutdown = true;
                    conn.incoming.clear();
                }
                Shutdown::Write => {
                    conn.write_shutdown = true;
                }
            }
            Ok(conn.peer_stream_id)
        })?;
        if let Shutdown::Write | Shutdown::Both = how {
            if let Some(peer_id) = peer {
                mark_peer_read_shutdown(peer_id);
            }
        }
        Ok(())
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_internal(buf, false)
    }

    fn read_internal(&self, buf: &mut [u8], consume: bool) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut deadline = None;
        loop {
            match self.try_read(buf.len(), consume)? {
                TcpReadStatus::Data(data) => {
                    let len = data.len();
                    if len > 0 {
                        buf[..len].copy_from_slice(&data[..len]);
                    }
                    return Ok(len);
                }
                TcpReadStatus::Eof => return Ok(0),
                TcpReadStatus::Pending {
                    nonblocking,
                    timeout,
                } => {
                    if nonblocking {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "no data available",
                        ));
                    }
                    self.wait_for_read_ready(timeout, &mut deadline)?;
                }
            }
        }
    }

    fn try_read(&self, len: usize, consume: bool) -> io::Result<TcpReadStatus> {
        // Lift any latency-released bytes into incoming before inspecting.
        let local_addr = self.with_conn(|conn| Ok(conn.local_addr))?;
        crate::state::release_pending_for_tcp(local_addr);
        self.with_conn(|conn| {
            if conn.reset_pending {
                conn.reset_pending = false;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            if conn.is_destroyed {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stream destroyed",
                ));
            }
            if conn.incoming.is_empty() {
                if conn.read_shutdown || conn.peer_stream_id.is_none() {
                    return Ok(TcpReadStatus::Eof);
                }
                return Ok(TcpReadStatus::Pending {
                    nonblocking: conn.nonblocking,
                    timeout: conn.read_timeout,
                });
            }
            let take = cmp::min(len, conn.incoming.len());
            let mut data = Vec::with_capacity(take);
            if consume {
                for _ in 0..take {
                    if let Some(byte) = conn.incoming.pop_front() {
                        data.push(byte);
                    }
                }
            } else {
                data.extend(conn.incoming.iter().take(take).copied());
            }
            Ok(TcpReadStatus::Data(data))
        })
    }

    fn wait_for_read_ready(
        &self,
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
    ) -> io::Result<()> {
        Self::wait_with_deadline(timeout, deadline)
    }

    fn wait_for_write_ready(
        &self,
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
    ) -> io::Result<()> {
        Self::wait_with_deadline(timeout, deadline)
    }

    fn wait_with_deadline(
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
    ) -> io::Result<()> {
        // Cap the wait at the earliest pending-release deadline across all
        // shim-managed conns. Without this, latency-delayed bytes would never
        // wake a blocked reader: nothing in the test thread fires `notify`
        // when the deadline elapses on its own.
        let pending_release = crate::state::earliest_pending_release();

        if let Some(duration) = timeout {
            let now = Instant::now();
            let target = match deadline {
                Some(existing) => *existing,
                None => {
                    let new_deadline = now + duration;
                    *deadline = Some(new_deadline);
                    new_deadline
                }
            };
            if now >= target {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "operation timed out",
                ));
            }
            let mut remaining = target - now;
            if let Some(release) = pending_release {
                let until_release = release.saturating_duration_since(now);
                if until_release < remaining {
                    remaining = until_release;
                }
            }
            if !wait_for_event(Some(remaining)) && Instant::now() >= target {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "operation timed out",
                ));
            }
        } else {
            *deadline = None;
            // No user timeout, but if there's a pending-release deadline we
            // must still wake at it; otherwise we'd block forever despite
            // having buffered bytes ready to surface.
            match pending_release {
                Some(release) => {
                    let now = Instant::now();
                    let dur = release.saturating_duration_since(now);
                    if dur.is_zero() {
                        return Ok(());
                    }
                    wait_for_event(Some(dur));
                }
                None => {
                    wait_for_event(None);
                }
            }
        }
        Ok(())
    }

    fn connect_addr(target: SocketAddr) -> io::Result<Self> {
        if !is_ip_addr_valid(target.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "invalid target address",
            ));
        }
        let listener_addr = find_tcp_listener(target).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionRefused, "no listener available")
        })?;
        match crate::state::listener_behavior(listener_addr) {
            crate::state::ListenerBehavior::Accepting => {}
            crate::state::ListenerBehavior::Refusing => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "listener configured to refuse",
                ));
            }
            crate::state::ListenerBehavior::DelayingUntil(deadline) => {
                let now = Instant::now();
                if deadline > now {
                    // Block until the deadline (or this thread is otherwise
                    // woken) — matches "SYN dropped, retry until backoff".
                    wait_for_event(Some(deadline - now));
                    if Instant::now() < deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "listener delaying accept",
                        ));
                    }
                }
            }
        }
        let client_ip = preferred_client_ip(&target);
        let local_addr = reserve_ephemeral_addr(client_ip);
        let server_ip = if listener_addr.ip().is_unspecified() {
            target.ip()
        } else {
            listener_addr.ip()
        };
        let server_addr = SocketAddr::new(server_ip, listener_addr.port());
        let client_stream = add_tcp_connection(local_addr, server_addr, true);
        let server_stream = add_tcp_connection(server_addr, local_addr, false);
        with_tcp_connection(client_stream, |conn| -> io::Result<()> {
            conn.peer_stream_id = Some(server_stream);
            Ok(())
        })?;
        with_tcp_connection(server_stream, |conn| -> io::Result<()> {
            conn.peer_stream_id = Some(client_stream);
            Ok(())
        })?;
        assign_tcp_stream_to_listener(listener_addr, server_stream);
        pcap_tcp_open(local_addr, server_addr);
        Ok(Self {
            stream_id: client_stream,
        })
    }

    fn with_conn<T, F>(&self, func: F) -> io::Result<T>
    where
        F: FnOnce(&mut crate::state::TcpConnection) -> io::Result<T>,
    {
        with_tcp_connection(self.stream_id, func)
    }
}

impl ShimStdTcpStream {
    /// Internal write that takes `&self` so we can implement `Write` for both
    /// `ShimStdTcpStream` and `&ShimStdTcpStream` (matching `std::net::TcpStream`).
    fn write_internal(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (peer_id, nonblocking, write_timeout, local_addr) = self.with_conn(|conn| {
            if conn.reset_pending {
                conn.reset_pending = false;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            if conn.write_shutdown {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "write half closed",
                ));
            }
            let peer = conn
                .peer_stream_id
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no peer connected"))?;
            Ok((peer, conn.nonblocking, conn.write_timeout, conn.local_addr))
        })?;

        // Apply outbound latency by routing the write into the peer's
        // pending_inbound queue with a release deadline. Recv-window also
        // applies on the peer side so the writer back-pressures naturally.
        let peer_local_addr = with_tcp_connection(peer_id, |peer| io::Result::Ok(peer.local_addr))?;
        let peer_policy = crate::state::tcp_policy(peer_local_addr);

        let mut deadline: Option<Instant> = None;
        loop {
            let result = with_tcp_connection(peer_id, |peer| {
                if peer.read_shutdown {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "peer closed the read half",
                    ));
                }
                if let Some(window) = peer_policy.recv_window {
                    let queued = peer.incoming.len()
                        + peer
                            .pending_inbound
                            .iter()
                            .map(|(_, b)| b.len())
                            .sum::<usize>();
                    if queued + buf.len() > window {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "peer recv window full",
                        ));
                    }
                }
                if peer_policy.inbound_latency.is_zero() {
                    peer.incoming.extend(buf.iter().copied());
                } else {
                    peer.pending_inbound
                        .push_back((Instant::now() + peer_policy.inbound_latency, buf.to_vec()));
                }
                Ok(buf.len())
            });

            match result {
                Ok(n) => {
                    pcap_tcp_data(local_addr, peer_local_addr, &buf[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if nonblocking {
                        return Err(e);
                    }
                    self.wait_for_write_ready(write_timeout, &mut deadline)?;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Returns `-1`: there is no kernel socket behind the shim. Raw syscalls on
/// it fail with `EBADF`, so a SUT probing socket capabilities through the fd
/// falls back to the portable std API, which the shim does implement. A real
/// dummy fd would be worse — option probes would succeed and the SUT would
/// then read from an empty kernel socket instead of the virtual network.
#[cfg(unix)]
impl std::os::fd::AsRawFd for ShimStdTcpStream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}

impl Read for ShimStdTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_internal(buf, true)
    }
}

impl Read for &ShimStdTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_internal(buf, true)
    }
}

impl Write for ShimStdTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_internal(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &ShimStdTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (**self).write_internal(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ShimStdTcpStream {
    fn drop(&mut self) {
        // Honor SO_LINGER: if a non-None linger duration is set and there are
        // still bytes pending in the peer's incoming buffer (or in flight via
        // pending_inbound), block here until either the peer drains them or
        // the linger timeout elapses. Matches std behavior where a non-zero
        // linger forces close() to wait for the send buffer to flush.
        let (peer_id_opt, linger) =
            with_tcp_connection(self.stream_id, |conn| (conn.peer_stream_id, conn.linger));

        if let (Some(peer_id), Some(linger_dur)) = (peer_id_opt, linger) {
            let deadline = Instant::now() + linger_dur;
            loop {
                let pending_bytes = with_tcp_connection(peer_id, |peer| {
                    peer.incoming.len()
                        + peer
                            .pending_inbound
                            .iter()
                            .map(|(_, b)| b.len())
                            .sum::<usize>()
                });
                if pending_bytes == 0 {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                wait_for_event(Some(deadline - now));
            }
        }

        // Capture addrs before release_stream may drop the connection out from
        // under us, so we can emit a synthetic FIN to the pcap log.
        let addrs = with_tcp_connection(
            self.stream_id,
            |conn| -> io::Result<(std::net::SocketAddr, std::net::SocketAddr)> {
                Ok((conn.local_addr, conn.peer_addr))
            },
        )
        .ok();
        if let Some(peer_id) = release_stream(self.stream_id) {
            notify_peer_dropped(peer_id);
            if let Some((local, peer)) = addrs {
                pcap_tcp_fin(local, peer);
            }
        }
    }
}

/// Returns `-1`; same rationale as [`ShimStdTcpStream`]'s impl.
#[cfg(unix)]
impl std::os::fd::AsRawFd for ShimStdTcpListener {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}

impl ShimStdTcpListener {
    #[doc(alias = "std::net::TcpListener::bind")]
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        for address in addr.to_socket_addrs()? {
            if !is_ip_addr_valid(address.ip()) {
                continue;
            }
            let actual_addr = if address.port() == 0 {
                reserve_ephemeral_addr(address.ip())
            } else if is_port_available(address.port()) {
                address
            } else {
                continue;
            };
            add_tcp_listener_state(actual_addr);
            return Ok(Self {
                bound_addr: actual_addr,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "could not bind to any addresses",
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound_addr)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        with_tcp_listener_state(self.bound_addr, |listener| {
            listener.nonblocking = nonblocking;
        });
        Ok(())
    }

    pub fn accept(&self) -> io::Result<(ShimStdTcpStream, SocketAddr)> {
        loop {
            let (stream_id, nonblocking, is_closed) =
                with_tcp_listener_state(self.bound_addr, |listener| {
                    (
                        listener.pending_streams.pop_front(),
                        listener.nonblocking,
                        listener.is_closed,
                    )
                });
            if is_closed {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "listener closed",
                ));
            }
            if let Some(stream_id) = stream_id {
                let peer_addr = with_tcp_connection(stream_id, |conn| -> io::Result<SocketAddr> {
                    Ok(conn.peer_addr)
                })?;
                return Ok((ShimStdTcpStream { stream_id }, peer_addr));
            }
            if nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no pending connections",
                ));
            }
            wait_for_event(None);
        }
    }

    pub fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        todo!()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        todo!()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        with_tcp_listener_state(self.bound_addr, |listener| Ok(listener.error.take()))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        clone_tcp_listener_state(self.bound_addr)?;
        Ok(Self {
            bound_addr: self.bound_addr,
        })
    }

    /// Returns an iterator over the connections being received on this listener.
    /// Mirrors [`std::net::TcpListener::incoming`].
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    // `std::net::TcpListener::into_incoming` is still unstable (rust issue
    // #88373) so we don't expose it on the shim either — keeping the snare
    // surface to what's stable on std.
}

/// Iterator over connections being received on a [`ShimStdTcpListener`].
/// Mirrors [`std::net::Incoming`].
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a ShimStdTcpListener,
}

impl<'a> Iterator for Incoming<'a> {
    type Item = io::Result<ShimStdTcpStream>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept().map(|(s, _)| s))
    }
}

impl Drop for ShimStdTcpListener {
    fn drop(&mut self) {
        if let Some(state) = remove_tcp_listener_state(self.bound_addr) {
            for stream_id in state.pending_streams {
                cleanup_unaccepted_stream(stream_id);
            }
        }
    }
}

fn cleanup_unaccepted_stream(stream_id: usize) {
    if let Some(conn) = remove_tcp_connection(stream_id) {
        if let Some(peer_id) = conn.peer_stream_id {
            notify_peer_dropped(peer_id);
        }
    }
}

fn preferred_client_ip(target: &SocketAddr) -> IpAddr {
    if is_ip_addr_valid(target.ip()) {
        target.ip()
    } else {
        match target {
            SocketAddr::V4(_) => IpAddr::from([127, 0, 0, 1]),
            SocketAddr::V6(_) => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        }
    }
}
