use std::{
    cmp,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr},
    time::Duration,
};

use crate::resolve::ToSocketAddrs;

use crate::netif::SocketId;
use crate::os::{Errno, OsSemantics, os_err_for};
use crate::sched::waitset::{WaitKey, WaitTicket};
use crate::shim_std_udp::{timed_out, would_block};
use crate::state::{
    ListenerBehavior, PeerClose, Pushed, SynFate, TcpConnection, add_tcp_connection,
    assign_tcp_stream_to_listener, clone_tcp_listener_state, find_tcp_listener, is_ip_addr_valid,
    listener_behavior, mark_peer_read_shutdown, notify_peer_dropped, notify_peer_reset, os_ctx,
    pcap_tcp_data, pcap_tcp_fin, pcap_tcp_open, pcap_tcp_rst, release_stream,
    remove_tcp_connection, remove_tcp_listener_state, reserve_ephemeral_addr, tcp_connect_plan,
    tcp_push_chunk, tcp_syn_fate, try_with_tcp_connection, wake, wake_at, wake_window_writer,
    with_tcp_connection, with_tcp_listener_state,
};
use crate::time::Instant;

#[derive(Debug)]
pub struct ShimStdTcpStream {
    stream_id: usize,
    id: SocketId,
}

#[derive(Debug)]
pub struct ShimStdTcpListener {
    bound_addr: SocketAddr,
    id: SocketId,
}

enum WriteGate {
    Open {
        peer: usize,
        nonblocking: bool,
        timeout: Option<Duration>,
        local: SocketAddr,
    },
    /// The peer's socket is gone; the bytes are lost and it answers with
    /// RST.
    Unread { local: SocketAddr, peer: SocketAddr },
}

enum TcpReadStatus {
    /// How many bytes were read into the caller's buffer, with the arrival
    /// instant of the newest of them when they were consumed, and how many
    /// bytes were buffered before the read.
    Data(usize, Option<Instant>, usize),
    Eof,
    Pending {
        nonblocking: bool,
        timeout: Option<Duration>,
    },
}

impl ShimStdTcpStream {
    /// Mirrors [`std::net::TcpStream::connect`]. Under faithful OS semantics
    /// a target with no accepting listener fails as that OS would, after the
    /// same virtual delay: refused at once (two seconds on Windows) by an
    /// address the host owns, timed out after the SYN retries (127 s Linux,
    /// 75 s macOS, 21 s Windows) at any other routable address.
    #[doc(alias = "std::net::TcpStream::connect")]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let mut last_err = None;
        for target in addr.to_socket_addrs()? {
            match Self::connect_addr(target, None) {
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
    /// (not the generic `ToSocketAddrs`) for strict signature parity. The
    /// timeout is virtual time and bounds a wait on a
    /// [`ListenerBehavior::DelayingUntil`](crate::ListenerBehavior::DelayingUntil)
    /// listener.
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<Self> {
        if timeout == Duration::from_secs(0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout duration must be non-zero",
            ));
        }
        Self::connect_addr(*addr, Some(timeout))
    }

    #[cfg_attr(not(feature = "mio-compat"), allow(dead_code))]
    pub(crate) fn stream_id(&self) -> usize {
        self.stream_id
    }

    pub(crate) fn id(&self) -> SocketId {
        self.id
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

    /// Under faithful OS semantics a zero linger is accepted and makes the
    /// drop of the last handle abort the connection: the peer gets a RST
    /// instead of a FIN.
    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        if let Some(dur) = linger
            && dur == Duration::from_secs(0)
            && !os_ctx().1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "linger duration must be non-zero",
            ));
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
        if let Some(d) = timeout
            && d == Duration::from_secs(0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout duration must be non-zero",
            ));
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
        if let Some(d) = timeout
            && d == Duration::from_secs(0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout duration must be non-zero",
            ));
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
            id: self.id,
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
                    conn.clear_incoming();
                }
                Shutdown::Write => {
                    conn.write_shutdown = true;
                }
            }
            Ok(conn.peer_stream_id)
        })?;
        wake(WaitKey::Stream(self.stream_id));
        if let Some(peer_id) = peer {
            match how {
                Shutdown::Write | Shutdown::Both => mark_peer_read_shutdown(peer_id),
                Shutdown::Read => wake(WaitKey::Stream(peer_id)),
            }
        }
        Ok(())
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_internal(buf, false, false).map(|(n, _)| n)
    }

    /// Reads like `read`, returning the arrival instant of the newest byte
    /// read. With `dontwait` it never blocks, whatever the stream's mode.
    #[cfg_attr(not(feature = "fast-talker-core"), allow(dead_code))]
    pub(crate) fn read_stamped(
        &self,
        buf: &mut [u8],
        dontwait: bool,
    ) -> io::Result<(usize, Option<Instant>)> {
        self.read_internal(buf, true, dontwait)
    }

    fn read_internal(
        &self,
        buf: &mut [u8],
        consume: bool,
        dontwait: bool,
    ) -> io::Result<(usize, Option<Instant>)> {
        if buf.is_empty() {
            return Ok((0, None));
        }
        let mut deadline = None;
        let mut ticket = None;
        loop {
            match self.try_read(buf, consume)? {
                TcpReadStatus::Data(len, at, before) => {
                    drop(ticket);
                    if len > 0 && consume {
                        crate::sched::class_effect("tcp read");
                        wake(WaitKey::Stream(self.stream_id));
                        wake_window_writer(self.stream_id, before);
                    }
                    return Ok((len, at));
                }
                TcpReadStatus::Eof => return Ok((0, None)),
                TcpReadStatus::Pending {
                    nonblocking,
                    timeout,
                } => {
                    if nonblocking || dontwait {
                        return Err(would_block());
                    }
                    match ticket.take() {
                        None => {
                            ticket = Some(WaitTicket::register([WaitKey::Stream(self.stream_id)]))
                        }
                        Some(t) => wait_ready(t, timeout, &mut deadline, "tcp read")?,
                    }
                }
            }
        }
    }

    fn try_read(&self, buf: &mut [u8], consume: bool) -> io::Result<TcpReadStatus> {
        // Lift any latency-released bytes into incoming before inspecting.
        crate::state::release_pending_for_stream(self.stream_id);
        let (os, faithful) = os_ctx();
        self.with_conn(|conn| {
            if conn.reset_pending {
                return Err(take_reset(conn, os, faithful));
            }
            if faithful && os == OsSemantics::Windows && conn.peer_close == PeerClose::Reset {
                return Err(os_err_for(os, Errno::ConnReset));
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
            if consume {
                let before = conn.buffered();
                let (len, at) = conn.take_incoming_into(buf);
                return Ok(TcpReadStatus::Data(len, at, before));
            }
            let take = cmp::min(buf.len(), conn.incoming.len());
            for (dst, src) in buf[..take].iter_mut().zip(&conn.incoming) {
                *dst = *src;
            }
            Ok(TcpReadStatus::Data(take, None, 0))
        })
    }

    fn connect_addr(target: SocketAddr, timeout: Option<Duration>) -> io::Result<Self> {
        crate::sched::note_effect("tcp connect");
        let (os, faithful) = os_ctx();
        let listener_addr = if faithful {
            faithful_listener(os, target, timeout)?
        } else {
            legacy_listener(target, timeout)?
        };
        let (nic, client_ip) = tcp_connect_plan(target)?;
        let local_addr = reserve_ephemeral_addr(client_ip)?;
        let server_ip = if listener_addr.ip().is_unspecified() {
            target.ip()
        } else {
            listener_addr.ip()
        };
        let server_addr = SocketAddr::new(server_ip, listener_addr.port());
        let listener_id = Some(with_tcp_listener_state(listener_addr, |l| l.id));
        let (client_stream, client_id) =
            add_tcp_connection(local_addr, server_addr, true, nic, None);
        let (server_stream, _) =
            add_tcp_connection(server_addr, local_addr, false, nic, listener_id);
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
            id: client_id,
        })
    }

    fn with_conn<T, F>(&self, func: F) -> io::Result<T>
    where
        F: FnOnce(&mut crate::state::TcpConnection) -> io::Result<T>,
    {
        try_with_tcp_connection(self.stream_id, func).unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset by peer",
            ))
        })
    }
}

impl ShimStdTcpStream {
    /// Internal write that takes `&self` so we can implement `Write` for both
    /// `ShimStdTcpStream` and `&ShimStdTcpStream` (matching `std::net::TcpStream`).
    fn write_internal(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_stamped(buf, false).map(|(n, _)| n)
    }

    /// Writes like `write`. Returns the transmit stamp id fast-talker gives
    /// the write, if it stamps it; `via_ft` marks a write made through
    /// `TimestampedStream`.
    pub(crate) fn write_stamped(
        &self,
        buf: &[u8],
        via_ft: bool,
    ) -> io::Result<(usize, Option<u32>)> {
        if buf.is_empty() {
            return Ok((0, None));
        }
        crate::sched::note_effect("tcp write");
        let (os, faithful) = os_ctx();
        let mut deadline: Option<Instant> = None;
        let mut ticket = None;
        loop {
            let (peer_id, nonblocking, write_timeout, local_addr) =
                match self.write_gate(os, faithful)? {
                    WriteGate::Open {
                        peer,
                        nonblocking,
                        timeout,
                        local,
                    } => (peer, nonblocking, timeout, local),
                    WriteGate::Unread { local, peer } => {
                        drop(ticket);
                        pcap_tcp_data(local, peer, buf);
                        pcap_tcp_rst(peer, local);
                        return Ok((buf.len(), self.stamp_write(local, buf.len(), None, via_ft)));
                    }
                };
            let peer_local_addr = try_with_tcp_connection(peer_id, |peer| peer.local_addr)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "peer connection closed")
                })?;
            let result = tcp_push_chunk(peer_id, local_addr, buf).unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "peer connection closed",
                ))
            });

            match result {
                Ok((pushed, len)) => {
                    drop(ticket);
                    let arrival = match pushed {
                        Pushed::Now => {
                            wake(WaitKey::Stream(peer_id));
                            Some(Instant::now())
                        }
                        Pushed::At(at) => {
                            wake_at(at, WaitKey::Stream(peer_id));
                            Some(at)
                        }
                        Pushed::Stalled => None,
                    };
                    pcap_tcp_data(local_addr, peer_local_addr, &buf[..len]);
                    let id = self.stamp_write(local_addr, len, arrival, via_ft);
                    return Ok((len, id));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if nonblocking {
                        try_with_tcp_connection(self.stream_id, |conn| conn.write_blocks += 1);
                        return Err(would_block());
                    }
                    match ticket.take() {
                        None => {
                            ticket = Some(WaitTicket::register([
                                WaitKey::Stream(self.stream_id),
                                WaitKey::Addr(peer_local_addr),
                            ]))
                        }
                        Some(t) => wait_ready(t, write_timeout, &mut deadline, "tcp write")?,
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn write_gate(&self, os: OsSemantics, faithful: bool) -> io::Result<WriteGate> {
        self.with_conn(|conn| {
            if conn.reset_pending {
                return Err(take_reset(conn, os, faithful));
            }
            if faithful {
                match conn.peer_close {
                    PeerClose::Reset => {
                        return Err(os_err_for(os, broken_after_reset(os)));
                    }
                    PeerClose::Fin if conn.peer_stream_id.is_none() && !conn.write_shutdown => {
                        conn.peer_close = PeerClose::Reset;
                        return Ok(WriteGate::Unread {
                            local: conn.local_addr,
                            peer: conn.peer_addr,
                        });
                    }
                    _ => {}
                }
            }
            if conn.write_shutdown {
                return Err(if faithful {
                    os_err_for(os, Errno::Pipe)
                } else {
                    io::Error::new(io::ErrorKind::BrokenPipe, "write half closed")
                });
            }
            let peer = conn
                .peer_stream_id
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no peer connected"))?;
            Ok(WriteGate::Open {
                peer,
                nonblocking: conn.nonblocking,
                timeout: conn.write_timeout,
                local: conn.local_addr,
            })
        })
    }
}

impl ShimStdTcpStream {
    #[cfg(feature = "fast-talker-core")]
    fn stamp_write(
        &self,
        local: SocketAddr,
        len: usize,
        arrival: Option<Instant>,
        via_ft: bool,
    ) -> Option<u32> {
        crate::fast_talker_shim::tcp::on_write(self.stream_id, local, len, arrival, via_ft)
    }

    #[cfg(not(feature = "fast-talker-core"))]
    fn stamp_write(
        &self,
        _local: SocketAddr,
        _len: usize,
        _arrival: Option<Instant>,
        _via_ft: bool,
    ) -> Option<u32> {
        None
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
        self.read_internal(buf, true, false).map(|(n, _)| n)
    }
}

impl Read for &ShimStdTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_internal(buf, true, false).map(|(n, _)| n)
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
        let Some((peer_id_opt, linger)) =
            try_with_tcp_connection(self.stream_id, |conn| (conn.peer_stream_id, conn.linger))
        else {
            // Connection already removed (e.g. peer reset and released it) —
            // nothing left to tear down.
            return;
        };
        let (os, faithful) = os_ctx();
        let abort = faithful && linger == Some(Duration::ZERO);

        if let (Some(peer_id), Some(linger_dur), false) = (peer_id_opt, linger, abort) {
            let deadline = Instant::now() + linger_dur;
            loop {
                let ticket = WaitTicket::register([WaitKey::Stream(peer_id)]);
                let pending_bytes =
                    try_with_tcp_connection(peer_id, |peer| peer.buffered()).unwrap_or(0);
                if pending_bytes == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                ticket.wait(Some(deadline), "tcp linger");
            }
        }

        // Capture addrs before release_stream may drop the connection out from
        // under us, so we can emit a synthetic FIN to the pcap log.
        let addrs =
            try_with_tcp_connection(self.stream_id, |conn| (conn.local_addr, conn.peer_addr));
        if let Some(peer_id) = release_stream(self.stream_id) {
            if abort {
                notify_peer_reset(peer_id, os);
            } else {
                notify_peer_dropped(peer_id);
            }
            if let Some((local, peer)) = addrs {
                if abort {
                    pcap_tcp_rst(local, peer);
                } else {
                    pcap_tcp_fin(local, peer);
                }
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
        let mut last_err = None;
        for address in addr.to_socket_addrs()? {
            match crate::state::bind_tcp_listener(address) {
                Ok((id, bound_addr)) => {
                    wake(WaitKey::Listener(bound_addr));
                    return Ok(Self { bound_addr, id });
                }
                Err(Some(e)) => last_err = Some(e),
                Err(None) => {}
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "could not bind to any addresses",
            )
        }))
    }

    pub(crate) fn id(&self) -> SocketId {
        self.id
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
        let mut ticket = None;
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
                let (peer_addr, id) =
                    try_with_tcp_connection(stream_id, |conn| (conn.peer_addr, conn.id))
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "accepted connection gone",
                            )
                        })?;
                return Ok((ShimStdTcpStream { stream_id, id }, peer_addr));
            }
            if nonblocking {
                return Err(would_block());
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Listener(self.bound_addr)])),
                Some(t) => {
                    t.wait(None, "tcp accept");
                }
            }
        }
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        with_tcp_listener_state(self.bound_addr, |listener| listener.ttl = ttl);
        Ok(())
    }

    pub fn ttl(&self) -> io::Result<u32> {
        Ok(with_tcp_listener_state(self.bound_addr, |listener| {
            listener.ttl
        }))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        with_tcp_listener_state(self.bound_addr, |listener| Ok(listener.error.take()))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        clone_tcp_listener_state(self.bound_addr)?;
        Ok(Self {
            bound_addr: self.bound_addr,
            id: self.id,
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
    if let Some(conn) = remove_tcp_connection(stream_id)
        && let Some(peer_id) = conn.peer_stream_id
    {
        match os_ctx() {
            (os, true) => notify_peer_reset(peer_id, os),
            _ => notify_peer_dropped(peer_id),
        }
    }
}

/// Report a RST that arrived on `conn`, once.
fn take_reset(conn: &mut TcpConnection, os: OsSemantics, faithful: bool) -> io::Error {
    conn.reset_pending = false;
    if !faithful {
        return io::Error::new(io::ErrorKind::ConnectionReset, "connection reset by peer");
    }
    conn.peer_close = PeerClose::Reset;
    conn.external_error = None;
    os_err_for(os, Errno::ConnReset)
}

/// What a write reports once the connection has been reset: `EPIPE`, or
/// `WSAECONNRESET` on Windows.
fn broken_after_reset(os: OsSemantics) -> Errno {
    match os {
        OsSemantics::Windows => Errno::ConnReset,
        _ => Errno::Pipe,
    }
}

/// How long `os` retransmits an unanswered SYN before `connect` fails with
/// `ETIMEDOUT`.
fn syn_give_up(os: OsSemantics) -> Duration {
    match os {
        OsSemantics::Linux => Duration::from_secs(127),
        OsSemantics::MacOs => Duration::from_secs(75),
        OsSemantics::Windows => Duration::from_secs(21),
    }
}

/// How long `os` keeps retrying a SYN answered with RST before `connect`
/// fails with `ECONNREFUSED`.
fn refused_after(os: OsSemantics) -> Duration {
    match os {
        OsSemantics::Windows => Duration::from_secs(2),
        OsSemantics::Linux | OsSemantics::MacOs => Duration::ZERO,
    }
}

/// The listener a legacy connect to `target` reaches.
fn legacy_listener(target: SocketAddr, timeout: Option<Duration>) -> io::Result<SocketAddr> {
    if !is_ip_addr_valid(target.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "invalid target address",
        ));
    }
    let listener_addr = find_tcp_listener(target)
        .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "no listener available"))?;
    match listener_behavior(listener_addr) {
        ListenerBehavior::Accepting => {}
        ListenerBehavior::Refusing => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "listener configured to refuse",
            ));
        }
        ListenerBehavior::DelayingUntil(deadline) => {
            wait_delaying(listener_addr, deadline, timeout)?;
        }
    }
    Ok(listener_addr)
}

/// Block until a [`ListenerBehavior::DelayingUntil`] listener's deadline (or
/// until the listener changes) — "SYN dropped, retry until backoff".
fn wait_delaying(
    listener_addr: SocketAddr,
    deadline: Instant,
    timeout: Option<Duration>,
) -> io::Result<()> {
    let ticket = WaitTicket::register([WaitKey::Listener(listener_addr)]);
    let now = Instant::now();
    if deadline > now {
        let until = timeout.map_or(deadline, |t| deadline.min(now + t));
        ticket.wait(Some(until), "tcp connect");
        if Instant::now() < deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "listener delaying accept",
            ));
        }
    }
    Ok(())
}

/// The listener a blocking connect to `target` reaches under `os`'s
/// semantics. With no accepting listener the connect retries in virtual time
/// as `os` does: an address the host owns refuses (at once, or after
/// Windows' two-second retry), any other routable address stays silent
/// until the SYN retransmissions give up. A listener that appears meanwhile
/// is taken; `timeout` caps the wait with std's own `TimedOut` error.
fn faithful_listener(
    os: OsSemantics,
    target: SocketAddr,
    timeout: Option<Duration>,
) -> io::Result<SocketAddr> {
    let start = Instant::now();
    let cap = timeout.map(|t| start + t);
    let wildcard = SocketAddr::new(
        match target {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        },
        target.port(),
    );
    let mut give_up: Option<(Instant, Errno)> = None;
    loop {
        let ticket = WaitTicket::register([WaitKey::Listener(target), WaitKey::Listener(wildcard)]);
        let found = find_tcp_listener(target);
        match found.map(|l| (l, listener_behavior(l))) {
            Some((l, ListenerBehavior::Accepting)) => return Ok(l),
            Some((l, ListenerBehavior::DelayingUntil(deadline))) => {
                drop(ticket);
                wait_delaying(l, deadline, timeout)?;
                return Ok(l);
            }
            Some((_, ListenerBehavior::Refusing)) | None => {}
        }
        let (at, err) = match give_up {
            Some(g) => g,
            None => {
                let fate = match found {
                    Some(_) => SynFate::Refused,
                    None => tcp_syn_fate(target)?,
                };
                let g = match fate {
                    SynFate::Refused => (start + refused_after(os), Errno::ConnRefused),
                    SynFate::Silent => (start + syn_give_up(os), Errno::TimedOut),
                };
                *give_up.insert(g)
            }
        };
        let now = Instant::now();
        if let Some(cap) = cap.filter(|c| *c < at)
            && now >= cap
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection timed out",
            ));
        }
        if now >= at {
            return Err(os_err_for(os, err));
        }
        ticket.wait(Some(cap.map_or(at, |c| c.min(at))), "tcp connect");
    }
}

/// Park on `ticket` until notified or until the operation's virtual timeout
/// (armed on the first wait) passes. A timeout that has already passed is
/// reported as a real socket's `SO_RCVTIMEO` reports it.
fn wait_ready(
    ticket: WaitTicket,
    timeout: Option<Duration>,
    deadline: &mut Option<Instant>,
    wait: &'static str,
) -> io::Result<()> {
    let target = match timeout {
        Some(d) => Some(*deadline.get_or_insert_with(|| Instant::now() + d)),
        None => {
            *deadline = None;
            None
        }
    };
    if target.is_some_and(|t| Instant::now() >= t) {
        return Err(timed_out());
    }
    ticket.wait(target, wait);
    Ok(())
}
