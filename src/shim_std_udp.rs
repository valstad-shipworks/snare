use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::resolve::ToSocketAddrs;

use crate::mcast::{McastIf, McastOp, McastState};
use crate::netif::SocketId;
use crate::os::{Errno, OsSemantics, os_err_for};
use crate::sched::waitset::{WaitKey, WaitTicket};
use crate::state::{os_ctx, udp_take};
use crate::time::Instant;

#[derive(Debug, Clone, Copy)]
enum UdpConfigs {
    ReadTimeout(Duration),
    WriteTimeout(Duration),
    Broadcast,
    IpTtl(u32),
    NonBlocking,
}

#[derive(Debug)]
pub struct ShimStdUdpSocket {
    handle: Arc<UdpHandle>,
    bound_addr: SocketAddr,
}

/// The state every clone of one socket shares. The socket closes when the
/// last clone drops.
#[derive(Debug)]
struct UdpHandle {
    id: SocketId,
    remote_addr: Mutex<Option<SocketAddr>>,
    configs: Mutex<Vec<UdpConfigs>>,
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        crate::state::drop_udp_socket(self.id);
    }
}

/// Returns `-1`: there is no kernel socket behind the shim. Raw syscalls on
/// it fail with `EBADF`, so a SUT probing socket capabilities through the fd
/// falls back to the portable std API, which the shim does implement. A real
/// dummy fd would be worse — option probes would succeed and the SUT would
/// then read from an empty kernel socket instead of the virtual network.
#[cfg(unix)]
impl std::os::fd::AsRawFd for ShimStdUdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}

impl ShimStdUdpSocket {
    fn set_option(&self, config: UdpConfigs) {
        self.del_option(config);
        let mut configs = self.handle.configs.lock().unwrap();
        configs.push(config);
    }

    fn del_option(&self, config_type: UdpConfigs) {
        let mut configs = self.handle.configs.lock().unwrap();
        configs.retain(|c| std::mem::discriminant(c) != std::mem::discriminant(&config_type));
    }

    fn get_option(&self, config_type: UdpConfigs) -> Option<UdpConfigs> {
        let configs = self.handle.configs.lock().unwrap();
        for c in configs.iter() {
            if std::mem::discriminant(c) == std::mem::discriminant(&config_type) {
                return Some(*c);
            }
        }
        None
    }

    #[doc(alias = "std::net::UdpSocket::bind")]
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let mut last_err = None;
        for a in addr.to_socket_addrs()? {
            // Port 0 means "any port" — reserve a concrete ephemeral one so the
            // source port on outgoing datagrams routes replies back (a GVCP/GVSP
            // camera client binds `0.0.0.0:0`). Device servers bind a concrete
            // IP and are unaffected.
            match crate::state::bind_udp(a) {
                Ok((id, bound)) => {
                    return Ok(ShimStdUdpSocket {
                        handle: Arc::new(UdpHandle {
                            id,
                            remote_addr: Mutex::new(None),
                            configs: Mutex::new(Vec::new()),
                        }),
                        bound_addr: bound,
                    });
                }
                Err(Some(e)) => last_err = Some(e),
                Err(None) => {}
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        }))
    }

    pub(crate) fn id(&self) -> SocketId {
        self.handle.id
    }

    /// Take the next datagram with its arrival metadata, waiting as
    /// `recv_from` does unless `never_wait` or the socket is nonblocking.
    /// `None` when that would block.
    #[cfg(feature = "fast-talker-core")]
    pub(crate) fn take_packet(
        &self,
        never_wait: bool,
        effect: &'static str,
    ) -> io::Result<Option<crate::state::RxPacket>> {
        let nonblocking = never_wait || self.is_nonblocking();
        let mut deadline = None;
        let mut ticket = None;
        loop {
            if let Some(pkt) = crate::state::udp_take_packet(self.handle.id, None, true)? {
                crate::sched::class_effect(effect);
                return Ok(Some(pkt));
            }
            if nonblocking {
                return Ok(None);
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Udp(self.bound_addr)])),
                Some(t) => {
                    let timeout = self.read_timeout()?;
                    self.wait_for_incoming(t, timeout, &mut deadline)?;
                }
            }
        }
    }

    /// Whether the socket has broadcast permission (`SO_BROADCAST`).
    #[cfg(feature = "fast-talker-core")]
    pub(crate) fn broadcast_ok(&self) -> bool {
        self.get_option(UdpConfigs::Broadcast).is_some()
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        let mut ticket = None;
        loop {
            if let Some((data, addr)) = self.pop_incoming_packet(None)? {
                let copied = Self::copy_into(buf, &data)?;
                return Ok((copied, addr));
            }
            if nonblocking {
                return Err(would_block());
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Udp(self.bound_addr)])),
                Some(t) => {
                    let timeout = self.read_timeout()?;
                    self.wait_for_incoming(t, timeout, &mut deadline)?;
                }
            }
        }
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        let mut ticket = None;
        loop {
            if let Some((data, addr)) = self.peek_incoming_packet(None)? {
                let copied = Self::copy_into(buf, &data)?;
                return Ok((copied, addr));
            }
            if nonblocking {
                return Err(would_block());
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Udp(self.bound_addr)])),
                Some(t) => {
                    let timeout = self.read_timeout()?;
                    self.wait_for_incoming(t, timeout, &mut deadline)?;
                }
            }
        }
    }

    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        crate::sched::note_effect("udp send");
        if buf.len() > i32::MAX as usize {
            unimplemented!("partial writes of massive buffers");
        }
        let first_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        })?;
        family_check(self.bound_addr, first_addr, false)?;
        crate::state::udp_send(
            self.handle.id,
            self.bound_addr,
            buf,
            first_addr,
            self.get_option(UdpConfigs::Broadcast).is_some(),
        )
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        let remote_addr = self.handle.remote_addr.lock().unwrap();
        remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound_addr)
    }

    pub fn try_clone(&self) -> io::Result<ShimStdUdpSocket> {
        Ok(ShimStdUdpSocket {
            handle: Arc::clone(&self.handle),
            bound_addr: self.bound_addr,
        })
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        if let Some(d) = dur {
            if d.as_secs() == 0 && d.subsec_nanos() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duration must be non-zero",
                ));
            }
            self.set_option(UdpConfigs::ReadTimeout(d));
        } else {
            self.del_option(UdpConfigs::ReadTimeout(Duration::from_secs(0)));
        }
        Ok(())
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        if let Some(d) = dur {
            if d.as_secs() == 0 && d.subsec_nanos() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duration must be non-zero",
                ));
            }
            self.set_option(UdpConfigs::WriteTimeout(d));
        } else {
            self.del_option(UdpConfigs::WriteTimeout(Duration::from_secs(0)));
        }
        Ok(())
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        if let Some(UdpConfigs::ReadTimeout(dur)) =
            self.get_option(UdpConfigs::ReadTimeout(Duration::from_secs(0)))
        {
            Ok(Some(dur))
        } else {
            Ok(None)
        }
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        if let Some(UdpConfigs::WriteTimeout(dur)) =
            self.get_option(UdpConfigs::WriteTimeout(Duration::from_secs(0)))
        {
            Ok(Some(dur))
        } else {
            Ok(None)
        }
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        if broadcast {
            self.set_option(UdpConfigs::Broadcast);
        } else {
            self.del_option(UdpConfigs::Broadcast);
        }
        Ok(())
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        if self.get_option(UdpConfigs::Broadcast).is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        self.mcast(|m| m.loop_v4 = multicast_loop_v4)
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        self.mcast(|m| m.loop_v4)
    }

    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        if multicast_ttl_v4 > 255 {
            return Err(crate::os::os_err(Errno::Inval));
        }
        self.mcast(|m| m.ttl_v4 = multicast_ttl_v4)
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        self.mcast(|m| m.ttl_v4)
    }

    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        self.mcast(|m| m.loop_v6 = multicast_loop_v6)
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        self.mcast(|m| m.loop_v6)
    }

    fn mcast<R>(&self, f: impl FnOnce(&mut McastState) -> R) -> io::Result<R> {
        crate::mcast::with_mcast(self.handle.id, |_, c| Ok(f(&mut c.mcast)))
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.set_option(UdpConfigs::IpTtl(ttl));
        Ok(())
    }

    pub fn ttl(&self) -> io::Result<u32> {
        if let Some(UdpConfigs::IpTtl(ttl)) = self.get_option(UdpConfigs::IpTtl(0)) {
            Ok(ttl)
        } else {
            Ok(64)
        }
    }

    /// Joins `multiaddr` on the interface owning the address `interface`, or
    /// the one routing picks for `0.0.0.0`.
    pub fn join_multicast_v4(
        &self,
        multiaddr: &std::net::Ipv4Addr,
        interface: &std::net::Ipv4Addr,
    ) -> io::Result<()> {
        self.membership_v4(McastOp::Join, multiaddr, interface)
    }

    pub fn leave_multicast_v4(
        &self,
        multiaddr: &std::net::Ipv4Addr,
        interface: &std::net::Ipv4Addr,
    ) -> io::Result<()> {
        self.membership_v4(McastOp::Leave, multiaddr, interface)
    }

    /// Joins `multiaddr` on the interface with index `interface`, or the one
    /// routing picks for 0.
    pub fn join_multicast_v6(
        &self,
        multiaddr: &std::net::Ipv6Addr,
        interface: u32,
    ) -> io::Result<()> {
        self.membership_v6(McastOp::Join, multiaddr, interface)
    }

    pub fn leave_multicast_v6(
        &self,
        multiaddr: &std::net::Ipv6Addr,
        interface: u32,
    ) -> io::Result<()> {
        self.membership_v6(McastOp::Leave, multiaddr, interface)
    }

    fn membership_v4(
        &self,
        op: McastOp,
        group: &std::net::Ipv4Addr,
        interface: &std::net::Ipv4Addr,
    ) -> io::Result<()> {
        crate::mcast::membership(
            self.handle.id,
            op,
            IpAddr::V4(*group),
            None,
            McastIf::Addr(IpAddr::V4(*interface)),
        )
    }

    fn membership_v6(
        &self,
        op: McastOp,
        group: &std::net::Ipv6Addr,
        interface: u32,
    ) -> io::Result<()> {
        crate::mcast::membership(
            self.handle.id,
            op,
            IpAddr::V6(*group),
            None,
            McastIf::Index(interface),
        )
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        crate::state::udp_take_error(self.handle.id)
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        let first_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        })?;
        family_check(self.bound_addr, first_addr, true)?;
        crate::state::udp_connect(self.handle.id, first_addr)?;
        let mut remote_addr = self.handle.remote_addr.lock().unwrap();
        *remote_addr = Some(first_addr);
        Ok(())
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let remote_addr = self.handle.remote_addr.lock().unwrap();
        let addr = remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))?;
        self.send_to(buf, addr)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let addr = self.peer_addr()?;
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        let mut ticket = None;
        loop {
            if let Some((data, _)) = self.pop_incoming_packet(Some(addr))? {
                let copied = Self::copy_into(buf, &data)?;
                return Ok(copied);
            }
            if nonblocking {
                return Err(would_block());
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Udp(self.bound_addr)])),
                Some(t) => {
                    let timeout = self.read_timeout()?;
                    self.wait_for_incoming(t, timeout, &mut deadline)?;
                }
            }
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let addr = self.peer_addr()?;
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        let mut ticket = None;
        loop {
            if let Some((data, _)) = self.peek_incoming_packet(Some(addr))? {
                let copied = Self::copy_into(buf, &data)?;
                return Ok(copied);
            }
            if nonblocking {
                return Err(would_block());
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register([WaitKey::Udp(self.bound_addr)])),
                Some(t) => {
                    let timeout = self.read_timeout()?;
                    self.wait_for_incoming(t, timeout, &mut deadline)?;
                }
            }
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        if nonblocking {
            self.set_option(UdpConfigs::NonBlocking);
        } else {
            self.del_option(UdpConfigs::NonBlocking);
        }
        Ok(())
    }

    fn is_nonblocking(&self) -> bool {
        self.get_option(UdpConfigs::NonBlocking).is_some()
    }

    fn pop_incoming_packet(
        &self,
        source_filter: Option<SocketAddr>,
    ) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        let packet = udp_take(self.handle.id, source_filter, true)?;
        if packet.is_some() {
            crate::sched::class_effect("udp recv");
        }
        Ok(packet)
    }

    fn peek_incoming_packet(
        &self,
        source_filter: Option<SocketAddr>,
    ) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        udp_take(self.handle.id, source_filter, false)
    }

    /// Park on `ticket` until the socket is notified or the virtual read
    /// timeout (armed on the first wait) passes. A passed timeout is
    /// `SO_RCVTIMEO`'s error: `EAGAIN`, or `WSAETIMEDOUT` on Windows.
    fn wait_for_incoming(
        &self,
        ticket: WaitTicket,
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
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
        ticket.wait(target, "udp read");
        Ok(())
    }

    /// Copy a datagram into `buf`. A datagram longer than `buf` is truncated;
    /// Windows then also reports `WSAEMSGSIZE`.
    pub(crate) fn copy_into(buf: &mut [u8], data: &[u8]) -> io::Result<usize> {
        let amount = buf.len().min(data.len());
        if amount > 0 {
            buf[..amount].copy_from_slice(&data[..amount]);
        }
        if amount < data.len() {
            let (os, faithful) = os_ctx();
            if faithful && os == OsSemantics::Windows {
                return Err(os_err_for(os, Errno::MsgSize));
            }
        }
        Ok(amount)
    }
}

/// An IPv4 socket cannot address an IPv6 destination, not even a
/// v4-mapped one. Linux refuses with `EAFNOSUPPORT`. macOS refuses `connect`
/// with `EINVAL`, and `send_to` with `EHOSTUNREACH` from a socket bound to a
/// specific address or `EINVAL` from a wildcard one. Windows refuses with
/// `WSAEAFNOSUPPORT`.
pub(crate) fn family_check(bound: SocketAddr, dst: SocketAddr, connect: bool) -> io::Result<()> {
    if bound.is_ipv6() || dst.is_ipv4() {
        return Ok(());
    }
    let os = os_ctx().0;
    let errno = match os {
        OsSemantics::MacOs if connect || bound.ip().is_unspecified() => Errno::Inval,
        OsSemantics::MacOs => Errno::HostUnreach,
        OsSemantics::Linux | OsSemantics::Windows => Errno::AfNoSupport,
    };
    Err(os_err_for(os, errno))
}

/// A nonblocking operation that found nothing to do.
pub(crate) fn would_block() -> io::Error {
    match os_ctx() {
        (os, true) => os_err_for(os, Errno::WouldBlock),
        _ => io::Error::from(io::ErrorKind::WouldBlock),
    }
}

/// A blocking operation whose `SO_RCVTIMEO` / `SO_SNDTIMEO` passed.
pub(crate) fn timed_out() -> io::Error {
    match os_ctx() {
        (OsSemantics::Windows, true) => os_err_for(OsSemantics::Windows, Errno::TimedOut),
        (os, true) => os_err_for(os, Errno::WouldBlock),
        _ => io::Error::from(io::ErrorKind::WouldBlock),
    }
}
