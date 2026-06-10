use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::state::{
    Packet, add_udp_connection, is_ip_addr_valid, is_port_available, wait_for_event,
    with_udp_connection,
};

#[derive(Debug, Clone, Copy)]
enum UdpConfigs {
    ReadTimeout(Duration),
    WriteTimeout(Duration),
    Broadcast,
    Ipv4MulticastLoop,
    Ipv6MulticastLoop,
    IpMulticastTtl(u32),
    IpTtl(u32),
    NonBlocking,
}

#[derive(Debug)]
pub struct ShimStdUdpSocket {
    bound_addr: SocketAddr,
    remote_addr: Arc<Mutex<Option<SocketAddr>>>,
    configs: Arc<Mutex<Vec<UdpConfigs>>>,
}

impl ShimStdUdpSocket {
    fn set_option(&self, config: UdpConfigs) {
        self.del_option(config);
        let mut configs = self.configs.lock().unwrap();
        configs.push(config);
    }

    fn del_option(&self, config_type: UdpConfigs) {
        let mut configs = self.configs.lock().unwrap();
        configs.retain(|c| std::mem::discriminant(c) != std::mem::discriminant(&config_type));
    }

    fn get_option(&self, config_type: UdpConfigs) -> Option<UdpConfigs> {
        let configs = self.configs.lock().unwrap();
        for c in configs.iter() {
            if std::mem::discriminant(c) == std::mem::discriminant(&config_type) {
                return Some(*c);
            }
        }
        None
    }

    #[doc(alias = "std::net::UdpSocket::bind")]
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        for a in addr.to_socket_addrs()? {
            if !is_ip_addr_valid(a.ip()) {
                continue;
            }
            if !is_port_available(a.port()) {
                continue;
            }
            add_udp_connection(a);
            return Ok(ShimStdUdpSocket {
                bound_addr: a,
                remote_addr: Arc::new(Mutex::new(None)),
                configs: Arc::new(Mutex::new(Vec::new())),
            });
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        ))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        loop {
            if let Some((data, addr)) = self.pop_incoming_packet(None)? {
                let copied = Self::copy_into(buf, &data);
                return Ok((copied, addr));
            }
            if nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available",
                ));
            }
            let timeout = self.read_timeout()?;
            self.wait_for_incoming(timeout, &mut deadline)?;
        }
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        loop {
            if let Some((data, addr)) = self.peek_incoming_packet(None)? {
                let copied = Self::copy_into(buf, &data);
                return Ok((copied, addr));
            }
            if nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available",
                ));
            }
            let timeout = self.read_timeout()?;
            self.wait_for_incoming(timeout, &mut deadline)?;
        }
    }

    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        if buf.len() > i32::MAX as usize {
            unimplemented!("partial writes of massive buffers");
        }
        let first_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        })?;
        // Pre-check destruction; the policy-aware enqueue does the rest
        // (MTU rejection, send-queue cap, etc).
        with_udp_connection(self.bound_addr, |conn| {
            if conn.is_destroyed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection destroyed",
                ));
            }
            Ok(())
        })?;
        crate::state::enqueue_udp_outbound(
            self.bound_addr,
            Packet {
                data: buf.to_vec(),
                dest: first_addr,
                source: self.bound_addr,
            },
        )?;
        Ok(buf.len())
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        let remote_addr = self.remote_addr.lock().unwrap();
        remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound_addr)
    }

    pub fn try_clone(&self) -> io::Result<ShimStdUdpSocket> {
        Ok(ShimStdUdpSocket {
            bound_addr: self.bound_addr,
            remote_addr: Arc::clone(&self.remote_addr),
            configs: Arc::clone(&self.configs),
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
        if let Some(_) = self.get_option(UdpConfigs::Broadcast) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        if multicast_loop_v4 {
            self.set_option(UdpConfigs::Ipv4MulticastLoop);
        } else {
            self.del_option(UdpConfigs::Ipv4MulticastLoop);
        }
        Ok(())
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        if let Some(_) = self.get_option(UdpConfigs::Ipv4MulticastLoop) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        self.set_option(UdpConfigs::IpMulticastTtl(multicast_ttl_v4));
        Ok(())
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        if let Some(UdpConfigs::IpMulticastTtl(ttl)) =
            self.get_option(UdpConfigs::IpMulticastTtl(0))
        {
            Ok(ttl)
        } else {
            Ok(1)
        }
    }

    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        if multicast_loop_v6 {
            self.set_option(UdpConfigs::Ipv6MulticastLoop);
        } else {
            self.del_option(UdpConfigs::Ipv6MulticastLoop);
        }
        Ok(())
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        if let Some(_) = self.get_option(UdpConfigs::Ipv6MulticastLoop) {
            Ok(true)
        } else {
            Ok(false)
        }
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

    pub fn join_multicast_v4(
        &self,
        _multiaddr: &std::net::Ipv4Addr,
        _interface: &std::net::Ipv4Addr,
    ) -> io::Result<()> {
        unimplemented!("join_multicast_v4 is not implemented in ShimStdUdpSocket");
    }

    pub fn leave_multicast_v4(
        &self,
        _multiaddr: &std::net::Ipv4Addr,
        _interface: &std::net::Ipv4Addr,
    ) -> io::Result<()> {
        unimplemented!("leave_multicast_v4 is not implemented in ShimStdUdpSocket");
    }

    pub fn join_multicast_v6(
        &self,
        _multiaddr: &std::net::Ipv6Addr,
        _interface: u32,
    ) -> io::Result<()> {
        unimplemented!("join_multicast_v6 is not implemented in ShimStdUdpSocket");
    }

    pub fn leave_multicast_v6(
        &self,
        _multiaddr: &std::net::Ipv6Addr,
        _interface: u32,
    ) -> io::Result<()> {
        unimplemented!("leave_multicast_v6 is not implemented in ShimStdUdpSocket");
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        with_udp_connection(self.bound_addr, |conn| Ok(conn.external_error.take()))
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        let first_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        })?;
        let mut remote_addr = self.remote_addr.lock().unwrap();
        *remote_addr = Some(first_addr);
        Ok(())
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let remote_addr = self.remote_addr.lock().unwrap();
        let addr = remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))?;
        self.send_to(buf, addr)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let remote_addr = self.remote_addr.lock().unwrap();
        let addr = remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))?;
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        loop {
            if let Some((data, _)) = self.pop_incoming_packet(Some(addr))? {
                let copied = Self::copy_into(buf, &data);
                return Ok(copied);
            }
            if nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available from connected address",
                ));
            }
            let timeout = self.read_timeout()?;
            self.wait_for_incoming(timeout, &mut deadline)?;
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let remote_addr = self.remote_addr.lock().unwrap();
        let addr = remote_addr
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no remote address set"))?;
        let nonblocking = self.is_nonblocking();
        let mut deadline = None;
        loop {
            if let Some((data, _)) = self.peek_incoming_packet(Some(addr))? {
                let copied = Self::copy_into(buf, &data);
                return Ok(copied);
            }
            if nonblocking {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available from connected address",
                ));
            }
            let timeout = self.read_timeout()?;
            self.wait_for_incoming(timeout, &mut deadline)?;
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
        with_udp_connection(self.bound_addr, |conn| {
            if conn.is_destroyed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection destroyed",
                ));
            }
            let packet = match source_filter {
                Some(addr) => conn
                    .to_local
                    .iter()
                    .position(|pkt| pkt.source == addr)
                    .and_then(|idx| conn.to_local.remove(idx)),
                None => conn.to_local.pop_front(),
            };
            Ok(packet.map(|pkt| (pkt.data, pkt.source)))
        })
    }

    fn peek_incoming_packet(
        &self,
        source_filter: Option<SocketAddr>,
    ) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        with_udp_connection(self.bound_addr, |conn| {
            if conn.is_destroyed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection destroyed",
                ));
            }
            let packet = match source_filter {
                Some(addr) => conn
                    .to_local
                    .iter()
                    .find(|pkt| pkt.source == addr)
                    .map(|pkt| (pkt.data.clone(), pkt.source)),
                None => conn
                    .to_local
                    .front()
                    .map(|pkt| (pkt.data.clone(), pkt.source)),
            };
            Ok(packet)
        })
    }

    fn wait_for_incoming(
        &self,
        timeout: Option<Duration>,
        deadline: &mut Option<Instant>,
    ) -> io::Result<()> {
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
            let remaining = target - now;
            if !wait_for_event(Some(remaining)) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "operation timed out",
                ));
            }
        } else {
            *deadline = None;
            wait_for_event(None);
        }
        Ok(())
    }

    fn copy_into(buf: &mut [u8], data: &[u8]) -> usize {
        let amount = buf.len().min(data.len());
        if amount > 0 {
            buf[..amount].copy_from_slice(&data[..amount]);
        }
        amount
    }
}
