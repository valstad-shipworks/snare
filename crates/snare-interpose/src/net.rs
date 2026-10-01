//! A per-domain network backend. When a domain has one, the socket and fd hooks offer each call
//! to it before the OS. The backend services the file descriptors it owns from its own state
//! (an in-memory fabric, for tests) and declines the rest, which then go to the real OS.
//!
//! Every method returns `Option<i64>`: `Some(n)` handles the call with the kernel's return
//! convention (a negative errno on failure); `None` declines it. Methods carry raw pointers and
//! are `unsafe` — the caller is the interposed libc entry point, so the pointers are whatever the
//! application passed.

use core::ffi::{c_char, c_int};

/// The result of a handled call: a non-negative return, or an errno to fail with.
pub enum NetResult {
    Ok(i64),
    Err(c_int),
}

impl NetResult {
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn into_raw(self) -> i64 {
        match self {
            NetResult::Ok(n) => n,
            // Raw kernel syscall ABI: an error is a negative errno in the return register, which
            // the libc wrapper turns into -1 + errno (syscall(2) NOTES; intro(2)).
            NetResult::Err(errno) => -(errno as i64),
        }
    }
}

/// Convenience: turn an `io`-style result into a handled call.
impl From<std::io::Result<i64>> for NetResult {
    fn from(result: std::io::Result<i64>) -> Self {
        const EIO: c_int = 5;
        match result {
            Ok(n) => NetResult::Ok(n),
            Err(e) => NetResult::Err(e.raw_os_error().unwrap_or(EIO)),
        }
    }
}

/// A network the interposer routes a managed thread's socket calls to.
///
/// All methods default to declining. A backend implements the ones it models. `owns` is the fast
/// path for the generic fd calls (`read`, `write`, `close`, `fcntl`): it must be cheap and must
/// answer for every fd the backend handed out.
#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Net: Send + Sync + 'static {
    fn owns(&self, fd: c_int) -> bool {
        false
    }

    /// Models `socket(2)`; `domain`, `ty` and `protocol` are `AF_*`/`SOCK_*`/`IPPROTO_*` from
    /// `<sys/socket.h>` and `<netinet/in.h>`.
    ///
    /// # Safety
    /// Called from the `socket` hook; no pointers are involved.
    unsafe fn socket(&self, domain: c_int, ty: c_int, protocol: c_int) -> Option<NetResult> {
        None
    }

    /// Models `connect(2)`; `addr` is a `struct sockaddr` (`<sys/socket.h>`; `sockaddr_in` in
    /// `<netinet/in.h>`) and `len` its `socklen_t` length.
    ///
    /// # Safety
    /// `addr` points to `len` bytes of a `sockaddr`.
    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        None
    }

    /// Models `bind(2)`.
    ///
    /// # Safety
    /// As for [`connect`](Self::connect).
    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        None
    }

    /// Models `listen(2)`; `backlog` caps the completed-connection queue.
    unsafe fn listen(&self, fd: c_int, backlog: c_int) -> Option<NetResult> {
        None
    }

    /// Models `accept(2)`; a non-zero `flags` is the Linux `accept4(2)` extension
    /// (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`).
    ///
    /// # Safety
    /// `addr`/`addr_len`, when non-null, receive the peer address.
    unsafe fn accept(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
        flags: c_int,
    ) -> Option<NetResult> {
        None
    }

    /// Models `send(2)`; `flags` are `MSG_*` from `<sys/socket.h>`.
    ///
    /// # Safety
    /// `buf` points to `len` readable bytes.
    unsafe fn send(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
    ) -> Option<NetResult> {
        None
    }

    /// Models `recv(2)`.
    ///
    /// # Safety
    /// `buf` points to `len` writable bytes.
    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        None
    }

    /// Models `sendto(2)`.
    ///
    /// # Safety
    /// `buf` readable; `addr`/`addr_len` a destination sockaddr.
    unsafe fn sendto(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
        addr: *const u8,
        addr_len: u32,
    ) -> Option<NetResult> {
        None
    }

    /// Models `recvfrom(2)`.
    ///
    /// # Safety
    /// `buf` writable; `addr`/`addr_len` receive the source sockaddr.
    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        None
    }

    /// Models `shutdown(2)`; `how` is `SHUT_RD`/`SHUT_WR`/`SHUT_RDWR` (`<sys/socket.h>`).
    unsafe fn shutdown(&self, fd: c_int, how: c_int) -> Option<NetResult> {
        None
    }

    /// Models `close(2)` for an owned socket fd.
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        None
    }

    /// Duplicates an owned socket, returning a new handle that refers to the same underlying
    /// socket (shared state). Backs Windows `WSADuplicateSocket`/`try_clone`; `None` declines.
    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        let _ = fd;
        None
    }

    /// Models `getsockname(2)`.
    ///
    /// # Safety
    /// `addr`/`addr_len` receive the local address.
    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        None
    }

    /// Models `getpeername(2)`.
    ///
    /// # Safety
    /// As for [`getsockname`](Self::getsockname), for the peer.
    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        None
    }

    /// Models `setsockopt(2)`; `level`/`name` follow `socket(7)` and `<sys/socket.h>` (`SOL_SOCKET`,
    /// `SO_*`), with protocol levels in `ip(7)`/`<netinet/in.h>` and `<netinet/tcp.h>`.
    ///
    /// # Safety
    /// `val` points to `len` (or `*len`) bytes of option data.
    unsafe fn setsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        None
    }

    /// Models `getsockopt(2)`.
    ///
    /// # Safety
    /// `val`/`len` receive the option value.
    unsafe fn getsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        None
    }

    /// `fcntl(fd, cmd, arg)` for an owned fd (nonblocking flag, fd flags, dup).
    ///
    /// Models `fcntl(2)`: `F_GETFL`/`F_SETFL` (`O_NONBLOCK`), `F_GETFD`/`F_SETFD` (`FD_CLOEXEC`),
    /// `F_DUPFD`/`F_DUPFD_CLOEXEC` (`<fcntl.h>`).
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        None
    }

    /// `ioctl(fd, request, arg)` for an owned fd (`FIONBIO`, `FIONREAD`).
    ///
    /// Models `ioctl(2)`; `FIONBIO`/`FIONREAD` are defined in `<sys/ioctl.h>`
    /// (`<asm-generic/ioctls.h>` on Linux).
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        None
    }

    /// Models `poll(2)`; `fds` is an array of `nfds` `struct pollfd` (`<poll.h>`), `timeout` in ms.
    ///
    /// # Safety
    /// `fds` points to `nfds` `pollfd` structs.
    unsafe fn poll(&self, fds: *mut u8, nfds: u64, timeout: c_int) -> Option<NetResult> {
        None
    }

    /// Models `read(2)` on an owned socket fd.
    ///
    /// # Safety
    /// `buf` writable. Defaults to `recv` with no flags.
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        // SAFETY: forwarded contract.
        unsafe { self.recv(fd, buf, len, 0) }
    }

    /// Models `write(2)` on an owned socket fd.
    ///
    /// # Safety
    /// `buf` readable. Defaults to `send` with no flags.
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        // SAFETY: forwarded contract.
        unsafe { self.send(fd, buf, len, 0) }
    }

    /// `eventfd(initval, flags)`: a counting fd for readiness wakeups (Linux).
    ///
    /// Models `eventfd2(2)`; `flags` are `EFD_NONBLOCK`/`EFD_CLOEXEC`/`EFD_SEMAPHORE`
    /// (`<sys/eventfd.h>`).
    unsafe fn eventfd(&self, initval: u32, flags: c_int) -> Option<NetResult> {
        let _ = (initval, flags);
        None
    }

    /// `epoll_create1(flags)`: a readiness set (Linux).
    ///
    /// Models `epoll_create1(2)`; `EPOLL_CLOEXEC` from `<sys/epoll.h>`. See `epoll(7)`.
    unsafe fn epoll_create1(&self, flags: c_int) -> Option<NetResult> {
        let _ = flags;
        None
    }

    /// `epoll_ctl(epfd, op, fd, event)`: add, modify, or remove interest in `fd`.
    ///
    /// Models `epoll_ctl(2)`; `op` is `EPOLL_CTL_ADD`/`_MOD`/`_DEL` and `event` a
    /// `struct epoll_event` (`EPOLLIN`, `EPOLLET`, … in `<sys/epoll.h>`).
    ///
    /// # Safety
    /// `event` points to an `epoll_event` for add/modify, and may be null for delete.
    unsafe fn epoll_ctl(
        &self,
        epfd: c_int,
        op: c_int,
        fd: c_int,
        event: *const u8,
    ) -> Option<NetResult> {
        let _ = (epfd, op, fd, event);
        None
    }

    /// `epoll_wait(epfd, events, maxevents, timeout)`: wait for readiness.
    ///
    /// Models `epoll_wait(2)`; `timeout` is in ms (`-1` blocks).
    ///
    /// # Safety
    /// `events` points to `maxevents` `epoll_event` slots.
    unsafe fn epoll_wait(
        &self,
        epfd: c_int,
        events: *mut u8,
        maxevents: c_int,
        timeout: c_int,
    ) -> Option<NetResult> {
        let _ = (epfd, events, maxevents, timeout);
        None
    }

    /// `kqueue()`: a readiness set (macOS/BSD), the kqueue(2) analogue of `epoll_create1`.
    unsafe fn kqueue(&self) -> Option<NetResult> {
        None
    }

    /// `kevent(kq, changelist, nchanges, eventlist, nevents, timeout)`: apply the interest changes
    /// in `changelist`, then wait for and return up to `nevents` ready events. Models `kevent(2)`
    /// (`<sys/event.h>`): each entry is a `struct kevent { ident, filter, flags, fflags, data,
    /// udata }` with `EVFILT_READ`/`EVFILT_WRITE`/`EVFILT_USER` filters and `EV_ADD`/`EV_DELETE`/
    /// `EV_CLEAR`/`EV_RECEIPT` flags; `timeout` is a `*const timespec` (null blocks). What `mio`'s
    /// selector uses on macOS.
    ///
    /// # Safety
    /// `changelist`/`eventlist` point to `nchanges`/`nevents` `kevent` structs; `timeout` to a
    /// `timespec` or is null.
    unsafe fn kevent(
        &self,
        kq: c_int,
        changelist: *const u8,
        nchanges: c_int,
        eventlist: *mut u8,
        nevents: c_int,
        timeout: *const u8,
    ) -> Option<NetResult> {
        let _ = (kq, changelist, nchanges, eventlist, nevents, timeout);
        None
    }

    /// `if_nametoindex(name)`: resolve an interface name to its index. `Ok(index)`, or `Ok(0)`
    /// with errno set (the C convention for this call) when the name is unknown.
    ///
    /// Models `if_nametoindex(3)` (POSIX; `<net/if.h>`).
    ///
    /// # Safety
    /// `name` is the caller's NUL-terminated interface name.
    unsafe fn if_nametoindex(&self, name: *const c_char) -> Option<NetResult> {
        let _ = name;
        None
    }

    /// `getifaddrs(ifap)`: build the interface-address linked list. On `Ok(0)` the backend has
    /// written a `*ifaddrs` head (allocated so [`freeifaddrs`](Self::freeifaddrs) can release it).
    ///
    /// Models `getifaddrs(3)`; the list is `struct ifaddrs` (`<ifaddrs.h>`), whose `ifa_data`
    /// carries `struct rtnl_link_stats` on Linux.
    ///
    /// # Safety
    /// `ifap` receives the head pointer.
    unsafe fn getifaddrs(&self, ifap: *mut *mut u8) -> Option<NetResult> {
        let _ = ifap;
        None
    }

    /// `freeifaddrs(ifa)`: release a list this backend produced.
    ///
    /// Models `freeifaddrs(3)`.
    ///
    /// # Safety
    /// `ifa` is a head previously returned by [`getifaddrs`](Self::getifaddrs).
    unsafe fn freeifaddrs(&self, ifa: *mut u8) -> Option<NetResult> {
        let _ = ifa;
        None
    }

    /// `sendmsg(fd, msg, flags)`: scatter-gather send carrying control messages (e.g. `SCM_TXTIME`).
    ///
    /// Models `sendmsg(2)`; `msg` is `struct msghdr` with control data parsed per `cmsg(3)`. The
    /// `SO_TXTIME`/`SCM_TXTIME` launch-time mechanism is defined in `<linux/net_tstamp.h>` (see
    /// `Documentation/networking/timestamping.rst` and `tc-etf(8)`).
    ///
    /// # Safety
    /// `msg` points to a `msghdr` describing the caller's iovec and control buffer.
    unsafe fn sendmsg(&self, fd: c_int, msg: *const u8, flags: c_int) -> Option<NetResult> {
        let _ = (fd, msg, flags);
        None
    }

    /// `recvmsg(fd, msg, flags)`: scatter-gather receive yielding control messages (e.g.
    /// `SCM_TIMESTAMPING`, or an error-queue entry under `MSG_ERRQUEUE`).
    ///
    /// Models `recvmsg(2)` with control data per `cmsg(3)`. `SO_TIMESTAMPING`/`SCM_TIMESTAMPING`
    /// (hardware/software RX/TX timestamps) follow `Documentation/networking/timestamping.rst` and
    /// `<linux/net_tstamp.h>`; `MSG_ERRQUEUE` drains the socket error queue (`ip(7)`).
    ///
    /// # Safety
    /// `msg` points to a `msghdr`; its iovec and control buffer receive the data.
    unsafe fn recvmsg(&self, fd: c_int, msg: *mut u8, flags: c_int) -> Option<NetResult> {
        let _ = (fd, msg, flags);
        None
    }

    /// `recvmmsg(fd, msgvec, vlen, flags, timeout)`: receive up to `vlen` messages at once.
    ///
    /// Models `recvmmsg(2)` (Linux); `msgvec` is an array of `struct mmsghdr` (a `msghdr` plus a
    /// received-length field) and `timeout` a `struct timespec`.
    ///
    /// # Safety
    /// `msgvec` points to `vlen` `mmsghdr` slots; `timeout`, when non-null, is a `timespec`.
    unsafe fn recvmmsg(
        &self,
        fd: c_int,
        msgvec: *mut u8,
        vlen: u32,
        flags: c_int,
        timeout: *mut u8,
    ) -> Option<NetResult> {
        let _ = (fd, msgvec, vlen, flags, timeout);
        None
    }

    // --- Windows raw L2 via `wpcap`/`npcap` (`pcap_*`). A capture handle is an opaque `pcap_t*`
    // carried here as `u64`; `Ok(handle)` claims it, `None` lets the real library take the call. ---

    /// `pcap_create(device, errbuf)` / `pcap_open_live(...)`: open a capture on `device` and return
    /// a handle in `Ok`. `device` is the caller's NUL-terminated interface name.
    ///
    /// libpcap / Npcap: `pcap_create(3PCAP)`, `pcap_open_live(3PCAP)`.
    ///
    /// # Safety
    /// `device` is a C string.
    unsafe fn pcap_open(&self, device: *const c_char) -> Option<NetResult> {
        let _ = device;
        None
    }

    /// `pcap_activate` / `pcap_set_immediate_mode` / `pcap_setnonblock`: configure an open handle.
    /// A modelled handle returns `Ok(0)`; an unknown one is declined so the real library sees it.
    ///
    /// libpcap / Npcap: `pcap_activate(3PCAP)`, `pcap_set_immediate_mode(3PCAP)`,
    /// `pcap_setnonblock(3PCAP)`.
    fn pcap_configure(&self, handle: u64) -> Option<NetResult> {
        let _ = handle;
        None
    }

    /// `pcap_sendpacket(handle, buf, len)`: transmit one raw frame. `Ok(0)` on success.
    ///
    /// libpcap / Npcap: `pcap_sendpacket(3PCAP)`.
    ///
    /// # Safety
    /// `buf` points to `len` readable bytes.
    unsafe fn pcap_send(&self, handle: u64, buf: *const u8, len: usize) -> Option<NetResult> {
        let _ = (handle, buf, len);
        None
    }

    /// `pcap_next_ex(handle, *header, *data)`: receive one frame. `Ok(1)` with `header`/`data`
    /// pointed at the captured packet, `Ok(0)` on timeout.
    ///
    /// libpcap / Npcap: `pcap_next_ex(3PCAP)`; `header` is a `struct pcap_pkthdr` (`<pcap/pcap.h>`).
    ///
    /// # Safety
    /// `header`/`data` receive pointers into capture-owned storage valid until the next call.
    unsafe fn pcap_next(
        &self,
        handle: u64,
        header: *mut *mut u8,
        data: *mut *const u8,
    ) -> Option<NetResult> {
        let _ = (handle, header, data);
        None
    }

    /// `pcap_close(handle)`: release a capture handle.
    ///
    /// libpcap / Npcap: `pcap_close(3PCAP)`.
    fn pcap_close(&self, handle: u64) -> Option<NetResult> {
        let _ = handle;
        None
    }
}
