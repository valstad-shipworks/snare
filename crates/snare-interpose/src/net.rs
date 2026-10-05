//! A per-domain network backend. When a domain has one, the socket and fd hooks offer each call
//! to it before the OS. The backend services the file descriptors it owns from its own state
//! (an in-memory fabric, for tests) and declines the rest, which then go to the real OS.
//!
//! Every method returns `Option<NetResult>`: `Some` handles the call, with [`NetResult::Ok`] the
//! call's return value and [`NetResult::Err`] the error it fails with; `None` declines it. Methods carry raw pointers and
//! are `unsafe` — the caller is the interposed libc entry point, so the pointers are whatever the
//! application passed.
//!
//! A backend runs with the calling thread in passthrough (see `domain::dispatch_net`), so its own
//! libc calls go to the OS. Backends are consulted in registration order and the first `Some`
//! wins; the error codes in `Err` are the platform's own (`errno` on Unix, `WSA*` on Windows).

use core::ffi::{c_char, c_int};

/// The result of a handled call: a non-negative return, or an errno to fail with.
#[derive(Debug)]
pub enum NetResult {
    /// The call's non-negative return value: a count, an fd, or a pointer cast to `i64`.
    Ok(i64),
    /// A positive error code: an `errno` value on Unix, a Winsock `WSA*` code on Windows.
    Err(c_int),
}

impl NetResult {
    /// Encodes the result as the raw kernel return: the value itself, or the negated error code.
    /// The unix hooks undo this with `os::sockets::finish`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn into_raw(self) -> i64 {
        match self {
            NetResult::Ok(n) => n,
            // Raw kernel syscall ABI: an error is a negative errno in the return register, which
            // the libc wrapper turns into -1 + errno (intro(2): "most system calls return a
            // negative error number", which the wrapper copies into errno, returning -1).
            NetResult::Err(errno) => -(errno as i64),
        }
    }
}

/// Convenience: turn an `io`-style result into a handled call.
impl From<std::io::Result<i64>> for NetResult {
    fn from(result: std::io::Result<i64>) -> Self {
        // EIO is 5 on Linux (include/uapi/asm-generic/errno-base.h), Darwin (<sys/errno.h>) and the
        // UCRT (<errno.h>); snare's fallback for an io::Error that carries no OS code.
        const EIO: c_int = 5;
        match result {
            Ok(n) => NetResult::Ok(n),
            Err(e) => NetResult::Err(e.raw_os_error().unwrap_or(EIO)),
        }
    }
}

#[cfg(windows)]
pub type CompletionQuery =
    unsafe extern "system" fn(*mut u8, *mut u8, u32, *mut u32, u32, i32) -> i32;
#[cfg(windows)]
pub type CompletionPost = unsafe extern "system" fn(*mut u8, *mut u8, *mut u8, i32, usize) -> i32;

#[cfg(windows)]
pub enum CompletionCall {
    Duplicate {
        handle: usize,
    },
    Associate {
        port: usize,
        afd: bool,
    },
    Register {
        file: usize,
        port: usize,
        key: usize,
        post: CompletionPost,
        afd: bool,
    },
    Notify {
        port: usize,
    },
    Close {
        handle: usize,
        native: unsafe extern "system" fn(*mut u8) -> i32,
    },
    Poll {
        file: usize,
        status: *mut u8,
        context: usize,
        input: *mut u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
    },
    Cancel {
        file: usize,
        status: *mut u8,
        result: *mut u8,
    },
    Get {
        port: usize,
        entries: *mut u8,
        count: u32,
        removed: *mut u32,
        timeout: u32,
        alertable: i32,
        query: CompletionQuery,
    },
}

/// A network the interposer routes a managed thread's socket calls to.
///
/// All methods default to declining. A backend implements the ones it models. `owns` is the fast
/// path for the generic fd calls (`read`, `write`, `close`, `fcntl`, `ioctl`): it must be cheap and must
/// answer for every fd the backend handed out.
#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Net: Send + Sync + 'static {
    #[cfg(windows)]
    unsafe fn completion(&self, call: CompletionCall) -> Option<NetResult> {
        None
    }

    /// Whether `fd` is one this backend minted. Called with the thread in passthrough on every
    /// generic fd call (`read`, `write`, `close`, `fcntl`, `ioctl`), before `sendmsg`/`recvmsg`/
    /// `kevent`, and before most Winsock calls on Windows, so it must not block and must stay true
    /// until the fd is closed.
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

    /// Models `socketpair(2)`: on success writes the two new fds to `fds` and returns `Ok(0)`.
    ///
    /// # Safety
    /// `fds` points to two writable `c_int`s.
    unsafe fn socketpair(
        &self,
        domain: c_int,
        ty: c_int,
        protocol: c_int,
        fds: *mut c_int,
    ) -> Option<NetResult> {
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
    ///
    /// # Safety
    /// Called from the `listen` hook; no pointers are involved.
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
    ///
    /// # Safety
    /// No pointers are involved.
    unsafe fn shutdown(&self, fd: c_int, how: c_int) -> Option<NetResult> {
        None
    }

    /// Models `close(2)` for an owned socket fd. After it returns, [`owns`](Self::owns) must be
    /// false for `fd`, since the OS may reuse the number for a real file.
    ///
    /// # Safety
    /// No pointers are involved.
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        None
    }

    /// Duplicates an owned socket, returning a new handle that refers to the same underlying
    /// socket (shared state). Backs Windows `WSADuplicateSocket`/`try_clone`; `None` declines.
    ///
    /// # Safety
    /// No pointers are involved.
    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        let _ = fd;
        None
    }

    /// Atomically duplicates an owned descriptor onto `newfd`. `None` flags selects `dup2`;
    /// `Some(flags)` selects `dup3`. On success, ownership follows the duplicate.
    ///
    /// # Safety
    /// No pointers are involved.
    unsafe fn dup_to(&self, fd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<NetResult> {
        let _ = (fd, newfd, flags);
        None
    }

    /// Releases simulated ownership after another descriptor has replaced the kernel fd.
    /// The replacement's kernel descriptor must remain open.
    ///
    /// # Safety
    /// No pointers are involved.
    unsafe fn fd_replaced(&self, fd: c_int) -> Option<NetResult> {
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
    /// `F_DUPFD`/`F_DUPFD_CLOEXEC` (`<fcntl.h>`). `arg` is the call's third word as an integer.
    ///
    /// # Safety
    /// The modelled commands take no pointer.
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        None
    }

    /// `ioctl(fd, request, arg)` for an owned fd (`FIONBIO`, `FIONREAD`).
    ///
    /// Models `ioctl(2)`; `FIONBIO`/`FIONREAD` are defined in `<sys/ioctl.h>`
    /// (`<asm-generic/ioctls.h>` on Linux).
    ///
    /// Also backs Windows `ioctlsocket`, whose `cmd` is a C `long`
    /// ([Microsoft Learn: ioctlsocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket)).
    /// It is widened with sign extension, so `FIONBIO`, `_IOW('f', 126, u_long)` = `0x8004667E`
    /// (`<winsock2.h>`), arrives as `0xFFFF_FFFF_8004_667E`: compare the low 32 bits.
    ///
    /// # Safety
    /// `arg` is the call's third word; for `FIONBIO`/`FIONREAD` and the `SIOC*` requests it is a
    /// pointer the caller supplied.
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

    /// `eventfd(initval, flags)`: a counting fd for readiness wakeups (Linux). No pointers.
    ///
    /// Models `eventfd(2)` (the `eventfd2` system call); `flags` are `EFD_NONBLOCK`/`EFD_CLOEXEC`/`EFD_SEMAPHORE`
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

    /// `kqueue()`: a readiness set (macOS/BSD), the kqueue(2) analogue of `epoll_create1`. No
    /// pointers.
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

    /// `if_nametoindex(name)`: resolve an interface name to its index. `Ok(index)`, or
    /// `Err(errno)` for an unknown name, which the hook returns as 0 with errno set (the C
    /// convention for this call).
    ///
    /// Models `if_nametoindex(3)` (POSIX; `<net/if.h>`).
    ///
    /// # Safety
    /// `name` is the caller's NUL-terminated interface name.
    unsafe fn if_nametoindex(&self, name: *const c_char) -> Option<NetResult> {
        let _ = name;
        None
    }

    /// `if_indextoname(index, name)`: write the interface's name into `name` (`IF_NAMESIZE`
    /// bytes) and return `Ok(name as i64)`, or `Err(errno)` when no interface has that index.
    ///
    /// Models `if_indextoname(3)` (`<net/if.h>`).
    ///
    /// # Safety
    /// `name` points to `IF_NAMESIZE` writable bytes.
    unsafe fn if_indextoname(&self, index: u32, name: *mut c_char) -> Option<NetResult> {
        let _ = (index, name);
        None
    }

    /// `if_nameindex()`: an array of `struct if_nameindex` ended by a zero entry, returned as
    /// `Ok(ptr as i64)` and released through [`if_freenameindex`](Self::if_freenameindex).
    ///
    /// Models `if_nameindex(3)`. No pointers.
    unsafe fn if_nameindex(&self) -> Option<NetResult> {
        None
    }

    /// `if_freenameindex(ptr)`: release an array this backend produced; `None` for any other.
    ///
    /// # Safety
    /// `ptr` came from an `if_nameindex` call.
    unsafe fn if_freenameindex(&self, ptr: *mut u8) -> Option<NetResult> {
        let _ = ptr;
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
    /// `SO_TXTIME`/`SCM_TXTIME` launch-time mechanism takes its numbers from
    /// `<asm-generic/socket.h>` and its `struct sock_txtime` from `<linux/net_tstamp.h>` (see
    /// `tc-etf(8)`).
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
    /// The default receives each message with [`recvmsg`](Net::recvmsg), as `do_recvmmsg` in
    /// net/socket.c does: up to `vlen` (at most `UIO_MAXIOV`, 1024), every one with `flags`
    /// (which block, as the kernel's do, unless `MSG_WAITFORONE` adds `MSG_DONTWAIT` after the
    /// first). `timeout` is checked only after a message arrives and is written back with the time
    /// left, so it never cuts a wait short (man 2 recvmmsg, BUGS). An error ends the batch: with
    /// no message yet it is the call's, otherwise the messages so far are returned and the error
    /// is dropped where the kernel would keep it for the next call. Declines when `recvmsg` declines
    /// the first message.
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
        #[cfg(target_os = "linux")]
        {
            unsafe { crate::os::recvmmsg_each(self, fd, msgvec, vlen, flags, timeout) }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (fd, msgvec, vlen, flags, timeout);
            None
        }
    }

    /// Models `select`: each non-null native `fd_set` is reduced to its ready descriptors.
    /// `timeout` is null or a native timeval. `Ok` is the number of readiness bits reported.
    ///
    /// # Safety
    /// The set pointers are null or valid `fd_set`s; `timeout` is null or a valid `TIMEVAL`.
    unsafe fn select(
        &self,
        nfds: c_int,
        read: *mut u8,
        write: *mut u8,
        except: *mut u8,
        timeout: *const u8,
    ) -> Option<NetResult> {
        let _ = (nfds, read, write, except, timeout);
        None
    }

    /// `WSAIoctl(fd, code, input, input_len, output, output_len, returned, NULL, NULL)` on an owned
    /// socket: `Ok(0)` on success, `Err(wsa_code)`; `None` declines.
    ///
    /// # Safety
    /// The buffers are the caller's, as MS `WSAIoctl` documents them.
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn wsa_ioctl(
        &self,
        fd: c_int,
        code: u32,
        input: *const u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
        returned: *mut u32,
    ) -> Option<NetResult> {
        let _ = (fd, code, input, input_len, output, output_len, returned);
        None
    }

    /// A synchronous Winsock message receive on an owned socket: `WSARecv` and `WSARecvFrom`
    /// (`extension` false), or the `WSARecvMsg` extension function (`extension` true), which takes
    /// datagram sockets only. `msg` is a `WSAMSG` holding the receive flags in `dwFlags`; the
    /// backend fills its buffers, `name`/`namelen`, `Control.len` and the output `dwFlags`, also
    /// when it fails with `WSAEMSGSIZE` after copying a truncated datagram. `Ok` is the bytes
    /// received
    /// ([Microsoft Learn: WSAMSG](https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsamsg)).
    ///
    /// # Safety
    /// `msg` points to a `WSAMSG` describing the caller's buffers.
    #[cfg(windows)]
    unsafe fn wsa_recv(&self, fd: c_int, msg: *mut u8, extension: bool) -> Option<NetResult> {
        let _ = (fd, msg, extension);
        None
    }

    /// A synchronous Winsock message send on an owned socket: `WSASend` and `WSASendTo`
    /// (`extension` false), or `WSASendMsg` (`extension` true), which takes datagram sockets only.
    /// `msg` is a `WSAMSG` naming the destination (null for the connected peer), the buffers and
    /// the control data; `flags` is the call's own `dwFlags`. `Ok` is the bytes sent
    /// ([Microsoft Learn: WSASendMsg](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)).
    ///
    /// # Safety
    /// `msg` points to a `WSAMSG` describing the caller's buffers.
    #[cfg(windows)]
    unsafe fn wsa_send(
        &self,
        fd: c_int,
        msg: *const u8,
        flags: u32,
        extension: bool,
    ) -> Option<NetResult> {
        let _ = (fd, msg, flags, extension);
        None
    }

    /// One IP Helper (`iphlpapi.dll`) call. `Ok(code)` is the call's own return value (a Win32
    /// status, or the index / pointer for `if_nametoindex` / `if_indextoname`); `None` declines.
    ///
    /// # Safety
    /// The pointers in `call` are the caller's, as the matching IP Helper function documents them.
    #[cfg(windows)]
    unsafe fn iphlp(&self, call: IpHlpCall<'_>) -> Option<NetResult> {
        let _ = call;
        None
    }

    /// `pcap_create(device, errbuf)` / `pcap_open_live(...)`: open a capture on `device` and return
    /// a handle in `Ok`. `device` is the caller's NUL-terminated interface name.
    ///
    /// The `pcap_*` methods back Windows raw L2 through `wpcap`/Npcap. A capture handle is an
    /// opaque `pcap_t*` carried as `u64`; `Ok(handle)` claims it, and `None` lets the real library
    /// take the call.
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

/// An IP Helper call offered to [`Net::iphlp`]. Pointer payloads are the caller's arguments as
/// documented for the function of the same name (`netioapi.h`, `iphlpapi.h`).
///
/// A LUID is the 64-bit `NET_LUID` value (`ifdef.h`, `NET_LUID_LH.Value`), and an interface index
/// the `NET_IFINDEX` (`ULONG`) the same functions use.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub enum IpHlpCall<'a> {
    /// `if_nametoindex` (iphlpapi export).
    NameToIndex(&'a core::ffi::CStr),
    /// `if_indextoname` (iphlpapi export); `name` holds `IF_NAMESIZE` bytes.
    IndexToName { index: u32, name: *mut c_char },
    /// `ConvertInterfaceAliasToLuid`; `alias` is the UTF-16 alias without its terminator.
    AliasToLuid { alias: &'a [u16], luid: *mut u64 },
    /// `ConvertInterfaceNameToLuidA`.
    NameToLuidA {
        name: &'a core::ffi::CStr,
        luid: *mut u64,
    },
    /// `ConvertInterfaceNameToLuidW`; `name` is UTF-16 without its terminator.
    NameToLuidW { name: &'a [u16], luid: *mut u64 },
    /// `ConvertInterfaceLuidToAlias`; `len` counts UTF-16 units in `alias`, terminator included.
    LuidToAlias {
        luid: u64,
        alias: *mut u16,
        len: usize,
    },
    /// `ConvertInterfaceLuidToNameA`; `len` counts bytes in `name`, terminator included.
    LuidToNameA {
        luid: u64,
        name: *mut c_char,
        len: usize,
    },
    /// `ConvertInterfaceLuidToIndex`.
    LuidToIndex { luid: u64, index: *mut u32 },
    /// `ConvertInterfaceIndexToLuid`.
    IndexToLuid { index: u32, luid: *mut u64 },
    /// A `MIB_IF_ROW2` whose `InterfaceLuid` or `InterfaceIndex` names the interface.
    GetIfEntry2(*mut u8),
    /// Receives a `MIB_IF_TABLE2 *`.
    GetIfTable2(*mut *mut u8),
    /// Receives a `MIB_UNICASTIPADDRESS_TABLE *` for `family`.
    GetUnicastIpAddressTable { family: u16, table: *mut *mut u8 },
    /// A table pointer from one of the getters above, or from the OS.
    FreeMibTable(*mut u8),
    /// `GetAdaptersAddresses`; `size` is in/out, and a short buffer returns
    /// `ERROR_BUFFER_OVERFLOW` with the needed size, as Win32 documents
    /// ([Microsoft Learn: GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)).
    GetAdaptersAddresses {
        family: u32,
        flags: u32,
        addresses: *mut u8,
        size: *mut u32,
    },
    /// `GetBestRoute2`; `source`/`destination` are `SOCKADDR_INET`, `route` a `MIB_IPFORWARD_ROW2`
    /// and `best_source` a `SOCKADDR_INET` (`netioapi.h`).
    GetBestRoute2 {
        luid: *const u64,
        index: u32,
        source: *const u8,
        destination: *const u8,
        options: u32,
        route: *mut u8,
        best_source: *mut u8,
    },
    /// `GetUdpStatisticsEx` for `family` (`GetUdpStatistics` is its `AF_INET` form): `stats` is
    /// a `MIB_UDPSTATS`, or a `MIB_UDPSTATS2` for `GetUdpStatisticsEx2` (`wide`) (`udpmib.h`).
    UdpStatistics {
        family: u32,
        stats: *mut u8,
        wide: bool,
    },
    /// `GetTcpStatisticsEx` for `family` (`GetTcpStatistics` is its `AF_INET` form): `stats` is
    /// a `MIB_TCPSTATS_LH`, or a `MIB_TCPSTATS2` for `GetTcpStatisticsEx2` (`wide`) (`tcpmib.h`).
    TcpStatistics {
        family: u32,
        stats: *mut u8,
        wide: bool,
    },
}
