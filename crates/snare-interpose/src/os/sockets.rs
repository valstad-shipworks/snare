//! Socket and generic-fd hooks that consult the calling thread's [`Net`](crate::Net) before the
//! OS. When no domain has a `Net`, or the `Net` declines, each call keeps its previous behaviour:
//! the socket calls record themselves as observed and forward; the generic fd calls forward
//! untouched.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::AtomicUsize;

use libc::{nfds_t, pollfd, size_t, sockaddr, socklen_t, ssize_t};

use crate::domain::{self, dispatch_fs, dispatch_net, fs_owns, net_owns};
use crate::hooks::{Hook, hook, original};

macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(SOCKET);
slot!(CONNECT);
slot!(BIND);
slot!(LISTEN);
slot!(ACCEPT);
slot!(SEND);
slot!(RECV);
slot!(SENDTO);
slot!(RECVFROM);
slot!(SHUTDOWN);
slot!(CLOSE);
slot!(GETSOCKNAME);
slot!(GETPEERNAME);
slot!(SETSOCKOPT);
slot!(GETSOCKOPT);
slot!(POLL);
slot!(READ);
slot!(WRITE);
slot!(FCNTL);
slot!(IF_NAMETOINDEX);
slot!(SENDMSG);
slot!(RECVMSG);
slot!(GETIFADDRS);
slot!(FREEIFADDRS);
#[cfg(target_os = "linux")]
slot!(ACCEPT4);
#[cfg(target_os = "linux")]
slot!(EVENTFD);
#[cfg(target_os = "linux")]
slot!(EPOLL_CREATE1);
#[cfg(target_os = "linux")]
slot!(EPOLL_CTL);
#[cfg(target_os = "linux")]
slot!(EPOLL_WAIT);
#[cfg(target_os = "linux")]
slot!(EPOLL_PWAIT);
#[cfg(target_os = "macos")]
slot!(KQUEUE);
#[cfg(target_os = "macos")]
slot!(KEVENT);

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("socket", socket, SOCKET),
        hook!("connect", connect, CONNECT),
        hook!("bind", bind, BIND),
        hook!("listen", listen, LISTEN),
        hook!("accept", accept, ACCEPT),
        hook!("send", send, SEND),
        hook!("recv", recv, RECV),
        hook!("sendto", sendto, SENDTO),
        hook!("recvfrom", recvfrom, RECVFROM),
        hook!("shutdown", shutdown, SHUTDOWN),
        hook!("close", close, CLOSE),
        hook!("getsockname", getsockname, GETSOCKNAME),
        hook!("getpeername", getpeername, GETPEERNAME),
        hook!("setsockopt", setsockopt, SETSOCKOPT),
        hook!("getsockopt", getsockopt, GETSOCKOPT),
        hook!("poll", poll, POLL),
        hook!("read", read, READ),
        hook!("write", write, WRITE),
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        hook!("fcntl", fcntl, FCNTL),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("fcntl", crate::os::variadic::fcntl, FCNTL),
        hook!("if_nametoindex", if_nametoindex, IF_NAMETOINDEX),
        hook!("sendmsg", sendmsg, SENDMSG),
        hook!("recvmsg", recvmsg, RECVMSG),
        hook!("getifaddrs", getifaddrs, GETIFADDRS),
        hook!("freeifaddrs", freeifaddrs, FREEIFADDRS),
        #[cfg(target_os = "linux")]
        hook!("accept4", accept4, ACCEPT4),
        #[cfg(target_os = "linux")]
        hook!("eventfd", eventfd, EVENTFD),
        #[cfg(target_os = "linux")]
        hook!("epoll_create1", epoll_create1, EPOLL_CREATE1),
        #[cfg(target_os = "linux")]
        hook!("epoll_ctl", epoll_ctl, EPOLL_CTL),
        #[cfg(target_os = "linux")]
        hook!("epoll_wait", epoll_wait, EPOLL_WAIT),
        #[cfg(target_os = "linux")]
        hook!("epoll_pwait", epoll_pwait, EPOLL_PWAIT),
        #[cfg(target_os = "macos")]
        hook!("kqueue", kqueue, KQUEUE),
        #[cfg(target_os = "macos")]
        hook!("kevent", kevent, KEVENT),
    ]
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn eventfd(initval: libc::c_uint, flags: c_int) -> c_int {
    // man 2 eventfd: 8-byte counter fd; flags EFD_CLOEXEC/EFD_NONBLOCK/EFD_SEMAPHORE.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.eventfd(initval, flags) }) {
        return finish(r) as c_int;
    }
    domain::observe("eventfd", None);
    // SAFETY: EVENTFD holds libc's eventfd.
    unsafe {
        original::<unsafe extern "C" fn(libc::c_uint, c_int) -> c_int>(&EVENTFD)(initval, flags)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    // man 7 epoll, man 2 epoll_create1: flags is EPOLL_CLOEXEC or 0.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.epoll_create1(flags) }) {
        return finish(r) as c_int;
    }
    domain::observe("epoll_create1", None);
    // SAFETY: EPOLL_CREATE1 holds libc's epoll_create1.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&EPOLL_CREATE1)(flags) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut libc::epoll_event,
) -> c_int {
    // man 2 epoll_ctl: op is EPOLL_CTL_ADD/MOD/DEL; struct epoll_event {events, data}.
    // SAFETY: `event` points to an epoll_event for add/mod.
    if let Some(r) = dispatch_net(|net| unsafe { net.epoll_ctl(epfd, op, fd, event.cast()) }) {
        return finish(r) as c_int;
    }
    domain::observe("epoll_ctl", None);
    // SAFETY: EPOLL_CTL holds libc's epoll_ctl.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int, c_int, *mut libc::epoll_event) -> c_int>(
            &EPOLL_CTL,
        )(epfd, op, fd, event)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    // man 2 epoll_wait: returns up to `maxevents` ready events; timeout in ms, -1 blocks.
    // SAFETY: `events` points to `maxevents` slots.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.epoll_wait(epfd, events.cast(), maxevents, timeout) })
    {
        return finish(r) as c_int;
    }
    domain::observe("epoll_wait", None);
    // SAFETY: EPOLL_WAIT holds libc's epoll_wait.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut libc::epoll_event, c_int, c_int) -> c_int>(
            &EPOLL_WAIT,
        )(epfd, events, maxevents, timeout)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn epoll_pwait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const libc::sigset_t,
) -> c_int {
    // man 2 epoll_pwait: epoll_wait that atomically swaps in `sigmask` for the wait.
    // The signal mask does not affect a simulated wait; model it as `epoll_wait`.
    // SAFETY: `events` points to `maxevents` slots.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.epoll_wait(epfd, events.cast(), maxevents, timeout) })
    {
        return finish(r) as c_int;
    }
    domain::observe("epoll_pwait", None);
    // SAFETY: EPOLL_PWAIT holds libc's epoll_pwait.
    unsafe {
        original::<
            unsafe extern "C" fn(
                c_int,
                *mut libc::epoll_event,
                c_int,
                c_int,
                *const libc::sigset_t,
            ) -> c_int,
        >(&EPOLL_PWAIT)(epfd, events, maxevents, timeout, sigmask)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn kqueue() -> c_int {
    // man 2 kqueue: creates a new kernel event queue, returning a descriptor.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.kqueue() }) {
        return finish(r) as c_int;
    }
    domain::observe("kqueue", None);
    // SAFETY: KQUEUE holds libc's kqueue.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&KQUEUE)() }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn kevent(
    kq: c_int,
    changelist: *const libc::kevent,
    nchanges: c_int,
    eventlist: *mut libc::kevent,
    nevents: c_int,
    timeout: *const libc::timespec,
) -> c_int {
    // man 2 kevent: applies `changelist` then returns up to `nevents` ready events; `timeout`
    // is a timespec (null blocks). SAFETY: the caller's change/event arrays and timeout.
    if net_owns(kq)
        && let Some(r) = dispatch_net(|net| unsafe {
            net.kevent(
                kq,
                changelist.cast(),
                nchanges,
                eventlist.cast(),
                nevents,
                timeout.cast(),
            )
        })
    {
        return finish(r) as c_int;
    }
    domain::observe("kevent", None);
    // SAFETY: KEVENT holds libc's kevent.
    unsafe {
        original::<
            unsafe extern "C" fn(
                c_int,
                *const libc::kevent,
                c_int,
                *mut libc::kevent,
                c_int,
                *const libc::timespec,
            ) -> c_int,
        >(&KEVENT)(kq, changelist, nchanges, eventlist, nevents, timeout)
    }
}

unsafe fn set_errno(errno: c_int) {
    #[cfg(target_os = "linux")]
    // SAFETY: valid on the calling thread.
    unsafe {
        *libc::__errno_location() = errno;
    }
    #[cfg(target_os = "macos")]
    // SAFETY: valid on the calling thread.
    unsafe {
        *libc::__error() = errno;
    }
}

/// Turns a handled return into a pointer: a negative errno becomes NULL (with errno set), and a
/// non-negative value is the pointer (0 = NULL, e.g. `readdir` end-of-stream, no errno).
pub(crate) fn finish_ptr(handled: i64) -> *mut core::ffi::c_void {
    if handled < 0 {
        // SAFETY: setting the calling thread's errno.
        unsafe { set_errno((-handled) as c_int) };
        core::ptr::null_mut()
    } else {
        handled as *mut core::ffi::c_void
    }
}

/// Turns a [`Net`](crate::Net) return (negative errno on failure) into a C `int`/`ssize_t`.
// man 2 intro / man 3 errno: the syscall convention is -1 returned with errno set to the
// (positive) error number; here the backend encodes it as a negative errno.
pub(crate) fn finish(handled: i64) -> i64 {
    if handled < 0 {
        // SAFETY: setting the calling thread's errno.
        unsafe { set_errno((-handled) as c_int) };
        -1
    } else {
        handled
    }
}

unsafe extern "C" fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> ssize_t {
    // man 2 sendmsg: struct msghdr {msg_name, msg_iov/msg_iovlen scatter-gather,
    // msg_control/msg_controllen ancillary cmsg(3)}; returns bytes sent.
    // SAFETY: `msg` is the caller's msghdr.
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.sendmsg(fd, msg.cast(), flags) })
    {
        return finish(r) as ssize_t;
    }
    domain::observe("sendmsg", None);
    // SAFETY: SENDMSG holds libc's sendmsg.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> ssize_t>(&SENDMSG)(
            fd, msg, flags,
        )
    }
}

unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> ssize_t {
    // man 2 recvmsg: fills the msghdr's iovecs and sets msg_flags (e.g. MSG_TRUNC/MSG_CTRUNC).
    // SAFETY: `msg` is the caller's msghdr.
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.recvmsg(fd, msg.cast(), flags) })
    {
        return finish(r) as ssize_t;
    }
    domain::observe("recvmsg", None);
    // SAFETY: RECVMSG holds libc's recvmsg.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut libc::msghdr, c_int) -> ssize_t>(&RECVMSG)(
            fd, msg, flags,
        )
    }
}

unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
    // man 3 getifaddrs: allocates a linked list of struct ifaddrs {ifa_next, ifa_name,
    // ifa_flags (SIOCGIFFLAGS), ifa_addr, ifa_netmask, ifa_broadaddr}; freed by freeifaddrs.
    // SAFETY: `ifap` receives the list head.
    if let Some(r) = dispatch_net(|net| unsafe { net.getifaddrs(ifap.cast()) }) {
        return finish(r) as c_int;
    }
    domain::observe("getifaddrs", None);
    // SAFETY: GETIFADDRS holds libc's getifaddrs.
    unsafe {
        original::<unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int>(&GETIFADDRS)(ifap)
    }
}

unsafe extern "C" fn freeifaddrs(ifa: *mut libc::ifaddrs) {
    // SAFETY: `ifa` is a list head. Offer it to the backend that may have produced it.
    if dispatch_net(|net| unsafe { net.freeifaddrs(ifa.cast()) }).is_some() {
        return;
    }
    // SAFETY: FREEIFADDRS holds libc's freeifaddrs.
    unsafe { original::<unsafe extern "C" fn(*mut libc::ifaddrs)>(&FREEIFADDRS)(ifa) }
}

unsafe extern "C" fn if_nametoindex(name: *const c_char) -> libc::c_uint {
    // man 3 if_nametoindex: maps an interface name to its 1-based index (see man 7 rtnetlink);
    // on error returns 0 with errno set (ENXIO/ENODEV), unlike the -1 syscall convention.
    // SAFETY: `name` is the caller's NUL-terminated interface name.
    if let Some(r) = dispatch_net(|net| unsafe { net.if_nametoindex(name) }) {
        if r < 0 {
            // SAFETY: setting the calling thread's errno.
            unsafe { set_errno((-r) as c_int) };
            return 0; // the C convention: 0 with errno set on an unknown name.
        }
        return r as libc::c_uint;
    }
    // SAFETY: IF_NAMETOINDEX holds libc's if_nametoindex.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char) -> libc::c_uint>(&IF_NAMETOINDEX)(name)
    }
}

unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    // man 2 socket: (AF_*, SOCK_* | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol) -> new fd.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.socket(domain, ty, protocol) }) {
        return finish(r) as c_int;
    }
    domain::observe("socket", None);
    // SAFETY: SOCKET holds libc's socket.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int, c_int) -> c_int>(&SOCKET)(
            domain, ty, protocol,
        )
    }
}

unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    // man 2 connect: `len` is the sockaddr size; a nonblocking connect returns EINPROGRESS.
    // SAFETY: `addr` points to `len` bytes.
    if let Some(r) = dispatch_net(|net| unsafe { net.connect(fd, addr.cast(), len) }) {
        return finish(r) as c_int;
    }
    domain::observe("connect", None);
    // SAFETY: CONNECT holds libc's connect.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int>(&CONNECT)(
            fd, addr, len,
        )
    }
}

unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    // man 2 bind: assigns the local address; a busy port yields EADDRINUSE.
    // SAFETY: `addr` points to `len` bytes.
    if let Some(r) = dispatch_net(|net| unsafe { net.bind(fd, addr.cast(), len) }) {
        return finish(r) as c_int;
    }
    domain::observe("bind", None);
    // SAFETY: BIND holds libc's bind.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int>(&BIND)(
            fd, addr, len,
        )
    }
}

unsafe extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    // man 2 listen: `backlog` bounds the pending-connection queue (capped by SOMAXCONN).
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.listen(fd, backlog) }) {
        return finish(r) as c_int;
    }
    domain::observe("listen", None);
    // SAFETY: LISTEN holds libc's listen.
    unsafe { original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&LISTEN)(fd, backlog) }
}

unsafe extern "C" fn accept(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // man 2 accept: `len` is in/out (buffer capacity in, actual peer-addr size out).
    // SAFETY: `addr`/`len` receive the peer address.
    if let Some(r) = dispatch_net(|net| unsafe { net.accept(fd, addr.cast(), len.cast(), 0) }) {
        return finish(r) as c_int;
    }
    domain::observe("accept", None);
    // SAFETY: ACCEPT holds libc's accept.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int>(&ACCEPT)(
            fd, addr, len,
        )
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn accept4(
    fd: c_int,
    addr: *mut sockaddr,
    len: *mut socklen_t,
    flags: c_int,
) -> c_int {
    // man 2 accept4: accept plus SOCK_NONBLOCK/SOCK_CLOEXEC on the new fd (Linux-specific).
    // SAFETY: `addr`/`len` receive the peer address.
    if let Some(r) = dispatch_net(|net| unsafe { net.accept(fd, addr.cast(), len.cast(), flags) }) {
        return finish(r) as c_int;
    }
    domain::observe("accept4", None);
    // SAFETY: ACCEPT4 holds libc's accept4.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t, c_int) -> c_int>(
            &ACCEPT4,
        )(fd, addr, len, flags)
    }
}

unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    // man 2 send: flags MSG_DONTWAIT/MSG_NOSIGNAL/MSG_MORE; a full buffer yields EAGAIN.
    // SAFETY: `buf` points to `len` bytes.
    if let Some(r) = dispatch_net(|net| unsafe { net.send(fd, buf.cast(), len, flags) }) {
        return finish(r) as ssize_t;
    }
    domain::observe("send", None);
    // SAFETY: SEND holds libc's send.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t>(&SEND)(
            fd, buf, len, flags,
        )
    }
}

unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    // man 2 recv: 0 means orderly shutdown; flags MSG_PEEK/MSG_WAITALL/MSG_DONTWAIT.
    // SAFETY: `buf` points to `len` writable bytes.
    if let Some(r) = dispatch_net(|net| unsafe { net.recv(fd, buf.cast(), len, flags) }) {
        return finish(r) as ssize_t;
    }
    domain::observe("recv", None);
    // SAFETY: RECV holds libc's recv.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut c_void, size_t, c_int) -> ssize_t>(&RECV)(
            fd, buf, len, flags,
        )
    }
}

unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const sockaddr,
    addr_len: socklen_t,
) -> ssize_t {
    // man 2 sendto: like send but `addr`/`addr_len` name the datagram destination.
    // SAFETY: `buf` readable; `addr` a destination sockaddr.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.sendto(fd, buf.cast(), len, flags, addr.cast(), addr_len) })
    {
        return finish(r) as ssize_t;
    }
    domain::observe("sendto", None);
    // SAFETY: SENDTO holds libc's sendto.
    unsafe {
        original::<
            unsafe extern "C" fn(
                c_int,
                *const c_void,
                size_t,
                c_int,
                *const sockaddr,
                socklen_t,
            ) -> ssize_t,
        >(&SENDTO)(fd, buf, len, flags, addr, addr_len)
    }
}

unsafe extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    addr: *mut sockaddr,
    addr_len: *mut socklen_t,
) -> ssize_t {
    // man 2 recvfrom: like recv but `addr`/`addr_len` (in/out) receive the datagram source.
    // SAFETY: `buf` writable; `addr`/`addr_len` receive the source.
    if let Some(r) = dispatch_net(|net| unsafe {
        net.recvfrom(fd, buf.cast(), len, flags, addr.cast(), addr_len.cast())
    }) {
        return finish(r) as ssize_t;
    }
    domain::observe("recvfrom", None);
    // SAFETY: RECVFROM holds libc's recvfrom.
    unsafe {
        original::<
            unsafe extern "C" fn(
                c_int,
                *mut c_void,
                size_t,
                c_int,
                *mut sockaddr,
                *mut socklen_t,
            ) -> ssize_t,
        >(&RECVFROM)(fd, buf, len, flags, addr, addr_len)
    }
}

unsafe extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    // man 2 shutdown: how is SHUT_RD(0)/SHUT_WR(1)/SHUT_RDWR(2).
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.shutdown(fd, how) }) {
        return finish(r) as c_int;
    }
    domain::observe("shutdown", None);
    // SAFETY: SHUTDOWN holds libc's shutdown.
    unsafe { original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&SHUTDOWN)(fd, how) }
}

unsafe extern "C" fn close(fd: c_int) -> c_int {
    // man 2 close: releases the fd; a simulated fd is closed by whichever backend owns it.
    // SAFETY: no pointers.
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.close(fd) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: no pointers.
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.close(fd) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: CLOSE holds libc's close.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&CLOSE)(fd) }
}

unsafe extern "C" fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // man 2 getsockname: reports the bound local address; `len` is in/out.
    // SAFETY: `addr`/`len` receive the local address.
    if let Some(r) = dispatch_net(|net| unsafe { net.getsockname(fd, addr.cast(), len.cast()) }) {
        return finish(r) as c_int;
    }
    domain::observe("getsockname", None);
    // SAFETY: GETSOCKNAME holds libc's getsockname.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int>(
            &GETSOCKNAME,
        )(fd, addr, len)
    }
}

unsafe extern "C" fn getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // man 2 getpeername: reports the connected peer address; ENOTCONN if unconnected.
    // SAFETY: `addr`/`len` receive the peer address.
    if let Some(r) = dispatch_net(|net| unsafe { net.getpeername(fd, addr.cast(), len.cast()) }) {
        return finish(r) as c_int;
    }
    domain::observe("getpeername", None);
    // SAFETY: GETPEERNAME holds libc's getpeername.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int>(
            &GETPEERNAME,
        )(fd, addr, len)
    }
}

unsafe extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    val: *const c_void,
    len: socklen_t,
) -> c_int {
    // man 2 setsockopt, man 7 socket: `level` (SOL_SOCKET/IPPROTO_*) selects the option
    // namespace for `name` (SO_REUSEADDR, SO_RCVBUF, SO_TIMESTAMPING, ...).
    // SAFETY: `val` points to `len` bytes.
    if let Some(r) = dispatch_net(|net| unsafe { net.setsockopt(fd, level, name, val.cast(), len) })
    {
        return finish(r) as c_int;
    }
    domain::observe("setsockopt", None);
    // SAFETY: SETSOCKOPT holds libc's setsockopt.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, socklen_t) -> c_int>(
            &SETSOCKOPT,
        )(fd, level, name, val, len)
    }
}

unsafe extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    val: *mut c_void,
    len: *mut socklen_t,
) -> c_int {
    // man 2 getsockopt: `len` is in/out; SO_ERROR retrieves and clears the pending error.
    // SAFETY: `val`/`len` receive the option value.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.getsockopt(fd, level, name, val.cast(), len.cast()) })
    {
        return finish(r) as c_int;
    }
    domain::observe("getsockopt", None);
    // SAFETY: GETSOCKOPT holds libc's getsockopt.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void, *mut socklen_t) -> c_int>(
            &GETSOCKOPT,
        )(fd, level, name, val, len)
    }
}

#[allow(clippy::unnecessary_cast)] // nfds_t is u32 on macOS, u64 on Linux
unsafe extern "C" fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int {
    // man 2 poll: struct pollfd {fd, events, revents}; timeout in ms, -1 blocks; POLLIN/POLLOUT.
    // SAFETY: `fds` points to `nfds` pollfd structs.
    if let Some(r) = dispatch_net(|net| unsafe { net.poll(fds.cast(), nfds as u64, timeout) }) {
        return finish(r) as c_int;
    }
    domain::observe("poll", None);
    // SAFETY: POLL holds libc's poll.
    unsafe {
        original::<unsafe extern "C" fn(*mut pollfd, nfds_t, c_int) -> c_int>(&POLL)(
            fds, nfds, timeout,
        )
    }
}

unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, len: size_t) -> ssize_t {
    // man 2 read: returns bytes read (0 at EOF); a stream socket fd reads like a byte stream.
    // SAFETY: `buf` points to `len` writable bytes.
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.read(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: `buf` points to `len` writable bytes.
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.read(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: READ holds libc's read.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t>(&READ)(fd, buf, len)
    }
}

unsafe extern "C" fn write(fd: c_int, buf: *const c_void, len: size_t) -> ssize_t {
    // man 2 write: may write fewer than `len` bytes (a short write) before returning.
    // SAFETY: `buf` points to `len` readable bytes.
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.write(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: `buf` points to `len` readable bytes.
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.write(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: WRITE holds libc's write.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t>(&WRITE)(
            fd, buf, len,
        )
    }
}

/// macOS aarch64 passes `fcntl`'s third word on the stack, so the real libc is reached through a
/// variadic pointer; elsewhere it travels in a register like a named argument.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type FcntlFn = unsafe extern "C" fn(c_int, c_int, ...) -> c_int;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
type FcntlFn = unsafe extern "C" fn(c_int, c_int, i64) -> c_int;

/// On macOS aarch64 the third word reaches here via the naked trampoline in [`crate::os::variadic`].
// The trampoline tail-branches here from another codegen unit, so the symbol must have external
// linkage to be resolvable; `sym` still emits the right (mangled) reference.
#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64"),
    unsafe(export_name = "__snare_interpose_fcntl")
)]
pub(crate) unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: i64) -> c_int {
    // man 2 fcntl: the modeled commands are F_GETFL/F_SETFL (O_NONBLOCK) and F_DUPFD/F_DUPFD_CLOEXEC.
    // SAFETY: no pointer args for the fcntl commands a socket/file sees (flags, dup).
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.fcntl(fd, cmd, arg) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: no pointer args for the fcntl commands a socket sees (flags, dup).
    if net_owns(fd)
        && let Some(r) = dispatch_net(|net| unsafe { net.fcntl(fd, cmd, arg) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: FCNTL holds libc's fcntl.
    unsafe { original::<FcntlFn>(&FCNTL)(fd, cmd, arg) }
}
