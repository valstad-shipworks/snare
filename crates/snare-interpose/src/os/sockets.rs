//! Socket and generic-fd hooks that consult the calling thread's [`Net`](crate::Net) before the
//! OS. When no domain has a `Net`, or the `Net` declines, each call behaves as it would unhooked:
//! the socket calls record themselves as observed and forward; the generic fd calls forward
//! untouched.
//!
//! Every hook follows one shape: offer the call through [`dispatch_net`] (or
//! [`domain::dispatch_net_effect`] for calls other threads can see, so an executive's audit notes
//! them), turn a handled result into the C convention with [`finish`], and otherwise call the
//! original through its slot. The dispatchers return `None` without consulting anything when the
//! thread is already in passthrough or belongs to no domain, and they enter passthrough for the
//! backend's duration, so a backend's own libc calls reach the OS rather than recursing here.
//!
//! The generic fd calls (`read`, `write`, `close`, `fcntl`) are shared with the file backend.
//! They ask [`fs_owns`] first and then [`net_owns`](domain::net_owns), and offer the call only to
//! the plane that owns the fd: an fd is minted by at most one backend, and a real fd must never be
//! handed to one.
//! Unowned fds forward without being observed, since every program does this I/O on real fds.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::AtomicUsize;

use libc::{nfds_t, pollfd, size_t, sockaddr, socklen_t, ssize_t};

use crate::domain::{self, dispatch_fs, dispatch_net, fs_owns};
use crate::hooks::{Hook, hook, original};

/// Declares the `AtomicUsize` that holds one hooked function's original address, filled when the
/// hook is installed and read through [`original`].
macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(SOCKET);
slot!(SOCKETPAIR);
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
slot!(SELECT);
slot!(DUP);
slot!(DUP2);
#[cfg(target_os = "linux")]
slot!(DUP3);
slot!(READ);
slot!(WRITE);
slot!(FCNTL);
slot!(IF_NAMETOINDEX);
slot!(SENDMSG);
slot!(RECVMSG);
#[cfg(target_os = "linux")]
slot!(RECVMMSG);
#[cfg(target_os = "linux")]
slot!(SENDMMSG);
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
#[cfg(target_os = "linux")]
slot!(EPOLL_PWAIT2);
#[cfg(target_os = "linux")]
slot!(TIMERFD_CREATE);
#[cfg(target_os = "linux")]
slot!(TIMERFD_SETTIME);
#[cfg(target_os = "linux")]
slot!(TIMERFD_GETTIME);
#[cfg(target_os = "macos")]
slot!(KQUEUE);
#[cfg(target_os = "macos")]
slot!(KEVENT);
slot!(IF_INDEXTONAME);
slot!(IF_NAMEINDEX);
slot!(IF_FREENAMEINDEX);

/// The socket and generic-fd hooks for this target. `fcntl` on macOS aarch64 enters through the
/// naked trampoline in `crate::os::variadic` because its third argument is variadic there.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("socket", socket, SOCKET),
        hook!("socketpair", socketpair, SOCKETPAIR),
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
        hook!("select", select, SELECT),
        hook!("dup", dup, DUP),
        hook!("dup2", dup2, DUP2),
        #[cfg(target_os = "linux")]
        hook!("dup3", dup3, DUP3),
        hook!("read", read, READ),
        hook!("write", write, WRITE),
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        hook!("fcntl", fcntl, FCNTL),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("fcntl", crate::os::variadic::fcntl, FCNTL),
        hook!("if_nametoindex", if_nametoindex, IF_NAMETOINDEX),
        hook!("if_indextoname", if_indextoname, IF_INDEXTONAME),
        hook!("if_nameindex", if_nameindex, IF_NAMEINDEX),
        hook!("if_freenameindex", if_freenameindex, IF_FREENAMEINDEX),
        hook!("sendmsg", sendmsg, SENDMSG),
        hook!("recvmsg", recvmsg, RECVMSG),
        #[cfg(target_os = "linux")]
        hook!("recvmmsg", recvmmsg, RECVMMSG),
        #[cfg(target_os = "linux")]
        hook!("sendmmsg", sendmmsg, SENDMMSG),
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
        #[cfg(target_os = "linux")]
        hook!("epoll_pwait2", epoll_pwait2, EPOLL_PWAIT2),
        #[cfg(target_os = "linux")]
        hook!("timerfd_create", timerfd_create, TIMERFD_CREATE),
        #[cfg(target_os = "linux")]
        hook!("timerfd_settime", timerfd_settime, TIMERFD_SETTIME),
        #[cfg(target_os = "linux")]
        hook!("timerfd_gettime", timerfd_gettime, TIMERFD_GETTIME),
        #[cfg(target_os = "macos")]
        hook!("kqueue", kqueue, KQUEUE),
        #[cfg(target_os = "macos")]
        hook!("kevent", kevent, KEVENT),
    ]
}

#[cfg(target_os = "linux")]
/// Hook for `eventfd(2)` (Linux): a backend may mint a simulated counter fd; otherwise observed
/// and forwarded.
unsafe extern "C" fn eventfd(initval: libc::c_uint, flags: c_int) -> c_int {
    // man 2 eventfd: 8-byte counter fd; flags EFD_CLOEXEC/EFD_NONBLOCK/EFD_SEMAPHORE.
    // SAFETY: no pointers.
    if let Some(r) = domain::descriptor_transaction(|| {
        dispatch_net(|net| unsafe { net.eventfd(initval, flags) })
    }) {
        return finish(r) as c_int;
    }
    domain::observe("eventfd", None);
    // SAFETY: EVENTFD holds libc's eventfd.
    unsafe {
        original::<unsafe extern "C" fn(libc::c_uint, c_int) -> c_int>(&EVENTFD)(initval, flags)
    }
}

#[cfg(target_os = "linux")]
/// Hook for `epoll_create1(2)` (Linux).
unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    // man 7 epoll, man 2 epoll_create1: flags is EPOLL_CLOEXEC or 0.
    // SAFETY: no pointers.
    if let Some(r) =
        domain::descriptor_transaction(|| dispatch_net(|net| unsafe { net.epoll_create1(flags) }))
    {
        return finish(r) as c_int;
    }
    domain::observe("epoll_create1", None);
    // SAFETY: EPOLL_CREATE1 holds libc's epoll_create1.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&EPOLL_CREATE1)(flags) }
}

#[cfg(target_os = "linux")]
/// Hook for `epoll_ctl(2)` (Linux). Offered to the backend whatever `epfd` is: the backend
/// declines an epoll set it did not create.
unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut libc::epoll_event,
) -> c_int {
    // man 2 epoll_ctl: op is EPOLL_CTL_ADD/MOD/DEL; struct epoll_event {events, data}.
    // SAFETY: `event` points to an epoll_event for add/mod.
    if let Some(r) =
        domain::dispatch_on(epfd, |net| unsafe { net.epoll_ctl(epfd, op, fd, event.cast()) })
    {
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
/// Hook for `epoll_wait(2)` (Linux).
unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    // man 2 epoll_wait: returns up to `maxevents` ready events; timeout in ms, -1 blocks.
    // SAFETY: `events` points to `maxevents` slots.
    if let Some(r) =
        domain::dispatch_on(epfd, |net| unsafe {
            net.epoll_wait(epfd, events.cast(), maxevents, timeout)
        })
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
/// Hook for `epoll_pwait(2)` (Linux), modelled as [`epoll_wait`] when a backend handles it.
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
        domain::dispatch_on(epfd, |net| unsafe {
            net.epoll_wait(epfd, events.cast(), maxevents, timeout)
        })
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

#[cfg(target_os = "linux")]
/// Hook for `epoll_pwait2(2)` (Linux 5.11, glibc 2.35): [`epoll_pwait`] with a timespec timeout.
unsafe extern "C" fn epoll_pwait2(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: *const libc::timespec,
    sigmask: *const libc::sigset_t,
) -> c_int {
    // SAFETY: `events` points to `maxevents` slots; `timeout` is null or a timespec.
    if let Some(r) = domain::dispatch_on(epfd, |net| unsafe {
        net.epoll_pwait2(epfd, events.cast(), maxevents, timeout.cast())
    }) {
        return finish(r) as c_int;
    }
    domain::observe("epoll_pwait2", None);
    type EpollPwait2Fn = unsafe extern "C" fn(
        c_int,
        *mut libc::epoll_event,
        c_int,
        *const libc::timespec,
        *const libc::sigset_t,
    ) -> c_int;
    // SAFETY: EPOLL_PWAIT2 holds libc's epoll_pwait2.
    unsafe { original::<EpollPwait2Fn>(&EPOLL_PWAIT2)(epfd, events, maxevents, timeout, sigmask) }
}

#[cfg(target_os = "linux")]
/// Hook for `timerfd_create(2)` (Linux): a backend may mint a simulated timer on the sim's clock;
/// otherwise observed and forwarded.
unsafe extern "C" fn timerfd_create(clockid: libc::clockid_t, flags: c_int) -> c_int {
    // SAFETY: no pointers.
    if let Some(r) = domain::descriptor_transaction(|| {
        dispatch_net(|net| unsafe { net.timerfd_create(clockid, flags) })
    }) {
        return finish(r) as c_int;
    }
    domain::observe("timerfd_create", None);
    // SAFETY: TIMERFD_CREATE holds libc's timerfd_create.
    unsafe {
        original::<unsafe extern "C" fn(libc::clockid_t, c_int) -> c_int>(&TIMERFD_CREATE)(
            clockid, flags,
        )
    }
}

#[cfg(target_os = "linux")]
/// Hook for `timerfd_settime(2)` (Linux), offered only for an fd a backend owns.
unsafe extern "C" fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const libc::itimerspec,
    old_value: *mut libc::itimerspec,
) -> c_int {
    // SAFETY: `new_value` is the caller's itimerspec; `old_value` null or writable.
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe {
        net.timerfd_settime(fd, flags, new_value.cast(), old_value.cast())
    }) {
        return finish(r) as c_int;
    }
    domain::observe("timerfd_settime", None);
    type TimerfdSettimeFn =
        unsafe extern "C" fn(c_int, c_int, *const libc::itimerspec, *mut libc::itimerspec) -> c_int;
    // SAFETY: TIMERFD_SETTIME holds libc's timerfd_settime.
    unsafe { original::<TimerfdSettimeFn>(&TIMERFD_SETTIME)(fd, flags, new_value, old_value) }
}

#[cfg(target_os = "linux")]
/// Hook for `timerfd_gettime(2)` (Linux), offered only for an fd a backend owns.
unsafe extern "C" fn timerfd_gettime(fd: c_int, curr_value: *mut libc::itimerspec) -> c_int {
    // SAFETY: `curr_value` is the caller's writable itimerspec.
    if let Some(r) =
        domain::dispatch_owned(fd, |net| unsafe { net.timerfd_gettime(fd, curr_value.cast()) })
    {
        return finish(r) as c_int;
    }
    domain::observe("timerfd_gettime", None);
    // SAFETY: TIMERFD_GETTIME holds libc's timerfd_gettime.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut libc::itimerspec) -> c_int>(&TIMERFD_GETTIME)(
            fd, curr_value,
        )
    }
}

#[cfg(target_os = "macos")]
/// Hook for `kqueue(2)` (macOS).
unsafe extern "C" fn kqueue() -> c_int {
    // man 2 kqueue: creates a new kernel event queue, returning a descriptor.
    // SAFETY: no pointers.
    if let Some(r) = domain::descriptor_transaction(|| dispatch_net(|net| unsafe { net.kqueue() }))
    {
        return finish(r) as c_int;
    }
    domain::observe("kqueue", None);
    // SAFETY: KQUEUE holds libc's kqueue.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&KQUEUE)() }
}

#[cfg(target_os = "macos")]
/// Hook for `kevent(2)` (macOS). Unlike the Linux epoll hooks this one is gated on
/// [`net_owns`](domain::net_owns), so a kqueue the OS made (for libdispatch, say) never reaches a
/// backend.
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
    if let Some(r) = domain::dispatch_owned(kq, |net| unsafe {
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

/// Sets the calling thread's `errno`, through glibc's `__errno_location()` (`<errno.h>`, which
/// defines `errno` as `(*__errno_location ())`) or Darwin's `__error()` (`<sys/errno.h>`:
/// `#define errno (*__error())`).
///
/// # Safety
/// Writes the thread's errno slot; always sound on the calling thread.
pub(crate) unsafe fn set_errno(errno: c_int) {
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

/// Hook for `sendmsg(2)`, offered only for an fd a backend owns. A handled send is an effect
/// other threads see.
unsafe extern "C" fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> ssize_t {
    // man 2 sendmsg: struct msghdr {msg_name, msg_iov/msg_iovlen scatter-gather,
    // msg_control/msg_controllen ancillary cmsg(3)}; returns bytes sent.
    // SAFETY: `msg` is the caller's msghdr.
    if let Some(r) = domain::dispatch_owned_effect("sendmsg", fd, |net| unsafe {
            net.sendmsg(fd, msg.cast(), flags)
        })
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

/// Hook for `recvmsg(2)`, offered only for an fd a backend owns.
unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> ssize_t {
    // man 2 recvmsg: fills the msghdr's iovecs and sets msg_flags (e.g. MSG_TRUNC/MSG_CTRUNC).
    // SAFETY: `msg` is the caller's msghdr.
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe { net.recvmsg(fd, msg.cast(), flags) })
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

/// Hook for `recvmmsg(2)`, offered only for an fd a backend owns.
#[cfg(target_os = "linux")]
unsafe extern "C" fn recvmmsg(
    fd: c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: c_int,
    timeout: *mut libc::timespec,
) -> c_int {
    // SAFETY: `msgvec` holds `vlen` mmsghdrs and `timeout` is null or a timespec, the caller's.
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe {
            net.recvmmsg(fd, msgvec.cast(), vlen, flags, timeout.cast())
        })
    {
        return finish(r) as c_int;
    }
    domain::observe("recvmmsg", None);
    type RecvmmsgFn =
        unsafe extern "C" fn(c_int, *mut libc::mmsghdr, libc::c_uint, c_int, *mut libc::timespec) -> c_int;
    // SAFETY: RECVMMSG holds libc's recvmmsg.
    unsafe { original::<RecvmmsgFn>(&RECVMMSG)(fd, msgvec, vlen, flags, timeout) }
}

/// Hook for `sendmmsg(2)`, offered only for an fd a backend owns.
#[cfg(target_os = "linux")]
unsafe extern "C" fn sendmmsg(
    fd: c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: c_int,
) -> c_int {
    // SAFETY: `msgvec` holds `vlen` mmsghdrs, the caller's.
    if let Some(r) =
        domain::dispatch_owned(fd, |net| unsafe { net.sendmmsg(fd, msgvec.cast(), vlen, flags) })
    {
        return finish(r) as c_int;
    }
    domain::observe("sendmmsg", None);
    type SendmmsgFn = unsafe extern "C" fn(c_int, *mut libc::mmsghdr, libc::c_uint, c_int) -> c_int;
    // SAFETY: SENDMMSG holds libc's sendmmsg.
    unsafe { original::<SendmmsgFn>(&SENDMMSG)(fd, msgvec, vlen, flags) }
}

/// The default [`Net::sendmmsg`](crate::Net::sendmmsg): one `sendmsg` per message.
///
/// # Safety
/// As [`Net::sendmmsg`](crate::Net::sendmmsg).
#[cfg(target_os = "linux")]
pub(crate) unsafe fn sendmmsg_each<N: crate::Net + ?Sized>(
    net: &N,
    fd: c_int,
    msgvec: *mut u8,
    vlen: u32,
    flags: c_int,
) -> Option<crate::NetResult> {
    use crate::NetResult::{Err, Ok};
    const UIO_MAXIOV: u32 = 1024;
    let messages = msgvec.cast::<libc::mmsghdr>();
    let mut sent = 0;
    while sent < vlen.min(UIO_MAXIOV) {
        // SAFETY: `sent` is below `vlen`, so the slot is the caller's.
        let entry = unsafe { messages.add(sent as usize) };
        let hdr = unsafe { &raw const (*entry).msg_hdr };
        match unsafe { net.sendmsg(fd, hdr.cast(), flags) } {
            Some(Ok(n)) => unsafe { (*entry).msg_len = n as libc::c_uint },
            Some(Err(errno)) if sent == 0 => return Some(Err(errno)),
            Some(Err(_)) => break,
            None if sent == 0 => return None,
            None => break,
        }
        sent += 1;
    }
    Some(Ok(sent.into()))
}

/// The default [`Net::recvmmsg`](crate::Net::recvmmsg): one `recvmsg` per message.
///
/// # Safety
/// As [`Net::recvmmsg`](crate::Net::recvmmsg).
#[cfg(target_os = "linux")]
pub(crate) unsafe fn recvmmsg_each<N: crate::Net + ?Sized>(
    net: &N,
    fd: c_int,
    msgvec: *mut u8,
    vlen: u32,
    flags: c_int,
    timeout: *mut u8,
) -> Option<crate::NetResult> {
    use crate::NetResult::{Err, Ok};
    const UIO_MAXIOV: u32 = 1024;
    let messages = msgvec.cast::<libc::mmsghdr>();
    let timeout = timeout.cast::<libc::timespec>();
    let started = std::time::Instant::now();
    let now = || crate::domain::virtual_now().unwrap_or_else(|| started.elapsed());
    let end = if timeout.is_null() {
        None
    } else {
        // SAFETY: a non-null `timeout` is the caller's timespec.
        let t = unsafe { timeout.read() };
        if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
            return Some(Err(libc::EINVAL));
        }
        Some(now() + std::time::Duration::new(t.tv_sec as u64, t.tv_nsec as u32))
    };
    let mut flags = flags;
    let mut received = 0;
    while received < vlen.min(UIO_MAXIOV) {
        // SAFETY: `received` is below `vlen`, so the slot is the caller's.
        let entry = unsafe { messages.add(received as usize) };
        let hdr = unsafe { &raw mut (*entry).msg_hdr };
        match unsafe { net.recvmsg(fd, hdr.cast(), flags & !libc::MSG_WAITFORONE) } {
            Some(Ok(n)) => unsafe { (*entry).msg_len = n as libc::c_uint },
            Some(Err(errno)) if received == 0 => return Some(Err(errno)),
            Some(Err(errno)) => {
                if errno != libc::EAGAIN {
                    net.keep_error(fd, errno);
                }
                break;
            }
            None if received == 0 => return None,
            None => break,
        }
        received += 1;
        if flags & libc::MSG_WAITFORONE != 0 {
            flags |= libc::MSG_DONTWAIT;
        }
        if let Some(end) = end {
            let left = end.saturating_sub(now());
            // SAFETY: as above.
            unsafe {
                timeout.write(libc::timespec {
                    tv_sec: left.as_secs() as libc::time_t,
                    tv_nsec: left.subsec_nanos() as libc::c_long,
                })
            };
            if left.is_zero() {
                break;
            }
        }
    }
    Some(Ok(received.into()))
}

/// Hook for `getifaddrs(3)`: a backend may answer with its own simulated interface list.
unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
    // man 3 getifaddrs: allocates a linked list of struct ifaddrs {ifa_next, ifa_name,
    // ifa_flags (SIOCGIFFLAGS), ifa_addr, ifa_netmask, ifa_broadaddr}; freed by freeifaddrs.
    // SAFETY: `ifap` receives the list head.
    if let Some(r) = dispatch_net(|net| unsafe { net.getifaddrs(ifap.cast()) }) {
        return finish(r) as c_int;
    }
    domain::observe("getifaddrs", None);
    // SAFETY: GETIFADDRS holds libc's getifaddrs.
    unsafe { original::<unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int>(&GETIFADDRS)(ifap) }
}

/// Hook for `freeifaddrs(3)`. Every backend is offered the list and only the one that built it
/// claims it; anything else is the OS's own and goes to the real `freeifaddrs`. Not observed.
unsafe extern "C" fn freeifaddrs(ifa: *mut libc::ifaddrs) {
    // SAFETY: `ifa` is a list head. Offer it to the backend that may have produced it.
    if dispatch_net(|net| unsafe { net.freeifaddrs(ifa.cast()) }).is_some() {
        return;
    }
    // SAFETY: FREEIFADDRS holds libc's freeifaddrs.
    unsafe { original::<unsafe extern "C" fn(*mut libc::ifaddrs)>(&FREEIFADDRS)(ifa) }
}

/// Hook for `if_nametoindex(3)`. A handled failure returns 0 with errno set, the call's own
/// convention (POSIX `if_nametoindex`), rather than [`finish`]'s -1. On glibc an unknown name
/// fails with `ENODEV`, the `SIOCGIFINDEX` ioctl's error, which sysdeps/unix/sysv/linux/if_index.c
/// `__if_nametoindex` passes through (and sets itself for a name of `IFNAMSIZ` or more); Darwin
/// sets `ENXIO` (Libinfo gen.subproj/if_nametoindex.c).
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

/// Hook for `if_indextoname(3)`: a handled success returns the caller's `name` buffer, a
/// handled failure NULL with errno set (POSIX `if_indextoname`; glibc
/// sysdeps/unix/sysv/linux/if_index.c `__if_indextoname` and Darwin Libinfo
/// gen.subproj/if_indextoname.c both use `ENXIO`).
unsafe extern "C" fn if_indextoname(index: libc::c_uint, name: *mut c_char) -> *mut c_char {
    // man 3 if_indextoname: writes the name into an IF_NAMESIZE buffer and returns it, or NULL
    // with errno set when no interface has that index.
    // SAFETY: `name` is the caller's IF_NAMESIZE buffer.
    if let Some(r) = dispatch_net(|net| unsafe { net.if_indextoname(index, name) }) {
        if r < 0 {
            // SAFETY: setting the calling thread's errno.
            unsafe { set_errno((-r) as c_int) };
            return std::ptr::null_mut();
        }
        return r as *mut c_char;
    }
    // SAFETY: IF_INDEXTONAME holds libc's if_indextoname.
    unsafe {
        original::<unsafe extern "C" fn(libc::c_uint, *mut c_char) -> *mut c_char>(&IF_INDEXTONAME)(
            index, name,
        )
    }
}

/// Hook for `if_nameindex(3)`: a handled success returns the backend's array as a pointer.
unsafe extern "C" fn if_nameindex() -> *mut libc::if_nameindex {
    // man 3 if_nameindex: an array of {if_index, if_name} ended by a zero entry, or NULL with
    // errno set.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_net(|net| unsafe { net.if_nameindex() }) {
        if r < 0 {
            // SAFETY: setting the calling thread's errno.
            unsafe { set_errno((-r) as c_int) };
            return std::ptr::null_mut();
        }
        return r as *mut libc::if_nameindex;
    }
    // SAFETY: IF_NAMEINDEX holds libc's if_nameindex.
    unsafe { original::<unsafe extern "C" fn() -> *mut libc::if_nameindex>(&IF_NAMEINDEX)() }
}

/// Hook for `if_freenameindex(3)`: the backend that built the array releases it; any other array
/// is the OS's.
unsafe extern "C" fn if_freenameindex(ptr: *mut libc::if_nameindex) {
    // SAFETY: `ptr` came from if_nameindex; the backend that made it releases it.
    if dispatch_net(|net| unsafe { net.if_freenameindex(ptr.cast()) }).is_some() {
        return;
    }
    // SAFETY: IF_FREENAMEINDEX holds libc's if_freenameindex.
    unsafe { original::<unsafe extern "C" fn(*mut libc::if_nameindex)>(&IF_FREENAMEINDEX)(ptr) }
}

/// Hook for `socket(2)`: a backend may mint a simulated socket fd.
unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    // man 2 socket: (AF_*, SOCK_* | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol) -> new fd.
    // SAFETY: no pointers.
    if let Some(r) = domain::descriptor_transaction(|| {
        dispatch_net(|net| unsafe { net.socket(domain, ty, protocol) })
    }) {
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

/// Hook for `socketpair(2)`: two connected, unnamed sockets of `domain` (`AF_UNIX`) written to
/// `fds`.
unsafe extern "C" fn socketpair(
    domain: c_int,
    ty: c_int,
    protocol: c_int,
    fds: *mut c_int,
) -> c_int {
    // SAFETY: `fds` holds two writable ints.
    if let Some(r) = domain::descriptor_transaction(|| {
        dispatch_net(|net| unsafe { net.socketpair(domain, ty, protocol, fds) })
    }) {
        return finish(r) as c_int;
    }
    domain::observe("socketpair", None);
    // SAFETY: SOCKETPAIR holds libc's socketpair.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int, c_int, *mut c_int) -> c_int>(&SOCKETPAIR)(
            domain, ty, protocol, fds,
        )
    }
}

/// Hook for `connect(2)`; a handled connect is an effect other threads see.
unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    // man 2 connect: `len` is the sockaddr size; a nonblocking connect returns EINPROGRESS.
    // SAFETY: `addr` points to `len` bytes.
    if let Some(r) = domain::dispatch_net_effect("connect", |net| unsafe {
        net.connect(fd, addr.cast(), len)
    }) {
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

/// Hook for `bind(2)`.
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

/// Hook for `listen(2)`.
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

/// Hook for `accept(2)`, offered as [`Net::accept`](crate::Net::accept) with no flags.
unsafe extern "C" fn accept(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // man 2 accept: `len` is in/out (buffer capacity in, actual peer-addr size out).
    // SAFETY: `addr`/`len` receive the peer address.
    if let Some(r) = domain::dispatch_net_effect("accept", |net| unsafe {
        net.accept(fd, addr.cast(), len.cast(), 0)
    }) {
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
/// Hook for `accept4(2)` (Linux). Noted for the audit under the same name as `accept`, but
/// observed as `accept4` when forwarded.
unsafe extern "C" fn accept4(
    fd: c_int,
    addr: *mut sockaddr,
    len: *mut socklen_t,
    flags: c_int,
) -> c_int {
    // man 2 accept4: accept plus SOCK_NONBLOCK/SOCK_CLOEXEC on the new fd (Linux-specific).
    // SAFETY: `addr`/`len` receive the peer address.
    if let Some(r) = domain::dispatch_net_effect("accept", |net| unsafe {
        net.accept(fd, addr.cast(), len.cast(), flags)
    }) {
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

/// Hook for `send(2)`; a handled send is an effect other threads see.
unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    // man 2 send: flags MSG_DONTWAIT/MSG_NOSIGNAL/MSG_MORE; a full buffer yields EAGAIN.
    // SAFETY: `buf` points to `len` bytes.
    if let Some(r) = domain::dispatch_net_effect("send", |net| unsafe {
        net.send(fd, buf.cast(), len, flags)
    }) {
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

/// Hook for `recv(2)`.
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

/// Hook for `sendto(2)`; a handled send is an effect other threads see.
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
    if let Some(r) = domain::dispatch_net_effect("sendto", |net| unsafe {
        net.sendto(fd, buf.cast(), len, flags, addr.cast(), addr_len)
    }) {
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

/// Hook for `recvfrom(2)`.
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

/// Hook for `shutdown(2)`; a handled shutdown is an effect the peer sees.
unsafe extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    // man 2 shutdown: how is SHUT_RD(0)/SHUT_WR(1)/SHUT_RDWR(2).
    // SAFETY: no pointers.
    if let Some(r) = domain::dispatch_net_effect("shutdown", |net| unsafe { net.shutdown(fd, how) })
    {
        return finish(r) as c_int;
    }
    domain::observe("shutdown", None);
    // SAFETY: SHUTDOWN holds libc's shutdown.
    unsafe { original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&SHUTDOWN)(fd, how) }
}

/// Hook for `close(2)`. The file plane is asked first, then the network plane, each only for an
/// fd it owns; a real fd closes without being observed.
unsafe extern "C" fn close(fd: c_int) -> c_int {
    let handled = domain::descriptor_transaction(|| {
        if fs_owns(fd)
            && let Some(result) = dispatch_fs(|fs| unsafe { fs.close(fd) })
        {
            return Some(result);
        }
        if let Some(result) =
            domain::dispatch_owned_effect("close", fd, |net| unsafe { net.close(fd) })
        {
            return Some(result);
        }
        if domain::descriptor_close_can_wait(fd) {
            return None;
        }
        crate::owners::forget_real(fd);
        let result = unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&CLOSE)(fd) };
        Some(if result < 0 {
            -i64::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EBADF),
            )
        } else {
            i64::from(result)
        })
    });
    if let Some(result) = handled {
        return finish(result) as c_int;
    }
    crate::owners::forget_real(fd);
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&CLOSE)(fd) }
}

/// Hook for `getsockname(2)`.
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

/// Hook for `getpeername(2)`.
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

/// Hook for `setsockopt(2)`.
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

/// Hook for `getsockopt(2)`.
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

/// Hook for `poll(2)`. Offered for any fd set; a backend declines a set it cannot answer.
// nfds_t is `unsigned int` on macOS (<sys/poll.h>) and `unsigned long` on Linux (<sys/poll.h>).
#[allow(clippy::unnecessary_cast)]
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

unsafe extern "C" fn dup(fd: c_int) -> c_int {
    domain::descriptor_transaction(|| unsafe { dup_inner(fd) })
}

unsafe fn dup_inner(fd: c_int) -> c_int {
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe { net.dup(fd) })
    {
        return finish(r) as c_int;
    }
    let newfd = unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&DUP)(fd) };
    if newfd >= 0 && fs_owns(fd) {
        let _ = dispatch_fs(|fs| unsafe { fs.dup(fd, newfd) });
    }
    newfd
}

unsafe extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let real = || {
        let result =
            unsafe { original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&DUP2)(oldfd, newfd) };
        if result >= 0 && oldfd != newfd {
            crate::owners::forget_real(newfd);
        }
        result
    };
    if let Some(result) =
        domain::descriptor_transaction(|| domain::dispatch_dup_to(oldfd, newfd, None, real))
    {
        return finish(result) as c_int;
    }
    real()
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
    let real = || {
        let result = unsafe {
            original::<unsafe extern "C" fn(c_int, c_int, c_int) -> c_int>(&DUP3)(
                oldfd, newfd, flags,
            )
        };
        if result >= 0 {
            crate::owners::forget_real(newfd);
        }
        result
    };
    if let Some(result) =
        domain::descriptor_transaction(|| domain::dispatch_dup_to(oldfd, newfd, Some(flags), real))
    {
        return finish(result) as c_int;
    }
    real()
}

unsafe extern "C" fn select(
    nfds: c_int,
    read: *mut libc::fd_set,
    write: *mut libc::fd_set,
    except: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    if let Some(r) = dispatch_net(|net| unsafe {
        net.select(
            nfds,
            read.cast(),
            write.cast(),
            except.cast(),
            timeout.cast(),
        )
    }) {
        return finish(r) as c_int;
    }
    domain::observe("select", None);
    unsafe {
        original::<
            unsafe extern "C" fn(
                c_int,
                *mut libc::fd_set,
                *mut libc::fd_set,
                *mut libc::fd_set,
                *mut libc::timeval,
            ) -> c_int,
        >(&SELECT)(nfds, read, write, except, timeout)
    }
}

/// Hook for `read(2)`: the owning plane's `read`, else the OS, unobserved.
unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, len: size_t) -> ssize_t {
    // man 2 read: returns bytes read (0 at EOF); a stream socket fd reads like a byte stream.
    // SAFETY: `buf` points to `len` writable bytes.
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.read(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: `buf` points to `len` writable bytes.
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe { net.read(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: READ holds libc's read.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t>(&READ)(fd, buf, len)
    }
}

/// Hook for `write(2)`: the owning plane's `write`, else the OS, unobserved. A handled socket
/// write is an effect other threads see.
unsafe extern "C" fn write(fd: c_int, buf: *const c_void, len: size_t) -> ssize_t {
    // man 2 write: may write fewer than `len` bytes (a short write) before returning.
    // SAFETY: `buf` points to `len` readable bytes.
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.write(fd, buf.cast(), len) })
    {
        return finish(r) as ssize_t;
    }
    // SAFETY: `buf` points to `len` readable bytes.
    if let Some(r) = domain::dispatch_owned_effect("write", fd, |net| unsafe {
        net.write(fd, buf.cast(), len)
    })
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
/// variadic pointer; elsewhere it travels in a register like a named argument (Apple, "Writing
/// ARM64 code for Apple platforms": variadic arguments go on the stack,
/// <https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms>;
/// AAPCS64 and the System V AMD64 ABI pass the first variadic words in registers).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type FcntlFn = unsafe extern "C" fn(c_int, c_int, ...) -> c_int;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
type FcntlFn = unsafe extern "C" fn(c_int, c_int, i64) -> c_int;

/// Hook for `fcntl(2)`: the owning plane's `fcntl`, else the OS, unobserved. `arg` is the third
/// word as an integer; the commands a backend models take no pointer.
///
/// On macOS aarch64 the third word reaches here via the naked trampoline in `crate::os::variadic`.
// The trampoline tail-branches here from another codegen unit, so the symbol must have external
// linkage to be resolvable; `sym` still emits the right (mangled) reference.
#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64"),
    unsafe(export_name = "__snare_interpose_fcntl")
)]
pub(crate) unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: i64) -> c_int {
    if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
        return domain::descriptor_transaction(|| unsafe { fcntl_inner(fd, cmd, arg) });
    }
    unsafe { fcntl_inner(fd, cmd, arg) }
}

unsafe fn fcntl_inner(fd: c_int, cmd: c_int, arg: i64) -> c_int {
    // man 2 fcntl: the modeled commands are F_GETFL/F_SETFL (O_NONBLOCK), F_GETFD/F_SETFD
    // (FD_CLOEXEC) and F_DUPFD/F_DUPFD_CLOEXEC.
    // SAFETY: no pointer args for the fcntl commands a socket/file sees (flags, dup).
    if fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.fcntl(fd, cmd, arg) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: no pointer args for the fcntl commands a socket sees (flags, dup).
    if let Some(r) = domain::dispatch_owned(fd, |net| unsafe { net.fcntl(fd, cmd, arg) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: FCNTL holds libc's fcntl.
    unsafe { original::<FcntlFn>(&FCNTL)(fd, cmd, arg) }
}
