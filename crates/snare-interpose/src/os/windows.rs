use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_NOT_SUPPORTED, FILETIME, GetLastError, HANDLE, HMODULE, SetLastError,
};
use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;
use windows_sys::Win32::System::Threading::GetThreadId;

use crate::domain::{self, dispatch, dispatch_host, dispatch_net, net_owns};
use crate::hooks::{self, Hook, hook, observed, original};
use crate::layer::{ClockKind, SleepRequest};
use crate::state;

static QUERY_PERFORMANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_TIME_PRECISE_AS_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_TIME_AS_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static SLEEP: AtomicUsize = AtomicUsize::new(0);
static SLEEP_EX: AtomicUsize = AtomicUsize::new(0);
static CREATE_WAITABLE_TIMER_EX_W: AtomicUsize = AtomicUsize::new(0);
static CREATE_THREAD: AtomicUsize = AtomicUsize::new(0);
static GET_PROC_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static PROCESS_PRNG: AtomicUsize = AtomicUsize::new(0);
static BCRYPT_GEN_RANDOM: AtomicUsize = AtomicUsize::new(0);
static LOAD_LIBRARY_A: AtomicUsize = AtomicUsize::new(0);
static LOAD_LIBRARY_W: AtomicUsize = AtomicUsize::new(0);
static LOAD_LIBRARY_EX_A: AtomicUsize = AtomicUsize::new(0);
static LOAD_LIBRARY_EX_W: AtomicUsize = AtomicUsize::new(0);
static PCAP_CREATE: AtomicUsize = AtomicUsize::new(0);
static PCAP_OPEN_LIVE: AtomicUsize = AtomicUsize::new(0);
static PCAP_ACTIVATE: AtomicUsize = AtomicUsize::new(0);
static PCAP_SET_IMMEDIATE_MODE: AtomicUsize = AtomicUsize::new(0);
static PCAP_SETNONBLOCK: AtomicUsize = AtomicUsize::new(0);
static PCAP_SENDPACKET: AtomicUsize = AtomicUsize::new(0);
static PCAP_SENDQUEUE_ALLOC: AtomicUsize = AtomicUsize::new(0);
static PCAP_SENDQUEUE_QUEUE: AtomicUsize = AtomicUsize::new(0);
static PCAP_SENDQUEUE_TRANSMIT: AtomicUsize = AtomicUsize::new(0);
static PCAP_SENDQUEUE_DESTROY: AtomicUsize = AtomicUsize::new(0);
static PCAP_GETERR: AtomicUsize = AtomicUsize::new(0);
static PCAP_NEXT_EX: AtomicUsize = AtomicUsize::new(0);
static PCAP_CLOSE: AtomicUsize = AtomicUsize::new(0);
static SET_THREAD_PRIORITY: AtomicUsize = AtomicUsize::new(0);
static GET_THREAD_PRIORITY: AtomicUsize = AtomicUsize::new(0);
static SET_THREAD_AFFINITY_MASK: AtomicUsize = AtomicUsize::new(0);
static SET_PRIORITY_CLASS: AtomicUsize = AtomicUsize::new(0);
static GET_PRIORITY_CLASS: AtomicUsize = AtomicUsize::new(0);
static TIME_BEGIN_PERIOD: AtomicUsize = AtomicUsize::new(0);
static TIME_END_PERIOD: AtomicUsize = AtomicUsize::new(0);
static WAIT_FOR_SINGLE_OBJECT: AtomicUsize = AtomicUsize::new(0);
static WAIT_ON_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static SWITCH_TO_THREAD: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn hooks() -> Vec<Hook> {
    let mut hooks = vec![
        hook!(
            "QueryPerformanceCounter",
            "kernel32.dll",
            query_performance_counter,
            QUERY_PERFORMANCE_COUNTER
        ),
        hook!(
            "GetSystemTimePreciseAsFileTime",
            "kernel32.dll",
            get_system_time_precise_as_file_time,
            GET_SYSTEM_TIME_PRECISE_AS_FILE_TIME
        ),
        hook!(
            "GetSystemTimeAsFileTime",
            "kernel32.dll",
            get_system_time_as_file_time,
            GET_SYSTEM_TIME_AS_FILE_TIME
        ),
        hook!("Sleep", "kernel32.dll", sleep, SLEEP),
        hook!("SleepEx", "kernel32.dll", sleep_ex, SLEEP_EX),
        hook!(
            "CreateWaitableTimerExW",
            "kernel32.dll",
            create_waitable_timer_ex_w,
            CREATE_WAITABLE_TIMER_EX_W
        ),
        hook!("CreateThread", "kernel32.dll", create_thread, CREATE_THREAD),
        hook!(
            "WaitForSingleObject",
            "kernel32.dll",
            wait_for_single_object,
            WAIT_FOR_SINGLE_OBJECT
        ),
        hook!(
            "WaitOnAddress",
            "api-ms-win-core-synch-l1-2-0.dll",
            wait_on_address,
            WAIT_ON_ADDRESS
        ),
        hook!("SwitchToThread", "kernel32.dll", switch_to_thread, SWITCH_TO_THREAD),
        hook!(
            "GetProcAddress",
            "kernel32.dll",
            get_proc_address,
            GET_PROC_ADDRESS
        ),
        hook!(
            "ProcessPrng",
            "bcryptprimitives.dll",
            process_prng,
            PROCESS_PRNG
        ),
        hook!(
            "BCryptGenRandom",
            "bcrypt.dll",
            bcrypt_gen_random,
            BCRYPT_GEN_RANDOM
        ),
        hook!(
            "LoadLibraryA",
            "kernel32.dll",
            load_library_a,
            LOAD_LIBRARY_A
        ),
        hook!(
            "LoadLibraryW",
            "kernel32.dll",
            load_library_w,
            LOAD_LIBRARY_W
        ),
        hook!(
            "LoadLibraryExA",
            "kernel32.dll",
            load_library_ex_a,
            LOAD_LIBRARY_EX_A
        ),
        hook!(
            "LoadLibraryExW",
            "kernel32.dll",
            load_library_ex_w,
            LOAD_LIBRARY_EX_W
        ),
        hook!(
            "SetThreadPriority",
            "kernel32.dll",
            set_thread_priority,
            SET_THREAD_PRIORITY
        ),
        hook!(
            "GetThreadPriority",
            "kernel32.dll",
            get_thread_priority,
            GET_THREAD_PRIORITY
        ),
        hook!(
            "SetThreadAffinityMask",
            "kernel32.dll",
            set_thread_affinity_mask,
            SET_THREAD_AFFINITY_MASK
        ),
        hook!(
            "SetPriorityClass",
            "kernel32.dll",
            set_priority_class,
            SET_PRIORITY_CLASS
        ),
        hook!(
            "GetPriorityClass",
            "kernel32.dll",
            get_priority_class,
            GET_PRIORITY_CLASS
        ),
        hook!("timeBeginPeriod", "winmm.dll", time_begin_period, TIME_BEGIN_PERIOD),
        hook!("timeEndPeriod", "winmm.dll", time_end_period, TIME_END_PERIOD),
        hook!("pcap_create", "wpcap.dll", pcap_create, PCAP_CREATE),
        hook!("pcap_open_live", "wpcap.dll", pcap_open_live, PCAP_OPEN_LIVE),
        hook!("pcap_activate", "wpcap.dll", pcap_activate, PCAP_ACTIVATE),
        hook!(
            "pcap_set_immediate_mode",
            "wpcap.dll",
            pcap_set_immediate_mode,
            PCAP_SET_IMMEDIATE_MODE
        ),
        hook!("pcap_setnonblock", "wpcap.dll", pcap_setnonblock, PCAP_SETNONBLOCK),
        hook!("pcap_sendpacket", "wpcap.dll", pcap_sendpacket, PCAP_SENDPACKET),
        hook!("pcap_next_ex", "wpcap.dll", pcap_next_ex, PCAP_NEXT_EX),
        hook!("pcap_close", "wpcap.dll", pcap_close, PCAP_CLOSE),
        hook!("pcap_sendqueue_alloc", "wpcap.dll", pcap_sendqueue_alloc, PCAP_SENDQUEUE_ALLOC),
        hook!("pcap_sendqueue_queue", "wpcap.dll", pcap_sendqueue_queue, PCAP_SENDQUEUE_QUEUE),
        hook!(
            "pcap_sendqueue_transmit",
            "wpcap.dll",
            pcap_sendqueue_transmit,
            PCAP_SENDQUEUE_TRANSMIT
        ),
        hook!("pcap_sendqueue_destroy", "wpcap.dll", pcap_sendqueue_destroy, PCAP_SENDQUEUE_DESTROY),
        hook!("pcap_geterr", "wpcap.dll", pcap_geterr, PCAP_GETERR),
    ];
    hooks.extend(winsock_hooks());
    hooks.extend(observed_hooks());
    hooks
}

static WS_SOCKET: AtomicUsize = AtomicUsize::new(0);
static WS_WSASOCKETW: AtomicUsize = AtomicUsize::new(0);
static WS_BIND: AtomicUsize = AtomicUsize::new(0);
static WS_CONNECT: AtomicUsize = AtomicUsize::new(0);
static WS_SEND: AtomicUsize = AtomicUsize::new(0);
static WS_RECV: AtomicUsize = AtomicUsize::new(0);
static WS_SENDTO: AtomicUsize = AtomicUsize::new(0);
static WS_RECVFROM: AtomicUsize = AtomicUsize::new(0);
static WS_CLOSESOCKET: AtomicUsize = AtomicUsize::new(0);
static WS_GETSOCKNAME: AtomicUsize = AtomicUsize::new(0);
static WS_GETPEERNAME: AtomicUsize = AtomicUsize::new(0);
static WS_SETSOCKOPT: AtomicUsize = AtomicUsize::new(0);
static WS_GETSOCKOPT: AtomicUsize = AtomicUsize::new(0);
static WS_IOCTLSOCKET: AtomicUsize = AtomicUsize::new(0);
static WS_LISTEN: AtomicUsize = AtomicUsize::new(0);
static WS_ACCEPT: AtomicUsize = AtomicUsize::new(0);
static WS_SHUTDOWN: AtomicUsize = AtomicUsize::new(0);
static WS_WSAPOLL: AtomicUsize = AtomicUsize::new(0);
static WS_WSADUPLICATESOCKETW: AtomicUsize = AtomicUsize::new(0);

/// Tag written into the `WSAPROTOCOL_INFOW` blob by `WSADuplicateSocketW` for a sim socket: a magic
/// word (never a real `dwServiceFlags1`) followed by the pre-created duplicate's handle, which
/// `WSASocketW` reads back. Keeps the duplicate within the sim rather than touching the real OS.
const DUP_TAG: u32 = 0x5a4e_4554;

type Socket = usize;
const INVALID_SOCKET: Socket = usize::MAX;
const SOCKET_ERROR: c_int = -1;

/// Winsock `SOCKET`-returning convention: `Err(e)` sets the last error and returns `INVALID_SOCKET`.
fn finish_socket(handled: i64) -> Socket {
    if handled < 0 {
        unsafe { SetLastError((-handled) as u32) };
        INVALID_SOCKET
    } else {
        handled as Socket
    }
}

/// Winsock `c_int`-returning convention: `Err(e)` sets the last error and returns `SOCKET_ERROR`.
fn finish_sock(handled: i64) -> c_int {
    if handled < 0 {
        unsafe { SetLastError((-handled) as u32) };
        SOCKET_ERROR
    } else {
        handled as c_int
    }
}

fn winsock_hooks() -> Vec<Hook> {
    vec![
        hook!("socket", "ws2_32.dll", ws_socket, WS_SOCKET),
        hook!("WSASocketW", "ws2_32.dll", ws_wsasocketw, WS_WSASOCKETW),
        hook!("bind", "ws2_32.dll", ws_bind, WS_BIND),
        hook!("connect", "ws2_32.dll", ws_connect, WS_CONNECT),
        hook!("send", "ws2_32.dll", ws_send, WS_SEND),
        hook!("recv", "ws2_32.dll", ws_recv, WS_RECV),
        hook!("sendto", "ws2_32.dll", ws_sendto, WS_SENDTO),
        hook!("recvfrom", "ws2_32.dll", ws_recvfrom, WS_RECVFROM),
        hook!("closesocket", "ws2_32.dll", ws_closesocket, WS_CLOSESOCKET),
        hook!("getsockname", "ws2_32.dll", ws_getsockname, WS_GETSOCKNAME),
        hook!("getpeername", "ws2_32.dll", ws_getpeername, WS_GETPEERNAME),
        hook!("setsockopt", "ws2_32.dll", ws_setsockopt, WS_SETSOCKOPT),
        hook!("getsockopt", "ws2_32.dll", ws_getsockopt, WS_GETSOCKOPT),
        hook!("ioctlsocket", "ws2_32.dll", ws_ioctlsocket, WS_IOCTLSOCKET),
        hook!("listen", "ws2_32.dll", ws_listen, WS_LISTEN),
        hook!("accept", "ws2_32.dll", ws_accept, WS_ACCEPT),
        hook!("shutdown", "ws2_32.dll", ws_shutdown, WS_SHUTDOWN),
        hook!("WSAPoll", "ws2_32.dll", ws_wsapoll, WS_WSAPOLL),
        hook!(
            "WSADuplicateSocketW",
            "ws2_32.dll",
            ws_wsaduplicatesocketw,
            WS_WSADUPLICATESOCKETW
        ),
    ]
}

// MSDN WSADuplicateSocketW: fills a protocol-info blob another `WSASocketW` turns back into a
// socket. For a sim socket we create the duplicate now and stash its handle (behind DUP_TAG) in
// the blob; the matching `WSASocketW` reads it back.
unsafe extern "system" fn ws_wsaduplicatesocketw(
    s: Socket,
    _pid: u32,
    info: *mut c_void,
) -> c_int {
    if net_owns(s as c_int)
        && !info.is_null()
        && let Some(r) = dispatch_net(|net| unsafe { net.dup(s as c_int) })
    {
        if r < 0 {
            unsafe { SetLastError((-r) as u32) };
            return SOCKET_ERROR;
        }
        unsafe {
            info.cast::<u32>().write_unaligned(DUP_TAG);
            info.cast::<u8>().add(4).cast::<i32>().write_unaligned(r as i32);
        }
        return 0;
    }
    domain::observe("WSADuplicateSocketW", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, u32, *mut c_void) -> c_int>(
            &WS_WSADUPLICATESOCKETW,
        )(s, _pid, info)
    }
}

// MSDN WSAPoll: poll an array of `WSAPOLLFD` with a millisecond `timeout` (-1 blocks). The backend
// interprets the array as its own and fills `revents`.
unsafe extern "system" fn ws_wsapoll(fds: *mut c_void, nfds: u32, timeout: c_int) -> c_int {
    if let Some(r) = dispatch_net(|net| unsafe { net.poll(fds.cast(), nfds as u64, timeout) }) {
        return finish_sock(r);
    }
    domain::observe("WSAPoll", None);
    unsafe {
        original::<unsafe extern "system" fn(*mut c_void, u32, c_int) -> c_int>(&WS_WSAPOLL)(
            fds, nfds, timeout,
        )
    }
}

unsafe extern "system" fn ws_listen(s: Socket, backlog: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.listen(s as c_int, backlog) })
    {
        return finish_sock(r);
    }
    domain::observe("listen", None);
    unsafe { original::<unsafe extern "system" fn(Socket, c_int) -> c_int>(&WS_LISTEN)(s, backlog) }
}

unsafe extern "system" fn ws_accept(s: Socket, addr: *mut c_void, addrlen: *mut c_int) -> Socket {
    if net_owns(s as c_int) {
        let mut ulen: u32 = if addrlen.is_null() { 0 } else { unsafe { *addrlen }.max(0) as u32 };
        let lenp = if addrlen.is_null() { std::ptr::null_mut() } else { &mut ulen as *mut u32 };
        if let Some(r) = dispatch_net(|net| unsafe { net.accept(s as c_int, addr.cast(), lenp, 0) }) {
            if !addrlen.is_null() {
                unsafe { *addrlen = ulen as c_int };
            }
            return finish_socket(r);
        }
    }
    domain::observe("accept", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> Socket>(&WS_ACCEPT)(
            s, addr, addrlen,
        )
    }
}

unsafe extern "system" fn ws_shutdown(s: Socket, how: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.shutdown(s as c_int, how) })
    {
        return finish_sock(r);
    }
    domain::observe("shutdown", None);
    unsafe { original::<unsafe extern "system" fn(Socket, c_int) -> c_int>(&WS_SHUTDOWN)(s, how) }
}

unsafe extern "system" fn ws_socket(af: c_int, ty: c_int, proto: c_int) -> Socket {
    if let Some(r) = dispatch_net(|net| unsafe { net.socket(af, ty, proto) }) {
        return finish_socket(r);
    }
    domain::observe("socket", None);
    unsafe { original::<unsafe extern "system" fn(c_int, c_int, c_int) -> Socket>(&WS_SOCKET)(af, ty, proto) }
}

// MSDN WSASocketW: the extended socket constructor; the sim maps it to the same backend `socket`.
unsafe extern "system" fn ws_wsasocketw(
    af: c_int,
    ty: c_int,
    proto: c_int,
    info: *mut c_void,
    group: u32,
    flags: u32,
) -> Socket {
    // A tagged protocol-info blob means this is a `try_clone`/`WSADuplicateSocket` of a sim socket;
    // return the handle the duplicate step pre-created.
    if !info.is_null() && unsafe { info.cast::<u32>().read_unaligned() } == DUP_TAG {
        let dup = unsafe { info.cast::<u8>().add(4).cast::<i32>().read_unaligned() };
        return dup as Socket;
    }
    if let Some(r) = dispatch_net(|net| unsafe { net.socket(af, ty, proto) }) {
        return finish_socket(r);
    }
    domain::observe("WSASocketW", None);
    unsafe {
        original::<unsafe extern "system" fn(c_int, c_int, c_int, *mut c_void, u32, u32) -> Socket>(
            &WS_WSASOCKETW,
        )(af, ty, proto, info, group, flags)
    }
}

unsafe extern "system" fn ws_bind(s: Socket, name: *const c_void, namelen: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.bind(s as c_int, name.cast(), namelen.max(0) as u32) })
    {
        return finish_sock(r);
    }
    domain::observe("bind", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *const c_void, c_int) -> c_int>(&WS_BIND)(s, name, namelen) }
}

unsafe extern "system" fn ws_connect(s: Socket, name: *const c_void, namelen: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.connect(s as c_int, name.cast(), namelen.max(0) as u32) })
    {
        return finish_sock(r);
    }
    domain::observe("connect", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *const c_void, c_int) -> c_int>(&WS_CONNECT)(s, name, namelen) }
}

unsafe extern "system" fn ws_send(s: Socket, buf: *const u8, len: c_int, flags: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.send(s as c_int, buf, len.max(0) as usize, flags) })
    {
        return finish_sock(r);
    }
    domain::observe("send", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *const u8, c_int, c_int) -> c_int>(&WS_SEND)(s, buf, len, flags) }
}

unsafe extern "system" fn ws_recv(s: Socket, buf: *mut u8, len: c_int, flags: c_int) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.recv(s as c_int, buf, len.max(0) as usize, flags) })
    {
        return finish_sock(r);
    }
    domain::observe("recv", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *mut u8, c_int, c_int) -> c_int>(&WS_RECV)(s, buf, len, flags) }
}

unsafe extern "system" fn ws_sendto(
    s: Socket,
    buf: *const u8,
    len: c_int,
    flags: c_int,
    to: *const c_void,
    tolen: c_int,
) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe {
            net.sendto(s as c_int, buf, len.max(0) as usize, flags, to.cast(), tolen.max(0) as u32)
        })
    {
        return finish_sock(r);
    }
    domain::observe("sendto", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *const u8, c_int, c_int, *const c_void, c_int) -> c_int>(
            &WS_SENDTO,
        )(s, buf, len, flags, to, tolen)
    }
}

unsafe extern "system" fn ws_recvfrom(
    s: Socket,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
    from: *mut c_void,
    fromlen: *mut c_int,
) -> c_int {
    if net_owns(s as c_int) {
        // Bridge Winsock's `*mut c_int` address length to the backend's `*mut u32`.
        let mut ulen: u32 = if fromlen.is_null() { 0 } else { unsafe { *fromlen }.max(0) as u32 };
        let lenp = if fromlen.is_null() { std::ptr::null_mut() } else { &mut ulen as *mut u32 };
        if let Some(r) =
            dispatch_net(|net| unsafe { net.recvfrom(s as c_int, buf, len.max(0) as usize, flags, from.cast(), lenp) })
        {
            if !fromlen.is_null() {
                unsafe { *fromlen = ulen as c_int };
            }
            return finish_sock(r);
        }
    }
    domain::observe("recvfrom", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut u8, c_int, c_int, *mut c_void, *mut c_int) -> c_int>(
            &WS_RECVFROM,
        )(s, buf, len, flags, from, fromlen)
    }
}

unsafe extern "system" fn ws_closesocket(s: Socket) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.close(s as c_int) })
    {
        return finish_sock(r);
    }
    domain::observe("closesocket", None);
    unsafe { original::<unsafe extern "system" fn(Socket) -> c_int>(&WS_CLOSESOCKET)(s) }
}

unsafe extern "system" fn ws_getsockname(s: Socket, name: *mut c_void, namelen: *mut c_int) -> c_int {
    if net_owns(s as c_int) {
        let mut ulen: u32 = if namelen.is_null() { 0 } else { unsafe { *namelen }.max(0) as u32 };
        let lenp = if namelen.is_null() { std::ptr::null_mut() } else { &mut ulen as *mut u32 };
        if let Some(r) = dispatch_net(|net| unsafe { net.getsockname(s as c_int, name.cast(), lenp) }) {
            if !namelen.is_null() {
                unsafe { *namelen = ulen as c_int };
            }
            return finish_sock(r);
        }
    }
    domain::observe("getsockname", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> c_int>(&WS_GETSOCKNAME)(s, name, namelen) }
}

unsafe extern "system" fn ws_getpeername(s: Socket, name: *mut c_void, namelen: *mut c_int) -> c_int {
    if net_owns(s as c_int) {
        let mut ulen: u32 = if namelen.is_null() { 0 } else { unsafe { *namelen }.max(0) as u32 };
        let lenp = if namelen.is_null() { std::ptr::null_mut() } else { &mut ulen as *mut u32 };
        if let Some(r) = dispatch_net(|net| unsafe { net.getpeername(s as c_int, name.cast(), lenp) }) {
            if !namelen.is_null() {
                unsafe { *namelen = ulen as c_int };
            }
            return finish_sock(r);
        }
    }
    domain::observe("getpeername", None);
    unsafe { original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> c_int>(&WS_GETPEERNAME)(s, name, namelen) }
}

unsafe extern "system" fn ws_setsockopt(
    s: Socket,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: c_int,
) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) =
            dispatch_net(|net| unsafe { net.setsockopt(s as c_int, level, name, val, len.max(0) as u32) })
    {
        return finish_sock(r);
    }
    domain::observe("setsockopt", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, c_int, c_int, *const u8, c_int) -> c_int>(&WS_SETSOCKOPT)(
            s, level, name, val, len,
        )
    }
}

unsafe extern "system" fn ws_getsockopt(
    s: Socket,
    level: c_int,
    name: c_int,
    val: *mut u8,
    len: *mut c_int,
) -> c_int {
    if net_owns(s as c_int) {
        let mut ulen: u32 = if len.is_null() { 0 } else { unsafe { *len }.max(0) as u32 };
        let lenp = if len.is_null() { std::ptr::null_mut() } else { &mut ulen as *mut u32 };
        if let Some(r) = dispatch_net(|net| unsafe { net.getsockopt(s as c_int, level, name, val, lenp) }) {
            if !len.is_null() {
                unsafe { *len = ulen as c_int };
            }
            return finish_sock(r);
        }
    }
    domain::observe("getsockopt", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, c_int, c_int, *mut u8, *mut c_int) -> c_int>(&WS_GETSOCKOPT)(
            s, level, name, val, len,
        )
    }
}

unsafe extern "system" fn ws_ioctlsocket(s: Socket, cmd: c_int, argp: *mut u32) -> c_int {
    if net_owns(s as c_int)
        && let Some(r) = dispatch_net(|net| unsafe { net.ioctl(s as c_int, cmd as u64, argp as i64) })
    {
        return finish_sock(r);
    }
    domain::observe("ioctlsocket", None);
    unsafe { original::<unsafe extern "system" fn(Socket, c_int, *mut u32) -> c_int>(&WS_IOCTLSOCKET)(s, cmd, argp) }
}

/// Win32 `BOOL` return convention for a handled host call: `Err(e)` fails with `SetLastError(e)`
/// and returns 0; anything non-negative returns as the `BOOL`. See MSDN `SetLastError` /
/// `GetLastError`.
fn finish_bool(handled: i64) -> i32 {
    if handled < 0 {
        // SAFETY: setting the calling thread's last-error.
        unsafe { SetLastError((-handled) as u32) };
        0
    } else {
        handled as i32
    }
}

// MSDN `SetThreadPriority` — `priority` is a `THREAD_PRIORITY_*` level; returns a `BOOL`.
unsafe extern "system" fn set_thread_priority(thread: HANDLE, priority: i32) -> i32 {
    if let Some(r) = dispatch_host(|h| h.set_thread_priority(thread as u64, priority)) {
        return finish_bool(r);
    }
    // SAFETY: SET_THREAD_PRIORITY holds kernel32's SetThreadPriority.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, i32) -> i32>(&SET_THREAD_PRIORITY)(
            thread, priority,
        )
    }
}

unsafe extern "system" fn get_thread_priority(thread: HANDLE) -> i32 {
    // The priority may be negative, so — like POSIX `getpriority` — it cannot use the `BOOL`
    // convention; a host returns the value directly.
    if let Some(r) = dispatch_host(|h| h.get_thread_priority(thread as u64)) {
        return r as i32;
    }
    // SAFETY: GET_THREAD_PRIORITY holds kernel32's GetThreadPriority.
    unsafe { original::<unsafe extern "system" fn(HANDLE) -> i32>(&GET_THREAD_PRIORITY)(thread) }
}

unsafe extern "system" fn set_thread_affinity_mask(thread: HANDLE, mask: usize) -> usize {
    // MSDN `SetThreadAffinityMask`: each bit is a logical processor in the caller's group.
    // Returns the previous affinity mask; a host signals failure with `Ok(0)`, as Win32 does.
    // `r as usize` preserves all 64 bits, so a mask with bit 63 set is NOT mistaken for an error
    // (the getpriority/GetThreadPriority trap) — the `-errno` convention cannot apply here.
    if let Some(r) = dispatch_host(|h| h.set_thread_affinity_mask(thread as u64, mask as u64)) {
        return r as usize;
    }
    // SAFETY: SET_THREAD_AFFINITY_MASK holds kernel32's SetThreadAffinityMask.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, usize) -> usize>(&SET_THREAD_AFFINITY_MASK)(
            thread, mask,
        )
    }
}

// MSDN `SetPriorityClass` — `class` is `REALTIME_PRIORITY_CLASS`/`HIGH_PRIORITY_CLASS`/…; `BOOL`.
unsafe extern "system" fn set_priority_class(process: HANDLE, class: u32) -> i32 {
    if let Some(r) = dispatch_host(|h| h.set_priority_class(process as u64, class)) {
        return finish_bool(r);
    }
    // SAFETY: SET_PRIORITY_CLASS holds kernel32's SetPriorityClass.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, u32) -> i32>(&SET_PRIORITY_CLASS)(
            process, class,
        )
    }
}

unsafe extern "system" fn get_priority_class(process: HANDLE) -> u32 {
    if let Some(r) = dispatch_host(|h| h.get_priority_class(process as u64)) {
        if r < 0 {
            // SAFETY: setting the calling thread's last-error.
            unsafe { SetLastError((-r) as u32) };
            return 0;
        }
        return r as u32;
    }
    // SAFETY: GET_PRIORITY_CLASS holds kernel32's GetPriorityClass.
    unsafe { original::<unsafe extern "system" fn(HANDLE) -> u32>(&GET_PRIORITY_CLASS)(process) }
}

// MSDN `timeBeginPeriod`/`timeEndPeriod` (winmm) — set the minimum timer resolution in ms;
// `TIMERR_NOERROR` (0) on success, `TIMERR_NOCANDO` for an out-of-range period.
unsafe extern "system" fn time_begin_period(period: u32) -> u32 {
    if let Some(r) = dispatch_host(|h| h.time_period(true, period)) {
        return r.max(0) as u32;
    }
    // SAFETY: TIME_BEGIN_PERIOD holds winmm's timeBeginPeriod.
    unsafe { original::<unsafe extern "system" fn(u32) -> u32>(&TIME_BEGIN_PERIOD)(period) }
}

unsafe extern "system" fn time_end_period(period: u32) -> u32 {
    if let Some(r) = dispatch_host(|h| h.time_period(false, period)) {
        return r.max(0) as u32;
    }
    // SAFETY: TIME_END_PERIOD holds winmm's timeEndPeriod.
    unsafe { original::<unsafe extern "system" fn(u32) -> u32>(&TIME_END_PERIOD)(period) }
}

// The `wpcap`/`npcap` exports are cdecl, not stdcall — hence `extern "C"`. A capture handle is an
// opaque `pcap_t*`, carried to the backend as `u64`. With no `Net`, each call forwards to the real
// library unchanged. Signatures and semantics per the libpcap/Npcap manuals (`pcap(3PCAP)`).

unsafe extern "C" fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> *mut c_void {
    // SAFETY: `source` is the caller's device name.
    if let Some(r) = dispatch_net(|net| unsafe { net.pcap_open(source) })
        && r > 0
    {
        return r as *mut c_void;
    }
    // SAFETY: PCAP_CREATE holds wpcap's pcap_create.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void>(&PCAP_CREATE)(
            source, errbuf,
        )
    }
}

unsafe extern "C" fn pcap_open_live(
    device: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: *mut c_char,
) -> *mut c_void {
    // SAFETY: `device` is the caller's interface name.
    if let Some(r) = dispatch_net(|net| unsafe { net.pcap_open(device) })
        && r > 0
    {
        return r as *mut c_void;
    }
    // SAFETY: PCAP_OPEN_LIVE holds wpcap's pcap_open_live.
    unsafe {
        original::<
            unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void,
        >(&PCAP_OPEN_LIVE)(device, snaplen, promisc, to_ms, errbuf)
    }
}

unsafe extern "C" fn pcap_activate(handle: *mut c_void) -> c_int {
    if let Some(r) = dispatch_net(|net| net.pcap_configure(handle as u64)) {
        return r as c_int;
    }
    // SAFETY: PCAP_ACTIVATE holds wpcap's pcap_activate.
    unsafe { original::<unsafe extern "C" fn(*mut c_void) -> c_int>(&PCAP_ACTIVATE)(handle) }
}

unsafe extern "C" fn pcap_set_immediate_mode(handle: *mut c_void, mode: c_int) -> c_int {
    if let Some(r) = dispatch_net(|net| net.pcap_configure(handle as u64)) {
        return r as c_int;
    }
    // SAFETY: PCAP_SET_IMMEDIATE_MODE holds wpcap's pcap_set_immediate_mode.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(&PCAP_SET_IMMEDIATE_MODE)(
            handle, mode,
        )
    }
}

unsafe extern "C" fn pcap_setnonblock(
    handle: *mut c_void,
    nonblock: c_int,
    errbuf: *mut c_char,
) -> c_int {
    if let Some(r) = dispatch_net(|net| net.pcap_configure(handle as u64)) {
        return r as c_int;
    }
    // SAFETY: PCAP_SETNONBLOCK holds wpcap's pcap_setnonblock.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int>(&PCAP_SETNONBLOCK)(
            handle, nonblock, errbuf,
        )
    }
}

unsafe extern "C" fn pcap_sendpacket(handle: *mut c_void, buf: *const u8, size: c_int) -> c_int {
    // SAFETY: `buf` points to `size` readable bytes.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.pcap_send(handle as u64, buf, size.max(0) as usize) })
    {
        return r as c_int;
    }
    // SAFETY: PCAP_SENDPACKET holds wpcap's pcap_sendpacket.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, *const u8, c_int) -> c_int>(&PCAP_SENDPACKET)(
            handle, buf, size,
        )
    }
}

unsafe extern "C" fn pcap_next_ex(
    handle: *mut c_void,
    header: *mut *mut c_void,
    data: *mut *const u8,
) -> c_int {
    // SAFETY: `header`/`data` receive pointers into capture storage.
    if let Some(r) =
        dispatch_net(|net| unsafe { net.pcap_next(handle as u64, header.cast(), data) })
    {
        return r as c_int;
    }
    // SAFETY: PCAP_NEXT_EX holds wpcap's pcap_next_ex.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, *mut *mut c_void, *mut *const u8) -> c_int>(
            &PCAP_NEXT_EX,
        )(handle, header, data)
    }
}

unsafe extern "C" fn pcap_close(handle: *mut c_void) {
    if dispatch_net(|net| net.pcap_close(handle as u64)).is_some() {
        return;
    }
    // SAFETY: PCAP_CLOSE holds wpcap's pcap_close.
    unsafe { original::<unsafe extern "C" fn(*mut c_void)>(&PCAP_CLOSE)(handle) }
}

// The `pcap_send_queue` (Npcap `<pcap.h>`): { u_int maxlen; u_int len; char* buffer }. A sim
// send-queue is one allocation holding the struct followed by its `maxlen`-byte buffer, so a single
// `dealloc` frees it. `pcap_sendqueue_queue` appends `[pcap_pkthdr][packet]` entries (the pkthdr's
// caplen@8 giving each packet's length); `pcap_sendqueue_transmit` replays them through the device.
const SQ_HDR: usize = 16; // sizeof(pcap_send_queue) on LP64/LLP64: two u32 + an 8-byte pointer
const PKTHDR_LEN: usize = 16; // sizeof(pcap_pkthdr): timeval(8) + caplen(4) + len(4)

unsafe extern "C" fn pcap_sendqueue_alloc(memsize: u32) -> *mut c_void {
    if state::passthrough() {
        domain::observe("pcap_sendqueue_alloc", None);
        return unsafe {
            original::<unsafe extern "C" fn(u32) -> *mut c_void>(&PCAP_SENDQUEUE_ALLOC)(memsize)
        };
    }
    let total = SQ_HDR + memsize as usize;
    let layout = std::alloc::Layout::from_size_align(total, 8).unwrap();
    // SAFETY: non-zero size; the block is freed by `pcap_sendqueue_destroy`.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    if block.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        block.cast::<u32>().write(memsize); // maxlen
        block.add(4).cast::<u32>().write(0); // len
        block.add(8).cast::<*mut u8>().write(block.add(SQ_HDR)); // buffer
    }
    block.cast()
}

unsafe extern "C" fn pcap_sendqueue_queue(
    queue: *mut c_void,
    pkthdr: *const c_void,
    data: *const u8,
) -> c_int {
    if queue.is_null() || pkthdr.is_null() {
        return -1;
    }
    let q = queue.cast::<u8>();
    let maxlen = unsafe { q.cast::<u32>().read() } as usize;
    let len = unsafe { q.add(4).cast::<u32>().read() } as usize;
    let buffer = unsafe { q.add(8).cast::<*mut u8>().read() };
    let caplen = unsafe { pkthdr.cast::<u8>().add(8).cast::<u32>().read() } as usize;
    let need = PKTHDR_LEN + caplen;
    if len + need > maxlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(pkthdr.cast::<u8>(), buffer.add(len), PKTHDR_LEN);
        std::ptr::copy_nonoverlapping(data, buffer.add(len + PKTHDR_LEN), caplen);
        q.add(4).cast::<u32>().write((len + need) as u32);
    }
    0
}

unsafe extern "C" fn pcap_sendqueue_transmit(handle: *mut c_void, queue: *mut c_void, sync: i32) -> u32 {
    // A sim capture handle: replay each queued frame through the device's fan-out.
    if dispatch_net(|net| net.pcap_configure(handle as u64)).is_some() {
        let q = queue.cast::<u8>();
        let len = unsafe { q.add(4).cast::<u32>().read() } as usize;
        let buffer = unsafe { q.add(8).cast::<*mut u8>().read() };
        let mut off = 0usize;
        while off + PKTHDR_LEN <= len {
            let caplen =
                unsafe { buffer.add(off).add(8).cast::<u32>().read() } as usize;
            let data = unsafe { buffer.add(off + PKTHDR_LEN) };
            if off + PKTHDR_LEN + caplen > len {
                break;
            }
            dispatch_net(|net| unsafe { net.pcap_send(handle as u64, data, caplen) });
            off += PKTHDR_LEN + caplen;
        }
        return len as u32;
    }
    domain::observe("pcap_sendqueue_transmit", None);
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, *mut c_void, i32) -> u32>(
            &PCAP_SENDQUEUE_TRANSMIT,
        )(handle, queue, sync)
    }
}

unsafe extern "C" fn pcap_sendqueue_destroy(queue: *mut c_void) {
    if state::passthrough() {
        domain::observe("pcap_sendqueue_destroy", None);
        return unsafe {
            original::<unsafe extern "C" fn(*mut c_void)>(&PCAP_SENDQUEUE_DESTROY)(queue)
        };
    }
    if queue.is_null() {
        return;
    }
    let q = queue.cast::<u8>();
    let maxlen = unsafe { q.cast::<u32>().read() } as usize;
    let layout = std::alloc::Layout::from_size_align(SQ_HDR + maxlen, 8).unwrap();
    // SAFETY: `queue` came from `pcap_sendqueue_alloc` with this exact layout.
    unsafe { std::alloc::dealloc(q, layout) };
}

unsafe extern "C" fn pcap_geterr(handle: *mut c_void) -> *mut c_char {
    if dispatch_net(|net| net.pcap_configure(handle as u64)).is_some() {
        // The sim never leaves an error pending; report an empty message.
        return c"".as_ptr() as *mut c_char;
    }
    domain::observe("pcap_geterr", None);
    unsafe { original::<unsafe extern "C" fn(*mut c_void) -> *mut c_char>(&PCAP_GETERR)(handle) }
}

/// OS calls no layer models yet; see [`crate::Unmodelled`].
fn observed_hooks() -> Vec<Hook> {
    vec![
        observed!("WSASend" in "ws2_32.dll", [socket, buffers, count, sent, flags, overlapped, routine]),
        observed!("WSARecv" in "ws2_32.dll", [socket, buffers, count, received, flags, overlapped, routine]),
        observed!("WSASendTo" in "ws2_32.dll", [socket, buffers, count, sent, flags, address, address_length, overlapped, routine]),
        observed!("WSARecvFrom" in "ws2_32.dll", [socket, buffers, count, received, flags, address, address_length, overlapped, routine]),
        observed!("WSAIoctl" in "ws2_32.dll", [socket, code, input, input_length, output, output_length, returned, overlapped, routine]),
        observed!("select" in "ws2_32.dll", [count, read, write, error, timeout]),
        observed!("getaddrinfo" in "ws2_32.dll", [node, service, hints, result]),
        observed!("GetAddrInfoW" in "ws2_32.dll", [node, service, hints, result]),
        observed!("GetAdaptersAddresses" in "iphlpapi.dll", [family, flags, reserved, addresses, size]),
        observed!("CreateIoCompletionPort" in "kernel32.dll", [file, port, key, threads]),
        observed!("GetQueuedCompletionStatus" in "kernel32.dll", [port, bytes, key, overlapped, timeout]),
        observed!("GetQueuedCompletionStatusEx" in "kernel32.dll", [port, entries, count, removed, timeout, alertable]),
        observed!("PostQueuedCompletionStatus" in "kernel32.dll", [port, bytes, key, overlapped]),
        observed!("WaitForSingleObjectEx" in "kernel32.dll", [handle, timeout, alertable]),
        observed!("WaitForMultipleObjects" in "kernel32.dll", [count, handles, all, timeout]),
        observed!("WakeByAddressSingle" in "api-ms-win-core-synch-l1-2-0.dll", [address]),
        observed!("WakeByAddressAll" in "api-ms-win-core-synch-l1-2-0.dll", [address]),
        observed!("SetConsoleCtrlHandler" in "kernel32.dll", [handler, add]),
        observed!("NtDeviceIoControlFile" in "ntdll.dll", [file, event, routine, context, status, code, input, input_length, output, output_length]),
        observed!("NtCreateFile" in "ntdll.dll", [file, access, attributes, status, size, file_attributes, share, disposition, options, buffer, length]),
        observed!("pcap_sendqueue_alloc" in "wpcap.dll", [memsize]),
        observed!("pcap_sendqueue_queue" in "wpcap.dll", [queue, header, data]),
        observed!("pcap_sendqueue_transmit" in "wpcap.dll", [handle, queue, sync]),
        observed!("pcap_findalldevs" in "wpcap.dll", [devices, errbuf]),
    ]
}
/// 100 ns intervals between 1601-01-01 (the FILETIME epoch) and the Unix epoch. A `FILETIME`
/// counts 100 ns ticks since 1601-01-01 UTC (MSDN `FILETIME`).
const FILETIME_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
const INFINITE: u32 = u32::MAX;

// MSDN `QueryPerformanceFrequency`: counts per second, fixed at boot. The virtual monotonic time
// is rescaled from nanoseconds to these units so `QueryPerformanceCounter` stays self-consistent.
fn counter_frequency() -> u128 {
    static FREQUENCY: OnceLock<i64> = OnceLock::new();
    *FREQUENCY.get_or_init(|| {
        let mut frequency = 0;
        // SAFETY: writes one i64; the function is not hooked.
        unsafe { QueryPerformanceFrequency(&mut frequency) };
        frequency.max(1)
    }) as u128
}

// MSDN `QueryPerformanceCounter` — the high-resolution monotonic tick count; returns a non-zero
// `BOOL` on success.
unsafe extern "system" fn query_performance_counter(count: *mut i64) -> i32 {
    if !count.is_null()
        && let Some(now) = dispatch(|layer| layer.now(ClockKind::Monotonic))
    {
        // SAFETY: the caller passed a writable i64.
        unsafe { count.write((now.as_nanos() * counter_frequency() / 1_000_000_000) as i64) };
        return 1;
    }
    // SAFETY: QUERY_PERFORMANCE_COUNTER holds kernel32's QueryPerformanceCounter.
    unsafe {
        original::<unsafe extern "system" fn(*mut i64) -> i32>(&QUERY_PERFORMANCE_COUNTER)(count)
    }
}

fn write_file_time(out: *mut FILETIME) -> bool {
    let Some(now) = dispatch(|layer| layer.now(ClockKind::Realtime)) else {
        return false;
    };
    let intervals = (now.as_nanos() / 100) as u64 + FILETIME_UNIX_OFFSET;
    // SAFETY: callers check `out` is non-null; it is the caller's writable FILETIME.
    unsafe {
        out.write(FILETIME {
            dwLowDateTime: intervals as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        })
    };
    true
}

// MSDN `GetSystemTimePreciseAsFileTime` / `GetSystemTimeAsFileTime` — wall-clock UTC as a
// `FILETIME` (100 ns ticks since 1601).
unsafe extern "system" fn get_system_time_precise_as_file_time(out: *mut FILETIME) {
    if out.is_null() || !write_file_time(out) {
        // SAFETY: GET_SYSTEM_TIME_PRECISE_AS_FILE_TIME holds the kernel32 function.
        unsafe {
            original::<unsafe extern "system" fn(*mut FILETIME)>(
                &GET_SYSTEM_TIME_PRECISE_AS_FILE_TIME,
            )(out)
        }
    }
}

unsafe extern "system" fn get_system_time_as_file_time(out: *mut FILETIME) {
    if out.is_null() || !write_file_time(out) {
        // SAFETY: GET_SYSTEM_TIME_AS_FILE_TIME holds the kernel32 function.
        unsafe {
            original::<unsafe extern "system" fn(*mut FILETIME)>(&GET_SYSTEM_TIME_AS_FILE_TIME)(out)
        }
    }
}

fn virtual_sleep(millis: u32) -> bool {
    millis != INFINITE
        && dispatch(|layer| layer.sleep(SleepRequest::For(Duration::from_millis(millis.into()))))
            .is_some()
}

unsafe extern "system" fn sleep(millis: u32) {
    if !virtual_sleep(millis) {
        // SAFETY: SLEEP holds kernel32's Sleep.
        unsafe { original::<unsafe extern "system" fn(u32)>(&SLEEP)(millis) }
    }
}

unsafe extern "system" fn sleep_ex(millis: u32, alertable: i32) -> u32 {
    if virtual_sleep(millis) {
        return 0;
    }
    // SAFETY: SLEEP_EX holds kernel32's SleepEx.
    unsafe { original::<unsafe extern "system" fn(u32, i32) -> u32>(&SLEEP_EX)(millis, alertable) }
}

/// Refused on managed threads, so std's `thread::sleep` falls back to `Sleep`, which layers see.
unsafe extern "system" fn create_waitable_timer_ex_w(
    attributes: *const c_void,
    name: *const u16,
    flags: u32,
    access: u32,
) -> HANDLE {
    if !state::passthrough() && !state::domain().is_null() {
        // SAFETY: sets the calling thread's last-error value.
        unsafe { SetLastError(ERROR_NOT_SUPPORTED) };
        return std::ptr::null_mut();
    }
    // SAFETY: CREATE_WAITABLE_TIMER_EX_W holds the kernel32 function; arguments are forwarded.
    unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const u16, u32, u32) -> HANDLE>(
            &CREATE_WAITABLE_TIMER_EX_W,
        )(attributes, name, flags, access)
    }
}

type StartRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

struct Start {
    routine: StartRoutine,
    parameter: *mut c_void,
    domain: *const domain::Inner,
    lineage: u64,
}

unsafe extern "system" fn managed_start(start: *mut c_void) -> u32 {
    // SAFETY: `create_thread` boxed this `Start` and handed ownership to this thread.
    let start = unsafe { Box::from_raw(start.cast::<Start>()) };
    // SAFETY: the reference was made by `inherit` for this thread alone.
    let child = unsafe { domain::adopt(start.domain, start.lineage) };
    // SAFETY: calling the caller's start routine with its own parameter.
    let result = unsafe { (start.routine)(start.parameter) };
    drop(child);
    result
}

type CreateThreadFn = unsafe extern "system" fn(
    *const c_void,
    usize,
    Option<StartRoutine>,
    *const c_void,
    u32,
    *mut u32,
) -> HANDLE;

unsafe extern "system" fn create_thread(
    attributes: *const c_void,
    stack_size: usize,
    routine: Option<StartRoutine>,
    parameter: *const c_void,
    flags: u32,
    thread_id: *mut u32,
) -> HANDLE {
    // SAFETY: CREATE_THREAD holds kernel32's CreateThread.
    let create = unsafe { original::<CreateThreadFn>(&CREATE_THREAD) };
    let inherited = domain::inherit();
    let Some(routine) = routine.filter(|_| !inherited.is_null()) else {
        // SAFETY: nothing adopted the reference, if one was made.
        unsafe { domain::release(inherited) };
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { create(attributes, stack_size, routine, parameter, flags, thread_id) };
    };
    let start = Box::into_raw(Box::new(Start {
        routine,
        parameter: parameter.cast_mut(),
        domain: inherited,
        lineage: domain::child_lineage(),
    }));
    // SAFETY: `managed_start` takes ownership of `start` once the thread runs.
    let handle = unsafe {
        create(
            attributes,
            stack_size,
            Some(managed_start),
            start.cast(),
            flags,
            thread_id,
        )
    };
    if handle.is_null() {
        // SAFETY: the thread was not created, so `start` is still ours.
        let start = unsafe { Box::from_raw(start) };
        // SAFETY: nothing adopted the reference.
        unsafe { domain::release(start.domain) };
    }
    handle
}

/// Whether `handle` refers to a thread. `GetThreadId` returns 0 for any non-thread (or invalid)
/// handle; the last-error save/restore keeps the probe invisible to the caller.
fn is_thread_handle(handle: HANDLE) -> bool {
    // SAFETY: GetThreadId accepts any handle value and reports 0 rather than faulting.
    let saved = unsafe { GetLastError() };
    let id = unsafe { GetThreadId(handle) };
    // SAFETY: restoring the caller's last-error value.
    unsafe { SetLastError(saved) };
    id != 0
}

// WaitForSingleObject on a thread handle is how std's `JoinHandle::join` blocks until the thread
// exits — the Windows counterpart of `pthread_join`. A managed thread joining another is an
// in-memory wait only another managed thread can satisfy, so it counts toward quiescence: without
// it, a thread that gives up on a deadlocked wait and then joins a still-parked peer leaves that
// peer short of the quiescence count forever. Waits on other handle kinds (mutexes, events) are
// left uncounted so they never trip the deadlock give-up. `mark_waiting` is a no-op off a domain.
unsafe extern "system" fn wait_for_single_object(handle: HANDLE, timeout: u32) -> u32 {
    // SAFETY: WAIT_FOR_SINGLE_OBJECT holds kernel32's WaitForSingleObject.
    let wait = unsafe { original::<unsafe extern "system" fn(HANDLE, u32) -> u32>(&WAIT_FOR_SINGLE_OBJECT) };
    if !state::passthrough() && !state::domain().is_null() && is_thread_handle(handle) {
        domain::mark_waiting(true);
        // SAFETY: forwarding the caller's arguments unchanged.
        let r = unsafe { wait(handle, timeout) };
        domain::mark_waiting(false);
        r
    } else {
        // SAFETY: forwarding the caller's arguments unchanged.
        unsafe { wait(handle, timeout) }
    }
}

/// The blocking edge of std's Mutex/RwLock/Condvar/park/Once on Windows 8+, and of parking_lot
/// (which reaches it through `GetProcAddress`, so the hook there hands out this replacement): a
/// managed thread waiting here can only be released by another, so the wait counts toward
/// quiescence. A finite timeout is a span the caller measured on the (virtual) clock, so it is
/// waited out in the domain's time. The wait re-checks the address every time, so a wake landing
/// between two slices is never lost.
unsafe extern "system" fn wait_on_address(
    address: *const c_void,
    compare: *const c_void,
    size: usize,
    millis: u32,
) -> i32 {
    // SAFETY: WAIT_ON_ADDRESS holds the system's WaitOnAddress.
    let wait = unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const c_void, usize, u32) -> i32>(
            &WAIT_ON_ADDRESS,
        )
    };
    // synchapi.h: INFINITE.
    const INFINITE: u32 = u32::MAX;
    // winerror.h: what a timed-out WaitOnAddress leaves in GetLastError.
    const ERROR_TIMEOUT: u32 = 1460;
    if millis == INFINITE {
        // SAFETY: forwarding the caller's arguments unchanged.
        return domain::native_wait(|| unsafe { wait(address, compare, size, millis) });
    }
    let after = Duration::from_millis(u64::from(millis));
    let outcome = domain::timed_native_wait(after, None, |slice| {
        let slice_ms = u32::try_from(slice.as_millis().max(1)).unwrap_or(INFINITE - 1);
        // SAFETY: the caller's address and comparand, with a timeout of `slice` on the real clock.
        let woke = unsafe { wait(address, compare, size, slice_ms) };
        // SAFETY: reading this thread's last-error value.
        let error = unsafe { GetLastError() };
        (woke != 0 || error != ERROR_TIMEOUT).then_some((woke, error))
    });
    let (woke, error) = match outcome {
        domain::TimedWait::Woken(result) => result,
        domain::TimedWait::TimedOut => (0, ERROR_TIMEOUT),
    };
    // SAFETY: restoring what the wait reported, which bookkeeping since may have overwritten.
    unsafe { SetLastError(error) };
    woke
}

/// std's `thread::yield_now` and the spin phase of crossbeam/kanal/parking_lot; see
/// `domain::yield_point`.
unsafe extern "system" fn switch_to_thread() -> i32 {
    domain::yield_point();
    // SAFETY: SWITCH_TO_THREAD holds kernel32's SwitchToThread.
    unsafe { original::<unsafe extern "system" fn() -> i32>(&SWITCH_TO_THREAD)() }
}

/// Hands out hooks instead of the real functions, so code that looks functions up at run time
/// is redirected like code that imports them.
unsafe extern "system" fn get_proc_address(module: *mut c_void, name: *const u8) -> usize {
    // SAFETY: GET_PROC_ADDRESS holds kernel32's GetProcAddress; arguments are forwarded.
    let found = unsafe {
        original::<unsafe extern "system" fn(*mut c_void, *const u8) -> usize>(&GET_PROC_ADDRESS)(
            module, name,
        )
    };
    // Values below 0x10000 are ordinals, not names.
    if found == 0 || (name as usize) < 0x10000 || state::passthrough() {
        return found;
    }
    // SAFETY: a lookup by name succeeded, so `name` is a C string.
    let name = unsafe { CStr::from_ptr(name.cast()) }.to_bytes();
    match hooks::find(name) {
        Some(hook) if hook.resolved() => hook.replacement,
        _ => found,
    }
}

fn virtual_random(buffer: *mut u8, length: usize) -> bool {
    if buffer.is_null() {
        return length == 0;
    }
    // SAFETY: the caller of the hooked function passed `length` writable bytes at `buffer`.
    let buffer = unsafe { std::slice::from_raw_parts_mut(buffer, length) };
    dispatch(|layer| layer.random(buffer)).is_some()
}

unsafe extern "system" fn process_prng(buffer: *mut u8, length: usize) -> i32 {
    if virtual_random(buffer, length) {
        return 1;
    }
    // SAFETY: PROCESS_PRNG holds bcryptprimitives' ProcessPrng.
    unsafe {
        original::<unsafe extern "system" fn(*mut u8, usize) -> i32>(&PROCESS_PRNG)(buffer, length)
    }
}

unsafe extern "system" fn bcrypt_gen_random(
    algorithm: *mut c_void,
    buffer: *mut u8,
    length: u32,
    flags: u32,
) -> i32 {
    if virtual_random(buffer, length as usize) {
        return 0;
    }
    // SAFETY: BCRYPT_GEN_RANDOM holds bcrypt's BCryptGenRandom.
    unsafe {
        original::<unsafe extern "system" fn(*mut c_void, *mut u8, u32, u32) -> i32>(
            &BCRYPT_GEN_RANDOM,
        )(algorithm, buffer, length, flags)
    }
}

/// Patches a module the loader just mapped, then reports the handle it returned unchanged.
///
/// Each public `LoadLibrary*` entry is hooked on its own: kernel32's internal calls between them
/// do not pass through this image's IAT, so hooking only the innermost would miss the rest.
fn after_load(module: HMODULE) -> HMODULE {
    if !module.is_null() && !state::passthrough() {
        crate::patch::patch_new_modules();
    }
    module
}

unsafe extern "system" fn load_library_a(name: *const u8) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_A holds kernel32's LoadLibraryA.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u8) -> HMODULE>(&LOAD_LIBRARY_A)(name)
    })
}

unsafe extern "system" fn load_library_w(name: *const u16) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_W holds kernel32's LoadLibraryW.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u16) -> HMODULE>(&LOAD_LIBRARY_W)(name)
    })
}

unsafe extern "system" fn load_library_ex_a(name: *const u8, file: HANDLE, flags: u32) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_EX_A holds kernel32's LoadLibraryExA.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u8, HANDLE, u32) -> HMODULE>(&LOAD_LIBRARY_EX_A)(
            name, file, flags,
        )
    })
}

unsafe extern "system" fn load_library_ex_w(name: *const u16, file: HANDLE, flags: u32) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_EX_W holds kernel32's LoadLibraryExW.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u16, HANDLE, u32) -> HMODULE>(
            &LOAD_LIBRARY_EX_W,
        )(name, file, flags)
    })
}
