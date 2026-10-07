//! The Windows hooks: replacements for kernel32, the synch API set, winmm, bcrypt,
//! bcryptprimitives, ws2_32, Npcap's wpcap and the UCRT, patched into each module's import address
//! table (`patch::pe`).
//!
//! Every replacement follows one pattern: offer the call to the calling thread's domain through
//! one of the `domain::dispatch*` functions, which decline in passthrough, off a managed thread,
//! or when no layer models the call; if declined, note an unmodelled call with
//! [`domain::observe`] where that is useful, and forward to the original, whose address the
//! patcher stored in the hook's `AtomicUsize`. A modelled call reports failure exactly as the
//! real function does: a Win32 `BOOL` 0 or Winsock `SOCKET_ERROR`/`INVALID_SOCKET` with the code
//! left in the thread's last-error value.
//!
//! Backends report results in the kernel convention (`net::NetResult::into_raw`, `host`): the
//! value itself, or a negated error code, which `finish_*` turn back into Win32 conventions.
//!
//! The waits here (`WaitForSingleObject`, `WaitOnAddress`, semaphores) are where std's
//! `JoinHandle::join`, `Mutex`, `Condvar`, `park` and parking_lot block on Windows; they are
//! counted toward the domain's quiescence and, under a deterministic schedule, waited in the
//! schedule instead of on the OS (see `domain::det_block`).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{FILETIME, GetLastError, HANDLE, HMODULE, SetLastError};
use windows_sys::Win32::Networking::WinSock::{
    SIO_GET_EXTENSION_FUNCTION_POINTER, WSAEFAULT, WSAENOTSOCK, WSAEOPNOTSUPP,
};
use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;
use windows_sys::Win32::System::Threading::{GetCurrentThreadId, GetThreadId};

use crate::domain::{self, dispatch, dispatch_host, dispatch_net, net_owns};
use crate::hooks::{self, Hook, hook, observed, original};
use crate::layer::{ClockKind, SleepRequest};
use crate::net::{Net, NetResult};
use crate::state;

#[path = "windows_iocp.rs"]
mod iocp;
#[path = "windows_locks.rs"]
mod locks;
#[path = "windows_timers.rs"]
mod timers;

// Each static holds the original function its hook replaced, stored by the patcher and read with
// `hooks::original`; 0 until resolved.
pub(crate) unsafe fn close_internal_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> i32 {
    unsafe { timers::close_native(handle) }
}

static QUERY_PERFORMANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
static GET_TICK_COUNT_64: AtomicUsize = AtomicUsize::new(0);
static GET_TICK_COUNT: AtomicUsize = AtomicUsize::new(0);
static QUERY_UNBIASED_INTERRUPT_TIME: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_TIME_PRECISE_AS_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_TIME_AS_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static SLEEP: AtomicUsize = AtomicUsize::new(0);
static SLEEP_EX: AtomicUsize = AtomicUsize::new(0);
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
static SET_PROCESS_WORKING_SET_SIZE_EX: AtomicUsize = AtomicUsize::new(0);
static GET_PROCESS_WORKING_SET_SIZE_EX: AtomicUsize = AtomicUsize::new(0);
static TIME_BEGIN_PERIOD: AtomicUsize = AtomicUsize::new(0);
static TIME_END_PERIOD: AtomicUsize = AtomicUsize::new(0);
static AV_SET_MM_THREAD_CHARACTERISTICS_W: AtomicUsize = AtomicUsize::new(0);
static AV_SET_MM_THREAD_PRIORITY: AtomicUsize = AtomicUsize::new(0);
static AV_REVERT_MM_THREAD_CHARACTERISTICS: AtomicUsize = AtomicUsize::new(0);
static SET_PROCESS_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static GET_PROCESS_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static SET_THREAD_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static GET_THREAD_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_CPU_SET_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static SET_PROCESS_DEFAULT_CPU_SETS: AtomicUsize = AtomicUsize::new(0);
static GET_PROCESS_DEFAULT_CPU_SETS: AtomicUsize = AtomicUsize::new(0);
static SET_THREAD_SELECTED_CPU_SETS: AtomicUsize = AtomicUsize::new(0);
static GET_THREAD_SELECTED_CPU_SETS: AtomicUsize = AtomicUsize::new(0);
static WAIT_FOR_SINGLE_OBJECT: AtomicUsize = AtomicUsize::new(0);
static WAIT_ON_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static SWITCH_TO_THREAD: AtomicUsize = AtomicUsize::new(0);
static WAKE_BY_ADDRESS_SINGLE: AtomicUsize = AtomicUsize::new(0);
static WAKE_BY_ADDRESS_ALL: AtomicUsize = AtomicUsize::new(0);
static SET_THREAD_DESCRIPTION: AtomicUsize = AtomicUsize::new(0);
static RELEASE_SEMAPHORE: AtomicUsize = AtomicUsize::new(0);
static SET_CONSOLE_CTRL_HANDLER: AtomicUsize = AtomicUsize::new(0);
static GENERATE_CONSOLE_CTRL_EVENT: AtomicUsize = AtomicUsize::new(0);
static CRT_SIGNAL: AtomicUsize = AtomicUsize::new(0);
static CRT_RAISE: AtomicUsize = AtomicUsize::new(0);

/// Every Windows hook: the clock, sleep, thread, loader, random, priority and pcap hooks here,
/// then the signal, Winsock, DNS and IP-helper hooks, then the observed-only ones.
///
/// Order matters: `hooks::find` returns the first entry with a name, so a modelled hook listed
/// here shadows an observed entry of the same name further down (as `SetConsoleCtrlHandler` and
/// the `pcap_sendqueue_*` functions are).
pub(crate) fn hooks() -> Vec<Hook> {
    let mut hooks = vec![
        hook!(
            "QueryPerformanceCounter",
            "kernel32.dll",
            query_performance_counter,
            QUERY_PERFORMANCE_COUNTER
        ),
        hook!(
            "GetTickCount64",
            "kernel32.dll",
            get_tick_count_64,
            GET_TICK_COUNT_64
        ),
        hook!(
            "GetTickCount",
            "kernel32.dll",
            get_tick_count,
            GET_TICK_COUNT
        ),
        hook!(
            "QueryUnbiasedInterruptTime",
            "kernel32.dll",
            query_unbiased_interrupt_time,
            QUERY_UNBIASED_INTERRUPT_TIME
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
        hook!(
            "SwitchToThread",
            "kernel32.dll",
            switch_to_thread,
            SWITCH_TO_THREAD
        ),
        hook!(
            "WakeByAddressSingle",
            "api-ms-win-core-synch-l1-2-0.dll",
            wake_by_address_single,
            WAKE_BY_ADDRESS_SINGLE
        ),
        hook!(
            "WakeByAddressAll",
            "api-ms-win-core-synch-l1-2-0.dll",
            wake_by_address_all,
            WAKE_BY_ADDRESS_ALL
        ),
        hook!(
            "SetThreadDescription",
            "kernel32.dll",
            set_thread_description,
            SET_THREAD_DESCRIPTION
        ),
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
        hook!(
            "SetProcessWorkingSetSizeEx",
            "kernel32.dll",
            set_process_working_set_size_ex,
            SET_PROCESS_WORKING_SET_SIZE_EX
        ),
        hook!(
            "GetProcessWorkingSetSizeEx",
            "kernel32.dll",
            get_process_working_set_size_ex,
            GET_PROCESS_WORKING_SET_SIZE_EX
        ),
        hook!(
            "timeBeginPeriod",
            "winmm.dll",
            time_begin_period,
            TIME_BEGIN_PERIOD
        ),
        hook!(
            "timeEndPeriod",
            "winmm.dll",
            time_end_period,
            TIME_END_PERIOD
        ),
        hook!(
            "AvSetMmThreadCharacteristicsW",
            "avrt.dll",
            av_set_mm_thread_characteristics_w,
            AV_SET_MM_THREAD_CHARACTERISTICS_W
        ),
        hook!(
            "AvSetMmThreadPriority",
            "avrt.dll",
            av_set_mm_thread_priority,
            AV_SET_MM_THREAD_PRIORITY
        ),
        hook!(
            "AvRevertMmThreadCharacteristics",
            "avrt.dll",
            av_revert_mm_thread_characteristics,
            AV_REVERT_MM_THREAD_CHARACTERISTICS
        ),
        hook!(
            "SetProcessInformation",
            "kernel32.dll",
            set_process_information,
            SET_PROCESS_INFORMATION
        ),
        hook!(
            "GetProcessInformation",
            "kernel32.dll",
            get_process_information,
            GET_PROCESS_INFORMATION
        ),
        hook!(
            "SetThreadInformation",
            "kernel32.dll",
            set_thread_information,
            SET_THREAD_INFORMATION
        ),
        hook!(
            "GetThreadInformation",
            "kernel32.dll",
            get_thread_information,
            GET_THREAD_INFORMATION
        ),
        hook!(
            "GetSystemCpuSetInformation",
            "kernel32.dll",
            get_system_cpu_set_information,
            GET_SYSTEM_CPU_SET_INFORMATION
        ),
        hook!(
            "SetProcessDefaultCpuSets",
            "kernel32.dll",
            set_process_default_cpu_sets,
            SET_PROCESS_DEFAULT_CPU_SETS
        ),
        hook!(
            "GetProcessDefaultCpuSets",
            "kernel32.dll",
            get_process_default_cpu_sets,
            GET_PROCESS_DEFAULT_CPU_SETS
        ),
        hook!(
            "SetThreadSelectedCpuSets",
            "kernel32.dll",
            set_thread_selected_cpu_sets,
            SET_THREAD_SELECTED_CPU_SETS
        ),
        hook!(
            "GetThreadSelectedCpuSets",
            "kernel32.dll",
            get_thread_selected_cpu_sets,
            GET_THREAD_SELECTED_CPU_SETS
        ),
        hook!("pcap_create", "wpcap.dll", pcap_create, PCAP_CREATE),
        hook!(
            "pcap_open_live",
            "wpcap.dll",
            pcap_open_live,
            PCAP_OPEN_LIVE
        ),
        hook!("pcap_activate", "wpcap.dll", pcap_activate, PCAP_ACTIVATE),
        hook!(
            "pcap_set_immediate_mode",
            "wpcap.dll",
            pcap_set_immediate_mode,
            PCAP_SET_IMMEDIATE_MODE
        ),
        hook!(
            "pcap_setnonblock",
            "wpcap.dll",
            pcap_setnonblock,
            PCAP_SETNONBLOCK
        ),
        hook!(
            "pcap_sendpacket",
            "wpcap.dll",
            pcap_sendpacket,
            PCAP_SENDPACKET
        ),
        hook!("pcap_next_ex", "wpcap.dll", pcap_next_ex, PCAP_NEXT_EX),
        hook!("pcap_close", "wpcap.dll", pcap_close, PCAP_CLOSE),
        hook!(
            "pcap_sendqueue_alloc",
            "wpcap.dll",
            pcap_sendqueue_alloc,
            PCAP_SENDQUEUE_ALLOC
        ),
        hook!(
            "pcap_sendqueue_queue",
            "wpcap.dll",
            pcap_sendqueue_queue,
            PCAP_SENDQUEUE_QUEUE
        ),
        hook!(
            "pcap_sendqueue_transmit",
            "wpcap.dll",
            pcap_sendqueue_transmit,
            PCAP_SENDQUEUE_TRANSMIT
        ),
        hook!(
            "pcap_sendqueue_destroy",
            "wpcap.dll",
            pcap_sendqueue_destroy,
            PCAP_SENDQUEUE_DESTROY
        ),
        hook!("pcap_geterr", "wpcap.dll", pcap_geterr, PCAP_GETERR),
    ];
    hooks.extend(iocp::hooks());
    hooks.extend(timers::hooks());
    hooks.extend(locks::hooks());
    hooks.extend(signal_hooks());
    hooks.extend(winsock_hooks());
    hooks.extend(crate::os::wsa_windows::hooks());
    hooks.extend(crate::os::dns_windows::hooks());
    hooks.extend(crate::os::iphlp_windows::hooks());
    hooks.extend(crate::os::devices_windows::hooks());
    hooks.extend(observed_hooks());
    hooks
}

// The ws2_32 originals, as above.
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
static WS_SELECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSADUPLICATESOCKETW: AtomicUsize = AtomicUsize::new(0);
static WS_WSAIOCTL: AtomicUsize = AtomicUsize::new(0);

/// Tag written into the `WSAPROTOCOL_INFOW` blob by `WSADuplicateSocketW` for a sim socket: a magic
/// word (never a real `dwServiceFlags1`) followed by the pre-created duplicate's handle, which
/// `WSASocketW` reads back. Keeps the duplicate within the sim rather than touching the real OS.
///
/// The value is a snare choice, ASCII "TENZ" read little-endian. It overlays `dwServiceFlags1`,
/// the first `DWORD` of `WSAPROTOCOL_INFOW` (winsock2.h), whose real values are `XP1_*` flag
/// combinations ([Microsoft Learn: WSAPROTOCOL_INFOW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaprotocol_infow));
/// the handle goes in the next four bytes, `dwServiceFlags2`. std's `try_clone` passes the blob
/// straight from `WSADuplicateSocketW` to `WSASocketW` (std/src/os/windows/io/socket.rs
/// `try_clone_to_owned`).
const DUP_TAG: u32 = 0x5a4e_4554;

/// winsock2.h `SOCKET`: a `UINT_PTR`.
pub(crate) type Socket = usize;
/// winsock2.h `INVALID_SOCKET`, `(SOCKET)(~0)`: what a failed socket-returning call returns.
pub(crate) const INVALID_SOCKET: Socket = usize::MAX;
/// winsock2.h `SOCKET_ERROR`: what a failed `int`-returning Winsock call returns.
pub(crate) const SOCKET_ERROR: c_int = -1;

/// Runs std's one-time Winsock startup outside every domain, once per process.
///
/// std starts Winsock under a process-wide `Once` the first time any of its socket calls runs
/// (std/src/sys/pal/windows/winsock.rs `startup`), and `WSAStartup` loads the provider DLLs: a
/// critical section far longer than the [`outside_grace`] of a wait on it. A managed thread that
/// found a thread of another domain inside it would wait on a word no thread of its own domain
/// releases, and its domain would read as quiescent. A connect to no address runs that startup and
/// then fails without creating a socket.
pub(crate) fn start_std_winsock() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    let _passthrough = state::Passthrough::enter();
    STARTED.call_once(|| {
        let _ = std::net::TcpStream::connect(&[][..] as &[std::net::SocketAddr]);
    });
}

/// `s` as one of the calling thread's sim handles. The sim mints its handles in the `c_int`
/// range, so a `SOCKET` beyond it is never the sim's, even when its low 32 bits equal a sim
/// handle.
pub(crate) fn sim_socket(s: Socket) -> Option<c_int> {
    let fd = c_int::try_from(s).ok()?;
    net_owns(fd).then_some(fd)
}

/// Offers a call on sim handle `fd` to the domain's backend, noting it as effect `effect` when
/// given. A sim handle never goes to Winsock, which does not know it or knows a different socket
/// by the same number, so a backend that declines a handle it minted — another thread closed it
/// since [`sim_socket`] looked — fails the call with `WSAENOTSOCK`
/// ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
pub(crate) fn on_sim(
    effect: Option<&'static str>,
    op: impl FnMut(&dyn Net) -> Option<NetResult>,
) -> i64 {
    let handled = match effect {
        Some(name) => domain::dispatch_net_effect(name, op),
        None => dispatch_net(op),
    };
    handled.unwrap_or(-i64::from(WSAENOTSOCK))
}

/// Fails a Winsock call with `code` as the `int`-returning calls do.
pub(crate) fn wsa_fail(code: i32) -> c_int {
    finish_sock(-i64::from(code))
}

/// Winsock `SOCKET`-returning convention: `Err(e)` sets the last error and returns `INVALID_SOCKET`.
///
/// The code goes to the thread's last-error value, where `WSAGetLastError` (and std's
/// `io::Error::last_os_error`) reads it; Microsoft Learn documents only that the Winsock error is
/// per thread ([Microsoft Learn: WSAGetLastError](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsagetlasterror)),
/// and the identity is relied on and exercised by crates/snare/tests/socket_limits_win.rs.
pub(crate) fn finish_socket(handled: i64) -> Socket {
    if handled < 0 {
        unsafe { SetLastError((-handled) as u32) };
        INVALID_SOCKET
    } else {
        handled as Socket
    }
}

/// Winsock `c_int`-returning convention: `Err(e)` sets the last error and returns `SOCKET_ERROR`;
/// see [`finish_socket`].
pub(crate) fn finish_sock(handled: i64) -> c_int {
    if handled < 0 {
        unsafe { SetLastError((-handled) as u32) };
        SOCKET_ERROR
    } else {
        handled as c_int
    }
}

/// The ws2_32 hooks. Each serves a socket the domain's `Net` minted ([`sim_socket`]) and forwards
/// any other unchanged; a sim socket never reaches Winsock. The `WSA*` message calls and the
/// guards on the other `SOCKET`-taking exports are in `wsa_windows`.
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
        hook!("WSAIoctl", "ws2_32.dll", ws_wsaioctl, WS_WSAIOCTL),
        hook!("listen", "ws2_32.dll", ws_listen, WS_LISTEN),
        hook!("accept", "ws2_32.dll", ws_accept, WS_ACCEPT),
        hook!("shutdown", "ws2_32.dll", ws_shutdown, WS_SHUTDOWN),
        hook!("WSAPoll", "ws2_32.dll", ws_wsapoll, WS_WSAPOLL),
        hook!("select", "ws2_32.dll", ws_select, WS_SELECT),
        hook!(
            "WSADuplicateSocketW",
            "ws2_32.dll",
            ws_wsaduplicatesocketw,
            WS_WSADUPLICATESOCKETW
        ),
    ]
}

/// `WSADuplicateSocketW`/`WSADuplicateSocketA` of sim socket `s`: the duplicate is created now and
/// its handle stashed (behind [`DUP_TAG`]) in the protocol-info blob, which the matching
/// `WSASocketW`/`WSASocketA` reads back. `None` for a socket that is not the sim's. A null blob
/// is `WSAEFAULT`, as
/// [Microsoft Learn: WSADuplicateSocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw)
/// documents for a `lpProtocolInfo` outside the address space.
pub(crate) unsafe fn duplicate(s: Socket, info: *mut c_void) -> Option<c_int> {
    let fd = sim_socket(s)?;
    if info.is_null() {
        return Some(wsa_fail(WSAEFAULT));
    }
    let r = on_sim(None, |net| unsafe { net.dup(fd) });
    if r < 0 {
        return Some(finish_sock(r));
    }
    unsafe {
        info.cast::<u32>().write_unaligned(DUP_TAG);
        info.cast::<u8>()
            .add(4)
            .cast::<i32>()
            .write_unaligned(r as i32);
    }
    Some(0)
}

/// The duplicate a [`DUP_TAG`]ged protocol-info blob names, for `WSASocketW`/`WSASocketA`.
pub(crate) unsafe fn tagged_duplicate(info: *const c_void) -> Option<Socket> {
    if info.is_null() || unsafe { info.cast::<u32>().read_unaligned() } != DUP_TAG {
        return None;
    }
    let dup = unsafe { info.cast::<u8>().add(4).cast::<i32>().read_unaligned() };
    Some(dup as Socket)
}

/// `WSADuplicateSocketW` fills a protocol-info blob another `WSASocketW` turns back into a socket
/// ([Microsoft Learn: WSADuplicateSocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw));
/// a sim socket's is made by [`duplicate`]. `_pid` is ignored: the sim's sockets cannot leave the
/// process.
unsafe extern "system" fn ws_wsaduplicatesocketw(s: Socket, _pid: u32, info: *mut c_void) -> c_int {
    if let Some(r) = unsafe { duplicate(s, info) } {
        return r;
    }
    domain::observe("WSADuplicateSocketW", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, u32, *mut c_void) -> c_int>(
            &WS_WSADUPLICATESOCKETW,
        )(s, _pid, info)
    }
}

/// `WSAPoll` polls an array of `WSAPOLLFD` with a millisecond `timeout`, negative to block,
/// 0 to return at once ([Microsoft Learn: WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll)).
/// The backend serves an array of its own sockets and fails one that mixes them with others.
pub(crate) unsafe extern "system" fn ws_wsapoll(
    fds: *mut c_void,
    nfds: u32,
    timeout: c_int,
) -> c_int {
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

/// `select` cuts up to three `fd_set`s down to their ready sockets, with a `TIMEVAL` timeout,
/// null to block; `nfds` is ignored by Winsock
/// ([Microsoft Learn: select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select)).
/// The backend serves sets of its own sockets and fails sets that mix them with others.
unsafe extern "system" fn ws_select(
    nfds: c_int,
    read: *mut c_void,
    write: *mut c_void,
    except: *mut c_void,
    timeout: *const c_void,
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
        return finish_sock(r);
    }
    domain::observe("select", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                c_int,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *const c_void,
            ) -> c_int,
        >(&WS_SELECT)(nfds, read, write, except, timeout)
    }
}

/// `listen` ([Microsoft Learn: listen](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen)).
unsafe extern "system" fn ws_listen(s: Socket, backlog: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(None, |net| unsafe { net.listen(fd, backlog) }));
    }
    domain::observe("listen", None);
    unsafe { original::<unsafe extern "system" fn(Socket, c_int) -> c_int>(&WS_LISTEN)(s, backlog) }
}

/// Accepts on sim listener `fd`, bridging Winsock's `int*` address length to the backend's
/// `socklen_t*` (a negative length reads as 0) and back; noted as an effect for the executive's
/// audit.
pub(crate) unsafe fn sim_accept(fd: c_int, addr: *mut c_void, addrlen: *mut c_int) -> Socket {
    let mut ulen: u32 = if addrlen.is_null() {
        0
    } else {
        unsafe { *addrlen }.max(0) as u32
    };
    let lenp = if addrlen.is_null() {
        std::ptr::null_mut()
    } else {
        &mut ulen as *mut u32
    };
    let r = on_sim(Some("accept"), |net| unsafe {
        net.accept(fd, addr.cast(), lenp, 0)
    });
    if !addrlen.is_null() {
        unsafe { *addrlen = ulen as c_int };
    }
    finish_socket(r)
}

/// `accept` ([Microsoft Learn: accept](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)).
unsafe extern "system" fn ws_accept(s: Socket, addr: *mut c_void, addrlen: *mut c_int) -> Socket {
    if let Some(fd) = sim_socket(s) {
        return unsafe { sim_accept(fd, addr, addrlen) };
    }
    domain::observe("accept", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> Socket>(&WS_ACCEPT)(
            s, addr, addrlen,
        )
    }
}

/// `shutdown` ([Microsoft Learn: shutdown](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-shutdown));
/// `how` is `SD_RECEIVE` 0, `SD_SEND` 1, `SD_BOTH` 2, numerically the same as `SHUT_*`.
unsafe extern "system" fn ws_shutdown(s: Socket, how: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(Some("shutdown"), |net| unsafe {
            net.shutdown(fd, how)
        }));
    }
    domain::observe("shutdown", None);
    unsafe { original::<unsafe extern "system" fn(Socket, c_int) -> c_int>(&WS_SHUTDOWN)(s, how) }
}

/// `socket` ([Microsoft Learn: socket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket)).
unsafe extern "system" fn ws_socket(af: c_int, ty: c_int, proto: c_int) -> Socket {
    if let Some(r) = dispatch_net(|net| unsafe { net.socket(af, ty, proto) }) {
        return finish_socket(r);
    }
    domain::observe("socket", None);
    unsafe {
        original::<unsafe extern "system" fn(c_int, c_int, c_int) -> Socket>(&WS_SOCKET)(
            af, ty, proto,
        )
    }
}

/// `WSASocketW`, the extended socket constructor
/// ([Microsoft Learn: WSASocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw));
/// the sim maps it to the same backend `socket`, ignoring `group` and `flags`
/// (`WSA_FLAG_OVERLAPPED`, `WSA_FLAG_NO_HANDLE_INHERIT`), or returns the duplicate a
/// [`DUP_TAG`]ged blob names.
unsafe extern "system" fn ws_wsasocketw(
    af: c_int,
    ty: c_int,
    proto: c_int,
    info: *mut c_void,
    group: u32,
    flags: u32,
) -> Socket {
    if let Some(dup) = unsafe { tagged_duplicate(info) } {
        return dup;
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

/// `bind` ([Microsoft Learn: bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind)).
unsafe extern "system" fn ws_bind(s: Socket, name: *const c_void, namelen: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(None, |net| unsafe {
            net.bind(fd, name.cast(), namelen.max(0) as u32)
        }));
    }
    domain::observe("bind", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *const c_void, c_int) -> c_int>(&WS_BIND)(
            s, name, namelen,
        )
    }
}

/// Connects sim socket `fd`; noted as an effect for the executive's audit.
pub(crate) unsafe fn sim_connect(fd: c_int, name: *const c_void, namelen: c_int) -> c_int {
    finish_sock(on_sim(Some("connect"), |net| unsafe {
        net.connect(fd, name.cast(), namelen.max(0) as u32)
    }))
}

/// `connect` ([Microsoft Learn: connect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)).
unsafe extern "system" fn ws_connect(s: Socket, name: *const c_void, namelen: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe { sim_connect(fd, name, namelen) };
    }
    domain::observe("connect", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *const c_void, c_int) -> c_int>(&WS_CONNECT)(
            s, name, namelen,
        )
    }
}

/// `send` ([Microsoft Learn: send](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send));
/// a negative `len` reads as 0. Noted as an effect.
unsafe extern "system" fn ws_send(s: Socket, buf: *const u8, len: c_int, flags: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(Some("send"), |net| unsafe {
            net.send(fd, buf, len.max(0) as usize, flags)
        }));
    }
    domain::observe("send", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *const u8, c_int, c_int) -> c_int>(&WS_SEND)(
            s, buf, len, flags,
        )
    }
}

/// Receives on sim socket `fd` as `recv` does.
pub(crate) unsafe fn sim_recv(fd: c_int, buf: *mut u8, len: c_int, flags: c_int) -> i64 {
    on_sim(None, |net| unsafe {
        net.recv(fd, buf, len.max(0) as usize, flags)
    })
}

/// `recv` ([Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)).
unsafe extern "system" fn ws_recv(s: Socket, buf: *mut u8, len: c_int, flags: c_int) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(unsafe { sim_recv(fd, buf, len, flags) });
    }
    domain::observe("recv", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut u8, c_int, c_int) -> c_int>(&WS_RECV)(
            s, buf, len, flags,
        )
    }
}

/// `sendto` ([Microsoft Learn: sendto](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto));
/// noted as an effect.
unsafe extern "system" fn ws_sendto(
    s: Socket,
    buf: *const u8,
    len: c_int,
    flags: c_int,
    to: *const c_void,
    tolen: c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(Some("sendto"), |net| unsafe {
            net.sendto(
                fd,
                buf,
                len.max(0) as usize,
                flags,
                to.cast(),
                tolen.max(0) as u32,
            )
        }));
    }
    domain::observe("sendto", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *const u8,
                c_int,
                c_int,
                *const c_void,
                c_int,
            ) -> c_int,
        >(&WS_SENDTO)(s, buf, len, flags, to, tolen)
    }
}

/// `recvfrom` ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)).
unsafe extern "system" fn ws_recvfrom(
    s: Socket,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
    from: *mut c_void,
    fromlen: *mut c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        let mut ulen: u32 = if fromlen.is_null() {
            0
        } else {
            unsafe { *fromlen }.max(0) as u32
        };
        let lenp = if fromlen.is_null() {
            std::ptr::null_mut()
        } else {
            &mut ulen as *mut u32
        };
        let r = on_sim(None, |net| unsafe {
            net.recvfrom(fd, buf, len.max(0) as usize, flags, from.cast(), lenp)
        });
        if !fromlen.is_null() {
            unsafe { *fromlen = ulen as c_int };
        }
        return finish_sock(r);
    }
    domain::observe("recvfrom", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut u8,
                c_int,
                c_int,
                *mut c_void,
                *mut c_int,
            ) -> c_int,
        >(&WS_RECVFROM)(s, buf, len, flags, from, fromlen)
    }
}

/// `closesocket` ([Microsoft Learn: closesocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-closesocket));
/// noted as an effect.
unsafe extern "system" fn ws_closesocket(s: Socket) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(Some("close"), |net| unsafe { net.close(fd) }));
    }
    domain::observe("closesocket", None);
    unsafe { original::<unsafe extern "system" fn(Socket) -> c_int>(&WS_CLOSESOCKET)(s) }
}

/// Bridges Winsock's `int*` address length to the backend's `socklen_t*` for `call` and back.
unsafe fn with_name_len(namelen: *mut c_int, call: impl FnOnce(*mut u32) -> i64) -> c_int {
    let mut ulen: u32 = if namelen.is_null() {
        0
    } else {
        unsafe { *namelen }.max(0) as u32
    };
    let lenp = if namelen.is_null() {
        std::ptr::null_mut()
    } else {
        &mut ulen as *mut u32
    };
    let r = call(lenp);
    if !namelen.is_null() {
        unsafe { *namelen = ulen as c_int };
    }
    finish_sock(r)
}

/// `getsockname` ([Microsoft Learn: getsockname](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname)).
unsafe extern "system" fn ws_getsockname(
    s: Socket,
    name: *mut c_void,
    namelen: *mut c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe {
            with_name_len(namelen, |lenp| {
                on_sim(None, |net| net.getsockname(fd, name.cast(), lenp))
            })
        };
    }
    domain::observe("getsockname", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> c_int>(
            &WS_GETSOCKNAME,
        )(s, name, namelen)
    }
}

/// `getpeername` ([Microsoft Learn: getpeername](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername)).
unsafe extern "system" fn ws_getpeername(
    s: Socket,
    name: *mut c_void,
    namelen: *mut c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe {
            with_name_len(namelen, |lenp| {
                on_sim(None, |net| net.getpeername(fd, name.cast(), lenp))
            })
        };
    }
    domain::observe("getpeername", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_int) -> c_int>(
            &WS_GETPEERNAME,
        )(s, name, namelen)
    }
}

/// `setsockopt` ([Microsoft Learn: setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)).
unsafe extern "system" fn ws_setsockopt(
    s: Socket,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(None, |net| unsafe {
            net.setsockopt(fd, level, name, val, len.max(0) as u32)
        }));
    }
    domain::observe("setsockopt", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, c_int, c_int, *const u8, c_int) -> c_int>(
            &WS_SETSOCKOPT,
        )(s, level, name, val, len)
    }
}

/// `getsockopt` ([Microsoft Learn: getsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt)).
unsafe extern "system" fn ws_getsockopt(
    s: Socket,
    level: c_int,
    name: c_int,
    val: *mut u8,
    len: *mut c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe {
            with_name_len(len, |lenp| {
                on_sim(None, |net| net.getsockopt(fd, level, name, val, lenp))
            })
        };
    }
    domain::observe("getsockopt", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, c_int, c_int, *mut u8, *mut c_int) -> c_int>(
            &WS_GETSOCKOPT,
        )(s, level, name, val, len)
    }
}

/// `ioctlsocket` ([Microsoft Learn: ioctlsocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket)).
///
/// `cmd` is a C `long` and is widened to the backend's `u64` with sign extension, so `FIONBIO`
/// (`_IOW('f', 126, u_long)` = `0x8004667E`, winsock2.h, bit 31 set) arrives as
/// `0xFFFF_FFFF_8004_667E`; backends compare the low 32 bits (see `Net::ioctl`).
unsafe extern "system" fn ws_ioctlsocket(s: Socket, cmd: c_int, argp: *mut u32) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return finish_sock(on_sim(None, |net| unsafe {
            net.ioctl(fd, cmd as u64, argp as i64)
        }));
    }
    domain::observe("ioctlsocket", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, c_int, *mut u32) -> c_int>(&WS_IOCTLSOCKET)(
            s, cmd, argp,
        )
    }
}

/// ws2_32's `WSAIoctl`.
pub(crate) type WsaIoctl = unsafe extern "system" fn(
    Socket,
    u32,
    *const u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    *mut c_void,
    *mut c_void,
) -> c_int;

/// The real `WSAIoctl`, for the extension-function lookups of `wsa_windows`.
///
/// # Safety
/// As `WSAIoctl`; the hook's original must be resolved, which it is once any module importing
/// `WSAIoctl` was patched.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn real_wsaioctl(
    s: Socket,
    code: u32,
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
    returned: *mut u32,
) -> Option<c_int> {
    if WS_WSAIOCTL.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return None;
    }
    Some(unsafe {
        original::<WsaIoctl>(&WS_WSAIOCTL)(
            s,
            code,
            input,
            input_len,
            output,
            output_len,
            returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    })
}

/// `WSAIoctl` ([Microsoft Learn: WSAIoctl](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl)).
///
/// On a sim socket: an overlapped call or one with a completion routine fails with
/// `WSAEOPNOTSUPP` (snare's choice: the sim has no overlapped completion to signal, and
/// Microsoft lists that code for an IOCTL that "cannot be realized");
/// `SIO_GET_EXTENSION_FUNCTION_POINTER` is answered by `wsa_windows::extension_pointer`; every
/// other code goes to the backend. On any other socket the call goes to Winsock, and a
/// `WSARecvMsg` or `WSASendMsg` pointer it returns is swapped for `wsa_windows`'s own, which
/// forwards a real socket to the pointer Winsock gave, so a pointer fetched once serves sim and
/// real sockets alike.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsaioctl(
    s: Socket,
    code: u32,
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
    returned: *mut u32,
    overlapped: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if !overlapped.is_null() || !routine.is_null() {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        if code == SIO_GET_EXTENSION_FUNCTION_POINTER {
            return unsafe {
                crate::os::wsa_windows::extension_pointer(
                    input, input_len, output, output_len, returned,
                )
            };
        }
        return finish_sock(on_sim(None, |net| unsafe {
            net.wsa_ioctl(fd, code, input, input_len, output, output_len, returned)
        }));
    }
    domain::observe("WSAIoctl", None);
    let rc = unsafe {
        original::<WsaIoctl>(&WS_WSAIOCTL)(
            s, code, input, input_len, output, output_len, returned, overlapped, routine,
        )
    };
    if rc == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && overlapped.is_null() {
        unsafe {
            crate::os::wsa_windows::wrap_real_extension(input, input_len, output, output_len)
        };
    }
    rc
}

/// Win32 `BOOL` return convention for a handled host call: `Err(e)` fails with `SetLastError(e)`
/// and returns 0; anything non-negative returns as the `BOOL`
/// ([Microsoft Learn: SetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror)).
pub(crate) fn finish_bool(handled: i64) -> i32 {
    if handled < 0 {
        // SAFETY: setting the calling thread's last-error.
        unsafe { SetLastError((-handled) as u32) };
        0
    } else {
        handled as i32
    }
}

/// `SetThreadPriority`: `priority` is a `THREAD_PRIORITY_*` level; returns a `BOOL`
/// ([Microsoft Learn: SetThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority)).
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

/// `GetThreadPriority`: the `THREAD_PRIORITY_*` level, or `THREAD_PRIORITY_ERROR_RETURN`
/// (`MAXLONG`) on failure
/// ([Microsoft Learn: GetThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority)).
unsafe extern "system" fn get_thread_priority(thread: HANDLE) -> i32 {
    // The priority may be negative, so — like POSIX `getpriority` — it cannot use the `BOOL`
    // convention; a host returns the value directly.
    if let Some(r) = dispatch_host(|h| {
        h.get_thread_priority(thread as u64)
            .map(|result| match result {
                crate::host::HostResult::Err(error) => {
                    unsafe { SetLastError(error as u32) };
                    crate::host::HostResult::Ok(i32::MAX as i64)
                }
                result => result,
            })
    }) {
        return r as i32;
    }
    // SAFETY: GET_THREAD_PRIORITY holds kernel32's GetThreadPriority.
    unsafe { original::<unsafe extern "system" fn(HANDLE) -> i32>(&GET_THREAD_PRIORITY)(thread) }
}

/// `SetThreadAffinityMask`, returning the previous mask or 0 on failure
/// ([Microsoft Learn: SetThreadAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask)).
unsafe extern "system" fn set_thread_affinity_mask(thread: HANDLE, mask: usize) -> usize {
    // `r as usize` preserves all 64 bits, so a mask with bit 63 set is NOT mistaken for an error
    // (the getpriority/GetThreadPriority trap) — the `-errno` convention cannot apply here.
    if let Some(r) = dispatch_host(|h| {
        h.set_thread_affinity_mask(thread as u64, mask as u64)
            .map(|result| match result {
                crate::host::HostResult::Err(error) => {
                    unsafe { SetLastError(error as u32) };
                    crate::host::HostResult::Ok(0)
                }
                result => result,
            })
    }) {
        return r as usize;
    }
    // SAFETY: SET_THREAD_AFFINITY_MASK holds kernel32's SetThreadAffinityMask.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, usize) -> usize>(&SET_THREAD_AFFINITY_MASK)(
            thread, mask,
        )
    }
}

/// `SetPriorityClass`: `class` is `REALTIME_PRIORITY_CLASS`/`HIGH_PRIORITY_CLASS`/...; returns a
/// `BOOL` ([Microsoft Learn: SetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass)).
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

/// `GetPriorityClass`: the class, or 0 with the last error set on failure
/// ([Microsoft Learn: GetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass)).
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

/// `SetProcessWorkingSetSizeEx`: the process's working-set bounds in bytes and their
/// `QUOTA_LIMITS_HARDWS_*` flags; returns a `BOOL`
/// ([Microsoft Learn: SetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex)).
unsafe extern "system" fn set_process_working_set_size_ex(
    process: HANDLE,
    min: usize,
    max: usize,
    flags: u32,
) -> i32 {
    if let Some(r) = dispatch_host(|h| h.set_working_set(process as u64, min, max, flags)) {
        return finish_bool(r);
    }
    // SAFETY: SET_PROCESS_WORKING_SET_SIZE_EX holds kernel32's SetProcessWorkingSetSizeEx.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, usize, usize, u32) -> i32>(
            &SET_PROCESS_WORKING_SET_SIZE_EX,
        )(process, min, max, flags)
    }
}

/// `GetProcessWorkingSetSizeEx`: reads the bounds and flags back; returns a `BOOL`
/// ([Microsoft Learn: GetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getprocessworkingsetsizeex)).
unsafe extern "system" fn get_process_working_set_size_ex(
    process: HANDLE,
    min: *mut usize,
    max: *mut usize,
    flags: *mut u32,
) -> i32 {
    // SAFETY: the caller's out-pointers, as the function requires.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.get_working_set(process as u64, min, max, flags) })
    {
        return finish_bool(r);
    }
    // SAFETY: GET_PROCESS_WORKING_SET_SIZE_EX holds kernel32's GetProcessWorkingSetSizeEx.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, *mut usize, *mut usize, *mut u32) -> i32>(
            &GET_PROCESS_WORKING_SET_SIZE_EX,
        )(process, min, max, flags)
    }
}

/// `timeBeginPeriod` (winmm) sets the minimum timer resolution in ms; `TIMERR_NOERROR` (0) on
/// success, `TIMERR_NOCANDO` (97, `TIMERR_BASE` + 1, timeapi.h/mmsystem.h) for an out-of-range
/// period ([Microsoft Learn: timeBeginPeriod](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)).
/// The host returns the `TIMERR_*` code itself; a host `Err` is a refusal, reported as
/// `TIMERR_NOCANDO`.
unsafe extern "system" fn time_begin_period(period: u32) -> u32 {
    if let Some(r) = dispatch_host(|h| h.time_period(true, period)) {
        return mmresult(r);
    }
    // SAFETY: TIME_BEGIN_PERIOD holds winmm's timeBeginPeriod.
    unsafe { original::<unsafe extern "system" fn(u32) -> u32>(&TIME_BEGIN_PERIOD)(period) }
}

/// `timeEndPeriod`, the matching release; same return codes
/// ([Microsoft Learn: timeEndPeriod](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timeendperiod)).
unsafe extern "system" fn time_end_period(period: u32) -> u32 {
    if let Some(r) = dispatch_host(|h| h.time_period(false, period)) {
        return mmresult(r);
    }
    // SAFETY: TIME_END_PERIOD holds winmm's timeEndPeriod.
    unsafe { original::<unsafe extern "system" fn(u32) -> u32>(&TIME_END_PERIOD)(period) }
}

/// `AvSetMmThreadCharacteristicsW` (avrt): registers the calling thread with the MMCSS task
/// `task`, returning the task handle, or NULL with the last error set
/// ([Microsoft Learn: AvSetMmThreadCharacteristicsW](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadcharacteristicsw)).
unsafe extern "system" fn av_set_mm_thread_characteristics_w(
    task: *const u16,
    task_index: *mut u32,
) -> HANDLE {
    // SAFETY: `task` is the caller's NUL-terminated task name.
    let name = unsafe { wide_str(task) };
    if let Some(r) =
        dispatch_host(|h| unsafe { h.av_set_mm_thread_characteristics(name, task_index) })
    {
        if r < 0 {
            // SAFETY: setting the calling thread's last-error.
            unsafe { SetLastError((-r) as u32) };
            return std::ptr::null_mut();
        }
        return r as usize as HANDLE;
    }
    // SAFETY: AV_SET_MM_THREAD_CHARACTERISTICS_W holds avrt's AvSetMmThreadCharacteristicsW.
    unsafe {
        original::<unsafe extern "system" fn(*const u16, *mut u32) -> HANDLE>(
            &AV_SET_MM_THREAD_CHARACTERISTICS_W,
        )(task, task_index)
    }
}

/// The UTF-16 string at `text` without its terminator; empty for a null pointer.
///
/// # Safety
/// `text` is null or NUL-terminated.
unsafe fn wide_str<'a>(text: *const u16) -> &'a [u16] {
    if text.is_null() {
        return &[];
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units precede the terminator.
    unsafe { std::slice::from_raw_parts(text, len) }
}

/// `AvSetMmThreadPriority` (avrt): an `AVRT_PRIORITY` for a registered task; returns a `BOOL`
/// ([Microsoft Learn: AvSetMmThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadpriority)).
unsafe extern "system" fn av_set_mm_thread_priority(task: HANDLE, priority: i32) -> i32 {
    if let Some(r) = dispatch_host(|h| h.av_set_mm_thread_priority(task as u64, priority)) {
        return finish_bool(r);
    }
    // SAFETY: AV_SET_MM_THREAD_PRIORITY holds avrt's AvSetMmThreadPriority.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, i32) -> i32>(&AV_SET_MM_THREAD_PRIORITY)(
            task, priority,
        )
    }
}

/// `AvRevertMmThreadCharacteristics` (avrt): ends a task registration; returns a `BOOL`
/// ([Microsoft Learn: AvRevertMmThreadCharacteristics](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avrevertmmthreadcharacteristics)).
unsafe extern "system" fn av_revert_mm_thread_characteristics(task: HANDLE) -> i32 {
    if let Some(r) = dispatch_host(|h| h.av_revert_mm_thread_characteristics(task as u64)) {
        return finish_bool(r);
    }
    // SAFETY: AV_REVERT_MM_THREAD_CHARACTERISTICS holds avrt's AvRevertMmThreadCharacteristics.
    unsafe {
        original::<unsafe extern "system" fn(HANDLE) -> i32>(&AV_REVERT_MM_THREAD_CHARACTERISTICS)(
            task,
        )
    }
}

/// The signature of `SetProcessInformation`, `GetProcessInformation` and their thread
/// counterparts: handle, information class, buffer, buffer size.
type InformationFn = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32) -> i32;

/// `SetProcessInformation`; returns a `BOOL`
/// ([Microsoft Learn: SetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation)).
unsafe extern "system" fn set_process_information(
    process: HANDLE,
    class: i32,
    info: *mut c_void,
    size: u32,
) -> i32 {
    // SAFETY: `info` is the caller's buffer of `size` bytes.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.set_process_information(process as u64, class, info.cast(), size)
    }) {
        return finish_bool(r);
    }
    // SAFETY: SET_PROCESS_INFORMATION holds kernel32's SetProcessInformation.
    unsafe { original::<InformationFn>(&SET_PROCESS_INFORMATION)(process, class, info, size) }
}

/// `GetProcessInformation`; returns a `BOOL`
/// ([Microsoft Learn: GetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation)).
unsafe extern "system" fn get_process_information(
    process: HANDLE,
    class: i32,
    info: *mut c_void,
    size: u32,
) -> i32 {
    // SAFETY: `info` is the caller's buffer of `size` bytes.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.get_process_information(process as u64, class, info.cast(), size)
    }) {
        return finish_bool(r);
    }
    // SAFETY: GET_PROCESS_INFORMATION holds kernel32's GetProcessInformation.
    unsafe { original::<InformationFn>(&GET_PROCESS_INFORMATION)(process, class, info, size) }
}

/// `SetThreadInformation`; returns a `BOOL`
/// ([Microsoft Learn: SetThreadInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadinformation)).
unsafe extern "system" fn set_thread_information(
    thread: HANDLE,
    class: i32,
    info: *mut c_void,
    size: u32,
) -> i32 {
    // SAFETY: `info` is the caller's buffer of `size` bytes.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.set_thread_information(thread as u64, class, info.cast(), size)
    }) {
        return finish_bool(r);
    }
    // SAFETY: SET_THREAD_INFORMATION holds kernel32's SetThreadInformation.
    unsafe { original::<InformationFn>(&SET_THREAD_INFORMATION)(thread, class, info, size) }
}

/// `GetThreadInformation`; returns a `BOOL`
/// ([Microsoft Learn: GetThreadInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadinformation)).
unsafe extern "system" fn get_thread_information(
    thread: HANDLE,
    class: i32,
    info: *mut c_void,
    size: u32,
) -> i32 {
    // SAFETY: `info` is the caller's buffer of `size` bytes.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.get_thread_information(thread as u64, class, info.cast(), size)
    }) {
        return finish_bool(r);
    }
    // SAFETY: GET_THREAD_INFORMATION holds kernel32's GetThreadInformation.
    unsafe { original::<InformationFn>(&GET_THREAD_INFORMATION)(thread, class, info, size) }
}

/// `GetSystemCpuSetInformation`; returns a `BOOL`
/// ([Microsoft Learn: GetSystemCpuSetInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemcpusetinformation)).
unsafe extern "system" fn get_system_cpu_set_information(
    info: *mut c_void,
    len: u32,
    returned: *mut u32,
    process: HANDLE,
    flags: u32,
) -> i32 {
    // SAFETY: `info` holds `len` bytes and `returned` is writable, the caller's.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.system_cpu_set_information(info.cast(), len, returned, process as u64, flags)
    }) {
        return finish_bool(r);
    }
    type CpuSetInformationFn = unsafe extern "system" fn(*mut c_void, u32, *mut u32, HANDLE, u32) -> i32;
    // SAFETY: GET_SYSTEM_CPU_SET_INFORMATION holds kernel32's GetSystemCpuSetInformation.
    unsafe {
        original::<CpuSetInformationFn>(&GET_SYSTEM_CPU_SET_INFORMATION)(
            info, len, returned, process, flags,
        )
    }
}

/// The signature of `SetProcessDefaultCpuSets` and `SetThreadSelectedCpuSets`.
type SetCpuSetsFn = unsafe extern "system" fn(HANDLE, *const u32, u32) -> i32;
/// The signature of `GetProcessDefaultCpuSets` and `GetThreadSelectedCpuSets`.
type GetCpuSetsFn = unsafe extern "system" fn(HANDLE, *mut u32, u32, *mut u32) -> i32;

/// `SetProcessDefaultCpuSets`; returns a `BOOL`
/// ([Microsoft Learn: SetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessdefaultcpusets)).
unsafe extern "system" fn set_process_default_cpu_sets(
    process: HANDLE,
    ids: *const u32,
    count: u32,
) -> i32 {
    // SAFETY: `ids` holds `count` ids, the caller's.
    if let Some(r) = dispatch_host(|h| unsafe { h.set_cpu_sets(false, process as u64, ids, count) })
    {
        return finish_bool(r);
    }
    // SAFETY: SET_PROCESS_DEFAULT_CPU_SETS holds kernel32's SetProcessDefaultCpuSets.
    unsafe { original::<SetCpuSetsFn>(&SET_PROCESS_DEFAULT_CPU_SETS)(process, ids, count) }
}

/// `GetProcessDefaultCpuSets`; returns a `BOOL`
/// ([Microsoft Learn: GetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessdefaultcpusets)).
unsafe extern "system" fn get_process_default_cpu_sets(
    process: HANDLE,
    ids: *mut u32,
    count: u32,
    required: *mut u32,
) -> i32 {
    // SAFETY: `ids` has room for `count` ids and `required` is writable, the caller's.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.get_cpu_sets(false, process as u64, ids, count, required)
    }) {
        return finish_bool(r);
    }
    // SAFETY: GET_PROCESS_DEFAULT_CPU_SETS holds kernel32's GetProcessDefaultCpuSets.
    unsafe {
        original::<GetCpuSetsFn>(&GET_PROCESS_DEFAULT_CPU_SETS)(process, ids, count, required)
    }
}

/// `SetThreadSelectedCpuSets`; returns a `BOOL`
/// ([Microsoft Learn: SetThreadSelectedCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadselectedcpusets)).
unsafe extern "system" fn set_thread_selected_cpu_sets(
    thread: HANDLE,
    ids: *const u32,
    count: u32,
) -> i32 {
    // SAFETY: `ids` holds `count` ids, the caller's.
    if let Some(r) = dispatch_host(|h| unsafe { h.set_cpu_sets(true, thread as u64, ids, count) })
    {
        return finish_bool(r);
    }
    // SAFETY: SET_THREAD_SELECTED_CPU_SETS holds kernel32's SetThreadSelectedCpuSets.
    unsafe { original::<SetCpuSetsFn>(&SET_THREAD_SELECTED_CPU_SETS)(thread, ids, count) }
}

/// `GetThreadSelectedCpuSets`; returns a `BOOL`
/// ([Microsoft Learn: GetThreadSelectedCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadselectedcpusets)).
unsafe extern "system" fn get_thread_selected_cpu_sets(
    thread: HANDLE,
    ids: *mut u32,
    count: u32,
    required: *mut u32,
) -> i32 {
    // SAFETY: `ids` has room for `count` ids and `required` is writable, the caller's.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.get_cpu_sets(true, thread as u64, ids, count, required) })
    {
        return finish_bool(r);
    }
    // SAFETY: GET_THREAD_SELECTED_CPU_SETS holds kernel32's GetThreadSelectedCpuSets.
    unsafe { original::<GetCpuSetsFn>(&GET_THREAD_SELECTED_CPU_SETS)(thread, ids, count, required) }
}

/// A host `time_period` result as the `MMRESULT` the caller reads: the code itself, or
/// `TIMERR_NOCANDO` (97, `TIMERR_BASE` + 1 in timeapi.h/mmsystem.h) for a host `Err`, the only
/// failure `timeBeginPeriod`/`timeEndPeriod` document.
fn mmresult(handled: i64) -> u32 {
    const TIMERR_NOCANDO: u32 = 97;
    if handled < 0 {
        TIMERR_NOCANDO
    } else {
        handled as u32
    }
}

// The `wpcap`/`npcap` exports are cdecl, not stdcall — hence `extern "C"`. A capture handle is an
// opaque `pcap_t*`, carried to the backend as `u64`. With no `Net`, each call forwards to the real
// library unchanged. Signatures and semantics per the libpcap/Npcap manuals (`pcap(3PCAP)`).

/// `pcap_create(source, errbuf)` ([pcap_create(3PCAP)](https://www.tcpdump.org/manpages/pcap_create.3pcap.html)):
/// a device the sim models gets a sim capture handle (a positive backend value used as the
/// `pcap_t*`); any other goes to Npcap.
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

/// `pcap_open_live` ([pcap_open_live(3PCAP)](https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html)):
/// as [`pcap_create`] plus activation in one call. `snaplen`, `promisc` and `to_ms` do not apply
/// to a sim device, which hands over whole frames as they arrive.
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

/// `pcap_activate` ([pcap_activate(3PCAP)](https://www.tcpdump.org/manpages/pcap_activate.3pcap.html)):
/// a sim handle gets the backend's `pcap_configure` answer, which serves every setup call on
/// its own handles; a real handle goes to Npcap.
unsafe extern "C" fn pcap_activate(handle: *mut c_void) -> c_int {
    if let Some(r) = dispatch_net(|net| net.pcap_configure(handle as u64)) {
        return r as c_int;
    }
    // SAFETY: PCAP_ACTIVATE holds wpcap's pcap_activate.
    unsafe { original::<unsafe extern "C" fn(*mut c_void) -> c_int>(&PCAP_ACTIVATE)(handle) }
}

/// `pcap_set_immediate_mode` ([pcap_set_immediate_mode(3PCAP)](https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html)):
/// accepted on a sim handle, whose delivery is always immediate.
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

/// `pcap_setnonblock` ([pcap_setnonblock(3PCAP)](https://www.tcpdump.org/manpages/pcap_setnonblock.3pcap.html)):
/// accepted on a sim handle.
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
        original::<unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int>(
            &PCAP_SETNONBLOCK,
        )(handle, nonblock, errbuf)
    }
}

/// `pcap_sendpacket` ([pcap_inject(3PCAP)](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html)):
/// 0 on success, `PCAP_ERROR` (-1) on failure; a sim handle puts the frame on the sim fabric.
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

/// `pcap_next_ex` ([pcap_next_ex(3PCAP)](https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html)):
/// 1 with `*header`/`*data` pointing at the next frame, 0 when the timeout expired with none,
/// `PCAP_ERROR` on error; libpcap's pointers stay valid only until the next call on the handle.
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

/// `pcap_close` ([pcap_close(3PCAP)](https://www.tcpdump.org/manpages/pcap_close.3pcap.html)).
unsafe extern "C" fn pcap_close(handle: *mut c_void) {
    if dispatch_net(|net| net.pcap_close(handle as u64)).is_some() {
        return;
    }
    // SAFETY: PCAP_CLOSE holds wpcap's pcap_close.
    unsafe { original::<unsafe extern "C" fn(*mut c_void)>(&PCAP_CLOSE)(handle) }
}

// The `pcap_send_queue` (Npcap `<pcap.h>`, WinPcap Win32-Extensions.h; WinPcap 4.1 docs
// "pcap_send_queue Struct Reference",
// https://www.winpcap.org/docs/docs_41/html/structpcap__send__queue.html):
// { u_int maxlen; u_int len; char* buffer }. A sim
// send-queue is one allocation holding the struct followed by its `maxlen`-byte buffer, so a single
// `dealloc` frees it. `pcap_sendqueue_queue` appends `[pcap_pkthdr][packet]` entries (the pkthdr's
// caplen@8 giving each packet's length); `pcap_sendqueue_transmit` replays them through the device.
const SQ_HDR: usize = 16; // sizeof(pcap_send_queue) on LP64/LLP64: two u32 + an 8-byte pointer
// sizeof(pcap_pkthdr) on Windows: timeval(8; two 32-bit LONGs under LLP64, winsock.h) + caplen(4)
// + len(4). Not the unix size, where `timeval` is 16 bytes.
const PKTHDR_LEN: usize = 16;

/// `pcap_sendqueue_alloc(memsize)`: on a managed thread the sim allocates the queue itself, so
/// that queueing and transmitting need no Npcap at all; in passthrough Npcap's is used. Queues
/// from the two allocators must not be mixed, which holds as long as a thread does not change
/// sides between allocating and destroying.
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

/// `pcap_sendqueue_queue(queue, pkthdr, data)`: appends `[pcap_pkthdr][caplen bytes]`; -1 when
/// the queue lacks room, 0 on success, as libpcap's (pcap.c `pcap_sendqueue_queue`, the code
/// Npcap ships). Works on both the sim's queues and Npcap's (same layout), so it is never
/// forwarded; a null queue or header also returns -1, where the real one would fault.
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

/// `pcap_sendqueue_transmit(handle, queue, sync)`: sends every queued packet and returns "the
/// amount of bytes actually sent", the queue's `len` when all went
/// ([WinPcap 4.1: Exported functions](https://www.winpcap.org/docs/docs_41/html/group__wpcapfunc.html);
/// [WinPcap 4.1: Sending Packets](https://www.winpcap.org/docs/docs_41/html/group__wpcap__tut8.html)
/// compares it with `squeue->len`).
/// `sync` (pace by the headers' timestamps) is ignored for a sim handle: frames go out at once.
/// A truncated last entry stops the replay.
unsafe extern "C" fn pcap_sendqueue_transmit(
    handle: *mut c_void,
    queue: *mut c_void,
    sync: i32,
) -> u32 {
    // A sim capture handle: replay each queued frame through the device's fan-out.
    if dispatch_net(|net| net.pcap_configure(handle as u64)).is_some() {
        let q = queue.cast::<u8>();
        let len = unsafe { q.add(4).cast::<u32>().read() } as usize;
        let buffer = unsafe { q.add(8).cast::<*mut u8>().read() };
        let mut off = 0usize;
        while off + PKTHDR_LEN <= len {
            let caplen = unsafe { buffer.add(off).add(8).cast::<u32>().read() } as usize;
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

/// `pcap_sendqueue_destroy(queue)`: frees a queue from [`pcap_sendqueue_alloc`], recomputing
/// its layout from the stored `maxlen`.
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

/// `pcap_geterr` ([pcap_geterr(3PCAP)](https://www.tcpdump.org/manpages/pcap_geterr.3pcap.html)):
/// the last error message on a handle.
unsafe extern "C" fn pcap_geterr(handle: *mut c_void) -> *mut c_char {
    if dispatch_net(|net| net.pcap_configure(handle as u64)).is_some() {
        // The sim never leaves an error pending; report an empty message.
        return c"".as_ptr() as *mut c_char;
    }
    domain::observe("pcap_geterr", None);
    unsafe { original::<unsafe extern "C" fn(*mut c_void) -> *mut c_char>(&PCAP_GETERR)(handle) }
}

/// OS calls no layer models yet; see [`crate::Unmodelled`]. Each is forwarded unchanged after
/// [`domain::observe`] notes it, so an executive's audit can flag unsupported I/O and device requests. Entries whose name also has a
/// modelled hook above are shadowed by it (see [`hooks()`]).
fn observed_hooks() -> Vec<Hook> {
    vec![
        observed!("SetConsoleCtrlHandler" in "kernel32.dll", [handler, add]),
        observed!("pcap_sendqueue_alloc" in "wpcap.dll", [memsize]),
        observed!("pcap_sendqueue_queue" in "wpcap.dll", [queue, header, data]),
        observed!("pcap_sendqueue_transmit" in "wpcap.dll", [handle, queue, sync]),
        observed!("pcap_findalldevs" in "wpcap.dll", [devices, errbuf]),
    ]
}
/// 100 ns intervals between 1601-01-01 (the FILETIME epoch) and the Unix epoch. A `FILETIME`
/// counts 100 ns ticks since 1601-01-01 UTC
/// ([Microsoft Learn: FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime));
/// the constant is the one in
/// [Microsoft Learn: Converting a time_t value to a FILETIME](https://learn.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time).
const FILETIME_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
/// winbase.h `INFINITE` (0xFFFFFFFF): a timeout that never expires.
const INFINITE: u32 = u32::MAX;

/// `QueryPerformanceFrequency`: counts per second, "fixed at system boot and ... consistent
/// across all processors"
/// ([Microsoft Learn: QueryPerformanceFrequency](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency)),
/// so it is read once and cached. The virtual monotonic time is rescaled from nanoseconds to
/// these units so `QueryPerformanceCounter` stays self-consistent. Clamped to at least 1.
fn counter_frequency() -> u128 {
    let _passthrough = crate::state::Passthrough::enter();
    static FREQUENCY: OnceLock<i64> = OnceLock::new();
    *FREQUENCY.get_or_init(|| {
        let mut frequency = 0;
        // SAFETY: writes one i64; the function is not hooked.
        unsafe { QueryPerformanceFrequency(&mut frequency) };
        frequency.max(1)
    }) as u128
}

/// The `QueryPerformanceCounter` value of monotonic time `monotonic`, in the units the hooked
/// `QueryPerformanceCounter` reports the virtual clock in, so a sim's software packet timestamps
/// compare with the code under test's own counter reads
/// ([Microsoft Learn: Winsock timestamping](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-timestamping):
/// software stamps are QPC values).
pub fn performance_count(monotonic: Duration) -> u64 {
    (monotonic.as_nanos() * counter_frequency() / 1_000_000_000) as u64
}

/// The first monotonic time after `monotonic` at which the hooked `QueryPerformanceCounter` reads
/// a higher count than at `monotonic`: the earliest a reader of the counter sees time pass.
pub fn next_performance_count(monotonic: Duration) -> Duration {
    let frequency = counter_frequency();
    let next = monotonic.as_nanos() * frequency / 1_000_000_000 + 1;
    Duration::from_nanos((next * 1_000_000_000).div_ceil(frequency) as u64)
}

/// `QueryPerformanceCounter`: the high-resolution monotonic tick count; returns a nonzero `BOOL`
/// on success ([Microsoft Learn: QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)).
/// std's `Instant` reads it.
unsafe extern "system" fn query_performance_counter(count: *mut i64) -> i32 {
    if !count.is_null()
        && let Some(now) = crate::domain::read_clock(ClockKind::Monotonic)
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

/// `GetTickCount64`: milliseconds since boot, served from the same virtual monotonic clock as
/// `QueryPerformanceCounter`
/// ([Microsoft Learn: GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)).
unsafe extern "system" fn get_tick_count_64() -> u64 {
    if let Some(now) = crate::domain::read_clock(ClockKind::Monotonic) {
        return now.as_millis() as u64;
    }
    // SAFETY: GET_TICK_COUNT_64 holds kernel32's GetTickCount64.
    unsafe { original::<unsafe extern "system" fn() -> u64>(&GET_TICK_COUNT_64)() }
}

/// `GetTickCount`: the same count truncated to 32 bits, so it wraps to zero after 2^32 ms
/// (about 49.7 days), as the real one does
/// ([Microsoft Learn: GetTickCount](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount)).
unsafe extern "system" fn get_tick_count() -> u32 {
    if let Some(now) = crate::domain::read_clock(ClockKind::Monotonic) {
        return now.as_millis() as u32;
    }
    // SAFETY: GET_TICK_COUNT holds kernel32's GetTickCount.
    unsafe { original::<unsafe extern "system" fn() -> u32>(&GET_TICK_COUNT)() }
}

/// `QueryUnbiasedInterruptTime`: the interrupt-time count in 100 ns units; returns a nonzero
/// `BOOL` on success
/// ([Microsoft Learn: QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime)).
/// The virtual monotonic clock never counts a suspend, so biased and unbiased agree.
unsafe extern "system" fn query_unbiased_interrupt_time(out: *mut u64) -> i32 {
    if !out.is_null()
        && let Some(now) = crate::domain::read_clock(ClockKind::Monotonic)
    {
        // SAFETY: the caller passed a writable u64.
        unsafe { out.write((now.as_nanos() / 100) as u64) };
        return 1;
    }
    // SAFETY: QUERY_UNBIASED_INTERRUPT_TIME holds kernel32's QueryUnbiasedInterruptTime.
    unsafe {
        original::<unsafe extern "system" fn(*mut u64) -> i32>(&QUERY_UNBIASED_INTERRUPT_TIME)(out)
    }
}

/// Writes the domain's realtime clock to `out` as a `FILETIME`, split into its low and high
/// `DWORD`s. `false` when no layer serves the clock, so the caller forwards.
fn write_file_time(out: *mut FILETIME) -> bool {
    let Some(now) = crate::domain::read_clock(ClockKind::Realtime) else {
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

/// `GetSystemTimePreciseAsFileTime`: wall-clock UTC as a `FILETIME` (100 ns ticks since 1601)
/// ([Microsoft Learn: GetSystemTimePreciseAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)).
/// std's `SystemTime::now` reads it.
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

/// `GetSystemTimeAsFileTime`, the coarse variant
/// ([Microsoft Learn: GetSystemTimeAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime));
/// the virtual clock serves both at full precision.
unsafe extern "system" fn get_system_time_as_file_time(out: *mut FILETIME) {
    if out.is_null() || !write_file_time(out) {
        // SAFETY: GET_SYSTEM_TIME_AS_FILE_TIME holds the kernel32 function.
        unsafe {
            original::<unsafe extern "system" fn(*mut FILETIME)>(&GET_SYSTEM_TIME_AS_FILE_TIME)(out)
        }
    }
}

/// Sleeps `millis` on the domain's clock. `false` (the caller sleeps for real) off a domain, and
/// for `INFINITE`, a sleep that never returns and so has nothing to simulate.
fn virtual_sleep(millis: u32) -> bool {
    millis != INFINITE
        && dispatch(|layer| layer.sleep(SleepRequest::For(Duration::from_millis(millis.into()))))
            .is_some()
}

/// `Sleep` ([Microsoft Learn: Sleep](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep)).
unsafe extern "system" fn sleep(millis: u32) {
    if !virtual_sleep(millis) {
        // SAFETY: SLEEP holds kernel32's Sleep.
        unsafe { original::<unsafe extern "system" fn(u32)>(&SLEEP)(millis) }
    }
}

/// `SleepEx`: a virtual sleep returns 0, the full-interval result; it never runs APCs, so the
/// `WAIT_IO_COMPLETION` return of an alertable sleep does not arise
/// ([Microsoft Learn: SleepEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)).
unsafe extern "system" fn sleep_ex(millis: u32, alertable: i32) -> u32 {
    if virtual_sleep(millis) {
        return 0;
    }
    // SAFETY: SLEEP_EX holds kernel32's SleepEx.
    unsafe { original::<unsafe extern "system" fn(u32, i32) -> u32>(&SLEEP_EX)(millis, alertable) }
}

/// `LPTHREAD_START_ROUTINE`.
type StartRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

/// What [`create_thread`] hands its new thread: the caller's start routine and parameter, and the
/// domain membership the thread adopts before running them.
struct Start {
    routine: StartRoutine,
    parameter: *mut c_void,
    /// Made by `domain::inherit` on the creating thread; adopted exactly once by the new thread,
    /// or released by the creator if the thread never starts.
    inherited: domain::Inherited,
}

/// The start routine every managed thread really runs: joins the creator's domain, runs the
/// caller's routine, and leaves the domain (dropping `child`) before returning its exit code.
unsafe extern "system" fn managed_start(start: *mut c_void) -> u32 {
    // SAFETY: `create_thread` boxed this `Start` and handed ownership to this thread.
    let Start {
        routine,
        parameter,
        inherited,
    } = *unsafe { Box::from_raw(start.cast::<Start>()) };
    // SAFETY: `inherit` made this for this thread alone.
    let child = unsafe { domain::adopt(inherited) };
    // SAFETY: calling the caller's start routine with its own parameter.
    let result = unsafe { routine(parameter) };
    drop(child);
    result
}

/// kernel32's `CreateThread`.
type CreateThreadFn = unsafe extern "system" fn(
    *const c_void,
    usize,
    Option<StartRoutine>,
    *const c_void,
    u32,
    *mut u32,
) -> HANDLE;

/// `CreateThread` ([Microsoft Learn: CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)),
/// which std's `thread::spawn` calls: a thread created by a managed thread joins its domain. The
/// start routine is wrapped in [`managed_start`], and the new thread's id is recorded against its
/// lineage so later `WaitForSingleObject` joins and `GetThreadId` lookups can find it. Off a
/// domain (no `Inherited`), the call is forwarded unchanged.
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
    let (Some(routine), Some(inherited)) = (routine, routine.and_then(|_| domain::inherit()))
    else {
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { create(attributes, stack_size, routine, parameter, flags, thread_id) };
    };
    let lineage = inherited.lineage;
    let start = Box::into_raw(Box::new(Start {
        routine,
        parameter: parameter.cast_mut(),
        inherited,
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
        // SAFETY: nothing adopted it.
        unsafe { domain::release(start.inherited) };
    } else {
        // SAFETY: a live thread handle CreateThread just returned.
        let id = unsafe { GetThreadId(handle) };
        domain::record_handle(id as usize, lineage);
    }
    handle
}

/// Whether `handle` refers to a thread. `GetThreadId` returns 0 for any non-thread (or invalid)
/// handle ([Microsoft Learn: GetThreadId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadid):
/// "If the function fails, the return value is zero"); the last-error save/restore keeps the
/// probe invisible to the caller.
fn is_thread_handle(handle: HANDLE) -> bool {
    // SAFETY: GetThreadId accepts any handle value and reports 0 rather than faulting.
    let saved = unsafe { GetLastError() };
    let id = unsafe { GetThreadId(handle) };
    // SAFETY: restoring the caller's last-error value.
    unsafe { SetLastError(saved) };
    id != 0
}

/// `WaitForSingleObject`
/// ([Microsoft Learn: WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)).
///
/// Three cases: a join under a deterministic schedule waits for the thread's exit in the schedule
/// first; a semaphore wait on a thread whose timeouts are virtual goes to [`semaphore_wait`]; a
/// join on any other managed thread is a counted native wait. Anything else is forwarded.
//
// WaitForSingleObject on a thread handle is how std's `JoinHandle::join` blocks until the thread
// exits — the Windows counterpart of `pthread_join` (std/src/sys/thread/windows.rs `join`, an
// INFINITE wait). A managed thread joining another is an
// in-memory wait only another managed thread can satisfy, so it counts toward quiescence: without
// it, a thread that gives up on a deadlocked wait and then joins a still-parked peer leaves that
// peer short of the quiescence count forever. Waits on other handle kinds (mutexes, events) are
// left uncounted so they never trip the deadlock give-up.
unsafe extern "system" fn wait_for_single_object(handle: HANDLE, timeout: u32) -> u32 {
    // SAFETY: WAIT_FOR_SINGLE_OBJECT holds kernel32's WaitForSingleObject.
    let wait = unsafe {
        original::<unsafe extern "system" fn(HANDLE, u32) -> u32>(&WAIT_FOR_SINGLE_OBJECT)
    };
    if let Some(result) = timers::wait(handle, timeout, wait) {
        return result;
    }
    if domain::counts_native_waits() && domain::det_active() && is_thread_handle(handle) {
        domain::end_spin();
        // SAFETY: GetThreadId on a handle just confirmed to be a thread.
        let id = unsafe { GetThreadId(handle) };
        if let Some(target) = domain::det_lineage_of(id as usize) {
            let _label = crate::wait_label("join");
            // Deterministic: wait for the thread's exit in the schedule; the real wait then only
            // collects a thread that is already leaving.
            domain::det_block(crate::DetKey::Exit(target), None);
        }
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { wait(handle, timeout) };
    }
    if domain::virtual_waits() && !is_thread_handle(handle) && is_semaphore(handle) {
        return semaphore_wait(handle, timeout, wait);
    }
    if !state::passthrough() && !state::domain().is_null() && is_thread_handle(handle) {
        domain::end_spin();
        let _label = crate::wait_label("join");
        // SAFETY: GetThreadId on a handle just confirmed to be a thread.
        if !domain::begin_join(unsafe { GetThreadId(handle) } as usize) {
            return unsafe { wait(handle, timeout) };
        }
        // SAFETY: forwarding the caller's arguments unchanged.
        domain::native_wait(|| unsafe { wait(handle, timeout) })
    } else {
        // SAFETY: forwarding the caller's arguments unchanged.
        unsafe { wait(handle, timeout) }
    }
}

/// `WaitOnAddress` ([Microsoft Learn: WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress)):
/// `TRUE` when woken or when `*address` already differs from `*compare` (`size` 1, 2, 4 or 8
/// bytes), `FALSE` with `ERROR_TIMEOUT` when `millis` runs out. Spurious wakes are allowed, so
/// callers re-check the value.
///
/// The blocking edge of std's Mutex/RwLock/Condvar/park/Once on Windows 8+ (std/src/sys/pal/
/// windows/futex.rs), and of parking_lot (which reaches it through `GetProcAddress`,
/// parking_lot_core src/thread_parker/windows/waitaddress.rs, so the hook there hands out this
/// replacement): a
/// managed thread waiting here can only be released by another, so the wait counts toward
/// quiescence. A finite timeout is a span the caller measured on the (virtual) clock, so it is
/// waited out in the domain's time. The wait re-checks the address every time, so a wake landing
/// between two slices is never lost.
///
/// A wait on the address the thread already waits on further up its stack is nested in that wait
/// (see `os::nested`): std's thread parker, parked again by sim code run inside the outer park. It
/// waits for real for at most `NESTED_WAIT_SLICE` for the address to change from what it holds
/// now, and then returns `TRUE`. An outer wait a nested one spoiled, or whose std parker a nested
/// park took the notification of, returns `TRUE` with that notification put back
/// (`nested::settle_parker`).
unsafe extern "system" fn wait_on_address(
    address: *const c_void,
    compare: *const c_void,
    size: usize,
    millis: u32,
) -> i32 {
    let Some(outer) = crate::os::nested::begin(address as usize) else {
        // SAFETY: the caller's address, `size` bytes.
        return unsafe { nested_wait_on_address(address, size) };
    };
    let (before, expected) = unsafe {
        let expected = match size {
            1 => u64::from(compare.cast::<u8>().read()),
            4 => u64::from(compare.cast::<u32>().read_unaligned()),
            _ => 0,
        };
        (crate::os::nested::load(address as usize, size), expected)
    };
    // SAFETY: the caller's arguments.
    let woke = unsafe { wait_on_address_call(address, compare, size, millis) };
    let settled = unsafe {
        crate::os::nested::settle_parker(&outer, address as usize, size, expected, before)
    };
    if settled { 1 } else { woke }
}

/// The nested `WaitOnAddress` of [`wait_on_address`]: one real wait for `address` to change from
/// what it holds now, for `NESTED_WAIT_SLICE` at most.
///
/// # Safety
/// `address` is the caller's, `size` bytes (1, 2, 4 or 8).
unsafe fn nested_wait_on_address(address: *const c_void, size: usize) -> i32 {
    // SAFETY: WAIT_ON_ADDRESS holds the system's WaitOnAddress.
    let wait = unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const c_void, usize, u32) -> i32>(
            &WAIT_ON_ADDRESS,
        )
    };
    let mut current = [0u8; 8];
    let millis = u32::try_from(crate::os::nested::NESTED_WAIT_SLICE.as_millis()).unwrap_or(1);
    // SAFETY: `size` bytes of the caller's address into a buffer of 8; then a wait on that address
    // with this snapshot as its comparand.
    unsafe {
        std::ptr::copy_nonoverlapping(address.cast::<u8>(), current.as_mut_ptr(), size.min(8));
        wait(address, current.as_ptr().cast(), size, millis);
    }
    1
}

thread_local! {
    static ADDRESS_WAIT_VALUE: std::cell::Cell<Option<(usize, usize, u64)>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn address_wait_value(addr: usize) -> Option<(usize, u64)> {
    ADDRESS_WAIT_VALUE
        .try_with(|value| value.get())
        .ok()
        .flatten()
        .and_then(|(address, size, value)| (address == addr).then_some((size, value)))
}

pub(crate) unsafe fn address_value(addr: usize, size: usize) -> u64 {
    use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
    match size {
        1 => unsafe { (&*(addr as *const AtomicU8)).load(Ordering::Acquire) }.into(),
        2 => unsafe { (&*(addr as *const AtomicU16)).load(Ordering::Acquire) }.into(),
        4 => unsafe { (&*(addr as *const AtomicU32)).load(Ordering::Acquire) }.into(),
        8 => unsafe { (&*(addr as *const AtomicU64)).load(Ordering::Acquire) },
        _ => 0,
    }
}

/// Whether a `WaitOnAddress` on `addr` that returned `woke` was woken: it returned `TRUE` and the
/// address no longer holds the comparand. A return with the comparand still in place is one of
/// the spurious wakes the call allows ([Microsoft Learn: WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress)),
/// which no thread caused and so is not a wake from outside the domain.
fn woken_at(addr: usize, woke: i32) -> bool {
    woke != 0
        && address_wait_value(addr)
            .is_none_or(|(size, expected)| unsafe { address_value(addr, size) } != expected)
}

struct AddressWaitValue(Option<(usize, usize, u64)>);

impl Drop for AddressWaitValue {
    fn drop(&mut self) {
        let _ = ADDRESS_WAIT_VALUE.try_with(|value| value.set(self.0));
    }
}

/// How many `WakeByAddressSingle`/`WakeByAddressAll` calls have reached each address, hashed into
/// a fixed table, so a timed wait can tell whether any wake was made on its address while it
/// waited. Two addresses sharing a slot only make a spurious return look like a wake.
static ADDRESS_WAKES: [AtomicU64; 65536] = [const { AtomicU64::new(0) }; 65536];

fn address_wakes(addr: usize) -> &'static AtomicU64 {
    let hash = (addr as u64 >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 48;
    &ADDRESS_WAKES[hash as usize]
}

/// winerror.h: ERROR_TIMEOUT (1460), what a timed-out WaitOnAddress leaves in GetLastError.
const ERROR_TIMEOUT: u32 = 1460;

/// How long a wait on a word in static data, or one a lock's back-off spin leads into (see
/// `domain::backing_off`), first waits in real time, for a holder outside the simulation, before
/// it counts as a wait in the domain. A snare choice, as on Linux: long enough for an outside
/// holder in a short critical section to let go, short enough not to slow a run that waits on an
/// inside one.
const OUTSIDE_HOLDER_GRACE_MS: u32 = 1;

/// [`OUTSIDE_HOLDER_GRACE_MS`] for a wait under a deterministic schedule, which keeps the baton
/// meanwhile: once a wait passes the baton on, which thread runs next depends on how long the outside
/// holder took, so the run no longer replays. A snare choice, as on Linux: long enough to outlast an
/// outside holder on a loaded machine, at the cost of that much real time per wait on a word a parked
/// thread of the domain holds.
const DET_OUTSIDE_HOLDER_GRACE_MS: u32 = 50;

/// The first [`OUTSIDE_HOLDER_GRACE_MS`] of a `WaitOnAddress` on a word in static data, which may
/// be a lock shared with threads outside the simulation (std's own statics: stdout's and stderr's
/// locks, the `Once` around Winsock's startup), or of one a lock's back-off spin leads into, as a
/// real wait the domain does not count. The word carries no owner, so whether a thread of the
/// domain holds it cannot be told; a holder outside lets go in that time, and a holder inside
/// merely delays the wait's counting by it. Returns the wait's result, with the last error as the
/// OS left it, when it ended other than by timing out; `None` once the grace ran out.
///
/// # Safety
/// As for `WaitOnAddress`.
unsafe fn outside_grace(
    grace_ms: u32,
    address: *const c_void,
    compare: *const c_void,
    size: usize,
) -> Option<i32> {
    // SAFETY: WAIT_ON_ADDRESS holds the system's WaitOnAddress.
    let wait = unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const c_void, usize, u32) -> i32>(
            &WAIT_ON_ADDRESS,
        )
    };
    // SAFETY: the caller's address and comparand, with the grace as the timeout.
    let woke = unsafe { wait(address, compare, size, grace_ms) };
    // SAFETY: reading this thread's last-error value.
    (woke != 0 || unsafe { GetLastError() } != ERROR_TIMEOUT).then_some(woke)
}

/// The body of [`wait_on_address`] for a wait not nested in another on the same address.
///
/// # Safety
/// As for `WaitOnAddress`.
unsafe fn wait_on_address_call(
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
    // winbase.h: INFINITE.
    const INFINITE: u32 = u32::MAX;
    let _label = crate::accounting::wait_label_on("WaitOnAddress", address as usize);
    let addr = address as usize;
    let wakes = address_wakes(addr).load(Ordering::Acquire);
    let _value = if domain::counts_native_waits()
        && !address.is_null()
        && !compare.is_null()
        && matches!(size, 1 | 2 | 4 | 8)
        && addr.is_multiple_of(size)
    {
        let expected = unsafe {
            match size {
                1 => u64::from(compare.cast::<u8>().read()),
                2 => u64::from(compare.cast::<u16>().read_unaligned()),
                4 => u64::from(compare.cast::<u32>().read_unaligned()),
                8 => compare.cast::<u64>().read_unaligned(),
                _ => unreachable!(),
            }
        };
        Some(AddressWaitValue(
            ADDRESS_WAIT_VALUE.with(|value| value.replace(Some((addr, size, expected)))),
        ))
    } else {
        None
    };
    if domain::counts_native_waits()
        && !domain::det_active()
        && address_wait_value(addr)
            .is_some_and(|(size, expected)| unsafe { address_value(addr, size) } != expected)
    {
        domain::end_spin();
        return 1;
    }
    if domain::counts_native_waits() && domain::det_active() {
        // Deterministic: return at once if the address no longer holds the comparand, else wait
        // on it in the schedule until a WakeByAddress there or the timeout.
        // SAFETY: the caller's address and comparand, each `size` bytes (1, 2, 4 or 8).
        let differs = unsafe {
            std::slice::from_raw_parts(address.cast::<u8>(), size)
                != std::slice::from_raw_parts(compare.cast::<u8>(), size)
        };
        if differs {
            return 1;
        }
        // A holder inside the simulation is parked while this thread keeps the baton and cannot
        // release the word meanwhile, so whether this wait yields never depends on outside timing.
        if (domain::in_static_image(addr) || domain::backing_off())
            && let Some(woke) =
                unsafe { outside_grace(DET_OUTSIDE_HOLDER_GRACE_MS, address, compare, size) }
        {
            return woke;
        }
        let deadline = (millis != INFINITE)
            .then(|| domain::virtual_now().map(|now| now + Duration::from_millis(millis.into())))
            .flatten();
        if domain::det_block(crate::DetKey::Addr(addr), deadline) == crate::DetWake::TimedOut {
            // SAFETY: setting this thread's last-error value.
            unsafe { SetLastError(ERROR_TIMEOUT) };
            return 0;
        }
        return 1;
    }
    if millis == INFINITE {
        if domain::counts_native_waits()
            && (domain::in_static_image(addr) || domain::backing_off())
            && let Some(woke) =
                unsafe { outside_grace(OUTSIDE_HOLDER_GRACE_MS, address, compare, size) }
        {
            return woke;
        }
        // SAFETY: forwarding the caller's arguments unchanged.
        return domain::native_wait_at_checked(
            None,
            || {
                address_wait_value(addr)
                    .is_some_and(
                        |(size, expected)| unsafe { address_value(addr, size) } != expected,
                    )
                    .then_some(1)
            },
            || loop {
                if crate::os::nested::spoiled(addr) {
                    break 1;
                }
                let woke = unsafe { wait(address, compare, size, millis) };
                // A return with the comparand in place and no wake made on the address since the
                // wait began is spurious: waiting on would be the same wait, and returning would
                // hand the caller (std's condition variable) a wake no thread made.
                if woke != 0
                    && !woken_at(addr, woke)
                    && address_wakes(addr).load(Ordering::Acquire) == wakes
                {
                    continue;
                }
                break woke;
            },
            |woke| woken_at(addr, *woke),
        );
    }
    let after = Duration::from_millis(u64::from(millis));
    let outcome = domain::timed_native_wait_checked(
        after,
        || {
            address_wait_value(addr)
                .is_some_and(|(size, expected)| unsafe { address_value(addr, size) } != expected)
                .then(|| (1, unsafe { GetLastError() }))
        },
        |slice| {
            if crate::os::nested::spoiled(addr) {
                return Some((1, unsafe { GetLastError() }));
            }
            let slice_ms = u32::try_from(slice.as_millis().max(1)).unwrap_or(INFINITE - 1);
            // SAFETY: the caller's address and comparand, with a timeout of `slice` on the real clock.
            let woke = unsafe { wait(address, compare, size, slice_ms) };
            // SAFETY: reading this thread's last-error value.
            let error = unsafe { GetLastError() };
            // A return with the comparand in place and no wake made on the address since the
            // wait began is spurious, and std's `park_timeout` would end early on it rather than
            // outlast its virtual timeout.
            if woke != 0
                && !woken_at(addr, woke)
                && address_wakes(addr).load(Ordering::Acquire) == wakes
            {
                return None;
            }
            (woke != 0 || error != ERROR_TIMEOUT).then_some((woke, error))
        },
        |(woke, _)| woken_at(addr, *woke),
    );
    let (woke, error) = match outcome {
        domain::TimedWait::Woken(result) => result,
        domain::TimedWait::TimedOut => (0, ERROR_TIMEOUT),
    };
    // SAFETY: restoring what the wait reported, which bookkeeping since may have overwritten.
    unsafe { SetLastError(error) };
    woke
}

/// `WakeByAddressSingle`: wakes one `WaitOnAddress` waiter on `address`: a deterministic waiter
/// in the schedule, and any real one outside the sim
/// ([Microsoft Learn: WakeByAddressSingle](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-wakebyaddresssingle)).
/// The release is noted first so the domain's accounting sees the waker before the woken thread
/// runs.
unsafe extern "system" fn wake_by_address_single(address: *const c_void) {
    domain::note_hook_effect("WakeByAddressSingle");
    address_wakes(address as usize).fetch_add(1, Ordering::Release);
    if domain::det_wakes() {
        domain::det_wake(crate::DetKey::Addr(address as usize), 1);
    }
    // SAFETY: WAKE_BY_ADDRESS_SINGLE holds the system's function; argument forwarded.
    domain::release_native(address as usize, 1, || unsafe {
        original::<unsafe extern "system" fn(*const c_void)>(&WAKE_BY_ADDRESS_SINGLE)(address)
    });
}

/// `WakeByAddressAll`: wakes every `WaitOnAddress` waiter on `address`, in the schedule and
/// outside it
/// ([Microsoft Learn: WakeByAddressAll](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-wakebyaddressall)).
unsafe extern "system" fn wake_by_address_all(address: *const c_void) {
    domain::note_hook_effect("WakeByAddressAll");
    address_wakes(address as usize).fetch_add(1, Ordering::Release);
    if domain::det_wakes() {
        domain::det_wake(crate::DetKey::Addr(address as usize), usize::MAX);
    }
    // SAFETY: WAKE_BY_ADDRESS_ALL holds the system's function; argument forwarded.
    domain::release_native(address as usize, usize::MAX, || unsafe {
        original::<unsafe extern "system" fn(*const c_void)>(&WAKE_BY_ADDRESS_ALL)(address)
    });
}

/// `SetThreadDescription` (processthreadsapi.h), which std's `Builder::name` calls: forwarded
/// unchanged, and a description the OS accepts is also recorded for the thread's row in its domain.
/// It returns an `HRESULT`, non-negative on success
/// ([Microsoft Learn: SetThreadDescription](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription)).
/// A description of the calling thread is recorded with no handle; another thread's by its id.
unsafe extern "system" fn set_thread_description(thread: HANDLE, description: *const u16) -> i32 {
    // SAFETY: SET_THREAD_DESCRIPTION holds kernel32's SetThreadDescription; arguments forwarded.
    let hresult = unsafe {
        original::<unsafe extern "system" fn(HANDLE, *const u16) -> i32>(&SET_THREAD_DESCRIPTION)(
            thread,
            description,
        )
    };
    if hresult >= 0 && !description.is_null() && !state::passthrough() {
        let _passthrough = state::Passthrough::enter();
        // SAFETY: the OS accepted `description`, so it is a NUL-terminated UTF-16 string.
        let wide = unsafe {
            let mut len = 0;
            while *description.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(description, len)
        };
        let name = String::from_utf16_lossy(wide);
        // SAFETY: GetThreadId accepts any handle, the current-thread pseudo-handle included.
        let id = unsafe { GetThreadId(thread) };
        let handle = (id != unsafe { GetCurrentThreadId() }).then_some(id as usize);
        drop(_passthrough);
        domain::record_thread_name(handle, name.as_bytes());
    }
    hresult
}

/// `SwitchToThread`
/// ([Microsoft Learn: SwitchToThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-switchtothread)):
/// std's `thread::yield_now` and the spin phase of crossbeam/kanal/parking_lot; see
/// `domain::yield_point`.
unsafe extern "system" fn switch_to_thread() -> i32 {
    domain::yield_point();
    // SAFETY: SWITCH_TO_THREAD holds kernel32's SwitchToThread.
    unsafe { original::<unsafe extern "system" fn() -> i32>(&SWITCH_TO_THREAD)() }
}

/// `GetProcAddress`: hands out hooks instead of the real functions, so code that looks functions
/// up at run time is redirected like code that imports them. Only by-name lookups of a function
/// with a resolved hook are redirected; the hook is chosen by name alone, whichever module was
/// asked.
unsafe extern "system" fn get_proc_address(module: *mut c_void, name: *const u8) -> usize {
    // SAFETY: GET_PROC_ADDRESS holds kernel32's GetProcAddress; arguments are forwarded.
    let found = unsafe {
        original::<unsafe extern "system" fn(*mut c_void, *const u8) -> usize>(&GET_PROC_ADDRESS)(
            module, name,
        )
    };
    // An ordinal is passed in the low-order word with the high-order word zero, so any value
    // below 0x10000 is one (Microsoft Learn: GetProcAddress, lpProcName: "it must be in the
    // low-order word; the high-order word must be zero"; the same test as winuser.h IS_INTRESOURCE).
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

/// Fills `length` bytes at `buffer` from the domain's random layer. A null buffer is only valid
/// for an empty request; `false` sends the call to the OS.
fn virtual_random(buffer: *mut u8, length: usize) -> bool {
    if buffer.is_null() {
        return length == 0;
    }
    // SAFETY: the caller of the hooked function passed `length` writable bytes at `buffer`.
    let buffer = unsafe { std::slice::from_raw_parts_mut(buffer, length) };
    dispatch(|layer| layer.random(buffer)).is_some()
}

/// `ProcessPrng` (bcryptprimitives), std's random source on Windows (std/src/sys/random/
/// windows.rs); it always returns `TRUE`
/// ([Microsoft Learn: ProcessPrng](https://learn.microsoft.com/en-us/windows/win32/seccng/processprng)).
unsafe extern "system" fn process_prng(buffer: *mut u8, length: usize) -> i32 {
    if virtual_random(buffer, length) {
        return 1;
    }
    // SAFETY: PROCESS_PRNG holds bcryptprimitives' ProcessPrng.
    unsafe {
        original::<unsafe extern "system" fn(*mut u8, usize) -> i32>(&PROCESS_PRNG)(buffer, length)
    }
}

/// `BCryptGenRandom`: returns an `NTSTATUS`, `STATUS_SUCCESS` (0) on success
/// ([Microsoft Learn: BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)).
/// The algorithm handle and flags do not matter to the virtual source.
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

/// `LoadLibraryA` ([Microsoft Learn: LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)).
unsafe extern "system" fn load_library_a(name: *const u8) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_A holds kernel32's LoadLibraryA.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u8) -> HMODULE>(&LOAD_LIBRARY_A)(name)
    })
}

/// `LoadLibraryW`.
unsafe extern "system" fn load_library_w(name: *const u16) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_W holds kernel32's LoadLibraryW.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u16) -> HMODULE>(&LOAD_LIBRARY_W)(name)
    })
}

/// `LoadLibraryExA` ([Microsoft Learn: LoadLibraryExA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa)).
unsafe extern "system" fn load_library_ex_a(name: *const u8, file: HANDLE, flags: u32) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_EX_A holds kernel32's LoadLibraryExA.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u8, HANDLE, u32) -> HMODULE>(&LOAD_LIBRARY_EX_A)(
            name, file, flags,
        )
    })
}

/// `LoadLibraryExW`.
unsafe extern "system" fn load_library_ex_w(name: *const u16, file: HANDLE, flags: u32) -> HMODULE {
    // SAFETY: LOAD_LIBRARY_EX_W holds kernel32's LoadLibraryExW.
    after_load(unsafe {
        original::<unsafe extern "system" fn(*const u16, HANDLE, u32) -> HMODULE>(
            &LOAD_LIBRARY_EX_W,
        )(name, file, flags)
    })
}

// The UCRT exports the C runtime's signal and raise through this API set (Microsoft Learn: signal,
// "api_location"; the import name binaries linked against the UCRT carry).
const CRT_RUNTIME: &str = "api-ms-win-crt-runtime-l1-1-0.dll";

/// The hooks behind a domain's [`Signals`](crate::Signals) table on Windows (console control and
/// the CRT's `signal`/`raise`), and `ReleaseSemaphore`, the waking side of [`semaphore_wait`].
fn signal_hooks() -> Vec<Hook> {
    vec![
        hook!(
            "ReleaseSemaphore",
            "kernel32.dll",
            release_semaphore,
            RELEASE_SEMAPHORE
        ),
        hook!(
            "SetConsoleCtrlHandler",
            "kernel32.dll",
            set_console_ctrl_handler,
            SET_CONSOLE_CTRL_HANDLER
        ),
        hook!(
            "GenerateConsoleCtrlEvent",
            "kernel32.dll",
            generate_console_ctrl_event,
            GENERATE_CONSOLE_CTRL_EVENT
        ),
        Hook {
            module: CRT_RUNTIME,
            ..hook!("signal", crt_signal, CRT_SIGNAL)
        },
        Hook {
            module: CRT_RUNTIME,
            ..hook!("raise", crt_raise, CRT_RAISE)
        },
    ]
}

// winbase.h / winerror.h: WAIT_OBJECT_0 (0), WAIT_TIMEOUT (258), INFINITE (0xFFFFFFFF),
// ERROR_INVALID_PARAMETER (87). Microsoft Learn: WaitForSingleObject, "Return value".
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const INFINITE_WAIT: u32 = u32::MAX;
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Whether `handle` is a semaphore, asked of `NtQueryObject` once per handle value.
///
/// `NtQueryObject(handle, ObjectTypeInformation, ..)` fills a `PUBLIC_OBJECT_TYPE_INFORMATION`
/// whose `TypeName` is the object manager's type name
/// ([Microsoft Learn: NtQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject)).
/// That page lists no type names; "Semaphore" is the one relied on by
/// crates/snare/tests/sem_waits.rs `semaphore_waits`, whose timed `WaitForSingleObject` on a
/// `CreateSemaphoreA` handle only runs on the virtual clock if this check matches.
/// The answer is cached by handle value and never invalidated, so a handle value closed and
/// reused for another kind of object keeps its first answer. The cache lock is taken in
/// passthrough and is not held across the query.
fn is_semaphore(handle: HANDLE) -> bool {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            class: u32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    static KINDS: std::sync::Mutex<Option<std::collections::HashMap<usize, bool>>> =
        std::sync::Mutex::new(None);
    let _passthrough = state::Passthrough::enter();
    let key = handle as usize;
    if let Some(&known) = KINDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Default::default)
        .get(&key)
    {
        return known;
    }
    // ObjectTypeInformation (2, winternl.h OBJECT_INFORMATION_CLASS) fills a
    // PUBLIC_OBJECT_TYPE_INFORMATION, which starts with the type name as a UNICODE_STRING
    // { Length: u16 bytes, MaximumLength: u16, Buffer: *const u16 } (winternl.h), the Buffer at
    // offset 8 on 64-bit. 1024 bytes (a snare choice) holds the struct (8 + 8 + 22 * 4 = 104
    // bytes) and the name the kernel copies after it; a longer answer fails and reads as "not a
    // semaphore".
    #[repr(C, align(8))]
    struct Info([u8; 1024]);
    let mut info = Info([0; 1024]);
    let mut returned = 0;
    // SAFETY: GetLastError/SetLastError keep the caller's value; NtQueryObject fills `info`.
    let semaphore = unsafe {
        let saved = GetLastError();
        let status = NtQueryObject(handle, 2, info.0.as_mut_ptr().cast(), 1024, &mut returned);
        SetLastError(saved);
        status >= 0 && {
            let len = usize::from(info.0.as_ptr().cast::<u16>().read()) / 2;
            let name = info.0.as_ptr().add(8).cast::<*const u16>().read();
            !name.is_null()
                && String::from_utf16_lossy(std::slice::from_raw_parts(name, len)) == "Semaphore"
        }
    };
    KINDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Default::default)
        .insert(key, semaphore);
    semaphore
}

/// A wait on a semaphore handle, in the domain's time: in the schedule under deterministic
/// scheduling, else a real wait counted toward quiescence and timed on the virtual clock.
///
/// A zero timeout is a poll: it never blocks, and a failed poll charges the per-call latency so a
/// polling loop still advances a discrete clock. Under the schedule each round tries a
/// non-blocking take and parks on the handle's address until a `ReleaseSemaphore` there wakes
/// it or the virtual deadline passes. Real slices are rounded up to whole milliseconds so a
/// sub-millisecond slice does not become a busy 0 ms poll.
fn semaphore_wait(
    handle: HANDLE,
    timeout: u32,
    wait: unsafe extern "system" fn(HANDLE, u32) -> u32,
) -> u32 {
    let _label = crate::accounting::wait_label_on("semaphore", handle as usize);
    if timeout == 0 {
        // SAFETY: a non-blocking check of the caller's handle.
        let r = unsafe { wait(handle, 0) };
        if r == WAIT_TIMEOUT {
            domain::charge_latency();
        }
        return r;
    }
    let deadline = (timeout != INFINITE_WAIT)
        .then(|| domain::virtual_now().map(|now| now + Duration::from_millis(timeout.into())))
        .flatten();
    while domain::counts_native_waits() && domain::det_active() {
        // SAFETY: a non-blocking take on the caller's semaphore.
        if unsafe { wait(handle, 0) } == WAIT_OBJECT_0 {
            return WAIT_OBJECT_0;
        }
        if domain::det_block(crate::DetKey::Addr(handle as usize), deadline)
            == crate::DetWake::TimedOut
        {
            return WAIT_TIMEOUT;
        }
    }
    if timeout == INFINITE_WAIT {
        // SAFETY: forwarding the caller's arguments unchanged.
        return domain::native_wait_on(crate::DetKey::Addr(handle as usize), || unsafe {
            wait(handle, timeout)
        });
    }
    let outcome =
        domain::timed_native_wait(Duration::from_millis(timeout.into()), None, None, |slice| {
            let millis = u32::try_from(slice.as_micros().div_ceil(1000)).unwrap_or(u32::MAX - 1);
            // SAFETY: the caller's handle, waited on for one slice.
            let r = unsafe { wait(handle, millis) };
            (r != WAIT_TIMEOUT).then_some(r)
        });
    match outcome {
        domain::TimedWait::Woken(r) => r,
        domain::TimedWait::TimedOut => WAIT_TIMEOUT,
    }
}

/// `ReleaseSemaphore` (synchapi.h): increases the semaphore's count by `count`, so up to that
/// many waiters can take it
/// ([Microsoft Learn: ReleaseSemaphore](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasesemaphore)).
/// The real release always happens; a successful one also wakes `count` waiters parked on the
/// handle in the deterministic schedule, with the caller's last-error value kept intact.
unsafe extern "system" fn release_semaphore(handle: HANDLE, count: i32, previous: *mut i32) -> i32 {
    domain::note_hook_effect("ReleaseSemaphore");
    let n = usize::try_from(count).unwrap_or(0);
    domain::note_release(handle as usize, n);
    // SAFETY: RELEASE_SEMAPHORE holds kernel32's ReleaseSemaphore; arguments forwarded unchanged.
    let r = unsafe {
        original::<unsafe extern "system" fn(HANDLE, i32, *mut i32) -> i32>(&RELEASE_SEMAPHORE)(
            handle, count, previous,
        )
    };
    if r != 0 && domain::det_wakes() {
        // SAFETY: reading and restoring this thread's last-error value.
        let saved = unsafe { GetLastError() };
        domain::det_wake(crate::DetKey::Addr(handle as usize), n);
        // SAFETY: as above.
        unsafe { SetLastError(saved) };
    }
    r
}

/// `SetConsoleCtrlHandler` (consoleapi.h): adds or removes a handler; a null handler sets or
/// clears the process's ignore-CTRL+C flag
/// ([Microsoft Learn: SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)).
/// With a domain table the change stays in the sim; the process's real handler list is untouched.
unsafe extern "system" fn set_console_ctrl_handler(handler: usize, add: i32) -> i32 {
    match domain::dispatch_signals(|table| table.set_console_ctrl_handler(handler, add != 0)) {
        Some(Ok(())) => return 1,
        Some(Err(code)) => {
            // SAFETY: setting this thread's last-error value.
            unsafe { SetLastError(code) };
            return 0;
        }
        None => {}
    }
    domain::observe("SetConsoleCtrlHandler", None);
    // SAFETY: SET_CONSOLE_CTRL_HANDLER holds kernel32's SetConsoleCtrlHandler.
    unsafe {
        original::<unsafe extern "system" fn(usize, i32) -> i32>(&SET_CONSOLE_CTRL_HANDLER)(
            handler, add,
        )
    }
}

/// `GenerateConsoleCtrlEvent` (consoleapi.h): only `CTRL_C_EVENT` (0) and `CTRL_BREAK_EVENT` (1)
/// may be generated. Group 0 is every process on the console, this one included; the sim
/// delivers only to this process. A group equal to this process's id is taken to be its own (true
/// when it is a group root, as after `CREATE_NEW_PROCESS_GROUP`; snare does not check). Delivery
/// is asynchronous: the handlers run on a new thread
/// ([Microsoft Learn: GenerateConsoleCtrlEvent](https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent);
/// [Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine)).
///
/// Any other event fails with `ERROR_INVALID_PARAMETER` (a snare choice of code: the page lists
/// the two valid values but not the error). A group naming another process is forwarded to the
/// OS, since the sim does not model other processes.
unsafe extern "system" fn generate_console_ctrl_event(event: u32, group: u32) -> i32 {
    // SAFETY: GetCurrentProcessId has no preconditions.
    let own = group == 0
        || group == unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
    let handled = domain::dispatch_signals(|table| {
        if event > 1 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        if !own {
            return Ok(false);
        }
        // CTRL+C cannot be generated for a nonzero process group: the call succeeds and no
        // process receives it (Microsoft Learn: GenerateConsoleCtrlEvent, CTRL_C_EVENT: "If
        // dwProcessGroupId is nonzero, this function will succeed, but the CTRL+C signal will not
        // be received").
        if event == 0 && group != 0 {
            return Ok(true);
        }
        table.console_event(event);
        Ok(true)
    });
    match handled {
        Some(Ok(true)) => return 1,
        Some(Err(code)) => {
            // SAFETY: setting this thread's last-error value.
            unsafe { SetLastError(code) };
            return 0;
        }
        _ => {}
    }
    domain::observe("GenerateConsoleCtrlEvent", None);
    // SAFETY: GENERATE_CONSOLE_CTRL_EVENT holds kernel32's GenerateConsoleCtrlEvent.
    unsafe {
        original::<unsafe extern "system" fn(u32, u32) -> i32>(&GENERATE_CONSOLE_CTRL_EVENT)(
            event, group,
        )
    }
}

/// The CRT signals a domain keeps its own handlers for (UCRT signal.h: SIGINT 2, SIGTERM 15,
/// SIGBREAK 21). The rest (`SIGABRT`, `SIGFPE`, `SIGILL`, `SIGSEGV`) report faults and stay with
/// the real CRT.
fn crt_virtual(sig: c_int) -> bool {
    matches!(sig, 2 | 15 | 21)
}

/// `signal` (UCRT): installs `handler` for `sig` and returns the previous one
/// ([Microsoft Learn: signal](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/signal)).
unsafe extern "C" fn crt_signal(sig: c_int, handler: usize) -> usize {
    if crt_virtual(sig)
        && let Some(previous) = domain::dispatch_signals(|table| table.crt_signal(sig, handler))
    {
        return previous;
    }
    // SAFETY: CRT_SIGNAL holds the CRT's signal.
    unsafe { original::<unsafe extern "C" fn(c_int, usize) -> usize>(&CRT_SIGNAL)(sig, handler) }
}

/// `raise` (UCRT): runs the handler for `sig` on the calling thread
/// ([Microsoft Learn: raise](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/raise)).
unsafe extern "C" fn crt_raise(sig: c_int) -> c_int {
    if crt_virtual(sig)
        && let Some(r) = domain::dispatch_signals(|table| table.crt_raise(sig))
    {
        return r;
    }
    // SAFETY: CRT_RAISE holds the CRT's raise.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&CRT_RAISE)(sig) }
}
