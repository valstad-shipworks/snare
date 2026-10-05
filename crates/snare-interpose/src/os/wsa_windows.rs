//! The Winsock calls beyond the BSD-style core in `windows.rs`: the scatter/gather `WSASend`,
//! `WSARecv`, `WSASendTo` and `WSARecvFrom` (std's `write_vectored`/`read_vectored`), `WSASendMsg`
//! and the `WSARecvMsg`/`WSASendMsg` extension functions handed out through
//! `SIO_GET_EXTENSION_FUNCTION_POINTER`, and a guard on every other ws2_32 or mswsock export that
//! takes a `SOCKET`, so a sim socket never reaches Winsock.
//!
//! The backend serves the synchronous form of the message calls (no `WSAOVERLAPPED`, no
//! completion routine). Overlapped I/O on a sim socket, and the calls the sim does not model at
//! all (event and window-message notification, `WSAJoinLeaf`, `AcceptEx`, `TransmitFile`, ...),
//! fail with `WSAEOPNOTSUPP`: snare's choice of code, the one Microsoft gives for an operation
//! "not supported for the type of object referenced"
//! ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
//! A sim socket cannot complete an overlapped operation later: the sim has no event, completion
//! routine or completion port to signal. Any other socket goes to the OS unchanged.

use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Networking::WinSock::{
    MSG_PARTIAL, SIO_GET_EXTENSION_FUNCTION_POINTER, WSABUF, WSAEFAULT, WSAEINVAL, WSAEMSGSIZE,
    WSAEOPNOTSUPP, WSAID_ACCEPTEX, WSAID_CONNECTEX, WSAID_DISCONNECTEX, WSAID_GETACCEPTEXSOCKADDRS,
    WSAID_TRANSMITFILE, WSAID_TRANSMITPACKETS, WSAID_WSAPOLL, WSAID_WSARECVMSG, WSAID_WSASENDMSG,
    WSAMSG,
};
use windows_sys::core::GUID;

use super::windows::{
    Socket, finish_bool, finish_sock, finish_socket, on_sim, real_wsaioctl, sim_accept,
    sim_connect, sim_recv, sim_socket, ws_wsapoll, wsa_fail,
};
use crate::domain;
use crate::hooks::{Hook, hook, original};

static WS_WSASEND: AtomicUsize = AtomicUsize::new(0);
static WS_WSARECV: AtomicUsize = AtomicUsize::new(0);
static WS_WSASENDTO: AtomicUsize = AtomicUsize::new(0);
static WS_WSARECVFROM: AtomicUsize = AtomicUsize::new(0);
static WS_WSASENDMSG: AtomicUsize = AtomicUsize::new(0);
static WS_WSAACCEPT: AtomicUsize = AtomicUsize::new(0);
static WS_WSACONNECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSASENDDISCONNECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSARECVDISCONNECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSAEVENTSELECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSAASYNCSELECT: AtomicUsize = AtomicUsize::new(0);
static WS_WSAENUMNETWORKEVENTS: AtomicUsize = AtomicUsize::new(0);
static WS_WSAGETOVERLAPPEDRESULT: AtomicUsize = AtomicUsize::new(0);
static WS_WSADUPLICATESOCKETA: AtomicUsize = AtomicUsize::new(0);
static WS_WSASOCKETA: AtomicUsize = AtomicUsize::new(0);
static WS_WSAHTONL: AtomicUsize = AtomicUsize::new(0);
static WS_WSAHTONS: AtomicUsize = AtomicUsize::new(0);
static WS_WSANTOHL: AtomicUsize = AtomicUsize::new(0);
static WS_WSANTOHS: AtomicUsize = AtomicUsize::new(0);
static WS_WSAJOINLEAF: AtomicUsize = AtomicUsize::new(0);
static WS_WSACONNECTBYNAMEW: AtomicUsize = AtomicUsize::new(0);
static WS_WSACONNECTBYNAMEA: AtomicUsize = AtomicUsize::new(0);
static WS_WSACONNECTBYLIST: AtomicUsize = AtomicUsize::new(0);
static WS_WSAGETQOSBYNAME: AtomicUsize = AtomicUsize::new(0);
static MSW_WSARECVEX: AtomicUsize = AtomicUsize::new(0);
static MSW_ACCEPTEX: AtomicUsize = AtomicUsize::new(0);
static MSW_TRANSMITFILE: AtomicUsize = AtomicUsize::new(0);

/// The real `WSARecvMsg` and `WSASendMsg`, as Winsock last handed them out for a real socket;
/// 0 until then. One pointer per function: every socket the sim does not own is assumed to use
/// the one Microsoft TCP/IP provider.
static REAL_WSARECVMSG: AtomicUsize = AtomicUsize::new(0);
static REAL_WSASENDMSG: AtomicUsize = AtomicUsize::new(0);

/// The hooks of this module.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("WSASend", "ws2_32.dll", ws_wsasend, WS_WSASEND),
        hook!("WSARecv", "ws2_32.dll", ws_wsarecv, WS_WSARECV),
        hook!("WSASendTo", "ws2_32.dll", ws_wsasendto, WS_WSASENDTO),
        hook!("WSARecvFrom", "ws2_32.dll", ws_wsarecvfrom, WS_WSARECVFROM),
        hook!("WSASendMsg", "ws2_32.dll", ws_wsasendmsg, WS_WSASENDMSG),
        hook!("WSAAccept", "ws2_32.dll", ws_wsaaccept, WS_WSAACCEPT),
        hook!("WSAConnect", "ws2_32.dll", ws_wsaconnect, WS_WSACONNECT),
        hook!(
            "WSASendDisconnect",
            "ws2_32.dll",
            ws_wsasenddisconnect,
            WS_WSASENDDISCONNECT
        ),
        hook!(
            "WSARecvDisconnect",
            "ws2_32.dll",
            ws_wsarecvdisconnect,
            WS_WSARECVDISCONNECT
        ),
        hook!(
            "WSAEventSelect",
            "ws2_32.dll",
            ws_wsaeventselect,
            WS_WSAEVENTSELECT
        ),
        hook!(
            "WSAAsyncSelect",
            "ws2_32.dll",
            ws_wsaasyncselect,
            WS_WSAASYNCSELECT
        ),
        hook!(
            "WSAEnumNetworkEvents",
            "ws2_32.dll",
            ws_wsaenumnetworkevents,
            WS_WSAENUMNETWORKEVENTS
        ),
        hook!(
            "WSAGetOverlappedResult",
            "ws2_32.dll",
            ws_wsagetoverlappedresult,
            WS_WSAGETOVERLAPPEDRESULT
        ),
        hook!(
            "WSADuplicateSocketA",
            "ws2_32.dll",
            ws_wsaduplicatesocketa,
            WS_WSADUPLICATESOCKETA
        ),
        hook!("WSASocketA", "ws2_32.dll", ws_wsasocketa, WS_WSASOCKETA),
        hook!("WSAHtonl", "ws2_32.dll", ws_wsahtonl, WS_WSAHTONL),
        hook!("WSAHtons", "ws2_32.dll", ws_wsahtons, WS_WSAHTONS),
        hook!("WSANtohl", "ws2_32.dll", ws_wsantohl, WS_WSANTOHL),
        hook!("WSANtohs", "ws2_32.dll", ws_wsantohs, WS_WSANTOHS),
        hook!("WSAJoinLeaf", "ws2_32.dll", ws_wsajoinleaf, WS_WSAJOINLEAF),
        hook!(
            "WSAConnectByNameW",
            "ws2_32.dll",
            ws_wsaconnectbynamew,
            WS_WSACONNECTBYNAMEW
        ),
        hook!(
            "WSAConnectByNameA",
            "ws2_32.dll",
            ws_wsaconnectbynamea,
            WS_WSACONNECTBYNAMEA
        ),
        hook!(
            "WSAConnectByList",
            "ws2_32.dll",
            ws_wsaconnectbylist,
            WS_WSACONNECTBYLIST
        ),
        hook!(
            "WSAGetQOSByName",
            "ws2_32.dll",
            ws_wsagetqosbyname,
            WS_WSAGETQOSBYNAME
        ),
        hook!("WSARecvEx", "mswsock.dll", msw_wsarecvex, MSW_WSARECVEX),
        hook!("AcceptEx", "mswsock.dll", msw_acceptex, MSW_ACCEPTEX),
        hook!(
            "TransmitFile",
            "mswsock.dll",
            msw_transmitfile,
            MSW_TRANSMITFILE
        ),
    ]
}

/// Whether two GUIDs are the same.
fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// The GUID at `input`, if `input_len` holds one.
///
/// # Safety
/// `input` is null or points to `input_len` readable bytes.
unsafe fn read_guid(input: *const u8, input_len: u32) -> Option<GUID> {
    if input.is_null() || (input_len as usize) < size_of::<GUID>() {
        return None;
    }
    Some(unsafe { input.cast::<GUID>().read_unaligned() })
}

/// `SIO_GET_EXTENSION_FUNCTION_POINTER` on a sim socket
/// ([Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_get_extension_function_pointer-opcode-setting-o-i-t1)).
///
/// `WSAID_WSARECVMSG` and `WSAID_WSASENDMSG` give this module's own `WSARecvMsg` and
/// `WSASendMsg`, which serve sim sockets and forward any other to Winsock's; `WSAID_WSAPOLL` gives
/// the hooked `WSAPoll`. The other extensions Microsoft's provider lists — `AcceptEx`,
/// `ConnectEx`, `DisconnectEx`, `GetAcceptExSockaddrs`, `TransmitFile`, `TransmitPackets` — are
/// overlapped operations the sim cannot complete, so they are declined with `WSAEOPNOTSUPP`
/// ("the specified IOCTL command cannot be realized",
/// [Microsoft Learn: WSAIoctl](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl))
/// rather than handed out as functions that could only fail: a caller learns at once, as it would
/// from a provider without them. Any other GUID is `WSAEINVAL` ("a specified input parameter is
/// not acceptable"), and an input shorter than a GUID or an output shorter than a pointer is
/// `WSAEFAULT` (the same page: "the cbInBuffer or cbOutBuffer parameter is too small").
///
/// # Safety
/// The buffers are the caller's, as `WSAIoctl` documents them.
pub(crate) unsafe fn extension_pointer(
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
    returned: *mut u32,
) -> c_int {
    let Some(guid) = (unsafe { read_guid(input, input_len) }) else {
        return wsa_fail(WSAEFAULT);
    };
    if output.is_null() || (output_len as usize) < size_of::<usize>() {
        return wsa_fail(WSAEFAULT);
    }
    let function = if same_guid(&guid, &WSAID_WSARECVMSG) {
        ext_wsarecvmsg as *const () as usize
    } else if same_guid(&guid, &WSAID_WSASENDMSG) {
        ext_wsasendmsg as *const () as usize
    } else if same_guid(&guid, &WSAID_WSAPOLL) {
        ws_wsapoll as *const () as usize
    } else if [
        WSAID_ACCEPTEX,
        WSAID_CONNECTEX,
        WSAID_DISCONNECTEX,
        WSAID_GETACCEPTEXSOCKADDRS,
        WSAID_TRANSMITFILE,
        WSAID_TRANSMITPACKETS,
    ]
    .iter()
    .any(|known| same_guid(&guid, known))
    {
        return wsa_fail(WSAEOPNOTSUPP);
    } else {
        return wsa_fail(WSAEINVAL);
    };
    unsafe {
        output.cast::<usize>().write_unaligned(function);
        if !returned.is_null() {
            returned.write_unaligned(size_of::<usize>() as u32);
        }
    }
    0
}

/// After Winsock answered `SIO_GET_EXTENSION_FUNCTION_POINTER` for a real socket: a `WSARecvMsg`
/// or `WSASendMsg` pointer is kept and replaced by this module's own, so code that fetches the
/// pointer once and calls it on sim sockets too reaches the sim.
///
/// # Safety
/// The buffers are those of a `WSAIoctl` that succeeded.
pub(crate) unsafe fn wrap_real_extension(
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
) {
    let Some(guid) = (unsafe { read_guid(input, input_len) }) else {
        return;
    };
    if output.is_null() || (output_len as usize) < size_of::<usize>() {
        return;
    }
    let (slot, ours) = if same_guid(&guid, &WSAID_WSARECVMSG) {
        (&REAL_WSARECVMSG, ext_wsarecvmsg as *const () as usize)
    } else if same_guid(&guid, &WSAID_WSASENDMSG) {
        (&REAL_WSASENDMSG, ext_wsasendmsg as *const () as usize)
    } else {
        return;
    };
    let real = unsafe { output.cast::<usize>().read_unaligned() };
    if real != 0 && real != ours {
        slot.store(real, Ordering::Release);
        unsafe { output.cast::<usize>().write_unaligned(ours) };
    }
}

/// Winsock's own extension function `guid` for real socket `s`: the one kept in `slot`, else
/// fetched now through the real `WSAIoctl` on `s`.
fn real_extension(s: Socket, guid: &GUID, slot: &AtomicUsize) -> Option<usize> {
    let known = slot.load(Ordering::Acquire);
    if known != 0 {
        return Some(known);
    }
    let mut function = 0usize;
    let mut returned = 0u32;
    let rc = unsafe {
        real_wsaioctl(
            s,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (guid as *const GUID).cast(),
            size_of::<GUID>() as u32,
            (&raw mut function).cast(),
            size_of::<usize>() as u32,
            &mut returned,
        )
    }?;
    if rc != 0 || function == 0 {
        return None;
    }
    slot.store(function, Ordering::Release);
    Some(function)
}

/// `LPFN_WSARECVMSG`.
type WsaRecvMsg =
    unsafe extern "system" fn(Socket, *mut WSAMSG, *mut u32, *mut c_void, *mut c_void) -> c_int;
/// `WSASendMsg`.
type WsaSendMsg = unsafe extern "system" fn(
    Socket,
    *const WSAMSG,
    u32,
    *mut u32,
    *mut c_void,
    *mut c_void,
) -> c_int;

/// Fails an overlapped call on a sim socket; see the module docs.
fn overlapped(overlapped: *mut c_void, routine: *mut c_void) -> bool {
    !overlapped.is_null() || !routine.is_null()
}

/// A receive on sim socket `fd` through the backend's `wsa_recv`: `msg`'s buffers are filled and
/// `*received` gets the byte count, as `WSARecv`, `WSARecvFrom` and `WSARecvMsg` report it for a
/// call that completes at once. A null `received` is `WSAEFAULT`: Microsoft allows it only with
/// an overlapped call
/// ([Microsoft Learn: WSARecv](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv)).
///
/// # Safety
/// `msg` is the caller's `WSAMSG`; `received` is null or writable.
unsafe fn recv_msg(fd: c_int, msg: *mut WSAMSG, received: *mut u32, extension: bool) -> c_int {
    if received.is_null() {
        return wsa_fail(WSAEFAULT);
    }
    let r = on_sim(None, |net| unsafe {
        net.wsa_recv(fd, msg.cast(), extension)
    });
    if r < 0 {
        return finish_sock(r);
    }
    unsafe { received.write_unaligned(r as u32) };
    0
}

/// A send on sim socket `fd` through the backend's `wsa_send`, noted as an effect; `*sent` gets
/// the byte count. A null `sent` is `WSAEFAULT`, as for [`recv_msg`].
///
/// # Safety
/// `msg` is the caller's `WSAMSG`; `sent` is null or writable.
unsafe fn send_msg(
    fd: c_int,
    msg: *const WSAMSG,
    flags: u32,
    sent: *mut u32,
    extension: bool,
) -> c_int {
    if sent.is_null() {
        return wsa_fail(WSAEFAULT);
    }
    let r = on_sim(Some("send"), |net| unsafe {
        net.wsa_send(fd, msg.cast(), flags, extension)
    });
    if r < 0 {
        return finish_sock(r);
    }
    unsafe { sent.write_unaligned(r as u32) };
    0
}

/// A `WSAMSG` over the caller's buffers with no control data, as the plain `WSA*` calls carry
/// them.
fn plain_msg(
    name: *mut c_void,
    namelen: c_int,
    buffers: *mut WSABUF,
    count: u32,
    flags: u32,
) -> WSAMSG {
    WSAMSG {
        name: name.cast(),
        namelen,
        lpBuffers: buffers,
        dwBufferCount: count,
        Control: WSABUF {
            len: 0,
            buf: ptr::null_mut(),
        },
        dwFlags: flags,
    }
}

/// `WSARecv` ([Microsoft Learn: WSARecv](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv)):
/// on a sim socket the flags in `*flags` apply as for `recv`, and `*flags` is written back with
/// `MSG_PARTIAL` clear, the sim never handing out part of a message.
unsafe extern "system" fn ws_wsarecv(
    s: Socket,
    buffers: *mut WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if overlapped(ov, routine) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        if flags.is_null() {
            return wsa_fail(WSAEFAULT);
        }
        let mut msg = plain_msg(ptr::null_mut(), 0, buffers, count, unsafe { *flags });
        let rc = unsafe { recv_msg(fd, &mut msg, received, false) };
        if rc == 0 {
            unsafe { *flags = msg.dwFlags & !MSG_PARTIAL };
        }
        return rc;
    }
    domain::observe("WSARecv", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut WSABUF,
                u32,
                *mut u32,
                *mut u32,
                *mut c_void,
                *mut c_void,
            ) -> c_int,
        >(&WS_WSARECV)(s, buffers, count, received, flags, ov, routine)
    }
}

/// `WSARecvFrom` ([Microsoft Learn: WSARecvFrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvfrom)):
/// as [`ws_wsarecv`], with the source written to `from` when `from` and `fromlen` are both given.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsarecvfrom(
    s: Socket,
    buffers: *mut WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    from: *mut c_void,
    fromlen: *mut c_int,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if overlapped(ov, routine) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        if flags.is_null() {
            return wsa_fail(WSAEFAULT);
        }
        let (name, namelen) = if from.is_null() || fromlen.is_null() {
            (ptr::null_mut(), 0)
        } else {
            (from, unsafe { *fromlen })
        };
        let mut msg = plain_msg(name, namelen, buffers, count, unsafe { *flags });
        let rc = unsafe { recv_msg(fd, &mut msg, received, false) };
        if !name.is_null() {
            unsafe { *fromlen = msg.namelen };
        }
        if rc == 0 {
            unsafe { *flags = msg.dwFlags & !MSG_PARTIAL };
        }
        return rc;
    }
    domain::observe("WSARecvFrom", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut WSABUF,
                u32,
                *mut u32,
                *mut u32,
                *mut c_void,
                *mut c_int,
                *mut c_void,
                *mut c_void,
            ) -> c_int,
        >(&WS_WSARECVFROM)(
            s, buffers, count, received, flags, from, fromlen, ov, routine,
        )
    }
}

/// `WSASend` ([Microsoft Learn: WSASend](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend)):
/// the buffers gathered in order and sent as one `send`.
unsafe extern "system" fn ws_wsasend(
    s: Socket,
    buffers: *mut WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if overlapped(ov, routine) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        let msg = plain_msg(ptr::null_mut(), 0, buffers, count, 0);
        return unsafe { send_msg(fd, &msg, flags, sent, false) };
    }
    domain::observe("WSASend", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut WSABUF,
                u32,
                *mut u32,
                u32,
                *mut c_void,
                *mut c_void,
            ) -> c_int,
        >(&WS_WSASEND)(s, buffers, count, sent, flags, ov, routine)
    }
}

/// `WSASendTo` ([Microsoft Learn: WSASendTo](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto)):
/// as [`ws_wsasend`] to `to`, or to the connected peer when `to` is null.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsasendto(
    s: Socket,
    buffers: *mut WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    to: *const c_void,
    tolen: c_int,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if overlapped(ov, routine) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        let (name, namelen) = if to.is_null() {
            (ptr::null_mut(), 0)
        } else {
            (to.cast_mut(), tolen)
        };
        let msg = plain_msg(name, namelen, buffers, count, 0);
        return unsafe { send_msg(fd, &msg, flags, sent, false) };
    }
    domain::observe("WSASendTo", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut WSABUF,
                u32,
                *mut u32,
                u32,
                *const c_void,
                c_int,
                *mut c_void,
                *mut c_void,
            ) -> c_int,
        >(&WS_WSASENDTO)(s, buffers, count, sent, flags, to, tolen, ov, routine)
    }
}

/// `WSASendMsg`, which ws2_32 exports
/// ([Microsoft Learn: WSASendMsg](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)).
unsafe extern "system" fn ws_wsasendmsg(
    s: Socket,
    msg: *const WSAMSG,
    flags: u32,
    sent: *mut u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe { sim_sendmsg(fd, msg, flags, sent, ov, routine) };
    }
    domain::observe("WSASendMsg", None);
    unsafe { original::<WsaSendMsg>(&WS_WSASENDMSG)(s, msg, flags, sent, ov, routine) }
}

/// `WSASendMsg` on sim socket `fd`: a null `msg` is `WSAEFAULT`.
///
/// # Safety
/// As `WSASendMsg`.
unsafe fn sim_sendmsg(
    fd: c_int,
    msg: *const WSAMSG,
    flags: u32,
    sent: *mut u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if overlapped(ov, routine) {
        return wsa_fail(WSAEOPNOTSUPP);
    }
    if msg.is_null() {
        return wsa_fail(WSAEFAULT);
    }
    unsafe { send_msg(fd, msg, flags, sent, true) }
}

/// The `WSARecvMsg` extension function handed out for every socket
/// ([Microsoft Learn: LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)):
/// a sim socket is served by the backend, any other by Winsock's own `WSARecvMsg`; if that cannot
/// be found the call fails with `WSAEOPNOTSUPP`.
unsafe extern "system" fn ext_wsarecvmsg(
    s: Socket,
    msg: *mut WSAMSG,
    received: *mut u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if overlapped(ov, routine) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        if msg.is_null() {
            return wsa_fail(WSAEFAULT);
        }
        return unsafe { recv_msg(fd, msg, received, true) };
    }
    domain::observe("WSARecvMsg", None);
    match real_extension(s, &WSAID_WSARECVMSG, &REAL_WSARECVMSG) {
        Some(real) => unsafe {
            std::mem::transmute::<usize, WsaRecvMsg>(real)(s, msg, received, ov, routine)
        },
        None => wsa_fail(WSAEOPNOTSUPP),
    }
}

/// The `WSASendMsg` extension function handed out for every socket: the same function ws2_32
/// exports, reached through Winsock's pointer for a socket that is not the sim's.
unsafe extern "system" fn ext_wsasendmsg(
    s: Socket,
    msg: *const WSAMSG,
    flags: u32,
    sent: *mut u32,
    ov: *mut c_void,
    routine: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        return unsafe { sim_sendmsg(fd, msg, flags, sent, ov, routine) };
    }
    domain::observe("WSASendMsg", None);
    match real_extension(s, &WSAID_WSASENDMSG, &REAL_WSASENDMSG) {
        Some(real) => unsafe {
            std::mem::transmute::<usize, WsaSendMsg>(real)(s, msg, flags, sent, ov, routine)
        },
        None => wsa_fail(WSAEOPNOTSUPP),
    }
}

/// `WSAAccept` ([Microsoft Learn: WSAAccept](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaaccept)):
/// without a condition function it is `accept`; a condition function, which decides on each
/// connection before it is accepted, is not modelled.
unsafe extern "system" fn ws_wsaaccept(
    s: Socket,
    addr: *mut c_void,
    addrlen: *mut c_int,
    condition: *mut c_void,
    data: usize,
) -> Socket {
    if let Some(fd) = sim_socket(s) {
        if !condition.is_null() {
            return finish_socket(-i64::from(WSAEOPNOTSUPP));
        }
        return unsafe { sim_accept(fd, addr, addrlen) };
    }
    domain::observe("WSAAccept", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut c_void,
                *mut c_int,
                *mut c_void,
                usize,
            ) -> Socket,
        >(&WS_WSAACCEPT)(s, addr, addrlen, condition, data)
    }
}

/// `WSAConnect` ([Microsoft Learn: WSAConnect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect)):
/// without connect data or QoS it is `connect`; those, which TCP/IP does not carry, are not
/// modelled.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsaconnect(
    s: Socket,
    name: *const c_void,
    namelen: c_int,
    caller: *mut c_void,
    callee: *mut c_void,
    sqos: *mut c_void,
    gqos: *mut c_void,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if [caller, callee, sqos, gqos].iter().any(|p| !p.is_null()) {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        return unsafe { sim_connect(fd, name, namelen) };
    }
    domain::observe("WSAConnect", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *const c_void,
                c_int,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> c_int,
        >(&WS_WSACONNECT)(s, name, namelen, caller, callee, sqos, gqos)
    }
}

/// `SD_RECEIVE` and `SD_SEND` (`winsock2.h`).
const SD_RECEIVE: c_int = 0;
const SD_SEND: c_int = 1;

/// `WSASendDisconnect` ([Microsoft Learn: WSASendDisconnect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasenddisconnect)):
/// without disconnect data, which TCP/IP does not carry, it is `shutdown(SD_SEND)`.
unsafe extern "system" fn ws_wsasenddisconnect(s: Socket, data: *mut c_void) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if !data.is_null() {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        return finish_sock(on_sim(Some("shutdown"), |net| unsafe {
            net.shutdown(fd, SD_SEND)
        }));
    }
    domain::observe("WSASendDisconnect", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void) -> c_int>(&WS_WSASENDDISCONNECT)(
            s, data,
        )
    }
}

/// `WSARecvDisconnect` ([Microsoft Learn: WSARecvDisconnect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvdisconnect)):
/// without disconnect data it is `shutdown(SD_RECEIVE)`.
unsafe extern "system" fn ws_wsarecvdisconnect(s: Socket, data: *mut c_void) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if !data.is_null() {
            return wsa_fail(WSAEOPNOTSUPP);
        }
        return finish_sock(on_sim(Some("shutdown"), |net| unsafe {
            net.shutdown(fd, SD_RECEIVE)
        }));
    }
    domain::observe("WSARecvDisconnect", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void) -> c_int>(&WS_WSARECVDISCONNECT)(
            s, data,
        )
    }
}

/// `WSAEventSelect` ([Microsoft Learn: WSAEventSelect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaeventselect)):
/// the sim signals no event objects, so a sim socket refuses it.
unsafe extern "system" fn ws_wsaeventselect(s: Socket, event: *mut c_void, events: i32) -> c_int {
    if sim_socket(s).is_some() {
        return wsa_fail(WSAEOPNOTSUPP);
    }
    domain::observe("WSAEventSelect", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, i32) -> c_int>(&WS_WSAEVENTSELECT)(
            s, event, events,
        )
    }
}

/// `WSAAsyncSelect` ([Microsoft Learn: WSAAsyncSelect](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsaasyncselect)):
/// the sim posts no window messages, so a sim socket refuses it.
unsafe extern "system" fn ws_wsaasyncselect(
    s: Socket,
    window: *mut c_void,
    message: u32,
    events: i32,
) -> c_int {
    if sim_socket(s).is_some() {
        return wsa_fail(WSAEOPNOTSUPP);
    }
    domain::observe("WSAAsyncSelect", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, u32, i32) -> c_int>(
            &WS_WSAASYNCSELECT,
        )(s, window, message, events)
    }
}

/// `WSAEnumNetworkEvents` ([Microsoft Learn: WSAEnumNetworkEvents](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaenumnetworkevents)):
/// refused on a sim socket, which never has `WSAEventSelect` events.
unsafe extern "system" fn ws_wsaenumnetworkevents(
    s: Socket,
    event: *mut c_void,
    out: *mut c_void,
) -> c_int {
    if sim_socket(s).is_some() {
        return wsa_fail(WSAEOPNOTSUPP);
    }
    domain::observe("WSAEnumNetworkEvents", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_void) -> c_int>(
            &WS_WSAENUMNETWORKEVENTS,
        )(s, event, out)
    }
}

/// `WSAGetOverlappedResult` ([Microsoft Learn: WSAGetOverlappedResult](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsagetoverlappedresult)):
/// a sim socket never started an overlapped operation, so the `WSAOVERLAPPED` names none of its
/// own; `FALSE` with `WSAEINVAL`, snare's choice among the page's codes.
unsafe extern "system" fn ws_wsagetoverlappedresult(
    s: Socket,
    ov: *mut c_void,
    transferred: *mut u32,
    wait: i32,
    flags: *mut u32,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEINVAL));
    }
    domain::observe("WSAGetOverlappedResult", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut u32, i32, *mut u32) -> i32>(
            &WS_WSAGETOVERLAPPEDRESULT,
        )(s, ov, transferred, wait, flags)
    }
}

/// `WSADuplicateSocketA`, the ANSI form of `WSADuplicateSocketW`, served the same way
/// ([Microsoft Learn: WSADuplicateSocketA](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketa)).
unsafe extern "system" fn ws_wsaduplicatesocketa(s: Socket, pid: u32, info: *mut c_void) -> c_int {
    if let Some(r) = unsafe { super::windows::duplicate(s, info) } {
        return r;
    }
    domain::observe("WSADuplicateSocketA", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, u32, *mut c_void) -> c_int>(
            &WS_WSADUPLICATESOCKETA,
        )(s, pid, info)
    }
}

/// `WSASocketA`, the ANSI form of `WSASocketW`, served the same way
/// ([Microsoft Learn: WSASocketA](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa)).
unsafe extern "system" fn ws_wsasocketa(
    af: c_int,
    ty: c_int,
    proto: c_int,
    info: *mut c_void,
    group: u32,
    flags: u32,
) -> Socket {
    if let Some(dup) = unsafe { super::windows::tagged_duplicate(info) } {
        return dup;
    }
    if let Some(r) = domain::dispatch_net(|net| unsafe { net.socket(af, ty, proto) }) {
        return finish_socket(r);
    }
    domain::observe("WSASocketA", None);
    unsafe {
        original::<unsafe extern "system" fn(c_int, c_int, c_int, *mut c_void, u32, u32) -> Socket>(
            &WS_WSASOCKETA,
        )(af, ty, proto, info, group, flags)
    }
}

/// `WSAHtonl`/`WSANtohl` on a sim socket: the byte swap itself, which TCP/IP's network order
/// (big-endian) makes on a little-endian Windows; a null output is `WSAEFAULT`
/// ([Microsoft Learn: WSAHtonl](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsahtonl)).
fn swap_u32(value: u32, out: *mut u32) -> c_int {
    if out.is_null() {
        return wsa_fail(WSAEFAULT);
    }
    unsafe { out.write_unaligned(value.swap_bytes()) };
    0
}

/// As [`swap_u32`] for a `u_short`
/// ([Microsoft Learn: WSAHtons](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsahtons)).
fn swap_u16(value: u16, out: *mut u16) -> c_int {
    if out.is_null() {
        return wsa_fail(WSAEFAULT);
    }
    unsafe { out.write_unaligned(value.swap_bytes()) };
    0
}

/// `WSAHtonl`.
unsafe extern "system" fn ws_wsahtonl(s: Socket, value: u32, out: *mut u32) -> c_int {
    if sim_socket(s).is_some() {
        return swap_u32(value, out);
    }
    unsafe {
        original::<unsafe extern "system" fn(Socket, u32, *mut u32) -> c_int>(&WS_WSAHTONL)(
            s, value, out,
        )
    }
}

/// `WSANtohl` ([Microsoft Learn: WSANtohl](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsantohl)).
unsafe extern "system" fn ws_wsantohl(s: Socket, value: u32, out: *mut u32) -> c_int {
    if sim_socket(s).is_some() {
        return swap_u32(value, out);
    }
    unsafe {
        original::<unsafe extern "system" fn(Socket, u32, *mut u32) -> c_int>(&WS_WSANTOHL)(
            s, value, out,
        )
    }
}

/// `WSAHtons`.
unsafe extern "system" fn ws_wsahtons(s: Socket, value: u16, out: *mut u16) -> c_int {
    if sim_socket(s).is_some() {
        return swap_u16(value, out);
    }
    unsafe {
        original::<unsafe extern "system" fn(Socket, u16, *mut u16) -> c_int>(&WS_WSAHTONS)(
            s, value, out,
        )
    }
}

/// `WSANtohs` ([Microsoft Learn: WSANtohs](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsantohs)).
unsafe extern "system" fn ws_wsantohs(s: Socket, value: u16, out: *mut u16) -> c_int {
    if sim_socket(s).is_some() {
        return swap_u16(value, out);
    }
    unsafe {
        original::<unsafe extern "system" fn(Socket, u16, *mut u16) -> c_int>(&WS_WSANTOHS)(
            s, value, out,
        )
    }
}

/// `WSAJoinLeaf` ([Microsoft Learn: WSAJoinLeaf](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsajoinleaf)):
/// multipoint sessions are not modelled.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsajoinleaf(
    s: Socket,
    name: *const c_void,
    namelen: c_int,
    caller: *mut c_void,
    callee: *mut c_void,
    sqos: *mut c_void,
    gqos: *mut c_void,
    flags: u32,
) -> Socket {
    if sim_socket(s).is_some() {
        return finish_socket(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("WSAJoinLeaf", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *const c_void,
                c_int,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                u32,
            ) -> Socket,
        >(&WS_WSAJOINLEAF)(s, name, namelen, caller, callee, sqos, gqos, flags)
    }
}

/// `WSAConnectByNameW`/`WSAConnectByNameA`'s nine arguments.
type ConnectByName = unsafe extern "system" fn(
    Socket,
    *const c_void,
    *const c_void,
    *mut u32,
    *mut c_void,
    *mut u32,
    *mut c_void,
    *const c_void,
    *mut c_void,
) -> i32;

/// `WSAConnectByNameW` ([Microsoft Learn: WSAConnectByNameW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnectbynamew)):
/// not modelled on a sim socket; `FALSE` with `WSAEOPNOTSUPP`.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsaconnectbynamew(
    s: Socket,
    node: *const c_void,
    service: *const c_void,
    local_len: *mut u32,
    local: *mut c_void,
    remote_len: *mut u32,
    remote: *mut c_void,
    timeout: *const c_void,
    reserved: *mut c_void,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("WSAConnectByNameW", None);
    unsafe {
        original::<ConnectByName>(&WS_WSACONNECTBYNAMEW)(
            s, node, service, local_len, local, remote_len, remote, timeout, reserved,
        )
    }
}

/// `WSAConnectByNameA`, as [`ws_wsaconnectbynamew`].
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsaconnectbynamea(
    s: Socket,
    node: *const c_void,
    service: *const c_void,
    local_len: *mut u32,
    local: *mut c_void,
    remote_len: *mut u32,
    remote: *mut c_void,
    timeout: *const c_void,
    reserved: *mut c_void,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("WSAConnectByNameA", None);
    unsafe {
        original::<ConnectByName>(&WS_WSACONNECTBYNAMEA)(
            s, node, service, local_len, local, remote_len, remote, timeout, reserved,
        )
    }
}

/// `WSAConnectByList` ([Microsoft Learn: WSAConnectByList](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnectbylist)):
/// not modelled on a sim socket; `FALSE` with `WSAEOPNOTSUPP`.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn ws_wsaconnectbylist(
    s: Socket,
    list: *mut c_void,
    local_len: *mut u32,
    local: *mut c_void,
    remote_len: *mut u32,
    remote: *mut c_void,
    timeout: *const c_void,
    reserved: *mut c_void,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("WSAConnectByList", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut c_void,
                *mut u32,
                *mut c_void,
                *mut u32,
                *mut c_void,
                *const c_void,
                *mut c_void,
            ) -> i32,
        >(&WS_WSACONNECTBYLIST)(
            s, list, local_len, local, remote_len, remote, timeout, reserved,
        )
    }
}

/// `WSAGetQOSByName` ([Microsoft Learn: WSAGetQOSByName](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsagetqosbyname)):
/// QoS templates are not modelled; `FALSE` with `WSAEOPNOTSUPP` on a sim socket.
unsafe extern "system" fn ws_wsagetqosbyname(
    s: Socket,
    name: *mut c_void,
    qos: *mut c_void,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("WSAGetQOSByName", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut c_void, *mut c_void) -> i32>(
            &WS_WSAGETQOSBYNAME,
        )(s, name, qos)
    }
}

/// mswsock's `WSARecvEx` ([Microsoft Learn: WSARecvEx](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-wsarecvex)):
/// `recv` with no flags (`*flags` is ignored on input) that reports a datagram cut to the buffer
/// by setting `MSG_PARTIAL` in `*flags` instead of failing with `WSAEMSGSIZE`; a whole message,
/// or any stream read, clears it. The rest of a cut UDP datagram is lost, as `recv` loses it.
/// A null `flags` is `WSAEFAULT`.
unsafe extern "system" fn msw_wsarecvex(
    s: Socket,
    buf: *mut u8,
    len: c_int,
    flags: *mut c_int,
) -> c_int {
    if let Some(fd) = sim_socket(s) {
        if flags.is_null() {
            return wsa_fail(WSAEFAULT);
        }
        let r = unsafe { sim_recv(fd, buf, len, 0) };
        if r == -i64::from(WSAEMSGSIZE) {
            unsafe { *flags = MSG_PARTIAL as c_int };
            return len.max(0);
        }
        if r >= 0 {
            unsafe { *flags = 0 };
        }
        return finish_sock(r);
    }
    domain::observe("WSARecvEx", None);
    unsafe {
        original::<unsafe extern "system" fn(Socket, *mut u8, c_int, *mut c_int) -> c_int>(
            &MSW_WSARECVEX,
        )(s, buf, len, flags)
    }
}

/// mswsock's `AcceptEx` ([Microsoft Learn: AcceptEx](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-acceptex)):
/// an overlapped accept the sim cannot complete; `FALSE` with `WSAEOPNOTSUPP` when either socket
/// is the sim's.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn msw_acceptex(
    listener: Socket,
    accepted: Socket,
    buf: *mut c_void,
    recv_len: u32,
    local_len: u32,
    remote_len: u32,
    received: *mut u32,
    ov: *mut c_void,
) -> i32 {
    if sim_socket(listener).is_some() || sim_socket(accepted).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("AcceptEx", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                Socket,
                *mut c_void,
                u32,
                u32,
                u32,
                *mut u32,
                *mut c_void,
            ) -> i32,
        >(&MSW_ACCEPTEX)(
            listener, accepted, buf, recv_len, local_len, remote_len, received, ov,
        )
    }
}

/// mswsock's `TransmitFile` ([Microsoft Learn: TransmitFile](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-transmitfile)):
/// not modelled; `FALSE` with `WSAEOPNOTSUPP` on a sim socket.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn msw_transmitfile(
    s: Socket,
    file: *mut c_void,
    bytes: u32,
    per_send: u32,
    ov: *mut c_void,
    buffers: *mut c_void,
    flags: u32,
) -> i32 {
    if sim_socket(s).is_some() {
        return finish_bool(-i64::from(WSAEOPNOTSUPP));
    }
    domain::observe("TransmitFile", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                Socket,
                *mut c_void,
                u32,
                u32,
                *mut c_void,
                *mut c_void,
                u32,
            ) -> i32,
        >(&MSW_TRANSMITFILE)(s, file, bytes, per_send, ov, buffers, flags)
    }
}
