//! Which operating system's socket and system-call semantics snare emulates.
//!
//! [`OsSemantics`] defaults to the host, so nothing changes until a test
//! selects another OS with `set_os_semantics` (per state slot) or the
//! `SNARE_OS` environment variable (`linux`, `macos` or `windows`). Selecting an OS explicitly also turns on the *faithful* rows
//! of snare's emulation: ephemeral port ranges, bind conflicts, read-timeout
//! and would-block errors and the like follow that OS instead of snare's
//! historical behaviour.
//!
//! Errors snare builds for the selected OS carry that OS's error code. When
//! the selected OS is the host they are ordinary `io::Error::from_raw_os_error`
//! values; otherwise the code travels in a [`SimOsError`] payload. Read it
//! either way with [`os_error_code`]. `kind()` follows std's own mapping for
//! that OS, except that codes std leaves uncategorized (EMSGSIZE, ENOBUFS,
//! WSAEMSGSIZE, …) report [`io::ErrorKind::Other`] off-host, so assert those
//! through [`os_error_code`].

use std::fmt;
use std::io;
use std::ops::RangeInclusive;
use std::sync::LazyLock;

/// The operating system whose semantics snare emulates.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsSemantics {
    Linux,
    MacOs,
    Windows,
}

impl Default for OsSemantics {
    fn default() -> Self {
        Self::host()
    }
}

impl fmt::Display for OsSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OsSemantics::Linux => "linux",
            OsSemantics::MacOs => "macos",
            OsSemantics::Windows => "windows",
        })
    }
}

impl OsSemantics {
    /// The OS snare was compiled for. Anything that is neither macOS nor
    /// Windows is treated as Linux.
    pub const fn host() -> Self {
        if cfg!(target_os = "macos") {
            OsSemantics::MacOs
        } else if cfg!(windows) {
            OsSemantics::Windows
        } else {
            OsSemantics::Linux
        }
    }

    /// Parse `linux`, `macos`, `darwin` or `windows`, ignoring case.
    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "linux" => Some(OsSemantics::Linux),
            "macos" | "darwin" | "osx" => Some(OsSemantics::MacOs),
            "windows" | "win" => Some(OsSemantics::Windows),
            _ => None,
        }
    }

    /// The socket-level error code for `e`: errno on Linux and macOS,
    /// the Winsock code on Windows.
    pub fn errno(self, e: Errno) -> i32 {
        errno_row(e).code(self)
    }

    /// The [`io::ErrorKind`] std gives [`errno`](Self::errno) on this OS.
    pub fn error_kind(self, e: Errno) -> io::ErrorKind {
        errno_row(e).kind(self)
    }

    /// The system-level error code for `e`: errno on Linux and macOS, the
    /// Win32 error on Windows.
    pub fn sys_errno(self, e: SysErrno) -> i32 {
        sys_row(e).code(self)
    }

    /// The [`io::ErrorKind`] std gives [`sys_errno`](Self::sys_errno) on
    /// this OS.
    pub fn sys_error_kind(self, e: SysErrno) -> io::ErrorKind {
        sys_row(e).kind(self)
    }

    /// The range ephemeral ports are drawn from.
    pub fn ephemeral_ports(self) -> RangeInclusive<u16> {
        match self {
            OsSemantics::Linux => 32768..=60999,
            OsSemantics::MacOs | OsSemantics::Windows => 49152..=65535,
        }
    }

    /// The loopback interface's name.
    pub fn loopback_name(self) -> &'static str {
        match self {
            OsSemantics::Linux => "lo",
            OsSemantics::MacOs => "lo0",
            OsSemantics::Windows => "Loopback Pseudo-Interface 1",
        }
    }
}

/// Socket-level errors snare can report, named after their POSIX errno.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Errno {
    ConnRefused,
    ConnReset,
    ConnAborted,
    NetUnreach,
    HostUnreach,
    NetDown,
    AddrInUse,
    AddrNotAvail,
    WouldBlock,
    InProgress,
    TimedOut,
    MsgSize,
    Access,
    NoBufs,
    Inval,
    OpNotSupp,
    NoProtoOpt,
    NoDev,
    Pipe,
    NotConn,
    NoMem,
    AfNoSupport,
}

/// Thread, process, NIC and privilege errors snare can report, named after
/// their POSIX errno.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SysErrno {
    Perm,
    Access,
    Inval,
    NoMem,
    Srch,
    Busy,
    NotSupported,
    NoDev,
}

#[cfg(test)]
const ALL_ERRNOS: [Errno; 22] = [
    Errno::ConnRefused,
    Errno::ConnReset,
    Errno::ConnAborted,
    Errno::NetUnreach,
    Errno::HostUnreach,
    Errno::NetDown,
    Errno::AddrInUse,
    Errno::AddrNotAvail,
    Errno::WouldBlock,
    Errno::InProgress,
    Errno::TimedOut,
    Errno::MsgSize,
    Errno::Access,
    Errno::NoBufs,
    Errno::Inval,
    Errno::OpNotSupp,
    Errno::NoProtoOpt,
    Errno::NoDev,
    Errno::Pipe,
    Errno::NotConn,
    Errno::NoMem,
    Errno::AfNoSupport,
];

#[cfg(test)]
const ALL_SYS_ERRNOS: [SysErrno; 8] = [
    SysErrno::Perm,
    SysErrno::Access,
    SysErrno::Inval,
    SysErrno::NoMem,
    SysErrno::Srch,
    SysErrno::Busy,
    SysErrno::NotSupported,
    SysErrno::NoDev,
];

type Entry = (i32, &'static str, io::ErrorKind);

struct Row {
    linux: Entry,
    macos: Entry,
    windows: Entry,
}

impl Row {
    fn entry(&self, os: OsSemantics) -> Entry {
        match os {
            OsSemantics::Linux => self.linux,
            OsSemantics::MacOs => self.macos,
            OsSemantics::Windows => self.windows,
        }
    }

    fn code(&self, os: OsSemantics) -> i32 {
        self.entry(os).0
    }

    fn name(&self, os: OsSemantics) -> &'static str {
        self.entry(os).1
    }

    fn kind(&self, os: OsSemantics) -> io::ErrorKind {
        self.entry(os).2
    }
}

fn errno_row(e: Errno) -> Row {
    use io::ErrorKind as K;
    let same = |linux: Entry, macos: Entry, windows: Entry| Row {
        linux,
        macos,
        windows,
    };
    match e {
        Errno::ConnRefused => same(
            (111, "ECONNREFUSED", K::ConnectionRefused),
            (61, "ECONNREFUSED", K::ConnectionRefused),
            (10061, "WSAECONNREFUSED", K::ConnectionRefused),
        ),
        Errno::ConnReset => same(
            (104, "ECONNRESET", K::ConnectionReset),
            (54, "ECONNRESET", K::ConnectionReset),
            (10054, "WSAECONNRESET", K::ConnectionReset),
        ),
        Errno::ConnAborted => same(
            (103, "ECONNABORTED", K::ConnectionAborted),
            (53, "ECONNABORTED", K::ConnectionAborted),
            (10053, "WSAECONNABORTED", K::ConnectionAborted),
        ),
        Errno::NetUnreach => same(
            (101, "ENETUNREACH", K::NetworkUnreachable),
            (51, "ENETUNREACH", K::NetworkUnreachable),
            (10051, "WSAENETUNREACH", K::NetworkUnreachable),
        ),
        Errno::HostUnreach => same(
            (113, "EHOSTUNREACH", K::HostUnreachable),
            (65, "EHOSTUNREACH", K::HostUnreachable),
            (10065, "WSAEHOSTUNREACH", K::HostUnreachable),
        ),
        Errno::NetDown => same(
            (100, "ENETDOWN", K::NetworkDown),
            (50, "ENETDOWN", K::NetworkDown),
            (10050, "WSAENETDOWN", K::NetworkDown),
        ),
        Errno::AddrInUse => same(
            (98, "EADDRINUSE", K::AddrInUse),
            (48, "EADDRINUSE", K::AddrInUse),
            (10048, "WSAEADDRINUSE", K::AddrInUse),
        ),
        Errno::AddrNotAvail => same(
            (99, "EADDRNOTAVAIL", K::AddrNotAvailable),
            (49, "EADDRNOTAVAIL", K::AddrNotAvailable),
            (10049, "WSAEADDRNOTAVAIL", K::AddrNotAvailable),
        ),
        Errno::WouldBlock => same(
            (11, "EAGAIN", K::WouldBlock),
            (35, "EAGAIN", K::WouldBlock),
            (10035, "WSAEWOULDBLOCK", K::WouldBlock),
        ),
        Errno::InProgress => same(
            (115, "EINPROGRESS", K::Other),
            (36, "EINPROGRESS", K::Other),
            (10036, "WSAEINPROGRESS", K::Other),
        ),
        Errno::TimedOut => same(
            (110, "ETIMEDOUT", K::TimedOut),
            (60, "ETIMEDOUT", K::TimedOut),
            (10060, "WSAETIMEDOUT", K::TimedOut),
        ),
        Errno::MsgSize => same(
            (90, "EMSGSIZE", K::Other),
            (40, "EMSGSIZE", K::Other),
            (10040, "WSAEMSGSIZE", K::Other),
        ),
        Errno::Access => same(
            (13, "EACCES", K::PermissionDenied),
            (13, "EACCES", K::PermissionDenied),
            (10013, "WSAEACCES", K::PermissionDenied),
        ),
        Errno::NoBufs => same(
            (105, "ENOBUFS", K::Other),
            (55, "ENOBUFS", K::Other),
            (10055, "WSAENOBUFS", K::Other),
        ),
        Errno::Inval => same(
            (22, "EINVAL", K::InvalidInput),
            (22, "EINVAL", K::InvalidInput),
            (10022, "WSAEINVAL", K::InvalidInput),
        ),
        Errno::OpNotSupp => same(
            (95, "EOPNOTSUPP", K::Unsupported),
            (102, "EOPNOTSUPP", K::Unsupported),
            (10045, "WSAEOPNOTSUPP", K::Other),
        ),
        Errno::NoProtoOpt => same(
            (92, "ENOPROTOOPT", K::Other),
            (42, "ENOPROTOOPT", K::Other),
            (10042, "WSAENOPROTOOPT", K::Other),
        ),
        Errno::NoDev => same(
            (19, "ENODEV", K::Other),
            (19, "ENODEV", K::Other),
            (10022, "WSAEINVAL", K::InvalidInput),
        ),
        Errno::Pipe => same(
            (32, "EPIPE", K::BrokenPipe),
            (32, "EPIPE", K::BrokenPipe),
            (10058, "WSAESHUTDOWN", K::BrokenPipe),
        ),
        Errno::NotConn => same(
            (107, "ENOTCONN", K::NotConnected),
            (57, "ENOTCONN", K::NotConnected),
            (10057, "WSAENOTCONN", K::NotConnected),
        ),
        Errno::NoMem => same(
            (12, "ENOMEM", K::OutOfMemory),
            (12, "ENOMEM", K::OutOfMemory),
            (10055, "WSAENOBUFS", K::Other),
        ),
        Errno::AfNoSupport => same(
            (97, "EAFNOSUPPORT", K::Other),
            (47, "EAFNOSUPPORT", K::Other),
            (10047, "WSAEAFNOSUPPORT", K::Other),
        ),
    }
}

fn sys_row(e: SysErrno) -> Row {
    use io::ErrorKind as K;
    let same = |linux: Entry, macos: Entry, windows: Entry| Row {
        linux,
        macos,
        windows,
    };
    match e {
        SysErrno::Perm => same(
            (1, "EPERM", K::PermissionDenied),
            (1, "EPERM", K::PermissionDenied),
            (1314, "ERROR_PRIVILEGE_NOT_HELD", K::Other),
        ),
        SysErrno::Access => same(
            (13, "EACCES", K::PermissionDenied),
            (13, "EACCES", K::PermissionDenied),
            (5, "ERROR_ACCESS_DENIED", K::PermissionDenied),
        ),
        SysErrno::Inval => same(
            (22, "EINVAL", K::InvalidInput),
            (22, "EINVAL", K::InvalidInput),
            (87, "ERROR_INVALID_PARAMETER", K::InvalidInput),
        ),
        SysErrno::NoMem => same(
            (12, "ENOMEM", K::OutOfMemory),
            (12, "ENOMEM", K::OutOfMemory),
            (8, "ERROR_NOT_ENOUGH_MEMORY", K::OutOfMemory),
        ),
        SysErrno::Srch => same(
            (3, "ESRCH", K::Other),
            (3, "ESRCH", K::Other),
            (87, "ERROR_INVALID_PARAMETER", K::InvalidInput),
        ),
        SysErrno::Busy => same(
            (16, "EBUSY", K::ResourceBusy),
            (16, "EBUSY", K::ResourceBusy),
            (170, "ERROR_BUSY", K::ResourceBusy),
        ),
        SysErrno::NotSupported => same(
            (95, "EOPNOTSUPP", K::Unsupported),
            (45, "ENOTSUP", K::Other),
            (50, "ERROR_NOT_SUPPORTED", K::Other),
        ),
        SysErrno::NoDev => same(
            (19, "ENODEV", K::Other),
            (19, "ENODEV", K::Other),
            (1167, "ERROR_DEVICE_NOT_CONNECTED", K::Other),
        ),
    }
}

/// The payload of an error snare built for a simulated OS other than the
/// host. Read the code with [`os_error_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimOsError {
    pub os: OsSemantics,
    pub code: i32,
    pub name: &'static str,
}

impl fmt::Display for SimOsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (os error {}, simulated {})",
            self.name, self.code, self.os
        )
    }
}

impl std::error::Error for SimOsError {}

/// The OS error code carried by `e`: [`io::Error::raw_os_error`], or the
/// code of a [`SimOsError`] payload.
pub fn os_error_code(e: &io::Error) -> Option<i32> {
    e.raw_os_error().or_else(|| {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<SimOsError>())
            .map(|sim| sim.code)
    })
}

fn build(os: OsSemantics, row: Row) -> io::Error {
    if os == OsSemantics::host() {
        io::Error::from_raw_os_error(row.code(os))
    } else {
        io::Error::new(
            row.kind(os),
            SimOsError {
                os,
                code: row.code(os),
                name: row.name(os),
            },
        )
    }
}

/// The socket error `e` as `os` reports it.
#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn os_err_for(os: OsSemantics, e: Errno) -> io::Error {
    build(os, errno_row(e))
}

/// The system error `e` as `os` reports it.
#[allow(dead_code)]
pub(crate) fn sys_err_for(os: OsSemantics, e: SysErrno) -> io::Error {
    build(os, sys_row(e))
}

/// An error with OS code `code` of `os`, for codes outside [`Errno`] and
/// [`SysErrno`]. `kind` is what std decodes the code to on `os`.
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
pub(crate) fn code_err(
    os: OsSemantics,
    code: i32,
    name: &'static str,
    kind: io::ErrorKind,
) -> io::Error {
    if os == OsSemantics::host() {
        io::Error::from_raw_os_error(code)
    } else {
        io::Error::new(kind, SimOsError { os, code, name })
    }
}

/// The socket error `e` as the calling thread's selected OS reports it.
/// Must not be called with snare's state lock held.
#[allow(dead_code)]
pub(crate) fn os_err(e: Errno) -> io::Error {
    os_err_for(os_semantics(), e)
}

/// The system error `e` as the calling thread's selected OS reports it.
/// Must not be called with snare's state lock held.
#[allow(dead_code)]
pub(crate) fn sys_err(e: SysErrno) -> io::Error {
    sys_err_for(os_semantics(), e)
}

static ENV_OS: LazyLock<Option<OsSemantics>> =
    LazyLock::new(
        || match init_os_from(std::env::var("SNARE_OS").ok().as_deref()) {
            Ok(os) => os,
            Err(msg) => panic!("{msg}"),
        },
    );

/// Parse a `SNARE_OS` value. Unset or empty selects nothing.
pub(crate) fn init_os_from(value: Option<&str>) -> Result<Option<OsSemantics>, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) => OsSemantics::from_name(v).map(Some).ok_or_else(|| {
            format!("SNARE_OS={v:?} is not an OS snare emulates (linux, macos or windows)")
        }),
    }
}

/// Parse `SNARE_OS` now, so a bad value panics on the calling thread before
/// any snare lock is taken.
#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn force_env() {
    LazyLock::force(&ENV_OS);
}

/// The OS chosen through `SNARE_OS`, if any.
#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn env_os() -> Option<OsSemantics> {
    *ENV_OS
}

/// The OS the calling thread's state slot emulates: the value set with
/// `set_os_semantics`, else `SNARE_OS`, else the
/// host. Always the host without the `shim` feature.
pub fn os_semantics() -> OsSemantics {
    #[cfg(feature = "shim")]
    {
        try_os_semantics().unwrap_or_else(|| env_os().unwrap_or_default())
    }
    #[cfg(not(feature = "shim"))]
    {
        OsSemantics::host()
    }
}

/// Select the OS the calling thread's state slot emulates, and turn on its
/// faithful rows. Affects operations from now on: call it before creating
/// sockets. Re-derives the loopback interface's name and, unless
/// [`set_sys_limits`](crate::set_sys_limits) was called, the socket buffer
/// limits.
#[cfg(feature = "shim")]
pub fn set_os_semantics(os: OsSemantics) {
    crate::state::set_os(os);
}

/// Whether the calling thread's state slot chose its OS explicitly, through
/// [`set_os_semantics`] or `SNARE_OS`.
#[cfg(feature = "shim")]
pub fn os_semantics_explicit() -> bool {
    match crate::sched::try_slot() {
        Some(_) => crate::state::os_ctx().1,
        None => env_os().is_some(),
    }
}

/// The calling thread's selected OS, or `None` when it has no state slot.
/// Never waits for registration and never panics.
#[cfg(feature = "shim")]
pub(crate) fn try_os_semantics() -> Option<OsSemantics> {
    crate::sched::try_slot()?;
    Some(crate::state::os_ctx().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(kind: io::ErrorKind) -> String {
        let text = format!("{kind:?}");
        match text.as_str() {
            "Uncategorized" | "InProgress" => format!("{:?}", io::ErrorKind::Other),
            _ => text,
        }
    }

    #[test]
    fn host_kinds_match_std() {
        let host = OsSemantics::host();
        for e in ALL_ERRNOS {
            let std_kind = io::Error::from_raw_os_error(host.errno(e)).kind();
            assert_eq!(
                normalize(std_kind),
                format!("{:?}", host.error_kind(e)),
                "{e:?}"
            );
        }
        for e in ALL_SYS_ERRNOS {
            let std_kind = io::Error::from_raw_os_error(host.sys_errno(e)).kind();
            assert_eq!(
                normalize(std_kind),
                format!("{:?}", host.sys_error_kind(e)),
                "{e:?}"
            );
        }
    }

    #[test]
    fn host_errors_are_raw() {
        let host = OsSemantics::host();
        let e = os_err_for(host, Errno::ConnRefused);
        assert_eq!(e.raw_os_error(), Some(host.errno(Errno::ConnRefused)));
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn foreign_errors_carry_the_code() {
        let foreign = if OsSemantics::host() == OsSemantics::Windows {
            OsSemantics::Linux
        } else {
            OsSemantics::Windows
        };
        for e in ALL_ERRNOS {
            let err = os_err_for(foreign, e);
            assert_eq!(err.raw_os_error(), None);
            assert_eq!(os_error_code(&err), Some(foreign.errno(e)));
            assert_eq!(err.kind(), foreign.error_kind(e));
        }
        let err = sys_err_for(foreign, SysErrno::Perm);
        assert_eq!(os_error_code(&err), Some(foreign.sys_errno(SysErrno::Perm)));
        assert!(err.to_string().contains(&foreign.to_string()));
    }

    #[test]
    fn tables_differ_per_os() {
        assert_eq!(OsSemantics::Linux.errno(Errno::ConnReset), 104);
        assert_eq!(OsSemantics::MacOs.errno(Errno::ConnReset), 54);
        assert_eq!(OsSemantics::Windows.errno(Errno::ConnReset), 10054);
        assert_eq!(OsSemantics::Windows.sys_errno(SysErrno::Perm), 1314);
        assert_eq!(*OsSemantics::Linux.ephemeral_ports().start(), 32768);
        assert_eq!(*OsSemantics::Windows.ephemeral_ports().end(), 65535);
        assert_eq!(OsSemantics::MacOs.loopback_name(), "lo0");
    }

    #[test]
    fn init_os_from_parses() {
        assert_eq!(init_os_from(None), Ok(None));
        assert_eq!(init_os_from(Some("")), Ok(None));
        assert_eq!(init_os_from(Some("Linux")), Ok(Some(OsSemantics::Linux)));
        assert_eq!(init_os_from(Some("darwin")), Ok(Some(OsSemantics::MacOs)));
        assert_eq!(
            init_os_from(Some("WINDOWS")),
            Ok(Some(OsSemantics::Windows))
        );
        assert!(init_os_from(Some("plan9")).is_err());
    }
}
