//! Kernel packet timestamps on the unix backends' sockets: the receive stamps a socket asks for
//! with `SO_TIMESTAMP`-style options and reads back as control messages, and the transmit stamps
//! Linux queues on the socket error queue. The [`Fabric`](crate::fabric::Fabric) and the Linux
//! `SimHost` both keep a socket's timestamping state in its [`SockRec`](crate::sockets::SockRec)
//! ([`TsState`]) and build their control messages here, so the two agree. Windows (`WinNet`) does
//! not model timestamping yet.
//!
//! A packet is stamped from the sim's clock at the moment it reaches the receiving socket: its
//! send time plus the link delay it crossed ([`Stamp::later`]), which is when a real kernel takes
//! its software receive stamp (Documentation/networking/timestamping.rst, "SOF_TIMESTAMPING_RX_SOFTWARE:
//! Request rx timestamps when data enters the kernel"). A transmit stamp is the send time.
//! Every option reports `CLOCK_REALTIME` (man 7 socket, `SO_TIMESTAMP`; timestamping.rst
//! "SO_TIMESTAMPING ... the timestamps are in CLOCK_REALTIME"), except macOS
//! `SO_TIMESTAMP_MONOTONIC`/`SO_TIMESTAMP_CONTINUOUS` (Mach absolute and continuous time), which
//! report the sim's monotonic clock in the units the code under test reads it in.
//!
//! What each host reports, and the cases measured against it, is pinned by tests/timestamps.rs.
//!
//! Locking: option and report access takes the record's `state` lock, so callers hold no other
//! lock of the record and may hold their backend's. Clock reads here do not advance time or run
//! callbacks.

use std::collections::VecDeque;
use std::ffi::c_int;
use std::time::Duration;

use crate::readiness::Deadline;
use crate::scope::SimShared;
use crate::sockets::SockRec;

#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct RxStartup {
    delay: std::sync::OnceLock<Duration>,
    active_at: std::sync::OnceLock<Duration>,
}

#[cfg(target_os = "linux")]
impl RxStartup {
    pub(crate) fn set_delay(&self, delay: Duration) {
        self.delay
            .set(delay)
            .expect("timestamp startup configured once");
    }

    fn enable(&self, shared: &SimShared) {
        let delay = self.delay.get().copied().unwrap_or_default();
        if !delay.is_zero() {
            self.active_at
                .get_or_init(|| shared.tstamp_now().real.saturating_add(delay));
        }
    }

    fn stamps(&self, at: Duration) -> bool {
        self.delay.get().is_none_or(Duration::is_zero)
            || self.active_at.get().is_some_and(|active| at >= *active)
    }
}

/// When a packet reached (or left) a socket, on the sim's clocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stamp {
    /// `CLOCK_REALTIME`, since the Unix epoch.
    pub(crate) real: Duration,
    /// The monotonic clock the code under test reads (`CLOCK_MONOTONIC`, `mach_absolute_time`),
    /// in nanoseconds since its zero.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) mono: Duration,
    /// The raw hardware stamp, on the PTP hardware clock of the NIC that stamped the packet, when
    /// one did (a Linux `SimHost` NIC with hardware timestamping configured); reported in
    /// `scm_timestamping.ts[2]`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) hw: Option<Duration>,
}

impl Stamp {
    /// A stamp known only by its `CLOCK_REALTIME` reading (a `SimHost` datagram's), which is all
    /// Linux reports.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_real(real: Duration) -> Self {
        Stamp {
            real,
            mono: Duration::ZERO,
            hw: None,
        }
    }

    /// A stamp taken only by a NIC's hardware, `hw` on its clock: what a hardware transmit
    /// report carries, whose software slot stays empty.
    #[cfg(target_os = "linux")]
    pub(crate) fn hardware(hw: Duration) -> Self {
        Stamp {
            real: Duration::ZERO,
            mono: Duration::ZERO,
            hw: Some(hw),
        }
    }

    /// The stamp `delay` later on both clocks: when something sent at `self` arrives after a
    /// link delay.
    pub(crate) fn later(self, delay: Duration) -> Self {
        Stamp {
            real: self.real.saturating_add(delay),
            mono: self.mono.saturating_add(delay),
            hw: None,
        }
    }
}

impl SimShared {
    /// The sim's clocks now, read without ticking: on a virtual clock its monotonic reading (an
    /// open executive timestamp's time included, as the code under test reads it) and
    /// `CLOCK_REALTIME` at that reading; on a plain unix sim on the real clock, the real clocks.
    pub(crate) fn tstamp_now(&self) -> Stamp {
        match &self.clock {
            Some(clock) => {
                let mono = Duration::from_nanos(clock.monotonic());
                Stamp {
                    real: clock.base_realtime() + mono,
                    mono,
                    hw: None,
                }
            }
            None => snare_interpose::real(real_clocks),
        }
    }

    /// A stamp is being handed to the code under test: a clock that jumps (as-fast-as-possible)
    /// is moved up to it, so no clock read after the receive is earlier than its stamp.
    pub(crate) fn reach_stamp(&self, stamp: Stamp) {
        if let Some(clock) = &self.clock {
            clock.reach_realtime(stamp.real);
        }
    }
}

/// The real clocks, for a sim with no virtual clock: `CLOCK_REALTIME`, and the host's monotonic
/// counter as nanoseconds (Mach absolute time on macOS; unused on Linux).
fn real_clocks() -> Stamp {
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    #[cfg(target_os = "macos")]
    let mono = {
        // SAFETY: mach_absolute_time reads a counter; it is not hooked inside `real`.
        let ticks = unsafe { mac::mach_absolute_time() };
        mac::ticks_to_nanos(ticks)
    };
    #[cfg(not(target_os = "macos"))]
    let mono = Duration::ZERO;
    Stamp {
        real,
        mono,
        hw: None,
    }
}

/// A transmit timestamp waiting to be read: a Linux error-queue entry.
pub(crate) struct TxReport {
    #[cfg(target_os = "linux")]
    pub(crate) charge: usize,
    #[cfg(target_os = "linux")]
    charged: bool,
    #[cfg(target_os = "linux")]
    order: crate::sockets::ErrorOrder,
    #[cfg(target_os = "linux")]
    wake_counted: bool,
    /// Linux `sock_extended_err.ee_data` (the `SOF_TIMESTAMPING_OPT_ID` key, 0 without it).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    key: u32,
    /// Linux `ee_info`: `SCM_TSTAMP_SND`, `SCM_TSTAMP_SCHED` or `SCM_TSTAMP_ACK`
    /// (include/uapi/linux/errqueue.h).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    stage: u32,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    at: Stamp,
    /// Not readable before then (an ACK still on its way back); `None` at once.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    visible: Option<Deadline>,
    /// What Linux loops back with the stamp: the packet as it left, or nothing under
    /// `SOF_TIMESTAMPING_OPT_TSONLY`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    packet: Vec<u8>,
}

/// A socket's timestamping state, kept in its record so every backend serving it agrees.
#[derive(Default)]
pub(crate) struct TsState {
    #[cfg(target_os = "linux")]
    report_wakes: u64,
    /// Linux `SOCK_RCVTSTAMP` (`SO_TIMESTAMP` or `SO_TIMESTAMPNS` on), macOS `SO_TIMESTAMP`.
    rcv: bool,
    /// Linux `SOCK_RCVTSTAMPNS` (`SO_TIMESTAMPNS`): a `timespec` rather than a `timeval`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rcv_ns: bool,
    /// macOS `SO_TIMESTAMP_MONOTONIC`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    mono: bool,
    /// macOS `SO_TIMESTAMP_CONTINUOUS`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    cont: bool,
    /// Linux `sk_tsflags`, the `SOF_TIMESTAMPING_*` word last set with `SO_TIMESTAMPING`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    flags: u32,
    /// Linux `so_timestamping.bind_phc`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    bind_phc: c_int,
    /// Linux `sk_tskey`: a datagram socket's next `OPT_ID` key, or a stream's byte count when
    /// `OPT_ID` was turned on, from which its keys count.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tskey: u32,
    /// A stream socket's bytes written so far, its `write_seq` relative to its first byte.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    written: u32,
    /// Transmit stamps not yet read, oldest first.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    txq: VecDeque<TxReport>,
    /// Linux `SOCK_TXTIME` with `sk_clockid` and the `SOF_TXTIME_*` flags, once `SO_TXTIME` was
    /// set; `None` before.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    txtime: Option<(c_int, u32)>,
}

impl TsState {
    pub(crate) fn has_tx_reports(&self) -> bool {
        !self.txq.is_empty()
    }

    pub(crate) fn pending_time(&self) -> bool {
        self.txq.iter().any(|report| report.visible.is_some())
    }
}

/// What a receive reads from, which decides the control messages it gets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rx {
    /// A datagram.
    Datagram,
    /// Bytes of a stream; the stamp is the arrival of the last byte read.
    Stream,
    /// A transmit stamp on Linux's error queue.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ErrQueue,
}

/// One control message: level, type and payload.
pub(crate) type Cmsg = (c_int, c_int, Vec<u8>);

/// A `struct timeval` as the host lays it out: `tv_sec` then `tv_usec`, padded to 16 bytes on
/// 64-bit Linux and macOS (`<sys/time.h>`; XNU bsd/sys/_types/_timeval64.h `user64_timeval`).
#[cfg(target_os = "linux")]
fn timeval(t: Duration) -> Vec<u8> {
    // SAFETY: an all-zero timeval is valid.
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    tv.tv_sec = t.as_secs() as libc::time_t;
    tv.tv_usec = t.subsec_micros() as libc::suseconds_t;
    // SAFETY: reads the plain-data struct's bytes.
    unsafe {
        std::slice::from_raw_parts(
            (&raw const tv).cast::<u8>(),
            std::mem::size_of::<libc::timeval>(),
        )
    }
    .to_vec()
}

#[cfg(target_os = "macos")]
fn timeval(t: Duration) -> Vec<u8> {
    let seconds = (t.as_secs() as libc::time_t).to_ne_bytes();
    let micros = (t.subsec_micros() as libc::suseconds_t).to_ne_bytes();
    let mut bytes = vec![0; size_of::<libc::timeval>()];
    let seconds_at = std::mem::offset_of!(libc::timeval, tv_sec);
    let micros_at = std::mem::offset_of!(libc::timeval, tv_usec);
    bytes[seconds_at..seconds_at + seconds.len()].copy_from_slice(&seconds);
    bytes[micros_at..micros_at + micros.len()].copy_from_slice(&micros);
    bytes
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn timeval_bytes_have_zero_tail_padding() {
    for (seconds, micros) in [(0i64, 0i32), (1_700_000_000, 250), (i64::MAX, 999_999)] {
        let time = Duration::new(seconds as u64, micros as u32 * 1000);
        let mut expected = Vec::from(seconds.to_ne_bytes());
        expected.extend(micros.to_ne_bytes());
        expected.extend([0; 4]);
        assert_eq!(timeval(time), expected);
    }
}

/// A `struct timespec` (`<time.h>`).
#[cfg(target_os = "linux")]
fn timespec(t: Duration) -> libc::timespec {
    // SAFETY: an all-zero timespec is valid.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    ts.tv_sec = t.as_secs() as libc::time_t;
    ts.tv_nsec = t.subsec_nanos() as _;
    ts
}

/// The bytes of plain-data `value`.
#[cfg(target_os = "linux")]
fn bytes_of<T: Copy>(value: &T) -> Vec<u8> {
    // SAFETY: reads `size_of::<T>()` bytes of a live value.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
}

/// Reads an `int` option value, `EINVAL` when `len` is short of one: Linux `sk_setsockopt`
/// (net/core/sock.c, "if (optlen < sizeof(int)) return -EINVAL") and XNU `sooptcopyin`
/// (bsd/kern/uipc_socket.c, `EINVAL` when `sopt_valsize < minlen`); measured by
/// tests/timestamps.rs `option_validation_os_truth`.
unsafe fn read_int(val: *const u8, len: u32) -> Result<c_int, c_int> {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return Err(libc::EINVAL);
    }
    // SAFETY: `val` holds at least an int.
    Ok(unsafe { val.cast::<c_int>().read_unaligned() })
}

/// How a socket stands for `SO_TIMESTAMPING`'s `OPT_ID`, which keys a stream's stamps by byte.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Kind {
    /// A datagram (or `socketpair`) socket.
    Datagram,
    /// A connected TCP socket.
    Established,
    /// A TCP socket that is not connected: fresh, connecting or listening.
    Unconnected,
}

#[cfg(target_os = "linux")]
pub(crate) use linux::*;

/// Linux: `SO_TIMESTAMP`, `SO_TIMESTAMPNS`, `SO_TIMESTAMPING` and the error queue
/// (Documentation/networking/timestamping.rst; include/uapi/linux/net_tstamp.h,
/// include/uapi/linux/errqueue.h).
#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// `SO_TIMESTAMP` = `SCM_TIMESTAMP` (29, `SO_TIMESTAMP_OLD` in
    /// include/uapi/asm-generic/socket.h): receive stamps as a `struct timeval`. The `_NEW`
    /// numbers (63, 64, 65) are what 32-bit targets with a 64-bit `time_t` get; they are not
    /// matched, as for `SO_TIMESTAMPING` in `simhost`.
    pub(crate) const SO_TIMESTAMP: c_int = 29;
    /// `SO_TIMESTAMPNS` = `SCM_TIMESTAMPNS` (35, `SO_TIMESTAMPNS_OLD`): as a `struct timespec`.
    pub(crate) const SO_TIMESTAMPNS: c_int = 35;
    /// `SO_TIMESTAMPING` = `SCM_TIMESTAMPING` (37, `SO_TIMESTAMPING_OLD`): the
    /// `SOF_TIMESTAMPING_*` flag word, or a `struct so_timestamping` (flags, `bind_phc`).
    pub(crate) const SO_TIMESTAMPING: c_int = 37;

    /// `SOF_TIMESTAMPING_TX_HARDWARE`, bit 0: hardware transmit stamps, which only a `SimHost`
    /// NIC with hardware timestamping takes (the plain fabric's NICs have no clock).
    pub(crate) const TX_HARDWARE: u32 = 1 << 0;
    /// `SOF_TIMESTAMPING_TX_SOFTWARE`, bit 1: a stamp as the packet leaves the driver.
    pub(crate) const TX_SOFTWARE: u32 = 1 << 1;
    /// `SOF_TIMESTAMPING_RX_HARDWARE`, bit 2: hardware receive stamps; with `OPT_RX_FILTER`,
    /// what decides whether this socket reports them.
    const RX_HARDWARE: u32 = 1 << 2;
    /// `SOF_TIMESTAMPING_RX_SOFTWARE`, bit 3: software receive stamps are generated.
    pub(crate) const RX_SOFTWARE: u32 = 1 << 3;
    /// `SOF_TIMESTAMPING_SOFTWARE`, bit 4: software stamps are reported, in `ts[0]`.
    pub(crate) const SOFTWARE: u32 = 1 << 4;
    /// `SOF_TIMESTAMPING_RAW_HARDWARE`, bit 6: hardware stamps are reported, in `ts[2]`.
    const RAW_HARDWARE: u32 = 1 << 6;
    /// `SOF_TIMESTAMPING_OPT_ID`, bit 7: number each send's stamps in `ee_data`.
    pub(crate) const OPT_ID: u32 = 1 << 7;
    /// `SOF_TIMESTAMPING_TX_SCHED`, bit 8: a stamp as the packet enters the qdisc.
    pub(crate) const TX_SCHED: u32 = 1 << 8;
    /// `SOF_TIMESTAMPING_TX_ACK`, bit 9: a stamp when the peer acknowledged all of a TCP send.
    pub(crate) const TX_ACK: u32 = 1 << 9;
    /// `SOF_TIMESTAMPING_OPT_TSONLY`, bit 11: loop back the stamp without the packet.
    pub(crate) const OPT_TSONLY: u32 = 1 << 11;
    /// `SOF_TIMESTAMPING_OPT_STATS`, bit 12: TCP stats with the stamp; requires `OPT_TSONLY`.
    const OPT_STATS: u32 = 1 << 12;
    /// `SOF_TIMESTAMPING_OPT_TX_SWHW`, bit 14: a software transmit stamp also when the driver
    /// takes a hardware one.
    const OPT_TX_SWHW: u32 = 1 << 14;
    /// `SOF_TIMESTAMPING_BIND_PHC`, bit 15: stamps in the PHC `bind_phc` names.
    const BIND_PHC: u32 = 1 << 15;
    /// `SOF_TIMESTAMPING_OPT_ID_TCP`, bit 16: key a stream by `write_seq`; requires `OPT_ID`.
    const OPT_ID_TCP: u32 = 1 << 16;
    /// `SOF_TIMESTAMPING_OPT_RX_FILTER`, bit 17: report software receive stamps only when this
    /// socket asked to generate them (`RX_SOFTWARE`).
    const OPT_RX_FILTER: u32 = 1 << 17;
    /// `SOF_TIMESTAMPING_MASK`: every flag through `SOF_TIMESTAMPING_TX_COMPLETION` (bit 18,
    /// `SOF_TIMESTAMPING_LAST`, Linux 6.15). A bit above it is `EINVAL` (net/core/sock.c
    /// `sock_set_timestamping`); measured on Linux 7.0 by tests/timestamps.rs
    /// `option_validation_os_truth`.
    const MASK: u32 = (1 << 19) - 1;
    /// `SCM_TSTAMP_SND` (include/uapi/linux/errqueue.h): the driver sent the packet.
    pub(crate) const SCM_TSTAMP_SND: u32 = 0;
    /// `SCM_TSTAMP_SCHED`: the packet entered the packet scheduler.
    pub(crate) const SCM_TSTAMP_SCHED: u32 = 1;
    /// `SCM_TSTAMP_ACK`: the peer acknowledged every byte of the send.
    pub(crate) const SCM_TSTAMP_ACK: u32 = 2;
    /// `SO_EE_ORIGIN_TIMESTAMPING` (include/uapi/linux/errqueue.h): a timestamp report.
    const SO_EE_ORIGIN_TIMESTAMPING: u8 = 4;
    /// `SO_TXTIME` = `SCM_TXTIME` (61, include/uapi/asm-generic/socket.h; parisc and sparc
    /// number it differently in their own socket.h): the option turning per-packet launch times
    /// on, and the control message carrying one.
    pub(crate) const SO_TXTIME: c_int = 61;
    /// `SOF_TXTIME_FLAGS_MASK` (include/uapi/linux/net_tstamp.h): `SOF_TXTIME_DEADLINE_MODE`
    /// (bit 0) and `SOF_TXTIME_REPORT_ERRORS` (bit 1).
    const SOF_TXTIME_FLAGS_MASK: u32 = 0b11;
    /// `sizeof(struct sock_txtime)` (include/uapi/linux/net_tstamp.h): `clockid_t clockid`,
    /// `__u32 flags`.
    const SOCK_TXTIME_LEN: u32 = 8;

    /// Sets `SO_TXTIME` on `rec` as net/core/sock.c `sk_setsockopt` does (Linux 7.0): an `optlen`
    /// short of an `int` (the function's prologue) or other than `sizeof(struct sock_txtime)` is
    /// `EINVAL`, an unreadable value `EFAULT`, a flag outside `SOF_TXTIME_FLAGS_MASK` `EINVAL`;
    /// a clock other than `CLOCK_MONOTONIC` needs `CAP_NET_ADMIN` (`sockopt_ns_capable`, else
    /// `EPERM`, checked before the clock is), and only `CLOCK_REALTIME`, `CLOCK_MONOTONIC` and
    /// `CLOCK_TAI` are accepted (`sockopt_validate_clockid`, else `EINVAL`). A refused request
    /// leaves the previous setting. `None` for any other option. Measured on Linux 7.0 by
    /// tests/hw_txtime_truth.rs `hw_txtime_sockopt_matches`.
    ///
    /// # Safety
    /// `val` is null or holds `len` bytes.
    pub(crate) unsafe fn set_txtime(
        rec: &SockRec,
        net_admin: bool,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        if level != libc::SOL_SOCKET || name != SO_TXTIME {
            return None;
        }
        if len != SOCK_TXTIME_LEN {
            return Some(Err(libc::EINVAL));
        }
        if val.is_null() {
            return Some(Err(libc::EFAULT));
        }
        // SAFETY: `len` is 8, the two words of `struct sock_txtime`.
        let (clockid, flags) = unsafe {
            (
                val.cast::<c_int>().read_unaligned(),
                val.cast::<u32>().add(1).read_unaligned(),
            )
        };
        if flags & !SOF_TXTIME_FLAGS_MASK != 0 {
            return Some(Err(libc::EINVAL));
        }
        if clockid != libc::CLOCK_MONOTONIC && !net_admin {
            return Some(Err(libc::EPERM));
        }
        if !matches!(
            clockid,
            libc::CLOCK_REALTIME | libc::CLOCK_MONOTONIC | libc::CLOCK_TAI
        ) {
            return Some(Err(libc::EINVAL));
        }
        rec.state().ts.txtime = Some((clockid, flags));
        Some(Ok(()))
    }

    /// The launch time of a `sendmsg`'s `SCM_TXTIME` control message on `rec`, checked as
    /// net/core/sock.c `__sock_cmsg_send` does (Linux 7.0): `EINVAL` on a socket without
    /// `SO_TXTIME` (`SOCK_TXTIME` clear) or for a `cmsg_len` other than `CMSG_LEN(sizeof(u64))`.
    /// The last such message wins, as each one overwrites `sockc->transmit_time`. `Ok(None)`
    /// without one. Walks with `CMSG_*` (man 3 cmsg), never past `msg_controllen`.
    ///
    /// # Safety
    /// `hdr` is the caller's `msghdr`, its control buffer `msg_controllen` bytes.
    pub(crate) unsafe fn txtime_cmsg(
        rec: &SockRec,
        hdr: *const libc::msghdr,
    ) -> Result<Option<u64>, c_int> {
        // SAFETY: forwarded contract.
        let (control, controllen) = unsafe { ((*hdr).msg_control, (*hdr).msg_controllen) };
        if control.is_null() || controllen == 0 {
            return Ok(None);
        }
        let enabled = rec.state().ts.txtime.is_some();
        let mut at = None;
        // SAFETY: the CMSG_* walk stays inside the control buffer.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
        while !cmsg.is_null() {
            // SAFETY: `cmsg` is a header inside the buffer.
            let (level, ty, len) = unsafe {
                (
                    (*cmsg).cmsg_level,
                    (*cmsg).cmsg_type,
                    (*cmsg).cmsg_len as usize,
                )
            };
            if level == libc::SOL_SOCKET && ty == SO_TXTIME {
                // SAFETY: CMSG_LEN is arithmetic.
                if !enabled || len != unsafe { libc::CMSG_LEN(8) } as usize {
                    return Err(libc::EINVAL);
                }
                // SAFETY: `cmsg_len` covers the eight data bytes.
                at = Some(unsafe { libc::CMSG_DATA(cmsg).cast::<u64>().read_unaligned() });
            }
            // SAFETY: as above.
            cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
        }
        Ok(at)
    }

    /// Sets `SO_TIMESTAMP`, `SO_TIMESTAMPNS` or `SO_TIMESTAMPING` on `rec` (a socket of `kind`),
    /// as net/core/sock.c `sk_setsockopt` does: an `optlen` short of an `int` is `EINVAL`;
    /// `SO_TIMESTAMP` turns `SO_TIMESTAMPNS` off and both off turn receive stamps off
    /// (`sock_set_timestamp`). `SO_TIMESTAMPING` (`sock_set_timestamping`) takes the flag word, or
    /// a whole `struct so_timestamping`; an unknown flag, `OPT_ID_TCP` without `OPT_ID`, or
    /// `OPT_STATS` without `OPT_TSONLY` is `EINVAL`; turning `OPT_ID` on restarts the keys, which a
    /// TCP socket that is not connected refuses with `EINVAL`; `BIND_PHC` fails, the sim's
    /// interfaces having no PHC: `EOPNOTSUPP` unbound, `EINVAL` bound to a device
    /// (`sock_timestamping_bind_phc`). `None` for any other option.
    ///
    /// # Safety
    /// `val` is null or holds `len` bytes.
    pub(crate) unsafe fn set(
        shared: Option<&SimShared>,
        rec: &SockRec,
        kind: Kind,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        if level != libc::SOL_SOCKET
            || !matches!(name, SO_TIMESTAMP | SO_TIMESTAMPNS | SO_TIMESTAMPING)
        {
            return None;
        }
        // SAFETY: forwarded contract.
        let v = match unsafe { read_int(val, len) } {
            Ok(v) => v,
            Err(errno) => return Some(Err(errno)),
        };
        let mut state = rec.state();
        let device = state.device.is_some();
        let ts = &mut state.ts;
        if name != SO_TIMESTAMPING {
            ts.rcv = v != 0;
            ts.rcv_ns = v != 0 && name == SO_TIMESTAMPNS;
            if ts.rcv
                && let Some(shared) = shared
            {
                shared.rx_timestamp_startup.enable(shared);
            }
            return Some(Ok(()));
        }
        let flags = v as u32;
        let bind_phc = if len as usize >= 2 * size_of::<c_int>() {
            // SAFETY: `len` covers the second int of `struct so_timestamping`.
            unsafe { val.cast::<c_int>().add(1).read_unaligned() }
        } else {
            0
        };
        if flags & !MASK != 0 || (flags & OPT_ID_TCP != 0 && flags & OPT_ID == 0) {
            return Some(Err(libc::EINVAL));
        }
        let restart = flags & OPT_ID != 0 && ts.flags & OPT_ID == 0;
        if restart && kind == Kind::Unconnected {
            return Some(Err(libc::EINVAL));
        }
        if flags & OPT_STATS != 0 && flags & OPT_TSONLY == 0 {
            return Some(Err(libc::EINVAL));
        }
        if flags & BIND_PHC != 0 {
            return Some(Err(if device {
                libc::EINVAL
            } else {
                libc::EOPNOTSUPP
            }));
        }
        if restart {
            ts.tskey = if kind == Kind::Established {
                ts.written
            } else {
                0
            };
        }
        ts.flags = flags;
        ts.bind_phc = bind_phc;
        if flags & RX_SOFTWARE != 0
            && let Some(shared) = shared
        {
            shared.rx_timestamp_startup.enable(shared);
        }
        Some(Ok(()))
    }

    /// Reads one of the timestamp options (net/core/sock.c `sk_getsockopt`): `SO_TIMESTAMP` is
    /// on only while `SO_TIMESTAMPNS` is not, `SO_TIMESTAMPING` is a `struct so_timestamping` and
    /// `SO_TXTIME` a `struct sock_txtime` (`sk_clockid`, 0 until set, and the flags), each cut to
    /// `*len` (8 bytes at most). `None` for any other option.
    ///
    /// # Safety
    /// `val`/`len` are null or the caller's buffer and its length.
    pub(crate) unsafe fn get(
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<()> {
        if level != libc::SOL_SOCKET {
            return None;
        }
        let state = rec.state();
        let ts = &state.ts;
        let bytes = match name {
            SO_TIMESTAMP => ((ts.rcv && !ts.rcv_ns) as c_int).to_ne_bytes().to_vec(),
            SO_TIMESTAMPNS => (ts.rcv_ns as c_int).to_ne_bytes().to_vec(),
            SO_TIMESTAMPING => [ts.flags.to_ne_bytes(), ts.bind_phc.to_ne_bytes()].concat(),
            SO_TXTIME => {
                let (clockid, flags) = ts.txtime.unwrap_or_default();
                [clockid.to_ne_bytes(), flags.to_ne_bytes()].concat()
            }
            _ => return None,
        };
        drop(state);
        if !val.is_null() && !len.is_null() {
            // SAFETY: the caller's buffer holds `*len` bytes.
            unsafe {
                let n = bytes.len().min(*len as usize);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), val, n);
                *len = n as u32;
            }
        }
        Some(())
    }

    /// The receive control messages for a packet stamped `at` on `rec`, in the order
    /// net/socket.c `__sock_recv_timestamp` (Linux 7.0) writes them: `SCM_TIMESTAMPNS` (or
    /// `SCM_TIMESTAMP`) while `SO_TIMESTAMPNS` (or `SO_TIMESTAMP`) is on, then one
    /// `SCM_TIMESTAMPING` once either of its slots is filled: the software stamp in `ts[0]` when
    /// `SOF_TIMESTAMPING_SOFTWARE` reports it and there is one (`ktime_to_timespec64_cond`: a
    /// hardware transmit report has none unless legacy timestamping supplies a read-time
    /// fallback), the hardware stamp in `ts[2]` when
    /// `SOF_TIMESTAMPING_RAW_HARDWARE` reports it and a NIC took one. Under `OPT_RX_FILTER` a
    /// received packet reports only the kinds the socket asked to generate (`RX_SOFTWARE`,
    /// `RX_HARDWARE`); an error-queue entry always reports. TCP reports the stamp of the last
    /// segment a read took (net/ipv4/tcp.c `tcp_recv_timestamp`), which is what [`Rx::Stream`]
    /// gets.
    ///
    pub(crate) fn rx_cmsgs(
        shared: Option<&SimShared>,
        rec: &SockRec,
        mut at: Stamp,
        rx: Rx,
        fallback: Option<&std::sync::OnceLock<Duration>>,
    ) -> Vec<Cmsg> {
        let state = rec.state();
        let ts = &state.ts;
        if rx != Rx::ErrQueue
            && shared.is_some_and(|shared| !shared.rx_timestamp_startup.stamps(at.real))
        {
            at.real = fallback
                .and_then(|fallback| fallback.get())
                .copied()
                .unwrap_or_default();
            if at.real.is_zero() && ts.rcv && rx == Rx::Datagram {
                let now = || shared.expect("timestamp startup sim").tstamp_now().real;
                at.real = fallback.map_or_else(now, |fallback| *fallback.get_or_init(now));
            }
        }
        let mut out = Vec::new();
        if ts.rcv && !at.real.is_zero() {
            out.push(if ts.rcv_ns {
                (
                    libc::SOL_SOCKET,
                    SO_TIMESTAMPNS,
                    bytes_of(&timespec(at.real)),
                )
            } else {
                (libc::SOL_SOCKET, SO_TIMESTAMP, timeval(at.real))
            });
        }
        let reports = |want: u32, generate: u32| {
            ts.flags & want != 0
                && (ts.flags & generate != 0 || rx == Rx::ErrQueue || ts.flags & OPT_RX_FILTER == 0)
        };
        let sw = (reports(SOFTWARE, RX_SOFTWARE) && !at.real.is_zero()).then_some(at.real);
        let hw = at.hw.filter(|_| reports(RAW_HARDWARE, RX_HARDWARE));
        if sw.is_some() || hw.is_some() {
            out.push((libc::SOL_SOCKET, SO_TIMESTAMPING, scm_timestamping(sw, hw)));
        }
        out
    }

    pub(crate) fn note_datagram_read(
        shared: &SimShared,
        rec: &SockRec,
        at: Stamp,
        fallback: &std::sync::OnceLock<Duration>,
    ) {
        if !shared.rx_timestamp_startup.stamps(at.real) && rec.state().ts.rcv {
            fallback.get_or_init(|| shared.tstamp_now().real);
        }
    }

    /// `struct scm_timestamping` (include/uapi/linux/errqueue.h): three `timespec`s, the
    /// software stamp in `ts[0]`, `ts[1]` deprecated and always zero, and the raw hardware stamp
    /// in `ts[2]` (Documentation/networking/timestamping.rst, "SCM_TIMESTAMPING"); an absent
    /// stamp is zero.
    pub(crate) fn scm_timestamping(sw: Option<Duration>, hw: Option<Duration>) -> Vec<u8> {
        let slot = |t: Option<Duration>| timespec(t.unwrap_or_default());
        bytes_of(&[slot(sw), slot(None), slot(hw)])
    }

    /// Queues the transmit stamps a datagram sent at `at` earns, as net/ipv4/ip_output.c
    /// `__ip_append_data` and the driver do: with `TX_SCHED` a `SCM_TSTAMP_SCHED` stamp, then
    /// with `TX_SOFTWARE` a `SCM_TSTAMP_SND` one at the send time, and with `TX_HARDWARE` on a
    /// NIC that stamps transmitted packets (`hw`, its clock's reading as the packet left) a
    /// second `SCM_TSTAMP_SND` carrying only that hardware stamp. A driver taking a hardware
    /// stamp marks the packet `SKBTX_IN_PROGRESS` before `skb_tx_timestamp`, and net/core/
    /// skbuff.c `__skb_tstamp_tx` (Linux 7.0) then drops the software one unless
    /// `OPT_TX_SWHW` asks for both. Every report is keyed by the socket's next `OPT_ID` key
    /// (which only a send asking for a stamp takes). `packet` is what is looped back without
    /// `OPT_TSONLY`.
    pub(crate) fn udp_sent(
        rec: &SockRec,
        at: Stamp,
        hw: Option<Duration>,
        packet: impl FnOnce() -> Vec<u8>,
    ) {
        let mut state = rec.state();
        let v6 = state.local.is_some_and(|a| a.is_ipv6());
        let (buf, ts) = {
            let state = &mut *state;
            (&mut state.buf, &mut state.ts)
        };
        if ts.flags & (TX_SCHED | TX_SOFTWARE | TX_HARDWARE) == 0 {
            return;
        }
        let hw = hw.filter(|_| ts.flags & TX_HARDWARE != 0);
        let software = ts.flags & TX_SOFTWARE != 0 && (hw.is_none() || ts.flags & OPT_TX_SWHW != 0);
        let mut reports = Vec::new();
        if ts.flags & TX_SCHED != 0 {
            reports.push((SCM_TSTAMP_SCHED, at));
        }
        if software {
            reports.push((SCM_TSTAMP_SND, at));
        }
        if let Some(hw) = hw {
            reports.push((SCM_TSTAMP_SND, Stamp::hardware(hw)));
        }
        let key = if ts.flags & OPT_ID != 0 {
            let key = ts.tskey;
            ts.tskey = ts.tskey.wrapping_add(1);
            key
        } else {
            0
        };
        let packet = if ts.flags & OPT_TSONLY != 0 || reports.is_empty() {
            Vec::new()
        } else {
            packet()
        };
        let charge = buf.error_charge(packet.len().saturating_sub(if v6 { 62 } else { 42 }), v6);
        for (stage, at) in reports {
            ts.txq.push_back(TxReport {
                charge,
                charged: false,
                order: crate::sockets::ErrorOrder::new(None),
                wake_counted: false,
                key,
                stage,
                at,
                visible: None,
                packet: packet.clone(),
            });
        }
    }

    /// Counts `n` bytes a stream socket wrote at `at` and queues the transmit stamps they earn
    /// (net/ipv4/tcp.c `tcp_tx_timestamp`, on the last segment of the send):
    /// `SCM_TSTAMP_SCHED` and `SCM_TSTAMP_SND` at the send time, and `SCM_TSTAMP_ACK` readable
    /// `rtt` later, when the acknowledgement of the last byte is back. Under `OPT_ID` each is
    /// keyed by that byte's offset from where the keys started (`ee_data` minus `sk_tskey`,
    /// net/core/skbuff.c `__skb_complete_tx_timestamp`); `sk_tskey` is taken from the bytes
    /// written, Linux's `write_seq` (or `snd_una` without `OPT_ID_TCP`, which the sim does not
    /// tell apart). The looped-back packet carries a fabricated header (see [`looped_frame`]).
    pub(crate) struct TcpWrite {
        key: u32,
        flags: u32,
    }

    pub(crate) fn tcp_requested(rec: &SockRec) -> bool {
        rec.state().ts.flags & (TX_SCHED | TX_SOFTWARE | TX_ACK | TX_HARDWARE) != 0
    }

    pub(crate) fn tcp_written(rec: &SockRec, n: usize) -> Option<TcpWrite> {
        let mut state = rec.state();
        let ts = &mut state.ts;
        ts.written = ts.written.wrapping_add(n as u32);
        if n == 0 || ts.flags & (TX_SCHED | TX_SOFTWARE | TX_ACK | TX_HARDWARE) == 0 {
            return None;
        }
        let key = if ts.flags & OPT_ID != 0 {
            ts.written.wrapping_sub(1).wrapping_sub(ts.tskey)
        } else {
            0
        };
        Some(TcpWrite {
            key,
            flags: ts.flags,
        })
    }

    pub(crate) fn tcp_transmitted(
        rec: &SockRec,
        request: TcpWrite,
        at: Stamp,
        len: usize,
        rtt: Duration,
        packet: impl FnOnce() -> Vec<u8>,
    ) {
        let mut state = rec.state();
        let v6 = state.local.is_some_and(|a| a.is_ipv6());
        let (buf, ts) = {
            let state = &mut *state;
            (&mut state.buf, &mut state.ts)
        };
        let packet = if request.flags & OPT_TSONLY != 0 {
            Vec::new()
        } else {
            packet()
        };
        let charge = buf.error_charge(0, v6) + if packet.is_empty() { 0 } else { len };
        let ack = (!rtt.is_zero()).then(|| Deadline::after(rtt));
        for (flag, stage, visible) in [
            (TX_SCHED, SCM_TSTAMP_SCHED, None),
            (TX_SOFTWARE, SCM_TSTAMP_SND, None),
            (TX_ACK, SCM_TSTAMP_ACK, ack),
        ] {
            if request.flags & flag == 0 {
                continue;
            }
            let at = if stage == SCM_TSTAMP_ACK {
                at.later(rtt)
            } else {
                at
            };
            ts.txq.push_back(TxReport {
                charge,
                charged: false,
                order: crate::sockets::ErrorOrder::new(visible),
                wake_counted: false,
                key: request.key,
                stage,
                at,
                visible,
                packet: packet.clone(),
            });
        }
        drop(state);
        if let Some(ack) = ack {
            ack.wake_waiters_then();
        }
    }

    /// Whether a transmit stamp is readable on the error queue now, which makes the socket
    /// report `POLLERR` (net/core/sock.c `sock_poll` via `datagram_poll`/`tcp_poll`: a
    /// non-empty `sk_error_queue` sets `EPOLLERR`).
    pub(crate) fn tx_report_ready(rec: &SockRec) -> bool {
        next_tx_report(&rec.state().ts).is_some()
    }

    pub(crate) fn next_tx_report(ts: &TsState) -> Option<(usize, crate::sockets::ErrorOrder)> {
        ts.txq
            .iter()
            .enumerate()
            .filter(|(_, report)| report.charged)
            .min_by_key(|(_, report)| report.order)
            .map(|(i, report)| (i, report.order))
    }

    impl TsState {
        pub(crate) fn admit_tx_report(&mut self, i: usize) {
            self.txq[i].charged = true;
        }

        pub(crate) fn pop_tx_report(&mut self, i: usize) -> Option<TxReport> {
            self.txq.remove(i)
        }
    }

    pub(crate) fn pending_tx_report(
        ts: &TsState,
        until: Option<Duration>,
    ) -> Option<(usize, crate::sockets::ErrorOrder, usize)> {
        ts.txq
            .iter()
            .enumerate()
            .filter(|(_, report)| {
                !report.charged
                    && report.visible.is_none_or(|d| d.passed())
                    && until.is_none_or(|until| report.order.at() <= until)
            })
            .min_by_key(|(_, report)| report.order)
            .map(|(i, report)| (i, report.order, report.charge))
    }

    pub(crate) fn tx_report_wakes(ts: &mut TsState) -> u64 {
        for report in &mut ts.txq {
            if !report.wake_counted && report.charged {
                report.wake_counted = true;
                ts.report_wakes = ts.report_wakes.saturating_add(1);
            }
        }
        ts.report_wakes
    }

    /// Writes a transmit stamp of `rec` into `hdr` as
    /// `recvmsg(MSG_ERRQUEUE)` does (net/ipv4/ip_sockglue.c `ip_recv_error`,
    /// net/ipv6/datagram.c `ipv6_recv_error`): the looped-back packet into the iovecs
    /// (`MSG_TRUNC` when it does not fit), no source address (`msg_namelen` 0: a timestamp has
    /// no offender), the timestamp messages of [`rx_cmsgs`] and then `IP_RECVERR` (or
    /// `IPV6_RECVERR` on an IPv6 socket) carrying `struct sock_extended_err` with `ee_errno`
    /// `ENOMSG`, `ee_origin` `SO_EE_ORIGIN_TIMESTAMPING`, `ee_info` the `SCM_TSTAMP_*` stage and
    /// `ee_data` the key, followed by a zeroed offender address; `msg_flags` gets
    /// `MSG_ERRQUEUE`. Returns the bytes copied. Measured by
    /// tests/timestamps.rs `tx_errqueue_os_truth`.
    ///
    /// # Safety
    /// `hdr` is the caller's valid `msghdr`.
    pub(crate) unsafe fn write_tx_report(
        rec: &SockRec,
        report: TxReport,
        hdr: *mut libc::msghdr,
        v6: bool,
        now: Duration,
    ) -> Option<snare_interpose::NetResult> {
        // SAFETY: forwarded contract.
        let copied = unsafe { crate::fabric::scatter(hdr, &report.packet) };
        let mut at = report.at;
        if at.real.is_zero() && rec.state().ts.rcv {
            at.real = now;
        }
        let mut cmsgs = rx_cmsgs(None, rec, at, Rx::ErrQueue, None);
        let mut ee = Vec::with_capacity(16 + 28);
        ee.extend_from_slice(&(libc::ENOMSG as u32).to_ne_bytes());
        ee.extend_from_slice(&[SO_EE_ORIGIN_TIMESTAMPING, 0, 0, 0]);
        ee.extend_from_slice(&report.stage.to_ne_bytes());
        ee.extend_from_slice(&report.key.to_ne_bytes());
        let (level, ty, offender) = if v6 {
            (
                libc::SOL_IPV6,
                libc::IPV6_RECVERR,
                size_of::<libc::sockaddr_in6>(),
            )
        } else {
            (
                libc::SOL_IP,
                libc::IP_RECVERR,
                size_of::<libc::sockaddr_in>(),
            )
        };
        ee.resize(ee.len() + offender, 0);
        cmsgs.push((level, ty, ee));
        let mut flags = libc::MSG_ERRQUEUE;
        if copied < report.packet.len() {
            flags |= libc::MSG_TRUNC;
        }
        // SAFETY: forwarded contract.
        unsafe {
            if !(*hdr).msg_name.is_null() {
                (*hdr).msg_namelen = 0;
            }
            if crate::fabric::write_cmsg_list(hdr, &cmsgs) {
                flags |= libc::MSG_CTRUNC;
            }
            (*hdr).msg_flags = flags;
        }
        Some(snare_interpose::NetResult::Ok(copied as i64))
    }
}

/// macOS: `SO_TIMESTAMP`, `SO_TIMESTAMP_MONOTONIC` and `SO_TIMESTAMP_CONTINUOUS`, which XNU's
/// `ip_savecontrol` (bsd/netinet/ip_input.c) attaches to each UDP datagram it queues.
#[cfg(target_os = "macos")]
pub(crate) use mac::{get, rx_cmsgs, set};

#[cfg(target_os = "macos")]
mod mac {
    use super::*;

    /// `SO_TIMESTAMP` (0x0400, XNU bsd/sys/socket.h): a `struct timeval` per datagram.
    const SO_TIMESTAMP: c_int = 0x0400;
    /// `SO_TIMESTAMP_MONOTONIC` (0x0800): a `uint64_t` of `mach_absolute_time` per datagram.
    const SO_TIMESTAMP_MONOTONIC: c_int = 0x0800;
    /// `SO_TIMESTAMP_CONTINUOUS` (0x40000): a `uint64_t` of `mach_continuous_time`.
    const SO_TIMESTAMP_CONTINUOUS: c_int = 0x40000;
    /// `SCM_TIMESTAMP` (0x02, bsd/sys/socket.h).
    const SCM_TIMESTAMP: c_int = 0x02;
    /// `SCM_TIMESTAMP_MONOTONIC` (0x04).
    const SCM_TIMESTAMP_MONOTONIC: c_int = 0x04;
    /// `SCM_TIMESTAMP_CONTINUOUS` (0x07).
    const SCM_TIMESTAMP_CONTINUOUS: c_int = 0x07;

    unsafe extern "C" {
        /// `<mach/mach_time.h>`.
        pub(super) fn mach_absolute_time() -> u64;
        /// `<mach/mach_time.h>`: `struct mach_timebase_info { uint32_t numer, denom; }`.
        fn mach_timebase_info(info: *mut [u32; 2]) -> c_int;
    }

    /// The Mach timebase `(numer, denom)`: ticks × numer / denom = nanoseconds ([Apple Technical
    /// Q&A QA1398](https://developer.apple.com/library/archive/qa/qa1398/_index.html)), fixed for
    /// the life of the process.
    fn timebase() -> (u64, u64) {
        static TIMEBASE: snare_interpose::RaceCell<(u64, u64)> = snare_interpose::RaceCell::new();
        *TIMEBASE
            .get_or_init(|| {
                let mut info = [1u32, 1];
                // SAFETY: fills the two words; not hooked.
                unsafe { mach_timebase_info(&mut info) };
                (u64::from(info[0]).max(1), u64::from(info[1]).max(1))
            })
            .0
    }

    /// Nanoseconds as Mach ticks, the conversion snare-interpose's `mach_absolute_time` hook
    /// makes, so a stamp compares with what the code under test reads.
    fn nanos_to_ticks(d: Duration) -> u64 {
        let (numer, denom) = timebase();
        (d.as_nanos() * u128::from(denom) / u128::from(numer)) as u64
    }

    /// Mach ticks as nanoseconds.
    pub(super) fn ticks_to_nanos(ticks: u64) -> Duration {
        let (numer, denom) = timebase();
        Duration::from_nanos((u128::from(ticks) * u128::from(numer) / u128::from(denom)) as u64)
    }

    /// The `so_options` bit of a timestamp option, which is also what `getsockopt` reports for
    /// it when set (XNU bsd/kern/uipc_socket.c `sogetoptlock`: `optval = so->so_options &
    /// sopt->sopt_name`; measured by tests/timestamps.rs `option_validation_os_truth`).
    fn bit(name: c_int) -> Option<c_int> {
        matches!(
            name,
            SO_TIMESTAMP | SO_TIMESTAMP_MONOTONIC | SO_TIMESTAMP_CONTINUOUS
        )
        .then_some(name)
    }

    /// Sets one of the timestamp options; an `optlen` short of an `int` is `EINVAL` (XNU
    /// `sooptcopyin`). Any socket takes them, but only UDP datagrams carry the stamps. `None`
    /// for any other option.
    ///
    /// # Safety
    /// `val` is null or holds `len` bytes.
    pub(crate) unsafe fn set(
        _shared: Option<&SimShared>,
        rec: &SockRec,
        _kind: Kind,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        if level != libc::SOL_SOCKET {
            return None;
        }
        bit(name)?;
        // SAFETY: forwarded contract.
        let on = match unsafe { read_int(val, len) } {
            Ok(v) => v != 0,
            Err(errno) => return Some(Err(errno)),
        };
        let mut state = rec.state();
        let ts = &mut state.ts;
        match name {
            SO_TIMESTAMP => ts.rcv = on,
            SO_TIMESTAMP_MONOTONIC => ts.mono = on,
            _ => ts.cont = on,
        }
        Some(Ok(()))
    }

    /// Reads a timestamp option: its `so_options` bit when on, else 0. `None` for any other.
    ///
    /// # Safety
    /// `val`/`len` are null or the caller's buffer and its length.
    pub(crate) unsafe fn get(
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<()> {
        if level != libc::SOL_SOCKET {
            return None;
        }
        let bit = bit(name)?;
        let ts = &rec.state().ts;
        let on = match name {
            SO_TIMESTAMP => ts.rcv,
            SO_TIMESTAMP_MONOTONIC => ts.mono,
            _ => ts.cont,
        };
        // SAFETY: forwarded contract.
        unsafe { crate::fabric::write_opt(if on { bit } else { 0 }, val, len) };
        Some(())
    }

    /// The control messages XNU's `ip_savecontrol` attaches to a UDP datagram that arrived at
    /// `at`, in its order: `SCM_TIMESTAMP` (a `timeval` from `getmicrotime`, so microseconds),
    /// `SCM_TIMESTAMP_MONOTONIC` and `SCM_TIMESTAMP_CONTINUOUS` (both Mach ticks: the sim has no
    /// sleep, so the two clocks agree). A TCP read gets none: XNU only adds them on the datagram
    /// path, measured by tests/timestamps.rs `tcp_rx_steady_state_os_truth`.
    pub(crate) fn rx_cmsgs(
        _shared: Option<&SimShared>,
        rec: &SockRec,
        at: Stamp,
        rx: Rx,
        _fallback: Option<&std::sync::OnceLock<Duration>>,
    ) -> Vec<Cmsg> {
        if rx != Rx::Datagram {
            return Vec::new();
        }
        let ts = &rec.state().ts;
        let mut out = Vec::new();
        if ts.rcv {
            out.push((libc::SOL_SOCKET, SCM_TIMESTAMP, timeval(at.real)));
        }
        if ts.mono || ts.cont {
            let ticks = nanos_to_ticks(at.mono).to_ne_bytes().to_vec();
            if ts.mono && ts.cont {
                out.push((libc::SOL_SOCKET, SCM_TIMESTAMP_MONOTONIC, ticks.clone()));
            }
            let kind = if ts.cont {
                SCM_TIMESTAMP_CONTINUOUS
            } else {
                SCM_TIMESTAMP_MONOTONIC
            };
            out.push((libc::SOL_SOCKET, kind, ticks));
        }
        out
    }
}

/// The frame Linux loops back with a transmit stamp when `OPT_TSONLY` is off: the packet from its
/// link-layer header on, as the driver held it when `skb_tx_timestamp` stamped it
/// (Documentation/networking/timestamping.rst, "SOF_TIMESTAMPING_OPT_TSONLY ... as opposed to
/// alongside the original packet"; measured as 14 + 20 + 8 bytes of header before a UDP payload
/// and 14 + 20 + 32 before a TCP one on loopback by tests/timestamps.rs `tx_errqueue_os_truth`).
/// The sim fabricates it: an Ethernet header with zero addresses, an IPv4 (`version` 4, `ihl` 5,
/// `DF`, TTL 64, header checksum filled) or IPv6 (hop limit 64) header, and a UDP header
/// (checksum 0) or a 32-byte TCP header (`ACK|PSH`, sequence numbers 0, window 65535, two `NOP`s
/// and a zero `TCP timestamps` option, checksum 0).
#[cfg(target_os = "linux")]
pub(crate) fn looped_frame(
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
    tcp: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&src.port().to_be_bytes());
    l4.extend_from_slice(&dst.port().to_be_bytes());
    if tcp {
        l4.extend_from_slice(&[0; 8]);
        l4.extend_from_slice(&[8 << 4, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        l4.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
    } else {
        l4.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
    }
    l4.extend_from_slice(payload);
    let proto = if tcp { 6u8 } else { 17 };
    let mut frame = vec![0u8; 12];
    match (src.ip(), dst.ip()) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            let mut ip = vec![0x45, 0];
            ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
            ip.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let sum = ip
                .chunks(2)
                .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
                .sum::<u32>();
            let folded = (sum & 0xffff) + (sum >> 16);
            let check = !(((folded & 0xffff) + (folded >> 16)) as u16);
            ip[10..12].copy_from_slice(&check.to_be_bytes());
            frame.extend_from_slice(&ip);
        }
        (s, d) => {
            let v6 = |ip: std::net::IpAddr| match ip {
                std::net::IpAddr::V6(v6) => v6,
                std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            frame.extend_from_slice(&0x86ddu16.to_be_bytes());
            frame.extend_from_slice(&[0x60, 0, 0, 0]);
            frame.extend_from_slice(&(l4.len() as u16).to_be_bytes());
            frame.extend_from_slice(&[proto, 64]);
            frame.extend_from_slice(&v6(s).octets());
            frame.extend_from_slice(&v6(d).octets());
        }
    }
    frame.extend_from_slice(&l4);
    frame
}
