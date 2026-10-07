//! Optional pcapng capture of every frame that crosses the simulated network, taken once per
//! frame at its sender. The sim has no real frames, so Ethernet, IP and TCP/UDP/ICMP headers are
//! fabricated around what the code under test and its testers send: a TCP connection shows its
//! handshake, segments, ACKs, FINs and resets with consistent sequence numbers. Frames are stamped
//! on the sim's own timeline, a frame due later (a SYN retransmission, an ACK after the link's
//! latency) waits in a heap until its time comes, and the file is valid after every write.
//!
//! Frame emission never reads the code under test's clock, charges latency, registers
//! a timer, wakes anything or draws from the sim's generator. Stamps are always the sim's; with
//! wall-time comments on (`SimBuilder::pcapng_wall_comment`, `SNARE_PCAPNG_WALL_COMMENT`) each
//! frame also carries the real wall time it was sent at, read on the real OS, as a comment, which
//! makes the file differ run to run.
//! Finalization refreshes transport probes before flushing their pending frames.
//!
//! The file follows the pcapng format of draft-ietf-opsawg-pcapng-06 (IETF, "PCAP Now Generic
//! (pcapng) Capture File Format"; section numbers below are that draft's): one Section Header
//! Block, an Interface Description Block the first time a frame crosses each interface, and an
//! Enhanced Packet Block per frame, all little-endian. Headers follow RFC 791 (IPv4), RFC 8200
//! (IPv6), RFC 9293 (TCP), RFC 768 (UDP), RFC 792 (ICMP) and RFC 4443 (ICMPv6).
//!
//! Locking: every write goes through [`Capture::with`] or [`Capture::finish`], which take the one
//! `Capture::inner` lock inside `snare_interpose::real`, so the file I/O and the lock wait are
//! never themselves simulated. Nothing else is locked while it is held: the topology read by
//! [`SimShared::wire_ends`] runs before the lock is taken.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::clock::Clock;
use crate::netif::Sender;
use crate::netpolicy::SplitMix64;
use crate::scope::SimShared;

/// The environment variable naming a directory to capture every sim into (see
/// [`Capture::from_env`]); a snare choice of name, as are the two below.
pub(crate) const ENV_DIR: &str = "SNARE_PCAPNG_DIR";
/// The environment variable listing, comma-separated, the test threads whose sims are captured
/// (see [`Capture::from_env`]).
pub(crate) const ENV_TESTS: &str = "SNARE_PCAPNG_TESTS";
/// The environment variable that, set to anything but empty or `0`, adds each frame's real wall
/// time as a comment (see [`wall_comment`]).
pub(crate) const ENV_WALL_COMMENT: &str = "SNARE_PCAPNG_WALL_COMMENT";

/// Block type of a Section Header Block (draft-ietf-opsawg-pcapng §4.1).
const BLOCK_SHB: u32 = 0x0A0D_0D0A;
/// Block type of an Interface Description Block (draft-ietf-opsawg-pcapng §4.2).
const BLOCK_IDB: u32 = 0x0000_0001;
/// Block type of an Enhanced Packet Block (draft-ietf-opsawg-pcapng §4.3).
const BLOCK_EPB: u32 = 0x0000_0006;
/// The SHB's Byte-Order Magic, written in the file's (little-endian) order
/// (draft-ietf-opsawg-pcapng §4.1).
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
/// LINKTYPE_ETHERNET: frames start with an Ethernet II header (draft-ietf-opsawg-pcaplinktype;
/// tcpdump.org "Link-layer header types").
const LINKTYPE_ETHERNET: u16 = 1;
/// opt_endofopt (draft-ietf-opsawg-pcapng §3.5).
const OPT_END: u16 = 0;
/// opt_comment (draft-ietf-opsawg-pcapng §3.5): a UTF-8 string, not zero-terminated, valid in
/// every block that takes options, the EPB included (§4.3).
const OPT_COMMENT: u16 = 1;
/// shb_os (draft-ietf-opsawg-pcapng §4.1).
const SHB_OS: u16 = 3;
/// shb_userappl (draft-ietf-opsawg-pcapng §4.1).
const SHB_USERAPPL: u16 = 4;
/// if_name (draft-ietf-opsawg-pcapng §4.2).
const IF_NAME: u16 = 2;
/// if_tsresol (draft-ietf-opsawg-pcapng §4.2); the IDB sets it to 9, which with the top bit clear
/// means 10^-9 seconds, so stamps are in nanoseconds.
const IF_TSRESOL: u16 = 9;
/// epb_flags (draft-ietf-opsawg-pcapng §4.3.1).
const EPB_FLAGS: u16 = 2;
/// The most bytes of a frame kept (a snare choice: the largest IPv4 total length, RFC 791 §3.1);
/// longer frames are truncated with their original length recorded.
const MAX_CAPLEN: usize = 65535;

/// EtherType of IPv4 and IPv6 (IEEE 802 EtherType registry; RFC 894, RFC 2464 §3).
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
/// IP protocol numbers (IANA "Protocol Numbers" registry).
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// TCP control bits, header byte 13 (RFC 9293 §3.1).
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// The host's default IPv4 TTL and IPv6 hop limit: 64 on Linux (Documentation/networking/
/// ip-sysctl.rst, `ip_default_ttl` and `hop_limit`, "Default: 64") and macOS (XNU
/// bsd/netinet/ip.h `IPDEFTTL` and bsd/netinet/ip6.h `IPV6_DEFHLIM`, both 64), 128 on Windows
/// (Microsoft Learn "Set-NetIPv4Protocol" and "Set-NetIPv6Protocol", `-DefaultHopLimit`: "The
/// default value is 128").
const TTL: u8 = if cfg!(windows) { 128 } else { 64 };

/// Which way a frame crossed the code under test's boundary: sent by it, or by a tester.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Sent by the code under test; written with epb_flags direction "outbound".
    Out,
    /// Sent by a tester or the simulated network; written as "inbound".
    In,
}

/// The interface a frame crosses.
#[derive(Clone, Debug)]
pub(crate) struct Link {
    /// The interface's name, as its IDB's if_name.
    pub(crate) iface: String,
    pub(crate) mtu: u32,
}

impl Link {
    /// The MSS a SYN on this link advertises, and the size TCP payload is cut into: the MTU less
    /// the fixed IP and TCP headers, 40 bytes over IPv4 and 60 over IPv6 (RFC 9293 §3.7.1;
    /// RFC 6691 §2). The MTU is capped at 65535 since the MSS option is 16 bits, and the result
    /// is at least 1 so chunking always progresses.
    fn mss(&self, v6: bool) -> usize {
        let mtu = self.mtu.min(65535) as usize;
        mtu.saturating_sub(if v6 { 60 } else { 40 }).max(1)
    }
}

/// One end of a frame: its address and the hardware address it has on the link.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Station {
    pub(crate) addr: SocketAddr,
    pub(crate) mac: [u8; 6],
}

/// One TCP connection's frames: the connecting end first, the accepting end second.
///
/// Handed out by [`SimShared::tcp_tap`] when the connection is made and kept by both ends; every
/// method forwards to the [`Capture`], which keeps the connection's sequence state in a
/// [`TcpFlow`] keyed by [`key`](TcpTap::key). Methods taking `from` index `ends`: 0 the
/// connecting end, 1 the accepting end. `ago`/`arrival` place the frame on the sim's timeline
/// relative to the moment of the call.
#[derive(Clone)]
pub(crate) struct TcpTap {
    capture: Arc<Capture>,
    link: Link,
    /// The connecting end, then the accepting end.
    ends: [Station; 2],
    /// Which way a segment sent by each end crosses the code under test's boundary.
    dirs: [Dir; 2],
}

impl TcpTap {
    /// The connection's key in [`Writer::flows`] and [`Writer::plans`]: (connecting, accepting).
    fn key(&self) -> (SocketAddr, SocketAddr) {
        (self.ends[0].addr, self.ends[1].addr)
    }

    /// The handshake of a connection accepted `ago` before now; `syn_sent` when its SYN went out
    /// earlier, with the connect's first attempt, whose planned retransmissions after that point
    /// are called off.
    pub(crate) fn open(&self, syn_sent: bool, ago: Duration) {
        self.capture.tcp_open(self, syn_sent, ago);
    }

    /// The connect's first SYN, now.
    pub(crate) fn syn(&self) {
        self.capture.tcp_syn(self);
    }

    /// The SYN retransmissions a connect still waiting will send, `retransmits` from now.
    pub(crate) fn syn_plan(&self, retransmits: &[Duration]) {
        self.capture.tcp_syn_plan(self, retransmits);
    }

    /// The SYN the connect sends `ago` before now outside its retransmission plan.
    pub(crate) fn resend_syn(&self, ago: Duration) {
        self.capture.tcp_resend_syn(self, ago);
    }

    /// The planned retransmissions up to the point `ago` before now were sent.
    pub(crate) fn confirm_plan(&self, ago: Duration) {
        self.capture.confirm_plan(self, ago);
    }

    /// The connect failed at the point `ago` before now: calls off the planned retransmissions
    /// after it and forgets the connection.
    pub(crate) fn failed(&self, ago: Duration) {
        self.capture.tcp_failed(self, ago);
    }

    /// The accepting end answers, `ago` before now, a SYN with a reset.
    pub(crate) fn refused(&self, ago: Duration) {
        self.capture.tcp_refused(self, ago);
    }

    /// `bytes` sent from `from` (0 the connecting end), arriving `arrival` from now.
    #[cfg(any(windows, test))]
    pub(crate) fn data(&self, from: usize, bytes: &[u8], arrival: Duration) {
        self.capture
            .tcp_data(self, from, bytes, arrival, None, true);
    }

    #[cfg(unix)]
    pub(crate) fn data_mss(
        &self,
        from: usize,
        bytes: &[u8],
        arrival: Duration,
        mss: Option<usize>,
    ) {
        self.capture.tcp_data(self, from, bytes, arrival, mss, true);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn data_mss_unacknowledged(
        &self,
        from: usize,
        bytes: &[u8],
        arrival: Duration,
        mss: Option<usize>,
    ) {
        self.capture
            .tcp_data(self, from, bytes, arrival, mss, false);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn watch_probe(&self, probe: std::sync::Weak<dyn crate::sockets::RxProbe>) {
        snare_interpose::real(|| {
            let mut probes = self.capture.probes.lock().unwrap();
            probes.retain(|probe| probe.strong_count() > 0);
            probes.push(probe);
        });
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn discard_acks_from(&self, from: usize, after: Duration, return_delay: Duration) {
        self.capture.with(|writer, now| {
            let at = now + crate::clock::nanos(after);
            writer.discard_acks(self.key(), Some(from), at);
            writer.reserve_reset(self, from, at, return_delay);
        });
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn retarget_reset(
        &self,
        from: usize,
        at: crate::readiness::Deadline,
        return_delay: Duration,
    ) {
        self.capture.with(|writer, _| {
            let at = crate::clock::nanos(
                at.timeline_at(self.capture.real_origin, self.capture.clock.as_deref()),
            );
            writer.retarget_reset(self, from, at, return_delay);
        });
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn defer_reset_receipt(&self, to: usize, at: crate::readiness::Deadline) {
        self.capture.with(|writer, _| {
            let at = crate::clock::nanos(
                at.timeline_at(self.capture.real_origin, self.capture.clock.as_deref()),
            );
            if let Some(flow) = writer.flows.get_mut(&self.key()) {
                flow.closed_at[to] = Some(at);
            }
        });
    }

    /// End `from` closes its side now: a FIN, and the other end's ACK of it `arrival` from now.
    /// Only the first FIN of each end is captured, and none after that end closes.
    pub(crate) fn fin(&self, from: usize, arrival: Duration) {
        self.capture.tcp_fin(self, from, arrival);
    }

    /// End `from` aborts the connection now with a reset. Only the first reset is captured.
    pub(crate) fn rst(&self, from: usize) {
        self.capture.tcp_rst(self, from, Duration::ZERO, None);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn rst_at(
        &self,
        from: usize,
        at: crate::readiness::Deadline,
        return_delay: Duration,
    ) {
        self.capture.with(|writer, _| {
            let at = crate::clock::nanos(
                at.timeline_at(self.capture.real_origin, self.capture.clock.as_deref()),
            );
            writer.reset_route(
                TcpRoute {
                    link: &self.link,
                    ends: &self.ends,
                    dirs: &self.dirs,
                },
                from,
                at,
                Some(return_delay),
            );
        });
    }
}

/// The sim's capture file.
///
/// Frames are stamped in nanoseconds on the sim's timeline (see `scope::timeline`), offset by
/// `base_realtime` so the file shows wall-clock-looking times.
pub(crate) struct Capture {
    path: PathBuf,
    /// The sim's seed, mixed into every connection's initial sequence numbers.
    seed: u64,
    /// The Unix time the sim's timeline starts at: the virtual clock's realtime at sim time zero,
    /// or, without one, the real time the sim was built.
    base_realtime: Duration,
    /// The sim's virtual clock, when it has one; stamps are read from it without advancing it.
    clock: Option<Arc<Clock>>,
    /// The real monotonic time the sim was built, the timeline's origin without a virtual clock.
    real_origin: Duration,
    #[cfg(target_os = "macos")]
    probes: Mutex<Vec<std::sync::Weak<dyn crate::sockets::RxProbe>>>,
    inner: Mutex<Writer>,
}

/// Whether a sim's frames carry their real wall time as a comment: asked for by its builder, or by
/// `SNARE_PCAPNG_WALL_COMMENT` set to anything but empty or `0`.
pub(crate) fn wall_comment(asked: bool) -> bool {
    asked
        || snare_interpose::real(|| std::env::var_os(ENV_WALL_COMMENT))
            .is_some_and(|v| !v.is_empty() && v != "0")
}

/// The real wall-clock time now, since the Unix epoch, read on the real OS.
fn real_wall() -> Duration {
    snare_interpose::real(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
    })
}

/// The sequence state of one captured TCP connection; each array is indexed by end, 0 the
/// connecting one.
struct TcpFlow {
    /// Each end's initial sequence number (see [`Capture::isn`]).
    isn: [u32; 2],
    /// The sequence number each end's next segment carries, and so the ACK the other end sends.
    next_seq: [u32; 2],
    /// Whether each end's SYN has been sent, which consumed one sequence number (RFC 9293 §3.4).
    syn: [bool; 2],
    /// Whether each end's FIN has been sent.
    fin: [bool; 2],
    /// A reset has been captured; further resets are suppressed.
    reset: bool,
    #[cfg(target_os = "macos")]
    closed_at: [Option<u64>; 2],
    #[cfg(target_os = "macos")]
    pending_closed_at: [Option<u64>; 2],
}

impl TcpFlow {
    fn can_send(&self, _from: usize, _at: u64) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.closed_at[_from]
                .into_iter()
                .chain(self.pending_closed_at[_from])
                .all(|closed| _at < closed)
        }
        #[cfg(not(target_os = "macos"))]
        {
            !self.reset
        }
    }
}

/// A frame built and waiting in [`Writer::pending`] for its stamp to come.
struct Frame {
    iface: String,
    dir: Dir,
    /// The frame as captured, at most [`MAX_CAPLEN`] bytes.
    bytes: Vec<u8>,
    /// The frame's full length on the wire, the EPB's Original Packet Length.
    orig_len: usize,
    /// A planned SYN retransmission of this connection, which its resolution may call off.
    plan: Option<(SocketAddr, SocketAddr)>,
    #[cfg(target_os = "macos")]
    ack: Option<TcpAck>,
    /// The real wall time the frame was sent, kept when it was built with its stamp already
    /// reached and the capture writes wall-time comments; see [`Writer::push`].
    wall: Option<Duration>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct TcpAck {
    flow: (SocketAddr, SocketAddr),
    from: usize,
    at: u64,
}

struct TcpRoute<'a> {
    link: &'a Link,
    ends: &'a [Station; 2],
    dirs: &'a [Dir; 2],
}

impl TcpRoute<'_> {
    fn key(&self) -> (SocketAddr, SocketAddr) {
        (self.ends[0].addr, self.ends[1].addr)
    }
}

#[cfg(target_os = "macos")]
struct ResetReservation {
    link: Link,
    ends: [Station; 2],
    dirs: [Dir; 2],
    at: [Option<u64>; 2],
    return_delay: [Duration; 2],
}

/// The capture's mutable state, behind [`Capture::inner`].
///
/// Invariant: frames leave `pending` in (stamp, id) order and are written with stamps that never
/// decrease, since [`push`](Writer::push) raises a stamp earlier than `last` to it. So the file is
/// in time order even when a frame is reported after a later one was written.
struct Writer {
    /// The file; `None` once capture finished or a write failed.
    out: Option<BufWriter<File>>,
    /// (stamp, frame id) of every frame not yet written, earliest first; the id breaks ties in
    /// the order frames were built.
    pending: BinaryHeap<Reverse<(u64, u64)>>,
    /// The frames `pending` refers to. An id in `pending` with no frame here was called off by
    /// [`end_plan`](Writer::end_plan) and is skipped.
    frames: HashMap<u64, Frame>,
    next_frame: u64,
    flows: HashMap<(SocketAddr, SocketAddr), TcpFlow>,
    /// Connects still waiting, with the stamp up to which their planned retransmissions were
    /// sent: later ones may yet be called off, so they and every frame after them stay pending.
    plans: HashMap<(SocketAddr, SocketAddr), u64>,
    #[cfg(target_os = "macos")]
    resets: HashMap<(SocketAddr, SocketAddr), ResetReservation>,
    /// The stamp of the last frame written; a frame stamped earlier is written at it.
    last: u64,
    /// The next IPv4 Identification each source address uses: a per-source counter, a snare
    /// choice that RFC 6864 §4.1 permits for atomic (DF-set) datagrams.
    ip_id: HashMap<IpAddr, u16>,
    /// Each interface's IDB index, in the order their IDBs were written (the EPB's Interface ID,
    /// draft-ietf-opsawg-pcapng §4.3).
    links: HashMap<String, u32>,
    /// [`Capture::finish`] ran: later frames are dropped.
    finished: bool,
    /// Whether each EPB carries the frame's real wall time as an opt_comment.
    wall_comment: bool,
    /// The stamp of the call being captured, set by [`Capture::with`] before it emits.
    now: u64,
}

impl Capture {
    /// Creates (or truncates) `path` and writes the section header. The file is opened on the
    /// real OS, so its descriptor never enters the sim's ownership. Without a virtual clock the
    /// timeline's Unix base is the real time now less the sim's age. With `wall_comment` every
    /// EPB carries the frame's real wall time as a comment.
    pub(crate) fn create(
        path: PathBuf,
        shared: &SimShared,
        wall_comment: bool,
    ) -> io::Result<Arc<Capture>> {
        let file = snare_interpose::real(|| File::create(&path))?;
        let base_realtime = match &shared.clock {
            Some(clock) => clock.timeline_realtime(),
            None => snare_interpose::real(|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                now.saturating_sub(shared.stamp())
            }),
        };
        let mut writer = Writer {
            out: Some(BufWriter::new(file)),
            pending: BinaryHeap::new(),
            frames: HashMap::new(),
            next_frame: 0,
            flows: HashMap::new(),
            plans: HashMap::new(),
            #[cfg(target_os = "macos")]
            resets: HashMap::new(),
            last: 0,
            ip_id: HashMap::new(),
            links: HashMap::new(),
            finished: false,
            wall_comment,
            now: 0,
        };
        snare_interpose::real(|| writer.put(&shb()).and_then(|()| writer.flush_out()))?;
        Ok(Arc::new(Capture {
            path,
            seed: shared.seed,
            base_realtime,
            clock: shared.clock.clone(),
            real_origin: shared.real_origin(),
            #[cfg(target_os = "macos")]
            probes: Mutex::new(Vec::new()),
            inner: Mutex::new(writer),
        }))
    }

    /// The capture the environment asks for, if any, for a sim built on a thread named `thread`
    /// (cargo's test harness names each test's thread after the test's path):
    ///
    /// - `SNARE_PCAPNG_TESTS` set to a comma-separated list of names captures only the sims built
    ///   on a listed thread, to `SNARE_PCAPNG_DIR` if set and else to `<temp dir>/snare-pcapng` (a
    ///   snare choice), saying where on stderr; a name matches the whole thread name or its last
    ///   `::` segments, so `my_test` lists `module::my_test`. A list of only blank entries counts
    ///   as unset.
    /// - Otherwise `SNARE_PCAPNG_DIR` alone captures every sim.
    ///
    /// The file is `<dir>/<thread name>.pcapng`, with a `-2`, `-3`… suffix for each further sim
    /// the same thread name builds. A failure warns and leaves the sim without capture.
    pub(crate) fn from_env(shared: &SimShared, wall_comment: bool) -> Option<Arc<Capture>> {
        let (dir, tests) = snare_interpose::real(|| {
            (
                std::env::var_os(ENV_DIR).filter(|dir| !dir.is_empty()),
                std::env::var(ENV_TESTS)
                    .ok()
                    .filter(|list| list.split(',').any(|entry| !entry.trim().is_empty())),
            )
        });
        let current = std::thread::current();
        let thread = current.name();
        let listed = tests.map(|list| test_listed(&list, thread));
        let dir = match (dir, listed) {
            (_, Some(false)) | (None, None) => return None,
            (Some(dir), _) => PathBuf::from(dir),
            (None, Some(true)) => snare_interpose::real(std::env::temp_dir).join("snare-pcapng"),
        };
        let announce = listed.is_some();
        let base = sanitize(thread.unwrap_or("sim"));
        let name = {
            static USED: Mutex<Option<HashMap<PathBuf, u32>>> = Mutex::new(None);
            let mut used = snare_interpose::real(|| USED.lock().unwrap_or_else(|e| e.into_inner()));
            let n = used
                .get_or_insert_with(HashMap::new)
                .entry(dir.join(&base))
                .or_insert(0);
            *n += 1;
            if *n == 1 {
                format!("{base}.pcapng")
            } else {
                format!("{base}-{n}.pcapng")
            }
        };
        let path = dir.join(name);
        let made = snare_interpose::real(|| std::fs::create_dir_all(&dir))
            .and_then(|()| Capture::create(path.clone(), shared, wall_comment));
        match made {
            Ok(capture) => {
                if announce {
                    eprintln!("snare: pcapng: capturing to {}", path.display());
                }
                Some(capture)
            }
            Err(e) => {
                eprintln!("snare: pcapng: cannot write {}: {e}", path.display());
                None
            }
        }
    }

    /// Where the capture is written.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Now on the sim's timeline, in nanoseconds since its origin. Reads the virtual clock's value
    /// without advancing it or charging latency.
    fn stamp(&self) -> u64 {
        crate::clock::nanos(crate::scope::timeline(
            self.clock.as_deref(),
            self.real_origin,
        ))
    }

    /// Runs `emit` on the writer at the current stamp, then writes every frame now due. Does
    /// nothing once capture has finished or stopped. The lock and the file I/O run inside
    /// `snare_interpose::real`, so they reach the real OS and never enter the sim.
    fn with(&self, emit: impl FnOnce(&mut Writer, u64)) {
        snare_interpose::real(|| {
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if w.finished || w.out.is_none() {
                return;
            }
            let now = self.stamp();
            w.now = now;
            emit(&mut w, now);
            w.flush_due(Some(now), self.base_realtime);
        });
    }

    /// Writes every frame still waiting, future ones included, and closes the file; later frames
    /// are dropped.
    pub(crate) fn finish(&self) {
        snare_interpose::real(|| {
            #[cfg(target_os = "macos")]
            {
                if self
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .finished
                {
                    return;
                }
                let probes: Vec<_> = self
                    .probes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter_map(std::sync::Weak::upgrade)
                    .collect();
                for probe in probes {
                    probe.land();
                }
            }
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if w.finished {
                return;
            }
            #[cfg(target_os = "macos")]
            {
                let now = self.stamp();
                w.now = now;
                w.finish_resets(now);
            }
            w.flush_due(None, self.base_realtime);
            w.finished = true;
            w.out = None;
        });
    }

    /// The initial sequence numbers of the connection `key`, connecting end first: FNV-1a of both
    /// addresses mixed with the sim's seed through SplitMix64, so a run's numbers depend only on
    /// the seed and the connection, never on the order connections were made. Real stacks derive
    /// theirs from a keyed hash of the four-tuple plus a clock (RFC 6528 §3); the clock part is
    /// left out so captures replay byte for byte.
    fn isn(&self, key: (SocketAddr, SocketAddr)) -> [u32; 2] {
        let mut h = Fnv::new();
        for addr in [key.0, key.1] {
            h.addr(addr);
        }
        let v = SplitMix64(self.seed ^ h.0).next_u64();
        [(v >> 32) as u32, v as u32]
    }

    /// See [`TcpTap::open`]. The three-way handshake (RFC 9293 §3.5), all stamped at the moment
    /// of acceptance: the SYN unless the connect already captured one, then SYN-ACK and ACK.
    fn tcp_open(&self, t: &TcpTap, syn_sent: bool, ago: Duration) {
        self.with(|w, now| {
            let at = now.saturating_sub(crate::clock::nanos(ago));
            w.end_plan(t.key(), at);
            if !syn_sent || !w.flows.contains_key(&t.key()) {
                w.start_flow(t.key(), self.isn(t.key()));
                w.segment(t, 0, SYN, &[], at, false);
            }
            w.segment(t, 1, SYN | ACK, &[], at, false);
            w.segment(t, 0, ACK, &[], at, false);
        });
    }

    /// See [`TcpTap::syn`]. Starts the connection's flow afresh.
    fn tcp_syn(&self, t: &TcpTap) {
        self.with(|w, now| {
            w.start_flow(t.key(), self.isn(t.key()));
            w.segment(t, 0, SYN, &[], now, false);
        });
    }

    /// See [`TcpTap::syn_plan`]. Queues each retransmission as a planned frame and marks the
    /// plan sent up to now; frames past that mark are held back by [`Writer::flush_due`] until
    /// the connect's outcome confirms or calls them off.
    fn tcp_syn_plan(&self, t: &TcpTap, retransmits: &[Duration]) {
        self.with(|w, now| {
            if !retransmits.is_empty() {
                w.plans.insert(t.key(), now);
            }
            for at in retransmits {
                w.segment(t, 0, SYN, &[], now + crate::clock::nanos(*at), true);
            }
        });
    }

    /// See [`TcpTap::resend_syn`].
    fn tcp_resend_syn(&self, t: &TcpTap, ago: Duration) {
        self.with(|w, now| {
            let at = now.saturating_sub(crate::clock::nanos(ago));
            w.segment(t, 0, SYN, &[], at, false);
        });
    }

    /// See [`TcpTap::confirm_plan`]. Only ever moves the mark forward.
    fn confirm_plan(&self, t: &TcpTap, ago: Duration) {
        self.with(|w, now| {
            let at = now.saturating_sub(crate::clock::nanos(ago));
            if let Some(sent) = w.plans.get_mut(&t.key()) {
                *sent = (*sent).max(at);
            }
        });
    }

    /// See [`TcpTap::failed`].
    fn tcp_failed(&self, t: &TcpTap, ago: Duration) {
        self.with(|w, now| {
            w.end_plan(t.key(), now.saturating_sub(crate::clock::nanos(ago)));
            w.flows.remove(&t.key());
        });
    }

    /// See [`TcpTap::refused`]. The RST carries sequence 0 and acknowledges the SYN, as a
    /// closed port answers one (RFC 9293 §3.10.7.1).
    fn tcp_refused(&self, t: &TcpTap, ago: Duration) {
        self.with(|w, now| {
            if !w.flows.contains_key(&t.key()) {
                w.start_flow(t.key(), self.isn(t.key()));
            }
            let at = now.saturating_sub(crate::clock::nanos(ago));
            w.segment(t, 1, RST | ACK, &[], at, false);
        });
    }

    /// See [`TcpTap::data`]. The bytes go out now as PSH|ACK segments of at most the link's MSS,
    /// and, when acknowledged, the receiver's single cumulative ACK follows at `arrival`.
    /// Dropped when the flow is unknown or its sending end has closed.
    fn tcp_data(
        &self,
        t: &TcpTap,
        from: usize,
        bytes: &[u8],
        arrival: Duration,
        mss: Option<usize>,
        acknowledge: bool,
    ) {
        if bytes.is_empty() {
            return;
        }
        self.with(|w, now| {
            if w.flows.get(&t.key()).is_none_or(|f| !f.can_send(from, now)) {
                return;
            }
            let mss = mss.unwrap_or_else(|| {
                t.link
                    .mss(wire_v6(t.ends[0].addr.ip(), t.ends[1].addr.ip()))
            });
            for chunk in bytes.chunks(mss) {
                w.segment(t, from, PSH | ACK, chunk, now, false);
            }
            if acknowledge {
                w.acknowledge(t, 1 - from, now + crate::clock::nanos(arrival));
            }
        });
    }

    /// See [`TcpTap::fin`].
    fn tcp_fin(&self, t: &TcpTap, from: usize, arrival: Duration) {
        self.with(|w, now| {
            let Some(flow) = w.flows.get_mut(&t.key()) else {
                return;
            };
            if !flow.can_send(from, now) || flow.fin[from] {
                return;
            }
            flow.fin[from] = true;
            w.segment(t, from, FIN | ACK, &[], now, false);
            w.acknowledge(t, 1 - from, now + crate::clock::nanos(arrival));
        });
    }

    /// See [`TcpTap::rst`].
    fn tcp_rst(&self, t: &TcpTap, from: usize, ago: Duration, return_delay: Option<Duration>) {
        self.with(|w, now| {
            w.reset_route(
                TcpRoute {
                    link: &t.link,
                    ends: &t.ends,
                    dirs: &t.dirs,
                },
                from,
                now.saturating_sub(crate::clock::nanos(ago)),
                return_delay,
            );
        });
    }

    /// One datagram from `src` to `dst`; at the realtime stamp `at` when the sender stamped it
    /// (a Unix time, converted to the timeline by subtracting `base_realtime`), else now.
    pub(crate) fn udp(
        &self,
        link: &Link,
        src: Station,
        dst: Station,
        dir: Dir,
        data: &[u8],
        at: Option<Duration>,
    ) {
        self.with(|w, now| {
            let at = at.map_or(now, |at| {
                crate::clock::nanos(at.saturating_sub(self.base_realtime))
            });
            let l4 = udp_header(src.addr.port(), dst.addr.port(), data);
            w.ip_frame(link, src, dst, dir, PROTO_UDP, l4, at, None);
        });
    }

    /// The ICMP port unreachable `from` sends back to `to` for the datagram `to` sent it, `after`
    /// from now: ICMP type 3 code 3 (RFC 792) or ICMPv6 type 1 code 4 (RFC 4443 §3.1), quoting
    /// the offending datagram's IP and UDP headers and as much of its payload as keeps the whole
    /// ICMP packet within 576 bytes over IPv4 (RFC 1812 §4.3.2.3) or the 1280-byte minimum IPv6
    /// MTU (RFC 4443 §2.4 (c)). The quoted UDP checksum is computed as the original carried it.
    pub(crate) fn icmp_port_unreachable(
        &self,
        link: &Link,
        from: Station,
        to: Station,
        datagram: &[u8],
        after: Duration,
    ) {
        self.with(|w, now| {
            let (a, b) = wire_pair(to.addr.ip(), from.addr.ip());
            let quoted_udp = udp_header(to.addr.port(), from.addr.port(), datagram);
            let (proto, l4) = match (a, b) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    let mut quoted = ipv4_header(a, b, PROTO_UDP, quoted_udp.len(), 0);
                    let mut udp = quoted_udp;
                    let sum = l4_checksum(a.into(), b.into(), PROTO_UDP, &udp, true);
                    write_u16(&mut udp, 6, sum);
                    quoted.extend_from_slice(&udp);
                    // RFC 1812 §4.3.2.3: whole ICMP datagram (IP 20 + ICMP 8 + quote) <= 576.
                    quoted.truncate(576 - 20 - 8);
                    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
                    icmp.extend_from_slice(&quoted);
                    (PROTO_ICMP, icmp)
                }
                (a, b) => {
                    let (a6, b6) = (as_v6(a), as_v6(b));
                    let mut quoted = ipv6_header(a6, b6, PROTO_UDP, quoted_udp.len());
                    let mut udp = quoted_udp;
                    let sum = l4_checksum(a6.into(), b6.into(), PROTO_UDP, &udp, true);
                    write_u16(&mut udp, 6, sum);
                    quoted.extend_from_slice(&udp);
                    // RFC 4443 §2.4 (c): whole packet (IPv6 40 + ICMPv6 8 + quote) <= 1280.
                    quoted.truncate(1280 - 40 - 8);
                    let mut icmp = vec![1, 4, 0, 0, 0, 0, 0, 0];
                    icmp.extend_from_slice(&quoted);
                    (PROTO_ICMPV6, icmp)
                }
            };
            w.ip_frame(
                link,
                from,
                to,
                Dir::In,
                proto,
                l4,
                now + crate::clock::nanos(after),
                None,
            );
        });
    }

    /// A raw Ethernet frame the code under test wrote on `iface`, kept as written (truncated to
    /// [`MAX_CAPLEN`]).
    pub(crate) fn l2(&self, iface: &str, frame: &[u8]) {
        self.with(|w, now| {
            w.push(
                now,
                Frame {
                    iface: iface.to_owned(),
                    dir: Dir::Out,
                    orig_len: frame.len(),
                    bytes: frame[..frame.len().min(MAX_CAPLEN)].to_vec(),
                    plan: None,
                    #[cfg(target_os = "macos")]
                    ack: None,
                    wall: None,
                },
            );
        });
    }
}

impl Writer {
    #[cfg(target_os = "macos")]
    fn reserve_reset(&mut self, tap: &TcpTap, from: usize, at: u64, return_delay: Duration) {
        let Some(flow) = self.flows.get_mut(&tap.key()) else {
            return;
        };
        if flow.pending_closed_at[from].is_some_and(|old| old <= at) {
            return;
        }
        self.retarget_reset(tap, from, at, return_delay);
    }

    #[cfg(target_os = "macos")]
    fn retarget_reset(&mut self, tap: &TcpTap, from: usize, at: u64, return_delay: Duration) {
        let Some(flow) = self.flows.get_mut(&tap.key()) else {
            return;
        };
        flow.pending_closed_at[from] = Some(at);
        if flow.reset {
            return;
        }
        let pending = self
            .resets
            .entry(tap.key())
            .or_insert_with(|| ResetReservation {
                link: tap.link.clone(),
                ends: tap.ends,
                dirs: tap.dirs,
                at: [None; 2],
                return_delay: [Duration::ZERO; 2],
            });
        pending.at[from] = Some(at);
        pending.return_delay[from] = return_delay;
    }

    #[cfg(target_os = "macos")]
    fn finish_resets(&mut self, now: u64) {
        let mut pending: Vec<_> = std::mem::take(&mut self.resets).into_iter().collect();
        pending.sort_by_key(|(key, reset)| (reset.at.into_iter().flatten().min(), *key));
        for (_, reset) in pending {
            let Some((at, from)) = reset
                .at
                .into_iter()
                .enumerate()
                .filter_map(|(from, at)| at.map(|at| (at, from)))
                .min_by_key(|(at, from)| (*at, 1 - *from))
            else {
                continue;
            };
            if at > now {
                continue;
            }
            self.reset_route(
                TcpRoute {
                    link: &reset.link,
                    ends: &reset.ends,
                    dirs: &reset.dirs,
                },
                from,
                at,
                Some(reset.return_delay[from]),
            );
        }
    }

    fn reset_route(
        &mut self,
        route: TcpRoute<'_>,
        from: usize,
        at: u64,
        _return_delay: Option<Duration>,
    ) {
        let key = route.key();
        #[cfg(target_os = "macos")]
        self.resets.remove(&key);
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        let emit = !flow.reset;
        flow.reset = true;
        #[cfg(target_os = "macos")]
        {
            flow.pending_closed_at[from] = None;
            let peer_at = at.saturating_add(crate::clock::nanos(_return_delay.unwrap_or_default()));
            for (end, closed) in [(from, at), (1 - from, peer_at)] {
                flow.closed_at[end] =
                    Some(flow.closed_at[end].map_or(closed, |old| old.min(closed)));
            }
            let closed_at = std::array::from_fn::<_, 2, _>(|end| {
                flow.closed_at[end]
                    .into_iter()
                    .chain(flow.pending_closed_at[end])
                    .min()
            });
            for (end, closed) in closed_at.into_iter().enumerate() {
                self.discard_acks(key, Some(end), closed.unwrap());
            }
        }
        if emit {
            self.segment_route(route, from, RST | ACK, &[], at, false);
        }
    }

    #[cfg(target_os = "macos")]
    fn discard_acks(&mut self, flow: (SocketAddr, SocketAddr), from: Option<usize>, after: u64) {
        self.frames.retain(|_, frame| {
            frame.ack.is_none_or(|ack| {
                ack.flow != flow || from.is_some_and(|from| ack.from != from) || ack.at < after
            })
        });
    }

    /// Resolves the connect `key`'s retransmission plan at stamp `after`: forgets the plan and
    /// drops every planned frame of it stamped later, the retransmissions that never happened.
    /// Does nothing when the connection has no plan.
    fn end_plan(&mut self, key: (SocketAddr, SocketAddr), after: u64) {
        if self.plans.remove(&key).is_none() {
            return;
        }
        let stale: Vec<u64> = self
            .pending
            .iter()
            .filter(|Reverse((at, id))| {
                *at > after && self.frames.get(id).is_some_and(|f| f.plan == Some(key))
            })
            .map(|Reverse((_, id))| *id)
            .collect();
        for id in stale {
            self.frames.remove(&id);
        }
    }

    /// Starts (or restarts) the flow `key` with nothing sent yet.
    fn start_flow(&mut self, key: (SocketAddr, SocketAddr), isn: [u32; 2]) {
        #[cfg(target_os = "macos")]
        self.resets.remove(&key);
        self.flows.insert(
            key,
            TcpFlow {
                isn,
                next_seq: isn,
                syn: [false; 2],
                fin: [false; 2],
                reset: false,
                #[cfg(target_os = "macos")]
                closed_at: [None; 2],
                #[cfg(target_os = "macos")]
                pending_closed_at: [None; 2],
            },
        );
    }

    /// Queues one TCP segment from end `from` at stamp `at`, then advances that end's sequence
    /// number by what the segment consumes: one for its first SYN and for a FIN, plus the payload
    /// (RFC 9293 §3.4). A SYN repeats the ISN; a RST from an end that never sent a SYN carries
    /// sequence 0 (RFC 9293 §3.10.7.1); an ACK acknowledges everything the other end has sent so
    /// far, since the sim loses nothing on a stream. SYNs carry the link's MSS option. `plan` marks
    /// the segment a planned retransmission [`end_plan`](Writer::end_plan) may call off. Does
    /// nothing for an unknown flow.
    fn segment(&mut self, t: &TcpTap, from: usize, flags: u8, payload: &[u8], at: u64, plan: bool) {
        self.segment_route(
            TcpRoute {
                link: &t.link,
                ends: &t.ends,
                dirs: &t.dirs,
            },
            from,
            flags,
            payload,
            at,
            plan,
        );
    }

    fn acknowledge(&mut self, tap: &TcpTap, from: usize, at: u64) {
        if self
            .flows
            .get(&tap.key())
            .is_some_and(|flow| flow.can_send(from, at))
        {
            self.segment(tap, from, ACK, &[], at, false);
        }
    }

    fn segment_route(
        &mut self,
        t: TcpRoute<'_>,
        from: usize,
        flags: u8,
        payload: &[u8],
        at: u64,
        plan: bool,
    ) {
        let Some(flow) = self.flows.get_mut(&t.key()) else {
            return;
        };
        let to = 1 - from;
        let seq = if flags & SYN != 0 {
            flow.isn[from]
        } else if flags & RST != 0 && !flow.syn[from] {
            0
        } else {
            flow.next_seq[from]
        };
        let ack = if flags & ACK != 0 {
            flow.next_seq[to]
        } else {
            0
        };
        if flags & SYN != 0 && !flow.syn[from] {
            flow.syn[from] = true;
            flow.next_seq[from] = flow.isn[from].wrapping_add(1);
        }
        if flags & FIN != 0 {
            flow.next_seq[from] = flow.next_seq[from].wrapping_add(1);
        }
        flow.next_seq[from] = flow.next_seq[from].wrapping_add(payload.len() as u32);
        let v6 = wire_v6(t.ends[0].addr.ip(), t.ends[1].addr.ip());
        let mss = (flags & SYN != 0).then(|| t.link.mss(v6) as u16);
        let (src, dst) = (t.ends[from], t.ends[to]);
        let l4 = tcp_header(
            src.addr.port(),
            dst.addr.port(),
            seq,
            ack,
            flags,
            mss,
            payload,
        );
        let key = plan.then(|| t.key());
        #[cfg(target_os = "macos")]
        let frame_id = self.next_frame;
        self.ip_frame(t.link, src, dst, t.dirs[from], PROTO_TCP, l4, at, key);
        #[cfg(target_os = "macos")]
        if flags == ACK
            && let Some(frame) = self.frames.get_mut(&frame_id)
        {
            frame.ack = Some(TcpAck {
                flow: t.key(),
                from,
                at: at.max(self.last),
            });
        }
    }

    /// Wraps the transport payload `l4` in IP and Ethernet II headers (destination MAC, source
    /// MAC, EtherType: 14 bytes) and queues it at `at`. The
    /// transport checksum is filled in here, at its offset in each header (TCP 16, RFC 9293 §3.1;
    /// UDP 6, RFC 768; ICMP and ICMPv6 2, RFC 792 and RFC 4443 §2.1): plain over the message for
    /// ICMP, over the pseudo-header otherwise (see [`l4_checksum`]). The IP version is chosen by
    /// [`wire_pair`]; IPv4 frames take the next Identification of their source address.
    #[allow(clippy::too_many_arguments)]
    fn ip_frame(
        &mut self,
        link: &Link,
        src: Station,
        dst: Station,
        dir: Dir,
        proto: u8,
        mut l4: Vec<u8>,
        at: u64,
        plan: Option<(SocketAddr, SocketAddr)>,
    ) {
        let (s, d) = wire_pair(src.addr.ip(), dst.addr.ip());
        let csum_at = match proto {
            PROTO_TCP => Some(16),
            PROTO_UDP => Some(6),
            PROTO_ICMP | PROTO_ICMPV6 => Some(2),
            _ => None,
        };
        let mut bytes = Vec::with_capacity(14 + 40 + l4.len());
        bytes.extend_from_slice(&dst.mac);
        bytes.extend_from_slice(&src.mac);
        match (s, d) {
            (IpAddr::V4(s4), IpAddr::V4(d4)) => {
                if let Some(off) = csum_at {
                    let sum = if proto == PROTO_ICMP {
                        checksum(&[&l4])
                    } else {
                        l4_checksum(s, d, proto, &l4, proto == PROTO_UDP)
                    };
                    write_u16(&mut l4, off, sum);
                }
                let id = self.ip_id.entry(s).or_insert(0);
                let this = *id;
                *id = id.wrapping_add(1);
                bytes.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                bytes.extend_from_slice(&ipv4_header(s4, d4, proto, l4.len(), this));
            }
            (s, d) => {
                let (s6, d6) = (as_v6(s), as_v6(d));
                if let Some(off) = csum_at {
                    let sum = l4_checksum(s6.into(), d6.into(), proto, &l4, proto == PROTO_UDP);
                    write_u16(&mut l4, off, sum);
                }
                bytes.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
                bytes.extend_from_slice(&ipv6_header(s6, d6, proto, l4.len()));
            }
        }
        bytes.extend_from_slice(&l4);
        let orig_len = bytes.len();
        bytes.truncate(MAX_CAPLEN);
        self.push(
            at,
            Frame {
                iface: link.iface.clone(),
                dir,
                bytes,
                orig_len,
                plan,
                #[cfg(target_os = "macos")]
                ack: None,
                wall: None,
            },
        );
    }

    /// Queues `frame` at stamp `at`, or at the last stamp written if `at` is earlier, so the file
    /// stays in time order. With wall-time comments on, a frame whose stamp the sim's clock has
    /// already reached takes the real wall time now, when its sender sent it; one due later (an
    /// ACK after latency, a planned retransmission) takes it when it is written, the first moment
    /// the capture sees the sim's clock past it.
    fn push(&mut self, at: u64, mut frame: Frame) {
        if self.wall_comment && at <= self.now {
            frame.wall = Some(real_wall());
        }
        let at = at.max(self.last);
        let id = self.next_frame;
        self.next_frame += 1;
        self.frames.insert(id, frame);
        self.pending.push(Reverse((at, id)));
    }

    /// Writes every frame stamped at or before `upto` (all of them for `None`) in time order, then
    /// flushes the file, so it is a valid pcapng file after every call. With `upto` set it stops
    /// at the first planned retransmission past its plan's confirmed mark: that frame and every
    /// later one wait until the connect resolves, since writing them could put a retransmission
    /// that never happened in the file. The first error stops capture: it warns, closes the file
    /// and discards what is pending.
    fn flush_due(&mut self, upto: Option<u64>, base_realtime: Duration) {
        let base = crate::clock::nanos(base_realtime);
        let mut result = Ok(());
        #[cfg(target_os = "macos")]
        let reset_at = self
            .resets
            .values()
            .flat_map(|reset| reset.at.into_iter().flatten())
            .min();
        while let Some(&Reverse((at, id))) = self.pending.peek() {
            if upto.is_some_and(|upto| at > upto) {
                break;
            }
            #[cfg(target_os = "macos")]
            if upto.is_some() && reset_at.is_some_and(|reset| at >= reset) {
                break;
            }
            let held = |frame: &Frame| {
                frame
                    .plan
                    .and_then(|key| self.plans.get(&key))
                    .is_some_and(|&sent| at > sent)
            };
            if upto.is_some() && self.frames.get(&id).is_some_and(held) {
                break;
            }
            self.pending.pop();
            let Some(frame) = self.frames.remove(&id) else {
                continue;
            };
            self.last = self.last.max(at);
            result = self.write_frame(base.saturating_add(at), &frame);
            if result.is_err() {
                break;
            }
        }
        if result.is_ok() {
            result = self.flush_out();
        }
        if let Err(e) = result {
            eprintln!("snare: pcapng: write failed, capture stopped: {e}");
            self.out = None;
            self.pending.clear();
            self.frames.clear();
        }
    }

    /// Writes `frame` stamped `ns` (Unix nanoseconds) as an EPB, preceded by its interface's IDB
    /// the first time that interface appears.
    fn write_frame(&mut self, ns: u64, frame: &Frame) -> io::Result<()> {
        let iface = match self.links.get(&frame.iface) {
            Some(&id) => id,
            None => {
                let id = self.links.len() as u32;
                self.put(&idb(&frame.iface))?;
                self.links.insert(frame.iface.clone(), id);
                id
            }
        };
        let wall = frame
            .wall
            .or_else(|| self.wall_comment.then(real_wall))
            .map(wall_text);
        self.put(&epb(iface, ns, frame, wall.as_deref()))
    }

    /// Appends `block` to the file; a no-op once capture stopped.
    fn put(&mut self, block: &[u8]) -> io::Result<()> {
        match &mut self.out {
            Some(out) => out.write_all(block),
            None => Ok(()),
        }
    }

    /// Flushes buffered blocks to the file; a no-op once capture stopped.
    fn flush_out(&mut self) -> io::Result<()> {
        match &mut self.out {
            Some(out) => out.flush(),
            None => Ok(()),
        }
    }
}

/// `name` made safe as a file name on every host: ASCII letters, digits, `.`, `_` and `-` kept,
/// `:` (from test paths such as `module::test`, and reserved on Windows) turned into `-`,
/// everything else into `_`.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => c,
            ':' => '-',
            _ => '_',
        })
        .collect()
}

/// Appends one option: 16-bit code, 16-bit value length, then the value zero-padded to 32 bits
/// (draft-ietf-opsawg-pcapng §3.5).
fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// Frames `body` (already a multiple of 4 bytes) as a block: type, total length, body, and the
/// total length again so readers can walk backwards (draft-ietf-opsawg-pcapng §3.1). The 12 is the
/// three 32-bit framing fields.
fn block(kind: u32, body: Vec<u8>) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

/// The Section Header Block (draft-ietf-opsawg-pcapng §4.1): byte-order magic, version 1.0, a
/// Section Length of -1 ("not specified", since the file grows as it is written), and shb_os and
/// shb_userappl naming the host OS and this snare.
fn shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    option(&mut body, SHB_OS, std::env::consts::OS.as_bytes());
    option(
        &mut body,
        SHB_USERAPPL,
        concat!("snare ", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    option(&mut body, OPT_END, &[]);
    block(BLOCK_SHB, body)
}

/// An Interface Description Block for the interface `name` (draft-ietf-opsawg-pcapng §4.2):
/// Ethernet link type, reserved 0, SnapLen 0 ("no limit"), if_name, and if_tsresol 9 so EPB
/// stamps are nanoseconds.
fn idb(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    option(&mut body, IF_NAME, name.as_bytes());
    option(&mut body, IF_TSRESOL, &[9]);
    option(&mut body, OPT_END, &[]);
    block(BLOCK_IDB, body)
}

/// An Enhanced Packet Block (draft-ietf-opsawg-pcapng §4.3): interface index, the 64-bit stamp
/// split into its upper and lower 32 bits, captured and original lengths, the padded frame,
/// epb_flags whose bits 0-1 give the direction, 01 inbound and 10 outbound (§4.3.1), and the
/// `comment`, if any, as an opt_comment (§3.5).
fn epb(iface: u32, ns: u64, frame: &Frame, comment: Option<&str>) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 + frame.bytes.len());
    body.extend_from_slice(&iface.to_le_bytes());
    body.extend_from_slice(&((ns >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(ns as u32).to_le_bytes());
    body.extend_from_slice(&(frame.bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(&(frame.orig_len as u32).to_le_bytes());
    body.extend_from_slice(&frame.bytes);
    body.resize(body.len().next_multiple_of(4), 0);
    let flags: u32 = match frame.dir {
        Dir::In => 1,
        Dir::Out => 2,
    };
    option(&mut body, EPB_FLAGS, &flags.to_le_bytes());
    if let Some(comment) = comment {
        option(&mut body, OPT_COMMENT, comment.as_bytes());
    }
    option(&mut body, OPT_END, &[]);
    block(BLOCK_EPB, body)
}

/// The comment a frame's real wall time is written as: `wall ` and the time in UTC in the RFC 3339
/// §5.6 `date-time` form with nanoseconds, `wall 2026-10-02T09:15:42.123456789Z`. The `wall`
/// prefix and the precision are snare's choice.
fn wall_text(wall: Duration) -> String {
    let secs = wall.as_secs();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let of_day = secs % 86_400;
    format!(
        "wall {year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60,
        wall.subsec_nanos()
    )
}

/// The proleptic Gregorian (year, month, day) of `days` after 1970-01-01, by Howard Hinnant's
/// `civil_from_days` ("chrono-Compatible Low-Level Date Algorithms",
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>), restricted to dates
/// on or after the epoch: eras of 146097 days (400 years), years of the era counted from March so
/// the leap day falls last.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// Whether the thread named `thread` is one of the comma-separated `list`'s: the whole name, or
/// its last `::`-separated segments. Blank entries are ignored; an unnamed thread is never listed.
fn test_listed(list: &str, thread: Option<&str>) -> bool {
    let Some(thread) = thread else {
        return false;
    };
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            thread == entry
                || thread
                    .strip_suffix(entry)
                    .is_some_and(|head| head.ends_with("::"))
        })
}

/// Stores `v` big-endian (network order) at `buf[at..at + 2]`.
fn write_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// The Internet checksum (RFC 1071) over `parts` taken as one byte string.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(hi) => sum += u64::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u64::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The TCP/UDP/ICMPv6 checksum over the pseudo-header and `l4` (whose checksum field must be
/// zero): source, destination, zero, protocol and length for IPv4 (RFC 9293 §3.1, RFC 768);
/// source, destination, 32-bit length, three zero bytes and next header for IPv6 (RFC 8200 §8.1,
/// which also covers ICMPv6, RFC 4443 §2.3). A computed UDP checksum of 0 goes out as 0xffff,
/// since 0 means "no checksum" (RFC 768; RFC 8200 §8.1).
fn l4_checksum(src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8], udp: bool) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, proto]);
            pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        }
        (s, d) => {
            pseudo.extend_from_slice(&as_v6(s).octets());
            pseudo.extend_from_slice(&as_v6(d).octets());
            pseudo.extend_from_slice(&(l4.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, proto]);
        }
    }
    let sum = checksum(&[&pseudo, l4]);
    if udp && sum == 0 { 0xffff } else { sum }
}

/// A 20-byte IPv4 header with its checksum (RFC 791 §3.1): version 4 and IHL 5 (0x45), TOS 0,
/// total length, Identification `id`, flags Don't Fragment (0x4000) with offset 0, the host's
/// default [`TTL`], and no options.
fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: usize, id: u16) -> Vec<u8> {
    let total = (20 + payload).min(65535) as u16;
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&0x4000u16.to_be_bytes());
    h.extend_from_slice(&[TTL, proto, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let sum = checksum(&[&h]);
    write_u16(&mut h, 10, sum);
    h
}

/// A 40-byte IPv6 header (RFC 8200 §3): version 6 (0x60), traffic class and flow label 0, payload
/// length, next header `proto`, and the host's default hop limit ([`TTL`]).
fn ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, payload: usize) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&(payload.min(65535) as u16).to_be_bytes());
    h.extend_from_slice(&[proto, TTL]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

/// A TCP header and payload with a zero checksum (RFC 9293 §3.1): data offset 5 words, or 6 with
/// an MSS option (kind 2, length 4, RFC 9293 §3.2), and a fixed window of 65535, the largest an
/// unscaled window can say (RFC 7323 §1.1) — a snare choice, since the capture models no window.
fn tcp_header(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let words: u8 = if mss.is_some() { 6 } else { 5 };
    let mut h = Vec::with_capacity(usize::from(words) * 4 + payload.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&ack.to_be_bytes());
    h.extend_from_slice(&[words << 4, flags]);
    h.extend_from_slice(&65535u16.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(mss) = mss {
        h.extend_from_slice(&[2, 4]);
        h.extend_from_slice(&mss.to_be_bytes());
    }
    h.extend_from_slice(payload);
    h
}

/// A UDP header and payload with a zero checksum (RFC 768): ports, length including the 8-byte
/// header.
fn udp_header(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(8 + data.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + data.len()).min(65535) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(data);
    h
}

/// `ip` as IPv6, an IPv4 address as its v4-mapped form (RFC 4291 §2.5.5.2).
fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// `ip` with a v4-mapped IPv6 address turned back into IPv4, as a dual-stack socket's traffic to
/// an IPv4 peer goes on the wire.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The addresses a frame between `a` and `b` carries: IPv4 when both are (v4-mapped included),
/// else IPv6.
fn wire_pair(a: IpAddr, b: IpAddr) -> (IpAddr, IpAddr) {
    match (unmapped(a), unmapped(b)) {
        (a @ IpAddr::V4(_), b @ IpAddr::V4(_)) => (a, b),
        (a, b) => (IpAddr::V6(as_v6(a)), IpAddr::V6(as_v6(b))),
    }
}

/// Whether a frame between `a` and `b` is IPv6 on the wire.
fn wire_v6(a: IpAddr, b: IpAddr) -> bool {
    wire_pair(a, b).0.is_ipv6()
}

/// FNV-1a, 64-bit (RFC 9923): a stable hash, unlike `std`'s randomly keyed one, so ISNs and
/// derived MACs repeat across runs.
struct Fnv(u64);

impl Fnv {
    /// Starts from the 64-bit FNV offset_basis (RFC 9923 §2.2, §5).
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }

    /// Hashes in `bytes`: XOR each octet, then multiply by the 64-bit FNV prime (RFC 9923 §2,
    /// §5).
    fn bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    /// Hashes in `ip`, v4-mapped addresses as their IPv4 form so both spellings hash alike.
    fn ip(&mut self, ip: IpAddr) {
        match unmapped(ip) {
            IpAddr::V4(v4) => self.bytes(&v4.octets()),
            IpAddr::V6(v6) => self.bytes(&v6.octets()),
        }
    }

    /// Hashes in `addr`'s IP and then its port, big-endian.
    fn addr(&mut self, addr: SocketAddr) {
        self.ip(addr.ip());
        self.bytes(&addr.port().to_be_bytes());
    }
}

/// The hardware address of `ip` on the wire when no interface of the sim owns it: a broadcast or
/// multicast address's group address, else a locally administered one hashed from the address.
/// Broadcast is ff:ff:ff:ff:ff:ff (RFC 894, "Broadcast Address"); IPv4 multicast is 01:00:5e
/// followed by the group's low 23 bits (RFC 1112 §6.4); IPv6 multicast is 33:33 followed by the
/// group's last four octets (RFC 2464 §7); otherwise 02 (the universal/local X bit set and the
/// group M bit clear, RFC 9542 §2.1.1) followed by five bytes of the address's FNV-1a hash.
fn derived_mac(ip: IpAddr, broadcast: bool) -> [u8; 6] {
    match unmapped(ip) {
        _ if broadcast => [0xff; 6],
        IpAddr::V4(v4) if v4.is_broadcast() => [0xff; 6],
        IpAddr::V4(v4) if v4.is_multicast() => {
            let o = v4.octets();
            [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]
        }
        IpAddr::V6(v6) if v6.is_multicast() => {
            let o = v6.octets();
            [0x33, 0x33, o[12], o[13], o[14], o[15]]
        }
        ip => {
            let mut h = Fnv::new();
            h.ip(ip);
            let b = h.0.to_be_bytes();
            [0x02, b[0], b[1], b[2], b[3], b[4]]
        }
    }
}

impl SimShared {
    /// The sim's capture, when it has one.
    pub(crate) fn capture(&self) -> Option<&Arc<Capture>> {
        self.capture.get()
    }

    /// The interface a frame from `src` to `dst` along `sender` is captured on, with each end's
    /// hardware address there: loopback for a host-local path, the egress interface of a routed
    /// one, and for a station (a tester or simulated host) the segment its address or the
    /// destination is on, falling back to loopback. Reads the topology's lock; callers run it
    /// before taking the capture's.
    pub(crate) fn wire_ends(
        &self,
        sender: &Sender,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> (Link, Station, Station) {
        let topo = self.topo();
        let index = match sender {
            Sender::Host(path) if path.local => topo.loopback_index(),
            Sender::Host(path) => path.egress,
            Sender::Station(ip) => topo
                .segment_of(*ip)
                .or_else(|| topo.segment_of(dst.ip()))
                .unwrap_or_else(|| topo.loopback_index()),
        };
        self.ends_on(&topo, index, src, dst)
    }

    /// The [`Link`] of interface `index` with each end's hardware address there: all zero on a
    /// loopback interface (as on Linux's `lo`, which drivers/net/loopback.c gives Ethernet
    /// headers through `eth_header_ops` but never a hardware address, so it stays zero; snare
    /// writes every interface, loopback included, as Ethernet), the address an interface of the
    /// sim owns, else [`derived_mac`]. An index the topology does not know is named `if<index>`
    /// with a 1500-byte MTU, Ethernet's (RFC 894).
    fn ends_on(
        &self,
        topo: &crate::netif::Topology,
        index: u32,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> (Link, Station, Station) {
        let (iface, mtu, loopback) = topo
            .wire_of(index)
            .unwrap_or_else(|| (format!("if{index}"), 1500, false));
        let mac = |ip: IpAddr| {
            if loopback {
                [0; 6]
            } else {
                topo.mac_of(unmapped(ip))
                    .unwrap_or_else(|| derived_mac(ip, topo.is_broadcast(unmapped(ip))))
            }
        };
        (
            Link { iface, mtu },
            Station {
                addr: src,
                mac: mac(src.ip()),
            },
            Station {
                addr: dst,
                mac: mac(dst.ip()),
            },
        )
    }

    /// The frames of a TCP connection from `client` to `server` along `sender`; `server_in` when
    /// the accepting end is not the code under test's.
    pub(crate) fn tcp_tap(
        &self,
        sender: &Sender,
        client: SocketAddr,
        server: SocketAddr,
        server_in: bool,
    ) -> Option<TcpTap> {
        let capture = self.capture()?.clone();
        let (link, c, s) = snare_interpose::real(|| self.wire_ends(sender, client, server));
        Some(TcpTap {
            capture,
            link,
            ends: [c, s],
            dirs: [Dir::Out, if server_in { Dir::In } else { Dir::Out }],
        })
    }

    /// Captures one datagram from `src` to `dst` along `sender`.
    pub(crate) fn capture_udp(
        &self,
        sender: &Sender,
        src: SocketAddr,
        dst: SocketAddr,
        dir: Dir,
        data: &[u8],
        at: Option<Duration>,
    ) {
        if let Some(capture) = self.capture() {
            let (link, s, d) = snare_interpose::real(|| self.wire_ends(sender, src, dst));
            capture.udp(&link, s, d, dir, data, at);
        }
    }

    /// Captures the ICMP port unreachable `unreachable` sends back to `src` for its datagram,
    /// `after` from now.
    pub(crate) fn capture_icmp(
        &self,
        sender: &Sender,
        src: SocketAddr,
        unreachable: SocketAddr,
        data: &[u8],
        after: Duration,
    ) {
        if let Some(capture) = self.capture() {
            let (link, s, d) = snare_interpose::real(|| self.wire_ends(sender, src, unreachable));
            capture.icmp_port_unreachable(&link, d, s, data, after);
        }
    }

    /// Captures a raw frame written on interface `index`.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn capture_l2(&self, index: u32, frame: &[u8]) {
        if let Some(capture) = self.capture() {
            let iface = snare_interpose::real(|| self.topo().name_of(index))
                .unwrap_or_else(|| format!("if{index}"));
            capture.l2(&iface, frame);
        }
    }

    /// Captures a raw frame written on the interface named `iface`.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn capture_l2_named(&self, iface: &str, frame: &[u8]) {
        if let Some(capture) = self.capture() {
            capture.l2(iface, frame);
        }
    }
}

/// Gives `shared` the capture its builder asked for at `path`, else the one the environment opts
/// into (see [`Capture::from_env`]); `wall_comment` is the builder's ask for wall-time comments,
/// which the environment can also turn on (see [`wall_comment`]). Panics when `path` cannot be
/// created.
pub(crate) fn attach(shared: &SimShared, path: Option<PathBuf>, wall_comment: bool) {
    let wall_comment = self::wall_comment(wall_comment);
    let capture = match path {
        Some(path) => match Capture::create(path.clone(), shared, wall_comment) {
            Ok(capture) => Some(capture),
            Err(e) => panic!("cannot create pcapng capture {}: {e}", path.display()),
        },
        None => Capture::from_env(shared, wall_comment),
    };
    if let Some(capture) = capture {
        let _ = shared.capture.set(capture);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The little-endian u32 at `b[at..at + 4]`.
    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// A writer with no file, for building frames without writing them.
    fn writer() -> Writer {
        Writer {
            out: None,
            pending: BinaryHeap::new(),
            frames: HashMap::new(),
            next_frame: 0,
            flows: HashMap::new(),
            plans: HashMap::new(),
            #[cfg(target_os = "macos")]
            resets: HashMap::new(),
            last: 0,
            ip_id: HashMap::new(),
            links: HashMap::new(),
            finished: false,
            wall_comment: false,
            now: 0,
        }
    }

    /// A tap on `eth0` from `client` (outbound) to `server` (inbound).
    fn tap(capture: Arc<Capture>, mtu: u32, client: &str, server: &str) -> TcpTap {
        TcpTap {
            capture,
            link: Link {
                iface: "eth0".into(),
                mtu,
            },
            ends: [
                Station {
                    addr: client.parse().unwrap(),
                    mac: [2, 0, 0, 0, 0, 1],
                },
                Station {
                    addr: server.parse().unwrap(),
                    mac: [2, 0, 0, 0, 0, 2],
                },
            ],
            dirs: [Dir::Out, Dir::In],
        }
    }

    /// A capture at `path` for a sim with `seed` and a virtual clock.
    fn capture_at(path: PathBuf, seed: u64) -> Arc<Capture> {
        let shared = SimShared::new(seed, Some(Arc::new(Clock::new(37))));
        Capture::create(path, &shared, false).unwrap()
    }

    /// A per-process scratch capture path in the temporary directory.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "snare-pcapng-unit-{}-{name}.pcapng",
            std::process::id()
        ))
    }

    /// Splits a capture into (block type, body) pairs, checking each block's trailing length.
    fn blocks(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let kind = le32(bytes, at);
            let len = le32(bytes, at + 4) as usize;
            assert_eq!(le32(bytes, at + len - 4) as usize, len);
            out.push((kind, bytes[at + 8..at + len - 4].to_vec()));
            at += len;
        }
        out
    }

    #[test]
    fn shb_idb_epb_layout() {
        let shb = shb();
        assert_eq!(le32(&shb, 0), BLOCK_SHB);
        assert_eq!(le32(&shb, 8), BYTE_ORDER_MAGIC);
        assert_eq!(&shb[12..16], &[1, 0, 0, 0]);
        assert_eq!(shb.len() % 4, 0);
        let idb = idb("eth0");
        assert_eq!(le32(&idb, 0), BLOCK_IDB);
        assert_eq!(&idb[8..10], &LINKTYPE_ETHERNET.to_le_bytes());
        assert_eq!(le32(&idb, 12), 0, "snaplen 0");
        assert_eq!(&idb[16..24], &[2, 0, 4, 0, b'e', b't', b'h', b'0']);
        assert_eq!(&idb[24..28], &[9, 0, 1, 0]);
        assert_eq!(idb[28], 9);
        let frame = Frame {
            iface: "eth0".into(),
            dir: Dir::In,
            bytes: vec![1, 2, 3],
            orig_len: 70000,
            plan: None,
            #[cfg(target_os = "macos")]
            ack: None,
            wall: None,
        };
        let epb = epb(3, 0x1_0000_0002, &frame, None);
        assert_eq!(le32(&epb, 0), BLOCK_EPB);
        assert_eq!(le32(&epb, 8), 3);
        assert_eq!(le32(&epb, 12), 1);
        assert_eq!(le32(&epb, 16), 2);
        assert_eq!(le32(&epb, 20), 3);
        assert_eq!(le32(&epb, 24), 70000);
        assert_eq!(&epb[28..32], &[1, 2, 3, 0]);
        assert_eq!(&epb[32..36], &[2, 0, 4, 0]);
        assert_eq!(le32(&epb, 36), 1, "inbound");
        assert_eq!(le32(&epb, 4) as usize, epb.len());
    }

    #[test]
    fn ipv4_header_checksum_known_value() {
        // 45 00 00 73 00 00 40 00 40 11 .. .. c0 a8 00 01 c0 a8 00 c7 sums to 0xb861, the usual
        // worked example of the IPv4 header checksum.
        let h = {
            let mut h = ipv4_header(
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 199),
                PROTO_UDP,
                0x73 - 20,
                0,
            );
            h[8] = 64;
            write_u16(&mut h, 10, 0);
            let sum = checksum(&[&h]);
            write_u16(&mut h, 10, sum);
            h
        };
        assert_eq!(&h[10..12], &[0xb8, 0x61]);
        assert_eq!(checksum(&[&h]), 0);
    }

    #[test]
    fn tcp_and_udp_checksums_verify() {
        let (s, d): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let mut tcp = tcp_header(1000, 80, 7, 9, PSH | ACK, None, b"hello");
        let sum = l4_checksum(s, d, PROTO_TCP, &tcp, false);
        write_u16(&mut tcp, 16, sum);
        assert_eq!(l4_checksum(s, d, PROTO_TCP, &tcp, false), 0);
        let (s6, d6): (IpAddr, IpAddr) = ("fe80::1".parse().unwrap(), "fe80::2".parse().unwrap());
        let mut udp = udp_header(5, 6, b"odd");
        let sum = l4_checksum(s6, d6, PROTO_UDP, &udp, true);
        write_u16(&mut udp, 6, sum);
        let check = l4_checksum(s6, d6, PROTO_UDP, &udp, false);
        assert!(check == 0 || check == 0xffff);
    }

    #[test]
    fn macs() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(derived_mac(ip("255.255.255.255"), false), [0xff; 6]);
        assert_eq!(derived_mac(ip("10.0.0.255"), true), [0xff; 6]);
        assert_eq!(
            derived_mac(ip("239.129.2.3"), false),
            [0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]
        );
        assert_eq!(
            derived_mac(ip("ff02::1:ff00:1234"), false),
            [0x33, 0x33, 0xff, 0x00, 0x12, 0x34]
        );
        let a = derived_mac(ip("10.0.0.7"), false);
        assert_eq!(a[0], 0x02);
        assert_eq!(a, derived_mac(ip("::ffff:10.0.0.7"), false));
        assert_ne!(a, derived_mac(ip("10.0.0.8"), false));
    }

    #[test]
    fn v4_mapped_pair_written_as_ipv4() {
        let (a, b) = wire_pair(
            "::ffff:10.0.0.1".parse().unwrap(),
            "::ffff:10.0.0.2".parse().unwrap(),
        );
        assert_eq!(a, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(b, "10.0.0.2".parse::<IpAddr>().unwrap());
        let mut w = writer();
        let src = Station {
            addr: "[::ffff:10.0.0.1]:5".parse().unwrap(),
            mac: [0; 6],
        };
        let dst = Station {
            addr: "[::ffff:10.0.0.2]:6".parse().unwrap(),
            mac: [0; 6],
        };
        let link = Link {
            iface: "lo".into(),
            mtu: 1500,
        };
        w.ip_frame(
            &link,
            src,
            dst,
            Dir::Out,
            PROTO_UDP,
            udp_header(5, 6, b"x"),
            0,
            None,
        );
        let frame = &w.frames[&0];
        assert_eq!(&frame.bytes[12..14], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&frame.bytes[26..30], &[10, 0, 0, 1]);
    }

    #[test]
    fn pending_heap_keeps_time_order() {
        let path = scratch("heap");
        let capture = capture_at(path.clone(), 1);
        let t = tap(capture.clone(), 1500, "10.0.0.1:40000", "10.0.0.2:80");
        t.syn();
        t.syn_plan(&[Duration::from_secs(3), Duration::from_secs(1)]);
        capture.finish();
        let bytes = std::fs::read(&path).unwrap();
        let stamps: Vec<u64> = blocks(&bytes)
            .into_iter()
            .filter(|(k, _)| *k == BLOCK_EPB)
            .map(|(_, b)| (u64::from(le32(&b, 4)) << 32) | u64::from(le32(&b, 8)))
            .collect();
        let base = 1_700_000_000u64 * 1_000_000_000;
        assert_eq!(stamps, [base, base + 1_000_000_000, base + 3_000_000_000]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tcp_write_larger_than_mss_is_segmented() {
        let path = scratch("mss");
        let capture = capture_at(path.clone(), 1);
        let t = tap(capture.clone(), 1500, "10.0.0.1:40000", "10.0.0.2:80");
        t.open(false, Duration::ZERO);
        t.data(0, &vec![7u8; 3000], Duration::ZERO);
        capture.finish();
        let bytes = std::fs::read(&path).unwrap();
        let lens: Vec<usize> = blocks(&bytes)
            .into_iter()
            .filter(|(k, _)| *k == BLOCK_EPB)
            .map(|(_, b)| le32(&b, 12) as usize - 54)
            .collect();
        assert_eq!(lens, [4, 4, 0, 1460, 1460, 80, 0]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn isn_depends_on_seed_and_flow_not_order() {
        let a = capture_at(scratch("isn-a"), 7);
        let b = capture_at(scratch("isn-b"), 7);
        let c = capture_at(scratch("isn-c"), 8);
        let f1: (SocketAddr, SocketAddr) =
            ("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
        let f2: (SocketAddr, SocketAddr) =
            ("10.0.0.1:3".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
        let first = (a.isn(f1), a.isn(f2));
        let second = (b.isn(f2), b.isn(f1));
        assert_eq!(first, (second.1, second.0));
        assert_ne!(a.isn(f1), c.isn(f1));
        assert_ne!(a.isn(f1), a.isn(f2));
        for name in ["isn-a", "isn-b", "isn-c"] {
            let _ = std::fs::remove_file(scratch(name));
        }
    }

    #[test]
    fn epb_comment_follows_flags_padded() {
        let frame = Frame {
            iface: "eth0".into(),
            dir: Dir::Out,
            bytes: vec![1, 2, 3, 4],
            orig_len: 4,
            plan: None,
            #[cfg(target_os = "macos")]
            ack: None,
            wall: None,
        };
        let epb = epb(0, 0, &frame, Some("wall x"));
        assert_eq!(&epb[32..36], &[2, 0, 4, 0], "epb_flags");
        assert_eq!(le32(&epb, 36), 2, "outbound");
        assert_eq!(&epb[40..44], &[1, 0, 6, 0], "opt_comment, 6 bytes");
        assert_eq!(&epb[44..52], b"wall x\0\0");
        assert_eq!(&epb[52..56], &[0, 0, 0, 0], "opt_endofopt");
        assert_eq!(le32(&epb, 4) as usize, epb.len());
    }

    #[test]
    fn wall_text_is_rfc3339_utc() {
        assert_eq!(
            wall_text(Duration::ZERO),
            "wall 1970-01-01T00:00:00.000000000Z"
        );
        // 2000-02-29 is day 11016 after the epoch; 951782400 s.
        assert_eq!(
            wall_text(Duration::new(951_782_400 + 3_723, 5)),
            "wall 2000-02-29T01:02:03.000000005Z"
        );
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_728), (2026, 10, 2));
        assert_eq!(civil_from_days(11_016 + 306), (2000, 12, 31));
    }

    #[test]
    fn test_list_matches_whole_names_and_trailing_segments() {
        assert!(test_listed("a, b", Some("b")));
        assert!(test_listed("mod::t", Some("mod::t")));
        assert!(test_listed("t", Some("mod::t")));
        assert!(test_listed("inner::t", Some("outer::inner::t")));
        assert!(!test_listed("t", Some("mod::not_t")));
        assert!(!test_listed("t", Some("tt")));
        assert!(!test_listed(" , ", Some("t")));
        assert!(!test_listed("t", None));
    }

    #[test]
    fn io_error_disables_capture_without_panicking() {
        let capture = capture_at(scratch("ioerr"), 1);
        {
            let mut w = capture.inner.lock().unwrap();
            let file = File::open(scratch("ioerr")).unwrap();
            w.out = Some(BufWriter::with_capacity(0, file));
        }
        let t = tap(capture.clone(), 1500, "10.0.0.1:40000", "10.0.0.2:80");
        t.open(false, Duration::ZERO);
        assert!(capture.inner.lock().unwrap().out.is_none());
        t.data(0, b"more", Duration::ZERO);
        capture.finish();
        let _ = std::fs::remove_file(scratch("ioerr"));
    }
}
