//! A `SimHost` NIC's driver through `SIOCETHTOOL`, driven with the exact call shapes
//! fast-talker's `nic::linux` and `nic::flow` use: whole command structs as `u32` words,
//! `ethtool_rxnfc` as raw bytes. Command numbers and layouts are include/uapi/linux/ethtool.h;
//! the rules are net/ethtool/ioctl.c (Linux 6.12).

#![cfg(target_os = "linux")]

use snare::{
    CAP_NET_ADMIN, Channels, Coalesce, CoalesceParams, Eee, HostProfile, Nic, Pause, Rings, Sim,
};

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GDRVINFO: u32 = 0x03;
const ETHTOOL_GLINK: u32 = 0x0a;
const ETHTOOL_GCOALESCE: u32 = 0x0e;
const ETHTOOL_SCOALESCE: u32 = 0x0f;
const ETHTOOL_GRINGPARAM: u32 = 0x10;
const ETHTOOL_SRINGPARAM: u32 = 0x11;
const ETHTOOL_GPAUSEPARAM: u32 = 0x12;
const ETHTOOL_SPAUSEPARAM: u32 = 0x13;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSTATS: u32 = 0x1d;
const ETHTOOL_GFLAGS: u32 = 0x25;
const ETHTOOL_SFLAGS: u32 = 0x26;
const ETHTOOL_GRXCLSRLCNT: u32 = 0x2e;
const ETHTOOL_GRXCLSRULE: u32 = 0x2f;
const ETHTOOL_GRXCLSRLALL: u32 = 0x30;
const ETHTOOL_SRXCLSRLDEL: u32 = 0x31;
const ETHTOOL_SRXCLSRLINS: u32 = 0x32;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GCHANNELS: u32 = 0x3c;
const ETHTOOL_SCHANNELS: u32 = 0x3d;
const ETHTOOL_GEEE: u32 = 0x44;
const ETHTOOL_SEEE: u32 = 0x45;
const ETH_FLAG_NTUPLE: u32 = 1 << 27;
const ETH_FLAG_LRO: u32 = 1 << 15;
const UDP_V4_FLOW: u32 = 0x02;

#[repr(C)]
struct Ifreq {
    name: [libc::c_char; 16],
    data: usize,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Runs one ethtool command on `eth0` over a fresh control socket: `Ok` or the errno.
fn ethtool(data: *mut u8) -> Result<(), i32> {
    ethtool_on("eth0", data)
}

/// Runs one ethtool command on interface `name`.
fn ethtool_on(name: &str, data: *mut u8) -> Result<(), i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    let mut req = Ifreq {
        name: [0; 16],
        data: data as usize,
    };
    for (i, b) in name.bytes().enumerate() {
        req.name[i] = b as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) };
    let e = errno();
    unsafe { libc::close(fd) };
    if rc == 0 { Ok(()) } else { Err(e) }
}

fn get<const N: usize>(cmd: u32) -> Result<[u32; N], i32> {
    let mut w = [0u32; N];
    w[0] = cmd;
    ethtool(w.as_mut_ptr().cast())?;
    Ok(w)
}

fn set<const N: usize>(mut w: [u32; N]) -> Result<(), i32> {
    ethtool(w.as_mut_ptr().cast())
}

/// An I350-like port: igb's ring limits, `ETHTOOL_COALESCE_USECS` only, 8 queue pairs, EEE and
/// a 16-slot flow table (drivers/net/ethernet/intel/igb).
fn tuned_nic() -> Nic {
    Nic::new("eth0", 3)
        .driver("igb", "6.12.0")
        .bus_info("0000:03:00.0")
        .firmware("1.63, 0x80000f3a")
        .expansion_rom("1.1824.0")
        .rings(Rings {
            rx_max: 4096,
            tx_max: 4096,
            rx: 256,
            tx: 256,
            ..Rings::default()
        })
        .coalesce(
            CoalesceParams::USECS,
            Coalesce {
                rx_usecs: 3,
                tx_usecs: 3,
                ..Coalesce::default()
            },
        )
        .coalesce_limits(10_000, u32::MAX)
        .channels(Channels {
            combined_max: 8,
            other_max: 1,
            combined: 4,
            other: 1,
            ..Channels::default()
        })
        .pause(Pause {
            autoneg: true,
            rx: true,
            tx: true,
        })
        .eee(Eee {
            supported: 0x28,
            advertised: 0x28,
            lp_advertised: 0x28,
            enabled: true,
            tx_lpi_enabled: true,
            ..Eee::default()
        })
        .ntuple(16)
        .driver_stats([("rx_packets", 10), ("rx_no_buffer_count", 2)])
}

fn admin_host() -> std::sync::Arc<snare::SimHost> {
    HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(tuned_nic())
        .build()
}

fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

#[test]
fn drvinfo_reports_firmware_rom_and_stat_count() {
    Sim::builder().host(admin_host()).build().run(|| {
        let mut info = [0u8; 196];
        info[..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
        ethtool(info.as_mut_ptr()).unwrap();
        assert_eq!(c_str(&info[4..36]), "igb");
        assert_eq!(c_str(&info[36..68]), "6.12.0");
        assert_eq!(c_str(&info[68..100]), "1.63, 0x80000f3a");
        assert_eq!(c_str(&info[100..132]), "0000:03:00.0");
        assert_eq!(c_str(&info[132..164]), "1.1824.0");
        assert_eq!(
            u32::from_ne_bytes(info[180..184].try_into().unwrap()),
            2,
            "n_stats"
        );
    });
}

#[test]
fn link_follows_the_topology() {
    let sim = Sim::builder().host(admin_host()).build();
    sim.run(|| assert_eq!(get::<2>(ETHTOOL_GLINK).unwrap()[1], 1));
    sim.set_link("eth0", false).unwrap();
    sim.run(|| assert_eq!(get::<2>(ETHTOOL_GLINK).unwrap()[1], 0));
}

#[test]
fn rings_resize_within_their_maxima_and_persist() {
    let host = admin_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let w = get::<9>(ETHTOOL_GRINGPARAM).unwrap();
        assert_eq!(w, [ETHTOOL_GRINGPARAM, 4096, 0, 0, 4096, 256, 0, 0, 256]);
        let mut s = w;
        s[0] = ETHTOOL_SRINGPARAM;
        s[5] = 4097;
        assert_eq!(set(s), Err(libc::EINVAL), "above rx_max_pending");
        s[5] = 1024;
        s[6] = 1;
        assert_eq!(set(s), Err(libc::EINVAL), "above rx_mini_max_pending (0)");
        s[6] = 0;
        s[1] = 1;
        s[8] = 2048;
        set(s).unwrap();
        let w = get::<9>(ETHTOOL_GRINGPARAM).unwrap();
        assert_eq!(
            (w[1], w[5], w[8]),
            (4096, 1024, 2048),
            "the *_max fields given are ignored"
        );
    });
    let rings = host.ethtool("eth0").unwrap().rings.unwrap();
    assert_eq!((rings.rx, rings.tx), (1024, 2048));
}

#[test]
fn coalescing_rejects_unsupported_fields_and_out_of_range_values() {
    let host = admin_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let w = get::<23>(ETHTOOL_GCOALESCE).unwrap();
        assert_eq!((w[1], w[5]), (3, 3));
        let mut s = w;
        s[0] = ETHTOOL_SCOALESCE;
        s[2] = 8;
        assert_eq!(set(s), Err(libc::EOPNOTSUPP), "rx-frames is not supported");
        s[2] = 0;
        s[10] = 1;
        assert_eq!(
            set(s),
            Err(libc::EOPNOTSUPP),
            "adaptive-rx is not supported"
        );
        s[10] = 0;
        s[1] = 10_001;
        assert_eq!(set(s), Err(libc::EINVAL), "above the driver's usecs limit");
        s[1] = 50;
        s[5] = 0;
        set(s).unwrap();
        let w = get::<23>(ETHTOOL_GCOALESCE).unwrap();
        assert_eq!((w[1], w[5]), (50, 0));
    });
    let (_, c) = host.ethtool("eth0").unwrap().coalesce.unwrap();
    assert_eq!(c.rx_usecs, 50);
}

#[test]
fn channels_resize_the_queues() {
    let host = admin_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let w = get::<9>(ETHTOOL_GCHANNELS).unwrap();
        assert_eq!(w, [ETHTOOL_GCHANNELS, 0, 0, 1, 8, 0, 0, 1, 4]);
        let queues = |dir: &str| {
            std::fs::read_dir("/sys/class/net/eth0/queues")
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(dir)
                })
                .count()
        };
        assert_eq!((queues("rx-"), queues("tx-")), (4, 4));
        let mut s = w;
        s[0] = ETHTOOL_SCHANNELS;
        s[8] = 9;
        assert_eq!(set(s), Err(libc::EINVAL), "above max_combined");
        s[8] = 0;
        s[5] = 1;
        assert_eq!(set(s), Err(libc::EINVAL), "an RX queue but no TX queue");
        s[5] = 0;
        s[8] = 2;
        set(s).unwrap();
        assert_eq!(get::<9>(ETHTOOL_GCHANNELS).unwrap()[8], 2);
        assert_eq!((queues("rx-"), queues("tx-")), (2, 2));
    });
    assert_eq!(host.ethtool("eth0").unwrap().channels.unwrap().combined, 2);
}

#[test]
fn pause_and_eee_persist() {
    let host = admin_host();
    Sim::builder().host(host.clone()).build().run(|| {
        assert_eq!(
            get::<4>(ETHTOOL_GPAUSEPARAM).unwrap(),
            [ETHTOOL_GPAUSEPARAM, 1, 1, 1]
        );
        set([ETHTOOL_SPAUSEPARAM, 0, 1, 0]).unwrap();
        assert_eq!(
            get::<4>(ETHTOOL_GPAUSEPARAM).unwrap(),
            [ETHTOOL_GPAUSEPARAM, 0, 1, 0]
        );

        let w = get::<10>(ETHTOOL_GEEE).unwrap();
        assert_eq!(
            (w[4], w[5], w[6]),
            (1, 1, 1),
            "active, enabled, tx_lpi_enabled"
        );
        let mut s = w;
        s[0] = ETHTOOL_SEEE;
        s[2] = 0x1000;
        assert_eq!(
            set(s),
            Err(libc::EINVAL),
            "advertising a mode EEE does not support"
        );
        s[2] = 0x28;
        s[5] = 0;
        s[6] = 0;
        set(s).unwrap();
        let w = get::<10>(ETHTOOL_GEEE).unwrap();
        assert_eq!((w[4], w[5], w[6]), (0, 0, 0));
    });
    let e = host.ethtool("eth0").unwrap();
    assert!(!e.eee.unwrap().enabled);
    assert_eq!(
        e.pause.unwrap(),
        Pause {
            autoneg: false,
            rx: true,
            tx: false
        }
    );
}

/// `struct ethtool_rxnfc` with room for `locs` rule locations, as fast-talker's `Rxnfc` (192
/// bytes) plus its `rule_locs` tail.
fn rxnfc(cmd: u32, locs: usize) -> Vec<u8> {
    let mut b = vec![0u8; 192 + 4 * locs];
    b[..4].copy_from_slice(&cmd.to_ne_bytes());
    b
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn insert_rule(location: u32, queue: u64) -> Result<(), i32> {
    let mut r = rxnfc(ETHTOOL_SRXCLSRLINS, 0);
    put_u32(&mut r, 16, UDP_V4_FLOW);
    r[16 + 4 + 10..16 + 4 + 12].copy_from_slice(&319u16.to_be_bytes());
    r[16 + 152..16 + 160].copy_from_slice(&queue.to_ne_bytes());
    put_u32(&mut r, 16 + 160, location);
    ethtool(r.as_mut_ptr())
}

#[test]
fn ntuple_flag_and_flow_rules() {
    let host = admin_host();
    Sim::builder().host(host.clone()).build().run(|| {
        assert_eq!(get::<2>(ETHTOOL_GFLAGS).unwrap()[1], 0);
        assert_eq!(
            set([ETHTOOL_SFLAGS, ETH_FLAG_LRO]),
            Err(libc::EOPNOTSUPP),
            "no LRO"
        );
        assert_eq!(
            set([ETHTOOL_SFLAGS, ETH_FLAG_LRO | ETH_FLAG_NTUPLE]),
            Err(libc::EINVAL),
            "a change outside hw_features alongside one inside"
        );
        assert_eq!(
            set([ETHTOOL_SFLAGS, 1]),
            Err(libc::EINVAL),
            "not an ETH_FLAG_*"
        );
        set([ETHTOOL_SFLAGS, ETH_FLAG_NTUPLE]).unwrap();
        assert_eq!(get::<2>(ETHTOOL_GFLAGS).unwrap()[1], ETH_FLAG_NTUPLE);

        assert_eq!(
            insert_rule(16, 0),
            Err(libc::EINVAL),
            "past the 16-slot table"
        );
        assert_eq!(insert_rule(0, 4), Err(libc::EINVAL), "queue 4 of 4");
        insert_rule(5, 3).unwrap();
        insert_rule(1, 0).unwrap();

        let mut cnt = rxnfc(ETHTOOL_GRXCLSRLCNT, 0);
        ethtool(cnt.as_mut_ptr()).unwrap();
        assert_eq!(
            (u32_at(&cnt, 184), u32_at(&cnt, 8)),
            (2, 16),
            "rule_cnt, table size"
        );

        let mut small = rxnfc(ETHTOOL_GRXCLSRLALL, 1);
        put_u32(&mut small, 184, 1);
        assert_eq!(ethtool(small.as_mut_ptr()), Err(libc::EMSGSIZE));
        let mut all = rxnfc(ETHTOOL_GRXCLSRLALL, 2);
        put_u32(&mut all, 184, 2);
        ethtool(all.as_mut_ptr()).unwrap();
        assert_eq!((u32_at(&all, 188), u32_at(&all, 192)), (1, 5));

        let mut one = rxnfc(ETHTOOL_GRXCLSRULE, 0);
        put_u32(&mut one, 16 + 160, 5);
        ethtool(one.as_mut_ptr()).unwrap();
        assert_eq!(u32_at(&one, 16), UDP_V4_FLOW);
        assert_eq!(u64::from_ne_bytes(one[168..176].try_into().unwrap()), 3);
        assert_eq!(
            &one[16 + 14..16 + 16],
            &319u16.to_be_bytes(),
            "udp_ip4_spec.pdst"
        );

        let mut ch = get::<9>(ETHTOOL_GCHANNELS).unwrap();
        ch[0] = ETHTOOL_SCHANNELS;
        ch[8] = 3;
        assert_eq!(set(ch), Err(libc::EINVAL), "a rule steers to queue 3");

        let mut del = rxnfc(ETHTOOL_SRXCLSRLDEL, 0);
        put_u32(&mut del, 16 + 160, 5);
        ethtool(del.as_mut_ptr()).unwrap();
        assert_eq!(
            ethtool(del.as_mut_ptr()),
            Err(libc::EINVAL),
            "already empty"
        );
        set(ch).unwrap();
    });
    let e = host.ethtool("eth0").unwrap();
    assert_eq!(e.flow_rules.keys().copied().collect::<Vec<_>>(), vec![1]);
    assert_eq!(e.features, ETH_FLAG_NTUPLE);
}

#[test]
fn driver_statistics_follow_the_host() {
    let host = admin_host();
    let sim = Sim::builder().host(host.clone()).build();
    let read = || {
        let mut info = [0u32; 5];
        info[0] = ETHTOOL_GSSET_INFO;
        info[2] = 1 << 1;
        ethtool(info.as_mut_ptr().cast()).unwrap();
        assert_eq!(info[2], 1 << 1, "ETH_SS_STATS is counted");
        let n = info[4] as usize;
        let mut strings = vec![0u32; 3 + n * 8];
        strings[0] = ETHTOOL_GSTRINGS;
        strings[1] = 1;
        ethtool(strings.as_mut_ptr().cast()).unwrap();
        assert_eq!(strings[2] as usize, n);
        let bytes: Vec<u8> = strings[3..].iter().flat_map(|w| w.to_ne_bytes()).collect();
        let names: Vec<String> = bytes.chunks(32).map(c_str).collect();
        let mut stats = vec![0u64; 1 + n];
        stats[0] = u64::from(ETHTOOL_GSTATS);
        ethtool(stats.as_mut_ptr().cast()).unwrap();
        names
            .into_iter()
            .zip(stats[1..].iter().copied())
            .collect::<Vec<_>>()
    };
    let before = sim.run(read);
    assert_eq!(
        before,
        vec![
            ("rx_packets".to_string(), 10),
            ("rx_no_buffer_count".to_string(), 2)
        ]
    );
    assert!(host.set_driver_stat("eth0", "rx_no_buffer_count", 7));
    assert_eq!(sim.run(read)[1].1, 7);
}

#[test]
fn setters_need_net_admin_and_missing_operations_are_eopnotsupp() {
    let host = HostProfile::new().nic(tuned_nic()).build();
    Sim::builder().host(host).build().run(|| {
        let rings = get::<9>(ETHTOOL_GRINGPARAM).unwrap();
        let mut s = rings;
        s[0] = ETHTOOL_SRINGPARAM;
        assert_eq!(set(s), Err(libc::EPERM));
        assert_eq!(set([ETHTOOL_SPAUSEPARAM, 0, 0, 0]), Err(libc::EPERM));
        assert_eq!(
            get::<2>(0x7777),
            Err(libc::EPERM),
            "an unknown command is a setter"
        );
        get::<23>(ETHTOOL_GCOALESCE).unwrap();
        get::<10>(ETHTOOL_GEEE).unwrap();
    });
    let bare = HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(Nic::new("eth0", 3))
        .build();
    Sim::builder().host(bare).build().run(|| {
        for cmd in [
            ETHTOOL_GRINGPARAM,
            ETHTOOL_GCOALESCE,
            ETHTOOL_GCHANNELS,
            ETHTOOL_GPAUSEPARAM,
            ETHTOOL_GEEE,
        ] {
            assert_eq!(
                get::<23>(cmd).map(drop),
                Err(libc::EOPNOTSUPP),
                "command {cmd:#x}"
            );
        }
        assert_eq!(get::<5>(ETHTOOL_GSTATS).map(drop), Err(libc::EOPNOTSUPP));
        assert_eq!(
            set([ETHTOOL_SFLAGS, ETH_FLAG_NTUPLE]),
            Err(libc::EOPNOTSUPP)
        );
        let mut cnt = rxnfc(ETHTOOL_GRXCLSRLCNT, 0);
        assert_eq!(ethtool(cnt.as_mut_ptr()), Err(libc::EOPNOTSUPP));
        assert_eq!(get::<2>(ETHTOOL_GLINK).unwrap()[1], 1);
    });
}

#[test]
fn tuning_is_deterministic() {
    let run = || {
        let host = admin_host();
        Sim::builder()
            .host(host.clone())
            .deterministic()
            .build()
            .run(|| {
                let workers: Vec<_> = (0..3u32)
                    .map(|i| {
                        std::thread::spawn(move || {
                            let mut s = get::<9>(ETHTOOL_GRINGPARAM).unwrap();
                            s[0] = ETHTOOL_SRINGPARAM;
                            s[5] = 512 * (i + 1);
                            set(s).unwrap();
                        })
                    })
                    .collect();
                for w in workers {
                    w.join().unwrap();
                }
            });
        host.ethtool("eth0").unwrap().rings.unwrap().rx
    };
    assert_eq!(run(), run());
}

const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const TC_H_ROOT: u32 = 0xffff_ffff;
const TC_ETF_OFFLOAD_ON: u32 = 2;

fn put_attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A `NETLINK_ROUTE` socket.
fn route_socket() -> i32 {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    assert!(fd >= 0);
    fd
}

/// Sends one rtnetlink request with a `struct tcmsg` body, as fast-talker's `Netlink::request`
/// builds it.
fn send(fd: i32, ty: u16, flags: u16, ifindex: u32, handle: u32, parent: u32, attrs: &[u8]) {
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&parent.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend_from_slice(attrs);
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&ty.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    msg.extend_from_slice(&7u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&body);
    assert_eq!(
        unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) },
        msg.len() as isize
    );
}

/// The messages `(type, body)` of the next reply on `fd`.
fn receive(fd: i32) -> Vec<(u16, Vec<u8>)> {
    let mut buf = vec![0u8; 16384];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert!(n > 0);
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= n as usize {
        let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
        let t = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
        out.push((t, buf[at + 16..at + len].to_vec()));
        at += len.next_multiple_of(4);
    }
    out
}

/// One request on a fresh socket and its reply.
fn rtnl(
    ty: u16,
    flags: u16,
    ifindex: u32,
    handle: u32,
    parent: u32,
    attrs: &[u8],
) -> Vec<(u16, Vec<u8>)> {
    let fd = route_socket();
    send(fd, ty, flags, ifindex, handle, parent, attrs);
    let reply = receive(fd);
    unsafe { libc::close(fd) };
    reply
}

/// The errno of an acked change, 0 for success.
fn change(ty: u16, ifindex: u32, handle: u32, parent: u32, attrs: &[u8]) -> i32 {
    let r = rtnl(
        ty,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        ifindex,
        handle,
        parent,
        attrs,
    );
    assert_eq!(r[0].0, NLMSG_ERROR);
    -i32::from_ne_bytes(r[0].1[..4].try_into().unwrap())
}

/// `(handle, parent, kind, etf flags)` of each qdisc on `ifindex`.
fn qdiscs(ifindex: u32) -> Vec<(u32, u32, String, Option<u32>)> {
    let reply = rtnl(RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, &[]);
    assert_eq!(reply.last().unwrap().0, NLMSG_DONE);
    reply
        .iter()
        .filter(|(t, b)| {
            *t == RTM_NEWQDISC && u32::from_ne_bytes(b[4..8].try_into().unwrap()) == ifindex
        })
        .map(|(_, b)| {
            let word = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
            let mut kind = String::new();
            let mut etf = None;
            let mut at = 20;
            while at + 4 <= b.len() {
                let len = u16::from_ne_bytes(b[at..at + 2].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(b[at + 2..at + 4].try_into().unwrap());
                if ty == 1 {
                    kind = c_str(&b[at + 4..at + len]);
                }
                if ty == 2 {
                    etf = Some(u32::from_ne_bytes(b[at + 16..at + 20].try_into().unwrap()));
                }
                at += len.next_multiple_of(4);
            }
            (word(8), word(12), kind, etf)
        })
        .collect()
}

fn etf_attrs(clockid: i32, flags: u32) -> Vec<u8> {
    let mut parms = Vec::new();
    parms.extend_from_slice(&300_000i32.to_ne_bytes());
    parms.extend_from_slice(&clockid.to_ne_bytes());
    parms.extend_from_slice(&flags.to_ne_bytes());
    let mut options = Vec::new();
    put_attr(&mut options, 1, &parms);
    let mut attrs = Vec::new();
    put_attr(&mut attrs, 1, b"etf\0");
    put_attr(&mut attrs, 2, &options);
    attrs
}

#[test]
fn etf_offload_on_a_queue_under_mq() {
    let nic = tuned_nic().etf_offload([0, 1]);
    let host = HostProfile::new().cap(CAP_NET_ADMIN).nic(nic).build();
    Sim::builder().host(host).build().run(|| {
        let q = qdiscs(3);
        assert_eq!(q.len(), 5, "mq over the 4 queues' default qdiscs");
        assert_eq!((q[0].0, q[0].1, q[0].2.as_str()), (0, TC_H_ROOT, "mq"));
        assert_eq!((q[1].1, q[1].2.as_str()), (1, "fq_codel"));

        let mut mq = Vec::new();
        put_attr(&mut mq, 1, b"mq\0");
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0x7ff0_0000,
                0x7ff0_0003,
                &etf_attrs(libc::CLOCK_TAI, 0)
            ),
            libc::ENOENT,
            "no 7ff0: yet"
        );
        assert_eq!(change(RTM_NEWQDISC, 3, 0x7ff0_0000, TC_H_ROOT, &mq), 0);
        assert_eq!(qdiscs(3)[1].1, 0x7ff0_0001);

        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                0x7ff0_0003,
                &etf_attrs(libc::CLOCK_TAI, TC_ETF_OFFLOAD_ON)
            ),
            libc::EINVAL,
            "queue 2 cannot launch"
        );
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                0x7ff0_0001,
                &etf_attrs(libc::CLOCK_REALTIME, 0)
            ),
            libc::EINVAL,
            "CLOCK_TAI only"
        );
        assert_eq!(
            change(RTM_NEWQDISC, 3, 0, 0x7ff0_0001, &etf_attrs(-3, 0)),
            524,
            "dynamic clocks: ENOTSUPP"
        );
        let mut bare = Vec::new();
        put_attr(&mut bare, 1, b"etf\0");
        assert_eq!(
            change(RTM_NEWQDISC, 3, 0, 0x7ff0_0001, &bare),
            libc::EINVAL,
            "options are mandatory"
        );
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                0x7ff0_0002,
                &etf_attrs(libc::CLOCK_TAI, TC_ETF_OFFLOAD_ON)
            ),
            0
        );
        let q = qdiscs(3);
        assert_eq!(
            (q[2].1, q[2].2.as_str(), q[2].3),
            (0x7ff0_0002, "etf", Some(TC_ETF_OFFLOAD_ON))
        );
        assert_eq!(q[2].0, 0x8001_0000, "an automatic handle");

        let mut fq = Vec::new();
        put_attr(&mut fq, 1, b"fq_codel\0");
        assert_eq!(
            change(RTM_NEWQDISC, 3, 0, 0x7ff0_0002, &fq),
            0,
            "restore the queue"
        );
        assert_eq!(qdiscs(3)[2].2, "fq_codel");
        assert_eq!(
            change(RTM_DELQDISC, 3, 0, TC_H_ROOT, &[]),
            0,
            "back to the defaults"
        );
        assert_eq!(qdiscs(3)[0].0, 0);
        assert_eq!(
            change(RTM_DELQDISC, 3, 0, TC_H_ROOT, &[]),
            libc::ENOENT,
            "a default root"
        );
    });
}

#[test]
fn etf_offload_needs_driver_support_and_changes_need_net_admin() {
    let host = HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(Nic::new("eth0", 3))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(qdiscs(3)[0].2, "fq_codel", "a single-queue root");
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                TC_H_ROOT,
                &etf_attrs(libc::CLOCK_TAI, TC_ETF_OFFLOAD_ON)
            ),
            libc::EOPNOTSUPP
        );
        let mut mq = Vec::new();
        put_attr(&mut mq, 1, b"mq\0");
        assert_eq!(
            change(RTM_NEWQDISC, 3, 0x7ff0_0000, TC_H_ROOT, &mq),
            libc::EOPNOTSUPP,
            "single queue"
        );
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                TC_H_ROOT,
                &etf_attrs(libc::CLOCK_TAI, 0)
            ),
            0
        );
        assert_eq!(
            change(
                RTM_NEWQDISC,
                9,
                0,
                TC_H_ROOT,
                &etf_attrs(libc::CLOCK_TAI, 0)
            ),
            libc::ENODEV
        );
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                TC_H_ROOT,
                &etf_attrs(libc::CLOCK_TAI, 0)
            ),
            libc::EINVAL,
            "etf has no change operation"
        );
        let mut fq = Vec::new();
        put_attr(&mut fq, 1, b"fq\0");
        let fd = route_socket();
        send(
            fd,
            RTM_NEWQDISC,
            NLM_F_CREATE | NLM_F_REPLACE,
            3,
            0,
            TC_H_ROOT,
            &fq,
        );
        send(fd, RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, &[]);
        assert_eq!(
            receive(fd)[0].0,
            RTM_NEWQDISC,
            "no ack asked, none sent: the dump comes first"
        );
        unsafe { libc::close(fd) };
    });
    let host = HostProfile::new().nic(Nic::new("eth0", 3)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            change(
                RTM_NEWQDISC,
                3,
                0,
                TC_H_ROOT,
                &etf_attrs(libc::CLOCK_TAI, 0)
            ),
            libc::EPERM
        );
        assert_eq!(
            change(RTM_NEWQDISC, 9, 0, TC_H_ROOT, &[]),
            libc::EPERM,
            "before the device lookup"
        );
    });
}

#[test]
fn threaded_napi_through_sysfs() {
    let write = |text: &str| {
        std::fs::write("/sys/class/net/eth0/threaded", text).map_err(|e| e.raw_os_error().unwrap())
    };
    let read = || std::fs::read_to_string("/sys/class/net/eth0/threaded").unwrap();
    let host = HostProfile::new()
        .root(true)
        .cap(CAP_NET_ADMIN)
        .nic(tuned_nic())
        .build();
    Sim::builder().host(host.clone()).build().run(|| {
        assert_eq!(read(), "0\n");
        write("1").unwrap();
        assert_eq!(read(), "1\n");
        assert_eq!(write("2\n"), Err(libc::EOPNOTSUPP));
        assert_eq!(write("on"), Err(libc::EINVAL));
        write("0x0\n").unwrap();
    });
    assert!(!host.ethtool("eth0").unwrap().threaded_napi);
    let host = HostProfile::new()
        .root(true)
        .nic(tuned_nic().threaded_napi(true))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read(), "1\n");
        assert_eq!(write("0"), Err(libc::EPERM), "root without CAP_NET_ADMIN");
    });
    let host = HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(tuned_nic())
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            write("1"),
            Err(libc::EACCES),
            "the attribute is root's, mode 0644"
        );
    });
}

/// The privilege-before-operation order of `__dev_ethtool` and its `EOPNOTSUPP` for a missing
/// operation: the real loopback device (whose driver has `get_link` and no ring, coalescing,
/// pause, channel or EEE operations) against a sim interface declaring none of them either,
/// with the sim's privileges taken from the real process. In
/// Docker's default container (no `CAP_NET_ADMIN`) every setter is `EPERM`; with
/// `--cap-add NET_ADMIN` they reach the missing operation.
#[test]
fn ethtool_privilege_order_os_truth() {
    fn probe(name: &str) -> Vec<Result<u32, i32>> {
        let word = |cmd: u32| -> Result<u32, i32> {
            let mut w = [0u32; 23];
            w[0] = cmd;
            ethtool_on(name, w.as_mut_ptr().cast()).map(|()| w[1])
        };
        [
            ETHTOOL_GLINK,
            ETHTOOL_GRINGPARAM,
            ETHTOOL_SRINGPARAM,
            ETHTOOL_GCOALESCE,
            ETHTOOL_SCOALESCE,
            ETHTOOL_GPAUSEPARAM,
            ETHTOOL_SPAUSEPARAM,
            ETHTOOL_GCHANNELS,
            ETHTOOL_SCHANNELS,
            ETHTOOL_GEEE,
            ETHTOOL_SEEE,
            0x7777,
        ]
        .map(word)
        .to_vec()
    }
    let real = snare::real(|| probe("lo"));
    let privileges = snare::Privileges::from_real_process().unwrap();
    let host = HostProfile::new().nic(Nic::new("bare0", 3)).build();
    let sim = Sim::builder()
        .host(host)
        .privileges(privileges.clone())
        .build()
        .run(|| probe("bare0"));
    assert_eq!(sim, real, "CAP_NET_ADMIN {}", privileges.net_admin);
}

#[test]
fn ts_info_reports_the_phc_and_hardware_stamping() {
    const ETHTOOL_GET_TS_INFO: u32 = 0x41;
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 3).hardware_timestamping(true).ptp_index(2))
        .build();
    Sim::builder().host(host).build().run(|| {
        let w = get::<11>(ETHTOOL_GET_TS_INFO).unwrap();
        assert_eq!(w[1], 0x5f, "TX/RX/raw hardware, TX/RX software, SOFTWARE");
        assert_eq!(w[2] as i32, 2, "phc_index");
        assert_eq!(
            (w[3], w[7]),
            (0b11, 0b11),
            "HWTSTAMP_TX_OFF|ON, HWTSTAMP_FILTER_NONE|ALL"
        );
    });
    let host = HostProfile::new().nic(Nic::new("eth0", 3)).build();
    Sim::builder().host(host).build().run(|| {
        let w = get::<11>(ETHTOOL_GET_TS_INFO).unwrap();
        assert_eq!(
            (w[1], w[2] as i32, w[3]),
            (0x18, -1, 0),
            "the core's software stamping only"
        );
    });
}
