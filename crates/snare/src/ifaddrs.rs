//! The interface lists of `getifaddrs(3)` and `if_nameindex(3)`, rendered from the sim's topology
//! into one `malloc` block each, so the caller's `freeifaddrs` / `if_freenameindex` hands back a
//! pointer this module can recognise and release.
//!
//! Each block holds the array of `struct ifaddrs` (or `struct if_nameindex`) first, then every
//! name and `sockaddr` it points to, each padded to 8 bytes so the `sockaddr` and `if_data` fields
//! land aligned. That layout is snare's own (see [`align`]); the entry order is glibc's on Linux
//! (`sysdeps/unix/sysv/linux/ifaddrs.c`, built from `RTM_GETLINK` then `RTM_GETADDR` dumps) and
//! Apple Libinfo's on macOS (`gen.subproj/getifaddrs.c`, built from the `NET_RT_IFLIST` sysctl).
//! One block per call lets [`release`] free it with a single `free`.

use std::collections::HashSet;
use std::ffi::{c_char, c_void};
use std::mem::size_of;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::netif::{IpNet, NicSnapshot};

/// The blocks this module handed out and the caller has not freed yet, by address. Process-wide,
/// not per sim: a list may outlive the sim it was built in, and `freeifaddrs` must still route it
/// back here.
static BLOCKS: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

/// Records `block` as one of ours, for [`release`] to recognise.
fn remember(block: *mut u8) {
    let mut blocks = BLOCKS.lock().unwrap_or_else(|e| e.into_inner());
    blocks
        .get_or_insert_with(HashSet::new)
        .insert(block as usize);
}

/// Frees `block` if it is one of ours; `false` leaves it to libc, which allocated it (a list built
/// outside a sim, or before the hooks were installed).
pub(crate) fn release(block: *mut u8) -> bool {
    let mut blocks = BLOCKS.lock().unwrap_or_else(|e| e.into_inner());
    let ours = blocks
        .as_mut()
        .is_some_and(|set| set.remove(&(block as usize)));
    if ours {
        unsafe { libc::free(block.cast::<c_void>()) };
    }
    ours
}

/// The `SIOCGIFFLAGS` word of an interface (man 7 netdevice): `IFF_UP` while administratively
/// up, `IFF_RUNNING` (and Linux's `IFF_LOWER_UP`, "driver signals L1 up") while it also has
/// carrier (Linux `Documentation/networking/operstates.rst`). Loopback carries `IFF_LOOPBACK`,
/// everything else is an Ethernet interface with `IFF_BROADCAST | IFF_MULTICAST`, as Linux's
/// `ether_setup` sets them (`net/ethernet/eth.c`). Linux's `lo` has only `IFF_LOOPBACK`
/// (`drivers/net/loopback.c`, `gen_lo_setup`), while XNU's `lo0` is
/// `IFF_LOOPBACK | IFF_MULTICAST` (`bsd/net/if_loop.c`, `loopattach`).
pub(crate) fn flags(nic: &NicSnapshot) -> u32 {
    let mut flags = 0u32;
    if nic.spec.admin_up {
        flags |= libc::IFF_UP as u32;
    }
    if nic.running() {
        flags |= libc::IFF_RUNNING as u32;
        #[cfg(target_os = "linux")]
        {
            flags |= libc::IFF_LOWER_UP as u32;
        }
    }
    flags |= if nic.loopback {
        libc::IFF_LOOPBACK as u32
    } else {
        libc::IFF_BROADCAST as u32
    };
    if !nic.loopback || cfg!(target_os = "macos") {
        flags |= libc::IFF_MULTICAST as u32;
    }
    flags
}

/// The raw bytes of a plain C struct.
fn bytes_of<T>(value: &T) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
}

/// `ip` as a `sockaddr_in`/`sockaddr_in6`, with the BSD `sin_len`/`sin6_len` byte set on macOS
/// (`<netinet/in.h>`). A link-local IPv6 address (`fe80::/10`, RFC 4291 §2.5.6; the `0xffc0`
/// mask keeps its top 10 bits) carries `scope` as `sin6_scope_id`, which for link-local scope is
/// the interface index (RFC 4007 §6; RFC 3493 §3.3).
fn sockaddr(ip: IpAddr, scope: u32) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            #[cfg(target_os = "macos")]
            {
                sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
            }
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from(v4).to_be();
            bytes_of(&sa)
        }
        IpAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            #[cfg(target_os = "macos")]
            {
                sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            }
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = v6.octets();
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                sa.sin6_scope_id = scope;
            }
            bytes_of(&sa)
        }
    }
}

/// The netmask of `net`'s prefix, in its address family.
fn mask_of(net: &IpNet) -> IpAddr {
    let bits = |width: u32| -> u128 {
        if net.prefix == 0 {
            0
        } else {
            (!0u128 << (width - net.prefix as u32)) & (!0u128 >> (128 - width))
        }
    };
    match net.addr {
        IpAddr::V4(_) => IpAddr::V4((bits(32) as u32).into()),
        IpAddr::V6(_) => IpAddr::V6(bits(128).into()),
    }
}

/// The Linux `AF_PACKET` entry: a `sockaddr_ll` (man 7 packet) carrying the hardware address
/// and, in `ifa_data`, a `struct rtnl_link_stats` (`include/uapi/linux/if_link.h`: 24 `__u32`
/// counters; man 3 getifaddrs, NOTES), which glibc copies from `IFLA_STATS`
/// (`sysdeps/unix/sysv/linux/ifaddrs.c`). Counters are truncated to 32 bits, as that struct holds
/// them. The non-loopback entry's broadcast address is the all-ones Ethernet broadcast. Real
/// Linux also gives `lo` one (all zeros: `rtnl_fill_ifinfo` in `net/core/rtnetlink.c` emits
/// `IFLA_BROADCAST` for any device with a hardware address length, and glibc copies it); snare
/// leaves loopback's null.
#[cfg(target_os = "linux")]
fn link_entry(nic: &NicSnapshot) -> Entry {
    // include/uapi/linux/if_arp.h.
    const ARPHRD_ETHER: u16 = 1;
    const ARPHRD_LOOPBACK: u16 = 772;
    let ll = |mac: [u8; 6]| {
        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_ifindex = nic.index as i32;
        sa.sll_hatype = if nic.loopback {
            ARPHRD_LOOPBACK
        } else {
            ARPHRD_ETHER
        };
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&mac);
        bytes_of(&sa)
    };
    let c = &nic.counters;
    let mut stats = [0u32; 24];
    // Field positions in struct rtnl_link_stats; the counters snare does not keep stay zero.
    let fields = [
        (0, c.rx_packets),
        (1, c.tx_packets),
        (2, c.rx_bytes),
        (3, c.tx_bytes),
        (4, c.rx_errors),
        (5, c.tx_errors),
        (6, c.rx_dropped),
        (7, c.tx_dropped),
        (8, c.multicast),
        (17, c.tx_carrier_errors),
        (23, c.rx_nohandler),
    ];
    for (i, v) in fields {
        stats[i] = v as u32;
    }
    Entry {
        name: nic.spec.name.clone(),
        flags: flags(nic),
        addr: ll(nic.hw_addr()),
        netmask: None,
        broadaddr: (!nic.loopback).then(|| ll([0xff; 6])),
        data: Some(stats.iter().flat_map(|v| v.to_ne_bytes()).collect()),
    }
}

/// The macOS `AF_LINK` entry: a `sockaddr_dl` (`<net/if_dl.h>`) holding the name then the
/// hardware address, and a `struct if_data` (`<net/if_var.h>`) in `ifa_data`.
///
/// `sockaddr_dl` is built by hand because its length varies: an 8-byte header (`sdl_len`,
/// `sdl_family`, the 16-bit `sdl_index`, `sdl_type`, `sdl_nlen`, `sdl_alen`, `sdl_slen`), then
/// `sdl_data` with the name (no NUL) followed by the address, never shorter than the struct's
/// 20 bytes. The buffer is padded to 4 bytes, the `SA_RLEN` rounding of Apple's `getifaddrs`
/// (Libinfo `gen.subproj/getifaddrs.c`). Loopback has no link address (`sdl_alen` 0) and no
/// link header; Ethernet's header is 14 bytes (`ETHER_HDR_LEN`, `<net/ethernet.h>`).
/// `ifi_baudrate` is in bits per second: XNU's `ifnet_set_baudrate` (`bsd/net/kpi_interface.c`)
/// stores the same value as the interface bandwidths, which `kpi_interface.h` documents in bits
/// per second, and pins it to 32 bits, as the saturating multiply here does. The counters are
/// truncated to `if_data`'s 32 bits.
#[cfg(target_os = "macos")]
fn link_entry(nic: &NicSnapshot) -> Entry {
    // bsd/net/if_types.h: IFT_ETHER 0x6, IFT_LOOP 0x18.
    const IFT_ETHER: u8 = 6;
    const IFT_LOOP: u8 = 24;
    let name = nic.spec.name.as_bytes();
    let alen = if nic.loopback { 0 } else { 6 };
    let len = (8 + name.len() + alen).max(size_of::<libc::sockaddr_dl>());
    let mut dl = vec![0u8; len.next_multiple_of(4)];
    dl[0] = len as u8;
    dl[1] = libc::AF_LINK as u8;
    dl[2..4].copy_from_slice(&(nic.index as u16).to_ne_bytes());
    dl[4] = if nic.loopback { IFT_LOOP } else { IFT_ETHER };
    dl[5] = name.len() as u8;
    dl[6] = alen as u8;
    dl[8..8 + name.len()].copy_from_slice(name);
    if alen > 0 {
        dl[8 + name.len()..8 + name.len() + 6].copy_from_slice(&nic.hw_addr());
    }
    let mut data: libc::if_data = unsafe { std::mem::zeroed() };
    data.ifi_type = dl[4];
    data.ifi_addrlen = alen as u8;
    data.ifi_hdrlen = if nic.loopback { 0 } else { 14 };
    data.ifi_mtu = nic.spec.mtu;
    data.ifi_baudrate = nic.spec.speed_mbps.unwrap_or(0).saturating_mul(1_000_000);
    let c = &nic.counters;
    data.ifi_ipackets = c.rx_packets as u32;
    data.ifi_ierrors = c.rx_errors as u32;
    data.ifi_opackets = c.tx_packets as u32;
    data.ifi_oerrors = c.tx_errors as u32;
    data.ifi_ibytes = c.rx_bytes as u32;
    data.ifi_obytes = c.tx_bytes as u32;
    data.ifi_imcasts = c.multicast as u32;
    data.ifi_iqdrops = c.rx_dropped as u32;
    Entry {
        name: nic.spec.name.clone(),
        flags: flags(nic),
        addr: dl,
        netmask: None,
        broadaddr: None,
        data: Some(bytes_of(&data)),
    }
}

/// One entry per host address of `nic` in the family `v4` selects, with its netmask and, for an
/// IPv4 subnet that has one on a non-loopback interface, its directed broadcast (IPv6 has no
/// broadcast, RFC 4291 §2). Station addresses are not the host's and are never listed.
fn ip_entries(nic: &NicSnapshot, v4: bool) -> impl Iterator<Item = Entry> + '_ {
    nic.spec
        .addresses
        .iter()
        .filter(move |net| net.addr.is_ipv4() == v4)
        .map(move |net| {
            let broadcast = net.broadcast().filter(|_| !nic.loopback && v4);
            Entry {
                name: nic.spec.name.clone(),
                flags: flags(nic),
                addr: sockaddr(net.addr, nic.index),
                netmask: Some(sockaddr(mask_of(net), 0)),
                broadaddr: broadcast.map(|b| sockaddr(b, 0)),
                data: None,
            }
        })
}

/// One `struct ifaddrs` before layout, each pointer field as the bytes it will point to.
struct Entry {
    name: String,
    flags: u32,
    /// The `sockaddr` bytes for `ifa_addr`.
    addr: Vec<u8>,
    netmask: Option<Vec<u8>>,
    /// `ifa_broadaddr` (Linux `ifa_ifu`, macOS `ifa_dstaddr`, the same slot).
    broadaddr: Option<Vec<u8>>,
    /// `ifa_data`: link statistics, on link entries only.
    data: Option<Vec<u8>>,
}

/// The entries in the host's order: glibc lists every `AF_PACKET` entry (its `RTM_GETLINK` dump),
/// then the IPv4 and then the IPv6 addresses (one `AF_UNSPEC` `RTM_GETADDR` dump, which the kernel
/// walks family by family in ascending number, `net/core/rtnetlink.c` `rtnl_dump_all`); macOS
/// lists each interface's link entry followed by its addresses (`NET_RT_IFLIST` emits
/// `RTM_IFINFO` then that interface's `RTM_NEWADDR`s, `bsd/net/rtsock.c` `sysctl_iflist`). Within
/// one macOS interface the real order is the order addresses were added; snare puts IPv4 first.
fn entries(mut nics: Vec<NicSnapshot>) -> Vec<Entry> {
    nics.sort_by_key(|n| n.index);
    if cfg!(target_os = "linux") {
        let mut out: Vec<Entry> = nics.iter().map(link_entry).collect();
        out.extend(nics.iter().flat_map(|n| ip_entries(n, true)));
        out.extend(nics.iter().flat_map(|n| ip_entries(n, false)));
        out
    } else {
        nics.iter()
            .flat_map(|n| {
                std::iter::once(link_entry(n))
                    .chain(ip_entries(n, true))
                    .chain(ip_entries(n, false))
            })
            .collect()
    }
}

/// Rounds up to 8 bytes, the strictest alignment of anything placed in a block (`ifaddrs`
/// pointers and `if_data`). A snare choice; the libcs pad differently, but
/// the caller only follows the pointers.
fn align(n: usize) -> usize {
    n.next_multiple_of(8)
}

/// Builds the `getifaddrs` list for `nics` as one allocation, linked in the host's order.
/// `Ok(null)` for no entries, which `getifaddrs` returns as an empty list. `Err(ENOMEM)` when the
/// block cannot be allocated, the `malloc(3)` error man 3 getifaddrs lists. The block comes from
/// `calloc` so the caller's `freeifaddrs` can hand it to [`release`] and on to `free`.
pub(crate) fn getifaddrs(nics: Vec<NicSnapshot>) -> Result<*mut libc::ifaddrs, i32> {
    let entries = entries(nics);
    if entries.is_empty() {
        return Ok(std::ptr::null_mut());
    }
    let head = align(entries.len() * size_of::<libc::ifaddrs>());
    let payload: usize = entries
        .iter()
        .map(|e| {
            align(e.name.len() + 1)
                + align(e.addr.len())
                + e.netmask.as_ref().map_or(0, |m| align(m.len()))
                + e.broadaddr.as_ref().map_or(0, |b| align(b.len()))
                + e.data.as_ref().map_or(0, |d| align(d.len()))
        })
        .sum();
    let total = head + payload;
    let block = unsafe { libc::calloc(1, total) }.cast::<u8>();
    if block.is_null() {
        return Err(libc::ENOMEM);
    }
    let ifs = block.cast::<libc::ifaddrs>();
    let mut at = head;
    let mut put = |bytes: &[u8]| -> *mut u8 {
        let dst = unsafe { block.add(at) };
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        at += align(bytes.len());
        dst
    };
    let n = entries.len();
    for (i, e) in entries.iter().enumerate() {
        let mut name = e.name.as_bytes().to_vec();
        name.push(0);
        let name = put(&name);
        let addr = put(&e.addr);
        let netmask = e.netmask.as_ref().map_or(std::ptr::null_mut(), |m| put(m));
        let broad = e
            .broadaddr
            .as_ref()
            .map_or(std::ptr::null_mut(), |b| put(b));
        let data = e.data.as_ref().map_or(std::ptr::null_mut(), |d| put(d));
        unsafe {
            let ifa = &mut *ifs.add(i);
            ifa.ifa_next = if i + 1 < n {
                ifs.add(i + 1)
            } else {
                std::ptr::null_mut()
            };
            ifa.ifa_name = name.cast::<c_char>();
            ifa.ifa_flags = e.flags as _;
            ifa.ifa_addr = addr.cast();
            ifa.ifa_netmask = netmask.cast();
            #[cfg(target_os = "linux")]
            {
                ifa.ifa_ifu = broad.cast();
            }
            #[cfg(target_os = "macos")]
            {
                ifa.ifa_dstaddr = broad.cast();
            }
            ifa.ifa_data = data.cast();
        }
    }
    remember(block);
    Ok(ifs)
}

/// Builds the `if_nameindex` array for `nics` in index order, ended by an entry with `if_index`
/// 0 and a null `if_name` (the zeroed `calloc` tail), as POSIX specifies
/// (IEEE Std 1003.1-2024, `if_nameindex`). `Err(ENOBUFS)` when it cannot be allocated, the error
/// POSIX lists for that function.
pub(crate) fn nameindex(mut nics: Vec<NicSnapshot>) -> Result<*mut libc::if_nameindex, i32> {
    nics.sort_by_key(|n| n.index);
    let head = align((nics.len() + 1) * size_of::<libc::if_nameindex>());
    let total = head
        + nics
            .iter()
            .map(|n| align(n.spec.name.len() + 1))
            .sum::<usize>();
    let block = unsafe { libc::calloc(1, total) }.cast::<u8>();
    if block.is_null() {
        return Err(libc::ENOBUFS);
    }
    let array = block.cast::<libc::if_nameindex>();
    let mut at = head;
    for (i, nic) in nics.iter().enumerate() {
        let name = unsafe { block.add(at) };
        let bytes = nic.spec.name.as_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), name, bytes.len());
            let slot = &mut *array.add(i);
            slot.if_index = nic.index as _;
            slot.if_name = name.cast::<c_char>();
        }
        at += align(bytes.len() + 1);
    }
    remember(block);
    Ok(array)
}
