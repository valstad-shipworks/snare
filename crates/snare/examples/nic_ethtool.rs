//! Query a NIC driver over `ethtool` and configure hardware timestamping — the sequence a
//! PTP/TSN program runs at startup.
//!
//! `SIOCETHTOOL` with `ETHTOOL_GDRVINFO` reads `struct ethtool_drvinfo` (<linux/ethtool.h>);
//! `SIOCSHWTSTAMP` installs a `struct hwtstamp_config` (<linux/net_tstamp.h>,
//! Documentation/networking/timestamping.rst) and needs `CAP_NET_ADMIN`.
//!
//! Run with: `cargo run -p snare --example nic_ethtool`

fn main() {
    run();
}

#[cfg(target_os = "linux")]
fn run() {
    use snare::{CAP_NET_ADMIN, HostProfile, Nic, Sim};

    const SIOCETHTOOL: libc::c_ulong = 0x8946;
    const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
    const ETHTOOL_GDRVINFO: u32 = 0x3;
    const HWTSTAMP_TX_ON: i32 = 1;
    const HWTSTAMP_FILTER_PTP_V2_EVENT: i32 = 12;

    #[repr(C)]
    struct Ifreq {
        name: [libc::c_char; 16],
        data: usize,
    }
    fn ifreq(name: &str) -> Ifreq {
        let mut n = [0 as libc::c_char; 16];
        for (i, b) in name.bytes().enumerate() {
            n[i] = b as libc::c_char;
        }
        Ifreq { name: n, data: 0 }
    }

    let host = HostProfile::new()
        .nic(
            Nic::new("eth0", 2)
                .driver("igb", "5.6.0")
                .bus_info("0000:01:00.0")
                .hardware_timestamping(true),
        )
        .cap(CAP_NET_ADMIN)
        .build();

    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };

        let mut drvinfo = [0u8; 196];
        drvinfo[0..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
        let mut req = ifreq("eth0");
        req.data = drvinfo.as_mut_ptr() as usize;
        assert_eq!(
            unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) },
            0
        );
        let field = |off: usize| {
            let end = drvinfo[off..off + 32].iter().position(|&b| b == 0).unwrap();
            String::from_utf8(drvinfo[off..off + end].to_vec()).unwrap()
        };

        let mut cfg = [0i32, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_EVENT];
        let mut req = ifreq("eth0");
        req.data = cfg.as_mut_ptr() as usize;
        let rc = unsafe { libc::ioctl(fd, SIOCSHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) };

        println!(
            "eth0: driver={} v{} bus={} hwtstamp_set={}",
            field(4),
            field(36),
            field(100),
            rc == 0,
        );
        unsafe { libc::close(fd) };
    });
}

#[cfg(not(target_os = "linux"))]
fn run() {
    println!("nic_ethtool: ethtool/SIOCSHWTSTAMP are Linux-only; nothing to do on this OS");
}
