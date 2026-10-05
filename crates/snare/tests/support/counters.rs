//! The host's protocol counters as the code under test reads them on each OS: `/proc/net/snmp`
//! on Linux, `sysctlbyname("net.inet.udp.stats")` on macOS, `GetUdpStatisticsEx` and
//! `GetTcpStatisticsEx` on Windows.

#![allow(dead_code)]

/// The UDP counters as (received, no-ports, rcvbuf-errors, sent), named by what the host's own
/// interface calls them: Linux `InDatagrams` counts reads, the others arrivals.
pub fn udp() -> [u64; 4] {
    udp_os()
}

#[cfg(target_os = "linux")]
fn udp_os() -> [u64; 4] {
    let v = proc_line("/proc/net/snmp", "Udp");
    [
        v["InDatagrams"],
        v["NoPorts"],
        v["RcvbufErrors"],
        v["OutDatagrams"],
    ]
}

/// The named values of the `name:` line pair in `path`.
#[cfg(target_os = "linux")]
pub fn proc_line(path: &str, name: &str) -> std::collections::HashMap<String, u64> {
    let text = std::fs::read_to_string(path).unwrap();
    let prefix = format!("{name}: ");
    let mut lines = text.lines().filter(|l| l.starts_with(&prefix));
    let header = lines.next().unwrap();
    let values = lines.next().unwrap();
    header[prefix.len()..]
        .split(' ')
        .zip(values[prefix.len()..].split(' '))
        .map(|(k, v)| (k.to_string(), v.parse::<i64>().unwrap() as u64))
        .collect()
}

/// `struct udpstat` as words.
#[cfg(target_os = "macos")]
pub fn udpstat() -> Vec<u32> {
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            c"net.inet.udp.stats".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0, "sysctlbyname");
    buf[..len]
        .chunks(4)
        .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
        .collect()
}

#[cfg(target_os = "macos")]
fn udp_os() -> [u64; 4] {
    let w = udpstat();
    [w[0] as u64, w[4] as u64, w[6] as u64, w[9] as u64]
}

#[cfg(windows)]
pub fn udpstats(family: u32) -> windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDPSTATS {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetUdpStatisticsEx;
    let mut s = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { GetUdpStatisticsEx(&mut s, family) }, 0);
    s
}

#[cfg(windows)]
pub fn tcpstats(family: u32) -> windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPSTATS_LH {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetTcpStatisticsEx;
    let mut s = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { GetTcpStatisticsEx(&mut s, family) }, 0);
    s
}

#[cfg(windows)]
fn udp_os() -> [u64; 4] {
    let s = udpstats(2);
    [
        s.dwInDatagrams as u64,
        s.dwNoPorts as u64,
        s.dwInErrors as u64,
        s.dwOutDatagrams as u64,
    ]
}
