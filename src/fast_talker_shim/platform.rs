//! Which fast-talker items exist on the OS snare emulates. Driven only by
//! [`os_semantics`](crate::os_semantics), never by the host.

use std::io;

use crate::os::OsSemantics;

/// A group of fast-talker items that are available or not together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub(crate) enum Item {
    Timestamped,
    SendAt,
    NicRingsCoalescePauseChannels,
    NicDriver,
    NicLinkStats,
    NicEee,
    LinuxNicTuning,
    RxTimestamping,
    WindowsNic,
    Irq,
    ThreadIdentity,
    ThreadScheduler,
    LinuxRt,
    ThreadAffinity,
    MacOsRt,
    WindowsRt,
    SocketTable,
    IncomingCpu,
    Multicast,
    Counters,
}

impl Item {
    pub(crate) fn available(self, os: OsSemantics) -> bool {
        let linux = os == OsSemantics::Linux;
        let macos = os == OsSemantics::MacOs;
        let windows = os == OsSemantics::Windows;
        match self {
            Item::Timestamped
            | Item::NicLinkStats
            | Item::ThreadIdentity
            | Item::SocketTable
            | Item::Multicast
            | Item::Counters => true,
            Item::SendAt | Item::LinuxNicTuning | Item::Irq | Item::LinuxRt => linux,
            Item::NicRingsCoalescePauseChannels
            | Item::NicDriver
            | Item::NicEee
            | Item::RxTimestamping
            | Item::ThreadAffinity
            | Item::IncomingCpu => linux || windows,
            Item::ThreadScheduler => linux || macos,
            Item::MacOsRt => macos,
            Item::WindowsNic | Item::WindowsRt => windows,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Item::Timestamped => "timestamped sockets",
            Item::SendAt => "timed sends (SO_TXTIME)",
            Item::NicRingsCoalescePauseChannels => {
                "NIC rings, coalescing, flow control and channels"
            }
            Item::NicDriver => "NIC driver information",
            Item::NicLinkStats => "NIC link state and statistics",
            Item::NicEee => "Energy Efficient Ethernet",
            Item::LinuxNicTuning => "Linux NIC tuning",
            Item::RxTimestamping => "NIC receive timestamping",
            Item::WindowsNic => "Windows NIC settings",
            Item::Irq => "IRQ affinity",
            Item::ThreadIdentity => "thread identity",
            Item::ThreadScheduler => "POSIX thread scheduling",
            Item::LinuxRt => "Linux real-time settings",
            Item::ThreadAffinity => "thread CPU affinity",
            Item::MacOsRt => "macOS thread QoS and time constraints",
            Item::WindowsRt => "Windows thread and process priorities",
            Item::SocketTable => "the socket table",
            Item::IncomingCpu => "incoming_cpu",
            Item::Multicast => "multicast",
            Item::Counters => "protocol counters",
        }
    }
}

/// `Ok` when `item` exists on the emulated OS, else `Unsupported`, logged
/// as an [`FtEvent::Unsupported`](super::sim::FtEvent::Unsupported). Must
/// not be called with snare's state lock held.
#[allow(dead_code)]
pub(crate) fn require(item: Item) -> io::Result<()> {
    let os = crate::os_semantics();
    if item.available(os) {
        return Ok(());
    }
    super::sim::log(super::sim::FtEvent::Unsupported {
        item: item.name(),
        os,
    });
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{} is not supported on {os} (snare simulated)", item.name()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_follows_the_os() {
        use OsSemantics::{Linux, MacOs, Windows};
        let row = |item: Item| {
            [Linux, MacOs, Windows]
                .map(|os| item.available(os))
                .to_vec()
        };
        assert_eq!(row(Item::Timestamped), [true, true, true]);
        assert_eq!(row(Item::SendAt), [true, false, false]);
        assert_eq!(
            row(Item::NicRingsCoalescePauseChannels),
            [true, false, true]
        );
        assert_eq!(row(Item::NicDriver), [true, false, true]);
        assert_eq!(row(Item::NicLinkStats), [true, true, true]);
        assert_eq!(row(Item::NicEee), [true, false, true]);
        assert_eq!(row(Item::LinuxNicTuning), [true, false, false]);
        assert_eq!(row(Item::RxTimestamping), [true, false, true]);
        assert_eq!(row(Item::WindowsNic), [false, false, true]);
        assert_eq!(row(Item::Irq), [true, false, false]);
        assert_eq!(row(Item::ThreadIdentity), [true, true, true]);
        assert_eq!(row(Item::ThreadScheduler), [true, true, false]);
        assert_eq!(row(Item::LinuxRt), [true, false, false]);
        assert_eq!(row(Item::ThreadAffinity), [true, false, true]);
        assert_eq!(row(Item::MacOsRt), [false, true, false]);
        assert_eq!(row(Item::WindowsRt), [false, false, true]);
        assert_eq!(row(Item::SocketTable), [true, true, true]);
        assert_eq!(row(Item::IncomingCpu), [true, false, true]);
        assert_eq!(row(Item::Multicast), [true, true, true]);
        assert_eq!(row(Item::Counters), [true, true, true]);
    }
}
