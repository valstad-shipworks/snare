#![cfg(all(windows, feature = "hw-npcap"))]
//! pcapng capture of raw frames sent through npcap: `pcap_sendpacket` and a send queue each
//! write the frame verbatim, once per send, on the device it went out on.

#[path = "support/pcapng_reader.rs"]
mod reader;

use pcap::Capture;
use pcap::sendqueue::{SendQueue, SendSync};

use snare::Sim;

#[test]
fn npcap_sendpacket_captured() {
    let path =
        std::env::temp_dir().join(format!("snare-pcapng-npcap-{}.pcapng", std::process::id()));
    let sim = Sim::builder().pcapng(&path).build();
    let frame: Vec<u8> = (0..60).map(|i| i as u8).collect();
    sim.run(|| {
        let mut cap = Capture::from_device("snare5")
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap()
            .setnonblock()
            .unwrap();
        cap.sendpacket(&frame[..]).unwrap();
        let mut sq = SendQueue::new(64 * 1024).unwrap();
        sq.queue(None, &frame).unwrap();
        sq.transmit(&mut cap, SendSync::Off).unwrap();
    });
    drop(sim);
    let file = reader::read(&path);
    assert_eq!(file.ifaces, ["snare5"]);
    assert_eq!(file.packets.len(), 2);
    assert!(file.packets.iter().all(|p| p.data == frame && !p.inbound));
}
