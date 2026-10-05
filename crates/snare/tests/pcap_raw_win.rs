#![cfg(all(windows, feature = "hw-npcap"))]

//! Windows raw L2 over npcap (`wpcap.dll`), serviced from process memory the way ethercrab's
//! Windows transport drives it: open a device with `immediate_mode` + non-blocking, push frames
//! through a `SendQueue`, and read them back with `next_packet`. Two captures on one device name
//! are two NICs on the same wire; a sent frame also loops back to its sender, as npcap does.

use pcap::Capture;
use pcap::sendqueue::{SendQueue, SendSync};

use snare::Sim;

fn open(device: &str) -> pcap::Capture<pcap::Active> {
    Capture::from_device(device)
        .expect("device")
        .immediate_mode(true)
        .open()
        .expect("open")
        .setnonblock()
        .expect("nonblock")
}

fn recv_frame(cap: &mut pcap::Capture<pcap::Active>) -> Vec<u8> {
    for _ in 0..100_000 {
        match cap.next_packet() {
            Ok(pkt) => return pkt.data.to_vec(),
            Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                std::thread::yield_now();
            }
            Err(e) => panic!("next_packet: {e}"),
        }
    }
    panic!("no frame received");
}

#[test]
fn sendqueue_loops_back_to_sender() {
    Sim::new().run(|| {
        let mut cap = open("snare0");
        let frame: Vec<u8> = (0..60).map(|i| i as u8).collect();
        let mut sq = SendQueue::new(64 * 1024).unwrap();
        sq.queue(None, &frame).unwrap();
        sq.transmit(&mut cap, SendSync::Off).unwrap();
        // npcap delivers the sent frame back to the sending capture.
        assert_eq!(recv_frame(&mut cap), frame);
    });
}

#[test]
fn frame_crosses_between_captures_on_one_device() {
    Sim::new().run(|| {
        let mut tx = open("snare1");
        let mut rx = open("snare1");
        let frame: Vec<u8> = (0..64).map(|i| (255 - i) as u8).collect();
        let mut sq = SendQueue::new(64 * 1024).unwrap();
        sq.queue(None, &frame).unwrap();
        sq.transmit(&mut tx, SendSync::Off).unwrap();
        assert_eq!(recv_frame(&mut rx), frame);
    });
}

#[test]
fn captures_on_different_devices_are_isolated() {
    Sim::new().run(|| {
        let mut tx = open("snareA");
        let mut other = open("snareB");
        let frame = vec![0xAAu8; 32];
        let mut sq = SendQueue::new(64 * 1024).unwrap();
        sq.queue(None, &frame).unwrap();
        sq.transmit(&mut tx, SendSync::Off).unwrap();
        // A different device sees nothing.
        match other.next_packet() {
            Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {}
            other => panic!("expected no packet on other device, got {other:?}"),
        }
    });
}
