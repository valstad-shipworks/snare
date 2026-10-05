use std::io::Write;
use std::num::NonZeroU32;
use std::str::FromStr;

use xsk_rs::{
    config::{BindFlags, Interface, SocketConfig, UmemConfig},
    Socket, Umem,
};

// Drives the shim the way ethercrab's `tx_rx_task_xdp` does: build a UMEM and socket, write a
// frame into the UMEM, produce it to TX, wake up to flush it through libc `send`, reclaim it from
// the completion queue, then receive it back through libc `recv` and check the bytes survived the
// round trip.
#[test]
fn frame_round_trips_through_libc() {
    let frame_count = NonZeroU32::new(8).unwrap();

    let (umem, mut descs) = Umem::new(UmemConfig::default(), frame_count, false).unwrap();

    let config = SocketConfig::builder()
        .bind_flags(BindFlags::XDP_USE_NEED_WAKEUP)
        .build();

    let (mut tx_q, mut rx_q, fq_and_cq) = unsafe {
        Socket::new(config, &umem, &Interface::from_str("sim0").unwrap(), 0).unwrap()
    };
    let (mut fq, mut cq) = fq_and_cq.expect("fill and comp queue");

    let mid = descs.len() / 2;
    let (tx_descs, rx_descs) = descs.split_at_mut(mid);

    unsafe { fq.produce(rx_descs) };

    let payload: Vec<u8> = (0..64u8).collect();

    let tx_desc = &mut tx_descs[0];
    unsafe {
        umem.data_mut(tx_desc)
            .cursor()
            .write_all(&payload)
            .unwrap();
    }
    assert_eq!(tx_desc.lengths().data(), payload.len());

    unsafe { tx_q.produce_one(tx_desc) };

    assert!(tx_q.needs_wakeup());
    tx_q.wakeup().unwrap();
    assert!(!tx_q.needs_wakeup());

    let sent = &mut tx_descs[0..1];
    let mut completed = 0;
    for _ in 0..1000 {
        completed = unsafe { cq.consume(sent) };
        if completed == 1 {
            break;
        }
    }
    assert_eq!(completed, 1, "frame should complete after being sent");

    let mut received = 0;
    for _ in 0..1000 {
        received = unsafe { rx_q.poll_and_consume(rx_descs, 100).unwrap() };
        if received > 0 {
            break;
        }
    }
    assert_eq!(received, 1, "one frame should arrive on the rx side");

    let recv_desc = &rx_descs[0];
    let data = unsafe { umem.data(recv_desc) };
    assert_eq!(&data[..], &payload[..], "payload survives the libc round trip");

    unsafe { fq.produce_one(recv_desc) };
}

#[test]
fn empty_rx_does_not_block() {
    let (umem, mut descs) = Umem::new(UmemConfig::default(), NonZeroU32::new(4).unwrap(), false)
        .unwrap();
    let (_tx_q, mut rx_q, fq_and_cq) = unsafe {
        Socket::new(
            SocketConfig::default(),
            &umem,
            &Interface::from_str("sim0").unwrap(),
            0,
        )
        .unwrap()
    };
    let (mut fq, _cq) = fq_and_cq.unwrap();

    unsafe { fq.produce(&descs) };

    let got = unsafe { rx_q.poll_and_consume(&mut descs, 0).unwrap() };
    assert_eq!(got, 0, "no frames sent, so nothing to receive");
}
