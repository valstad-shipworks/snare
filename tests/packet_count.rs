use std::{
    io::{ErrorKind, Write},
    net::SocketAddr,
    time::Duration,
};

use bincode::{Decode, Encode};
use snare::{
    Packetable, SocketType, TcpListener, TcpStream, ThreadExt, TimerState, UdpSocket,
    connect_tester, register_test, run_testers,
};

#[derive(Clone, Debug, Encode, Decode)]
struct TcpTestPacket {
    data_size: u32,
    data: Vec<u8>,
}

impl TcpTestPacket {
    fn new(data: &'static [u8]) -> Self {
        Self {
            data_size: data.len() as u32,
            data: data.to_vec(),
        }
    }
}

impl Packetable for TcpTestPacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Tcp;

    fn encode(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        bincode::decode_from_slice(data, bincode::config::standard()).ok()
    }
}

#[test]
fn test_encode_decode_tcp_packet() {
    let original = TcpTestPacket {
        data_size: 5,
        data: vec![1, 2, 3, 4, 5],
    };
    let encoded = snare::Packetable::encode(&original);
    let (decoded, size) = <TcpTestPacket as snare::Packetable>::decode(&encoded).unwrap();
    assert_eq!(size, encoded.len());
    assert_eq!(original.data_size, decoded.data_size);
    assert_eq!(original.data.len(), decoded.data.len());
    for (o, d) in original.data.iter().zip(decoded.data.iter()) {
        assert_eq!(o, d);
    }
}

#[derive(Clone, Debug, Encode, Decode)]
struct UdpTestPacket {
    data_size: u32,
    data: Vec<u8>,
}

impl UdpTestPacket {
    fn new(data: &'static [u8]) -> Self {
        Self {
            data_size: data.len() as u32,
            data: data.to_vec(),
        }
    }
}

impl Packetable for UdpTestPacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        bincode::decode_from_slice(data, bincode::config::standard()).ok()
    }
}

#[test]
fn test_encode_decode_udp_packet() {
    let original = UdpTestPacket {
        data_size: 5,
        data: vec![1, 2, 3, 4, 5],
    };
    let encoded = snare::Packetable::encode(&original);
    let (decoded, size) = <UdpTestPacket as snare::Packetable>::decode(&encoded).unwrap();
    assert_eq!(size, encoded.len());
    assert_eq!(original.data_size, decoded.data_size);
    assert_eq!(original.data.len(), decoded.data.len());
    for (o, d) in original.data.iter().zip(decoded.data.iter()) {
        assert_eq!(o, d);
    }
}

#[derive(Default)]
struct PacketCountStatec {
    packet_count: usize,
}

fn send_packets<T: Packetable>(addr: SocketAddr, packets: Vec<T>) {
    if packets.is_empty() {
        panic!("not enough packets")
    }
    if T::SOCKET_TYPE == SocketType::Tcp {
        let mut stream = TcpStream::connect(addr).unwrap();
        for packet in packets {
            let encoded = Packetable::encode(&packet);
            stream.write_all(&encoded).unwrap();
        }
    } else {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 4001))).unwrap();
        for packet in packets {
            let encoded = Packetable::encode(&packet);
            socket.send_to(&encoded, addr).unwrap();
        }
    }
}

#[test]
fn test_tcp_packet_count() {
    type Packet = TcpTestPacket;
    register_test();
    fn incr_cnt(state: &mut PacketCountStatec, packet: Packet, _src: SocketAddr) -> Option<Packet> {
        state.packet_count += 1;
        Some(packet)
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    let mut tester = connect_tester::<Packet>(addr).then_stateful_test(incr_cnt);
    let packets_to_send = vec![
        Packet::new(&[1, 2, 3]),
        Packet::new(&[4, 5, 6, 7]),
        Packet::new(&[8, 9]),
        Packet::new(&[10]),
        Packet::new(&[11, 12, 13, 14, 15]),
        Packet::new(&[16, 17, 18, 19, 20, 21]),
        Packet::new(&[22, 23, 24, 25, 26, 27, 28]),
        Packet::new(&[29, 30, 31, 32, 33, 34, 35, 36]),
        Packet::new(&[37, 38, 39, 40, 41, 42, 43, 44, 45]),
        Packet::new(&[46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56]),
    ];
    let expected_packet_count = packets_to_send.len();
    std::thread::spawn(move || {
        send_packets(addr, packets_to_send);
    })
    .thread()
    .id()
    .register_as_child();
    run_testers!(tester);
    let rx_cnt = tester.peek_state::<PacketCountStatec>().packet_count;
    assert_eq!(rx_cnt, expected_packet_count);
}

#[test]
fn test_udp_packet_count() {
    type Packet = UdpTestPacket;
    register_test();
    fn incr_cnt(state: &mut PacketCountStatec, packet: Packet, _src: SocketAddr) -> Option<Packet> {
        state.packet_count += 1;
        Some(packet)
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    let mut tester = connect_tester::<Packet>(addr)
        .then_stateful_test(incr_cnt)
        .until_stateful_condition::<TimerState>(|state| {
            state.poll_elapsed() >= Duration::from_secs(2)
        });
    let packets_to_send = vec![
        Packet::new(&[1, 2, 3]),
        Packet::new(&[4, 5, 6, 7]),
        Packet::new(&[8, 9]),
        Packet::new(&[10]),
        Packet::new(&[11, 12, 13, 14, 15]),
        Packet::new(&[16, 17, 18, 19, 20, 21]),
        Packet::new(&[22, 23, 24, 25, 26, 27, 28]),
        Packet::new(&[29, 30, 31, 32, 33, 34, 35, 36]),
        Packet::new(&[37, 38, 39, 40, 41, 42, 43, 44, 45]),
        Packet::new(&[46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56]),
    ];
    let expected_packet_count = packets_to_send.len();
    std::thread::spawn(move || {
        send_packets(addr, packets_to_send);
    })
    .thread()
    .id()
    .register_as_child();
    run_testers!(tester);
    let rx_cnt = tester.peek_state::<PacketCountStatec>().packet_count;
    assert_eq!(rx_cnt, expected_packet_count);
}

#[test]
fn test_udp_nonblocking_recv() {
    register_test();
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 4];
    let err = socket.recv_from(&mut buf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

#[test]
fn test_tcp_accept_nonblocking() {
    register_test();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.set_nonblocking(true).unwrap();
    let err = match listener.accept() {
        Ok(_) => panic!("expected nonblocking accept to fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}
