use std::{
    net::SocketAddr,
    time::Duration,
};

use snare::{
    NetTesterInterface, Packetable, SocketType, TesterAction, ThreadExt, TimerState, UdpSocket, connect_tester, register_test, run_testers,
};

#[derive(Clone, Debug)]
struct BytePacket(Vec<u8>);

impl Packetable for BytePacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            None
        } else {
            Some((Self(data.to_vec()), data.len()))
        }
    }
}

#[derive(Default)]
struct ResponseState {
    sent: usize,
    expected: usize,
    last_response: Vec<u8>,
}

fn respond_by_first_byte(
    state: &mut ResponseState,
    packet: BytePacket,
    src: SocketAddr,
) -> TesterAction<BytePacket> {
    let response = match packet.0.first().copied() {
        Some(0x01) => vec![0xA1],
        Some(0x02) => vec![0xA2, 0x00],
        Some(0x03) => vec![0xA3, 0x01, 0x02],
        _ => vec![0xFF],
    };
    state.sent += 1;
    state.last_response = response.clone();
    TesterAction::Send(src, BytePacket(response))
}

fn run_response_in_thread(request: Vec<u8>, expected: Vec<u8>, tester_addr: SocketAddr, client_addr: SocketAddr) {
    let handle = std::thread::spawn(move || {
        register_test();
        let mut tester = connect_tester::<BytePacket>(tester_addr)
            .with_state::<ResponseState>(|state| state.expected = 1)
            .then_stateful_action(respond_by_first_byte)
            .until_stateful_condition::<ResponseState>(|state| state.sent >= state.expected)
            .until_stateful_condition::<TimerState>(|state| state.poll_elapsed() >= Duration::from_secs(5));

        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let client_handle = std::thread::spawn(move || {
            start_rx.recv().unwrap();
            let socket = UdpSocket::bind(client_addr).unwrap();
            socket.send_to(&request, tester_addr).unwrap();
        });
        client_handle.thread().id().register_as_child();
        start_tx.send(()).unwrap();
        run_testers!(tester);
        let state = tester.peek_state::<ResponseState>();
        assert_eq!(state.last_response, expected);
        client_handle.join().unwrap();
    });
    handle.join().unwrap();
}

#[test]
fn responds_with_correct_payload_single_packet() {
    run_response_in_thread(
        vec![0x01, 0x10],
        vec![0xA1],
        SocketAddr::from(([127, 0, 0, 1], 4400)),
        SocketAddr::from(([127, 0, 0, 1], 4401)),
    );
}

#[test]
fn responds_with_correct_payload_alt_packet() {
    run_response_in_thread(
        vec![0x03, 0x99],
        vec![0xA3, 0x01, 0x02],
        SocketAddr::from(([127, 0, 0, 1], 4410)),
        SocketAddr::from(([127, 0, 0, 1], 4411)),
    );
}
