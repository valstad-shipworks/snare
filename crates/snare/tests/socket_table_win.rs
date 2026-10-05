#![cfg(windows)]

//! The socket table on the Winsock backend: ids, `WSADuplicateSocketW` (`try_clone`) sharing one
//! record, and an accepted stream naming its listener.

use std::net::{TcpListener, TcpStream, UdpSocket};

use snare::{Sim, SocketKind};

#[test]
fn ids_dup_and_close() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (ida, idb) = (snare::socket_id(&a).unwrap(), snare::socket_id(&b).unwrap());
        assert!(ida < idb);

        let a2 = a.try_clone().unwrap();
        assert_eq!(snare::socket_id(&a2), Some(ida));
        drop(a);
        assert_eq!(snare::socket_entry(ida).unwrap().closed_at, None);
        drop(a2);
        assert!(snare::socket_entry(ida).unwrap().closed_at.is_some());

        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(snare::socket_id(&c).unwrap() > idb);
        let closed: Vec<_> = snare::closed_sockets().iter().map(|e| e.id).collect();
        assert_eq!(closed, vec![ida]);
    });
}

#[test]
fn accepted_stream_records_listener() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        let e = snare::socket_entry(snare::socket_id(&accepted).unwrap()).unwrap();
        assert_eq!(e.kind, SocketKind::TcpStream);
        assert_eq!(e.listener, snare::socket_id(&listener));
        assert_eq!((e.local, e.peer), (Some(addr), Some(peer)));
        assert_eq!(client.local_addr().unwrap(), peer);
        assert_eq!(
            snare::socket_entry(snare::socket_id(&listener).unwrap())
                .unwrap()
                .kind,
            SocketKind::TcpListener
        );
    });
}
