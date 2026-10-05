#![cfg(windows)]

use std::sync::atomic::{AtomicU64, Ordering};

use snare::Sim;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};

fn install_completion_hooks() {
    let report = snare_interpose::install();
    for name in [
        "CreateIoCompletionPort",
        "GetQueuedCompletionStatus",
        "GetQueuedCompletionStatusEx",
        "NtCreateFile",
        "NtDeviceIoControlFile",
        "NtCancelIoFileEx",
    ] {
        assert!(
            report
                .images
                .iter()
                .any(|image| image.modelled.contains(&name)),
            "missing modeled hook {name}: {report:?}"
        );
    }
}

#[repr(C)]
#[derive(Default)]
struct Overlapped {
    internal: usize,
    high: usize,
    offset: [u32; 2],
    event: HANDLE,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateIoCompletionPort(file: HANDLE, port: HANDLE, key: usize, threads: u32) -> HANDLE;
    fn PostQueuedCompletionStatus(port: HANDLE, bytes: u32, key: usize, overlapped: *mut u8)
    -> i32;
    fn GetQueuedCompletionStatus(
        port: HANDLE,
        bytes: *mut u32,
        key: *mut usize,
        overlapped: *mut *mut u8,
        timeout: u32,
    ) -> i32;
    fn CreateNamedPipeW(
        name: *const u16,
        access: u32,
        mode: u32,
        instances: u32,
        output: u32,
        input: u32,
        timeout: u32,
        security: *mut u8,
    ) -> HANDLE;
    fn ConnectNamedPipe(pipe: HANDLE, overlapped: *mut Overlapped) -> i32;
    fn CancelIoEx(file: HANDLE, overlapped: *mut Overlapped) -> i32;
}

type Posted = (i32, u32, usize, bool);
type TimedOut = (i32, u32, u32, usize, bool);

#[inline(never)]
fn posted_and_timed_out() -> (Posted, TimedOut) {
    unsafe {
        let port = CreateIoCompletionPort(usize::MAX as HANDLE, std::ptr::null_mut(), 0, 1);
        assert!(!port.is_null());
        let mut packet = 0u8;
        assert_ne!(PostQueuedCompletionStatus(port, 37, 91, &mut packet), 0);
        let mut bytes = 0;
        let mut key = 0;
        let mut pointer = std::ptr::null_mut();
        let result = GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut pointer, 1000);
        let posted = (result, bytes, key, pointer == &raw mut packet);
        bytes = 13;
        key = 17;
        pointer = std::ptr::dangling_mut::<u8>();
        let result = GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut pointer, 0);
        let timeout = (result, GetLastError(), bytes, key, pointer.is_null());
        assert_ne!(CloseHandle(port), 0);
        (posted, timeout)
    }
}

#[test]
fn posted_packets_and_timeout_outputs_match_native() {
    install_completion_hooks();
    let native = posted_and_timed_out();
    assert_eq!(native, ((1, 37, 91, true), (0, 258, 13, 17, true)));
    assert_eq!(Sim::new().run(posted_and_timed_out), native);
    assert_eq!(
        Sim::builder()
            .deterministic()
            .build()
            .run(posted_and_timed_out),
        native
    );
}

#[inline(never)]
fn cancelled_file_completion() -> (i32, u32, u32, usize, bool) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name: Vec<u16> = format!(
        "\\\\.\\pipe\\snare-iocp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .chain([0])
    .collect();
    unsafe {
        let pipe = CreateNamedPipeW(
            name.as_ptr(),
            3 | 0x40000000,
            0,
            1,
            4096,
            4096,
            0,
            std::ptr::null_mut(),
        );
        assert_ne!(pipe as usize, usize::MAX, "{}", GetLastError());
        let port = CreateIoCompletionPort(pipe, std::ptr::null_mut(), 71, 1);
        assert!(!port.is_null(), "{}", GetLastError());
        let mut operation = Overlapped::default();
        assert_eq!(ConnectNamedPipe(pipe, &mut operation), 0);
        assert_eq!(GetLastError(), 997);
        assert_ne!(CancelIoEx(pipe, &mut operation), 0, "{}", GetLastError());
        let mut bytes = 99;
        let mut key = 0;
        let mut pointer = std::ptr::null_mut();
        let result = GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut pointer, 1000);
        let error = GetLastError();
        let observed = (
            result,
            error,
            bytes,
            key,
            pointer == (&raw mut operation).cast(),
        );
        assert_ne!(CloseHandle(pipe), 0);
        assert_ne!(CloseHandle(port), 0);
        observed
    }
}

#[test]
fn failed_native_file_completion_preserves_status_and_outputs() {
    install_completion_hooks();
    let native = cancelled_file_completion();
    assert_eq!(native, (0, 995, 0, 71, true));
    assert_eq!(Sim::new().run(cancelled_file_completion), native);
    assert_eq!(
        Sim::builder()
            .deterministic()
            .build()
            .run(cancelled_file_completion),
        native
    );
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: usize,
    name: *const UnicodeString,
    attributes: u32,
    security: usize,
    quality: usize,
}
#[repr(C)]
#[derive(Default)]
struct IoStatus {
    status: isize,
    information: usize,
}
#[repr(C)]
struct PollInfo {
    timeout: i64,
    count: u32,
    exclusive: u32,
    handle: usize,
    events: u32,
    status: i32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        status: *mut IoStatus,
        size: *mut i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        buffer: *mut u8,
        length: u32,
    ) -> i32;
    fn NtDeviceIoControlFile(
        file: HANDLE,
        event: HANDLE,
        routine: *mut u8,
        context: *mut u8,
        status: *mut IoStatus,
        code: u32,
        input: *mut PollInfo,
        input_len: u32,
        output: *mut PollInfo,
        output_len: u32,
    ) -> i32;
    fn NtCancelIoFileEx(file: HANDLE, request: *mut IoStatus, status: *mut IoStatus) -> i32;
}

type CancelledPacket = (i32, u32, u32, usize, bool, i32);
type CancelledAfd = (CancelledPacket, usize, u32, u32, i32);

#[inline(never)]
fn afd_probe(wait: std::time::Duration, cancel: bool) -> (i32, CancelledAfd) {
    use std::os::windows::io::AsRawSocket;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    if !cancel {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"ready", socket.local_addr().unwrap())
            .unwrap();
        assert_eq!(socket.peek_from(&mut [0; 8]).unwrap().0, 5);
    }
    let name: Vec<u16> = "\\Device\\Afd\\Mio".encode_utf16().collect();
    let unicode = UnicodeString {
        length: (name.len() * 2) as u16,
        maximum: (name.len() * 2) as u16,
        buffer: name.as_ptr(),
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root: 0,
        name: &unicode,
        attributes: 0,
        security: 0,
        quality: 0,
    };
    unsafe {
        let mut file = std::ptr::null_mut();
        let mut create_status = IoStatus::default();
        assert_eq!(
            NtCreateFile(
                &mut file,
                0x100003,
                &attributes,
                &mut create_status,
                std::ptr::null_mut(),
                0,
                3,
                1,
                0,
                std::ptr::null_mut(),
                0
            ),
            0
        );
        let port = CreateIoCompletionPort(file, std::ptr::null_mut(), 81, 1);
        assert!(!port.is_null());
        let mut info = PollInfo {
            timeout: i64::MAX,
            count: 1,
            exclusive: 0,
            handle: socket.as_raw_socket() as usize,
            events: 1,
            status: 0,
        };
        let mut request = IoStatus::default();
        let mut context = 0u8;
        let size = std::mem::size_of::<PollInfo>() as u32;
        let submitted = NtDeviceIoControlFile(
            file,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut context,
            &mut request,
            0x12024,
            &mut info,
            size,
            &mut info,
            size,
        );
        if cancel {
            assert_eq!(submitted, 0x103);
            std::thread::sleep(wait);
            let mut cancelled = IoStatus::default();
            assert_eq!(NtCancelIoFileEx(file, &mut request, &mut cancelled), 0);
        }
        let mut bytes = 99;
        let mut key = 0;
        let mut pointer = std::ptr::null_mut();
        let result = GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut pointer, 1000);
        let observed = (
            result,
            if result == 0 { GetLastError() } else { 0 },
            bytes,
            key,
            pointer == &raw mut context,
            request.status as i32,
        );
        assert_ne!(CloseHandle(file), 0);
        assert_ne!(CloseHandle(port), 0);
        (
            submitted,
            (
                observed,
                request.information,
                info.count,
                info.events,
                info.status,
            ),
        )
    }
}

#[inline(never)]
fn cancelled_afd_with_wait(wait: std::time::Duration) -> CancelledAfd {
    afd_probe(wait, true).1
}

#[inline(never)]
fn cancelled_afd_completion() -> CancelledAfd {
    cancelled_afd_with_wait(std::time::Duration::from_millis(1))
}

#[test]
fn cancelled_afd_completion_matches_native_status() {
    install_completion_hooks();
    let native = cancelled_afd_completion();
    assert_eq!(
        native,
        ((0, 995, 16, 81, true, 0xc0000120_u32 as i32), 16, 1, 1, 0)
    );
    assert_eq!(Sim::new().run(cancelled_afd_completion), native);
    assert_eq!(
        Sim::builder()
            .deterministic()
            .build()
            .run(cancelled_afd_completion),
        native
    );
}

#[inline(never)]
fn native_socket_poll() {
    use std::time::Duration;
    let receiver = snare::real(|| std::net::UdpSocket::bind("127.0.0.1:0")).unwrap();
    let destination = receiver.local_addr().unwrap();
    receiver.set_nonblocking(true).unwrap();
    let mut receiver = mio::net::UdpSocket::from_std(receiver);
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut receiver, mio::Token(77), mio::Interest::READABLE)
        .unwrap();
    let sender = snare::real(|| {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(b"native", destination)
                .unwrap();
        })
    });
    let mut events = mio::Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_secs(1)))
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.token() == mio::Token(77) && event.is_readable())
    );
    let mut bytes = [0; 8];
    let (count, _) = receiver.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"native");
    snare::real(|| sender.join()).unwrap();
}

#[test]
fn native_socket_completion_keeps_native_waiting() {
    install_completion_hooks();
    native_socket_poll();
    Sim::new().run(native_socket_poll);
    Sim::builder()
        .deterministic()
        .build()
        .run(native_socket_poll);
}

#[test]
fn infinite_poll_tracks_a_new_delayed_arrival() {
    install_completion_hooks();
    use std::time::{Duration, Instant};
    for deterministic in [false, true] {
        let builder = Sim::builder().stuck_after(Duration::from_secs(5));
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let mut receiver = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let destination = receiver.local_addr().unwrap();
            snare::set_udp_policy(destination, |policy| {
                policy.latency = Duration::from_millis(40)
            });
            let mut poll = mio::Poll::new().unwrap();
            poll.registry()
                .register(&mut receiver, mio::Token(78), mio::Interest::READABLE)
                .unwrap();
            let sender = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .unwrap()
                    .send_to(b"delayed", destination)
                    .unwrap();
            });
            let start = Instant::now();
            let mut events = mio::Events::with_capacity(4);
            poll.poll(&mut events, None).unwrap();
            assert!(start.elapsed() >= Duration::from_millis(60));
            assert!(
                events
                    .iter()
                    .any(|event| event.token() == mio::Token(78) && event.is_readable())
            );
            sender.join().unwrap();
        });
    }
}

#[test]
fn modeled_port_duplication_is_explicitly_rejected() {
    install_completion_hooks();
    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    for close_source in [false, true] {
        Sim::new().run(|| unsafe {
            let process = GetCurrentProcess();
            let port = CreateIoCompletionPort(usize::MAX as HANDLE, std::ptr::null_mut(), 0, 1);
            assert!(!port.is_null());
            let mut copy = std::ptr::null_mut();
            assert_eq!(
                DuplicateHandle(
                    process,
                    port,
                    process,
                    &mut copy,
                    0,
                    0,
                    2 | u32::from(close_source)
                ),
                0
            );
            assert_eq!(GetLastError(), 50);
            assert!(copy.is_null());
            if close_source {
                assert_eq!(
                    PostQueuedCompletionStatus(port, 0, 0, std::ptr::null_mut()),
                    0
                );
                assert_eq!(GetLastError(), 6);
            } else {
                assert_ne!(
                    PostQueuedCompletionStatus(port, 0, 0, std::ptr::null_mut()),
                    0
                );
                assert_ne!(CloseHandle(port), 0);
            }
        });
    }
}

#[repr(C)]
#[derive(Default)]
struct CompletionEntry {
    key: usize,
    overlapped: *mut u8,
    internal: usize,
    bytes: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetQueuedCompletionStatusEx(
        port: HANDLE,
        entries: *mut CompletionEntry,
        count: u32,
        removed: *mut u32,
        timeout: u32,
        alertable: i32,
    ) -> i32;
}

#[inline(never)]
fn empty_port_timeout() {
    use std::time::{Duration, Instant};
    unsafe {
        let port = CreateIoCompletionPort(usize::MAX as HANDLE, std::ptr::null_mut(), 0, 1);
        assert!(!port.is_null());
        let mut entry = CompletionEntry::default();
        let mut removed = 0;
        let start = Instant::now();
        assert_eq!(
            GetQueuedCompletionStatusEx(port, &mut entry, 1, &mut removed, 1000, 0),
            0
        );
        assert_eq!(GetLastError(), 258);
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert_ne!(CloseHandle(port), 0);
    }
}

#[test]
fn empty_owned_port_waits_on_virtual_time() {
    install_completion_hooks();
    Sim::new().run(empty_port_timeout);
    Sim::builder()
        .deterministic()
        .build()
        .run(empty_port_timeout);
}

#[test]
fn already_readable_afd_poll_matches_native_completion() {
    install_completion_hooks();
    let probe = || afd_probe(std::time::Duration::ZERO, false);
    let native = probe();
    assert_eq!(native, (0, ((1, 0, 32, 81, true, 0), 32, 1, 1, 0)));
    assert_eq!(Sim::new().run(probe), native);
    assert_eq!(Sim::builder().deterministic().build().run(probe), native);
}

#[test]
fn native_file_and_device_fallthrough_remains_visible_to_the_audit() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    install_completion_hooks();
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        sim.run(|| {
            let domain = snare_interpose::Domain::current().unwrap();
            domain.clear_unmodelled();
            let _ = afd_probe(std::time::Duration::ZERO, false);
            assert!(domain.unmodelled().iter().all(|(call, _)| {
                !matches!(call.function, "NtCreateFile" | "NtDeviceIoControlFile")
            }));
            domain.clear_unmodelled();
            let name: Vec<u16> = format!(
                "\\??\\C:\\snare-iocp-absent-{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )
            .encode_utf16()
            .collect();
            let unicode = UnicodeString {
                length: (name.len() * 2) as u16,
                maximum: (name.len() * 2) as u16,
                buffer: name.as_ptr(),
            };
            let attributes = ObjectAttributes {
                length: std::mem::size_of::<ObjectAttributes>() as u32,
                root: 0,
                name: &unicode,
                attributes: 0,
                security: 0,
                quality: 0,
            };
            let mut file = std::ptr::null_mut();
            let mut status = IoStatus::default();
            unsafe {
                assert!(
                    NtCreateFile(
                        &mut file,
                        0x100001,
                        &attributes,
                        &mut status,
                        std::ptr::null_mut(),
                        0,
                        3,
                        1,
                        0,
                        std::ptr::null_mut(),
                        0,
                    ) < 0
                );
                assert!(
                    NtDeviceIoControlFile(
                        usize::MAX as HANDLE,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut status,
                        0,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        0,
                    ) < 0
                );
            }
            for function in ["NtCreateFile", "NtDeviceIoControlFile"] {
                assert_eq!(
                    domain
                        .unmodelled()
                        .iter()
                        .filter(|(call, _)| call.function == function)
                        .map(|(_, count)| count)
                        .sum::<u64>(),
                    1,
                    "{function}"
                );
            }
        });
    }
}
