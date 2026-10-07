//! Threads with the smallest stack the OS allows run their hooked calls inside a sim: logger
//! flushers and other helper threads ask for a few KiB (flexi_logger's flusher asks for 1 KiB,
//! raised to the platform minimum of 16 KiB on macOS and x86-64 Linux), and every hook those
//! threads reach runs on that stack. A hook whose frames do not fit overflows it and aborts the
//! test process, so a failure here shows as the binary dying with a stack overflow, not as a
//! failed assertion. Debug builds are the strict case: every local keeps its own slot.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use snare::FsBuilder;
use snare::{Sim, SimBuilder};

const STACK: usize = 16 * 1024;

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// A sim to build, with its name for messages.
type NamedSim = (&'static str, fn() -> SimBuilder);

fn sims() -> [NamedSim; 2] {
    [
        ("free-running", Sim::builder as fn() -> SimBuilder),
        ("deterministic", || Sim::builder().deterministic()),
    ]
}

fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("snare-small-stack-{}-{tag}", std::process::id()))
}

fn file_io(path: PathBuf) {
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"hello").unwrap();
    f.flush().unwrap();
    drop(f);
    let mut read = String::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_string(&mut read)
        .unwrap();
    assert_eq!(read, "hello");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn file_io_on_a_small_stack() {
    for (name, sim) in sims() {
        let path = scratch(name);
        sim()
            .build()
            .run(move || on_small_stack(move || file_io(path)));
    }
}

#[cfg(unix)]
#[test]
fn virtual_file_io_on_a_small_stack() {
    for (_, sim) in sims() {
        let fs = FsBuilder::new().file("/var/log/app.log", "").build();
        sim().fs(fs).build().run(|| {
            on_small_stack(|| {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open("/var/log/app.log")
                    .unwrap();
                f.write_all(b"line\n").unwrap();
                assert_eq!(std::fs::read("/var/log/app.log").unwrap(), b"line\n");
            })
        });
    }
}

#[test]
fn tcp_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            on_small_stack(|| {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let mut client =
                    std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (mut server, _) = listener.accept().unwrap();
                client.write_all(b"x").unwrap();
                let mut byte = [0u8; 1];
                server.read_exact(&mut byte).unwrap();
                drop(client);
                assert_eq!(server.read(&mut byte).unwrap(), 0);
            })
        });
    }
}

#[test]
fn udp_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            on_small_stack(|| {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_millis(5)))
                    .unwrap();
                socket
                    .send_to(b"ping", socket.local_addr().unwrap())
                    .unwrap();
                let mut buf = [0u8; 8];
                assert_eq!(socket.recv(&mut buf).unwrap(), 4);
                assert!(socket.recv(&mut buf).is_err());
            })
        });
    }
}

#[test]
fn sleep_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            on_small_stack(|| {
                for _ in 0..3 {
                    thread::sleep(Duration::from_millis(5));
                }
            })
        });
    }
}

#[test]
fn condvar_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            on_small_stack(|| {
                let pair = Arc::new((Mutex::new(false), Condvar::new()));
                let theirs = pair.clone();
                let setter = thread::Builder::new()
                    .stack_size(STACK)
                    .spawn(move || {
                        thread::sleep(Duration::from_millis(2));
                        *theirs.0.lock().unwrap() = true;
                        theirs.1.notify_all();
                    })
                    .unwrap();
                let (flag, cv) = &*pair;
                let mut set = flag.lock().unwrap();
                while !*set {
                    set = cv.wait_timeout(set, Duration::from_millis(50)).unwrap().0;
                }
                drop(set);
                setter.join().unwrap();
            })
        });
    }
}

#[test]
fn recv_timeout_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            on_small_stack(|| {
                let (tx, rx) = mpsc::channel::<u32>();
                assert!(rx.recv_timeout(Duration::from_millis(5)).is_err());
                let sender = thread::Builder::new()
                    .stack_size(STACK)
                    .spawn(move || {
                        thread::sleep(Duration::from_millis(5));
                        tx.send(7).unwrap();
                    })
                    .unwrap();
                assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), 7);
                sender.join().unwrap();
            })
        });
    }
}

#[test]
fn contended_mutex_on_a_small_stack() {
    for (_, sim) in sims() {
        sim().build().run(|| {
            let count = Arc::new(Mutex::new(0u32));
            let threads: Vec<_> = (0..3)
                .map(|_| {
                    let count = count.clone();
                    thread::Builder::new()
                        .stack_size(STACK)
                        .spawn(move || {
                            for _ in 0..100 {
                                *count.lock().unwrap() += 1;
                                thread::yield_now();
                            }
                        })
                        .unwrap()
                })
                .collect();
            for thread in threads {
                thread.join().unwrap();
            }
            assert_eq!(*count.lock().unwrap(), 300);
        });
    }
}

/// A small-stack thread a sim created keeps running after that sim's `run` returns, as a
/// logger's flusher does, and its calls are still served there.
#[test]
fn a_small_stack_thread_outliving_its_run() {
    let (steps, rx) = mpsc::channel::<Option<PathBuf>>();
    let (done, finished) = mpsc::channel::<()>();
    Sim::new().run(move || {
        thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                while let Ok(Some(path)) = rx.recv() {
                    file_io(path);
                    thread::sleep(Duration::from_millis(1));
                    done.send(()).unwrap();
                }
            })
            .unwrap();
    });
    for n in 0..3 {
        steps.send(Some(scratch(&format!("after-{n}")))).unwrap();
        finished.recv().unwrap();
    }
    steps.send(None).unwrap();
}
