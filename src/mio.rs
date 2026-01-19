
use std::{sync::{Arc, atomic::{AtomicI8, AtomicUsize, Ordering}}, time::{Duration, Instant}};

use std::io;

use parking_lot::Mutex;

use crate::{
    TcpListener, TcpStream, UdpSocket,
    state::{trigger_event, wait_for_event, tcp_listener_status, tcp_stream_status, udp_socket_status}
};

pub use mio::{Interest, Token, features, guide};

#[derive(Debug)]
pub struct Poll {
    registry: Registry
}

impl Poll {
    pub fn new() -> io::Result<Poll> {
        Ok(
            Self { registry: Registry::new() }
        )
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();
        let deadline = match timeout {
            Some(dur) => Instant::now() + dur,
            None => Instant::now() + Duration::from_secs(60_000)
        };

        loop {
            if Instant::now() >= deadline || events.inner.len() > 0 {
                break;
            }

            if self.registry.waker_state.swap(-1, Ordering::SeqCst) == 1 {
                let token = self.registry.waker_token.load(Ordering::SeqCst);
                events.inner.push(
                    event::Event {
                        token: Token(token),
                        is_readable: true,
                        is_writable: true,
                        is_error: false,
                        is_read_closed: false,
                        is_write_closed: false,
                        is_priority: false,
                        is_aio: false,
                        is_lio: false
                    }
                );
            }

            let reg_data = self.registry.data.lock();
            for entry in reg_data.listeners.iter() {
                let Ok(addr) = entry.src.local_addr() else {
                    continue;
                };
                if let Some(status) = tcp_listener_status(addr) {
                    let is_readable = entry.interest.is_readable() && status.pending;
                    let is_error = status.error;
                    let is_read_closed = status.closed && entry.interest.is_readable();
                    if is_readable || is_error || is_read_closed {
                        events.inner.push(event::Event {
                            token: entry.token,
                            is_readable,
                            is_writable: false,
                            is_error,
                            is_read_closed,
                            is_write_closed: false,
                            is_priority: false,
                            is_aio: false,
                            is_lio: false,
                        });
                    }
                }
            }

            for entry in reg_data.streams.iter() {
                let Ok(addr) = entry.src.local_addr() else {
                    continue;
                };
                if let Some(status) = tcp_stream_status(addr) {
                    let is_readable = entry.interest.is_readable() && status.readable;
                    let is_writable = entry.interest.is_writable() && status.writable;
                    let is_error = status.error;
                    let is_read_closed = status.read_closed && entry.interest.is_readable();
                    let is_write_closed = status.write_closed && entry.interest.is_writable();
                    if is_readable || is_writable || is_error || is_read_closed || is_write_closed {
                        events.inner.push(event::Event {
                            token: entry.token,
                            is_readable,
                            is_writable,
                            is_error,
                            is_read_closed,
                            is_write_closed,
                            is_priority: false,
                            is_aio: false,
                            is_lio: false,
                        });
                    }
                }
            }

            for entry in reg_data.sockets.iter() {
                let Ok(addr) = entry.src.local_addr() else {
                    continue;
                };
                if let Some(status) = udp_socket_status(addr) {
                    let is_readable = entry.interest.is_readable() && status.readable;
                    let is_writable = entry.interest.is_writable() && status.writable;
                    let is_error = status.error;
                    let is_read_closed = status.closed && entry.interest.is_readable();
                    let is_write_closed = status.closed && entry.interest.is_writable();
                    if is_readable || is_writable || is_error || is_read_closed || is_write_closed {
                        events.inner.push(event::Event {
                            token: entry.token,
                            is_readable,
                            is_writable,
                            is_error,
                            is_read_closed,
                            is_write_closed,
                            is_priority: false,
                            is_aio: false,
                            is_lio: false,
                        });
                    }
                }
            }

            wait_for_event(Some(deadline.saturating_duration_since(Instant::now())));
        }

        Ok(())
    }
}

#[derive(Debug)]
struct RegistryEntry<S> {
    src: S,
    token: Token,
    interest: Interest
}

#[derive(Debug)]
struct RegistryData {
    listeners: Vec<RegistryEntry<TcpListener>>,
    streams: Vec<RegistryEntry<TcpStream>>,
    sockets: Vec<RegistryEntry<UdpSocket>>
}

#[derive(Debug)]
pub struct Registry {
    waker_state: Arc<AtomicI8>,
    waker_token: Arc<AtomicUsize>,
    data: Arc<Mutex<RegistryData>>
}

impl Registry {
    fn new() -> Registry {
        Registry {
            waker_state: Arc::new(AtomicI8::new(0)),
            waker_token: Arc::new(AtomicUsize::new(0)),
            data: Arc::new(Mutex::new(
                RegistryData {
                    listeners: Vec::new(),
                    streams: Vec::new(),
                    sockets: Vec::new()
                }
            ))
        }
    }

    pub fn register<S>(&self, source: &mut S, token: Token, interests: Interest) -> io::Result<()>
    where
        S: event::Source + ?Sized,
    {
        source.register(self, token, interests)
    }

    pub fn reregister<S>(&self, source: &mut S, token: Token, interests: Interest) -> io::Result<()>
    where
        S: event::Source + ?Sized,
    {
        source.reregister(self, token, interests)
    }

    pub fn deregister<S>(&self, source: &mut S) -> io::Result<()>
    where
        S: event::Source + ?Sized,
    {
        source.deregister(self)
    }

    pub fn try_clone(&self) -> io::Result<Registry> {
        Ok(Registry {
            waker_state: self.waker_state.clone(),
            waker_token: self.waker_token.clone(),
            data: self.data.clone()
        })
    }
}

#[derive(Debug)]
pub struct Waker {
    waker_state: Arc<AtomicI8>
}

impl Waker {
    pub fn new(registry: &Registry, token: Token) -> io::Result<Waker> {
        let waker_state = registry.waker_state.clone();
        if waker_state.swap(-1, Ordering::SeqCst) != 0 {
            panic!("Only a single waker is allowed per registry")
        }
        registry.waker_token.store(token.0, Ordering::SeqCst);
        Ok(Self {
            waker_state
        })
    }

    pub fn wake(&self) -> io::Result<()> {
        self.waker_state.store(1, Ordering::Relaxed);
        trigger_event();
        Ok(())
    }
}

pub use event::Events;
pub mod event {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Event {
        pub(crate) token: Token,
        pub(crate) is_readable: bool,
        pub(crate) is_writable: bool,
        pub(crate) is_error: bool,
        pub(crate) is_read_closed: bool,
        pub(crate) is_write_closed: bool,
        pub(crate) is_priority: bool,
        pub(crate) is_aio: bool,
        pub(crate) is_lio: bool,
    }

    impl Event {
        pub fn token(&self) -> Token {
            self.token
        }

        pub fn is_readable(&self) -> bool {
            self.is_readable
        }

        pub fn is_writable(&self) -> bool {
            self.is_writable
        }

        pub fn is_error(&self) -> bool {
            self.is_error
        }

        pub fn is_read_closed(&self) -> bool {
            self.is_read_closed
        }

        pub fn is_write_closed(&self) -> bool {
            self.is_write_closed
        }

        pub fn is_priority(&self) -> bool {
            self.is_priority
        }

        pub fn is_aio(&self) -> bool {
            self.is_aio
        }

        pub fn is_lio(&self) -> bool {
            self.is_lio
        }
    }

    #[derive(Debug)]
    pub struct Events {
        pub(crate) inner: Vec<Event>
    }

    impl Events {
        pub fn with_capacity(capacity: usize) -> Events {
            Events {
                inner: Vec::with_capacity(capacity)
            }
        }

        pub fn capacity(&self) -> usize {
            self.inner.capacity()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn clear(&mut self) {
            self.inner.clear();
        }

        pub fn iter(&self) -> std::slice::Iter<'_, Event> {
            self.inner.iter()
        }
    }

    impl IntoIterator for Events {
        type Item = Event;
        type IntoIter = std::vec::IntoIter<Event>;

        fn into_iter(self) -> Self::IntoIter {
            self.inner.into_iter()
        }
    }

    pub trait Source {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()>;

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.deregister(registry)?;
            self.register(registry, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()>;
    }

    impl<T> Source for Box<T>
    where
        T: Source + ?Sized,
    {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            (**self).register(registry, token, interests)
        }

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            (**self).reregister(registry, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            (**self).deregister(registry)
        }
    }
}

pub mod net {
    use std::io;

    use mio::{Interest, Token};

    use crate::mio::{Registry, RegistryEntry, event::Source};

    pub use crate::{TcpListener, TcpStream, UdpSocket};

    impl TcpListener {
        pub fn from_std(listener: TcpListener) -> TcpListener {
            listener
        }
    }

    impl Source for TcpListener {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            reg_data.listeners.push(
                RegistryEntry {
                    src: self.try_clone()?,
                    token: token,
                    interest: interests
                }
            );
            Ok(())
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data.listeners.iter()
                .position(|listener| listener.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.listeners.remove(idx);
            }
            Ok(())
        }
    }

    impl TcpStream {
        pub fn from_std(stream: TcpStream) -> TcpStream {
            stream
        }
    }

    impl Source for TcpStream {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            reg_data.streams.push(
                RegistryEntry {
                    src: self.try_clone()?,
                    token: token,
                    interest: interests
                }
            );
            Ok(())
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data.streams.iter()
                .position(|listener| listener.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.streams.remove(idx);
            }
            Ok(())
        }
    }

    impl UdpSocket {
        pub fn from_std(socket: UdpSocket) -> UdpSocket {
            socket
        }
    }

    impl Source for UdpSocket {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            reg_data.sockets.push(
                RegistryEntry {
                    src: self.try_clone()?,
                    token: token,
                    interest: interests
                }
            );
            Ok(())
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data.sockets.iter()
                .position(|socket| socket.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.sockets.remove(idx);
            }
            Ok(())
        }
    }
}
