use std::{
    sync::{
        Arc,
        atomic::{AtomicI8, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use std::io;

use parking_lot::Mutex;

use crate::{
    TcpListener, TcpStream, UdpSocket,
    state::{
        tcp_listener_status, tcp_stream_status, trigger_event, udp_socket_status, wait_for_event,
    },
};

pub use mio::{Interest, Token, features, guide};

#[derive(Debug)]
pub struct Poll {
    registry: Registry,
}

/// Returns `-1`: there is no kernel poller behind the shim. Real mio exposes
/// the epoll/kqueue fd here; anything that tries to use this one (e.g.
/// nesting the poller in an outer event loop) fails with `EBADF` instead of
/// silently polling the wrong thing.
#[cfg(unix)]
impl std::os::fd::AsRawFd for Poll {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}

impl Poll {
    pub fn new() -> io::Result<Poll> {
        Ok(Self {
            registry: Registry::new(),
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();
        let deadline = match timeout {
            Some(dur) => Instant::now() + dur,
            None => Instant::now() + Duration::from_secs(60_000),
        };

        loop {
            if Instant::now() >= deadline || events.inner.len() > 0 {
                break;
            }

            if self.registry.waker_state.swap(-1, Ordering::SeqCst) == 1 {
                let token = self.registry.waker_token.load(Ordering::SeqCst);
                events.inner.push(event::Event {
                    token: Token(token),
                    is_readable: true,
                    is_writable: true,
                    is_error: false,
                    is_read_closed: false,
                    is_write_closed: false,
                    is_priority: false,
                    is_aio: false,
                    is_lio: false,
                });
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
    interest: Interest,
}

#[derive(Debug)]
struct RegistryData {
    listeners: Vec<RegistryEntry<TcpListener>>,
    streams: Vec<RegistryEntry<TcpStream>>,
    sockets: Vec<RegistryEntry<UdpSocket>>,
}

#[derive(Debug)]
pub struct Registry {
    waker_state: Arc<AtomicI8>,
    waker_token: Arc<AtomicUsize>,
    data: Arc<Mutex<RegistryData>>,
}

/// Returns `-1`; same rationale as [`Poll`]'s impl.
#[cfg(unix)]
impl std::os::fd::AsRawFd for Registry {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}

impl Registry {
    fn new() -> Registry {
        Registry {
            waker_state: Arc::new(AtomicI8::new(0)),
            waker_token: Arc::new(AtomicUsize::new(0)),
            data: Arc::new(Mutex::new(RegistryData {
                listeners: Vec::new(),
                streams: Vec::new(),
                sockets: Vec::new(),
            })),
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
            data: self.data.clone(),
        })
    }
}

#[derive(Debug)]
pub struct Waker {
    waker_state: Arc<AtomicI8>,
}

impl Waker {
    pub fn new(registry: &Registry, token: Token) -> io::Result<Waker> {
        let waker_state = registry.waker_state.clone();
        if waker_state.swap(-1, Ordering::SeqCst) != 0 {
            panic!("Only a single waker is allowed per registry")
        }
        registry.waker_token.store(token.0, Ordering::SeqCst);
        Ok(Self { waker_state })
    }

    pub fn wake(&self) -> io::Result<()> {
        // SeqCst pairs with the swap in Poll::poll — Relaxed here would let
        // a concurrent poll on another thread miss the state change.
        self.waker_state.store(1, Ordering::SeqCst);
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

    pub struct Events {
        pub(crate) inner: Vec<Event>,
    }

    impl Events {
        pub fn with_capacity(capacity: usize) -> Events {
            Events {
                inner: Vec::with_capacity(capacity),
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

        pub fn iter(&self) -> Iter<'_> {
            Iter {
                inner: self,
                pos: 0,
            }
        }
    }

    impl std::fmt::Debug for Events {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_list().entries(self).finish()
        }
    }

    impl<'a> IntoIterator for &'a Events {
        type Item = &'a Event;
        type IntoIter = Iter<'a>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    /// [`Events`] iterator. Mirrors [`mio::event::Iter`].
    #[derive(Clone)]
    pub struct Iter<'a> {
        inner: &'a Events,
        pos: usize,
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = &'a Event;

        fn next(&mut self) -> Option<Self::Item> {
            let ret = self.inner.inner.get(self.pos);
            self.pos += 1;
            ret
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let size = self.inner.inner.len().saturating_sub(self.pos);
            (size, Some(size))
        }

        fn count(self) -> usize {
            self.inner.inner.len().saturating_sub(self.pos)
        }
    }

    impl<'a> std::fmt::Debug for Iter<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Iter").field("pos", &self.pos).finish()
        }
    }

    /// Mirrors [`mio::event::Source`]. Real mio has no default body for
    /// `reregister`, so neither do we — both must be implemented to satisfy
    /// the same contract.
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
        ) -> io::Result<()>;

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

    use crate::mio_shim::{Registry, RegistryEntry, event::Source};

    pub use crate::{TcpListener, TcpStream, UdpSocket};

    impl TcpListener {
        pub fn from_std(listener: TcpListener) -> TcpListener {
            let _ = listener.set_nonblocking(true);
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
            reg_data.listeners.push(RegistryEntry {
                src: self.try_clone()?,
                token: token,
                interest: interests,
            });
            Ok(())
        }

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.deregister(registry)?;
            self.register(registry, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data
                .listeners
                .iter()
                .position(|listener| listener.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.listeners.remove(idx);
            }
            Ok(())
        }
    }

    impl TcpStream {
        pub fn from_std(stream: TcpStream) -> TcpStream {
            let _ = stream.set_nonblocking(true);
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
            // mio only ever drives non-blocking sockets; real `mio::TcpStream`
            // is created non-blocking. The shim's `net::TcpStream` reuses the
            // std-shim's blocking `connect`, so enforce the invariant here —
            // otherwise a registered stream blocks in `read`/`write` inside the
            // poll loop instead of returning `WouldBlock`.
            self.set_nonblocking(true)?;
            let mut reg_data = registry.data.lock();
            reg_data.streams.push(RegistryEntry {
                src: self.try_clone()?,
                token: token,
                interest: interests,
            });
            Ok(())
        }

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.deregister(registry)?;
            self.register(registry, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data
                .streams
                .iter()
                .position(|listener| listener.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.streams.remove(idx);
            }
            Ok(())
        }
    }

    impl UdpSocket {
        pub fn from_std(socket: UdpSocket) -> UdpSocket {
            let _ = socket.set_nonblocking(true);
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
            self.set_nonblocking(true)?;
            let mut reg_data = registry.data.lock();
            reg_data.sockets.push(RegistryEntry {
                src: self.try_clone()?,
                token: token,
                interest: interests,
            });
            Ok(())
        }

        fn reregister(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.deregister(registry)?;
            self.register(registry, token, interests)
        }

        fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
            let mut reg_data = registry.data.lock();
            let bound_attr = self.local_addr()?;
            let pos = reg_data
                .sockets
                .iter()
                .position(|socket| socket.src.local_addr().unwrap() == bound_attr);
            if let Some(idx) = pos {
                reg_data.sockets.remove(idx);
            }
            Ok(())
        }
    }
}
