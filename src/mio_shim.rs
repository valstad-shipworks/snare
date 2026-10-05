use std::{
    sync::{
        Arc,
        atomic::{AtomicI8, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use std::io;

use parking_lot::Mutex;

use crate::{
    TcpListener, TcpStream, UdpSocket,
    sched::waitset::{WaitKey, WaitTicket},
    state::{tcp_listener_status, tcp_stream_status, udp_socket_status, wake},
    time::Instant,
};

static NEXT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

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

    /// Wait for readiness events. Timeouts are virtual time; `None` blocks
    /// until a registered source changes or a [`Waker`] fires.
    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut ticket = None;
        loop {
            self.collect(events);
            if !events.inner.is_empty() || deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            match ticket.take() {
                None => ticket = Some(WaitTicket::register(self.registry.wait_keys())),
                Some(t) => {
                    t.wait(deadline, "mio poll");
                }
            }
        }
        Ok(())
    }

    fn collect(&self, events: &mut Events) {
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

        let mut reg_data = self.registry.data.lock();
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

        for entry in reg_data.streams.iter_mut() {
            if let Some(status) = tcp_stream_status(entry.src.stream_id()) {
                let is_readable = entry.interest.is_readable() && status.readable;
                // Edge-triggered like real mio: writability is reported once,
                // then again only after it was lost or a write hit
                // `WouldBlock`. Level-triggered, an idle READABLE|WRITABLE
                // poller never blocks, so it spins and holds the clock.
                let is_writable = entry.interest.is_writable()
                    && status.writable
                    && entry.writable_at != Some(status.write_blocks);
                if !status.writable {
                    entry.writable_at = None;
                } else if is_writable {
                    entry.writable_at = Some(status.write_blocks);
                }
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
    }
}

#[derive(Debug)]
struct RegistryEntry<S> {
    src: S,
    token: Token,
    interest: Interest,
    /// The stream's `write_blocks` count when writability was last reported.
    writable_at: Option<u64>,
}

#[derive(Debug)]
struct RegistryData {
    listeners: Vec<RegistryEntry<TcpListener>>,
    streams: Vec<RegistryEntry<TcpStream>>,
    sockets: Vec<RegistryEntry<UdpSocket>>,
}

#[derive(Debug)]
pub struct Registry {
    id: u64,
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
            id: NEXT_REGISTRY_ID.fetch_add(1, Ordering::Relaxed),
            waker_state: Arc::new(AtomicI8::new(0)),
            waker_token: Arc::new(AtomicUsize::new(0)),
            data: Arc::new(Mutex::new(RegistryData {
                listeners: Vec::new(),
                streams: Vec::new(),
                sockets: Vec::new(),
            })),
        }
    }

    /// Every wait set a readiness change of a registered source is notified
    /// on, plus this registry's waker.
    fn wait_keys(&self) -> Vec<WaitKey> {
        let data = self.data.lock();
        let mut keys = vec![WaitKey::Poll(self.id)];
        let mut add = |k: WaitKey| {
            if !keys.contains(&k) {
                keys.push(k);
            }
        };
        for entry in &data.listeners {
            if let Ok(addr) = entry.src.local_addr() {
                add(WaitKey::Listener(addr));
                add(WaitKey::Addr(addr));
            }
        }
        for entry in &data.streams {
            add(WaitKey::Stream(entry.src.stream_id()));
            if let Ok(addr) = entry.src.local_addr() {
                add(WaitKey::Addr(addr));
            }
        }
        for entry in &data.sockets {
            if let Ok(addr) = entry.src.local_addr() {
                add(WaitKey::Udp(addr));
                add(WaitKey::Addr(addr));
            }
        }
        keys
    }

    fn sources_changed(&self) {
        wake(WaitKey::Poll(self.id));
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
            id: self.id,
            waker_state: self.waker_state.clone(),
            waker_token: self.waker_token.clone(),
            data: self.data.clone(),
        })
    }
}

#[derive(Debug)]
pub struct Waker {
    registry: u64,
    waker_state: Arc<AtomicI8>,
}

impl Waker {
    pub fn new(registry: &Registry, token: Token) -> io::Result<Waker> {
        let waker_state = registry.waker_state.clone();
        if waker_state.swap(-1, Ordering::SeqCst) != 0 {
            panic!("Only a single waker is allowed per registry")
        }
        registry.waker_token.store(token.0, Ordering::SeqCst);
        Ok(Self {
            registry: registry.id,
            waker_state,
        })
    }

    pub fn wake(&self) -> io::Result<()> {
        // SeqCst pairs with the swap in Poll::poll — Relaxed here would let
        // a concurrent poll on another thread miss the state change.
        self.waker_state.store(1, Ordering::SeqCst);
        wake(WaitKey::Poll(self.registry));
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
    //! mio's `net` types on snare's sockets. Like real mio they are
    //! nonblocking from creation: [`bind`](UdpSocket::bind), `from_std`,
    //! [`TcpStream::connect`] and [`TcpListener::accept`] all return
    //! nonblocking sockets. Each derefs to the snare socket it wraps.
    //!
    //! Two differences from real mio remain: `bind`, `connect` and
    //! `send_to` take any [`ToSocketAddrs`] rather than a `SocketAddr`, and
    //! [`TcpStream::connect`] completes (or fails) before it returns instead
    //! of reporting the outcome through writability and `take_error`.

    use std::io::{self, Read, Write};
    use std::net::SocketAddr;
    use std::ops::Deref;

    use mio::{Interest, Token};

    use crate::mio_shim::{Registry, RegistryEntry, event::Source};
    use crate::net::ToSocketAddrs;

    macro_rules! wrapper {
        ($name:ident) => {
            impl $name {
                /// Wraps a snare socket, switching it to nonblocking.
                pub fn from_std(inner: crate::net::$name) -> $name {
                    let _ = inner.set_nonblocking(true);
                    $name { inner }
                }
            }

            impl Deref for $name {
                type Target = crate::net::$name;

                fn deref(&self) -> &crate::net::$name {
                    &self.inner
                }
            }

            impl From<crate::net::$name> for $name {
                fn from(inner: crate::net::$name) -> $name {
                    $name::from_std(inner)
                }
            }

            impl From<$name> for crate::net::$name {
                fn from(s: $name) -> crate::net::$name {
                    s.inner
                }
            }

            /// Returns `-1`, as the snare socket it wraps does.
            #[cfg(unix)]
            impl std::os::fd::AsRawFd for $name {
                fn as_raw_fd(&self) -> std::os::fd::RawFd {
                    -1
                }
            }

            impl Source for $name {
                fn register(
                    &mut self,
                    registry: &Registry,
                    token: Token,
                    interests: Interest,
                ) -> io::Result<()> {
                    self.inner.register(registry, token, interests)
                }

                fn reregister(
                    &mut self,
                    registry: &Registry,
                    token: Token,
                    interests: Interest,
                ) -> io::Result<()> {
                    self.inner.reregister(registry, token, interests)
                }

                fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
                    self.inner.deregister(registry)
                }
            }
        };
    }

    /// Mirrors [`mio::net::TcpListener`].
    #[derive(Debug)]
    pub struct TcpListener {
        inner: crate::net::TcpListener,
    }

    wrapper!(TcpListener);

    impl TcpListener {
        pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<TcpListener> {
            crate::net::TcpListener::bind(addr).map(TcpListener::from_std)
        }

        /// Accepts a pending connection as a nonblocking stream, or fails
        /// with `WouldBlock` when none is pending.
        pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
            let (stream, addr) = self.inner.accept()?;
            Ok((TcpStream::from_std(stream), addr))
        }
    }

    /// Mirrors [`mio::net::TcpStream`].
    #[derive(Debug)]
    pub struct TcpStream {
        inner: crate::net::TcpStream,
    }

    wrapper!(TcpStream);

    impl TcpStream {
        pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
            crate::net::TcpStream::connect(addr).map(TcpStream::from_std)
        }

        /// Runs `f`, an I/O operation on this stream made outside its own
        /// methods. The shim keeps no readiness state to clear on
        /// `WouldBlock`, so this is `f()`.
        pub fn try_io<F, T>(&self, f: F) -> io::Result<T>
        where
            F: FnOnce() -> io::Result<T>,
        {
            f()
        }
    }

    impl Read for TcpStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (&self.inner).read(buf)
        }
    }

    impl Read for &TcpStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (&self.inner).read(buf)
        }
    }

    impl Write for TcpStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (&self.inner).write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&self.inner).flush()
        }
    }

    impl Write for &TcpStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (&self.inner).write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&self.inner).flush()
        }
    }

    /// Mirrors [`mio::net::UdpSocket`].
    #[derive(Debug)]
    pub struct UdpSocket {
        inner: crate::net::UdpSocket,
    }

    wrapper!(UdpSocket);

    impl UdpSocket {
        pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
            crate::net::UdpSocket::bind(addr).map(UdpSocket::from_std)
        }

        /// `IPV6_V6ONLY`: off by default on Linux and macOS, on on Windows,
        /// as the emulated OS's dual-stack sockets behave. An IPv4 socket
        /// has no such option and fails with `ENOPROTOOPT`.
        pub fn only_v6(&self) -> io::Result<bool> {
            let (os, faithful) = crate::state::os_ctx();
            if self.inner.local_addr()?.is_ipv4() {
                return Err(crate::os::os_err_for(os, crate::os::Errno::NoProtoOpt));
            }
            Ok(!faithful || os == crate::os::OsSemantics::Windows)
        }

        /// Runs `f`, an I/O operation on this socket made outside its own
        /// methods. The shim keeps no readiness state to clear on
        /// `WouldBlock`, so this is `f()`.
        pub fn try_io<F, T>(&self, f: F) -> io::Result<T>
        where
            F: FnOnce() -> io::Result<T>,
        {
            f()
        }
    }

    impl Source for crate::net::TcpListener {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.set_nonblocking(true)?;
            let mut reg_data = registry.data.lock();
            reg_data.listeners.push(RegistryEntry {
                src: self.try_clone()?,
                token,
                interest: interests,
                writable_at: None,
            });
            drop(reg_data);
            registry.sources_changed();
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

    impl Source for crate::net::TcpStream {
        fn register(
            &mut self,
            registry: &Registry,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.set_nonblocking(true)?;
            let mut reg_data = registry.data.lock();
            reg_data.streams.push(RegistryEntry {
                src: self.try_clone()?,
                token,
                interest: interests,
                writable_at: None,
            });
            drop(reg_data);
            registry.sources_changed();
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

    impl Source for crate::net::UdpSocket {
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
                token,
                interest: interests,
                writable_at: None,
            });
            drop(reg_data);
            registry.sources_changed();
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
