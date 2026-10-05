//! snare's sockets as fast-talker socket handles: they carry a simulated
//! handle and never an OS one.

use ::fast_talker::__sim::{AsHandle, SimHandle};

use crate::netif::SimSocket;

macro_rules! sim_handle {
    ($($ty:ty),*) => {$(
        impl AsHandle for $ty {
            fn sim_handle(&self) -> Option<SimHandle> {
                Some(SimHandle(self.socket_id().get()))
            }

            #[cfg(unix)]
            fn os_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
                None
            }

            #[cfg(windows)]
            fn os_socket(&self) -> Option<std::os::windows::io::BorrowedSocket<'_>> {
                None
            }
        }
    )*};
}

sim_handle!(
    crate::net::UdpSocket,
    crate::net::TcpStream,
    crate::net::TcpListener
);

#[cfg(feature = "mio-compat")]
sim_handle!(
    crate::mio_shim::net::UdpSocket,
    crate::mio_shim::net::TcpStream,
    crate::mio_shim::net::TcpListener
);
