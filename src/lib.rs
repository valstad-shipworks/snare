#[cfg(feature = "shim")]
pub(crate) mod state;
#[cfg(feature = "shim")]
mod shim_std_tcp;
#[cfg(feature = "shim")]
mod shim_std_udp;
#[cfg(feature = "shim")]
mod framework;

#[cfg(feature = "shim")]
pub use shim_std_udp::ShimStdUdpSocket as UdpSocket;
#[cfg(not(feature = "shim"))]
pub use std::net::UdpSocket as UdpSocket;
#[cfg(feature = "shim")]
pub use shim_std_tcp::{ShimStdTcpListener as TcpListener, ShimStdTcpStream as TcpStream};
#[cfg(not(feature = "shim"))]
pub use std::net::{TcpListener, TcpStream};

#[cfg(feature = "shim")]
pub use state::{add_ip_addr, register_child_thread, register_test};
#[cfg(feature = "shim")]
pub use framework::*;

#[cfg(all(feature = "shim", feature = "mio-compat"))]
pub mod mio;

#[cfg(not(feature = "shim"))]
#[inline(always)]
pub fn register_child_thread(_child_thread_id: std::thread::ThreadId) {}

pub trait ThreadExt {
    fn register_as_child(self) -> Self;
}

impl ThreadExt for std::thread::ThreadId {
    #[inline(always)]
    fn register_as_child(self) -> std::thread::ThreadId {
        register_child_thread(self.clone());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    Udp,
    Tcp,
}
