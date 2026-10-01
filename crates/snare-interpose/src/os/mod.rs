#[cfg(unix)]
mod files;
#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "macos")]
mod host_macos;
#[cfg(unix)]
mod sockets;
#[cfg(unix)]
mod sync;
#[cfg(unix)]
mod unix;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod variadic;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::hooks;
#[cfg(windows)]
pub(crate) use windows::hooks;
