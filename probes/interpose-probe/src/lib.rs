//! A dynamic library loaded at run time by snare-interpose's Windows tests. Its one export calls
//! a hooked OS function, so a test can prove a module loaded after `install` is both patched and
//! redirected.

/// Reads the monotonic performance counter through this module's own import of
/// `QueryPerformanceCounter`, which the interposer must have rebound when the module loaded.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "C" fn interpose_probe_qpc() -> i64 {
    unsafe extern "system" {
        fn QueryPerformanceCounter(count: *mut i64) -> i32;
    }
    let mut count = 0;
    // SAFETY: writes one i64.
    unsafe { QueryPerformanceCounter(&mut count) };
    count
}

#[cfg(not(windows))]
#[unsafe(no_mangle)]
pub extern "C" fn interpose_probe_qpc() -> i64 {
    0
}
