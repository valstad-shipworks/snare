//! jemalloc as the global allocator, with (on Linux) its background threads on and a short decay,
//! so a purge and its wake-ups happen in the middle of a run: see `support/allocator.rs`.
#![cfg(unix)]

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc's options (jemalloc(3), "TUNING"), read under the unprefixed name the Linux build
/// gives it in replacing the system `malloc`. Background threads exist only on Linux.
#[cfg(target_os = "linux")]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8; 61] =
    b"background_thread:true,dirty_decay_ms:100,muzzy_decay_ms:100\0";

#[path = "support/allocator.rs"]
mod allocator;

#[test]
fn threads_allocating_under_sims() {
    allocator::under_sims();
}
