//! mimalloc as the global allocator: see `support/allocator.rs`.
#![cfg(unix)]

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[path = "support/allocator.rs"]
mod allocator;

#[test]
fn threads_allocating_under_sims() {
    allocator::under_sims();
}
