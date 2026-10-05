//! Deterministic randomness for the code under test: every `getrandom`/`getentropy`/`arc4random`/
//! `CCRandomGenerateBytes`/`BCryptGenRandom`/`ProcessPrng` call a managed thread makes is served from a stream seeded by
//! the sim's seed and the thread's lineage id, so std's `HashMap` keys, `rand`'s OS-seeded
//! generators and the like come out the same on every run — and each thread's stream is its own,
//! so how the OS interleaves threads cannot reorder the values any one thread sees.
//!
//! The hooks that land here live in `snare-interpose` (`os/unix.rs`, `os/windows.rs`):
//! `getrandom(2)`, `getentropy(3)`, `arc4random(3)`/`arc4random_buf(3)`, macOS
//! `CCRandomGenerateBytes`, and on Windows `BCryptGenRandom`
//! ([Microsoft Learn: BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom))
//! and `ProcessPrng`, which Rust's std calls for its own randomness on Windows
//! (rust-lang/rust `library/std/src/sys/random/windows.rs`; `RtlGenRandom` on the win7 targets).
//! Each hook applies its own call's limits (such as `getentropy`'s 256-byte cap, Linux man 3
//! getentropy and XNU `bsd/man/man2/getentropy.2`) before asking this layer, which fills whatever
//! buffer it is handed in full.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use snare_interpose::{Flow, Layer};

use crate::netpolicy::SplitMix64;

/// The interposition layer that answers every OS randomness call of a managed thread.
pub(crate) struct RandomLayer {
    /// The sim's seed; mixed with each thread's lineage id to start that thread's stream.
    pub(crate) seed: u64,
    id: u64,
    lifetime: Arc<()>,
}

impl RandomLayer {
    pub(crate) fn new(seed: u64) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            seed,
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            lifetime: Arc::new(()),
        }
    }
}

thread_local! {
    static STREAMS: RefCell<BTreeMap<(u64, u64), Stream>> = const { RefCell::new(BTreeMap::new()) };
}

struct Stream {
    lifetime: Weak<()>,
    rng: SplitMix64,
}

impl Layer for RandomLayer {
    /// Fills `buffer` from the calling thread's stream, 8 bytes per draw, little-endian, the last
    /// draw truncated to fit. The stream's state starts at the first output of
    /// `SplitMix64(seed ^ lineage.rotate_left(32))`: a snare choice that separates the two 64-bit
    /// inputs and whitens the result through one full SplitMix64 round before the first draw. Passes to the OS during thread
    /// teardown, when the thread-local is already gone.
    fn random(&self, buffer: &mut [u8]) -> Flow<()> {
        let key = (self.id, snare_interpose::thread_lineage());
        let filled = STREAMS.try_with(|streams| {
            let mut streams = streams.borrow_mut();
            if !streams.contains_key(&key) {
                streams.retain(|_, stream| stream.lifetime.strong_count() > 0);
                let mut origin = SplitMix64(self.seed ^ key.1.rotate_left(32));
                streams.insert(
                    key,
                    Stream {
                        lifetime: Arc::downgrade(&self.lifetime),
                        rng: SplitMix64(origin.next_u64()),
                    },
                );
            }
            let rng = &mut streams.get_mut(&key).expect("stream").rng;
            for chunk in buffer.chunks_mut(8) {
                let word = rng.next_u64().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        });
        match filled {
            Ok(()) => Flow::Done(()),
            // Thread teardown: let the OS answer.
            Err(_) => Flow::Pass,
        }
    }
}
