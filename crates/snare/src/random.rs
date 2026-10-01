//! Deterministic randomness for the code under test: every `getrandom`/`getentropy`/`arc4random`/
//! `BCryptGenRandom`/`ProcessPrng` call a managed thread makes is served from a stream seeded by
//! the sim's seed and the thread's lineage id, so std's `HashMap` keys, `rand`'s OS-seeded
//! generators and the like come out the same on every run — and each thread's stream is its own,
//! so how the OS interleaves threads cannot reorder the values any one thread sees.

use std::cell::RefCell;

use snare_interpose::{Flow, Layer};

use crate::netpolicy::SplitMix64;

pub(crate) struct RandomLayer {
    pub(crate) seed: u64,
}

thread_local! {
    /// The calling thread's stream, with the (seed, lineage) it was started from.
    static STREAM: RefCell<Option<((u64, u64), SplitMix64)>> = const { RefCell::new(None) };
}

impl Layer for RandomLayer {
    fn random(&self, buffer: &mut [u8]) -> Flow<()> {
        let key = (self.seed, snare_interpose::thread_lineage());
        let filled = STREAM.try_with(|stream| {
            let mut stream = stream.borrow_mut();
            if stream.as_ref().is_none_or(|(k, _)| *k != key) {
                let mut origin = SplitMix64(key.0 ^ key.1.rotate_left(32));
                *stream = Some((key, SplitMix64(origin.next_u64())));
            }
            let (_, rng) = stream.as_mut().expect("stream");
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
