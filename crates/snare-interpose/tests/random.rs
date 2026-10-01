use std::hash::BuildHasher;
use std::sync::{Arc, Mutex};

use snare_interpose::{Domain, Flow, Layer};

/// A xorshift64 stream standing in for the OS entropy source.
struct Seeded(Mutex<u64>);

impl Layer for Seeded {
    fn random(&self, buffer: &mut [u8]) -> Flow<()> {
        let mut state = self.0.lock().unwrap();
        for byte in buffer {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *byte = *state as u8;
        }
        Flow::Done(())
    }
}

fn seeded(seed: u64) -> Domain {
    Domain::new([Arc::new(Seeded(Mutex::new(seed))) as Arc<dyn Layer>])
}

/// std draws hash keys once per thread, so each run hashes on a fresh thread.
fn hash_on_fresh_thread(domain: &Domain) -> u64 {
    domain.run(|| {
        std::thread::spawn(|| std::hash::RandomState::new().hash_one("snare"))
            .join()
            .unwrap()
    })
}

#[test]
fn hash_map_seeds_follow_the_layer() {
    let first = hash_on_fresh_thread(&seeded(7));
    let again = hash_on_fresh_thread(&seeded(7));
    let other = hash_on_fresh_thread(&seeded(8));
    assert_eq!(first, again);
    assert_ne!(first, other);
}

#[test]
fn unmanaged_threads_use_os_entropy() {
    let _domain = seeded(7);
    let a = std::thread::spawn(|| std::hash::RandomState::new().hash_one("snare"))
        .join()
        .unwrap();
    let b = std::thread::spawn(|| std::hash::RandomState::new().hash_one("snare"))
        .join()
        .unwrap();
    assert_ne!(a, b);
}
