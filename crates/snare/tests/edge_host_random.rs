//! Pins the seeded entropy plane byte for byte: every OS randomness call of a managed thread is
//! served from `SplitMix64(SplitMix64(seed ^ lineage.rotate_left(32)).next())`, eight bytes per
//! draw, little-endian, a short tail truncating its word; a thread's lineage is 0 for a sim's first
//! root, `mix(ROOT_SALT, n)` for its n-th later entry and `mix(parent, birth order)` for a child.
//! The streams of several seeds, lineages and calls are kept in a golden
//! (`golden/edge_host_random.<os>.txt`) as well as recomputed here. Also pinned: chunking (a
//! partial word is discarded), empty and oversized requests, `getrandom` flags, OS entropy for
//! unmanaged threads and under `snare::real`, and how a thread's stream carries across sims.
#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::hash::BuildHasher;
use std::sync::mpsc;

use snare::Sim;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn mix(parent: u64, order: u64) -> u64 {
    let mut z = parent ^ order.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

const ROOT_SALT: u64 = 0x524f_4f54_454e_5452;

/// The stream a thread with this key starts, as successive requests of the given lengths see it.
fn expected(seed: u64, lineage: u64, requests: &[usize]) -> Vec<Vec<u8>> {
    let mut origin = SplitMix64(seed ^ lineage.rotate_left(32));
    let mut rng = SplitMix64(origin.next_u64());
    requests
        .iter()
        .map(|&n| {
            let mut out = vec![0u8; n];
            for chunk in out.chunks_mut(8) {
                let word = rng.next_u64().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            out
        })
        .collect()
}

fn getentropy(n: usize) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; n];
    let rc = unsafe { libc::getentropy(buf.as_mut_ptr().cast(), n) };
    if rc == 0 {
        Ok(buf)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

#[cfg(target_os = "linux")]
fn getrandom(n: usize, flags: libc::c_uint) -> (isize, Vec<u8>) {
    let mut buf = vec![0u8; n];
    let rc = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), n, flags) };
    (rc, buf)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CCRandomGenerateBytes(bytes: *mut std::ffi::c_void, count: usize) -> i32;
}

/// One request through each randomness call this OS has, in a fixed order.
fn every_call() -> Calls {
    let mut out = vec![("getentropy(16)", getentropy(16).unwrap())];
    #[cfg(target_os = "linux")]
    {
        out.push(("getrandom(16, 0)", getrandom(16, 0).1));
        out.push((
            "getrandom(5, GRND_NONBLOCK)",
            getrandom(5, libc::GRND_NONBLOCK).1,
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 16];
        assert_eq!(
            unsafe { CCRandomGenerateBytes(buf.as_mut_ptr().cast(), 16) },
            0
        );
        out.push(("CCRandomGenerateBytes(16)", buf));
        let mut buf = vec![0u8; 11];
        unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), 11) };
        out.push(("arc4random_buf(11)", buf));
        out.push((
            "arc4random()",
            unsafe { libc::arc4random() }.to_ne_bytes().to_vec(),
        ));
    }
    out
}

fn lengths() -> Vec<usize> {
    every_call().iter().map(|(_, b)| b.len()).collect()
}

type Calls = Vec<(&'static str, Vec<u8>)>;
type Row = (&'static str, u64, Calls);

/// What the root, its first two children and the first child's child see, with each one's
/// lineage as the sim reports it.
fn family(sim: &Sim) -> Vec<Row> {
    sim.run(|| {
        let root = (snare_interpose::thread_lineage(), every_call());
        let first = std::thread::spawn(|| {
            let mine = (snare_interpose::thread_lineage(), every_call());
            let grandchild =
                std::thread::spawn(|| (snare_interpose::thread_lineage(), every_call()))
                    .join()
                    .unwrap();
            (mine, grandchild)
        })
        .join()
        .unwrap();
        let second = std::thread::spawn(|| (snare_interpose::thread_lineage(), every_call()))
            .join()
            .unwrap();
        vec![
            ("root", root.0, root.1),
            ("child 1", first.0.0, first.0.1),
            ("grandchild 1.1", first.1.0, first.1.1),
            ("child 2", second.0, second.1),
        ]
    })
}

fn render(seed: u64, rows: &[Row], out: &mut String) {
    for (who, lineage, calls) in rows {
        out.push_str(&format!(
            "seed {seed:#018x} {who} lineage {lineage:#018x}\n"
        ));
        for (call, bytes) in calls {
            out.push_str(&format!("  {call}: {}", golden::hex(bytes)));
        }
    }
}

fn os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else {
        "macos"
    }
}

#[test]
fn seeded_streams_match_the_golden_and_the_documented_algorithm() {
    let mut text = String::new();
    for seed in [0u64, 1, 42, 0xdead_beef_cafe_f00d, u64::MAX] {
        let rows = family(&Sim::builder().seed(seed).build());
        let lineages: Vec<u64> = rows.iter().map(|r| r.1).collect();
        assert_eq!(lineages, [0, mix(0, 1), mix(mix(0, 1), 1), mix(0, 2)]);
        for (who, lineage, calls) in &rows {
            let bytes: Vec<Vec<u8>> = calls.iter().map(|(_, b)| b.clone()).collect();
            assert_eq!(
                bytes,
                expected(seed, *lineage, &lengths()),
                "seed {seed} {who}"
            );
        }
        render(seed, &rows, &mut text);
    }
    golden::check_text(&format!("edge_host_random.{}.txt", os()), &text);
}

#[test]
fn the_default_seed_is_zero() {
    let default = Sim::new().run(|| getentropy(32).unwrap());
    assert_eq!(default, expected(0, 0, &[32])[0]);
}

#[test]
fn a_partial_word_is_discarded() {
    let split = Sim::builder().seed(9).build().run(|| {
        let a = getentropy(13).unwrap();
        let b = getentropy(3).unwrap();
        (a, b)
    });
    let whole = std::thread::spawn(|| {
        Sim::builder()
            .seed(9)
            .build()
            .run(|| getentropy(16).unwrap())
    })
    .join()
    .unwrap();
    let words = expected(9, 0, &[24])[0].clone();
    assert_eq!(whole, words[..16]);
    assert_eq!(split.0, words[..13]);
    assert_eq!(
        split.1,
        words[16..19],
        "the 13-byte read spent two whole words"
    );
    assert_ne!([split.0, split.1].concat(), whole);
}

#[test]
fn an_empty_request_draws_nothing() {
    let got = Sim::builder().seed(3).build().run(|| {
        assert_eq!(getentropy(0), Ok(vec![]));
        assert_eq!(unsafe { libc::getentropy(std::ptr::null_mut(), 0) }, 0);
        getentropy(8).unwrap()
    });
    assert_eq!(got, expected(3, 0, &[8])[0]);
}

#[test]
fn an_oversized_getentropy_is_the_os_error_and_draws_nothing_os_truth() {
    let real = getentropy(257);
    assert_eq!(
        real,
        Err(if cfg!(target_os = "linux") {
            libc::EIO
        } else {
            libc::EINVAL
        })
    );
    let got = Sim::builder().seed(4).build().run(|| {
        assert_eq!(getentropy(257), real);
        assert_eq!(getentropy(256).map(|b| b.len()), Ok(256));
        getentropy(8).unwrap()
    });
    assert_eq!(got, expected(4, 0, &[256, 8])[1]);
}

#[cfg(target_os = "linux")]
#[test]
fn getrandom_ignores_its_flags_and_has_no_length_cap() {
    let (a, b, c) = Sim::builder().seed(5).build().run(|| {
        let a = getrandom(8, libc::GRND_RANDOM | libc::GRND_NONBLOCK);
        let b = getrandom(1 << 20, 0);
        let c = getrandom(8, 0xffff);
        (a, b, c)
    });
    let want = expected(5, 0, &[8, 1 << 20, 8]);
    assert_eq!(a, (8, want[0].clone()));
    assert_eq!(b.0, 1 << 20);
    assert!(b.1 == want[1]);
    assert_eq!(
        c,
        (8, want[2].clone()),
        "unknown flags are not EINVAL in the sim"
    );
    let raw = Sim::builder().seed(5).build().run(|| {
        let mut buf = [0u8; 8];
        let n = unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), 8usize, 0u32) };
        (n, buf)
    });
    assert_eq!(raw.0, 8);
    assert_eq!(
        raw.1.to_vec(),
        want[0],
        "the raw syscall draws the same stream as the wrapper"
    );
}

#[test]
fn later_runs_of_one_sim_start_new_root_streams() {
    let sim = Sim::builder().seed(11).build();
    let runs: Vec<(u64, Vec<u8>)> = (0..3)
        .map(|_| sim.run(|| (snare_interpose::thread_lineage(), getentropy(8).unwrap())))
        .collect();
    let lineages: Vec<u64> = runs.iter().map(|r| r.0).collect();
    assert_eq!(lineages, [0, mix(ROOT_SALT, 1), mix(ROOT_SALT, 2)]);
    for (lineage, bytes) in &runs {
        assert_eq!(bytes, &expected(11, *lineage, &[8])[0]);
    }
    let child = sim.run(|| {
        std::thread::spawn(snare_interpose::thread_lineage)
            .join()
            .unwrap()
    });
    assert_eq!(
        child,
        mix(mix(ROOT_SALT, 3), 1),
        "a later root's children mix from it"
    );
}

#[test]
fn entries_from_other_threads_count_as_later_entries() {
    let sim = Sim::builder().seed(12).build();
    let first = sim.run(snare_interpose::thread_lineage);
    let on_other = std::thread::scope(|s| {
        s.spawn(|| sim.run(snare_interpose::thread_lineage))
            .join()
            .unwrap()
    });
    assert_eq!((first, on_other), (0, mix(ROOT_SALT, 1)));
}

#[test]
fn a_nested_sim_preserves_the_outer_random_stream() {
    let seed = 23;
    let want = Sim::builder()
        .seed(seed)
        .build()
        .run(|| (getentropy(8).unwrap(), getentropy(8).unwrap()));
    for inner_seed in [seed, seed + 1] {
        let got = Sim::builder().seed(seed).build().run(|| {
            let first = getentropy(8).unwrap();
            let inner = Sim::builder()
                .seed(inner_seed)
                .build()
                .run(|| getentropy(8).unwrap());
            assert_eq!(inner, expected(inner_seed, 0, &[8])[0]);
            (first, getentropy(8).unwrap())
        });
        assert_eq!(got, want);
    }
}

#[test]
fn a_fresh_sim_replays_whatever_thread_runs_it() {
    let a = Sim::builder()
        .seed(23)
        .build()
        .run(|| getentropy(8).unwrap());
    let b = Sim::builder()
        .seed(23)
        .build()
        .run(|| getentropy(8).unwrap());
    assert_eq!(a, b);
}

#[test]
fn unmanaged_threads_and_real_get_os_entropy() {
    let want = expected(31, 0, &[16])[0].clone();
    let sim = Sim::builder().seed(31).build();
    let (inside_real, inside) = sim.run(|| {
        let r = snare::real(|| getentropy(16).unwrap());
        (r, getentropy(16).unwrap())
    });
    assert_eq!(inside, want, "real() drew nothing from the stream");
    assert_ne!(inside_real, want);
    let (tx, rx) = mpsc::channel();
    sim.run(|| {
        snare::real(|| {
            std::thread::spawn(move || {
                tx.send((
                    snare::sched::in_sim(),
                    getentropy(16).unwrap(),
                    getentropy(16).unwrap(),
                ))
                .unwrap();
            })
            .join()
            .unwrap()
        })
    });
    let (in_sim, a, b) = rx.recv().unwrap();
    assert!(!in_sim, "a thread spawned under real() is unmanaged");
    assert_ne!(a, b);
    assert_ne!(a, expected(31, mix(0, 1), &[16])[0]);
    let outside = getentropy(16).unwrap();
    assert_ne!(outside, getentropy(16).unwrap());
}

#[test]
fn a_thread_spawned_under_real_does_not_take_a_birth_order() {
    let lineage = Sim::new().run(|| {
        snare::real(|| std::thread::spawn(|| ()).join().unwrap());
        std::thread::spawn(snare_interpose::thread_lineage)
            .join()
            .unwrap()
    });
    assert_eq!(lineage, mix(0, 1));
}

#[test]
fn hash_keys_replay_per_seed_and_thread() {
    let keys = |seed: u64| {
        Sim::builder().seed(seed).build().run(|| {
            (0..3)
                .map(|_| std::thread::spawn(|| std::hash::RandomState::new().hash_one(7u64)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        })
    };
    let first = keys(77);
    assert_eq!(first, keys(77));
    assert_ne!(first, keys(78));
    assert_ne!(first[0], first[1], "each child its own stream");
}
