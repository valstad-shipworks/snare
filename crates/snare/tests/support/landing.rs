//! Where a time skip to a deadline lands, for tests that pin the clock exactly.

#![allow(dead_code)]

/// The monotonic time, in nanoseconds, a time skip to a deadline at `t` lands on: 1 ns past it;
/// on Windows 100 ns past it, or the next `QueryPerformanceCounter` tick should that be later.
/// Saturates at the end of the clock.
pub fn past(t: u64) -> u64 {
    #[cfg(windows)]
    {
        let mut frequency = 0i64;
        // SAFETY: writes one i64.
        unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency)
        };
        let frequency = u128::from(frequency.max(1) as u64);
        let next = u128::from(t) * frequency / 1_000_000_000 + 1;
        let tick = u64::try_from((next * 1_000_000_000).div_ceil(frequency))
            .unwrap_or_else(|_| t.saturating_add(1));
        tick.max(t.saturating_add(100))
    }
    #[cfg(not(windows))]
    {
        t + 1
    }
}

/// The landings of `n` back-to-back waits of `step` nanoseconds each, starting from `start`.
pub fn steps(start: u64, step: u64, n: usize) -> Vec<u64> {
    std::iter::successors(Some(start), |&at| Some(past(at + step)))
        .skip(1)
        .take(n)
        .collect()
}

/// Where each of `deadlines` (nanoseconds, all registered at time 0) wakes: at the first landing at
/// or past it, a landing being [`past`] the earliest deadline still ahead.
pub fn wakes(deadlines: &[u64]) -> Vec<u64> {
    let mut sorted = deadlines.to_vec();
    sorted.sort_unstable();
    let mut landings = Vec::new();
    let mut now = 0u64;
    for d in sorted {
        if d > now {
            now = past(d);
            landings.push(now);
        }
    }
    deadlines
        .iter()
        .map(|&d| *landings.iter().find(|&&l| l >= d).unwrap())
        .collect()
}

/// How far past its deadline a landing lies at most: [`past`] of zero.
pub fn tick() -> std::time::Duration {
    std::time::Duration::from_nanos(past(0))
}

/// Whether `elapsed`, read from `Instant`s around a wait of `wait` that timed out, lies just past
/// it: beyond it, by no more than a landing's [`tick`] and the `Instant` resolution on top.
pub fn just_past(elapsed: std::time::Duration, wait: std::time::Duration) -> bool {
    elapsed > wait && elapsed <= wait + 2 * tick()
}
