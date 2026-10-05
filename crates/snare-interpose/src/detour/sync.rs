//! A mutual exclusion lock that ignores poisoning.

use std::sync::{self, MutexGuard, PoisonError};

/// A mutual exclusion lock, ignoring poisoning.
///
/// None of the guarded state can be left inconsistent by a panic.
pub struct Mutex<T>(sync::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex(sync::Mutex::new(value))
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
