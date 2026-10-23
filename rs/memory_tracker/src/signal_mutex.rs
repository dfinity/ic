use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

/// A mutex that uses an [`AtomicBool`] instead of `pthread_mutex_lock`.
///
/// Unlike [`std::sync::Mutex`], acquiring this lock never calls any
/// non-async-signal-safe functions, making it safe to use inside signal
/// handlers.  If the lock is already held when [`lock`][SignalMutex::lock]
/// is called, the thread panics immediately rather than blocking.
///
/// # Warning
///
/// This type is only suitable for use in contexts where contention is
/// impossible by construction.  Because `lock` panics on contention instead
/// of blocking, any situation where two threads (or a thread and a signal
/// handler) could genuinely race to acquire the lock will crash the process.
/// Callers must ensure that the lock is always uncontended at the time it is
/// acquired.
pub struct SignalMutex<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `SignalMutex<T>` can be shared across threads when `T: Send`
// because exclusive access is enforced by the atomic flag.
unsafe impl<T: ?Sized + Send> Send for SignalMutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for SignalMutex<T> {}

impl<T> SignalMutex<T> {
    pub fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> SignalMutex<T> {
    /// Acquires the lock, panicking immediately if it is already held.
    pub fn lock(&self) -> SignalMutexGuard<'_, T> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            panic!("SignalMutex is already locked");
        }
        SignalMutexGuard { mutex: self }
    }
}

/// Guard returned by [`SignalMutex::lock`]. Releases the lock on drop.
pub struct SignalMutexGuard<'a, T: ?Sized> {
    mutex: &'a SignalMutex<T>,
}

impl<T: ?Sized> Deref for SignalMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so we have exclusive access to the data.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SignalMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so we have exclusive access to the data.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for SignalMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}
