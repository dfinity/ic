//! The time source public interface.
use ic_types::time::{Time, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

/// A interface that represent the source of time.
pub trait TimeSource: Send + Sync {
    /// Return the relative time since origin. The definition of origin depends
    /// on the actual implementation. For [SysTimeSource] it is the UNIX
    /// epoch.
    fn get_relative_time(&self) -> Time;

    /// Can be used as measurement of a monotonically nondecreasing clock. Production
    /// code should use std::time::Instant::now() as implementation of this method.
    /// However, accessing the Instant via the trait enables dependency injection for
    /// more comprehensive testing.
    fn get_instant(&self) -> Instant;
}

/// Implements monotonically nondecreasing clock using SystemTime relative to the UNIX_EPOCH.
pub struct SysTimeSource {
    current_time: AtomicU64,
}

#[allow(clippy::new_without_default)]
/// Provide real system time as a [TimeSource].
impl SysTimeSource {
    /// Create a new [SysTimeSource].
    pub fn new() -> Self {
        SysTimeSource {
            current_time: AtomicU64::new(system_time_now().as_nanos_since_unix_epoch()),
        }
    }
}

impl TimeSource for SysTimeSource {
    fn get_relative_time(&self) -> Time {
        let t = system_time_now().as_nanos_since_unix_epoch();
        self.current_time.fetch_max(t, Ordering::SeqCst);
        Time::from_nanos_since_unix_epoch(self.current_time.load(Ordering::SeqCst))
    }

    // Can be used as measurement of a monotonically nondecreasing clock.
    fn get_instant(&self) -> Instant {
        Instant::now()
    }
}

/// Return the current system time. Note that the value returned is not
/// guaranteed to be monotonic.
#[inline]
fn system_time_now() -> Time {
    UNIX_EPOCH
        + SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime is before UNIX EPOCH!")
}
