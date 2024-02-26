//! The time source public interface.
use ic_types::time::{Time, UNIX_EPOCH};
use std::sync::RwLock;
use std::time::{Instant, SystemTime};

/// A interface that represent the source of time.
pub trait TimeSource: Send + Sync {
    /// Return the relative time since origin. The definition of origin depends
    /// on the actual implementation. For [SysTimeSource] it is the UNIX
    /// epoch.
    fn get_relative_time(&self) -> Time;
}

/// A [`TimeSource`] that also allows measuring monotonic timestamps ("instants").
pub trait MonotonicTimeSource: TimeSource {
    /// Return a time measurement from a monotonic clock. For [`SysTimeSource`], it
    /// will call and wrap [`std::time::Instant::now`].
    fn get_monotonic_time(&self) -> Instant;
}

/// Time source using the system time.
pub struct SysTimeSource {
    current_time: RwLock<Time>,
}

/// Error when time update is not monotone.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TimeNotMonotoneError;

#[allow(clippy::new_without_default)]
/// Provide real system time as a [TimeSource].
impl SysTimeSource {
    /// Create a new [SysTimeSource].
    pub fn new() -> Self {
        SysTimeSource {
            current_time: RwLock::new(system_time_now()),
        }
    }

    /// Update time to the new system time value.
    ///
    /// It will skip the update and return an error if the new system time is
    /// less than the previous value.
    pub fn update_time(&self) -> Result<(), TimeNotMonotoneError> {
        let mut current_time = self.current_time.write().unwrap();
        let t = system_time_now();
        if *current_time > t {
            Err(TimeNotMonotoneError)
        } else {
            *current_time = t;
            Ok(())
        }
    }
}

impl TimeSource for SysTimeSource {
    fn get_relative_time(&self) -> Time {
        *self.current_time.read().unwrap()
    }
}

impl MonotonicTimeSource for SysTimeSource {
    fn get_monotonic_time(&self) -> Instant {
        Instant::now()
    }
}

pub struct RealClock;

impl TimeSource for RealClock {
    fn get_relative_time(&self) -> Time {
        system_time_now()
    }
}

impl MonotonicTimeSource for RealClock {
    fn get_monotonic_time(&self) -> Instant {
        Instant::now()
    }
}

/// Return the current system time. Note that the value returned is not
/// guaranteed to be monotonic.
fn system_time_now() -> Time {
    UNIX_EPOCH
        + SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime is before UNIX EPOCH!")
}
