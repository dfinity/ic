//! This library provides a custom "Measurement" trait implementation that
//! allows one to get a more accurate time measurement in Criterion.rs
//! benchmarks.
//!
//! See https://bheisler.github.io/criterion.rs/book/user_guide/custom_measurements.html
//! for more details on how to extend Criterion.rs.

use criterion::measurement::{Measurement, ValueFormatter, WallTime};
use std::mem::MaybeUninit;
use std::time::Duration;

/// An implementation of Criterion.rs measurement that tracks the amount of time
/// spent by the process running the benchmark.  This should provide a bit more
/// accurate measurement of time than default WallClock measurement
/// implementation provided by Criterion.rs, though the timing is still affected
/// by the background load.
///
/// This implementation uses getrusage system call to obtain the timings.
pub enum ProcessTime {
    /// User time used by this process.
    UserTime,
    /// User + System time used by this process.
    UserAndSystemTime,
}

impl Default for ProcessTime {
    fn default() -> Self {
        Self::UserAndSystemTime
    }
}

impl ProcessTime {
    fn now(&self) -> Duration {
        let usage = resource_usage();
        match self {
            Self::UserTime => timeval_to_duration(usage.ru_utime),
            Self::UserAndSystemTime => {
                timeval_to_duration(usage.ru_utime) + timeval_to_duration(usage.ru_stime)
            }
        }
    }
}

impl Measurement for ProcessTime {
    type Intermediate = Duration;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        self.now()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        self.now() - i
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }

    fn zero(&self) -> Self::Value {
        Duration::from_secs(0)
    }

    fn to_f64(&self, val: &Self::Value) -> f64 {
        val.as_nanos() as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        WallTime.formatter()
    }
}

fn resource_usage() -> libc::rusage {
    let mut buf = MaybeUninit::<libc::rusage>::uninit();
    let c = unsafe { libc::getrusage(libc::RUSAGE_SELF, buf.as_mut_ptr()) };
    if c != 0 {
        panic!(
            "Failed to call getrusage(RUSAGE_SELF, {:?}): {:?}",
            buf.as_mut_ptr(),
            std::io::Error::last_os_error(),
        )
    }
    unsafe { buf.assume_init() }
}

fn timeval_to_duration(tv: libc::timeval) -> Duration {
    Duration::from_secs(tv.tv_sec as u64) + Duration::from_micros(tv.tv_usec as u64)
}
