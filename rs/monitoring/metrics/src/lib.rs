pub mod buckets;
#[cfg(target_os = "linux")]
pub mod process_collector;
pub mod registry;

pub use registry::MetricsRegistry;

use std::time::Instant;

/// A timer to be used with `HistogramVec`, when the labels are not known ahead
/// of time (e.g. when observing request durations by response status).
pub struct Timer {
    /// Starting instant for the timer.
    start: Instant,
}

impl Timer {
    /// Starts a new timer.
    pub fn start() -> Self {
        Timer {
            start: Instant::now(),
        }
    }

    /// Returns the time elapsed since the timer was started (in seconds).
    pub fn elapsed(&self) -> f64 {
        let d = self.start.elapsed();
        let nanos = f64::from(d.subsec_nanos()) / 1e9;
        d.as_secs() as f64 + nanos
    }
}
