use ic_interfaces::time_source::TimeSource;
use ic_types::time::{Time, UNIX_EPOCH};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A pure implementation of [TimeSource] that requires manual
/// fast forward to advance time.
pub struct FastForwardTimeSource(RwLock<TickTimeData>);

/// Error when time update is not monotone.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TimeNotMonotoneError;
struct TickTimeData {
    current_time: Time,
    current_instant: Instant,
    /// Duration by which monotonic time has advanced more than the relative time.
    diff: Duration,
    origin_instant: Instant,
}

impl FastForwardTimeSource {
    pub fn new() -> Arc<FastForwardTimeSource> {
        let now = Instant::now();
        Arc::new(FastForwardTimeSource(RwLock::new(TickTimeData {
            current_time: UNIX_EPOCH,
            current_instant: now,
            diff: Duration::ZERO,
            origin_instant: now,
        })))
    }

    /// Set the time to a new value, only when the given time is greater than
    /// or equal to the current time. Return error otherwise.
    ///
    /// Setting time this way will increase the monotonic time proportionally,
    /// so no additional desync is introduced. Any existing desync introduced
    /// with [`advance_only_monotonic`] will be maintained.
    pub fn set_time(&self, time: Time) -> Result<(), TimeNotMonotoneError> {
        let data = &mut self.0.write().unwrap();
        let diff = time.saturating_duration_since(data.current_time);
        if time >= data.current_time {
            data.current_time = time;
            data.current_instant += diff;
            Ok(())
        } else {
            Err(TimeNotMonotoneError)
        }
    }

    /// Increases only the monotonic time. This emulates a stalled real-time clock.
    /// Call [`sync_realtime`] to bring the real-time clock back in sync with how much
    /// time the monotonic clock has advanced
    pub fn advance_only_monotonic(&self, duration: Duration) {
        let data = &mut self.0.write().unwrap();
        data.current_instant += duration;
        data.diff += duration;
    }

    /// Brings the real-time clock back into sync with the monotonic clock by
    /// fast-forwarding the real-time clock. Call this to fix desync introduced by
    /// [`advance_only_monotonic`].
    pub fn sync_realtime(&self) {
        let data = &mut self.0.write().unwrap();
        data.current_time = data.current_time + data.diff;
        data.diff = Duration::ZERO;
    }

    /// Advance time by the given [`Duration`]. Advances the real-world and monotonic
    /// clock at the same rate.
    pub fn advance_time(&self, duration: Duration) {
        let data = &mut self.0.write().unwrap();
        data.current_time += duration;
        data.current_instant += duration;
    }

    /// Reset the time to start value.
    pub fn reset(&self) {
        let data = &mut self.0.write().unwrap();
        data.current_time = UNIX_EPOCH;
        data.current_instant = data.origin_instant;
        data.diff = Duration::ZERO;
    }
}

impl TimeSource for FastForwardTimeSource {
    fn get_relative_time(&self) -> Time {
        self.0.read().unwrap().current_time
    }

    fn get_instant(&self) -> Instant {
        self.0.read().unwrap().current_instant
    }
}

/// Execute the provided closure on a separate thread, but with a timeout.
/// Return true if the action completed successfully and false otherwise.
pub fn with_timeout<T>(timeout: Duration, action: T) -> bool
where
    T: FnOnce() + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        action();
        tx.send(()).unwrap();
    });
    rx.recv_timeout(timeout).is_ok()
}
