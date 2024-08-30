use candid::CandidType;
use ic_types::Cycles;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    convert::TryInto,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A record of how many cycles have been minted in the last `max_age`
/// period. Minting events are aggregated into windows of `resolution`
/// seconds in size to limit memory consumption.
#[derive(Serialize, Deserialize, Clone, CandidType, Eq, PartialEq, Debug)]
pub struct Limiter {
    time_windows: VecDeque<TimeWindowCount>,
    total_count: Cycles,
    resolution: Duration,
    max_age: Duration,
}

impl Limiter {
    pub fn new(resolution: Duration, max_age: Duration) -> Self {
        Self {
            time_windows: VecDeque::new(),
            total_count: Cycles::zero(),
            resolution,
            max_age,
        }
    }

    /// Record a cycles minting event at time `now`. It's expected
    /// that `now` is monotonically non-decreasing.
    pub fn add(&mut self, now: SystemTime, cycles: Cycles) {
        self.purge_old(now);

        let window = self.time_to_window(now);

        if self
            .time_windows
            .back()
            .filter(|w| w.window >= window)
            .is_none()
        {
            self.time_windows.push_back(TimeWindowCount {
                window,
                count: Cycles::zero(),
            });
        };

        self.time_windows.back_mut().unwrap().count += cycles;
        self.total_count += cycles;
    }

    /// Forget about all cycles minting events older than `now -
    /// self.max_age`.
    pub fn purge_old(&mut self, now: SystemTime) {
        while let Some(oldest) = self.time_windows.front() {
            if self.window_to_time(oldest.window + 1) + self.max_age <= now {
                self.total_count -= oldest.count;
                self.time_windows.pop_front();
            } else {
                break;
            }
        }
    }

    fn time_to_window(&self, time: SystemTime) -> TimeWindow {
        (time.duration_since(UNIX_EPOCH).unwrap().as_secs() / self.resolution.as_secs())
            .try_into()
            .unwrap()
    }

    fn window_to_time(&self, window: TimeWindow) -> SystemTime {
        UNIX_EPOCH + self.resolution * window
    }

    /// Return the total number of cycles minted in the last
    /// `self.max_age` period.
    pub fn get_count(&self) -> Cycles {
        self.total_count
    }

    pub fn get_max_age(&self) -> Duration {
        self.max_age
    }
}

type TimeWindow = u32;

#[derive(Serialize, Deserialize, Clone, CandidType, Eq, PartialEq, Debug)]
struct TimeWindowCount {
    window: TimeWindow,
    count: Cycles,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minting_limiter() {
        let resolution = Duration::from_secs(60);
        let max_age = Duration::from_secs(24 * 60 * 60);
        let mut limiter = Limiter::new(resolution, max_age);
        assert_eq!(limiter.get_count(), Cycles::zero());

        let t = UNIX_EPOCH;
        limiter.add(t, Cycles::new(100));
        assert_eq!(limiter.get_count(), Cycles::new(100));

        limiter.add(t + Duration::from_secs(59), Cycles::new(10));
        assert_eq!(limiter.time_windows.len(), 1);
        assert_eq!(limiter.get_count(), Cycles::new(110));

        limiter.add(t + Duration::from_secs(60), Cycles::new(20));
        assert_eq!(limiter.time_windows.len(), 2);
        assert_eq!(limiter.get_count(), Cycles::new(130));

        limiter.add(t + Duration::from_secs(10000), Cycles::new(1));
        assert_eq!(limiter.time_windows.len(), 3);
        assert_eq!(limiter.get_count(), Cycles::new(131));

        limiter.add(t + max_age, Cycles::new(7));
        assert_eq!(limiter.time_windows.len(), 4);
        assert_eq!(limiter.get_count(), Cycles::new(138));

        limiter.add(t + max_age + resolution, Cycles::new(1));
        assert_eq!(limiter.time_windows.len(), 4);
        assert_eq!(limiter.get_count(), Cycles::new(29));

        limiter.add(t + max_age + max_age + resolution, Cycles::new(23));
        assert_eq!(limiter.time_windows.len(), 2);
        assert_eq!(limiter.get_count(), Cycles::new(24));

        // Times in the past should be added to the most recent window.
        limiter.add(t, Cycles::from(1u128));
        assert_eq!(limiter.time_windows.len(), 2);
        assert_eq!(limiter.get_count(), Cycles::new(25));

        limiter.purge_old(t + max_age * 4);
        assert_eq!(limiter.time_windows.len(), 0);
        assert_eq!(limiter.get_count(), Cycles::zero());
    }
}
