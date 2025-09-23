//! Rate limits library for nervous system components.
//!
//! This crate provides utilities for implementing rate limiting in nervous system canisters.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// type TimeWindow = u32;
//
// #[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
// struct TimeWindowCount {
//     window: TimeWindow,
//     count: u64,
// }
//
// struct Counter {
//     time_windows: VecDeque<TimeWindowCount>,
//     total_count: u64,
// }
//
// fn time_to_window(time: SystemTime, resolution: Duration) -> TimeWindow {
//     (time.duration_since(UNIX_EPOCH).unwrap().as_secs() / resolution.as_secs())
//         .try_into()
//         .unwrap()
// }
// fn window_to_time(window: TimeWindow, resolution: Duration) -> SystemTime {
//     UNIX_EPOCH + resolution * window
// }
//
// impl Counter {
//     fn use_capacity(&mut self, now: SystemTime, capacity: u64, resolution: Duration) -> Self {
//         let window = time_to_window(now, resolution);
//
//         if self
//             .time_windows
//             .back()
//             .filter(|w| w.window >= window)
//             .is_none()
//         {
//             self.time_windows.push_back(TimeWindowCount {
//                 window,
//                 count: Cycles::zero(),
//             });
//         };
//
//         self.time_windows.back_mut().unwrap().count += capacity;
//         self.total_count += capacity;
//     }
//
//     fn purge_old(&mut self, now: SystemTime, resolution: Duration) {
//         while let Some(oldest) = self.time_windows.front() {
//             if window_to_time(oldest.window + 1) + self.max_age <= now {
//                 self.total_count -= oldest.count;
//                 self.time_windows.pop_front();
//             } else {
//                 break;
//             }
//         }
//     }
// }
//
// trait RateLimiterDataProvider<K> {
//     // Implementation should clean up Counter if there is no window data in it, and supply
//     // a fresh counter if it has no record of one.
//     fn with_counter_for<R>(&self, key: &K, f: fn(&mut Counter) -> R) -> R;
//     fn limit_for(&self, key: &K) -> u64;
//     fn keys(&self) -> Vec<K>;
// }

// Notes: So far, this design can work if you assume you know the limit in the RateLimiter.

// But what if the limits are different for different kinds of things?  You need to somehow have
// The limit passed in with the key.  This is kind of an odd design choice, when you think about it.

// How would you be able to know, from the key, what the limit was?  You'd have to have a way of
// setting it per key.
pub struct RateLimiter<K> {
    config: RateLimiterConfig,
    reservations: BTreeMap<(K, u64), Reservation<K>>,
}

pub struct RateLimiterConfig {
    pub resolution: Duration,
    pub max_age: Duration,
    pub max_capacity: u64,
}

#[derive(Debug, PartialEq)]
pub enum RateLimiterError {
    NotEnoughCapacity,
}

impl<K: Ord + Clone + Debug> RateLimiter<K> {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            reservations: BTreeMap::new(),
        }
    }

    pub fn try_reserve(
        &mut self,
        now: SystemTime,
        key: K,
        capacity: u64,
    ) -> Result<Reservation<K>, RateLimiterError> {
        println!("reservations all: {:?}", self.reservations);
        // TODO add the currently used capacity count to this
        let reservations: Vec<&Reservation<K>> = self
            .reservations
            .range((key.clone(), 0)..(key.clone(), u64::MAX))
            .map(|(keys, reservation)| reservation)
            .collect();

        println!("reservations filtered: {reservations:?}");

        let next_index = reservations
            .iter()
            .last()
            .map_or(0, |reservation| reservation.index + 1);

        let reserved_capacity: u64 = reservations
            .into_iter()
            .filter(|reservation| reservation.now > now - self.config.max_age)
            .map(|r| r.capacity)
            .sum();

        if reserved_capacity + capacity <= self.config.max_capacity {
            let reservation = Reservation {
                key: key.clone(),
                capacity,
                now,
                index: next_index,
            };
            self.reservations
                .insert((key, next_index), reservation.clone());
            Ok(reservation)
        } else {
            Err(RateLimiterError::NotEnoughCapacity)
        }
    }

    pub fn commit(&self, reservation: Reservation<K>) {}
}

#[derive(Clone, Debug, PartialEq)]
struct Reservation<K> {
    key: K,
    index: u64,
    now: SystemTime,
    capacity: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_just_reservations() {
        let mut rate_limiter: RateLimiter<String> = RateLimiter::new(RateLimiterConfig {
            resolution: Duration::from_millis(100),
            max_age: Duration::from_secs(60),
            max_capacity: 10,
        });

        let now = SystemTime::now();

        let too_much = rate_limiter.try_reserve(now, "Foo".to_string(), 11);
        assert_eq!(too_much, Err(RateLimiterError::NotEnoughCapacity));

        let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert_eq!(
            one,
            Ok(Reservation {
                index: 0,
                key: "Foo".to_string(),
                now,
                capacity: 5
            })
        );

        let two = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert_eq!(
            two,
            Ok(Reservation {
                key: "Foo".to_string(),
                index: 1,
                now,
                capacity: 5
            })
        );

        let three_is_over = rate_limiter.try_reserve(SystemTime::now(), "Foo".to_string(), 1);
        assert_eq!(three_is_over, Err(RateLimiterError::NotEnoughCapacity));

        let next_now = now + Duration::from_secs(61);

        let three_after_time = rate_limiter.try_reserve(next_now, "Foo".to_string(), 1);
        assert_eq!(
            three_after_time,
            Ok(Reservation {
                key: "Foo".to_string(),
                index: 2,
                now: next_now,
                capacity: 1
            })
        );
    }
}
