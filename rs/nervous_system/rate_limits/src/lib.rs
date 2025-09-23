//! Rate limits library for nervous system components.
//!
//! This crate provides utilities for implementing rate limiting in nervous system canisters.
use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
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

struct UsageRecord {
    last_updated: SystemTime,
    capacity_used: u64,
}

pub struct RateLimiter<K> {
    config: RateLimiterConfig,
    reservations: Arc<Mutex<BTreeMap<(K, u64), ReservationData>>>,
    used_capacity: BTreeMap<K, UsageRecord>,
}

#[derive(Clone, Debug, PartialEq)]
struct ReservationData {
    now: SystemTime,
    capacity: u64,
}

pub struct RateLimiterConfig {
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
            reservations: Arc::new(Mutex::new(BTreeMap::new())),
            used_capacity: BTreeMap::new(),
        }
    }

    pub fn try_reserve(
        &mut self,
        now: SystemTime,
        key: K,
        capacity: u64,
    ) -> Result<Reservation<K>, RateLimiterError> {
        let mut reservations = self.reservations.lock().unwrap();

        // Get all reservations for this key to calculate next index and current usage
        let key_reservations: Vec<(u64, &ReservationData)> = reservations
            .range((key.clone(), 0)..(key.clone(), u64::MAX))
            .map(|((_, index), data)| (*index, data))
            .collect();

        let next_index = key_reservations
            .iter()
            .map(|(index, _)| *index)
            .max()
            .map_or(0, |max_index| max_index + 1);

        let reserved_capacity: u64 = key_reservations
            .into_iter()
            .map(|(_, data)| data.capacity)
            .sum();

        // Also check committed usage that hasn't expired
        let committed_capacity = self
            .used_capacity
            .get(&key)
            .filter(|usage| usage.last_updated > now - self.config.max_age)
            .map(|usage| usage.capacity_used)
            .unwrap_or(0);

        if reserved_capacity + committed_capacity + capacity <= self.config.max_capacity {
            let reservation_data = ReservationData { now, capacity };
            reservations.insert((key.clone(), next_index), reservation_data);

            let reservation = Reservation {
                key: key.clone(),
                index: next_index,
                reservations_map: Arc::downgrade(&self.reservations),
            };

            Ok(reservation)
        } else {
            Err(RateLimiterError::NotEnoughCapacity)
        }
    }

    pub fn commit(&mut self, reservation: Reservation<K>) {
        let usage = self
            .used_capacity
            .entry(reservation.key.clone())
            .or_insert_with(|| UsageRecord {
                last_updated: SystemTime::now(),
                capacity_used: 0,
            });

        // TODO DO NOT MERGE - should this throw an error if the reservation cannot be found
        // How do we handle that?
        if let Ok(mut reservations) = self.reservations.lock() {
            if let Some(reservation) =
                reservations.remove(&(reservation.key.clone(), reservation.index))
            {
                usage.last_updated = SystemTime::now();
                usage.capacity_used = usage.capacity_used.saturating_add(reservation.capacity);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Reservation<K: Clone + Ord> {
    key: K,
    index: u64,
    reservations_map: Weak<Mutex<BTreeMap<(K, u64), ReservationData>>>,
}

impl<K: Clone + Ord> Drop for Reservation<K> {
    fn drop(&mut self) {
        if let Some(reservations_arc) = self.reservations_map.upgrade() {
            if let Ok(mut reservations) = reservations_arc.lock() {
                reservations.remove(&(self.key.clone(), self.index));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_just_reservations() {
        let mut rate_limiter: RateLimiter<String> = RateLimiter::new(RateLimiterConfig {
            max_age: Duration::from_secs(60),
            max_capacity: 10,
        });

        let now = SystemTime::now();

        let too_much = rate_limiter.try_reserve(now, "Foo".to_string(), 11);
        assert!(matches!(too_much, Err(RateLimiterError::NotEnoughCapacity)));

        let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert!(one.is_ok());
        let one = one.unwrap();
        assert_eq!(one.index, 0);
        assert_eq!(one.key, "Foo".to_string());

        let two = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert!(two.is_ok());
        let two = two.unwrap();
        assert_eq!(two.key, "Foo".to_string());
        assert_eq!(two.index, 1);

        let three_is_over = rate_limiter.try_reserve(SystemTime::now(), "Foo".to_string(), 1);
        assert!(matches!(
            three_is_over,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // Now we test the Drop logic on Reservations
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);
        drop(one);
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1);

        let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert!(one.is_ok());
        let one = one.unwrap();
        // Still gets next highest index, b/c two is still there.
        assert_eq!(one.index, 2);
        assert_eq!(one.key, "Foo".to_string());

        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);
        let three_is_over = rate_limiter.try_reserve(SystemTime::now(), "Foo".to_string(), 1);
        assert!(matches!(
            three_is_over,
            Err(RateLimiterError::NotEnoughCapacity)
        ));
        drop(one);
        drop(two);
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_rate_limiter_commits_and_new_reservations() {
        let mut rate_limiter: RateLimiter<String> = RateLimiter::new(RateLimiterConfig {
            max_age: Duration::from_secs(60),
            max_capacity: 10,
        });

        let now = SystemTime::now();
        let one = rate_limiter.try_reserve(now, "Foo".to_string(), 5);
        assert!(one.is_ok());
        let one = one.unwrap();
        assert_eq!(one.index, 0);
        assert_eq!(one.key, "Foo".to_string());

        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1);
        // Now commit
        rate_limiter.commit(one);
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 0);

        let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 6);
        assert!(matches!(
            over_limit,
            Err(RateLimiterError::NotEnoughCapacity)
        ));
    }
}
