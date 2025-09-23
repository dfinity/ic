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
    pub add_capacity_amount: u64,
    pub add_capacity_interval: Duration,
    pub max_capacity: u64,
    pub reservation_timeout: Duration,
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
        requested_capacity: u64,
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

        // Update token bucket capacity and get current committed usage
        let committed_capacity = if let Some(usage) = self.used_capacity.get_mut(&key) {
            update_capacity(
                usage,
                now,
                self.config.add_capacity_amount,
                self.config.add_capacity_interval,
            );
            usage.capacity_used
        } else {
            0
        };

        if reserved_capacity + committed_capacity + requested_capacity <= self.config.max_capacity {
            let reservation_data = ReservationData {
                now,
                capacity: requested_capacity,
            };
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

        update_capacity(
            usage,
            SystemTime::now(),
            self.config.add_capacity_amount,
            self.config.add_capacity_interval,
        );

        // TODO DO NOT MERGE - should this throw an error if the reservation cannot be found
        // How do we handle that?
        if let Ok(mut reservations) = self.reservations.lock() {
            println!("We are doing the reservation thing!");
            if let Some(reservation) =
                reservations.remove(&(reservation.key.clone(), reservation.index))
            {
                usage.last_updated = SystemTime::now();
                usage.capacity_used = usage.capacity_used.saturating_add(reservation.capacity);
            }
        }
    }
}

fn update_capacity(
    usage_record: &mut UsageRecord,
    now: SystemTime,
    amount_to_add: u64,
    add_frequency: Duration,
) {
    // Calculate time elapsed since last update
    let elapsed = now
        .duration_since(usage_record.last_updated)
        .unwrap_or(Duration::ZERO);

    // Calculate how many complete intervals have passed
    let complete_intervals = elapsed.as_secs() / add_frequency.as_secs();

    // Calculate new last_updated so that the rate remains constant regardless of when this is checked.
    let last_updated = usage_record.last_updated
        + Duration::from_secs(complete_intervals.saturating_mul(add_frequency.as_secs()));

    // Add capacity for complete intervals (saturating subtract from used capacity)
    let capacity_to_add = complete_intervals * amount_to_add;
    usage_record.capacity_used = usage_record.capacity_used.saturating_sub(capacity_to_add);

    // Set last_updated to account for the remaining partial interval
    // This keeps the partial interval progress for the next call
    usage_record.last_updated = last_updated;
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
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(10),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(u64::MAX),
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
    fn test_token_bucket_replenishment() {
        let mut rate_limiter: RateLimiter<String> = RateLimiter::new(RateLimiterConfig {
            add_capacity_amount: 2, // Add 2 capacity every 10 seconds
            add_capacity_interval: Duration::from_secs(10),
            max_capacity: 10,
            reservation_timeout: Duration::from_secs(u64::MAX),
        });

        let now = SystemTime::now();

        // Use up 8 capacity
        let reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 8).unwrap();
        rate_limiter.commit(reservation1);

        // Should only have 2 capacity left
        let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 3);
        assert!(matches!(
            over_limit,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // Can still reserve 2
        let reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 2).unwrap();
        rate_limiter.commit(reservation2);

        // Now we're at full capacity (10/10 used), nothing more should work
        let fully_used = rate_limiter.try_reserve(now, "Foo".to_string(), 1);
        assert!(matches!(
            fully_used,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // Fast forward 12 seconds - 1 interval
        let later = now + Duration::from_secs(12);

        // Should be able to reserve 2 (one interval's worth) but not more
        let later_ok = rate_limiter.try_reserve(later, "Foo".to_string(), 2);
        assert!(later_ok.is_ok());
        drop(later_ok);

        let after_time_too_much = rate_limiter.try_reserve(later, "Foo".to_string(), 3);
        assert!(matches!(
            after_time_too_much,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // We add 9 instead of 9 because there are some irritating minor time difference in SystemTime/Duration
        let even_later = later + Duration::from_secs(9);
        let even_later_okay = rate_limiter.try_reserve(even_later, "Foo".to_string(), 4);
        assert!(even_later_okay.is_ok());
    }
}
