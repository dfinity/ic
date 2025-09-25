//! Rate limits library for nervous system components.
//!
//! This crate provides utilities for implementing rate limiting in nervous system canisters.
use ic_stable_structures::{StableBTreeMap, Storable, storable::Bound};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt::Debug,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug, PartialEq)]
pub struct UsageRecord {
    pub last_capacity_drip: SystemTime,
    pub capacity_used: u64,
}

impl Storable for UsageRecord {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let timestamp_secs = self
            .last_capacity_drip
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&timestamp_secs.to_be_bytes());
        bytes.extend_from_slice(&self.capacity_used.to_be_bytes());

        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        if bytes.len() != 16 {
            panic!("Invalid UsageRecord bytes length");
        }

        let timestamp_bytes: [u8; 8] = bytes[0..8].try_into().unwrap();
        let capacity_bytes: [u8; 8] = bytes[8..16].try_into().unwrap();

        let timestamp_secs = u64::from_be_bytes(timestamp_bytes);
        let capacity_used = u64::from_be_bytes(capacity_bytes);

        let last_updated = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp_secs);

        Self {
            last_capacity_drip: last_updated,
            capacity_used,
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 16,
        is_fixed_size: true,
    };
}

// Note: String already implements Storable in ic-stable-structures
// If you need a custom key type, create a newtype wrapper:
//
// #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
// pub struct RateLimiterKey(pub String);
//
// impl Storable for RateLimiterKey {
//     fn to_bytes(&self) -> Cow<[u8]> {
//         Cow::Borrowed(self.0.as_bytes())
//     }
//
//     fn from_bytes(bytes: Cow<[u8]>) -> Self {
//         Self(String::from_utf8(bytes.into_owned()).expect("Invalid UTF-8 string"))
//     }
//
//     const BOUND: Bound = Bound::Unbounded;
// }

/// Trait for storing and retrieving capacity usage records.
/// This allows different storage backends (in-memory, persistent, etc.)
pub trait CapacityStorage<K> {
    /// Get usage record for a key
    fn get_usage(&self, key: &K) -> Option<UsageRecord>;

    /// Insert or update usage record for a key  
    fn insert_usage(&mut self, key: K, record: UsageRecord);

    /// Atomic update operation
    fn with_usage<R>(
        &mut self,
        key: K,
        default: UsageRecord,
        f: impl FnOnce(&mut UsageRecord) -> R,
    ) -> R {
        let mut usage = self.get_usage(&key).unwrap_or(default);
        let result = f(&mut usage);
        self.insert_usage(key, usage);
        result
    }
}

pub struct InMemoryCapacityStorage<K> {
    storage: BTreeMap<K, UsageRecord>,
}

impl<K: Ord + Clone> InMemoryCapacityStorage<K> {
    pub fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone> Default for InMemoryCapacityStorage<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord + Clone> CapacityStorage<K> for InMemoryCapacityStorage<K> {
    fn get_usage(&self, key: &K) -> Option<UsageRecord> {
        self.storage.get(key).cloned()
    }

    fn insert_usage(&mut self, key: K, record: UsageRecord) {
        self.storage.insert(key, record);
    }
}

/// Persistent capacity storage implementation using StableBTreeMap.
/// This allows capacity usage to survive canister upgrades.
pub struct StableBTreeMapCapacityStorage<K, Memory>
where
    K: Storable + Ord + Clone,
    Memory: ic_stable_structures::Memory,
{
    map: StableBTreeMap<K, UsageRecord, Memory>,
}

impl<K, Memory> StableBTreeMapCapacityStorage<K, Memory>
where
    K: Ord + Clone + Storable,
    Memory: ic_stable_structures::Memory,
{
    pub fn new(memory: Memory) -> Self {
        Self {
            map: StableBTreeMap::init(memory),
        }
    }
}

impl<K, Memory> CapacityStorage<K> for StableBTreeMapCapacityStorage<K, Memory>
where
    K: Ord + Clone + Storable,
    Memory: ic_stable_structures::Memory,
{
    fn get_usage(&self, key: &K) -> Option<UsageRecord> {
        self.map.get(key)
    }

    fn insert_usage(&mut self, key: K, record: UsageRecord) {
        self.map.insert(key, record);
    }

    fn with_usage<R>(
        &mut self,
        key: K,
        default: UsageRecord,
        f: impl FnOnce(&mut UsageRecord) -> R,
    ) -> R {
        let mut usage = self.get_usage(&key).unwrap_or(default);
        let result = f(&mut usage);
        self.insert_usage(key, usage);
        result
    }
}

pub struct RateLimiter<K, S> {
    config: RateLimiterConfig,
    reservations: Arc<Mutex<BTreeMap<(K, u64), ReservationData>>>,
    capacity_storage: S,
    next_index: u64,
}

// Convenience type alias for the common in-memory case
pub type InMemoryRateLimiter<K> = RateLimiter<K, InMemoryCapacityStorage<K>>;

// Convenience type alias for the stable structures case
pub type StableRateLimiter<K, Memory> = RateLimiter<K, StableBTreeMapCapacityStorage<K, Memory>>;

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

impl<K: Ord + Clone + Debug, S: CapacityStorage<K>> RateLimiter<K, S> {
    pub fn new(config: RateLimiterConfig, capacity_storage: S) -> Self {
        Self {
            config,
            reservations: Arc::new(Mutex::new(BTreeMap::new())),
            capacity_storage,
            next_index: 0,
        }
    }

    fn cleanup_expired_reservations(&self, key: &K, now: SystemTime) {
        if let Ok(mut reservations) = self.reservations.lock() {
            let expired_keys: Vec<(K, u64)> = reservations
                .range((key.clone(), 0)..(key.clone(), u64::MAX))
                .filter(|(_, data)| {
                    now.duration_since(data.now).unwrap_or(Duration::ZERO)
                        > self.config.reservation_timeout
                })
                .map(|((k, idx), _)| (k.clone(), *idx))
                .collect();

            for expired_key in expired_keys {
                reservations.remove(&expired_key);
            }
        }
    }

    pub fn try_reserve(
        &mut self,
        now: SystemTime,
        key: K,
        requested_capacity: u64,
    ) -> Result<Reservation<K>, RateLimiterError> {
        // Clean up expired reservations first
        self.cleanup_expired_reservations(&key, now);

        let mut reservations = self.reservations.lock().unwrap();

        // Get all reservations for this key to calculate current usage
        let reserved_capacity: u64 = reservations
            .range((key.clone(), 0)..(key.clone(), u64::MAX))
            .map(|(_, data)| data.capacity)
            .sum();

        // Update token bucket capacity and get current committed usage
        let committed_capacity = if let Some(usage_record) = self.capacity_storage.get_usage(&key) {
            let mut usage = usage_record;
            update_capacity(
                &mut usage,
                now,
                self.config.add_capacity_amount,
                self.config.add_capacity_interval,
            );
            // Update the storage with the modified usage
            self.capacity_storage
                .insert_usage(key.clone(), usage.clone());
            usage.capacity_used
        } else {
            0
        };

        if reserved_capacity + committed_capacity + requested_capacity <= self.config.max_capacity {
            // Only allocate global index on successful reservation
            let index = self.next_index;
            self.next_index += 1;

            let reservation_data = ReservationData {
                now,
                capacity: requested_capacity,
            };
            reservations.insert((key.clone(), index), reservation_data);

            let reservation = Reservation {
                key: key.clone(),
                index,
                reservations_map: Arc::downgrade(&self.reservations),
            };

            Ok(reservation)
        } else {
            Err(RateLimiterError::NotEnoughCapacity)
        }
    }

    pub fn commit(&mut self, now: SystemTime, reservation: Reservation<K>) {
        let default_usage = UsageRecord {
            last_capacity_drip: now,
            capacity_used: 0,
        };

        self.capacity_storage
            .with_usage(reservation.key.clone(), default_usage, |usage| {
                // Update token bucket capacity
                update_capacity(
                    usage,
                    now,
                    self.config.add_capacity_amount,
                    self.config.add_capacity_interval,
                );

                // TODO DO NOT MERGE - should this throw an error if the reservation cannot be found
                // How do we handle that?
                if let Ok(mut reservations) = self.reservations.lock() {
                    if let Some(reservation_data) =
                        reservations.remove(&(reservation.key.clone(), reservation.index))
                    {
                        usage.capacity_used = usage
                            .capacity_used
                            .saturating_add(reservation_data.capacity);
                    }
                }
            });
    }

    pub fn restore_capacity(&mut self, now: SystemTime, key: K, capacity_to_restore: u64) {
        // If there's no usage record, do nothing (already at max capacity)
        if self.capacity_storage.get_usage(&key).is_none() {
            return;
        }

        let default_usage = UsageRecord {
            last_capacity_drip: now,
            capacity_used: 0,
        };

        self.capacity_storage
            .with_usage(key, default_usage, |usage| {
                // Update token bucket capacity first (this may update last_updated)
                update_capacity(
                    usage,
                    now,
                    self.config.add_capacity_amount,
                    self.config.add_capacity_interval,
                );

                // Restore capacity (subtract from used capacity, cannot go below 0)
                // Don't update last_updated - let the natural token bucket drip continue
                usage.capacity_used = usage.capacity_used.saturating_sub(capacity_to_restore);
            });
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
        .duration_since(usage_record.last_capacity_drip)
        .unwrap_or(Duration::ZERO);
    // Calculate how many complete intervals have passed
    let complete_intervals = elapsed.as_secs() / add_frequency.as_secs();

    // Calculate new last_updated so that the rate remains constant regardless of when this is checked.
    let last_updated = usage_record.last_capacity_drip
        + Duration::from_secs(complete_intervals.saturating_mul(add_frequency.as_secs()));

    // Add capacity for complete intervals (saturating subtract from used capacity)
    let capacity_to_add = complete_intervals * amount_to_add;
    usage_record.capacity_used = usage_record.capacity_used.saturating_sub(capacity_to_add);

    // Set last_updated to account for the remaining partial interval
    // This keeps the partial interval progress for the next call
    usage_record.last_capacity_drip = last_updated;
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
        let mut rate_limiter = RateLimiter::new(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(10),
                max_capacity: 10,
                reservation_timeout: Duration::from_secs(u64::MAX),
            },
            InMemoryCapacityStorage::new(),
        );

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
        // Now gets global index (continuing from where it left off)
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
        let mut rate_limiter = RateLimiter::new(
            RateLimiterConfig {
                add_capacity_amount: 2, // Add 2 capacity every 10 seconds
                add_capacity_interval: Duration::from_secs(10),
                max_capacity: 10,
                reservation_timeout: Duration::from_secs(u64::MAX),
            },
            InMemoryCapacityStorage::new(),
        );

        let now = SystemTime::now();

        // Use up 8 capacity
        let reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 8).unwrap();
        rate_limiter.commit(now, reservation1);

        // Should only have 2 capacity left
        let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 3);
        assert!(matches!(
            over_limit,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // Can still reserve 2
        let reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 2).unwrap();
        rate_limiter.commit(now, reservation2);

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

    #[test]
    fn test_reservation_timeouts() {
        let mut rate_limiter = RateLimiter::new(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(100),
                max_capacity: 10,
                reservation_timeout: Duration::from_secs(5), // 5 second timeout
            },
            InMemoryCapacityStorage::new(),
        );

        let now = SystemTime::now();

        // Create two reservations that use up all capacity
        let reservation1 = rate_limiter.try_reserve(now, "Foo".to_string(), 6).unwrap();
        let reservation2 = rate_limiter.try_reserve(now, "Foo".to_string(), 4).unwrap();

        // Should not be able to reserve more
        let over_limit = rate_limiter.try_reserve(now, "Foo".to_string(), 1);
        assert!(matches!(
            over_limit,
            Err(RateLimiterError::NotEnoughCapacity)
        ));

        // Verify we have 2 reservations
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 2);

        // Fast forward past the timeout
        let later = now + Duration::from_secs(6);

        // Try to reserve again - this should clean up the expired reservations
        let after_timeout = rate_limiter.try_reserve(later, "Foo".to_string(), 8);
        assert!(after_timeout.is_ok()); // Should work because expired reservations were cleaned up

        // Both old reservations should be gone
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1); // Only the new reservation

        // Try committing old reservations - should have no effect
        rate_limiter.commit(later, reservation1);
        rate_limiter.commit(later, reservation2);
        assert_eq!(rate_limiter.reservations.lock().unwrap().len(), 1);
        assert_eq!(
            rate_limiter
                .capacity_storage
                .get_usage(&"Foo".to_string())
                .unwrap()
                .capacity_used,
            0
        );
    }

    #[test]
    fn test_stable_rate_limiter() {
        use ic_stable_structures::{
            DefaultMemoryImpl,
            memory_manager::{MemoryId, MemoryManager},
        };

        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let capacity_memory = memory_manager.get(MemoryId::new(0));
        let capacity_storage = StableBTreeMapCapacityStorage::new(capacity_memory);

        let mut rate_limiter = RateLimiter::new(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(100),
                max_capacity: 10,
                reservation_timeout: Duration::from_secs(u64::MAX),
            },
            capacity_storage,
        );

        let now = SystemTime::now();

        // Test basic functionality with stable storage
        let reservation1 = rate_limiter
            .try_reserve(now, "stable_key".to_string(), 5)
            .unwrap();
        assert_eq!(reservation1.index, 0);
        assert_eq!(reservation1.key, "stable_key".to_string());

        // Commit the reservation
        rate_limiter.commit(now, reservation1);

        // Verify the usage is stored
        let usage = rate_limiter
            .capacity_storage
            .get_usage(&"stable_key".to_string());
        assert!(usage.is_some());
        assert_eq!(usage.unwrap().capacity_used, 5);

        // Verify rate limiting works with committed capacity
        let reservation2 = rate_limiter.try_reserve(now, "stable_key".to_string(), 6);
        assert!(matches!(
            reservation2,
            Err(RateLimiterError::NotEnoughCapacity)
        ));
    }

    #[test]
    fn test_usage_record_serialization() {
        let now = SystemTime::now();
        let original = UsageRecord {
            last_capacity_drip: now,
            capacity_used: 42,
        };

        // Serialize and deserialize
        let bytes = original.to_bytes();
        let deserialized = UsageRecord::from_bytes(bytes);

        // Capacity should be exactly equal
        assert_eq!(deserialized.capacity_used, original.capacity_used);

        // Time should be equal when both are truncated to seconds
        let original_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deserialized_secs = deserialized
            .last_capacity_drip
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(deserialized_secs, original_secs);
    }

    #[test]
    fn test_restore_capacity() {
        let mut rate_limiter = RateLimiter::new(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(100),
                max_capacity: 10,
                reservation_timeout: Duration::from_secs(u64::MAX),
            },
            InMemoryCapacityStorage::new(),
        );

        let now = SystemTime::now();

        // First, use some capacity
        let reservation1 = rate_limiter
            .try_reserve(now, "test_key".to_string(), 8)
            .unwrap();
        rate_limiter.commit(now, reservation1);

        // Verify capacity is used
        let usage = rate_limiter
            .capacity_storage
            .get_usage(&"test_key".to_string())
            .unwrap();
        assert_eq!(usage.capacity_used, 8);

        // Restore 3 units of capacity
        rate_limiter.restore_capacity(now, "test_key".to_string(), 3);

        // Should now have 5 units used (8 - 3 = 5)
        let usage = rate_limiter
            .capacity_storage
            .get_usage(&"test_key".to_string())
            .unwrap();
        assert_eq!(usage.capacity_used, 5);

        // Test saturating_sub: restore more than used
        rate_limiter.restore_capacity(now, "test_key".to_string(), 10);

        // Should now have 0 units used (5 - 10 = 0, saturating)
        let usage = rate_limiter
            .capacity_storage
            .get_usage(&"test_key".to_string())
            .unwrap();
        assert_eq!(usage.capacity_used, 0);

        // Test restoring capacity for a key that has no usage record (should do nothing)
        rate_limiter.restore_capacity(now, "nonexistent_key".to_string(), 5);

        // Should not create a new entry - no usage record should exist
        assert!(
            rate_limiter
                .capacity_storage
                .get_usage(&"nonexistent_key".to_string())
                .is_none()
        );

        // Should be able to reserve full capacity since no usage record exists
        let full_reservation = rate_limiter.try_reserve(now, "nonexistent_key".to_string(), 10);
        assert!(full_reservation.is_ok());
    }
}
