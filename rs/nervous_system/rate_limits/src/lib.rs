//! Rate limits library for nervous system components.
//!
//! This library uses a [Leaky Bucket Algorithm](https://en.wikipedia.org/wiki/Leaky_bucket) to
//! enforce rate limites, which allows for a configurable amount of spikiness around the average
//! limit desired.
//!
//! A reserve-commit pattern is used so that any failure would not affect the rate limit (otherwise
//! a DoS would be possible by deliberately triggering operations that would fail).
//!
//! Example:
//!
//! ```
//! let reservation = get_rate_limiter().try_reserve(now, key, requested_capacity)?;
//! do_something()?; // if this fails, the reservation is dropped without affecting the rate limit
//! get_rate_limiter().commit(now, reservation).expect("Failed to commit reservation"); // Or handle the error by logging. It should not fail unless there the resevation is invalid.
//! ```
//!
//! This pattern is also safe to use in an asynchronous context - if the reservation happens at the
//! first message of the async call, then the entire async call is protected by the rate limiting.
//! Although, in those cases, the user should consider whether the reservation should be committed
//! if the async call fails, depending on whether the rate limiting is trying to protect against the
//! inter-canister call (in which case, the reservation should be committed) or the some other
//! mutations inside the canister (in which case, the reservation should not be committed).
use ic_stable_structures::{StableBTreeMap, Storable};
use std::fmt::{Display, Formatter};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug, PartialEq)]
pub struct CapacityUsageRecord {
    last_capacity_drip: SystemTime,
    capacity_used: u64,
}

/// Trait for storing and retrieving capacity usage records.
/// This allows different storage backends (in-memory, persistent, etc.)
pub trait CapacityUsageRecordStorage<K> {
    /// Get usage record for a key
    fn get(&self, key: &K) -> Option<CapacityUsageRecord>;

    /// Insert or update usage record for a key
    fn upsert(&mut self, key: K, record: CapacityUsageRecord);

    fn remove(&mut self, key: &K) -> Option<CapacityUsageRecord>;
}

pub struct InMemoryCapacityStorage<K> {
    capacity_usage_records: BTreeMap<K, CapacityUsageRecord>,
}

impl<K: Ord + Clone> InMemoryCapacityStorage<K> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<K: Ord + Clone> Default for InMemoryCapacityStorage<K> {
    fn default() -> Self {
        Self {
            capacity_usage_records: Default::default(),
        }
    }
}

impl<K: Ord + Clone> CapacityUsageRecordStorage<K> for InMemoryCapacityStorage<K> {
    fn get(&self, key: &K) -> Option<CapacityUsageRecord> {
        self.capacity_usage_records.get(key).cloned()
    }

    fn upsert(&mut self, key: K, record: CapacityUsageRecord) {
        self.capacity_usage_records.insert(key, record);
    }

    fn remove(&mut self, key: &K) -> Option<CapacityUsageRecord> {
        self.capacity_usage_records.remove(key)
    }
}

/// Persistent capacity storage implementation using StableBTreeMap.
/// This allows capacity usage to survive canister upgrades.
pub struct StableMemoryCapacityStorage<K, Memory>
where
    K: Storable + Ord + Clone,
    Memory: ic_stable_structures::Memory,
{
    capacity_usage_records: StableBTreeMap<K, (u64 /*time*/, u64 /*capacity used*/), Memory>,
}

impl<K, Memory> StableMemoryCapacityStorage<K, Memory>
where
    K: Ord + Clone + Storable,
    Memory: ic_stable_structures::Memory,
{
    pub fn new(memory: Memory) -> Self {
        Self {
            capacity_usage_records: StableBTreeMap::init(memory),
        }
    }
}

impl From<(u64, u64)> for CapacityUsageRecord {
    fn from(value: (u64, u64)) -> Self {
        let (last_drip_nanoseconds, capacity_used) = value;

        let last_capacity_drip =
            SystemTime::UNIX_EPOCH + Duration::from_nanos(last_drip_nanoseconds);
        CapacityUsageRecord {
            last_capacity_drip,
            capacity_used,
        }
    }
}

impl From<CapacityUsageRecord> for (u64, u64) {
    fn from(value: CapacityUsageRecord) -> Self {
        let last_capacity_drip = value
            .last_capacity_drip
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .try_into()
            .expect("Nanos from Unix Epoch should be under u64::MAX for hundreds of years...");

        (last_capacity_drip, value.capacity_used)
    }
}

impl<K, Memory> CapacityUsageRecordStorage<K> for StableMemoryCapacityStorage<K, Memory>
where
    K: Ord + Clone + Storable,
    Memory: ic_stable_structures::Memory,
{
    fn get(&self, key: &K) -> Option<CapacityUsageRecord> {
        self.capacity_usage_records
            .get(key)
            .map(CapacityUsageRecord::from)
    }

    fn upsert(&mut self, key: K, record: CapacityUsageRecord) {
        self.capacity_usage_records
            .insert(key, <(u64, u64)>::from(record));
    }

    fn remove(&mut self, key: &K) -> Option<CapacityUsageRecord> {
        self.capacity_usage_records
            .remove(key)
            .map(CapacityUsageRecord::from)
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

impl<K: Ord + Clone + Debug> InMemoryRateLimiter<K> {
    pub fn new_in_memory(config: RateLimiterConfig) -> Self {
        Self::new(config, InMemoryCapacityStorage::default())
    }
}

// Convenience type alias for the stable structures case
pub type StableRateLimiter<K, Memory> = RateLimiter<K, StableMemoryCapacityStorage<K, Memory>>;

impl<K: Ord + Clone + Debug + Storable, Memory: ic_stable_structures::Memory>
    StableRateLimiter<K, Memory>
{
    pub fn new_stable(config: RateLimiterConfig, memory: Memory) -> Self {
        Self::new(config, StableMemoryCapacityStorage::new(memory))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ReservationData {
    now: SystemTime,
    capacity: u64,
}

// Configureation for RateLimiter.
pub struct RateLimiterConfig {
    // How much capacity is restored after each add_capacity_interval.
    pub add_capacity_amount: u64,
    // How frequently capacity is restored after usage.
    pub add_capacity_interval: Duration,
    // Max capacity per item being rate limited.  If there are many items
    // then each would have its own limit, but they would all be max_capacity.
    pub max_capacity: u64,
    // Max reservations across entire space
    pub max_reservations: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RateLimiterError {
    NotEnoughCapacity,
    InvalidArguments(String),
    MaxReservationsReached,
    ReservationNotFound,
}

impl Display for RateLimiterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            RateLimiterError::NotEnoughCapacity => "Rate Limit Capacity exceeded. \
                    Please wait and try again later."
                .to_string(),
            RateLimiterError::InvalidArguments(e) => format!("Rate Limit Invalid Arguments: {e}"),
            RateLimiterError::MaxReservationsReached => {
                "Maximum Open Rate Limit Reservations Reached.".to_string()
            }
            RateLimiterError::ReservationNotFound => {
                "Ratelimiter has no record of the reservation \
                passed to commit, so could not commit reservation."
                    .to_string()
            }
        };

        f.write_str(message.as_str())
    }
}

impl From<RateLimiterError> for String {
    fn from(value: RateLimiterError) -> Self {
        format!("{value}")
    }
}

impl<K: Ord + Clone + Debug, S: CapacityUsageRecordStorage<K>> RateLimiter<K, S> {
    fn new(config: RateLimiterConfig, capacity_storage: S) -> Self {
        Self {
            config,
            reservations: Arc::new(Mutex::new(BTreeMap::new())),
            capacity_storage,
            next_index: 0,
        }
    }

    /// Tries to reserve capacity for a given key and requested capacity. Returns a Reservation
    /// object if successful, or an error if the capacity is not available. The reservation object
    /// needs to be committed (i.e. call `commit()` with it) to actually consume the capacity. If
    /// the reservation is not committed, then when the reservation is dropped, the capacity is not
    /// consumed and the reservation is removed from the rate limiter, so it does not affect the
    /// rate limit. Note that while the reservation object exists, the capacity is effectively
    /// consumed, so that the subsequent `commit()` should succeed (unless somehow the reservation
    /// is not created by the same rate limiter, in which case, the commit will fail).
    pub fn try_reserve(
        &mut self,
        now: SystemTime,
        key: K,
        requested_capacity: u64,
    ) -> Result<Reservation<K>, RateLimiterError> {
        // validate reservation for actual capacity.
        if requested_capacity < 1 {
            return Err(RateLimiterError::InvalidArguments(
                "To make a rate-limit reservation, requested_capacity must be at least 1"
                    .to_string(),
            ));
        }

        let reservations = self.reservations.lock().unwrap();
        // validate that system can handle more reservations
        let used_reservations: u64 = reservations
            .len()
            .try_into()
            .expect("usize should always safely convert to u64");

        if used_reservations >= self.config.max_reservations {
            return Err(RateLimiterError::MaxReservationsReached);
        }

        // Drop this borrow so we can borrow mutably to get usage
        drop(reservations);

        if requested_capacity <= self.get_available_capacity(key.clone(), now) {
            let mut reservations = self.reservations.lock().unwrap();
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

    /// Commits a reservation, consuming the capacity. Returns an error if the reservation is not
    /// found or is invalid (i.e. not created by the same rate limiter).
    pub fn commit(
        &mut self,
        now: SystemTime,
        reservation: Reservation<K>,
    ) -> Result<(), RateLimiterError> {
        let reservation_data = if let Ok(mut reservations) = self.reservations.lock() {
            if let Some(reservation_data) =
                reservations.remove(&(reservation.key.clone(), reservation.index))
            {
                reservation_data
            } else {
                return Err(RateLimiterError::ReservationNotFound);
            }
        } else {
            return Err(RateLimiterError::ReservationNotFound);
        };

        self.with_capacity_usage_record(reservation.key.clone(), now, |usage| {
            usage.capacity_used = usage
                .capacity_used
                .saturating_add(reservation_data.capacity);
        });

        Ok(())
    }

    pub fn get_available_capacity(&mut self, key: K, now: SystemTime) -> u64 {
        let committed_capacity =
            self.with_capacity_usage_record(key.clone(), now, |usage| usage.capacity_used);

        let reservations = self.reservations.lock().unwrap();

        // Get all reservations for this key to calculate current usage
        let reserved_capacity: u64 = reservations
            .range((key.clone(), 0)..=(key.clone(), u64::MAX))
            .map(|(_, data)| data.capacity)
            .sum();

        self.config
            .max_capacity
            .saturating_sub(reserved_capacity)
            .saturating_sub(committed_capacity)
    }

    // Internal helper to correctly deal with memory usage.
    fn with_capacity_usage_record<R>(
        &mut self,
        key: K,
        now: SystemTime,
        f: impl FnOnce(&mut CapacityUsageRecord) -> R,
    ) -> R {
        // Get mutable record
        let mut usage = self
            .capacity_storage
            .remove(&key)
            .unwrap_or(CapacityUsageRecord {
                last_capacity_drip: now,
                capacity_used: 0,
            });

        // Update token bucket capacity so that it's always accurate when retrieved.
        update_capacity(
            &mut usage,
            now,
            self.config.add_capacity_amount,
            self.config.add_capacity_interval,
        );

        let result = f(&mut usage);
        // We only insert the record if there's something in it.
        if usage.capacity_used > 0 {
            self.capacity_storage.upsert(key, usage);
        }
        result
    }
}

fn update_capacity(
    usage_record: &mut CapacityUsageRecord,
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
        #[allow(clippy::collapsible_if)]
        if let Some(reservations_arc) = self.reservations_map.upgrade() {
            if let Ok(mut reservations) = reservations_arc.lock() {
                reservations.remove(&(self.key.clone(), self.index));
            }
        }
    }
}

#[cfg(test)]
mod tests;
