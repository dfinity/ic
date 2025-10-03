use crate::storage::get_rate_limiter_memory;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_rate_limits::{
    RateLimiter, RateLimiterConfig, RateLimiterError, Reservation, StableMemoryCapacityStorage,
};
use ic_stable_structures::{DefaultMemoryImpl, memory_manager::VirtualMemory};
use std::time::SystemTime;
use std::{cell::RefCell, time::Duration};

type VM = VirtualMemory<DefaultMemoryImpl>;

// Note, operations are weighted, so that some operations, such as adding a node, cost 20, while others
// such as updating a single record, cost 1.
const NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY: u64 = 100;
const NODE_PROVIDER_MAX_SPIKE: u64 = NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY * 7;
pub const NODE_PROVIDER_CAPACITY_ADD_INTERVAL_SECONDS: u64 =
    ONE_DAY_SECONDS / NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY;

thread_local! {
    static NODE_PROVIDER_RATE_LIMITER: RefCell<
        RateLimiter<String, StableMemoryCapacityStorage<String, VM>>,
    > = RefCell::new(RateLimiter::new_stable(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(NODE_PROVIDER_CAPACITY_ADD_INTERVAL_SECONDS),
            max_capacity: NODE_PROVIDER_MAX_SPIKE,
            // This value is somewhat arbitrary.  Given the short-lived nature of the requests, and
            // the fact that the operations are largely sy this
            // should never actually be a factor
            max_reservations: NODE_PROVIDER_MAX_SPIKE * 2,
        },
        get_rate_limiter_memory(),
    ));
}

fn with_node_provider_rate_limiter<R>(
    f: impl FnOnce(&mut RateLimiter<String, StableMemoryCapacityStorage<String, VM>>) -> R,
) -> R {
    NODE_PROVIDER_RATE_LIMITER.with_borrow_mut(f)
}

/// Try to reserve capacity for an operation that is rate limited by Node Provider
pub fn try_reserve_node_provider_op_capacity(
    now: SystemTime,
    key: impl ToString,
    requested_capacity: u64,
) -> Result<Reservation<String>, RateLimiterError> {
    with_node_provider_rate_limiter(|rate_limiter| {
        rate_limiter.try_reserve(now, key.to_string(), requested_capacity)
    })
}

/// Commit the reserved usage (i.e. commit the reserved usage)
pub fn commit_node_provider_op_reservation(
    now: SystemTime,
    reservation: Reservation<String>,
) -> Result<(), RateLimiterError> {
    with_node_provider_rate_limiter(|rate_limiter| rate_limiter.commit(now, reservation))
}

// This function tells how much capacity is left, which is very useful for tests.  This could also
// potentially be used in production code, but there's no use case yet.
#[cfg(test)]
pub fn get_available_node_provider_op_capacity(key: impl ToString, now: SystemTime) -> u64 {
    with_node_provider_rate_limiter(|rate_limiter| {
        rate_limiter.get_available_capacity(key.to_string(), now)
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_drop_behavior_in_thread_local() {
        let now = SystemTime::now();
        let key = "Foo";
        let first_available = get_available_node_provider_op_capacity(key, now);

        let reservation = try_reserve_node_provider_op_capacity(now, key, 5).unwrap();

        let second_available = get_available_node_provider_op_capacity(key, now);
        assert_eq!(first_available - 5, second_available);

        drop(reservation);

        let third_available = get_available_node_provider_op_capacity(key, now);

        assert_eq!(first_available, third_available);
    }
}
