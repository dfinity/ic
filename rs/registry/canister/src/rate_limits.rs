use crate::storage::get_rate_limiter_memory;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_rate_limits::{RateLimiter, RateLimiterConfig, StableMemoryCapacityStorage};
use ic_stable_structures::{DefaultMemoryImpl, memory_manager::VirtualMemory};
use std::{cell::RefCell, time::Duration};

type VM = VirtualMemory<DefaultMemoryImpl>;

const MAX_AVG_OPERATIONS_PER_DAY: u64 = 50;
const MAX_SPIKE: u64 = MAX_AVG_OPERATIONS_PER_DAY * 7;
const CAPACITY_ADD_INTERVAL_SECONDS: u64 = ONE_DAY_SECONDS / MAX_AVG_OPERATIONS_PER_DAY;

thread_local! {
    static NODE_OPERATOR_RATE_LIMITER: RefCell<
        RateLimiter<String, StableMemoryCapacityStorage<String, VM>>,
    > = RefCell::new(RateLimiter::new_stable(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(CAPACITY_ADD_INTERVAL_SECONDS),
            max_capacity: MAX_SPIKE,
            // This value is somewhat arbitrary.  Given the short-lived nature of the requests, and
            // the fact that the operations are largely sy this
            // should never actually be a factor
            max_reservations: MAX_SPIKE * 2,
        },
        get_rate_limiter_memory(),
    ));
}

pub fn with_node_operator_rate_limiter<R>(
    f: impl FnOnce(&mut RateLimiter<String, StableMemoryCapacityStorage<String, VM>>) -> R,
) -> R {
    NODE_OPERATOR_RATE_LIMITER.with_borrow_mut(f)
}
