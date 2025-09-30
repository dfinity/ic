use crate::storage::with_rate_limiter_memory;
use ic_nervous_system_rate_limits::{RateLimiter, RateLimiterConfig, StableMemoryCapacityStorage};
use ic_stable_structures::{DefaultMemoryImpl, memory_manager::VirtualMemory};
use std::{cell::RefCell, time::Duration};

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {

      static NODE_OPERATOR_RATE_LIMITER: RefCell<RateLimiter<String, StableMemoryCapacityStorage<String, VM>>>
            = RefCell::new(RateLimiter::new(RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(100),
                max_capacity: 0,
                max_reservations: 0,
        },
        with_rate_limiter_memory(StableMemoryCapacityStorage::new)
    ));
}
