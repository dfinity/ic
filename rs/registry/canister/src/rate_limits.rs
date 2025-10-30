use crate::mutations::node_management::common::get_node_provider_id_for_operator_id;
use crate::registry::Registry;
use crate::storage::{
    get_node_operator_rate_limiter_memory, get_node_provider_rate_limiter_memory,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_rate_limits::{
    InMemoryRateLimiter, RateLimiter, RateLimiterConfig, RateLimiterError, Reservation,
    StableMemoryCapacityStorage,
};
use ic_stable_structures::{DefaultMemoryImpl, memory_manager::VirtualMemory};
use std::time::SystemTime;
use std::{cell::RefCell, time::Duration};

type VM = VirtualMemory<DefaultMemoryImpl>;

const NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY: u64 = 20;
const NODE_PROVIDER_MAX_SPIKE: u64 = NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY * 7;
pub const NODE_PROVIDER_CAPACITY_ADD_INTERVAL_SECONDS: u64 =
    ONE_DAY_SECONDS / NODE_PROVIDER_MAX_AVG_OPERATIONS_PER_DAY;

// Node Operator rate limiting constants
const NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY: u64 = 20;
const NODE_OPERATOR_MAX_SPIKE: u64 = NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY * 7;
pub const NODE_OPERATOR_CAPACITY_ADD_INTERVAL_SECONDS: u64 =
    ONE_DAY_SECONDS / NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY;

const AVG_ADD_NODE_BY_IP_PER_DAY: u64 = 1;
const ADD_NODE_IP_MAX_SPIKE: u64 = AVG_ADD_NODE_BY_IP_PER_DAY * 7;
const ADD_NODE_IP_REFILL_INTERVAL_SECONDS: u64 = ONE_DAY_SECONDS;

thread_local! {
    static NODE_PROVIDER_RATE_LIMITER: RefCell<
        RateLimiter<String, StableMemoryCapacityStorage<String, VM>>,
    > = RefCell::new(RateLimiter::new_stable(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(NODE_PROVIDER_CAPACITY_ADD_INTERVAL_SECONDS),
            max_capacity: NODE_PROVIDER_MAX_SPIKE,
            max_reservations: NODE_PROVIDER_MAX_SPIKE * 2,
        },
        get_node_provider_rate_limiter_memory(),
    ));

    static NODE_OPERATOR_RATE_LIMITER: RefCell<
        RateLimiter<String, StableMemoryCapacityStorage<String, VM>>,
    > = RefCell::new(RateLimiter::new_stable(
        RateLimiterConfig {
            add_capacity_amount: 1,
            add_capacity_interval: Duration::from_secs(NODE_OPERATOR_CAPACITY_ADD_INTERVAL_SECONDS),
            max_capacity: NODE_OPERATOR_MAX_SPIKE,
            max_reservations: NODE_OPERATOR_MAX_SPIKE * 2,
        },
        get_node_operator_rate_limiter_memory(),
    ));

    /// IP-based rate limiter for add_node operations.
    /// Stored in heap memory (not stable memory).
    /// Limits to 1 node addition per day per IP address.
    static ADD_NODE_IP_RATE_LIMITER: RefCell<InMemoryRateLimiter<String>> =
        RefCell::new(InMemoryRateLimiter::new_in_memory(
            RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: Duration::from_secs(ADD_NODE_IP_REFILL_INTERVAL_SECONDS),
                max_capacity: ADD_NODE_IP_MAX_SPIKE,
                max_reservations: ADD_NODE_IP_MAX_SPIKE * 2,
            },
        ));
}

fn node_provider_key(node_provider: PrincipalId) -> String {
    format!("node_provider_{node_provider}")
}

fn node_operator_key(node_operator: PrincipalId) -> String {
    format!("node_operator_{node_operator}")
}

fn with_node_provider_rate_limiter<R>(
    f: impl FnOnce(&mut RateLimiter<String, StableMemoryCapacityStorage<String, VM>>) -> R,
) -> R {
    NODE_PROVIDER_RATE_LIMITER.with_borrow_mut(f)
}

fn with_node_operator_rate_limiter<R>(
    f: impl FnOnce(&mut RateLimiter<String, StableMemoryCapacityStorage<String, VM>>) -> R,
) -> R {
    NODE_OPERATOR_RATE_LIMITER.with_borrow_mut(f)
}

fn with_add_node_ip_rate_limiter<R>(f: impl FnOnce(&mut InMemoryRateLimiter<String>) -> R) -> R {
    ADD_NODE_IP_RATE_LIMITER.with_borrow_mut(f)
}

pub struct RateLimitReservation {
    operator_reservation: Reservation<String>,
    provider_reservation: Reservation<String>,
}

impl Registry {
    /// Try to reserve capacity for an operation that is rate limited by both Node Operator and Node Provider
    /// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
    pub fn try_reserve_capacity_for_node_operator_operation(
        &self,
        now: SystemTime,
        node_operator_id: PrincipalId,
        requested_capacity: u64,
    ) -> Result<RateLimitReservation, RateLimiterError> {
        // Find the associated node provider ID for this node operator
        let node_provider_id = get_node_provider_id_for_operator_id(self, node_operator_id)
            .map_err(RateLimiterError::InvalidArguments)?;

        // First reserve from node operator rate limiter (primary)
        let operator_reservation = with_node_operator_rate_limiter(|rate_limiter| {
            rate_limiter.try_reserve(now, node_operator_key(node_operator_id), requested_capacity)
        })?;

        // Then reserve from node provider rate limiter (secondary)
        let provider_reservation = with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.try_reserve(now, node_provider_key(node_provider_id), requested_capacity)
        })?;

        Ok(RateLimitReservation {
            operator_reservation,
            provider_reservation,
        })
    }

    /// Tries to reserve capacity for a node provider operation.
    /// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
    pub fn try_reserve_capacity_for_node_provider_operation(
        &self,
        now: SystemTime,
        node_provider_id: PrincipalId,
        requested_capacity: u64,
    ) -> Result<Reservation<String>, RateLimiterError> {
        with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.try_reserve(now, node_provider_key(node_provider_id), requested_capacity)
        })
    }

    /// Commits the reserved usage (i.e. commit the reserved usage)
    /// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
    pub fn commit_used_capacity_for_node_operator_operation(
        &self,
        now: SystemTime,
        reservation: RateLimitReservation,
    ) -> Result<(), RateLimiterError> {
        // Commit both reservations, trying both even if one fails
        let operator_result = with_node_operator_rate_limiter(|rate_limiter| {
            rate_limiter.commit(now, reservation.operator_reservation)
        });

        let provider_result = with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.commit(now, reservation.provider_reservation)
        });

        // Return the first error if any, or Ok(()) if both succeeded
        operator_result?;
        provider_result?;
        Ok(())
    }

    /// Commits the reserved usage for a node provider operation.
    /// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
    pub fn commit_used_capacity_for_node_provider_operation(
        &self,
        now: SystemTime,
        reservation: Reservation<String>,
    ) -> Result<(), RateLimiterError> {
        with_node_provider_rate_limiter(|rate_limiter| rate_limiter.commit(now, reservation))
    }

    // This function tells how much capacity is left, which is very useful for tests.  This could also
    // potentially be used in production code, but there's no use case yet.
    #[cfg(test)]
    pub fn get_available_node_provider_op_capacity(
        &self,
        node_provider_id: PrincipalId,
        now: SystemTime,
    ) -> u64 {
        with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.get_available_capacity(node_provider_key(node_provider_id), now)
        })
    }

    // This function tells how much capacity is left for node operators, which is very useful for tests.
    #[cfg(test)]
    pub fn get_available_node_operator_op_capacity(
        &self,
        node_operator_id: PrincipalId,
        now: SystemTime,
    ) -> u64 {
        with_node_operator_rate_limiter(|rate_limiter| {
            rate_limiter.get_available_capacity(node_operator_key(node_operator_id), now)
        })
    }
}

/// Tries to reserve capacity for an add_node operation based on IP address.
/// Each IP address can (on average)add 1 node per day.
/// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
pub fn try_reserve_add_node_capacity(
    now: SystemTime,
    ip_addr: String,
) -> Result<Reservation<String>, RateLimiterError> {
    with_add_node_ip_rate_limiter(|rate_limiter| rate_limiter.try_reserve(now, ip_addr, 1))
}

/// Commits the reserved capacity for an add_node operation.
/// See ic_nervous_system_rate_limits documentation to understand the reserve-commit pattern.
pub fn commit_add_node_capacity(
    now: SystemTime,
    reservation: Reservation<String>,
) -> Result<(), RateLimiterError> {
    with_add_node_ip_rate_limiter(|rate_limiter| rate_limiter.commit(now, reservation))
}

/// Get available capacity for an IP address (for testing).
#[cfg(test)]
pub fn get_available_add_node_capacity(ip_addr: String, now: SystemTime) -> u64 {
    with_add_node_ip_rate_limiter(|rate_limiter| rate_limiter.get_available_capacity(ip_addr, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use maplit::btreemap;

    #[test]
    fn test_combined_rate_limiting() {
        let now = SystemTime::now();
        let shared_node_provider = PrincipalId::new_user_test_id(1000);
        let node_operator_1 = PrincipalId::new_user_test_id(1);
        let node_operator_2 = PrincipalId::new_user_test_id(2);
        let mut registry = invariant_compliant_registry(0);

        // Add first node operator that shares the node provider
        let payload_1 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_1),
            node_provider_principal_id: Some(shared_node_provider),
            node_allowance: 10,
            dc_id: "test_dc_1".to_string(),
            rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ipv6: None,
            max_rewardable_nodes: Some(btreemap! { "type1".to_string() => 1 }),
        };
        registry.do_add_node_operator(payload_1);

        // Add second node operator that shares the same node provider
        let payload_2 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_2),
            node_provider_principal_id: Some(shared_node_provider),
            node_allowance: 10,
            dc_id: "test_dc_2".to_string(),
            rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ipv6: None,
            max_rewardable_nodes: Some(btreemap! { "type1".to_string() => 1 }),
        };
        registry.do_add_node_operator(payload_2);

        // Get initial capacities
        let initial_operator_1_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_1, now);
        let initial_operator_2_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_2, now);
        let initial_provider_capacity =
            registry.get_available_node_provider_op_capacity(shared_node_provider, now);

        // Reserve capacity for first node operator
        let reservation_1 = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_1, 5)
            .unwrap();

        // Check that both operator and provider capacities decreased
        let after_operator_1_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_1, now);
        let after_provider_capacity =
            registry.get_available_node_provider_op_capacity(shared_node_provider, now);
        assert_eq!(initial_operator_1_capacity - 5, after_operator_1_capacity);
        assert_eq!(initial_provider_capacity - 5, after_provider_capacity);

        // Reserve capacity for second node operator
        let reservation_2 = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_2, 3)
            .unwrap();

        // Check that second operator capacity decreased, but provider capacity decreased further
        let after_operator_2_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_2, now);
        let final_provider_capacity =
            registry.get_available_node_provider_op_capacity(shared_node_provider, now);
        assert_eq!(initial_operator_2_capacity - 3, after_operator_2_capacity);
        assert_eq!(initial_provider_capacity - 5 - 3, final_provider_capacity);

        // Drop first reservation - should restore operator 1 capacity and provider capacity
        drop(reservation_1);

        let restored_operator_1_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_1, now);
        let restored_provider_capacity =
            registry.get_available_node_provider_op_capacity(shared_node_provider, now);
        assert_eq!(initial_operator_1_capacity, restored_operator_1_capacity);
        assert_eq!(initial_provider_capacity - 3, restored_provider_capacity); // Only operator 2's reservation remains

        // Drop second reservation - should restore everything
        drop(reservation_2);

        let final_operator_1_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_1, now);
        let final_operator_2_capacity =
            registry.get_available_node_operator_op_capacity(node_operator_2, now);
        let final_provider_capacity =
            registry.get_available_node_provider_op_capacity(shared_node_provider, now);

        assert_eq!(initial_operator_1_capacity, final_operator_1_capacity);
        assert_eq!(initial_operator_2_capacity, final_operator_2_capacity);
        assert_eq!(initial_provider_capacity, final_provider_capacity);
    }
}
