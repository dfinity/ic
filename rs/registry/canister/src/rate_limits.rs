use crate::mutations::node_management::common::get_node_provider_id_for_operator_id;
use crate::registry::Registry;
use crate::storage::{
    get_node_operator_rate_limiter_memory, get_node_proivder_rate_limiter_memory,
};
use ic_base_types::PrincipalId;
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

// Node Operator rate limiting constants
const NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY: u64 = 25;
const NODE_OPERATOR_MAX_SPIKE: u64 = NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY * 7;
pub const NODE_OPERATOR_CAPACITY_ADD_INTERVAL_SECONDS: u64 =
    ONE_DAY_SECONDS / NODE_OPERATOR_MAX_AVG_OPERATIONS_PER_DAY;

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
        get_node_proivder_rate_limiter_memory(),
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

pub struct RateLimitReservation {
    operator_reservation: Reservation<String>,
    provider_reservation: Reservation<String>,
}

impl Registry {
    /// Try to reserve capacity for an operation that is rate limited by both Node Operator and Node Provider
    pub fn try_reserve_node_operation_rate_limit_capacity(
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

    pub fn try_reserve_node_provider_rate_limit_capacity(
        &self,
        now: SystemTime,
        node_provider_id: PrincipalId,
        requested_capacity: u64,
    ) -> Result<Reservation<String>, RateLimiterError> {
        with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.try_reserve(now, node_provider_key(node_provider_id), requested_capacity)
        })
    }

    /// Commit the reserved usage (i.e. commit the reserved usage)
    pub fn commit_node_operation_rate_limit_capacity(
        &self,
        now: SystemTime,
        reservation: RateLimitReservation,
    ) -> Result<(), RateLimiterError> {
        // Commit both reservations
        with_node_operator_rate_limiter(|rate_limiter| {
            rate_limiter.commit(now, reservation.operator_reservation)
        })?;

        with_node_provider_rate_limiter(|rate_limiter| {
            rate_limiter.commit(now, reservation.provider_reservation)
        })?;

        Ok(())
    }

    pub fn commit_node_provider_rate_limit_capacity(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use maplit::btreemap;

    #[test]
    fn test_drop_behavior_in_thread_local() {
        let now = SystemTime::now();
        let key = PrincipalId::new_user_test_id(1);
        let mut registry = invariant_compliant_registry(0);

        // Add a node operator record to the registry
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(key),
            node_provider_principal_id: Some(key), // Use same ID for simplicity
            node_allowance: 10,
            dc_id: "test_dc".to_string(),
            rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ipv6: None,
            max_rewardable_nodes: Some(btreemap! { "type1".to_string() => 1 }),
        };
        registry.do_add_node_operator(payload);

        let first_available_operator = registry.get_available_node_operator_op_capacity(key, now);
        let first_available_provider = registry.get_available_node_provider_op_capacity(key, now);

        let reservation = registry
            .try_reserve_node_operation_rate_limit_capacity(now, key, 5)
            .unwrap();

        let second_available_operator = registry.get_available_node_operator_op_capacity(key, now);
        let second_available_provider = registry.get_available_node_provider_op_capacity(key, now);
        assert_eq!(first_available_operator - 5, second_available_operator);
        assert_eq!(first_available_provider - 5, second_available_provider);

        drop(reservation);

        let third_available_operator = registry.get_available_node_operator_op_capacity(key, now);
        let third_available_provider = registry.get_available_node_provider_op_capacity(key, now);

        assert_eq!(first_available_operator, third_available_operator);
        assert_eq!(first_available_provider, third_available_provider);
    }
}
