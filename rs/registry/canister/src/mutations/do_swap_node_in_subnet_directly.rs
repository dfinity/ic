use std::{
    cell::RefCell,
    fmt::Display,
    time::{Duration, SystemTime},
};

use candid::CandidType;
use ic_nervous_system_rate_limits::{InMemoryRateLimiter, RateLimiterConfig, Reservation};
use ic_nervous_system_time_helpers::now_system_time;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::upsert;
use ic_types::{NodeId, PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    flags::{
        is_node_swapping_enabled, is_node_swapping_enabled_for_caller,
        is_node_swapping_enabled_on_subnet,
    },
    mutations::node_management::common::find_subnet_for_node,
    registry::Registry,
};

pub const NODE_SWAPS_SUBNET_CAPACITY_INTERVAL: Duration = Duration::from_secs(4 * 60 * 60);
pub const NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

struct SwapRateLimiter {
    subnet_limiter: InMemoryRateLimiter<SubnetId>,
    node_operator_limiter: InMemoryRateLimiter<(PrincipalId, SubnetId)>,
}

#[derive(Debug)]
struct SwapReservation {
    subnet_reservation: Reservation<SubnetId>,
    node_operator_reservation: Reservation<(PrincipalId, SubnetId)>,
}

impl SwapRateLimiter {
    fn new() -> Self {
        Self {
            subnet_limiter: InMemoryRateLimiter::new_in_memory(RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: NODE_SWAPS_SUBNET_CAPACITY_INTERVAL,
                max_capacity: 1,
                max_reservations: 1,
            }),
            node_operator_limiter: InMemoryRateLimiter::new_in_memory(RateLimiterConfig {
                add_capacity_amount: 1,
                add_capacity_interval: NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL,
                max_capacity: 1,
                max_reservations: 1,
            }),
        }
    }

    fn try_reserve(
        &mut self,
        node_operator: PrincipalId,
        subnet_id: SubnetId,
        now: SystemTime,
    ) -> Result<SwapReservation, SwapError> {
        let subnet_reservation =
            self.subnet_limiter
                .try_reserve(now, subnet_id, 1)
                .map_err(|e| match e {
                    ic_nervous_system_rate_limits::RateLimiterError::NotEnoughCapacity => {
                        SwapError::SubnetRateLimited { subnet_id }
                    }
                    re => panic!("Unexpected error from subnet rate limiter: {re:?}"),
                })?;

        let node_operator_reservation = self
            .node_operator_limiter
            .try_reserve(now, (node_operator, subnet_id), 1)
            .map_err(|e| match e {
                ic_nervous_system_rate_limits::RateLimiterError::NotEnoughCapacity => {
                    SwapError::OperatorRateLimitedOnSubnet {
                        subnet_id,
                        caller: node_operator,
                    }
                }
                re => panic!("Unexpected error from node operator rate limiter: {re:?}"),
            })?;

        Ok(SwapReservation {
            subnet_reservation,
            node_operator_reservation,
        })
    }

    fn commit(&mut self, reservation: SwapReservation, now: SystemTime) {
        // This call cannot fail as the whole execution is performed in a single update context
        self.subnet_limiter
            .commit(now, reservation.subnet_reservation)
            .unwrap();
        self.node_operator_limiter
            .commit(now, reservation.node_operator_reservation)
            .unwrap();
    }
}
thread_local! {
    static SWAP_LIMITER: RefCell<SwapRateLimiter> = RefCell::new(SwapRateLimiter::new());
}

impl Registry {
    /// Called by the node operators in order to rotate their nodes without the need for governance.
    pub fn do_swap_node_in_subnet_directly(&mut self, payload: SwapNodeInSubnetDirectlyPayload) {
        self.swap_nodes_inner(payload, dfn_core::api::caller(), now_system_time())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Top level function for the swapping feature which has all inputs.
    fn swap_nodes_inner(
        &mut self,
        payload: SwapNodeInSubnetDirectlyPayload,
        caller: PrincipalId,
        now: SystemTime,
    ) -> Result<(), SwapError> {
        // Check if the feature is enabled on the network.
        if !is_node_swapping_enabled() {
            return Err(SwapError::FeatureDisabled);
        }

        // Check if the payload is valid by itself.
        payload.validate()?;
        let (old_node_id, new_node_id) =
            (payload.old_node_id.unwrap(), payload.new_node_id.unwrap());

        //Check if the feature is allowed on the target subnet and for the caller
        Self::swapping_enabled_for_caller(caller)?;
        let subnet_id = self.find_subnet_for_old_node(old_node_id)?;
        Self::swapping_allowed_on_subnet(subnet_id)?;

        let reservation =
            SWAP_LIMITER.with_borrow_mut(|limiter| limiter.try_reserve(caller, subnet_id, now))?;

        self.validate_node_swap(old_node_id, new_node_id, caller, subnet_id)?;
        self.swap_nodes_in_subnet(subnet_id, old_node_id, new_node_id)?;

        SWAP_LIMITER.with_borrow_mut(|limiter| limiter.commit(reservation, now));
        Ok(())
    }

    /// Check if the caller is whitelisted to use this feature.
    fn swapping_enabled_for_caller(caller: PrincipalId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_for_caller(caller) {
            return Err(SwapError::FeatureDisabledForCaller { caller });
        }

        Ok(())
    }

    /// Map the `old_node_id` to a subnet and error if it is
    /// not a member of any subnet.
    fn find_subnet_for_old_node(&self, old_node_id: PrincipalId) -> Result<SubnetId, SwapError> {
        find_subnet_for_node(
            self,
            NodeId::new(old_node_id),
            &self.get_subnet_list_record(),
        )
        .ok_or(SwapError::SubnetNotFoundForNode { old_node_id })
    }

    fn swapping_allowed_on_subnet(subnet_id: SubnetId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_on_subnet(subnet_id) {
            return Err(SwapError::FeatureDisabledOnSubnet { subnet_id });
        }

        Ok(())
    }

    fn validate_node_swap(
        &self,
        old_node_id: PrincipalId,
        new_node_id: PrincipalId,
        caller: PrincipalId,
        subnet_id: SubnetId,
    ) -> Result<(), SwapError> {
        // Ensure that the nodes exist
        let old_node_id = NodeId::new(old_node_id);
        let new_node_id = NodeId::new(new_node_id);
        let old_node = self.get_node(old_node_id).ok_or(SwapError::UnknownNode {
            node_id: old_node_id.get(),
        })?;
        let new_node = self.get_node(new_node_id).ok_or(SwapError::UnknownNode {
            node_id: new_node_id.get(),
        })?;

        // Ensure that the old node is a member in a subnet
        // This is done before calling `validate_node_swap`

        // Ensure that the new node is not a member of any subnets
        let maybe_subnet_new_node =
            find_subnet_for_node(self, new_node_id, &self.get_subnet_list_record());

        if let Some(subnet_id) = maybe_subnet_new_node {
            return Err(SwapError::NewNodeAssigned {
                node_id: new_node_id.get(),
                subnet_id,
            });
        }

        // Ensure that both of the nodes are owned by the same node operator
        let old_node_operator = PrincipalId::try_from(old_node.node_operator_id).unwrap();
        let new_node_operator = PrincipalId::try_from(new_node.node_operator_id).unwrap();

        if old_node_operator != new_node_operator {
            return Err(SwapError::NodesOwnedByDifferentOperators);
        }

        // Ensure that the caller is the actual node operator of the nodes.
        // Since the before check passed we can check for either one of the
        // node operators, new or old.
        if new_node_operator != caller {
            return Err(SwapError::CallerNodeOperatorMismatch {
                caller,
                node_operator: new_node_operator,
            });
        }

        // Disalbe swapping of nodes during recovery, when the subnet
        // is halted.
        let subnet_record = self.get_subnet_or_panic(subnet_id);
        if subnet_record.is_halted {
            return Err(SwapError::SubnetHalted { subnet_id });
        }

        Ok(())
    }

    fn swap_nodes_in_subnet(
        &mut self,
        subnet_id: SubnetId,
        old_node_id: PrincipalId,
        new_node_id: PrincipalId,
    ) -> Result<(), SwapError> {
        let mut subnet = self.get_subnet_or_panic(subnet_id);
        let subnet_size_before = subnet.membership.len();
        subnet.membership.retain(|node| {
            let node_id = PrincipalId::try_from(node).unwrap();

            node_id != old_node_id
        });
        subnet.membership.push(new_node_id.to_vec());
        let subnet_size_after = subnet.membership.len();

        // Ensure subnet size stays consistent
        if subnet_size_before != subnet_size_after {
            return Err(SwapError::SubnetSizeMismatch { subnet_id });
        }

        let subnet_mutations = vec![upsert(
            make_subnet_record_key(subnet_id).as_bytes(),
            subnet.encode_to_vec(),
        )];

        self.maybe_apply_mutation_internal(subnet_mutations);

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct SwapNodeInSubnetDirectlyPayload {
    /// Represents the principal of a node that will be added to a subnet
    /// in place of the `old_node_id`.
    #[prost(message, optional, tag = "1")]
    pub new_node_id: Option<PrincipalId>,

    /// Represents the principal of an assigned node that will be removed
    /// from a subnet.
    #[prost(message, optional, tag = "2")]
    pub old_node_id: Option<PrincipalId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwapError {
    FeatureDisabled,
    MissingInput,
    SamePrincipals,
    FeatureDisabledForCaller {
        caller: PrincipalId,
    },
    FeatureDisabledOnSubnet {
        subnet_id: SubnetId,
    },
    SubnetNotFoundForNode {
        old_node_id: PrincipalId,
    },
    SubnetRateLimited {
        subnet_id: SubnetId,
    },
    OperatorRateLimitedOnSubnet {
        subnet_id: SubnetId,
        caller: PrincipalId,
    },
    SubnetSizeMismatch {
        subnet_id: SubnetId,
    },
    NodesOwnedByDifferentOperators,
    UnknownNode {
        node_id: PrincipalId,
    },
    NewNodeAssigned {
        node_id: PrincipalId,
        subnet_id: SubnetId,
    },
    CallerNodeOperatorMismatch {
        caller: PrincipalId,
        node_operator: PrincipalId,
    },
    SubnetHalted {
        subnet_id: SubnetId,
    },
}

impl Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SwapError::FeatureDisabled =>
                    "Swapping feature is disabled on the network.".to_string(),
                SwapError::MissingInput => "The provided payload has missing data".to_string(),
                SwapError::SamePrincipals =>
                    "`new_node_id` and `old_node_id` must differ".to_string(),
                SwapError::FeatureDisabledForCaller { caller } =>
                    format!("Caller `{caller}` isn't whitelisted to use swapping feature yet."),
                SwapError::FeatureDisabledOnSubnet { subnet_id } =>
                    format!("Swapping is disabled on subnet `{subnet_id}`."),
                SwapError::SubnetNotFoundForNode { old_node_id } =>
                    format!("Node {old_node_id} is not a member of any subnet."),
                SwapError::SubnetRateLimited { subnet_id } => format!(
                    "Subnet {subnet_id} had a swap performed within last two hours. Try again later."
                ),
                SwapError::OperatorRateLimitedOnSubnet { subnet_id, caller } => format!(
                    "Caller {caller} performed a swap on subnet {subnet_id} within last twelve hours. Try again later."
                ),
                SwapError::SubnetSizeMismatch { subnet_id } => format!(
                    "Subnet {subnet_id} changed size after performing the swap which shouldn't happen"
                ),
                SwapError::NodesOwnedByDifferentOperators =>
                    "Both nodes must be owned by the same node operator".to_string(),
                SwapError::UnknownNode { node_id } => format!("Node {node_id} doesn't exist"),
                SwapError::NewNodeAssigned { node_id, subnet_id } => format!(
                    "New node {node_id} is a member of subnet {subnet_id} and cannot be used for direct swapping"
                ),
                SwapError::CallerNodeOperatorMismatch {
                    caller,
                    node_operator,
                } => format!(
                    "Caller {caller} isn't an operator of the specified nodes. Expected operator {node_operator}"
                ),
                SwapError::SubnetHalted { subnet_id } => format!(
                    "Subnet {subnet_id} is halted and swapping is disabled. This is likely due to an on going recovery on that subnet"
                ),
            }
        )
    }
}

impl SwapNodeInSubnetDirectlyPayload {
    fn validate(&self) -> Result<(), SwapError> {
        let (old_node_id, new_node_id) = match (&self.old_node_id, &self.new_node_id) {
            (Some(old_node_id), Some(new_node_id)) => (old_node_id, new_node_id),
            _ => return Err(SwapError::MissingInput),
        };

        if old_node_id == new_node_id {
            return Err(SwapError::SamePrincipals);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::BTreeMap, time::Duration};

    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_nervous_system_time_helpers::now_system_time;
    use ic_protobuf::registry::node::v1::ConnectionEndpoint;
    use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetListRecord};
    use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
    use ic_types::{NodeId, PrincipalId, SubnetId};
    use itertools::Itertools;

    use crate::{
        common::test_helpers::{
            get_invariant_compliant_subnet_record, invariant_compliant_registry,
        },
        flags::{
            temporarily_disable_node_swapping, temporarily_enable_node_swapping,
            temporary_overrides::{
                test_set_swapping_enabled_subnets, test_set_swapping_whitelisted_callers,
            },
        },
        mutations::{
            do_swap_node_in_subnet_directly::{
                NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL, NODE_SWAPS_SUBNET_CAPACITY_INTERVAL,
                SwapError, SwapNodeInSubnetDirectlyPayload, SwapRateLimiter,
            },
            node_management::common::make_add_node_registry_mutations,
        },
        registry::Registry,
    };
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_nns_test_utils::registry::create_subnet_threshold_signing_pubkey_and_cup_mutations;
    use ic_protobuf::registry::subnet::v1::SubnetType;
    use prost::Message;

    fn invalid_payloads_with_expected_errors() -> Vec<(SwapNodeInSubnetDirectlyPayload, SwapError)>
    {
        vec![
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: None,
                    old_node_id: None,
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: Some(PrincipalId::new_node_test_id(1)),
                    old_node_id: None,
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: None,
                    old_node_id: Some(PrincipalId::new_user_test_id(2)),
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: Some(PrincipalId::new_node_test_id(1)),
                    old_node_id: Some(PrincipalId::new_node_test_id(1)),
                },
                SwapError::SamePrincipals,
            ),
        ]
    }

    fn valid_payload() -> SwapNodeInSubnetDirectlyPayload {
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        }
    }

    #[test]
    fn feature_flag_check_works() {
        let mut registry = Registry::new();

        let _temp = temporarily_disable_node_swapping();

        let payload = valid_payload();

        assert!(
            registry
                .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1), now_system_time())
                .is_err_and(|err| err == SwapError::FeatureDisabled)
        )
    }

    #[test]
    fn valid_payload_test() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        let payload = valid_payload();

        let result =
            registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1), now_system_time());

        // First error that occurs after validation
        assert!(result.is_err_and(|err| err
            == SwapError::FeatureDisabledForCaller {
                caller: PrincipalId::new_user_test_id(1)
            }));
    }

    #[test]
    fn invalid_payloads() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        for (payload, expected_err) in invalid_payloads_with_expected_errors() {
            let output = registry.swap_nodes_inner(
                payload,
                PrincipalId::new_user_test_id(1),
                now_system_time(),
            );

            let expected: Result<(), SwapError> = Err(expected_err);
            assert_eq!(
                output, expected,
                "Expected: {expected:?} but found result: {output:?}"
            );
        }
    }

    struct NodeInformation {
        node_id: NodeId,
        subnet_id: Option<SubnetId>,
        node_operator: PrincipalId,
        valid_pks: ValidNodePublicKeys,
    }

    fn get_mutations_from_node_information(
        node_information: &[NodeInformation],
        halt_subnets: bool,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];

        let mut subnets = BTreeMap::new();

        for (index, node) in node_information.iter().enumerate() {
            if let Some(subnet) = node.subnet_id {
                subnets
                    .entry(subnet)
                    .or_insert(vec![])
                    .push(node.valid_pks.clone());
            }

            // Some endpoints may come from `invariant_compliant_registry`
            let index = 200 - index;
            let ip_addr = format!("128.0.{index}.1");
            let xnet_connection_endpoint = ConnectionEndpoint {
                ip_addr: ip_addr.clone(),
                port: 1234,
            };
            let http_connection_endpoint = ConnectionEndpoint {
                ip_addr,
                port: 4321,
            };

            let node_mutations = make_add_node_registry_mutations(
                node.node_id,
                NodeRecord {
                    node_operator_id: node.node_operator.to_vec(),
                    xnet: Some(xnet_connection_endpoint),
                    http: Some(http_connection_endpoint),
                    ..Default::default()
                },
                node.valid_pks.clone(),
            );
            mutations.extend(node_mutations);
        }

        for (subnet, nodes) in &subnets {
            let node_ids: Vec<_> = nodes.iter().map(|n| n.node_id()).collect();
            let mut subnet_record = get_invariant_compliant_subnet_record(node_ids.clone());
            subnet_record.subnet_type = i32::from(SubnetType::System);
            subnet_record.is_halted = halt_subnets;

            mutations.push(upsert(
                make_subnet_record_key(*subnet),
                subnet_record.encode_to_vec(),
            ));

            let relevant_nodes = nodes
                .iter()
                .map(|n| (n.node_id(), n.dkg_dealing_encryption_key().clone()))
                .collect();
            let threshold_and_cup_mutations =
                create_subnet_threshold_signing_pubkey_and_cup_mutations(*subnet, &relevant_nodes);

            mutations.extend(threshold_and_cup_mutations);
        }

        mutations.push(upsert(
            make_subnet_list_record_key(),
            SubnetListRecord {
                subnets: subnets.keys().map(|k| k.get().to_vec()).collect(),
            }
            .encode_to_vec(),
        ));

        mutations
    }

    fn get_new_node_and_keys() -> (NodeId, ValidNodePublicKeys) {
        let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
        let keys = generate_node_keys_once(&config, None).unwrap();

        (keys.node_id(), keys)
    }

    fn setup_registry_for_test(
        halt_subnets: bool,
    ) -> (NodeId, NodeId, SubnetId, PrincipalId, Registry) {
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let (old_node_id, old_node_keys) = get_new_node_and_keys();
        let (new_node_id, new_node_keys) = get_new_node_and_keys();
        let node_operator_id = PrincipalId::new_user_test_id(1);

        let mutations = get_mutations_from_node_information(
            &[
                NodeInformation {
                    node_id: old_node_id,
                    subnet_id: Some(subnet_id),
                    node_operator: node_operator_id,
                    valid_pks: old_node_keys,
                },
                NodeInformation {
                    node_id: new_node_id,
                    subnet_id: None,
                    node_operator: node_operator_id,
                    valid_pks: new_node_keys,
                },
            ],
            halt_subnets,
        );
        registry.apply_mutations_for_test(mutations);

        (
            old_node_id,
            new_node_id,
            subnet_id,
            node_operator_id,
            registry,
        )
    }

    #[test]
    fn feature_enabled_for_caller() {
        let _temp_enable_feat = temporarily_enable_node_swapping();

        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(false);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let payload = SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(new_node_id.get()),
            old_node_id: Some(old_node_id.get()),
        };

        // First make a call and expect to fail because
        // the feature is not enabled for this caller.
        let response =
            registry.swap_nodes_inner(payload.clone(), node_operator_id, now_system_time());
        let expected_err = SwapError::FeatureDisabledForCaller {
            caller: node_operator_id,
        };
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected error {expected_err:?} but got {response:?}"
        );

        // Enable the feature for the caller
        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        // Expect the first next error which is the missing
        // subnet in the registry.
        assert!(response.is_ok(), "Expected OK but got {response:?}");
    }

    #[test]
    fn feature_enabled_for_subnet() {
        let _temp_enable_feat = temporarily_enable_node_swapping();

        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(false);

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        let response =
            registry.swap_nodes_inner(payload.clone(), node_operator_id, now_system_time());
        let expected_err = SwapError::FeatureDisabledOnSubnet { subnet_id };

        // First call when the feature isn't enabled on the subnet.
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected to get error {expected_err:?} but got {response:?}"
        );

        // Now enable the feature and call again.
        test_set_swapping_enabled_subnets(vec![subnet_id]);
        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        assert!(
            response.is_ok(),
            "Expected the result to be OK but got {response:?}"
        );
    }

    #[test]
    fn rate_limit_test() {
        let mut swap_limiter = SwapRateLimiter::new();
        let now = now_system_time();
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let caller_1 = PrincipalId::new_user_test_id(1);
        let caller_2 = PrincipalId::new_user_test_id(2);

        // First call should be successful
        let reservation = swap_limiter.try_reserve(caller_1, subnet_id, now).unwrap();
        swap_limiter.commit(reservation, now);

        let before_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_SUBNET_CAPACITY_INTERVAL.saturating_sub(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        let expected_err = SwapError::SubnetRateLimited { subnet_id };

        // Second call from the same node operator should fail because of subnet rate limit
        let response = swap_limiter
            .try_reserve(caller_1, subnet_id, before_duration_elapsed)
            .expect_err("Should error out");
        assert_eq!(response, expected_err);

        // Call from a different node operator should fail as well
        let response = swap_limiter
            .try_reserve(caller_2, subnet_id, before_duration_elapsed)
            .expect_err("Should error out");
        assert_eq!(response, expected_err);

        // After SUBNET_CAPACITY_INTERVAL the second caller should be able to make reservation but
        // first shouldn't
        let after_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_SUBNET_CAPACITY_INTERVAL.saturating_add(Duration::from_secs(5 * 60)),
            )
            .unwrap();

        let reservation = swap_limiter
            .try_reserve(caller_2, subnet_id, after_duration_elapsed)
            .unwrap();
        drop(reservation);

        let expected_err = SwapError::OperatorRateLimitedOnSubnet {
            subnet_id,
            caller: caller_1,
        };
        let response = swap_limiter
            .try_reserve(caller_1, subnet_id, after_duration_elapsed)
            .expect_err("Should error out");
        assert_eq!(response, expected_err);

        // After NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL the first node operator
        // should be able to perform a swap
        let after_node_operator_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL
                    .saturating_add(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        let response =
            swap_limiter.try_reserve(caller_1, subnet_id, after_node_operator_duration_elapsed);
        assert!(response.is_ok());
    }

    #[test]
    fn rate_limit_different_subnets() {
        let mut swap_limiter = SwapRateLimiter::new();
        let now = now_system_time();
        let subnet_1 = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let subnet_2 = SubnetId::new(PrincipalId::new_subnet_test_id(2));

        let caller = PrincipalId::new_user_test_id(1);

        for subnet in [subnet_1, subnet_2] {
            let reservation = swap_limiter.try_reserve(caller, subnet, now).unwrap();
            swap_limiter.commit(reservation, now);
        }

        let before_subnet_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_SUBNET_CAPACITY_INTERVAL.saturating_sub(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        for subnet in [subnet_1, subnet_2] {
            let response = swap_limiter
                .try_reserve(caller, subnet, before_subnet_duration_elapsed)
                .expect_err("Should error out");
            let expected_err = SwapError::SubnetRateLimited { subnet_id: subnet };

            assert_eq!(response, expected_err);
        }
    }

    #[test]
    fn rate_limits_e2e_respected() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(false);

        let now = now_system_time();
        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry.swap_nodes_inner(payload.clone(), node_operator_id, now);
        assert!(
            response.is_ok(),
            "Expected OK response but got: {response:?}"
        );

        // Swap nodes again in payload because the swap was performed
        let (old_node_id, new_node_id) = (new_node_id, old_node_id);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        // Make an additional call which should fail because of the subnet limit
        let before_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_SUBNET_CAPACITY_INTERVAL.saturating_sub(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        let response = registry
            .swap_nodes_inner(payload.clone(), node_operator_id, before_duration_elapsed)
            .expect_err("Should error out");

        let expected_err = SwapError::SubnetRateLimited { subnet_id };
        assert_eq!(response, expected_err);

        // Make an additional call which should fail because of the node operator limit
        let after_subnet_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_SUBNET_CAPACITY_INTERVAL.saturating_add(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        let response = registry
            .swap_nodes_inner(
                payload.clone(),
                node_operator_id,
                after_subnet_duration_elapsed,
            )
            .expect_err("Should error out");

        let expected_err = SwapError::OperatorRateLimitedOnSubnet {
            subnet_id,
            caller: node_operator_id,
        };
        assert_eq!(response, expected_err);

        // Make an additional call after all the rate limits have elapsed
        let after_node_operator_duration_elapsed = now
            .checked_add(
                NODE_SWAPS_NODE_OPERATOR_CAPACITY_INTERVAL
                    .saturating_add(Duration::from_secs(5 * 60)),
            )
            .unwrap();
        let response = registry.swap_nodes_inner(
            payload,
            node_operator_id,
            after_node_operator_duration_elapsed,
        );

        assert!(response.is_ok());

        let subnet_record = registry.get_subnet_or_panic(subnet_id);

        let members = subnet_record
            .membership
            .iter()
            .map(|n| NodeId::new(PrincipalId::try_from(n).unwrap()))
            .collect_vec();

        // Here at the end the old node should be back in because of double swap
        let (old_node_id, new_node_id) = (new_node_id, old_node_id);

        assert!(members.contains(&old_node_id));
        assert!(!members.contains(&new_node_id));
    }

    #[test]
    fn nodes_owned_by_different_node_operators() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let (old_node_id, old_node_keys) = get_new_node_and_keys();
        let (new_node_id, new_node_keys) = get_new_node_and_keys();
        let node_operator_id_1 = PrincipalId::new_user_test_id(1);
        let node_operator_id_2 = PrincipalId::new_user_test_id(2);

        let mutations = get_mutations_from_node_information(
            &[
                NodeInformation {
                    node_id: old_node_id,
                    subnet_id: Some(subnet_id),
                    node_operator: node_operator_id_1,
                    valid_pks: old_node_keys,
                },
                NodeInformation {
                    node_id: new_node_id,
                    subnet_id: None,
                    node_operator: node_operator_id_2,
                    valid_pks: new_node_keys,
                },
            ],
            false,
        );
        registry.apply_mutations_for_test(mutations);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id_1, node_operator_id_2]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry
            .swap_nodes_inner(payload, node_operator_id_1, now_system_time())
            .expect_err("Should error out");

        let expected_err = SwapError::NodesOwnedByDifferentOperators;
        assert_eq!(
            response, expected_err,
            "Expected error {expected_err:?} but got error: {response:?}"
        );
    }

    #[test]
    fn nodes_not_owned_by_the_caller() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(false);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        let different_caller = PrincipalId::new_user_test_id(2);

        test_set_swapping_whitelisted_callers(vec![node_operator_id, different_caller]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry
            .swap_nodes_inner(payload, different_caller, now_system_time())
            .expect_err("Should error out");

        let expected_err = SwapError::CallerNodeOperatorMismatch {
            caller: different_caller,
            node_operator: node_operator_id,
        };
        assert_eq!(
            response, expected_err,
            "Expected error {expected_err:?} but got error: {response:?}"
        );
    }

    #[test]
    fn new_node_in_subnet() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let mut registry = invariant_compliant_registry(0);

        let subnet_id_1 = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let subnet_id_2 = SubnetId::new(PrincipalId::new_subnet_test_id(2));
        let (old_node_id, old_node_keys) = get_new_node_and_keys();
        let (new_node_id, new_node_keys) = get_new_node_and_keys();
        let node_operator_id_1 = PrincipalId::new_user_test_id(1);
        let node_operator_id_2 = PrincipalId::new_user_test_id(2);

        let mutations = get_mutations_from_node_information(
            &[
                NodeInformation {
                    node_id: old_node_id,
                    subnet_id: Some(subnet_id_1),
                    node_operator: node_operator_id_1,
                    valid_pks: old_node_keys,
                },
                NodeInformation {
                    node_id: new_node_id,
                    subnet_id: Some(subnet_id_2),
                    node_operator: node_operator_id_2,
                    valid_pks: new_node_keys,
                },
            ],
            false,
        );
        registry.apply_mutations_for_test(mutations);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id_1, node_operator_id_2]);
        test_set_swapping_enabled_subnets(vec![subnet_id_1]);

        let response = registry
            .swap_nodes_inner(payload, node_operator_id_1, now_system_time())
            .expect_err("Should error out");

        let expected_err = SwapError::NewNodeAssigned {
            node_id: new_node_id.get(),
            subnet_id: subnet_id_2,
        };
        assert_eq!(
            response, expected_err,
            "Expected error {expected_err:?} but got error: {response:?}"
        );
    }

    #[test]
    fn subnet_halted() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(true);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry
            .swap_nodes_inner(payload, node_operator_id, now_system_time())
            .expect_err("Should error out");
        let expected_err = SwapError::SubnetHalted { subnet_id };
        assert_eq!(
            response, expected_err,
            "Expected err {expected_err:?} but got: {response:?}"
        );
    }

    #[test]
    fn e2e_valid_swap() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (old_node_id, new_node_id, subnet_id, node_operator_id, mut registry) =
            setup_registry_for_test(false);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        assert!(
            response.is_ok(),
            "Expected OK response but got: {response:?}"
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);

        let members = subnet_record
            .membership
            .iter()
            .map(|n| NodeId::new(PrincipalId::try_from(n).unwrap()))
            .collect_vec();

        assert!(members.contains(&new_node_id));
        assert!(!members.contains(&old_node_id));
    }
}
