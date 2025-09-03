use std::fmt::Display;

use candid::CandidType;
use ic_types::{PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    flags::{
        is_node_swapping_enabled, is_node_swapping_enabled_for_caller,
        is_node_swapping_enabled_on_subnet,
    },
    registry::Registry,
};

impl Registry {
    /// Called by the node operators in order to rotate their nodes without the need for governance.
    pub fn do_swap_node_in_subnet_directly(&mut self, payload: SwapNodeInSubnetDirectlyPayload) {
        self.swap_nodes_inner(payload, dfn_core::api::caller())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Top level function for the swapping feature which has all inputs.
    fn swap_nodes_inner(
        &mut self,
        payload: SwapNodeInSubnetDirectlyPayload,
        caller: PrincipalId,
    ) -> Result<(), SwapError> {
        // Check if the feature is enabled on the network.
        if !is_node_swapping_enabled() {
            return Err(SwapError::FeatureDisabled);
        }

        // Check if the payload is valid by itself.
        payload.validate()?;
        let (old_node_id, _new_node_id) =
            (payload.old_node_id.unwrap(), payload.new_node_id.unwrap());

        // Check if the feature is allowed on the target subnet and for the caller
        Self::swapping_allowed_for_caller(caller)?;
        let subnet_id = self.find_subnet_for_node(old_node_id)?;
        Self::swapping_allowed_on_subnet(subnet_id)?;

        //TODO(DRE-553): Rate-limiting mechanism

        //TODO(DRE-548): Implement the swapping functionality
        Ok(())
    }

    /// Check if the caller is whitelisted to use this feature.
    fn swapping_allowed_for_caller(caller: PrincipalId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_for_caller(caller) {
            return Err(SwapError::FeatureDisabledForCaller { caller });
        }

        Ok(())
    }

    /// Map the `old_node_id` to a subnet and error if it is
    /// not a member of any subnet.
    fn find_subnet_for_node(&self, old_node_id: PrincipalId) -> Result<SubnetId, SwapError> {
        for (subnet, id) in self
            .get_subnet_list_record()
            .subnets
            .into_iter()
            // This unwrap should never happen if the registry is invariant compliant.
            .map(|bytes| SubnetId::new(PrincipalId::try_from(bytes).unwrap()))
            // This unwrap should never happen if the registry is invariant compliant.
            .map(|subnet_id| (self.get_subnet_or_panic(subnet_id), subnet_id))
        {
            if !subnet
                .membership
                .iter()
                .map(|bytes| PrincipalId::try_from(bytes).unwrap())
                .any(|node| node == old_node_id)
            {
                // Node is not a member of this subnet so skip it.
                continue;
            }

            return Ok(id);
        }

        Err(SwapError::SubnetNotFoundForNode { old_node_id })
    }

    fn swapping_allowed_on_subnet(subnet_id: SubnetId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_on_subnet(subnet_id) {
            return Err(SwapError::FeatureDisabledOnSubnet { subnet_id });
        }

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
    FeatureDisabledForCaller { caller: PrincipalId },
    FeatureDisabledOnSubnet { subnet_id: SubnetId },
    SubnetNotFoundForNode { old_node_id: PrincipalId },
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

    use std::collections::BTreeMap;

    use ic_nns_test_utils::registry::create_subnet_threshold_signing_pubkey_and_cup_mutations;
    use ic_protobuf::registry::{
        dc::v1::DataCenterRecord,
        node_operator::v1::NodeOperatorRecord,
        subnet::v1::{SubnetListRecord, SubnetType},
    };
    use ic_registry_keys::{
        make_data_center_record_key, make_node_operator_record_key, make_subnet_list_record_key,
        make_subnet_record_key,
    };
    use ic_registry_transport::upsert;
    use ic_types::{NodeId, PrincipalId, SubnetId};
    use prost::Message;

    use crate::{
        common::test_helpers::{
            get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes_and_node_operator_id,
        },
        flags::{
            enable_swapping_for_callers, enable_swapping_on_subnets,
            temporarily_disable_node_swapping, temporarily_enable_node_swapping,
        },
        mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
        registry::Registry,
    };

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

    fn operator(id: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(id)
    }

    fn provider(id: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(9999 - id)
    }

    fn subnet(id: u64) -> SubnetId {
        SubnetId::new(PrincipalId::new_subnet_test_id(id))
    }

    /// Generate
    fn scenario_compliant_registry(
        providers: &[(PrincipalId, &[(PrincipalId, &str, Option<SubnetId>, u64)])],
    ) -> (
        Registry,
        BTreeMap<
            PrincipalId,
            BTreeMap<String, BTreeMap<PrincipalId, Vec<(NodeId, Option<SubnetId>)>>>,
        >,
    ) {
        let mut registry = invariant_compliant_registry(1);
        let mut mutations = vec![];
        let mut mutation_id = 2;
        let mut subnets = BTreeMap::new();
        let mut network_data = BTreeMap::new();

        for (provider, provider_layout) in providers {
            for (operator, dc_id, maybe_subnet, num_nodes) in *provider_layout {
                let (request, nodes) = prepare_registry_with_nodes_and_node_operator_id(
                    mutation_id,
                    *num_nodes,
                    *operator,
                );
                mutation_id += 1;

                mutations.extend(request.mutations);

                mutations.push(upsert(
                    make_data_center_record_key(dc_id),
                    DataCenterRecord {
                        id: dc_id.to_string(),
                        region: "region".to_string(),
                        owner: "owner".to_string(),
                        gps: Some(ic_protobuf::registry::dc::v1::Gps {
                            latitude: 0.0,
                            longitude: 0.0,
                        }),
                    }
                    .encode_to_vec(),
                ));

                mutations.push(upsert(
                    make_node_operator_record_key(*operator),
                    NodeOperatorRecord {
                        node_operator_principal_id: operator.to_vec(),
                        node_allowance: 10,
                        node_provider_principal_id: provider.to_vec(),
                        dc_id: dc_id.to_string(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ));

                network_data
                    .entry(*provider)
                    .or_insert(BTreeMap::new())
                    .entry(dc_id.to_string())
                    .or_insert(BTreeMap::new())
                    .entry(*operator)
                    .or_insert(vec![])
                    .extend(nodes.keys().map(|n| (*n, maybe_subnet.clone())));

                if let Some(subnet) = maybe_subnet {
                    subnets
                        .entry(subnet)
                        .or_insert(BTreeMap::new())
                        .extend(nodes);
                }
            }
        }

        for (subnet, nodes) in &subnets {
            let mut subnet_record =
                get_invariant_compliant_subnet_record(nodes.keys().cloned().collect());
            // For simplicity mark every subnet as system subnet
            subnet_record.subnet_type = SubnetType::System.into();

            mutations.push(upsert(
                make_subnet_record_key(**subnet),
                subnet_record.encode_to_vec(),
            ));

            let threshold_pk_and_cup =
                create_subnet_threshold_signing_pubkey_and_cup_mutations(**subnet, nodes);

            mutations.extend(threshold_pk_and_cup);
        }

        mutations.push(upsert(
            make_subnet_list_record_key(),
            SubnetListRecord {
                subnets: subnets.keys().map(|k| k.get().to_vec()).collect(),
            }
            .encode_to_vec(),
        ));

        // Sort and dedup by key if we have duplicated dcs or nos
        mutations.sort_by_key(|m| m.key.clone());
        mutations.dedup_by_key(|m| m.key.clone());

        registry.maybe_apply_mutation_internal(mutations);
        (registry, network_data)
    }

    #[test]
    fn feature_flag_check_works() {
        let mut registry = Registry::new();

        let _temp = temporarily_disable_node_swapping();

        let payload = valid_payload();

        assert!(registry
            .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1))
            .is_err_and(|err| err == SwapError::FeatureDisabled))
    }

    #[test]
    fn valid_payload_test() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        let payload = valid_payload();

        let result = registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1));

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
            let output = registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1));

            let expected: Result<(), SwapError> = Err(expected_err);
            assert_eq!(
                output, expected,
                "Expected: {expected:?} but found result: {output:?}"
            );
        }
    }

    #[test]
    fn feature_enabled_for_caller() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let caller = PrincipalId::new_user_test_id(1);
        let mut registry = invariant_compliant_registry(1);
        let payload = valid_payload();

        // First make a call and expect to fail because
        // the feature is not enabled for this caller.
        assert!(registry
            .swap_nodes_inner(payload.clone(), caller)
            .is_err_and(|err| err
                == SwapError::FeatureDisabledForCaller {
                    caller: caller.clone()
                }));

        // Enable the feature for the caller
        enable_swapping_for_callers(vec![caller.clone()]);

        // Expect the first next error which is the missing
        // subnet in the registry.
        assert!(registry
            .swap_nodes_inner(payload.clone(), caller)
            .is_err_and(|err| err
                == SwapError::SubnetNotFoundForNode {
                    old_node_id: payload.old_node_id.unwrap()
                }))
    }

    #[test]
    fn feature_enabled_for_subnet() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let caller = PrincipalId::new_user_test_id(1);
        enable_swapping_for_callers(vec![caller.clone()]);
        let mut registry = invariant_compliant_registry(1);

        let payload = valid_payload();

        let subnet_record =
            get_invariant_compliant_subnet_record(vec![NodeId::new(payload.old_node_id.unwrap())]);
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));

        registry.apply_mutations_for_test(vec![
            upsert(
                make_subnet_record_key(subnet_id),
                subnet_record.encode_to_vec(),
            ),
            upsert(
                make_subnet_list_record_key(),
                SubnetListRecord {
                    subnets: vec![subnet_id.get().to_vec()],
                }
                .encode_to_vec(),
            ),
        ]);

        // First call when the feature isn't enabled on the subnet.
        assert!(registry
            .swap_nodes_inner(payload.clone(), caller.clone())
            .is_err_and(|err| err
                == SwapError::FeatureDisabledOnSubnet {
                    subnet_id: subnet_id.clone()
                }));

        // Now enable the feature and call again.
        enable_swapping_on_subnets(vec![subnet_id.clone()]);
        assert!(registry.swap_nodes_inner(payload, caller).is_ok());
    }

    #[test]
    fn e2e_valid_swap() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        enable_swapping_for_callers(vec![operator(1)]);
        enable_swapping_on_subnets(vec![subnet(1)]);

        let (mut registry, network_data) = scenario_compliant_registry(&[(
            provider(1),
            &[
                (operator(1), "dc", None, 1),
                (operator(1), "dc", Some(subnet(1)), 1),
            ],
        )]);

        let nodes = &network_data[&provider(1)]["dc"][&operator(1)];
        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: nodes
                .iter()
                .find_map(|(id, subnet)| subnet.map(|_| id.get())),
            new_node_id: nodes
                .iter()
                .find_map(|(id, subnet)| subnet.is_none().then(|| id.get())),
        };

        let response = registry.swap_nodes_inner(payload, operator(1));
        assert!(
            response.is_ok(),
            "Expected OK response but got: {response:?}"
        );

        //TODO(DRE-548): Add assertions that the swap has been made
    }
}
