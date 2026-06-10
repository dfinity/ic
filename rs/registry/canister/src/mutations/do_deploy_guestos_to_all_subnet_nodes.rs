use crate::{
    common::LOG_PREFIX, mutations::common::check_replica_version_is_elected, registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_constants::ENGINE_CONTROLLER_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType as SubnetTypePb};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue, registry_mutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    pub fn do_deploy_guestos_to_all_subnet_nodes(
        &mut self,
        caller: PrincipalId,
        payload: DeployGuestosToAllSubnetNodesPayload,
    ) {
        println!(
            "{LOG_PREFIX}do_deploy_guestos_to_all_subnet_nodes: caller={caller}, payload={payload:?}"
        );

        let subnet_id = SubnetId::from(payload.subnet_id);

        // The engine controller canister is only allowed to mutate CloudEngine
        // subnets. Other authorized callers (governance) can update any subnet.
        if caller == ENGINE_CONTROLLER_CANISTER_ID.get() {
            let subnet_record = self.get_subnet_or_panic(subnet_id);
            assert_eq!(
                subnet_record.subnet_type,
                i32::from(SubnetTypePb::CloudEngine),
                "{LOG_PREFIX}do_deploy_guestos_to_all_subnet_nodes: engine controller may only \
                 update CloudEngine subnets; subnet {subnet_id} has subnet_type {:?}",
                subnet_record.subnet_type,
            );
        }

        check_replica_version_is_elected(self, &payload.replica_version_id);

        // Get the subnet record
        let subnet_key = make_subnet_record_key(subnet_id);
        let mutation = match self.get(subnet_key.as_bytes(), self.latest_version()) {
            Some(RegistryValue {
                value: subnet_record_vec,
                version: _,
                deletion_marker: _,
                timestamp_nanoseconds: _,
            }) => {
                let mut subnet_record = SubnetRecord::decode(subnet_record_vec.as_slice()).unwrap();
                subnet_record.replica_version_id = payload.replica_version_id;
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Update as i32,
                    key: subnet_key.as_bytes().to_vec(),
                    value: subnet_record.encode_to_vec(),
                }
            }
            None => panic!("Error while fetching the subnet record"),
        };

        let mutations = vec![mutation];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes, prepare_registry_with_nodes_and_reward_type,
    };
    use ic_nns_constants::{ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID};
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use ic_protobuf::registry::subnet::v1::{
        CanisterCyclesCostSchedule, SubnetType as SubnetTypePb,
    };
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::ReplicaVersion;
    use maplit::btreemap;

    /// Creates a registry with a single subnet of the given `subnet_type`.
    fn make_registry_with_subnet(subnet_type: SubnetType) -> (Registry, SubnetId) {
        let mut registry = invariant_compliant_registry(0);
        // CloudEngine subnets require nodes with reward type 4.
        let (mutate_request, node_ids_and_dkg_pks) = if subnet_type == SubnetType::CloudEngine {
            prepare_registry_with_nodes_and_reward_type(1, 2, NodeRewardType::Type4)
        } else {
            prepare_registry_with_nodes(1, 2)
        };
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");

        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
        subnet_record.subnet_type = i32::from(SubnetTypePb::from(subnet_type));
        if subnet_type == SubnetType::CloudEngine {
            subnet_record.canister_cycles_cost_schedule = CanisterCyclesCostSchedule::Free as i32;
        }

        let subnet_id = subnet_test_id(3000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        (registry, subnet_id)
    }

    fn deploy_payload(subnet_id: SubnetId) -> DeployGuestosToAllSubnetNodesPayload {
        DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: ReplicaVersion::default().to_string(),
        }
    }

    #[test]
    fn engine_controller_can_deploy_to_cloud_engine_subnet() {
        let (mut registry, subnet_id) = make_registry_with_subnet(SubnetType::CloudEngine);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(
            subnet_record.replica_version_id,
            ReplicaVersion::default().to_string()
        );
    }

    #[test]
    #[should_panic(expected = "engine controller may only update CloudEngine subnets")]
    fn engine_controller_cannot_deploy_to_non_cloud_engine_subnet() {
        let (mut registry, subnet_id) = make_registry_with_subnet(SubnetType::Application);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );
    }

    #[test]
    fn governance_can_deploy_to_non_cloud_engine_subnet() {
        let (mut registry, subnet_id) = make_registry_with_subnet(SubnetType::Application);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            GOVERNANCE_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(
            subnet_record.replica_version_id,
            ReplicaVersion::default().to_string()
        );
    }
}

/// The argument of a command to update the replica version of a single subnet
/// to a specific version.
///
/// The replica will be mutated only if the given version is, indeed, elected.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeployGuestosToAllSubnetNodesPayload {
    /// The subnet to update.
    pub subnet_id: PrincipalId, // SubnetId See NNS-73
    /// The new Replica version to use.
    pub replica_version_id: String,
}
