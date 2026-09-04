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
                 deploy GuestOS to CloudEngine subnets; subnet {subnet_id} has subnet_type {:?}",
                subnet_record.subnet_type,
            );
        }

        self.validate_deploy_guestos_payload(&payload);

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

    fn validate_deploy_guestos_payload(&self, payload: &DeployGuestosToAllSubnetNodesPayload) {
        if payload.replica_version_id.is_empty() {
            let subnet_id = SubnetId::from(payload.subnet_id);
            self.check_engine_can_have_blank_replica_version_id(subnet_id);
        } else {
            check_replica_version_is_elected(self, &payload.replica_version_id);
        }
    }

    /// Panics unless `subnet_id` is allowed to have a blank
    /// `replica_version_id` — i.e. it is a Cloud Engine, and there is a
    /// StandardEngineReplicaVersionRecord to resolve the blank against.
    /// Without the latter, blanking would leave the subnet with no replica
    /// version at all (and trip the SubnetRecord invariant).
    fn check_engine_can_have_blank_replica_version_id(&self, subnet_id: SubnetId) {
        let subnet_record = self.get_subnet_or_panic(subnet_id);
        assert_eq!(
            subnet_record.subnet_type,
            i32::from(SubnetTypePb::CloudEngine),
            "{LOG_PREFIX}do_deploy_guestos_to_all_subnet_nodes: only CloudEngine subnets may \
             have a blank replica_version_id; subnet {subnet_id} has subnet_type {:?}",
            subnet_record.subnet_type,
        );

        assert!(
            self.get_standard_engine_replica_version_record().is_some(),
            "{LOG_PREFIX}do_deploy_guestos_to_all_subnet_nodes: cannot blank the \
             replica_version_id of subnet {subnet_id}, because Registry has no \
             StandardEngineReplicaVersionRecord to determine its replica version from.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, add_guest_launch_measurements_to_replica_version,
        get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_cloud_engine_subnet, prepare_registry_with_nodes,
    };
    use crate::flags::{
        temporarily_disable_blank_replica_version_id_for_cloud_engines,
        temporarily_enable_blank_replica_version_id_for_cloud_engines,
    };
    use ic_nns_constants::{ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID};
    use ic_protobuf::registry::{
        replica_version::v1::ReplicaVersionRecord,
        standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord,
        subnet::v1::SubnetType as SubnetTypePb,
    };
    use ic_registry_keys::{
        make_replica_version_key, make_standard_engine_replica_version_record_key,
    };
    use ic_registry_subnet_type::SubnetType;
    use ic_registry_transport::insert;
    use ic_test_utilities_types::ids::{subnet_test_id, test_replica_version};
    use maplit::btreemap;

    // StandardEngineReplicaVersionRecord.
    const OLD_REPLICA_VERSION_ID: &str = "55c61431287c71ca6c70aa9457ab6c0a6fb61dab";
    const NEW_REPLICA_VERSION_ID: &str = "5f13942e58297b970fdf5f4e33c0af8fc7faa267";

    /// Creates a registry with a single non-CloudEngine subnet of the given
    /// `subnet_type`. For CloudEngine subnets, use
    /// [`prepare_registry_with_cloud_engine_subnet`] directly.
    fn make_registry_with_non_cloud_engine_subnet(subnet_type: SubnetType) -> (Registry, SubnetId) {
        assert_ne!(
            subnet_type,
            SubnetType::CloudEngine,
            "use prepare_registry_with_cloud_engine_subnet for CloudEngine subnets",
        );
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");

        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
        subnet_record.subnet_type = i32::from(SubnetTypePb::from(subnet_type));

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
            replica_version_id: test_replica_version().to_string(),
        }
    }

    /// Creates a payload that makes the subnet (presumably, an engine)
    /// follow StandardEngineReplicaVersionRecord instead.
    fn new_blank_replica_version_id_payload(
        subnet_id: SubnetId,
    ) -> DeployGuestosToAllSubnetNodesPayload {
        DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: String::new(),
        }
    }

    /// Installs the record a blank `replica_version_id` resolves against. Its
    /// two version IDs must differ and both must be elected and have guest
    /// launch measurements, so both are elected (with measurements) here.
    fn add_standard_engine_replica_version_record(registry: &mut Registry) {
        registry.maybe_apply_mutation_internal(vec![
            insert(
                make_replica_version_key(OLD_REPLICA_VERSION_ID).as_bytes(),
                ReplicaVersionRecord::default().encode_to_vec(),
            ),
            insert(
                make_replica_version_key(NEW_REPLICA_VERSION_ID).as_bytes(),
                ReplicaVersionRecord::default().encode_to_vec(),
            ),
        ]);
        add_guest_launch_measurements_to_replica_version(registry, OLD_REPLICA_VERSION_ID);
        add_guest_launch_measurements_to_replica_version(registry, NEW_REPLICA_VERSION_ID);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_standard_engine_replica_version_record_key().as_bytes(),
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: NEW_REPLICA_VERSION_ID.to_string(),
                old_replica_version_id: OLD_REPLICA_VERSION_ID.to_string(),
                deployment_progress: 0.1,
            }
            .encode_to_vec(),
        )]);
    }

    /// A CloudEngine subnet pinned to the default replica version, with the
    /// standard engine record in place so the pin can be removed again.
    fn make_registry_with_blankable_cloud_engine_subnet() -> (Registry, SubnetId) {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, subnet_id) = prepare_registry_with_cloud_engine_subnet(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        add_standard_engine_replica_version_record(&mut registry);

        (registry, subnet_id)
    }

    #[test]
    fn engine_controller_can_deploy_to_cloud_engine_subnet() {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, subnet_id) = prepare_registry_with_cloud_engine_subnet(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(
            subnet_record.replica_version_id,
            test_replica_version().to_string()
        );
    }

    #[test]
    #[should_panic(expected = "engine controller may only deploy GuestOS to CloudEngine subnets")]
    fn engine_controller_cannot_deploy_to_non_cloud_engine_subnet() {
        let (mut registry, subnet_id) =
            make_registry_with_non_cloud_engine_subnet(SubnetType::Application);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );
    }

    #[test]
    fn governance_can_deploy_to_non_cloud_engine_subnet() {
        let (mut registry, subnet_id) =
            make_registry_with_non_cloud_engine_subnet(SubnetType::Application);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            GOVERNANCE_CANISTER_ID.get(),
            deploy_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(
            subnet_record.replica_version_id,
            test_replica_version().to_string()
        );
    }

    #[test]
    fn engine_controller_can_blank_cloud_engine_replica_version() {
        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let (mut registry, subnet_id) = make_registry_with_blankable_cloud_engine_subnet();

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            new_blank_replica_version_id_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(subnet_record.replica_version_id, "");
    }

    #[test]
    fn governance_can_blank_cloud_engine_replica_version() {
        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let (mut registry, subnet_id) = make_registry_with_blankable_cloud_engine_subnet();

        registry.do_deploy_guestos_to_all_subnet_nodes(
            GOVERNANCE_CANISTER_ID.get(),
            new_blank_replica_version_id_payload(subnet_id),
        );

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        assert_eq!(subnet_record.replica_version_id, "");
    }

    #[test]
    #[should_panic(expected = "a blank replica_version_id is not enabled yet")]
    fn cannot_blank_replica_version_when_feature_is_disabled() {
        let _restore_on_drop = temporarily_disable_blank_replica_version_id_for_cloud_engines();
        let (mut registry, subnet_id) = make_registry_with_blankable_cloud_engine_subnet();

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            new_blank_replica_version_id_payload(subnet_id),
        );
    }

    /// Without the standard engine record, a blank id would leave the subnet
    /// with no replica version at all.
    #[test]
    #[should_panic(expected = "Registry has no StandardEngineReplicaVersionRecord")]
    fn cannot_blank_replica_version_without_standard_engine_record() {
        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, subnet_id) = prepare_registry_with_cloud_engine_subnet(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            ENGINE_CONTROLLER_CANISTER_ID.get(),
            new_blank_replica_version_id_payload(subnet_id),
        );
    }

    /// Blanking is a Cloud Engine affordance only: every other subnet type must
    /// keep pinning an elected version. Governance is the caller here, because
    /// the engine controller is already barred from non-CloudEngine subnets.
    #[test]
    #[should_panic(expected = "only CloudEngine subnets may have a blank replica_version_id")]
    fn cannot_blank_replica_version_of_non_cloud_engine_subnet() {
        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let (mut registry, subnet_id) =
            make_registry_with_non_cloud_engine_subnet(SubnetType::Application);
        add_standard_engine_replica_version_record(&mut registry);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            GOVERNANCE_CANISTER_ID.get(),
            new_blank_replica_version_id_payload(subnet_id),
        );
    }

    /// The blank case must not weaken the check for non-blank versions.
    #[test]
    #[should_panic(expected = "is NOT elected")]
    fn cannot_deploy_unelected_replica_version() {
        let (mut registry, subnet_id) =
            make_registry_with_non_cloud_engine_subnet(SubnetType::Application);

        registry.do_deploy_guestos_to_all_subnet_nodes(
            GOVERNANCE_CANISTER_ID.get(),
            DeployGuestosToAllSubnetNodesPayload {
                subnet_id: subnet_id.get(),
                replica_version_id: NEW_REPLICA_VERSION_ID.to_string(),
            },
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
