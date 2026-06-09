use crate::{
    common::LOG_PREFIX,
    mutations::common::{check_replica_version_is_elected, get_subnet_ids_from_subnet_list},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Deploys the given (elected) GuestOS version to every CloudEngine subnet.
    ///
    /// Unlike `do_deploy_guestos_to_all_subnet_nodes`, which targets a single
    /// subnet, this enumerates the current `subnet_list` and updates the
    /// `replica_version_id` of every subnet whose `subnet_type` is
    /// `SubnetType::CloudEngine`. The set of affected subnets is therefore
    /// resolved at execution time rather than captured in the payload, so the
    /// proposal always acts on the CloudEngine fleet as it exists when it runs.
    ///
    /// All updates are applied as a single atomic registry mutation: either the
    /// whole fleet moves to the new version, or nothing does.
    pub fn do_deploy_guestos_to_all_cloud_engines(
        &mut self,
        payload: DeployGuestosToAllCloudEnginesPayload,
    ) {
        println!("{LOG_PREFIX}do_deploy_guestos_to_all_cloud_engines: {payload:?}");

        check_replica_version_is_elected(self, &payload.replica_version_id);

        let cloud_engine_type = i32::from(SubnetType::CloudEngine);
        let mut mutations = vec![];
        for subnet_id in get_subnet_ids_from_subnet_list(self.get_subnet_list_record()) {
            let mut subnet_record = self.get_subnet_or_panic(subnet_id);

            // Only CloudEngine subnets are affected; everything else is left untouched.
            if subnet_record.subnet_type != cloud_engine_type {
                continue;
            }

            // Skip subnets that are already on the requested version to avoid
            // churning the registry with no-op updates.
            if subnet_record.replica_version_id == payload.replica_version_id {
                continue;
            }

            subnet_record.replica_version_id = payload.replica_version_id.clone();
            mutations.push(RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_subnet_record_key(subnet_id).into_bytes(),
                value: subnet_record.encode_to_vec(),
            });
        }

        println!(
            "{LOG_PREFIX}do_deploy_guestos_to_all_cloud_engines: updating {} CloudEngine subnet(s) to version {}",
            mutations.len(),
            payload.replica_version_id,
        );

        // Check invariants before applying mutations. An empty mutation list is
        // a no-op (e.g. when no CloudEngine subnets exist, or all are already on
        // the requested version).
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// The argument of a command to update the replica version of every CloudEngine
/// subnet to a specific version.
///
/// The subnets will be mutated only if the given version is, indeed, elected.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeployGuestosToAllCloudEnginesPayload {
    /// The new Replica version to deploy to all CloudEngine subnets.
    pub replica_version_id: String,
}

#[cfg(test)]
mod tests {
    use ic_base_types::{NodeId, SubnetId};
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
    use ic_protobuf::registry::subnet::v1::CanisterCyclesCostSchedule;
    use ic_registry_keys::make_replica_version_key;
    use ic_registry_subnet_type::SubnetType;
    use ic_registry_transport::insert;
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;

    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes, prepare_registry_with_nodes_and_reward_type,
    };
    use crate::registry::Registry;

    use super::DeployGuestosToAllCloudEnginesPayload;

    const TARGET_VERSION: &str = "version";

    /// Elects `TARGET_VERSION` so the deploy passes the elected-version check.
    fn elect_target_version(registry: &mut Registry) {
        registry.maybe_apply_mutation_internal(vec![insert(
            make_replica_version_key(TARGET_VERSION),
            ReplicaVersionRecord {
                release_package_sha256_hex: "".into(),
                release_package_urls: vec![],
                guest_launch_measurements: None,
            }
            .encode_to_vec(),
        )]);
    }

    /// Adds a CloudEngine subnet backed by `node_id` and returns its id. The
    /// node must have reward type `Type4` and the subnet uses the free cycles
    /// cost schedule, both required by registry invariants for CloudEngines.
    fn add_cloud_engine_subnet(
        registry: &mut Registry,
        node_id: NodeId,
        dkg_pk: PublicKey,
        subnet_index: u64,
    ) -> SubnetId {
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
        subnet_record.subnet_type = i32::from(SubnetType::CloudEngine);
        subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Free);
        add_subnet(registry, node_id, dkg_pk, subnet_index, subnet_record)
    }

    /// Adds an application subnet backed by `node_id` and returns its id.
    fn add_application_subnet(
        registry: &mut Registry,
        node_id: NodeId,
        dkg_pk: PublicKey,
        subnet_index: u64,
    ) -> SubnetId {
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
        subnet_record.subnet_type = i32::from(SubnetType::Application);
        add_subnet(registry, node_id, dkg_pk, subnet_index, subnet_record)
    }

    fn add_subnet(
        registry: &mut Registry,
        node_id: NodeId,
        dkg_pk: PublicKey,
        subnet_index: u64,
        subnet_record: ic_protobuf::registry::subnet::v1::SubnetRecord,
    ) -> SubnetId {
        let mut subnet_list_record = registry.get_subnet_list_record();
        let subnet_id = subnet_test_id(subnet_index);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(node_id => dkg_pk),
        ));
        subnet_id
    }

    fn replica_version_of(registry: &Registry, subnet_id: SubnetId) -> String {
        registry.get_subnet_or_panic(subnet_id).replica_version_id
    }

    #[test]
    #[should_panic(expected = "'version' is NOT elected")]
    fn should_panic_if_version_not_elected() {
        let mut registry = invariant_compliant_registry(0);

        registry.do_deploy_guestos_to_all_cloud_engines(DeployGuestosToAllCloudEnginesPayload {
            replica_version_id: TARGET_VERSION.into(),
        });
    }

    #[test]
    fn should_upgrade_only_cloud_engine_subnets() {
        let mut registry = invariant_compliant_registry(0);
        elect_target_version(&mut registry);

        // CloudEngine subnets require nodes with reward type Type4; the
        // application subnet must use a non-Type4 node. Distinct mutation-id
        // ranges keep the generated node IPs/domains from colliding.
        let (ce_req, ce_nodes) =
            prepare_registry_with_nodes_and_reward_type(1, 2, NodeRewardType::Type4);
        registry.maybe_apply_mutation_internal(ce_req.mutations);
        let (app_req, app_nodes) = prepare_registry_with_nodes(10, 1);
        registry.maybe_apply_mutation_internal(app_req.mutations);

        let mut ce_nodes = ce_nodes.into_iter();
        let (n1, pk1) = ce_nodes.next().unwrap();
        let (n2, pk2) = ce_nodes.next().unwrap();
        let (app_node, app_pk) = app_nodes.into_iter().next().unwrap();

        let cloud_engine_a = add_cloud_engine_subnet(&mut registry, n1, pk1, 1001);
        let cloud_engine_b = add_cloud_engine_subnet(&mut registry, n2, pk2, 1002);
        let application = add_application_subnet(&mut registry, app_node, app_pk, 1003);

        registry.do_deploy_guestos_to_all_cloud_engines(DeployGuestosToAllCloudEnginesPayload {
            replica_version_id: TARGET_VERSION.into(),
        });

        assert_eq!(
            replica_version_of(&registry, cloud_engine_a),
            TARGET_VERSION
        );
        assert_eq!(
            replica_version_of(&registry, cloud_engine_b),
            TARGET_VERSION
        );
        // The application subnet must be untouched.
        assert_ne!(replica_version_of(&registry, application), TARGET_VERSION);
    }

    #[test]
    fn should_be_noop_when_no_cloud_engine_subnets_exist() {
        let mut registry = invariant_compliant_registry(0);
        elect_target_version(&mut registry);

        let (app_req, app_nodes) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(app_req.mutations);
        let (app_node, app_pk) = app_nodes.into_iter().next().unwrap();
        add_application_subnet(&mut registry, app_node, app_pk, 1001);
        let version_before = registry.latest_version();

        registry.do_deploy_guestos_to_all_cloud_engines(DeployGuestosToAllCloudEnginesPayload {
            replica_version_id: TARGET_VERSION.into(),
        });

        // No CloudEngine subnets means no mutations, hence no version bump.
        assert_eq!(registry.latest_version(), version_before);
    }
}
