use crate::{
    common::LOG_PREFIX,
    mutations::common::{check_replica_version_is_elected, has_duplicates},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{PrincipalId, SubnetId};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Sets the `replica_version_id` of every subnet in `payload.subnet_ids` to
    /// the given (elected) GuestOS version.
    ///
    /// Unlike `do_deploy_guestos_to_all_subnet_nodes`, which targets a single
    /// subnet, this updates an explicit list of subnets in one atomic registry
    /// mutation: either all listed subnets move to the new version, or none do.
    /// Subnets that are already on the requested version are skipped to avoid
    /// churning the registry with no-op updates.
    pub fn do_update_guestos_version_for_subnets(
        &mut self,
        payload: UpdateGuestosVersionForSubnetsPayload,
    ) {
        println!("{LOG_PREFIX}do_update_guestos_version_for_subnets: {payload:?}");

        check_replica_version_is_elected(self, &payload.replica_version_id);

        assert!(
            !payload.subnet_ids.is_empty(),
            "{LOG_PREFIX}do_update_guestos_version_for_subnets: subnet_ids must not be empty.",
        );
        assert!(
            !has_duplicates(&payload.subnet_ids),
            "{LOG_PREFIX}do_update_guestos_version_for_subnets: subnet_ids must not contain duplicates.",
        );

        let mut mutations = vec![];
        for subnet_id in &payload.subnet_ids {
            let subnet_id = SubnetId::from(*subnet_id);
            let mut subnet_record = self
                .get_subnet(subnet_id, self.latest_version())
                .unwrap_or_else(|err| {
                    panic!("{LOG_PREFIX}do_update_guestos_version_for_subnets: {err}")
                });

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
            "{LOG_PREFIX}do_update_guestos_version_for_subnets: updating {} of {} requested subnet(s) to version {}",
            mutations.len(),
            payload.subnet_ids.len(),
            payload.replica_version_id,
        );

        // Check invariants before applying mutations. An empty mutation list is
        // a no-op (e.g. when all listed subnets are already on the requested
        // version).
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// The argument of a command to update the GuestOS (replica) version of a
/// specific list of subnets to a single version.
///
/// The subnets will be mutated only if the given version is, indeed, elected.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateGuestosVersionForSubnetsPayload {
    /// The subnets to update.
    pub subnet_ids: Vec<PrincipalId>, // SubnetId See NNS-73
    /// The new GuestOS (replica) version to use.
    pub replica_version_id: String,
}

#[cfg(test)]
mod tests {
    use ic_base_types::{NodeId, PrincipalId, SubnetId};
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
    use ic_registry_keys::make_replica_version_key;
    use ic_registry_transport::insert;
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;

    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use crate::registry::Registry;

    use super::UpdateGuestosVersionForSubnetsPayload;

    const TARGET_VERSION: &str = "version";

    /// Elects `TARGET_VERSION` so the update passes the elected-version check.
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

    /// Adds an application subnet backed by `node_id` and returns its id.
    fn add_subnet(
        registry: &mut Registry,
        node_id: NodeId,
        dkg_pk: PublicKey,
        subnet_index: u64,
    ) -> SubnetId {
        let subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
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

    /// Sets up a registry with three application subnets and elects the target
    /// version. Returns the three subnet ids.
    fn registry_with_three_subnets() -> (Registry, [SubnetId; 3]) {
        let mut registry = invariant_compliant_registry(0);
        elect_target_version(&mut registry);

        let (mutate_request, nodes) = prepare_registry_with_nodes(1, 3);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut nodes = nodes.into_iter();
        let (n1, pk1) = nodes.next().unwrap();
        let (n2, pk2) = nodes.next().unwrap();
        let (n3, pk3) = nodes.next().unwrap();

        let s1 = add_subnet(&mut registry, n1, pk1, 1001);
        let s2 = add_subnet(&mut registry, n2, pk2, 1002);
        let s3 = add_subnet(&mut registry, n3, pk3, 1003);
        (registry, [s1, s2, s3])
    }

    #[test]
    #[should_panic(expected = "'version' is NOT elected")]
    fn should_panic_if_version_not_elected() {
        let mut registry = invariant_compliant_registry(0);

        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![subnet_test_id(1001).get()],
            replica_version_id: TARGET_VERSION.into(),
        });
    }

    #[test]
    #[should_panic(expected = "subnet_ids must not be empty")]
    fn should_panic_on_empty_subnet_list() {
        let mut registry = invariant_compliant_registry(0);
        elect_target_version(&mut registry);

        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![],
            replica_version_id: TARGET_VERSION.into(),
        });
    }

    #[test]
    #[should_panic(expected = "must not contain duplicates")]
    fn should_panic_on_duplicate_subnets() {
        let (mut registry, [s1, ..]) = registry_with_three_subnets();

        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![s1.get(), s1.get()],
            replica_version_id: TARGET_VERSION.into(),
        });
    }

    #[test]
    #[should_panic(expected = "not found in the registry")]
    fn should_panic_on_unknown_subnet() {
        let mut registry = invariant_compliant_registry(0);
        elect_target_version(&mut registry);

        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![PrincipalId::new_subnet_test_id(12345)],
            replica_version_id: TARGET_VERSION.into(),
        });
    }

    #[test]
    fn should_update_only_listed_subnets() {
        let (mut registry, [s1, s2, s3]) = registry_with_three_subnets();

        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![s1.get(), s2.get()],
            replica_version_id: TARGET_VERSION.into(),
        });

        assert_eq!(replica_version_of(&registry, s1), TARGET_VERSION);
        assert_eq!(replica_version_of(&registry, s2), TARGET_VERSION);
        // The subnet that was not listed must be untouched.
        assert_ne!(replica_version_of(&registry, s3), TARGET_VERSION);
    }

    #[test]
    fn should_be_noop_when_listed_subnets_already_on_version() {
        let (mut registry, [s1, ..]) = registry_with_three_subnets();

        // Bring s1 to the target version first.
        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![s1.get()],
            replica_version_id: TARGET_VERSION.into(),
        });
        let version_before = registry.latest_version();

        // Re-applying for the same subnet produces no mutation, hence no bump.
        registry.do_update_guestos_version_for_subnets(UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![s1.get()],
            replica_version_id: TARGET_VERSION.into(),
        });

        assert_eq!(registry.latest_version(), version_before);
    }
}
