//! Contains the method to merge a subnet into another subnet.
//!
//! Merging the source subnet into the destination subnet reroutes all canisters
//! of the source subnet to the destination subnet and lets the destination
//! subnet resume from a state that was extended, while both subnets were
//! offline, with the state of those canisters. The state extension itself
//! happens outside of the registry: this method only records its outcome, as the
//! state hash of a recovery catch-up package for the destination subnet.

use crate::{
    common::LOG_PREFIX, mutations::do_recover_subnet::panic_if_record_changed_across_versions,
    registry::Registry,
};
use candid::{CandidType, Encode};
use dfn_core::api::{CanisterId, call};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_management_canister_types_private::{SetupInitialDKGArgs, SetupInitialDKGResponse};
use ic_protobuf::registry::subnet::v1::{RecoveryArgs, catch_up_package_contents::CupType};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_record_key,
};
use ic_registry_routing_table::are_disjoint;
use ic_registry_transport::{
    pb::v1::{RegistryMutation, registry_mutation},
    upsert,
};
use on_wire::bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

impl Registry {
    /// Merges the source subnet into the destination subnet.
    ///
    /// Three things happen, all in a single registry version, so that the
    /// destination subnet never observes a state where only some of them took
    /// effect:
    ///
    ///   1. the canister ID ranges of the source subnet are merged into the
    ///      canister ID range set of the destination subnet, so that all
    ///      canisters that used to be hosted by the source subnet are routed to
    ///      the destination subnet;
    ///   2. a recovery catch-up package is created for the destination subnet,
    ///      at the height, time and state hash of the merged state, running a
    ///      fresh DKG for the destination subnet's membership; and
    ///   3. the destination subnet is brought back online.
    ///
    /// The caller is expected to have taken both subnets offline and to have
    /// extended the state of the destination subnet with the state of the
    /// canisters of the source subnet beforehand; `state_hash` is the hash of
    /// the manifest of the resulting merged state.
    ///
    /// Note that neither subnet record is deleted and, in particular, the source
    /// subnet is not deleted: it merely does not host any canister ID range
    /// anymore.
    pub async fn merge_subnets(&mut self, payload: MergeSubnetsPayload) -> Result<(), String> {
        println!("{LOG_PREFIX}merge_subnets: {payload:?}");

        let MergeSubnetsPayload {
            source_subnet,
            destination_subnet,
            height,
            time_ns,
            state_hash,
            initial_dkg_subnet_id,
        } = payload;

        if source_subnet == destination_subnet {
            return Err(format!(
                "source subnet {source_subnet} and destination subnet {destination_subnet} must be different subnets"
            ));
        }

        let pre_call_registry_version = self.latest_version();

        self.get(
            &make_subnet_record_key(source_subnet).into_bytes(),
            pre_call_registry_version,
        )
        .ok_or_else(|| format!("source {source_subnet} is not a known subnet"))?;
        let destination_record = self
            .get_subnet(destination_subnet, pre_call_registry_version)
            .map_err(|_| format!("destination {destination_subnet} is not a known subnet"))?;

        let routing_table = self.get_routing_table_or_panic(pre_call_registry_version);
        let source_ranges = routing_table.ranges(source_subnet);
        if source_ranges.is_empty() {
            return Err(format!(
                "source subnet {source_subnet} does not host any canister ID range"
            ));
        }

        // Rerouting the canister ID ranges of the source subnet would break any ongoing canister
        // migration out of those ranges: the migrated ranges would end up being hosted by the
        // destination subnet, which is not on the recorded migration trace.
        if let Some(canister_migrations) = self.get_canister_migrations(pre_call_registry_version)
            && !are_disjoint(canister_migrations.ranges(), source_ranges.iter())
        {
            return Err(format!(
                "source subnet {source_subnet} hosts canister ID ranges with ongoing canister migrations"
            ));
        }

        // Recovering a subnet holding chain keys requires resharing those keys onto the recovery
        // CUP, which this method does not do; rather than silently leave the destination subnet
        // unable to sign, refuse to merge into it.
        if destination_record
            .chain_key_config
            .as_ref()
            .is_some_and(|config| !config.key_configs.is_empty())
        {
            return Err(format!(
                "destination subnet {destination_subnet} holds chain keys, which merging does not reshare"
            ));
        }

        // `setup_initial_dkg` must not be handled by the subnet being recovered, as that subnet is
        // offline and could not respond.
        if let Some(initial_dkg_subnet_id) = initial_dkg_subnet_id {
            if initial_dkg_subnet_id == destination_subnet {
                return Err(format!(
                    "initial DKG subnet {initial_dkg_subnet_id} must be different from the destination subnet"
                ));
            }
            self.get(
                &make_subnet_record_key(initial_dkg_subnet_id).into_bytes(),
                pre_call_registry_version,
            )
            .ok_or_else(|| {
                format!("initial DKG subnet {initial_dkg_subnet_id} is not a known subnet")
            })?;
        }

        let mut cup_contents = self
            .get_subnet_catch_up_package(destination_subnet, Some(pre_call_registry_version))
            .map_err(|err| format!("failed to get the CUP of {destination_subnet}: {err}"))?;
        cup_contents.registry_store_uri = None;
        // Chain key initializations in a CUP take precedence over the chain key configuration of
        // the subnet record, so carrying over the ones of the CUP being replaced would make the
        // destination subnet bootstrap stale key material. The destination subnet holds no chain
        // keys (checked above) and merging reshares none, so both fields are cleared, just like
        // recovering a subnet without an initial chain key configuration does.
        cup_contents.chain_key_initializations = vec![];
        cup_contents.ecdsa_initializations = vec![];

        let mut subnet_record = destination_record;

        // Bring the destination subnet back online. Consensus looks at the registry version from
        // the highest CUP when considering `halt_at_cup_height`, so clearing both flags is what
        // makes the subnet resume from the recovery CUP created below.
        subnet_record.halt_at_cup_height = false;
        subnet_record.is_halted = false;

        let dkg_nodes: Vec<NodeId> = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect();

        let request = SetupInitialDKGArgs::new(
            dkg_nodes,
            RegistryVersion::new(pre_call_registry_version),
            initial_dkg_subnet_id,
        );
        let response_bytes = call(
            CanisterId::ic_00(),
            "setup_initial_dkg",
            bytes,
            Encode!(&request).unwrap(),
        )
        .await
        .unwrap_or_else(|(code, msg)| {
            panic!("{LOG_PREFIX}`setup_initial_dkg` failed with code {code:?}: {msg}")
        });

        let post_call_registry_version = self.latest_version();

        // Check that the records this method is about to overwrite, and the routing table it based
        // its validation on, did not change while `setup_initial_dkg` was in flight.
        for (key, what) in [
            (
                make_subnet_record_key(destination_subnet),
                format!("Subnet with ID {destination_subnet}"),
            ),
            (
                make_crypto_threshold_signing_pubkey_key(destination_subnet),
                format!("Threshold Signing Pubkey for Subnet {destination_subnet}"),
            ),
            (
                make_catch_up_package_contents_key(destination_subnet),
                format!("CUP for Subnet {destination_subnet}"),
            ),
            (
                make_subnet_record_key(source_subnet),
                format!("Subnet with ID {source_subnet}"),
            ),
        ] {
            panic_if_record_changed_across_versions(
                self,
                &key,
                pre_call_registry_version,
                post_call_registry_version,
                format!("{what} was updated during the `setup_initial_dkg` call"),
            );
        }
        assert_eq!(
            self.get_routing_table_or_panic(post_call_registry_version)
                .ranges(source_subnet),
            source_ranges,
            "{LOG_PREFIX}The canister ID ranges of subnet {source_subnet} were updated during the \
             `setup_initial_dkg` call",
        );
        // A canister migration overlapping the canister ID ranges of the source subnet could have
        // been prepared, without changing the routing table, while `setup_initial_dkg` was in
        // flight; rerouting those ranges would break it, just like it would have before the call.
        assert!(
            self.get_canister_migrations(post_call_registry_version)
                .is_none_or(|canister_migrations| are_disjoint(
                    canister_migrations.ranges(),
                    source_ranges.iter()
                )),
            "{LOG_PREFIX}Canister migrations overlapping the canister ID ranges of subnet \
             {source_subnet} were added during the `setup_initial_dkg` call",
        );

        let dkg_response = SetupInitialDKGResponse::decode(&response_bytes).unwrap();

        cup_contents.initial_ni_dkg_transcript_low_threshold =
            Some(dkg_response.low_threshold_transcript_record);
        cup_contents.initial_ni_dkg_transcript_high_threshold =
            Some(dkg_response.high_threshold_transcript_record);
        cup_contents.height = height;
        cup_contents.time = time_ns;
        cup_contents.state_hash = state_hash.clone();
        cup_contents.cup_type = Some(CupType::Recovery(RecoveryArgs {
            height,
            time: time_ns,
            state_hash,
        }));

        let mut mutations = vec![
            RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_crypto_threshold_signing_pubkey_key(destination_subnet).into_bytes(),
                value: dkg_response.subnet_threshold_public_key.encode_to_vec(),
            },
            RegistryMutation {
                mutation_type: registry_mutation::Type::Update as i32,
                key: make_catch_up_package_contents_key(destination_subnet).into_bytes(),
                value: cup_contents.encode_to_vec(),
            },
            upsert(
                make_subnet_record_key(destination_subnet),
                subnet_record.encode_to_vec(),
            ),
        ];
        mutations.append(&mut self.merge_subnets_mutation(
            post_call_registry_version,
            source_subnet,
            destination_subnet,
        ));

        self.maybe_apply_mutation_internal(mutations);

        Ok(())
    }
}

/// The argument for the `merge_subnets` update call.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct MergeSubnetsPayload {
    /// The subnet whose canister ID ranges are merged into the canister ID range
    /// set of `destination_subnet`.
    pub source_subnet: SubnetId,
    /// The subnet that hosts the canister ID ranges of `source_subnet` after the
    /// merge, and that is recovered at the merged state and brought back online.
    pub destination_subnet: SubnetId,
    /// The height of the recovery CUP of `destination_subnet`, i.e. the height
    /// of the checkpoint holding the merged state.
    pub height: u64,
    /// The block time the recovered `destination_subnet` starts from, in
    /// nanoseconds since the Epoch. Must be larger than the times of the
    /// checkpoints at which both subnets were taken offline.
    pub time_ns: u64,
    /// The hash of the manifest of the merged state.
    pub state_hash: Vec<u8>,
    /// The subnet that should handle the `setup_initial_dkg` call producing the
    /// DKG transcripts of the recovery CUP. Must be different from
    /// `destination_subnet`, which is offline while the merge is in progress. If
    /// unset, the request is handled by the NNS subnet.
    pub initial_dkg_subnet_id: Option<SubnetId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        mutations::{
            prepare_canister_migration::PrepareCanisterMigrationPayload,
            routing_table::routing_table_into_registry_mutation,
        },
    };
    use futures::executor::block_on;
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_types::CanisterId;
    use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2, SUBNET_3};
    use maplit::btreemap;

    /// The recovery CUP fields of the payload, which the validation-failure tests
    /// below are not about: they all fail before the CUP is even looked at.
    fn default_cup_args() -> MergeSubnetsPayload {
        MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
            height: 100,
            time_ns: 1_000_000_000,
            state_hash: vec![1; 32],
            initial_dkg_subnet_id: Some(SUBNET_3),
        }
    }

    fn range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: CanisterId::from_u64(start),
            end: CanisterId::from_u64(end),
        }
    }

    /// Returns a registry with two subnets, `SUBNET_1` and `SUBNET_2`, where
    /// `SUBNET_1` hosts the canister ID ranges `[10, 19]` and `[30, 39]` and
    /// `SUBNET_2` hosts the canister ID range `[20, 29]`.
    fn new_two_subnets_fixture_registry() -> Registry {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes(/* start_mutation_id = */ 1, /* nodes = */ 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();
        let subnet_ids_and_nodes = [SUBNET_1, SUBNET_2].into_iter().zip(node_ids_and_dkg_pks);

        for (subnet_id, (node_id, dkg_pk)) in subnet_ids_and_nodes {
            let subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
            let subnet_mutations = add_fake_subnet(
                subnet_id,
                &mut subnet_list_record,
                subnet_record,
                &btreemap! { node_id => dkg_pk },
            );
            registry.maybe_apply_mutation_internal(subnet_mutations);
        }

        let mut routing_table = RoutingTable::new();
        routing_table.insert(range(10, 19), SUBNET_1).unwrap();
        routing_table.insert(range(20, 29), SUBNET_2).unwrap();
        routing_table.insert(range(30, 39), SUBNET_1).unwrap();
        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        registry
    }

    fn get_routing_table_entries(registry: &Registry) -> Vec<(CanisterIdRange, SubnetId)> {
        registry
            .get_routing_table_or_panic(registry.latest_version())
            .into_iter()
            .collect::<Vec<(CanisterIdRange, SubnetId)>>()
    }

    /// Applies just the routing table part of a merge. `Registry::merge_subnets`
    /// itself cannot be driven to completion in a unit test, as it calls
    /// `setup_initial_dkg` on the management canister half way through; the
    /// success path as a whole is covered by the integration test in
    /// `rs/registry/canister/tests/merge_subnets.rs`.
    fn merge_routing_table(registry: &mut Registry, source: SubnetId, destination: SubnetId) {
        let mutations =
            registry.merge_subnets_mutation(registry.latest_version(), source, destination);
        registry.maybe_apply_mutation_internal(mutations);
    }

    #[test]
    fn test_merge_subnets() {
        // Step 1: Prepare the world.
        let mut registry = new_two_subnets_fixture_registry();

        // Step 2: Run the code under test.
        merge_routing_table(&mut registry, SUBNET_1, SUBNET_2);

        // Step 3: Verify results: the canister ID ranges of both subnets are now
        // hosted by the destination subnet, and the three adjacent ranges got
        // merged into one.
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![(range(10, 39), SUBNET_2)],
        );
    }

    #[test]
    fn test_merge_subnets_into_subnet_without_canister_id_ranges() {
        // Step 1: Prepare the world: let the destination subnet host no canister ID
        // range at all, so that the merge has to add the destination subnet to the
        // routing table. The two ranges of the source subnet are not adjacent, so
        // they must stay two separate entries.
        let mut registry = new_two_subnets_fixture_registry();
        let mut routing_table = RoutingTable::new();
        routing_table.insert(range(10, 19), SUBNET_1).unwrap();
        routing_table.insert(range(30, 39), SUBNET_1).unwrap();
        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        // Step 2: Run the code under test.
        merge_routing_table(&mut registry, SUBNET_1, SUBNET_2);

        // Step 3: Verify results. Both ranges are hosted by the destination subnet
        // and, not being adjacent, did not get merged into a single entry.
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![(range(10, 19), SUBNET_2), (range(30, 39), SUBNET_2)],
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_subnets_are_equal() {
        // Step 1: Prepare the world.
        let mut registry = new_two_subnets_fixture_registry();

        // Step 2: Run the code under test.
        let result = block_on(registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_1,
            ..default_cup_args()
        }));

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("must be different subnets"),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![
                (range(10, 19), SUBNET_1),
                (range(20, 29), SUBNET_2),
                (range(30, 39), SUBNET_1),
            ],
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_source_subnet_is_unknown() {
        // Step 1: Prepare the world.
        let mut registry = new_two_subnets_fixture_registry();

        // Step 2: Run the code under test.
        let result = block_on(registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_3,
            destination_subnet: SUBNET_2,
            ..default_cup_args()
        }));

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains(&format!("source {SUBNET_3} is not a known subnet")),
            "{error_message}"
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_destination_subnet_is_unknown() {
        // Step 1: Prepare the world.
        let mut registry = new_two_subnets_fixture_registry();

        // Step 2: Run the code under test.
        let result = block_on(registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_3,
            ..default_cup_args()
        }));

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains(&format!("destination {SUBNET_3} is not a known subnet")),
            "{error_message}"
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_source_subnet_hosts_no_canister_id_range() {
        // Step 1: Prepare the world: only the destination subnet hosts a canister
        // ID range.
        let mut registry = new_two_subnets_fixture_registry();
        let mut routing_table = RoutingTable::new();
        routing_table.insert(range(20, 29), SUBNET_2).unwrap();
        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        // Step 2: Run the code under test.
        let result = block_on(registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
            ..default_cup_args()
        }));

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("does not host any canister ID range"),
            "{error_message}"
        );
    }

    #[test]
    fn test_merge_subnets_fails_with_ongoing_canister_migration() {
        // Step 1: Prepare the world: start migrating a canister ID range away from
        // the source subnet.
        let mut registry = new_two_subnets_fixture_registry();
        registry
            .prepare_canister_migration(PrepareCanisterMigrationPayload {
                canister_id_ranges: vec![range(10, 11)],
                source_subnet: SUBNET_1,
                destination_subnet: SUBNET_2,
            })
            .unwrap();

        // Step 2: Run the code under test.
        let result = block_on(registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
            ..default_cup_args()
        }));

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("ongoing canister migrations"),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![
                (range(10, 19), SUBNET_1),
                (range(20, 29), SUBNET_2),
                (range(30, 39), SUBNET_1),
            ],
        );
    }
}
