use crate::{common::LOG_PREFIX, registry::Registry};
use candid::CandidType;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::SubnetId;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_routing_table::are_disjoint;
use serde::{Deserialize, Serialize};

impl Registry {
    /// Merges the canister ID ranges of the source subnet into the canister ID
    /// range set of the destination subnet.
    ///
    /// This is one step of the subnet merging process: by the time this mutation
    /// is applied, both subnets are halted and all streams to and from the source
    /// subnet are empty. The destination subnet is only unhalted after this
    /// registry change has been applied.
    ///
    /// After this operation, all canisters that used to be hosted by the source
    /// subnet are routed to the destination subnet and the source subnet does
    /// not host any canister ID range anymore.
    ///
    /// Note that only the routing table is updated: neither subnet record is
    /// modified and, in particular, the source subnet is not deleted.
    pub fn merge_subnets(&mut self, payload: MergeSubnetsPayload) -> Result<(), String> {
        println!("{LOG_PREFIX}merge_subnets: {payload:?}");

        let MergeSubnetsPayload {
            source_subnet,
            destination_subnet,
        } = payload;

        // The subnets must be distinct.
        if source_subnet == destination_subnet {
            return Err(format!(
                "source subnet {source_subnet} and destination subnet {destination_subnet} must be different subnets"
            ));
        }

        let version = self.latest_version();

        // The subnets must exist.
        self.get(&make_subnet_record_key(source_subnet).into_bytes(), version)
            .ok_or_else(|| format!("source {source_subnet} is not a known subnet"))?;
        self.get(
            &make_subnet_record_key(destination_subnet).into_bytes(),
            version,
        )
        .ok_or_else(|| format!("destination {destination_subnet} is not a known subnet"))?;

        // The source subnet must be nonempty.
        let routing_table = self.get_routing_table_or_panic(version);
        let source_ranges = routing_table.ranges(source_subnet);
        if source_ranges.is_empty() {
            return Err(format!(
                "source subnet {source_subnet} does not host any canister ID range"
            ));
        }

        // Separate checks before the merge should ensure that this never triggers: rerouting the
        // canister ID ranges of the source subnet would break any ongoing canister migration out
        // of those ranges, since the migrated ranges would end up being hosted by the destination
        // subnet, which is not on the recorded migration trace.
        if let Some(canister_migrations) = self.get_canister_migrations(version)
            && !are_disjoint(canister_migrations.ranges(), source_ranges.iter())
        {
            return Err(format!(
                "source subnet {source_subnet} hosts canister ID ranges with ongoing canister migrations"
            ));
        }

        self.maybe_apply_mutation_internal(self.merge_subnets_mutation(
            version,
            source_subnet,
            destination_subnet,
        ));

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
    /// merge.
    pub destination_subnet: SubnetId,
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
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_types::CanisterId;
    use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2, SUBNET_3};
    use lazy_static::lazy_static;
    use maplit::btreemap;

    const fn range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: CanisterId::from_u64(start),
            end: CanisterId::from_u64(end),
        }
    }

    /// The routing table of `TWO_SUBNETS_REGISTRY`.
    const FIXTURE_ROUTING_TABLE_ENTRIES: [(CanisterIdRange, SubnetId); 3] = [
        (range(10, 19), SUBNET_1),
        (range(20, 29), SUBNET_2),
        (range(30, 39), SUBNET_1),
    ];

    lazy_static! {
        /// A registry with two subnets, `SUBNET_1` and `SUBNET_2`, where `SUBNET_1`
        /// hosts the canister ID ranges `[10, 19]` and `[30, 39]` and `SUBNET_2`
        /// hosts the canister ID range `[20, 29]`.
        static ref TWO_SUBNETS_REGISTRY: Registry = {
            let mut registry = invariant_compliant_registry(0);

            let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
                1, // start_mutation_id
                2, // nodes
            );
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
            for (canister_id_range, subnet_id) in FIXTURE_ROUTING_TABLE_ENTRIES {
                routing_table.insert(canister_id_range, subnet_id).unwrap();
            }
            registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
                &registry,
                routing_table,
            ));

            registry
        };
    }

    fn get_routing_table_entries(registry: &Registry) -> Vec<(CanisterIdRange, SubnetId)> {
        registry
            .get_routing_table_or_panic(registry.latest_version())
            .into_iter()
            .collect::<Vec<(CanisterIdRange, SubnetId)>>()
    }

    #[test]
    fn test_merge_subnets() {
        // Step 1: Prepare the world.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
        });

        // Step 3: Verify results.

        // Step 3.1: Inspect the return value.
        assert_eq!(result, Ok(()));

        // Step 3.2: The canister ID ranges of both subnets are now hosted by the
        // destination subnet, and the three adjacent ranges got merged into one.
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
        // they must stay two separate entries. A subnet hosting no canister ID range
        // is not a realistic scenario; this only exercises that code path.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();
        let mut routing_table = RoutingTable::new();
        routing_table.insert(range(10, 19), SUBNET_1).unwrap();
        routing_table.insert(range(30, 39), SUBNET_1).unwrap();
        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
        });

        // Step 3: Verify results. Both ranges are hosted by the destination subnet
        // and, not being adjacent, did not get merged into a single entry.
        assert_eq!(result, Ok(()));
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![(range(10, 19), SUBNET_2), (range(30, 39), SUBNET_2)],
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_subnets_are_equal() {
        // Step 1: Prepare the world.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_1,
        });

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("must be different subnets"),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            FIXTURE_ROUTING_TABLE_ENTRIES.to_vec(),
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_source_subnet_is_unknown() {
        // Step 1: Prepare the world.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_3,
            destination_subnet: SUBNET_2,
        });

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains(&format!("source {SUBNET_3} is not a known subnet")),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            FIXTURE_ROUTING_TABLE_ENTRIES.to_vec(),
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_destination_subnet_is_unknown() {
        // Step 1: Prepare the world.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_3,
        });

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains(&format!("destination {SUBNET_3} is not a known subnet")),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            FIXTURE_ROUTING_TABLE_ENTRIES.to_vec(),
        );
    }

    #[test]
    fn test_merge_subnets_fails_when_source_subnet_hosts_no_canister_id_range() {
        // Step 1: Prepare the world: only the destination subnet hosts a canister
        // ID range.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();
        let mut routing_table = RoutingTable::new();
        routing_table.insert(range(20, 29), SUBNET_2).unwrap();
        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
        });

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("does not host any canister ID range"),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            vec![(range(20, 29), SUBNET_2)],
        );
    }

    #[test]
    fn test_merge_subnets_fails_with_ongoing_canister_migration() {
        // Step 1: Prepare the world: start migrating a canister ID range away from
        // the source subnet.
        let mut registry = TWO_SUBNETS_REGISTRY.clone();
        registry
            .prepare_canister_migration(PrepareCanisterMigrationPayload {
                canister_id_ranges: vec![range(10, 11)],
                source_subnet: SUBNET_1,
                destination_subnet: SUBNET_2,
            })
            .unwrap();

        // Step 2: Run the code under test.
        let result = registry.merge_subnets(MergeSubnetsPayload {
            source_subnet: SUBNET_1,
            destination_subnet: SUBNET_2,
        });

        // Step 3: Verify results.
        let error_message = result.unwrap_err();
        assert!(
            error_message.contains("ongoing canister migrations"),
            "{error_message}"
        );
        assert_eq!(
            get_routing_table_entries(&registry),
            FIXTURE_ROUTING_TABLE_ENTRIES.to_vec(),
        );
    }
}
