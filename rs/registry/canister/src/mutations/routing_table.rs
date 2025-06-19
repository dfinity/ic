use crate::mutations::node_management::common::get_key_family_iter_at_version;
use crate::{common::LOG_PREFIX, pb::v1::SubnetForCanister, registry::Registry};
use dfn_core::CanisterId;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{
    make_canister_migrations_record_key, make_canister_ranges_key, make_routing_table_record_key,
    CANISTER_RANGES_PREFIX,
};
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRange, CanisterIdRanges, CanisterMigrations,
    RoutingTable,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use ic_registry_transport::{delete, upsert};
use prost::Message;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::TryFrom;

#[derive(Eq, PartialEq, Debug)]
pub enum GetSubnetForCanisterError {
    InvalidCanisterId,
    NoSubnetAssigned,
}

impl std::fmt::Display for GetSubnetForCanisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetSubnetForCanisterError::InvalidCanisterId => {
                write!(f, "Invalid canister ID.")
            }
            GetSubnetForCanisterError::NoSubnetAssigned => {
                write!(f, "Canister is not assigned to any subnet.")
            }
        }
    }
}

const MAX_RANGES_PER_CANISTER_RANGES: u16 = 20;

/// Complexity O(n)
// TODO after migration runs in registry_lifecycle.rs, make this function private to this module again.
pub(crate) fn mutations_for_canister_ranges(
    registry: &Registry,
    new_rt: &RoutingTable,
) -> Vec<RegistryMutation> {
    // Helper functions
    let range_key = |canister_id: CanisterId| -> Vec<u8> {
        make_canister_ranges_key(canister_id).as_bytes().to_vec()
    };

    let create_rt_entry =
        |range: &CanisterIdRange, subnet: &SubnetId| -> pb::routing_table::Entry {
            pb::routing_table::Entry {
                range: Some((*range).into()),
                subnet_id: Some(pb_subnet_id(*subnet)),
            }
        };

    // We have to use the old routing table (in canister_range_* form) in order to create the
    // diff here.
    // We create the structure of the new shards from the current structure without values, as the values
    // will be populated below.  This allows us to compare what will be saved and only write changes.
    // This prevents unnecessary rearrangements of shards which could have cascading effects,
    // (i.e. each shard shifts right by just one entry, causing all the old entries to be deleted
    // and new entries to be rewritten).
    // but populate it with the routing table
    let version = registry.latest_version();
    let (mut new_shards, current_shards): (
        BTreeMap<CanisterId, pb::RoutingTable>,
        BTreeMap<CanisterId, pb::RoutingTable>,
    ) = get_key_family_iter_at_version(registry, CANISTER_RANGES_PREFIX, version)
        .map(|(k, v)| {
            let bytes = hex::decode(k).unwrap();
            let canister_id = CanisterId::try_from(bytes).expect("Invalid CanisterId in range key");
            (
                (canister_id, pb::RoutingTable { entries: vec![] }),
                (canister_id, v),
            )
        })
        .unzip();

    let zero_id = CanisterId::from_u64(0);
    // If we don't have any routing table fragments in the new_shards, we need to create a default one to
    // hold all the ranges until a split occurs.
    new_shards
        .entry(zero_id)
        .or_insert_with(|| pb::RoutingTable { entries: vec![] });

    for (range, subnet) in new_rt.iter() {
        let range_start = range.start;

        // find the entry in the new_shards that is closest to the start of the range in the lower direction
        // Because we always ensure there's a CanisterId(0) shard, this cannot fail.
        let key = *(new_shards
            .range(zero_id..=range_start)
            .next_back()
            .unwrap()
            .0);

        let rt_fragment = new_shards.get_mut(&key).unwrap();

        if rt_fragment.entries.len() == MAX_RANGES_PER_CANISTER_RANGES as usize {
            // If the current shard has more than MAX_RANGES_PER_CANISTER_RANGES, we need to split it
            // into multiple shards.
            let mut entries = rt_fragment
                .entries
                .split_off(MAX_RANGES_PER_CANISTER_RANGES as usize / 2);

            entries.push(create_rt_entry(range, subnet));

            let shard_key = entries
                .first()
                .and_then(|e| e.range.as_ref())
                .and_then(|range| range.start_canister_id.as_ref())
                .and_then(|canister_id| canister_id.principal_id.as_ref())
                .map(|principal| {
                    CanisterId::try_from(principal.raw.clone())
                        .expect("Invalid canisterId in range key")
                })
                // This expect is safe because we push at least one entry right before this.
                .expect("Invalid Range found in routing table entry.");
            let new_shard = pb::RoutingTable { entries };

            new_shards.insert(shard_key, new_shard);
        } else {
            // Otherwise, we just add the entry to the current shard.
            rt_fragment.entries.push(create_rt_entry(range, subnet));
        }
    }

    let mut old_shard_iterator = current_shards.iter().peekable();
    let mut new_shard_iterator = new_shards
        .iter()
        .filter(|(_, rt)| !rt.entries.is_empty())
        .peekable();

    let mut mutations = vec![];
    loop {
        // Every branch advances one or both of the iterators, so that the loop eventually terminates
        // on (None, None).
        match (old_shard_iterator.peek(), new_shard_iterator.peek()) {
            (Some(&(o_key, old_rt_fragment)), Some(&(n_key, new_rt_fragment))) => match o_key
                .cmp(n_key)
            {
                Ordering::Less => {
                    mutations.push(delete(range_key(*o_key)));
                    old_shard_iterator.next();
                }
                Ordering::Greater => {
                    mutations.push(upsert(range_key(*n_key), new_rt_fragment.encode_to_vec()));
                    new_shard_iterator.next();
                }
                Ordering::Equal => {
                    // Only produce mutations for differences, since every mutation will take space
                    // in the registry even if the values are equivalent.
                    if old_rt_fragment != new_rt_fragment {
                        mutations.push(upsert(range_key(*n_key), new_rt_fragment.encode_to_vec()));
                    }
                    old_shard_iterator.next();
                    new_shard_iterator.next();
                }
            },
            (Some(&(o_key, _)), None) => {
                mutations.push(delete(range_key(*o_key)));
                old_shard_iterator.next();
            }
            (None, Some(&(n_key, new_rt_fragment))) => {
                mutations.push(upsert(range_key(*n_key), new_rt_fragment.encode_to_vec()));
                new_shard_iterator.next();
            }
            (None, None) => break,
        }
    }

    mutations
}

fn pb_subnet_id(subnet_id: SubnetId) -> ic_protobuf::types::v1::SubnetId {
    ic_protobuf::types::v1::SubnetId {
        principal_id: Some(ic_protobuf::types::v1::PrincipalId {
            raw: subnet_id.get().as_slice().to_vec(),
        }),
    }
}

pub(crate) fn routing_table_into_registry_mutation(
    registry: &Registry,
    routing_table: RoutingTable,
) -> Vec<RegistryMutation> {
    let mut mutations = mutations_for_canister_ranges(registry, &routing_table);

    let new_routing_table = pb::RoutingTable::from(routing_table);
    mutations.push(upsert(
        make_routing_table_record_key().as_bytes(),
        new_routing_table.encode_to_vec(),
    ));

    mutations
}

/// Returns the given `CanisterMigrations` as a registry mutation of the given type.
fn canister_migrations_into_registry_mutation(
    canister_migrations: CanisterMigrations,
    mutation_type: i32,
) -> RegistryMutation {
    let canister_migrations = pb::CanisterMigrations::from(canister_migrations);
    let mut buf = vec![];
    canister_migrations.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type,
        key: make_canister_migrations_record_key().as_bytes().to_vec(),
        value: buf,
    }
}

impl Registry {
    pub fn get_routing_table(&self, version: u64) -> Result<RoutingTable, String> {
        let RegistryValue {
            value: routing_table_bytes,
            version: _,
            deletion_marker: _,
        } = self
            .get(make_routing_table_record_key().as_bytes(), version)
            .ok_or(format!(
                "{}routing table not found in the registry.",
                LOG_PREFIX
            ))?;

        RoutingTable::try_from(pb::RoutingTable::decode(routing_table_bytes.as_slice()).unwrap())
            .map_err(|e| {
                format!(
                    "{}failed to decode the routing table from protobuf: {}",
                    LOG_PREFIX, e
                )
            })
    }
    /// Get the routing table or panic on error with a message.
    pub fn get_routing_table_or_panic(&self, version: u64) -> RoutingTable {
        self.get_routing_table(version)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    pub fn get_routing_table_from_canister_range_records_or_panic(
        &self,
        version: u64,
    ) -> RoutingTable {
        let entries = get_key_family_iter_at_version::<pb::RoutingTable>(
            self,
            CANISTER_RANGES_PREFIX,
            version,
        )
        .flat_map(|(_, v)| v.entries)
        .collect::<Vec<pb::routing_table::Entry>>();

        RoutingTable::try_from(pb::RoutingTable { entries }).unwrap()
    }

    /// Applies the given mutation to the routing table at the specified version.
    fn modify_routing_table(
        &self,
        version: u64,
        f: impl FnOnce(&mut RoutingTable),
    ) -> Vec<RegistryMutation> {
        let mut routing_table = self.get_routing_table_or_panic(version);
        f(&mut routing_table);
        routing_table_into_registry_mutation(self, routing_table)
    }

    pub fn migrate_canisters_to_subnet(
        &self,
        version: u64,
        canister_ids: Vec<CanisterId>,
        subnet_id: SubnetId,
    ) -> Vec<RegistryMutation> {
        self.modify_routing_table(version, |routing_table| {
            for canister_id in canister_ids {
                routing_table.assign_canister(canister_id, subnet_id);
            }
            routing_table.optimize();
        })
    }

    /// Handle adding a subnet to the routing table.
    pub fn add_subnet_to_routing_table(
        &self,
        version: u64,
        subnet_id_to_add: SubnetId,
    ) -> Vec<RegistryMutation> {
        self.modify_routing_table(version, |routing_table| {
            routing_table_insert_subnet(routing_table, subnet_id_to_add).unwrap();
        })
    }

    /// Handle removing a subnet from the routing table.
    pub fn remove_subnet_from_routing_table(
        &self,
        version: u64,
        subnet_id_to_remove: SubnetId,
    ) -> Vec<RegistryMutation> {
        self.modify_routing_table(version, |routing_table| {
            routing_table.remove_subnet(subnet_id_to_remove);
        })
    }

    /// Makes a registry mutation that remaps the specified canister ID range to
    /// another subnet.
    pub fn reroute_canister_ranges_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        destination: SubnetId,
    ) -> Vec<RegistryMutation> {
        self.modify_routing_table(version, |routing_table| {
            routing_table
                .assign_ranges(canister_id_ranges, destination)
                .unwrap();
            routing_table.optimize();
        })
    }

    /// Retrieves the canister migrations if the key exists.
    pub fn get_canister_migrations(&self, version: u64) -> Option<CanisterMigrations> {
        self.get(make_canister_migrations_record_key().as_bytes(), version)
            .map(|registry_value| {
                CanisterMigrations::try_from(
                    pb::CanisterMigrations::decode(registry_value.value.as_slice()).unwrap(),
                )
                .expect("failed to decode the canister migrations from protobuf")
            })
    }

    /// Creates a mutation that applies the given change to `canister_mutations`
    /// at the specified version, creating the entry if it doesn't exist.
    fn modify_canister_migrations(
        &self,
        version: u64,
        f: impl FnOnce(&mut CanisterMigrations),
        mutation_type: i32,
    ) -> RegistryMutation {
        let mut canister_migrations = self.get_canister_migrations(version).unwrap_or_default();

        f(&mut canister_migrations);
        canister_migrations_into_registry_mutation(canister_migrations, mutation_type)
    }

    /// Makes a registry mutation that modifies the canister migrations.
    pub fn migrate_canister_ranges_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        source: SubnetId,
        destination: SubnetId,
    ) -> RegistryMutation {
        // The registry mutation type is set to `Upsert` so that the mutation is still valid
        // when canister migrations are not present in the registry.
        self.modify_canister_migrations(
            version,
            |canister_migrations| {
                canister_migrations
                    .insert_ranges(canister_id_ranges, source, destination)
                    .unwrap();
            },
            registry_mutation::Type::Upsert as i32,
        )
    }

    /// Makes a registry mutation that removes all provided entries from `canister_migrations`.
    pub fn remove_canister_migrations_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        migration_trace: Vec<SubnetId>,
    ) -> RegistryMutation {
        // The registry mutation type is set to `Update` to prevent the removal
        // when canister migrations are not present in the registry.
        self.modify_canister_migrations(
            version,
            |canister_migrations| {
                canister_migrations
                    .remove_ranges(canister_id_ranges, migration_trace)
                    .unwrap();
            },
            registry_mutation::Type::Update as i32,
        )
    }

    pub fn get_subnet_for_canister(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<SubnetForCanister, GetSubnetForCanisterError> {
        let latest_version = self.latest_version();
        let routing_table = self.get_routing_table_or_panic(latest_version);
        let canister_id = CanisterId::try_from(*principal_id)
            .map_err(|_| GetSubnetForCanisterError::InvalidCanisterId)?;

        match routing_table
            .lookup_entry(canister_id)
            .map(|(_, subnet_id)| subnet_id.get())
        {
            Some(subnet_id) => Ok(SubnetForCanister {
                subnet_id: Some(subnet_id),
            }),
            None => Err(GetSubnetForCanisterError::NoSubnetAssigned),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;

    use super::*;
    use crate::mutations::node_management::common::get_key_family;
    use assert_matches::assert_matches;
    use ic_base_types::CanisterId;
    use ic_registry_keys::CANISTER_RANGES_PREFIX;
    use ic_registry_routing_table::CanisterIdRange;

    #[test]
    fn test_get_subnet_for_canister() {
        let mut registry = invariant_compliant_registry(0);
        let system_subnet =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets.first().unwrap())
                .unwrap();

        let mut rt = RoutingTable::new();
        rt.insert(
            CanisterIdRange {
                start: CanisterId::from(0),
                end: CanisterId::from(255),
            },
            system_subnet.into(),
        )
        .unwrap();
        let mutations = routing_table_into_registry_mutation(&registry, rt);
        registry.maybe_apply_mutation_internal(mutations);

        assert_eq!(
            registry
                .get_subnet_for_canister(&CanisterId::from(5).get())
                .unwrap()
                .subnet_id
                .unwrap(),
            system_subnet
        );

        assert_matches!(
            registry
                .get_subnet_for_canister(&CanisterId::from(256).get())
                .unwrap_err(),
            GetSubnetForCanisterError::NoSubnetAssigned
        );

        assert_matches!(
            registry
                .get_subnet_for_canister(&CanisterId::from(999).get())
                .unwrap_err(),
            GetSubnetForCanisterError::NoSubnetAssigned
        );

        // GetSubnetForCanisterError::CanisterIdConversion currently not reachable - CanisterId::try_from() always succeeds
    }

    #[test]
    fn test_routing_table_saves_as_canister_range_records_on_first_invocation_correctly() {
        let mut registry = invariant_compliant_registry(0);
        let system_subnet =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets.first().unwrap())
                .unwrap();

        let mut original = RoutingTable::new();
        original
            .insert(
                CanisterIdRange {
                    start: CanisterId::from(5000),
                    end: CanisterId::from(6000),
                },
                system_subnet.into(),
            )
            .unwrap();
        original
            .insert(
                CanisterIdRange {
                    start: CanisterId::from(6001),
                    end: CanisterId::from(7000),
                },
                system_subnet.into(),
            )
            .unwrap();

        let new_routing_table = pb::RoutingTable::from(original.clone());
        let mutations = vec![upsert(
            make_routing_table_record_key().as_bytes(),
            new_routing_table.encode_to_vec(),
        )];
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(recovered, RoutingTable::new());

        // Now we are in a situation where there is no difference between what's stored under the
        // `routing_table` key and what's being saved BUT we should still generate canister_ranges_*
        // records b/c they're empty
        let mutations = routing_table_into_registry_mutation(&registry, original.clone());
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(recovered, original);
    }

    #[test]
    fn test_routing_table_updates_and_deletes_entries_as_expected() {
        let mut registry = invariant_compliant_registry(0);
        let system_subnet =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets.first().unwrap())
                .unwrap();

        let mut rt = RoutingTable::new();
        rt.insert(
            CanisterIdRange {
                start: CanisterId::from(5000),
                end: CanisterId::from(6000),
            },
            system_subnet.into(),
        )
        .unwrap();
        rt.insert(
            CanisterIdRange {
                start: CanisterId::from(6002),
                end: CanisterId::from(7000),
            },
            system_subnet.into(),
        )
        .unwrap();

        // We are testing the mutation to create new ranges
        let mutations = routing_table_into_registry_mutation(&registry, rt.clone());
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());
        assert_eq!(recovered, rt);

        // Now we are going to test the mutations delete + update
        registry.maybe_apply_mutation_internal(registry.migrate_canisters_to_subnet(
            registry.latest_version(),
            vec![CanisterId::from(6001)],
            system_subnet.into(),
        ));

        let newly_recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(
            newly_recovered,
            RoutingTable::try_from(pb::RoutingTable {
                entries: vec![pb::routing_table::Entry {
                    range: Some(pb::CanisterIdRange {
                        start_canister_id: Some(CanisterId::from(5000).into()),
                        end_canister_id: Some(CanisterId::from(7000).into()),
                    }),
                    subnet_id: Some(pb_subnet_id(SubnetId::from(system_subnet))),
                }],
            })
            .unwrap()
        );
    }

    /// Helper to build a RoutingTable from a Vec of ((start, end), subnet_id)
    fn rt_from_ranges(ranges: Vec<((u64, u64), SubnetId)>) -> RoutingTable {
        let pb_rt = shard_pb_rt(ranges);
        RoutingTable::try_from(pb_rt).unwrap()
    }

    /// Given a list of (start,end,subnet), spit back a `pb::RoutingTable` fragment.
    fn shard_pb_rt(ranges: Vec<((u64, u64), SubnetId)>) -> pb::RoutingTable {
        let mut rt = pb::RoutingTable {
            entries: Vec::new(),
        };
        for ((s, e), subnet) in ranges {
            let entry = pb::routing_table::Entry {
                range: Some(pb::CanisterIdRange {
                    start_canister_id: Some(CanisterId::from(s).into()),
                    end_canister_id: Some(CanisterId::from(e).into()),
                }),
                subnet_id: Some(pb_subnet_id(subnet)),
            };
            rt.entries.push(entry);
        }
        rt
    }

    #[allow(clippy::type_complexity)]
    fn shards(shards: Vec<(u64, Vec<((u64, u64), SubnetId)>)>) -> Vec<(u64, pb::RoutingTable)> {
        shards
            .into_iter()
            .map(|(start, ranges)| {
                let rt = shard_pb_rt(ranges);
                (start, rt)
            })
            .collect()
    }

    fn rt_from_shards(shards: &[(u64, pb::RoutingTable)]) -> RoutingTable {
        let entries = shards
            .iter()
            .flat_map(|(_, rt_proto)| rt_proto.entries.clone())
            .collect();

        RoutingTable::try_from(pb::RoutingTable { entries }).unwrap()
    }

    // This helper lets us create artificial shards for testing that otherwise
    // would not be created by the routing table saving logic.
    fn apply_shards_to_registry(registry: &mut Registry, shards: &[(u64, pb::RoutingTable)]) {
        let mutations: Vec<RegistryMutation> = shards
            .iter()
            .map(|(start, rt)| {
                upsert(
                    make_canister_ranges_key(CanisterId::from(*start)),
                    rt.encode_to_vec(),
                )
            })
            .collect();

        registry.apply_mutations_for_test(mutations);
    }

    fn make_rt_entry_definitions(
        count_range: impl Iterator<Item = u64>,
        entries_per_range: u64,
    ) -> Vec<((u64, u64), SubnetId)> {
        count_range
            .map(|i| {
                (
                    (
                        i * entries_per_range,
                        i * entries_per_range + entries_per_range - 1,
                    ),
                    SubnetId::new(PrincipalId::new_user_test_id(i)),
                )
            })
            .collect()
    }

    fn compare_rt_mutations(expected: Vec<RegistryMutation>, actual: Vec<RegistryMutation>) {
        let expected_keys = expected
            .iter()
            .map(|m| std::str::from_utf8(m.key.as_slice()).unwrap())
            .collect::<Vec<_>>();
        let actual_keys = actual
            .iter()
            .map(|m| std::str::from_utf8(m.key.as_slice()).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(expected_keys, actual_keys);
        for (e, a) in expected.iter().zip(actual.iter()) {
            let expected_key = std::str::from_utf8(e.key.as_slice()).unwrap();
            let actual_key = std::str::from_utf8(a.key.as_slice()).unwrap();
            assert_eq!(expected_key, actual_key);

            let e_routing_table = pb::RoutingTable::decode(e.value.as_slice())
                .expect("Failed to decode expected routing table");
            let a_routing_table = pb::RoutingTable::decode(a.value.as_slice())
                .expect("Failed to decode actual routing table");
            assert_eq!(
                e_routing_table, a_routing_table,
                "Comparison of tables for key {} failed",
                actual_key
            );

            assert_eq!(e.mutation_type, a.mutation_type);
        }
    }

    #[test]
    fn empty_old_and_new_yields_no_mutations() {
        let mut registry = invariant_compliant_registry(0);
        let old = rt_from_shards(&[]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let entries = get_key_family::<pb::RoutingTable>(&registry, CANISTER_RANGES_PREFIX);
        assert!(entries.is_empty());

        let new = rt_from_shards(&[]);
        let mutations = mutations_for_canister_ranges(&registry, &new);
        assert!(mutations.is_empty());

        // should not panic, even with nothing written to the registry
        let _rt = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());
    }

    #[test]
    fn old_has_extra_range_generates_delete() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(1));
        let old_shards = shards(vec![(0, vec![((10, 20), subnet)])]);
        let old = rt_from_shards(&old_shards);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new = rt_from_shards(&[]);
        let mutations = mutations_for_canister_ranges(&registry, &new);

        let expected = vec![delete(make_canister_ranges_key(CanisterId::from(0)))];
        compare_rt_mutations(expected, mutations);
    }

    #[test]
    fn up_to_limit_all_entries_are_in_same_table() {
        let mut registry = invariant_compliant_registry(0);
        let old = rt_from_shards(&[]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new_ranges = make_rt_entry_definitions(1..=20, 10);
        let new = rt_from_ranges(new_ranges);
        let mutations = mutations_for_canister_ranges(&registry, &new);

        let expected_pb_rt = pb::RoutingTable::from(new);

        let expected = vec![upsert(
            make_canister_ranges_key(CanisterId::from(0)),
            expected_pb_rt.encode_to_vec(),
        )];
        compare_rt_mutations(expected, mutations);
    }

    #[test]
    fn new_has_enough_extra_ranges_generates_upsert_with_new_range() {
        let mut registry = invariant_compliant_registry(0);
        let old = rt_from_ranges(vec![]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new_ranges = make_rt_entry_definitions(1..=21, 10);
        let new = rt_from_ranges(new_ranges);
        let mutations = mutations_for_canister_ranges(&registry, &new);

        let shard_1 = shard_pb_rt(make_rt_entry_definitions(1..=10, 10));
        let shard_2 = shard_pb_rt(make_rt_entry_definitions(11..=21, 10));

        let expected = vec![
            upsert(
                make_canister_ranges_key(CanisterId::from(0)),
                shard_1.encode_to_vec(),
            ),
            upsert(
                make_canister_ranges_key(CanisterId::from(110)),
                shard_2.encode_to_vec(),
            ),
        ];

        compare_rt_mutations(expected, mutations);
    }

    #[test]
    fn identical_range_generates_no_mutation() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(3));
        let old = rt_from_ranges(vec![((100, 200), subnet)]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new = rt_from_ranges(vec![((100, 200), subnet)]);
        let mutations = mutations_for_canister_ranges(&registry, &new);

        let expected = vec![];
        compare_rt_mutations(expected, mutations);
    }

    #[test]
    fn mutations_for_canister_ranges_can_create_a_0_canister_range_when_needed() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(3));
        let subnet_b = SubnetId::new(PrincipalId::new_user_test_id(4));
        let initial_shards = shards(vec![(1, vec![((1, 200), subnet)])]);
        apply_shards_to_registry(&mut registry, &initial_shards);

        let new_rt = rt_from_shards(&shards(vec![
            (0, vec![((0, 0), subnet_b)]),
            (1, vec![((1, 200), subnet)]),
        ]));

        // If we try to create a routing table without 0 canister range, it should panic.
        let mutations = mutations_for_canister_ranges(&registry, &new_rt);

        let expected = vec![upsert(
            make_canister_ranges_key(CanisterId::from(0)),
            shard_pb_rt(vec![((0, 0), subnet_b)]).encode_to_vec(),
        )];
        compare_rt_mutations(expected, mutations);
    }

    #[test]
    fn mixed_case_generates_delete_upsert() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(1));
        let old_shards = shards(vec![
            (0, make_rt_entry_definitions(0..=10, 10)),
            (150, vec![((150, 199), subnet)]),
            (200, make_rt_entry_definitions(20..=40, 10)),
        ]);
        apply_shards_to_registry(&mut registry, &old_shards);

        let new_shards = shards(vec![
            (0, make_rt_entry_definitions(0..=11, 10)),
            (110, vec![]),
            (200, make_rt_entry_definitions(20..=41, 10)),
        ]);
        let new = rt_from_shards(&new_shards);
        // Note, the shards are not passed in directly, so the logic has to work by figuring out
        // what changes given the existing shards it ought to make.
        let mutations = mutations_for_canister_ranges(&registry, &new);

        let expected_shard_1 = shard_pb_rt(make_rt_entry_definitions(0..=11, 10));
        let expected_shard_2 = shard_pb_rt(make_rt_entry_definitions(20..=29, 10));
        let expected_shard_3 = shard_pb_rt(make_rt_entry_definitions(30..=41, 10));

        let expected = vec![
            upsert(
                make_canister_ranges_key(CanisterId::from(0)),
                expected_shard_1.encode_to_vec(),
            ),
            delete(make_canister_ranges_key(CanisterId::from(150))),
            upsert(
                make_canister_ranges_key(CanisterId::from(200)),
                expected_shard_2.encode_to_vec(),
            ),
            upsert(
                make_canister_ranges_key(CanisterId::from(300)),
                expected_shard_3.encode_to_vec(),
            ),
        ];
        compare_rt_mutations(expected, mutations);
    }
}
