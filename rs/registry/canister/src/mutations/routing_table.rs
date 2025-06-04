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
    canister_id_into_u64, routing_table_insert_subnet, CanisterIdRange, CanisterIdRanges,
    CanisterMigrations, RoutingTable,
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

const MAX_RANGES_PER_CANISTER_RANGES: u16 = 100;

/// Complexity O(n)
// TODO after migration runs in registry_lifecycle.rs, make this function private to this module again.
//
// TODO DO NOT MERGE This is the function that will figure out the correct sharding of canister ranges
pub(crate) fn mutations_for_canister_ranges(
    registry: &Registry,
    new_rt: &RoutingTable,
) -> Vec<RegistryMutation> {
    // Helper functions
    let range_key = |key: u64| -> Vec<u8> {
        make_canister_ranges_key(CanisterId::from_u64(key))
            .as_bytes()
            .to_vec()
    };

    let create_rt_entry =
        |range: &CanisterIdRange, subnet: &SubnetId| -> pb::routing_table::Entry {
            pb::routing_table::Entry {
                range: Some(range.into()),
                subnet_id: Some(pb_subnet_id(*subnet)),
            }
        };

    let routing_table_to_bytes = |rt: &pb::RoutingTable| -> Vec<u8> { rt.encode_to_vec() };

    // We have to use the old routing table (in canister_range_* form) in order to create the
    // diff here.
    let version = registry.latest_version();
    let (range_starts, current_shards): (Vec<u64>, BTreeMap<u64, pb::RoutingTable>) =
        get_key_family_iter_at_version(&registry, CANISTER_RANGES_PREFIX, version)
            .map(|(k, v)| {
                let bytes = hex::decode(k).unwrap();
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                let original_u64 = u64::from_be_bytes(buf);
                (original_u64, (original_u64, v))
            })
            .unzip();

    let mut new_shards = range_starts
        .iter()
        .map(|&start| {
            // Create a new shard for each range start.
            (start, pb::RoutingTable { entries: vec![] })
        })
        .collect::<BTreeMap<u64, pb::RoutingTable>>();

    for (range, subnet) in new_rt.iter() {
        let start_u64 = canister_id_into_u64(range.start);

        // find the entry in the new_shards that is closest to the start of the range in the lower direction
        let key = new_shards.range(0..=start_u64).next_back().unwrap().0;

        let rt_fragment = new_shards.get_mut(&key).unwrap();

        if rt_fragment.entries.len() >= MAX_RANGES_PER_CANISTER_RANGES as usize {
            // If the current shard has more than MAX_RANGES_PER_CANISTER_RANGES, we need to split it
            // into multiple shards.

            let new_shard = pb::RoutingTable {
                entries: vec![create_rt_entry(range, subnet)],
            };
            new_shards.insert(start_u64, new_shard);
        } else {
            // Otherwise, we just add the entry to the current shard.
            rt_fragment.entries.push(create_rt_entry(range, subnet));
        }
    }

    let mut old_shard_iterator = current_shards.iter().peekable();
    let mut new_shard_iterator = new_shards.iter().peekable();

    let mut mutations = vec![];
    loop {
        // Every branch advances one or both of the iterators, so that the loop eventually terminates
        // on (None, None).
        match (old_shard_iterator.peek(), new_shard_iterator.peek()) {
            (Some(&(o_key, old_rt_fragment)), Some(&(n_key, new_rt_fragment))) => match o_key
                .cmp(&n_key)
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
        let entries = get_key_family_iter_at_version(self, CANISTER_RANGES_PREFIX, version)
            .map(|(_, v)| v)
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
    use crate::mutations::node_management::common::get_key_family_iter;
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
                start: CanisterId::from(6001),
                end: CanisterId::from(7000),
            },
            system_subnet.into(),
        )
        .unwrap();

        let new_routing_table = pb::RoutingTable::from(rt.clone());
        let mutations = vec![upsert(
            make_routing_table_record_key().as_bytes(),
            new_routing_table.encode_to_vec(),
        )];
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(recovered, RoutingTable::new());

        // Now we are in a situation where there is no difference between what's stored in routing_table
        // and what's being saved BUT we should still generate canister_range_* records b/c they're empty
        let mutations = routing_table_into_registry_mutation(&registry, rt.clone());
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(recovered, rt);
    }

    #[test]
    fn test_routing_table_saves_as_canister_range_records_correctly() {
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
                start: CanisterId::from(6001),
                end: CanisterId::from(7000),
            },
            system_subnet.into(),
        )
        .unwrap();
        let mutations = routing_table_into_registry_mutation(&registry, rt.clone());
        registry.maybe_apply_mutation_internal(mutations);

        let recovered = registry
            .get_routing_table_from_canister_range_records_or_panic(registry.latest_version());

        assert_eq!(recovered, rt);
    }

    #[test]
    fn test_routing_table_updates_and_deletes_canister_ranges_as_expected() {
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

        let keys = get_key_family_iter::<()>(&registry, CANISTER_RANGES_PREFIX)
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        assert_eq!(keys.len(), 2);

        assert_eq!(
            keys[0],
            make_canister_ranges_key(CanisterId::from(5000))
                .strip_prefix(CANISTER_RANGES_PREFIX)
                .unwrap()
        );
        assert_eq!(
            keys[1],
            make_canister_ranges_key(CanisterId::from(6002))
                .strip_prefix(CANISTER_RANGES_PREFIX)
                .unwrap()
        );

        // Now we are going to test the mutations delete + update
        registry.maybe_apply_mutation_internal(registry.migrate_canisters_to_subnet(
            registry.latest_version(),
            vec![CanisterId::from(6001)],
            system_subnet.into(),
        ));

        let keys = get_key_family_iter::<()>(&registry, CANISTER_RANGES_PREFIX)
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        assert_eq!(keys.len(), 1);

        assert_eq!(
            keys[0],
            make_canister_ranges_key(CanisterId::from(5000))
                .strip_prefix(CANISTER_RANGES_PREFIX)
                .unwrap()
        );

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
    fn make_routing_table(ranges: Vec<((u64, u64), SubnetId)>) -> RoutingTable {
        let mut rt = RoutingTable::new();
        for ((start, end), subnet) in ranges {
            rt.insert(
                CanisterIdRange {
                    start: CanisterId::from(start),
                    end: CanisterId::from(end),
                },
                subnet,
            )
            .expect("Couldn't insert");
        }
        rt
    }

    fn make_entry(start: u64, end: u64, subnet: SubnetId) -> pb::routing_table::Entry {
        pb::routing_table::Entry {
            range: Some(pb::CanisterIdRange {
                start_canister_id: Some(CanisterId::from(start).into()),
                end_canister_id: Some(CanisterId::from(end).into()),
            }),
            subnet_id: Some(pb_subnet_id(subnet)),
        }
    }

    #[test]
    fn empty_old_and_new_yields_no_mutations() {
        let registry = invariant_compliant_registry(0);
        let new = make_routing_table(vec![]);
        let mutations = mutations_for_canister_ranges(&registry, &new);
        assert!(mutations.is_empty());
    }

    #[test]
    fn old_has_extra_range_generates_delete() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(1));
        let old = make_routing_table(vec![((10, 20), subnet)]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new = make_routing_table(vec![]);
        let muts = mutations_for_canister_ranges(&registry, &new);

        let expected = vec![delete(make_canister_ranges_key(CanisterId::from(10)))];
        assert_eq!(muts, expected);
    }

    #[test]
    fn new_has_extra_range_generates_upsert() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(2));
        let old = make_routing_table(vec![]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new = make_routing_table(vec![((30, 40), subnet)]);
        let muts = mutations_for_canister_ranges(&registry, &new);

        let value = make_entry(30, 40, subnet).encode_to_vec();

        let expected = vec![upsert(
            make_canister_ranges_key(CanisterId::from(30)),
            value,
        )];
        assert_eq!(muts, expected);
    }

    #[test]
    fn identical_range_generates_no_mutation() {
        let mut registry = invariant_compliant_registry(0);
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(3));
        let old = make_routing_table(vec![((100, 200), subnet)]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        let new = make_routing_table(vec![((100, 200), subnet)]);
        let muts = mutations_for_canister_ranges(&registry, &new);

        let expected = vec![];
        assert_eq!(muts, expected);
    }

    #[test]
    fn mixed_case_generates_delete_upsert() {
        let mut registry = invariant_compliant_registry(0);
        let s1 = SubnetId::new(PrincipalId::new_user_test_id(4));
        let s2 = SubnetId::new(PrincipalId::new_user_test_id(5));
        let s3 = SubnetId::new(PrincipalId::new_user_test_id(6));

        // old has (1,5)->s1 and (3,7)->s2
        let old = make_routing_table(vec![((1, 2), s1), ((3, 7), s2)]);
        registry.apply_mutations_for_test(mutations_for_canister_ranges(&registry, &old));

        // new has (1,5)->s1 and (4,8)->s3
        let new = make_routing_table(vec![((1, 2), s1), ((4, 8), s3)]);

        let muts = mutations_for_canister_ranges(&registry, &new);

        let value = make_entry(4, 8, s3).encode_to_vec();

        let expected = vec![
            delete(make_canister_ranges_key(CanisterId::from(3))),
            upsert(make_canister_ranges_key(CanisterId::from(4)), value),
        ];
        assert_eq!(muts, expected);
    }
}
