use crate::{common::LOG_PREFIX, pb::v1::SubnetForCanister, registry::Registry};
use std::cmp::Ordering;

use crate::mutations::node_management::common::get_key_family_iter_at_version;
use dfn_core::CanisterId;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{
    make_canister_migrations_record_key, make_canister_range_key, make_routing_table_record_key,
    CANISTER_RANGE_PREFIX,
};
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRanges, CanisterMigrations, RoutingTable,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use ic_registry_transport::{delete, upsert};
use prost::Message;
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

/// Complexity O(n)
// TODO after migration runs in registry_lifecycle.rs, make this function private to this module again.
pub(crate) fn mutations_for_canister_ranges(
    old_rt: &RoutingTable,
    new_rt: &RoutingTable,
) -> Vec<RegistryMutation> {
    // Helper functions
    let range_key = |key: (CanisterId, SubnetId)| -> Vec<u8> {
        make_canister_range_key(key.0, key.1).as_bytes().to_vec()
    };

    let create_entry = |key: (CanisterId, SubnetId), range_end: CanisterId| -> Vec<u8> {
        pb::routing_table::Entry {
            range: Some(pb::CanisterIdRange {
                start_canister_id: Some(key.0.into()),
                end_canister_id: Some(range_end.into()),
            }),
            subnet_id: Some(pb_subnet_id(key.1)),
        }
        .encode_to_vec()
    };

    // These two iterators are both sorted in the same way - by start of the range. If the sort
    // were not guaranteed the same, the below algorithm would produce incorrect results.
    let mut old_it = old_rt
        .iter()
        .map(|(range, &subnet)| ((range.start, subnet), range.end))
        .peekable();
    let mut new_it = new_rt
        .iter()
        .map(|(range, &subnet)| ((range.start, subnet), range.end))
        .peekable();

    let mut mutations = vec![];
    loop {
        // Every branch advances one or both of the iterators, so that the loop eventually terminates
        // on (None, None).
        match (old_it.peek(), new_it.peek()) {
            (Some(&(o_key, o_end)), Some(&(n_key, n_end))) => match o_key.cmp(&n_key) {
                Ordering::Less => {
                    mutations.push(delete(range_key(o_key)));
                    old_it.next();
                }
                Ordering::Greater => {
                    mutations.push(upsert(range_key(n_key), create_entry(n_key, n_end)));
                    new_it.next();
                }
                Ordering::Equal => {
                    // Only produce mutations for differences, since every mutation will take space
                    // in the registry even if the values are equivalent.
                    if o_end != n_end {
                        mutations.push(upsert(range_key(n_key), create_entry(n_key, n_end)));
                    }
                    old_it.next();
                    new_it.next();
                }
            },
            (Some(&(o_key, _)), None) => {
                mutations.push(delete(range_key(o_key)));
                old_it.next();
            }
            (None, Some(&(n_key, n_end))) => {
                mutations.push(upsert(range_key(n_key), create_entry(n_key, n_end)));
                new_it.next();
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
    let mut mutations = vec![];

    // We have to use the old routing table (in canister_range_* form) in order to create the
    // diff here.
    let old =
        registry.get_routing_table_from_canister_range_records_or_panic(registry.latest_version());
    mutations.append(&mut mutations_for_canister_ranges(&old, &routing_table));

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
    /// Get the routing table or panic on error with a message.
    pub fn get_routing_table_or_panic(&self, version: u64) -> RoutingTable {
        let RegistryValue {
            value: routing_table_bytes,
            version: _,
            deletion_marker: _,
        } = self
            .get(make_routing_table_record_key().as_bytes(), version)
            .unwrap_or_else(|| panic!("{}routing table not found in the registry.", LOG_PREFIX));

        RoutingTable::try_from(pb::RoutingTable::decode(routing_table_bytes.as_slice()).unwrap())
            .expect("failed to decode the routing table from protobuf")
    }

    pub fn get_routing_table_from_canister_range_records_or_panic(
        &self,
        version: u64,
    ) -> RoutingTable {
        let entries = get_key_family_iter_at_version(self, CANISTER_RANGE_PREFIX, version)
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
    use ic_registry_keys::CANISTER_RANGE_PREFIX;
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

        let keys = get_key_family_iter::<()>(&registry, CANISTER_RANGE_PREFIX)
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        assert_eq!(keys.len(), 2);

        assert_eq!(
            keys[0],
            make_canister_range_key(CanisterId::from(5000), system_subnet.into())
                .strip_prefix(CANISTER_RANGE_PREFIX)
                .unwrap()
        );
        assert_eq!(
            keys[1],
            make_canister_range_key(CanisterId::from(6002), system_subnet.into())
                .strip_prefix(CANISTER_RANGE_PREFIX)
                .unwrap()
        );

        // Now we are going to test the mutations delete + update
        registry.maybe_apply_mutation_internal(registry.migrate_canisters_to_subnet(
            registry.latest_version(),
            vec![CanisterId::from(6001)],
            system_subnet.into(),
        ));

        let keys = get_key_family_iter::<()>(&registry, CANISTER_RANGE_PREFIX)
            .map(|(k, _)| k)
            .collect::<Vec<_>>();

        assert_eq!(keys.len(), 1);

        assert_eq!(
            keys[0],
            make_canister_range_key(CanisterId::from(5000), system_subnet.into())
                .strip_prefix(CANISTER_RANGE_PREFIX)
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
        let old = make_routing_table(vec![]);
        let new = make_routing_table(vec![]);
        let muts = mutations_for_canister_ranges(&old, &new);
        assert!(muts.is_empty());
    }

    #[test]
    fn old_has_extra_range_generates_delete() {
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(1));
        let old = make_routing_table(vec![((10, 20), subnet)]);
        let new = make_routing_table(vec![]);
        let muts = mutations_for_canister_ranges(&old, &new);

        let expected = vec![delete(make_canister_range_key(
            CanisterId::from(10),
            subnet,
        ))];
        assert_eq!(muts, expected);
    }

    #[test]
    fn new_has_extra_range_generates_upsert() {
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(2));
        let old = make_routing_table(vec![]);
        let new = make_routing_table(vec![((30, 40), subnet)]);
        let muts = mutations_for_canister_ranges(&old, &new);

        let value = make_entry(30, 40, subnet).encode_to_vec();

        let expected = vec![upsert(
            make_canister_range_key(CanisterId::from(30), subnet),
            value,
        )];
        assert_eq!(muts, expected);
    }

    #[test]
    fn identical_range_generates_no_mutation() {
        let subnet = SubnetId::new(PrincipalId::new_user_test_id(3));
        let old = make_routing_table(vec![((100, 200), subnet)]);
        let new = make_routing_table(vec![((100, 200), subnet)]);
        let muts = mutations_for_canister_ranges(&old, &new);

        let expected = vec![];
        assert_eq!(muts, expected);
    }

    #[test]
    fn mixed_case_generates_delete_upsert() {
        let s1 = SubnetId::new(PrincipalId::new_user_test_id(4));
        let s2 = SubnetId::new(PrincipalId::new_user_test_id(5));
        let s3 = SubnetId::new(PrincipalId::new_user_test_id(6));

        // old has (1,5)->s1 and (3,7)->s2
        let old = make_routing_table(vec![((1, 2), s1), ((3, 7), s2)]);
        // new has (1,5)->s1 and (4,8)->s3
        let new = make_routing_table(vec![((1, 2), s1), ((4, 8), s3)]);

        let muts = mutations_for_canister_ranges(&old, &new);

        let value = make_entry(4, 8, s3).encode_to_vec();

        let expected = vec![
            delete(make_canister_range_key(CanisterId::from(3), s2)),
            upsert(make_canister_range_key(CanisterId::from(4), s3), value),
        ];
        assert_eq!(muts, expected);
    }
}
