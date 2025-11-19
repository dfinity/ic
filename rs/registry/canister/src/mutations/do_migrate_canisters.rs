use crate::registry::{Registry, Version};
use candid::{CandidType, Deserialize};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use serde::Serialize;

impl Registry {
    pub fn do_migrate_canisters(
        &mut self,
        payload: MigrateCanistersPayload,
    ) -> MigrateCanistersResponse {
        let (canister_ids, target_subnet_id) =
            self.validate_payload(payload).expect("Invalid payload");

        self.maybe_apply_mutation_internal(self.migrate_canisters_to_subnet(
            self.latest_version(),
            canister_ids,
            target_subnet_id,
        ));

        MigrateCanistersResponse {
            registry_version: self.latest_version(),
        }
    }

    fn validate_payload(
        &self,
        payload: MigrateCanistersPayload,
    ) -> Result<(Vec<CanisterId>, SubnetId), String> {
        let MigrateCanistersPayload {
            canister_ids,
            target_subnet_id,
        } = payload;

        let canister_ids = canister_ids
            .into_iter()
            .map(|canister_id| {
                CanisterId::try_from_principal_id(canister_id)
                    .map_err(|e| format!("Invalid canister id: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let target_subnet_id = SubnetId::new(target_subnet_id);
        self.get_subnet(target_subnet_id, self.latest_version())?;

        Ok((canister_ids, target_subnet_id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize, Serialize)]
pub struct MigrateCanistersPayload {
    canister_ids: Vec<PrincipalId>,
    target_subnet_id: PrincipalId,
}

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize, Serialize)]
pub struct MigrateCanistersResponse {
    registry_version: Version,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::test_helpers::{
        invariant_compliant_registry, prepare_registry_with_nodes,
        registry_create_subnet_with_nodes,
    };
    use crate::mutations::routing_table::routing_table_into_registry_mutation;
    use ic_base_types::CanisterId;
    use ic_base_types::PrincipalId;
    use ic_registry_routing_table::CanisterIdRange;
    use ic_registry_routing_table::RoutingTable;

    // We only need a basic test, because the rest of the logic for this is tested in the tests
    // for migrating canister ranges, which is already supported.
    #[test]
    fn test_basic_migrate_canisters() {
        // We create an invariant compliant registry, then we migrate a single canister
        // to a new subnet, and we check that the Routing table has the correct ranges at that point.

        let mut registry = invariant_compliant_registry(0);
        let system_subnet =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets.first().unwrap())
                .unwrap();

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 6);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let target_subnet_id =
            registry_create_subnet_with_nodes(&mut registry, &node_ids_and_dkg_pks, &[0, 1, 2, 3]);

        let mut initial_routing_table = RoutingTable::new();
        initial_routing_table
            .insert(
                CanisterIdRange {
                    start: CanisterId::from(0),
                    end: CanisterId::from(255),
                },
                system_subnet.into(),
            )
            .unwrap();

        registry.apply_mutations_for_test(routing_table_into_registry_mutation(
            &registry,
            initial_routing_table.clone(),
        ));

        let first_saved_table = registry.get_routing_table_or_panic(registry.latest_version());
        assert_eq!(first_saved_table, initial_routing_table);

        let request = MigrateCanistersPayload {
            canister_ids: vec![PrincipalId::from(CanisterId::from(100))],
            target_subnet_id: target_subnet_id.get(),
        };

        let response = registry.do_migrate_canisters(request);

        // currently just empty response.
        assert_eq!(
            MigrateCanistersResponse {
                registry_version: registry.latest_version()
            },
            response
        );

        let updated_routing_table = registry.get_routing_table_or_panic(registry.latest_version());

        // We expect the range to be split into 3 ranges, with the middle one being a single-canister-id range
        // and the others pointing at the system subnet as before.
        let mut expected_routing_table = RoutingTable::new();
        expected_routing_table
            .insert(
                CanisterIdRange {
                    start: CanisterId::from_u64(0),
                    end: CanisterId::from_u64(99),
                },
                system_subnet.into(),
            )
            .unwrap();
        expected_routing_table
            .insert(
                CanisterIdRange {
                    start: CanisterId::from_u64(100),
                    end: CanisterId::from_u64(100),
                },
                target_subnet_id,
            )
            .unwrap();
        expected_routing_table
            .insert(
                CanisterIdRange {
                    start: CanisterId::from_u64(101),
                    end: CanisterId::from_u64(255),
                },
                system_subnet.into(),
            )
            .unwrap();
        assert_eq!(updated_routing_table, expected_routing_table);
    }
}
