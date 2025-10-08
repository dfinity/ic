use crate::registry::{Registry, Version};
use candid::CandidType;
use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_registry_routing_table::{
    CanisterIdRange, CanisterIdRanges, WellFormedError, are_disjoint, is_subset_of,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

const SUPPORTED_SUBNET_TYPES: [SubnetType; 2] =
    [SubnetType::Application, SubnetType::VerifiedApplication];

/// The argument for the `prepare_canister_migration` update call.
#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct PrepareCanisterMigrationPayload {
    /// The list of canister ID ranges to be added into canister migrations.
    pub canister_id_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    pub source_subnet: SubnetId,
    /// The new destination for the canister ID ranges.
    pub destination_subnet: SubnetId,
}

#[derive(Debug)]
pub enum PrepareCanisterMigrationError {
    SubnetRecordError(String),
    DisallowedSubnetType(SubnetId, Option<SubnetType>),
    SubnetIsSigningSubnet(SubnetId),
    SubnetSizesMismatch(
        /*source size=*/ usize,
        /*destination size=*/ usize,
    ),
    SubnetTypesMismatch(Option<SubnetType>, Option<SubnetType>),
    CanisterIdsNotWellFormed(WellFormedError),
    UnhostedCanisterIds,
    CanisterIdsAlreadyBeingMigrated(CanisterIdRanges),
}

impl Registry {
    /// Adds new entries to `canister_migrations`.
    ///
    /// Validates the payload and applies the mutation derived from the payload
    /// to the registry.
    pub fn prepare_canister_migration(
        &mut self,
        payload: PrepareCanisterMigrationPayload,
    ) -> Result<(), PrepareCanisterMigrationError> {
        // Check if the canister ID ranges are well formed.
        let ranges_to_migrate = CanisterIdRanges::try_from(payload.canister_id_ranges)
            .map_err(PrepareCanisterMigrationError::CanisterIdsNotWellFormed)?;

        let source_subnet_id = payload.source_subnet;
        let destination_subnet_id = payload.destination_subnet;

        let version = self.latest_version();

        let source_subnet_record = self
            .get_subnet(source_subnet_id, version)
            .map_err(PrepareCanisterMigrationError::SubnetRecordError)?;
        let destination_subnet_record = self
            .get_subnet(destination_subnet_id, version)
            .map_err(PrepareCanisterMigrationError::SubnetRecordError)?;

        let routing_table = self.get_routing_table_or_panic(version);
        let source_subnet_ranges = routing_table.ranges(source_subnet_id);

        validate_subnets(
            source_subnet_id,
            &source_subnet_record,
            destination_subnet_id,
            &destination_subnet_record,
        )?;
        self.validate_canisters(&source_subnet_ranges, &ranges_to_migrate, version)?;

        self.maybe_apply_mutation_internal(vec![self.migrate_canister_ranges_mutation(
            version,
            ranges_to_migrate,
            source_subnet_id,
            destination_subnet_id,
        )]);

        Ok(())
    }

    /// Validates that the requested canister id ranges to be migrated satisfy the following
    /// conditions:
    /// 1. All canisters are hosted by the source subnet,
    /// 2. None of the canisters are already being migrated.
    fn validate_canisters(
        &self,
        source_subnet_ranges: &CanisterIdRanges,
        ranges_to_migrate: &CanisterIdRanges,
        version: Version,
    ) -> Result<(), PrepareCanisterMigrationError> {
        // Check if all the canister ID ranges to be migrated are from the source subnet.
        if !is_subset_of(ranges_to_migrate.iter(), source_subnet_ranges.iter()) {
            return Err(PrepareCanisterMigrationError::UnhostedCanisterIds);
        }

        // Check if the canister ID ranges to be migrated are NOT in active canister migration.
        if self
            .get_canister_migrations(version)
            .is_some_and(|canister_migrations| {
                !are_disjoint(canister_migrations.ranges(), ranges_to_migrate.iter())
            })
        {
            return Err(
                PrepareCanisterMigrationError::CanisterIdsAlreadyBeingMigrated(
                    ranges_to_migrate.clone(),
                ),
            );
        }

        Ok(())
    }
}

/// Validates that the subnets satisfy the following conditions:
/// 1. Both subnets have the same size,
/// 2. Both subnets have the same type,
/// 3. Neither of the subnets is a signing subnet, and
/// 4. Both subnets are Application subnets.
fn validate_subnets(
    source_subnet_id: SubnetId,
    source_subnet_record: &SubnetRecord,
    destination_subnet_id: SubnetId,
    destination_subnet_record: &SubnetRecord,
) -> Result<(), PrepareCanisterMigrationError> {
    validate_subnet(source_subnet_id, source_subnet_record)?;
    validate_subnet(destination_subnet_id, destination_subnet_record)?;
    validate_subnets_consistency(source_subnet_record, destination_subnet_record)?;

    Ok(())
}

fn validate_subnet(
    subnet_id: SubnetId,
    subnet_record: &SubnetRecord,
) -> Result<(), PrepareCanisterMigrationError> {
    if !SUPPORTED_SUBNET_TYPES
        .iter()
        .any(|allowed| (*allowed as i32) == subnet_record.subnet_type)
    {
        return Err(PrepareCanisterMigrationError::DisallowedSubnetType(
            subnet_id,
            SubnetType::try_from(subnet_record.subnet_type).ok(),
        ));
    }

    if subnet_record
        .chain_key_config
        .as_ref()
        .is_some_and(|chain_key_config| !chain_key_config.key_configs.is_empty())
    {
        return Err(PrepareCanisterMigrationError::SubnetIsSigningSubnet(
            subnet_id,
        ));
    }

    Ok(())
}

fn validate_subnets_consistency(
    source_subnet: &SubnetRecord,
    destination_subnet: &SubnetRecord,
) -> Result<(), PrepareCanisterMigrationError> {
    if source_subnet.subnet_type != destination_subnet.subnet_type {
        return Err(PrepareCanisterMigrationError::SubnetTypesMismatch(
            SubnetType::try_from(source_subnet.subnet_type).ok(),
            SubnetType::try_from(destination_subnet.subnet_type).ok(),
        ));
    }

    if source_subnet.membership.len() != destination_subnet.membership.len() {
        return Err(PrepareCanisterMigrationError::SubnetSizesMismatch(
            source_subnet.membership.len(),
            destination_subnet.membership.len(),
        ));
    }

    Ok(())
}

impl fmt::Display for PrepareCanisterMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrepareCanisterMigrationError::DisallowedSubnetType(subnet_id, subnet_type) => {
                write!(
                    f,
                    "The type ({subnet_type:?}) of the subnet with ID {subnet_id} \
                    is not allowed for subnet splitting. Allowlist: {SUPPORTED_SUBNET_TYPES:?}"
                )
            }
            PrepareCanisterMigrationError::SubnetIsSigningSubnet(subnet_id) => {
                write!(
                    f,
                    "Subnet with id {subnet_id} should not be a signing subnet"
                )
            }
            PrepareCanisterMigrationError::SubnetSizesMismatch(source_size, destination_size) => {
                write!(
                    f,
                    "Subnet sizes do not match. \
                    Source subnet's size: {source_size}, destination subnet's size: {destination_size}"
                )
            }
            PrepareCanisterMigrationError::SubnetTypesMismatch(source_type, destination_type) => {
                write!(
                    f,
                    "Subnet types do not match. \
                    Source subnet's type: {source_type:?}, destination subnet's type: {destination_type:?}"
                )
            }
            PrepareCanisterMigrationError::UnhostedCanisterIds => {
                write!(
                    f,
                    "Not all canisters to be migrated are hosted by the provided source subnet"
                )
            }
            PrepareCanisterMigrationError::CanisterIdsAlreadyBeingMigrated(ranges_to_migrate) => {
                write!(
                    f,
                    "some of the canister in the given ranges {ranges_to_migrate:?} are already being migrated"
                )
            }
            PrepareCanisterMigrationError::SubnetRecordError(err) => {
                write!(f, "Failed to get subnet record: {err}")
            }
            PrepareCanisterMigrationError::CanisterIdsNotWellFormed(err) => {
                write!(f, "canister ID ranges are not well formed: {err:?}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ic_base_types::CanisterId;
    use ic_registry_routing_table::RoutingTable;
    use ic_test_utilities_types::ids::subnet_test_id;

    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        mutations::routing_table::routing_table_into_registry_mutation,
    };

    use super::*;

    struct SubnetInfo {
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        nodes_count: u64,
        canister_id_ranges: Vec<CanisterIdRange>,
    }

    fn dummy_subnet_ids() -> (SubnetId, SubnetId) {
        (subnet_test_id(1), subnet_test_id(2))
    }

    fn set_up(source_subnet: SubnetInfo, destination_subnet: SubnetInfo) -> Registry {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, source_node_ids_and_dkg_pks) =
            prepare_registry_with_nodes(1, source_subnet.nodes_count);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let (mutate_request, destination_node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1 + source_subnet.nodes_count as u8,
            destination_subnet.nodes_count,
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Add subnets to the registry
        let mut subnet_list_record = registry.get_subnet_list_record();
        let mut source_subnet_record = get_invariant_compliant_subnet_record(
            source_node_ids_and_dkg_pks.keys().copied().collect(),
        );
        source_subnet_record.subnet_type = source_subnet.subnet_type as i32;
        let mut destination_subnet_record = get_invariant_compliant_subnet_record(
            destination_node_ids_and_dkg_pks.keys().copied().collect(),
        );
        destination_subnet_record.subnet_type = destination_subnet.subnet_type as i32;

        let subnet_mutation = add_fake_subnet(
            source_subnet.subnet_id,
            &mut subnet_list_record,
            source_subnet_record,
            &source_node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(subnet_mutation);

        let subnet_mutation = add_fake_subnet(
            destination_subnet.subnet_id,
            &mut subnet_list_record,
            destination_subnet_record,
            &destination_node_ids_and_dkg_pks,
        );
        registry.maybe_apply_mutation_internal(subnet_mutation);

        // Add canister id ranges to the routing table
        let mut rt = RoutingTable::new();
        rt.assign_ranges(
            source_subnet.canister_id_ranges.try_into().unwrap(),
            source_subnet.subnet_id,
        )
        .unwrap();
        rt.assign_ranges(
            destination_subnet.canister_id_ranges.try_into().unwrap(),
            destination_subnet.subnet_id,
        )
        .unwrap();

        let mutations = routing_table_into_registry_mutation(&registry, rt);
        registry.maybe_apply_mutation_internal(mutations);

        registry
    }

    #[test]
    fn prepare_canister_migration_happy_path_test() {
        let (source_subnet_id, destination_subnet_id) = dummy_subnet_ids();

        let mut registry = set_up(
            SubnetInfo {
                subnet_id: source_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(0),
                    end: CanisterId::from(10),
                }],
            },
            SubnetInfo {
                subnet_id: destination_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![],
            },
        );

        let payload = PrepareCanisterMigrationPayload {
            canister_id_ranges: vec![CanisterIdRange {
                start: CanisterId::from(3),
                end: CanisterId::from(7),
            }],
            source_subnet: source_subnet_id,
            destination_subnet: destination_subnet_id,
        };

        assert!(registry.prepare_canister_migration(payload).is_ok());
    }

    #[test]
    fn prepare_canister_migration_should_fail_when_sizes_dont_match_test() {
        let (source_subnet_id, destination_subnet_id) = dummy_subnet_ids();

        let mut registry = set_up(
            SubnetInfo {
                subnet_id: source_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 2,
                canister_id_ranges: vec![],
            },
            SubnetInfo {
                subnet_id: destination_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![],
            },
        );

        let payload = PrepareCanisterMigrationPayload {
            canister_id_ranges: vec![],
            source_subnet: source_subnet_id,
            destination_subnet: destination_subnet_id,
        };

        let err = registry
            .prepare_canister_migration(payload)
            .expect_err("Canister migration preparation should fail");

        assert_matches!(
            err,
            PrepareCanisterMigrationError::SubnetSizesMismatch { .. }
        );
    }

    #[test]
    fn prepare_canister_migration_should_fail_when_types_dont_match_test() {
        let (source_subnet_id, destination_subnet_id) = dummy_subnet_ids();

        let mut registry = set_up(
            SubnetInfo {
                subnet_id: source_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![],
            },
            SubnetInfo {
                subnet_id: destination_subnet_id,
                subnet_type: SubnetType::VerifiedApplication,
                nodes_count: 1,
                canister_id_ranges: vec![],
            },
        );

        let payload = PrepareCanisterMigrationPayload {
            canister_id_ranges: vec![],
            source_subnet: source_subnet_id,
            destination_subnet: destination_subnet_id,
        };

        let err = registry
            .prepare_canister_migration(payload)
            .expect_err("Canister migration preparation should fail");

        assert_matches!(
            err,
            PrepareCanisterMigrationError::SubnetTypesMismatch { .. }
        );
    }

    #[test]
    fn prepare_canister_migration_should_fail_when_canister_id_not_hosted_test() {
        let (source_subnet_id, destination_subnet_id) = dummy_subnet_ids();

        let mut registry = set_up(
            SubnetInfo {
                subnet_id: source_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![CanisterIdRange {
                    start: CanisterId::from(0),
                    end: CanisterId::from(10),
                }],
            },
            SubnetInfo {
                subnet_id: destination_subnet_id,
                subnet_type: SubnetType::Application,
                nodes_count: 1,
                canister_id_ranges: vec![],
            },
        );

        let payload = PrepareCanisterMigrationPayload {
            canister_id_ranges: vec![CanisterIdRange {
                start: CanisterId::from(3),
                end: CanisterId::from(23),
            }],
            source_subnet: source_subnet_id,
            destination_subnet: destination_subnet_id,
        };

        let err = registry
            .prepare_canister_migration(payload)
            .expect_err("Canister migration preparation should fail");

        assert_matches!(err, PrepareCanisterMigrationError::UnhostedCanisterIds);
    }
}
