use crate::registry::Registry;
use candid::CandidType;
use ic_base_types::SubnetId;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_routing_table::{are_disjoint, is_subset_of, CanisterIdRange, CanisterIdRanges};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

impl Registry {
    /// Adds new entries to `canister_migrations`.
    ///
    /// Validates the payload and applies the mutation derived from the payload
    /// to the registry.
    pub fn prepare_canister_migration(
        &mut self,
        payload: PrepareCanisterMigrationPayload,
    ) -> Result<(), String> {
        // Construct the canister ID ranges from payload.
        let ranges_to_migrate = payload.canister_id_ranges.clone();
        // Check if the canister ID ranges are well formed.
        let ranges_to_migrate = CanisterIdRanges::try_from(ranges_to_migrate)
            .map_err(|e| format!("canister ID ranges are not well formed: {:?}", e))?;

        let source = payload.source_subnet;
        let destination = payload.destination_subnet;

        let version = self.latest_version();

        self.get(&make_subnet_record_key(source).into_bytes(), version)
            .ok_or_else(|| format!("source {} is not a known subnet", source))?;
        self.get(&make_subnet_record_key(destination).into_bytes(), version)
            .ok_or_else(|| format!("destination {} is not a known subnet", destination))?;

        let routing_table = self.get_routing_table_or_panic(version);
        let source_subnet_ranges = routing_table.ranges(source);
        // Check if all the canister ID ranges to be migrated are from the source subnet.
        if !is_subset_of(ranges_to_migrate.iter(), source_subnet_ranges.iter()) {
            return Err(format!(
                "not all canisters to be migrated are hosted by the provided source subnet {}",
                source
            ));
        }

        // Check if the canister ID ranges to be migrated are NOT in active canister migration.
        if let Some(canister_migrations) = self.get_canister_migrations(version) {
            if !are_disjoint(canister_migrations.ranges(), ranges_to_migrate.iter()) {
                return Err(format!(
                    "some of the canister in the given ranges {:?} are already being migrated",
                    ranges_to_migrate
                ));
            }
        }

        self.maybe_apply_mutation_internal(vec![self.migrate_canister_ranges_mutation(
            version,
            ranges_to_migrate,
            source,
            destination,
        )]);

        Ok(())
    }
}

/// The argument for the `prepare_canister_migration` update call.
#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct PrepareCanisterMigrationPayload {
    /// The list of canister ID ranges to be added into canister migrations.
    pub canister_id_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    pub source_subnet: SubnetId,
    /// The new destination for the canister ID ranges.
    pub destination_subnet: SubnetId,
}
