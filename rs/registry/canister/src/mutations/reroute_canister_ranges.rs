use crate::registry::Registry;
use candid::CandidType;
use ic_base_types::SubnetId;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

impl Registry {
    /// Validates the payload and applies the mutation derived from the payload
    /// to the registry.
    pub fn reroute_canister_ranges(
        &mut self,
        payload: RerouteCanisterRangesPayload,
    ) -> Result<(), String> {
        // Construct the canister ID ranges from payload.
        let mut reassigned_canister_ranges = payload.reassigned_canister_ranges.clone();
        reassigned_canister_ranges.sort();
        // Check if the canister ID ranges are well formed.
        let reassigned_canister_ranges = CanisterIdRanges::try_from(reassigned_canister_ranges)
            .map_err(|e| format!("canister ID ranges are not well formed: {:?}", e))?;

        let source = payload.source_subnet;
        let destination = payload.destination_subnet;

        let version = self.latest_version();

        self.get(&make_subnet_record_key(source).into_bytes(), version)
            .ok_or_else(|| format!("source {} is not a known subnet", source))?;
        self.get(&make_subnet_record_key(destination).into_bytes(), version)
            .ok_or_else(|| format!("destination {} is not a known subnet", destination))?;

        let dest_to_src = vec![source, destination];

        // Check that routing table mutation is covered by an existing canister migration.
        let canister_migrations = self.get_canister_migrations(version).ok_or_else(|| {
            format!(
                "the ranges to be migrated {:?} are not covered by any existing canister migrations.",
                reassigned_canister_ranges
            )
        })?;

        // The exact range needs to be present in the map with the same trace.
        let all_covered_by_canister_migrations = reassigned_canister_ranges
            .iter()
            .all(|range| canister_migrations.get(range) == Some(&dest_to_src));

        if !all_covered_by_canister_migrations {
            return Err(format!(
                "the ranges to be migrated {:?} are not covered by any existing canister migrations.",
                reassigned_canister_ranges
            ));
        }

        self.maybe_apply_mutation_internal(vec![self.reroute_canister_ranges_mutation(
            version,
            reassigned_canister_ranges,
            destination,
        )]);

        Ok(())
    }
}

/// The argument for the `reroute_canister_range` update call.
#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct RerouteCanisterRangesPayload {
    /// The list of canister ID ranges that needs to be mapped to the new
    /// destination.
    pub reassigned_canister_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    pub source_subnet: SubnetId,
    /// The new destination for the canister ID ranges.
    pub destination_subnet: SubnetId,
}
