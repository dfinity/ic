use crate::registry::Registry;
use candid::CandidType;
use ic_base_types::SubnetId;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_routing_table::{is_subset_of, CanisterIdRange, CanisterIdRanges};
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
        let reassigned_canister_ranges = payload.reassigned_canister_ranges.clone();
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

        // Check if all the canister ID ranges to be rerouted are from the source subnet.
        // To be clear, the source subnet here always means the subnet
        // where the canister ranges are currently assigned in the routing table.
        let routing_table = self.get_routing_table_or_panic(version);
        let source_subnet_ranges = routing_table.ranges(source);

        if !is_subset_of(
            reassigned_canister_ranges.iter(),
            source_subnet_ranges.iter(),
        ) {
            return Err(format!(
                "not all canisters to be migrated are hosted by the provided source subnet {}",
                source
            ));
        }

        // Check that routing table mutation is covered by an existing canister migration.
        let canister_migrations = self.get_canister_migrations(version).ok_or_else(|| {
            format!(
                "the ranges to be migrated {:?} are not covered by any existing canister migrations.",
                reassigned_canister_ranges
            )
        })?;

        let src_to_dest = vec![source, destination];
        let dest_to_src = vec![destination, source];
        // The exact range needs to be present in the map with the same trace.
        // In case of rolling back the migration, the trace from destination to source is also allowed.
        let all_covered_by_canister_migrations = reassigned_canister_ranges
            .iter()
            .all(|range| canister_migrations.get(range) == Some(&src_to_dest))
            || reassigned_canister_ranges
                .iter()
                .all(|range| canister_migrations.get(range) == Some(&dest_to_src));

        if !all_covered_by_canister_migrations {
            // If the rerouting is neither valid normal migration nor valid rollback,
            // the rerouting cannot proceed and an error is returned.
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
#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct RerouteCanisterRangesPayload {
    /// The list of canister ID ranges that needs to be mapped to the new
    /// destination.
    pub reassigned_canister_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    pub source_subnet: SubnetId,
    /// The new destination for the canister ID ranges.
    pub destination_subnet: SubnetId,
}
