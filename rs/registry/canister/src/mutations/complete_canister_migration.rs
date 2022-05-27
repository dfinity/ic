use crate::registry::Registry;
use candid::CandidType;
use ic_base_types::SubnetId;
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

impl Registry {
    /// Removes the given entries from `canister_migrations`.
    ///
    /// Validates the payload and applies the mutation derived from the payload.
    pub fn complete_canister_migration(
        &mut self,
        payload: CompleteCanisterMigrationPayload,
    ) -> Result<(), String> {
        // Construct the canister ID ranges from payload.
        let mut canister_id_ranges = payload.canister_id_ranges;
        canister_id_ranges.sort();
        // Check if the canister ID ranges are well formed.
        let canister_id_ranges = CanisterIdRanges::try_from(canister_id_ranges)
            .map_err(|e| format!("canister ID ranges are not well formed: {:?}", e))?;

        self.maybe_apply_mutation_internal(vec![self.remove_canister_migrations_mutation(
            self.latest_version(),
            canister_id_ranges,
            payload.migration_trace,
        )]);

        Ok(())
    }
}

/// The argument for the `complete_canister_migrations` update call.
#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct CompleteCanisterMigrationPayload {
    /// The list of canister ID ranges to be removed from canister migrations.
    pub canister_id_ranges: Vec<CanisterIdRange>,
    /// The migration trace containing a list of subnet IDs.
    pub migration_trace: Vec<SubnetId>,
}
