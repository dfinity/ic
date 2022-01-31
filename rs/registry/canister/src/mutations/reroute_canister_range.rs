use crate::registry::Registry;
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_routing_table::CanisterIdRange;
use serde::{Deserialize, Serialize};

impl Registry {
    /// Validates the payload and applies the mutation derived from the payload
    /// to the registry.
    pub fn reroute_canister_range(
        &mut self,
        payload: RerouteCanisterRangePayload,
    ) -> Result<(), String> {
        let start = CanisterId::new(payload.range_start_inclusive)
            .map_err(|e| format!("range start is not a canister id: {}", e))?;
        let end = CanisterId::new(payload.range_end_inclusive)
            .map_err(|e| format!("range end is not a canister id: {}", e))?;

        let destination = SubnetId::from(payload.destination_subnet);

        if end < start {
            return Err(format!(
                "invalid canister id range ({}, {}): start > end",
                start, end
            ));
        }

        let version = self.latest_version();

        self.get(&make_subnet_record_key(destination).into_bytes(), version)
            .ok_or_else(|| format!("destination {} is not a known subnet", destination))?;

        self.maybe_apply_mutation_internal(vec![self.reroute_canister_range_mutation(
            version,
            CanisterIdRange { start, end },
            destination,
        )]);

        Ok(())
    }
}

/// The argument for the `reroute_canister_range` update call.
#[derive(CandidType, Serialize, Deserialize)]
pub struct RerouteCanisterRangePayload {
    /// The first canister id in the range that needs to be mapped to the new
    /// destination.
    pub range_start_inclusive: PrincipalId,
    /// The last canister id in the range that needs to be mapped to the new
    /// destination.
    pub range_end_inclusive: PrincipalId,
    /// The new destination for the canister id range.
    pub destination_subnet: PrincipalId,
}
