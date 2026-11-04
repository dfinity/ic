//! Tracks which canister IDs have ever been allocated to a subnet, so that subnet creation never
//! hands out the canister IDs of a deleted subnet again.
//!
//! The registry stores a `CanisterIdAllocation` under `make_canister_id_allocation_key()`, holding
//! one past the largest canister index ever allocated, including to subnets that have since been
//! deleted (and whose ranges are therefore no longer in the routing table). It only ever increases,
//! and new ranges always start at or above it.

use crate::{common::LOG_PREFIX, registry::Registry, storage::with_chunks};
use ic_protobuf::registry::routing_table::v1::CanisterIdAllocation;
use ic_protobuf::types::v1 as pb_types;
use ic_registry_canister_chunkify::dechunkify_registry_value;
use ic_registry_keys::{
    CANISTER_RANGES_PREFIX, make_canister_id_allocation_key, make_routing_table_record_key,
};
use ic_registry_routing_table::canister_id_into_u64;
use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
use ic_types::CanisterId;
use prost::Message;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

impl Registry {
    /// Returns the smallest canister index that has never been allocated to any subnet, as of
    /// `version`.
    ///
    /// This is read from the `CanisterIdAllocation`. If that does not exist yet (e.g., the
    /// registry has not been upgraded past the release introducing it), it is computed from the
    /// full history of the routing table instead.
    pub(crate) fn get_next_unallocated_canister_index(&self, version: u64) -> u64 {
        let key = make_canister_id_allocation_key();
        let Some(registry_value) = self.get(key.as_bytes(), version) else {
            return self.compute_next_unallocated_canister_index_from_history(version);
        };

        CanisterIdAllocation::decode(registry_value.value.as_slice())
            .unwrap_or_else(|err| panic!("Unable to decode the CanisterIdAllocation: {err}"))
            .next_unallocated_canister_index
    }

    /// Returns one past the largest canister ID range end in any version (up to and including
    /// `version`) of the routing table ever stored, or 0 if there is no such range.
    ///
    /// Unlike the latest routing table, this includes the ranges of subnets that have since been
    /// deleted. Both the routing table shards (`canister_ranges_*`) and the legacy single-key
    /// routing table (`routing_table`) are scanned.
    pub(crate) fn compute_next_unallocated_canister_index_from_history(&self, version: u64) -> u64 {
        let canister_ranges_prefix = CANISTER_RANGES_PREFIX.as_bytes();
        let shards = self
            .store
            .range(canister_ranges_prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(canister_ranges_prefix));
        let legacy_routing_table = self
            .store
            .get_key_value(make_routing_table_record_key().as_bytes());

        let mut next_unallocated_canister_index = 0;
        for (key, values) in shards.chain(legacy_routing_table) {
            for value in values {
                if value.version > version {
                    break;
                }
                // A value without content holds no routing table, hence no ranges to account for.
                let Some(content) = value.content.clone() else {
                    continue;
                };
                // Large values live in the chunk store, so they are reassembled first. `None` means
                // that the key was deleted in this version, so this version holds no ranges either
                // (the ranges it held before are accounted for by the earlier versions).
                let Some(bytes) = with_chunks(|chunks| dechunkify_registry_value(content, chunks))
                else {
                    continue;
                };

                let routing_table = HistoricalRoutingTable::decode(bytes.as_slice())
                    .unwrap_or_else(|err| {
                        panic!(
                            "Unable to decode version {} of routing table key {}: {err}",
                            value.version,
                            String::from_utf8_lossy(key),
                        )
                    });
                for entry in routing_table.entries {
                    // An entry without a range assigns no canister IDs to its subnet, so there is
                    // nothing to account for.
                    let Some(range) = entry.range else {
                        continue;
                    };
                    let end = range.try_get_end_canister_index().unwrap_or_else(|err| {
                        panic!(
                            "Invalid range end in version {} of routing table key {}: {err}",
                            value.version,
                            String::from_utf8_lossy(key),
                        )
                    });
                    next_unallocated_canister_index = next_unallocated_canister_index.max(end + 1);
                }
            }
        }

        next_unallocated_canister_index
    }
}

/// The part of `pb::RoutingTable` needed to find the end of each range, in every encoding that the
/// registry has ever stored.
///
/// Today, `CanisterIdRange` encodes its end as a `CanisterId` (field 4). Very old versions encoded
/// it as a plain `uint64` canister index instead (field 2, now reserved). `pb::RoutingTable` drops
/// field 2 when decoding, so the history is decoded with these messages instead, which keep both.
#[derive(Clone, PartialEq, prost::Message)]
struct HistoricalRoutingTable {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<HistoricalRoutingTableEntry>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HistoricalRoutingTableEntry {
    #[prost(message, optional, tag = "1")]
    range: Option<HistoricalCanisterIdRange>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HistoricalCanisterIdRange {
    /// The end in the very old encoding. As in proto3, 0 is not encoded, so `None` means 0.
    #[prost(uint64, optional, tag = "2")]
    legacy_end: Option<u64>,

    #[prost(message, optional, tag = "4")]
    end_canister_id: Option<pb_types::CanisterId>,
}

impl HistoricalCanisterIdRange {
    /// Returns the canister index of the (inclusive) end of this range, in either encoding.
    fn try_get_end_canister_index(self) -> Result<u64, String> {
        let Some(end_canister_id) = self.end_canister_id else {
            return Ok(self.legacy_end.unwrap_or(0));
        };
        let end_canister_id =
            CanisterId::try_from(end_canister_id).map_err(|err| err.to_string())?;
        Ok(canister_id_into_u64(end_canister_id))
    }
}

/// Returns the mutation that sets the `CanisterIdAllocation` to `next_unallocated_canister_index`.
pub(crate) fn make_canister_id_allocation_mutation(
    next_unallocated_canister_index: u64,
) -> RegistryMutation {
    let canister_id_allocation = CanisterIdAllocation {
        next_unallocated_canister_index,
    };
    upsert(
        make_canister_id_allocation_key(),
        canister_id_allocation.encode_to_vec(),
    )
}

/// Registry data migration: creates the `CanisterIdAllocation` from the history of the routing
/// table, unless it already exists. Returns no mutations if it already exists, so this is a no-op
/// on all upgrades after the first one. Also returns no mutations if no canister IDs have ever been
/// allocated (e.g., in a registry without a routing table), since there is nothing to record yet.
///
/// TODO: Remove this once the registry canister on mainnet has been upgraded with it.
pub(crate) fn backfill_canister_id_allocation(registry: &Registry) -> Vec<RegistryMutation> {
    let key = make_canister_id_allocation_key();
    if registry
        .get(key.as_bytes(), registry.latest_version())
        .is_some()
    {
        return vec![];
    }

    let next_unallocated_canister_index =
        registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());
    println!(
        "{LOG_PREFIX}backfill_canister_id_allocation: next_unallocated_canister_index = {next_unallocated_canister_index}"
    );
    if next_unallocated_canister_index == 0 {
        return vec![];
    }
    vec![make_canister_id_allocation_mutation(
        next_unallocated_canister_index,
    )]
}

#[cfg(test)]
#[path = "canister_id_allocation_tests.rs"]
mod tests;
