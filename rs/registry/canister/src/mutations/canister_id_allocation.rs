//! Whatever is needed to allocate canister IDs to new subnets, so that a new canister never gets
//! the ID of an old canister.
//!
//! The registry stores a `CanisterIdAllocation` under `make_canister_id_allocation_key()`. No
//! canister index at or above its `next_unallocated_canister_index` has ever been allocated to a
//! subnet, including to subnets that have since been deleted (and whose ranges are therefore no
//! longer in the routing table). It only ever increases, and new ranges always start at or above
//! it.

use crate::{common::LOG_PREFIX, registry::Registry, storage::with_chunks};
use ic_protobuf::registry::routing_table::v1::CanisterIdAllocation;
use ic_protobuf::types::v1 as pb_types;
use ic_registry_canister_chunkify::decode_high_capacity_registry_value;
use ic_registry_keys::{
    CANISTER_RANGES_PREFIX, make_canister_id_allocation_key, make_routing_table_record_key,
};
use ic_registry_routing_table::canister_id_into_u64;
use ic_registry_transport::{
    pb::v1::{HighCapacityRegistryValue, RegistryMutation},
    upsert,
};
use ic_types::CanisterId;
use prost::Message;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

impl Registry {
    /// Returns a canister index such that no canister index at or above it has ever been allocated
    /// to any subnet, as of `version`.
    ///
    /// This is read from the `CanisterIdAllocation`. In production, that always exists: the
    /// post-upgrade backfill writes it the first time the registry is upgraded to a release that
    /// knows about it. It only does not exist in a fresh registry (e.g., in tests that fill the
    /// registry through mutations), in which case this is computed from the full history of the
    /// routing table instead.
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

                let max_end = get_canister_id_range_ends_or_panic(value, /* for errors */ key)
                    .into_iter()
                    .max();

                if let Some(max_end) = max_end {
                    // A range ending at u64::MAX would leave no canister index unallocated. Rather
                    // than wrapping around to 0 (and thereby allowing every canister ID to be
                    // allocated again), panic.
                    let after_max_end = max_end.checked_add(1).unwrap_or_else(|| {
                        panic!(
                            "A range in routing table key {} ends at {max_end}, so no canister \
                             index is left unallocated.",
                            String::from_utf8_lossy(key),
                        )
                    });
                    next_unallocated_canister_index =
                        next_unallocated_canister_index.max(after_max_end);
                }
            }
        }

        next_unallocated_canister_index
    }
}

/// The part of `pb::RoutingTable` needed to find the end of each range. Unlike `pb::RoutingTable`,
/// this decodes routing tables in every encoding that the registry has ever stored, current or
/// legacy.
///
/// Today, `CanisterIdRange` encodes its end as a `CanisterId` (field 4). Very old versions encoded
/// it as a plain `uint64` canister index instead (field 2, now reserved). `pb::RoutingTable` drops
/// field 2 when decoding, so routing tables are decoded with these messages instead, which keep
/// both.
#[derive(Clone, PartialEq, prost::Message)]
struct LegacyCompatibleRoutingTable {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<LegacyCompatibleRoutingTableEntry>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LegacyCompatibleRoutingTableEntry {
    #[prost(message, optional, tag = "1")]
    range: Option<LegacyCompatibleCanisterIdRange>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LegacyCompatibleCanisterIdRange {
    /// The end in the very old encoding. As in proto3, 0 is not encoded, so `None` means 0.
    #[prost(uint64, optional, tag = "2")]
    legacy_end: Option<u64>,

    #[prost(message, optional, tag = "4")]
    end_canister_id: Option<pb_types::CanisterId>,
}

impl LegacyCompatibleCanisterIdRange {
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

/// Returns the (inclusive) end of each canister ID range in `value`, a version of the routing table
/// stored under `key` (a shard or the legacy single-key routing table), in any encoding that the
/// registry has ever stored. `key` is only used in panic messages.
///
/// Returns no ends if `value` deletes `key`: that version holds no ranges (the ranges held before
/// are in the earlier versions).
///
/// Panics if `value` cannot be decoded, or if a range end is not a valid canister ID.
fn get_canister_id_range_ends_or_panic(value: &HighCapacityRegistryValue, key: &[u8]) -> Vec<u64> {
    let Some(routing_table) = with_chunks(|chunks| {
        decode_high_capacity_registry_value::<LegacyCompatibleRoutingTable, _>(value, chunks)
    }) else {
        return vec![];
    };

    routing_table
        .entries
        .into_iter()
        // An entry without a range assigns no canister IDs to its subnet.
        .filter_map(|entry| entry.range)
        .map(|range| {
            range.try_get_end_canister_index().unwrap_or_else(|err| {
                panic!(
                    "Invalid range end in version {} of routing table key {}: {err}",
                    value.version,
                    String::from_utf8_lossy(key),
                )
            })
        })
        .collect::<Vec<u64>>()
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
/// TODO: Remove this once the registry canister on mainnet has been upgraded with it. Remove
/// `check_canister_id_allocation_covers_mainnet_history` (in the NNS golden state test) along with
/// it.
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
