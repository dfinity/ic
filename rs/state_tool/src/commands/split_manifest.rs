//! Outputs the manifests expected after a subnet split.

use super::verify_manifest::parse_manifest;
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_manager::manifest::split::split_manifest;
use ic_state_manager::manifest::{manifest_hash, validate_manifest};
use ic_state_manager::state_sync::types::Manifest;
use ic_types::crypto::CryptoHash;
use ic_types::{CanisterId, CryptoHashOfState, SubnetId, Time};
use std::fs::File;
use std::path::PathBuf;

/// Computes the expected manifests (chunk hashes, file hashes and root hash) of
/// the states resulting from splitting the manifest at `path` between
/// `subnet_b` (hosting all canisters in `migrated_ranges`) and `subnet_a` (all
/// remaining canisters).
///
/// `subnet_a` is expected to have subnet type `subnet_type` (although there is
/// no wau to validate this); and this same subnet type will be assigned to
/// `subnet_b`. Same with `batch_time`, which is assumed to be the batch time
/// of `subnet_a` just before halting.
pub fn do_split_manifest(
    path: PathBuf,
    subnet_a: SubnetId,
    subnet_b: SubnetId,
    subnet_type: SubnetType,
    batch_time: Time,
    migrated_ranges: Vec<CanisterIdRange>,
) -> Result<(), String> {
    let (version, files, chunks, hash) = parse_manifest(
        File::open(&path)
            .map_err(|e| format!("Failed to parse manifest at {}: {}", path.display(), e))?,
    )
    .map_err(|e| format!("Failed to parse manifest at {}: {}", path.display(), e))?;
    let manifest = Manifest::new(version, files, chunks);

    // Sanity check: ensure that the parsed manifest is internally consistent; and
    // that the parsed hash matches the one computed from the manifest.
    validate_manifest(
        &manifest,
        &CryptoHashOfState::from(CryptoHash(hash.to_vec())),
    )
    .map_err(|e| format!("Invalid manifest: {e}"))?;

    let mut routing_table = RoutingTable::new();
    // Assigns the given ranges in `routing_table` to the given subnet.
    let mut assign_ranges = |ranges: Vec<CanisterIdRange>, subnet_id: SubnetId| {
        CanisterIdRanges::try_from(ranges.clone())
            .and_then(|ranges| routing_table.assign_ranges(ranges, subnet_id))
            .map_err(|e| format!("Failed to assign ranges {ranges:?}: {e:?}"))
    };
    // Start off with everything assigned to `subnet_a`.
    assign_ranges(
        vec![CanisterIdRange {
            start: CanisterId::from_u64(0),
            end: CanisterId::from_u64(u64::MAX),
        }],
        subnet_a,
    )?;
    // Reassign `migrated_ranges` to `subnet_b`.
    assign_ranges(migrated_ranges, subnet_b)?;

    let (manifest_a, manifest_b) = split_manifest(
        &manifest,
        subnet_a,
        subnet_b,
        subnet_type,
        batch_time,
        &routing_table,
    )
    .map_err(|e| format!("Failed to split manifest: {e}"))?;

    print_manifest(subnet_a, &manifest_a);
    print_manifest(subnet_b, &manifest_b);

    Ok(())
}

fn print_manifest(subnet: SubnetId, manifest: &Manifest) {
    println!("Subnet {subnet}");
    println!("--------");
    println!("{manifest}");
    println!();
    println!("ROOT HASH: {}", hex::encode(manifest_hash(manifest)));
    println!("========");
    println!();
}
