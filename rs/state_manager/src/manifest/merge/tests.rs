use super::*;
use crate::manifest::split::tests::{
    canister_pbuf_path, empty_file_info, non_empty_file_and_chunk_infos, snapshot_pbuf_path,
};
use assert_matches::assert_matches;
use ic_base_types::{CanisterId, SnapshotId};
use ic_state_layout::{INGRESS_HISTORY_FILE, SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE};
use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;

const CANISTER_1: CanisterId = CanisterId::from_u64(1);
const CANISTER_2: CanisterId = CanisterId::from_u64(2);
const CANISTER_3: CanisterId = CanisterId::from_u64(3);

/// Builds a manifest of the given version from files without chunks at the
/// given paths, which must be sorted.
fn manifest_of(version: StateSyncVersion, paths: &[String]) -> Manifest {
    let mut builder = ManifestBuilder::new(version);
    for path in paths {
        builder.append(&empty_file_info(path), &[]);
    }
    builder.build().unwrap()
}

#[test]
fn merge_manifests_takes_the_canisters_of_the_source() {
    let snapshot_1 = SnapshotId::from((CANISTER_1, 0));
    let snapshot_2 = SnapshotId::from((CANISTER_2, 0));

    // The destination holds `CANISTER_1` with a snapshot, and the source holds
    // `CANISTER_2` with a snapshot, as well as `CANISTER_3`; both hold
    // non-empty ingress histories and subnet queues.
    let (ingress_history_file_info, ingress_history_chunk_info) =
        non_empty_file_and_chunk_infos(INGRESS_HISTORY_FILE);
    let (subnet_queues_file_info, subnet_queues_chunk_info) =
        non_empty_file_and_chunk_infos(SUBNET_QUEUES_FILE);
    let build = |canister_ids: &[CanisterId], snapshot_id: SnapshotId| {
        let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
        for canister_id in canister_ids {
            builder.append(&empty_file_info(&canister_pbuf_path(*canister_id)), &[]);
        }
        builder.append(
            &ingress_history_file_info,
            std::slice::from_ref(&ingress_history_chunk_info),
        );
        builder.append(&empty_file_info(&snapshot_pbuf_path(snapshot_id)), &[]);
        builder.append(
            &subnet_queues_file_info,
            std::slice::from_ref(&subnet_queues_chunk_info),
        );
        builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
        builder.build().unwrap()
    };
    let destination = build(&[CANISTER_1], snapshot_1);
    let source = build(&[CANISTER_2, CANISTER_3], snapshot_2);

    // Expecting everything of the destination, the canisters and the snapshot
    // of the source, and the marker.
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_1)), &[]);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_2)), &[]);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_3)), &[]);
    builder.append(
        &ingress_history_file_info,
        std::slice::from_ref(&ingress_history_chunk_info),
    );
    builder.append(&empty_file_info(&snapshot_pbuf_path(snapshot_1)), &[]);
    builder.append(&empty_file_info(&snapshot_pbuf_path(snapshot_2)), &[]);
    builder.append_subnet_merged_marker();
    builder.append(
        &subnet_queues_file_info,
        std::slice::from_ref(&subnet_queues_chunk_info),
    );
    builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
    let expected = builder.build().unwrap();

    assert_eq!(merge_manifests(&destination, &source), Ok(expected));
}

#[test]
fn merge_manifests_appends_the_marker_last() {
    let destination = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_1)],
    );
    let source = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_2)],
    );

    let merged = merge_manifests(&destination, &source).unwrap();

    let paths: Vec<_> = merged
        .file_table
        .iter()
        .map(|file| file.relative_path.to_str().unwrap().to_string())
        .collect();
    assert_eq!(
        paths,
        vec![
            canister_pbuf_path(CANISTER_1),
            canister_pbuf_path(CANISTER_2),
            SUBNET_MERGED_FILE.to_string(),
        ]
    );
}

#[test]
fn merge_manifests_replaces_the_marker_of_the_destination() {
    let destination = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[
            canister_pbuf_path(CANISTER_1),
            SUBNET_MERGED_FILE.to_string(),
        ],
    );
    let source = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_2)],
    );
    let without_marker = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_1)],
    );

    assert_eq!(
        merge_manifests(&destination, &source).unwrap(),
        merge_manifests(&without_marker, &source).unwrap()
    );
}

#[test]
fn merge_manifests_common_canister() {
    let destination = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_1)],
    );
    let source = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[snapshot_pbuf_path(SnapshotId::from((CANISTER_2, 0)))],
    );
    // `CANISTER_1` in the source, though with a different snapshot.
    let colliding_source = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[
            canister_pbuf_path(CANISTER_1),
            snapshot_pbuf_path(SnapshotId::from((CANISTER_2, 0))),
        ],
    );
    let destination_with_snapshot = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[snapshot_pbuf_path(SnapshotId::from((CANISTER_2, 1)))],
    );

    assert_matches!(
        merge_manifests(&destination, &colliding_source),
        Err(ManifestValidationError::InconsistentManifest { reason })
            if reason.starts_with("both manifests hold files in canister_states/")
    );
    assert_matches!(
        merge_manifests(&destination_with_snapshot, &source),
        Err(ManifestValidationError::InconsistentManifest { reason })
            if reason.starts_with("both manifests hold files in snapshots/")
    );
}

#[test]
fn merge_manifests_unsupported_version() {
    let supported = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_1)],
    );
    let unsupported = manifest_of(StateSyncVersion::V2, &[canister_pbuf_path(CANISTER_2)]);

    for (destination, source) in [(&supported, &unsupported), (&unsupported, &supported)] {
        assert_matches!(
            merge_manifests(destination, source),
            Err(ManifestValidationError::UnsupportedManifestVersion {
                manifest_version: StateSyncVersion::V2,
                ..
            })
        );
    }
}

#[test]
fn merge_manifests_version_mismatch() {
    let destination = manifest_of(StateSyncVersion::V3, &[canister_pbuf_path(CANISTER_1)]);
    let source = manifest_of(
        CURRENT_STATE_SYNC_VERSION,
        &[canister_pbuf_path(CANISTER_2)],
    );
    assert_ne!(StateSyncVersion::V3, CURRENT_STATE_SYNC_VERSION);

    assert_matches!(
        merge_manifests(&destination, &source),
        Err(ManifestValidationError::InconsistentManifest { reason })
            if reason.contains("version")
    );
}
