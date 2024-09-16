use assert_matches::assert_matches;
//use ic_base_types::{CanisterId, SnapshotId};
use ic_base_types::CanisterId;
//use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
use ic_state_layout::{CheckpointLayout, ReadOnly};
use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
use ic_types::{state_sync::CURRENT_STATE_SYNC_VERSION, Height};

use super::*;

/// Expected hash of a zero length file.
const EMPTY_FILE_HASH: [u8; 32] = [
    152, 19, 5, 215, 192, 178, 172, 224, 245, 63, 232, 34, 244, 7, 82, 120, 250, 40, 81, 30, 140,
    52, 231, 15, 55, 253, 132, 37, 175, 101, 155, 54,
];
/// A `Time` constant to be used as the batch time of the state to be split.
const BATCH_TIME: Time = Time::from_nanos_since_unix_epoch(1234567890);

#[test]
fn manifest_builder_out_of_order_files() {
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
    builder.append(&empty_file_info(SPLIT_MARKER_FILE), &[]);

    assert_eq!(
        builder.build(),
        Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "file paths are not sorted: {}, {}",
                SYSTEM_METADATA_FILE, SPLIT_MARKER_FILE
            )
        })
    );
}

#[test]
fn manifest_builder_duplicate_files() {
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
    builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);

    assert_eq!(
        builder.build(),
        Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "file paths are not sorted: {}, {}",
                SYSTEM_METADATA_FILE, SYSTEM_METADATA_FILE
            )
        })
    );
}

#[test]
fn manifest_builder_out_of_order_generated_files() {
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append_system_metadata(SUBNET_0, SubnetType::Application, BATCH_TIME);
    builder.append_split_marker(SUBNET_0);

    assert_eq!(
        builder.build(),
        Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "file paths are not sorted: {}, {}",
                SYSTEM_METADATA_FILE, SPLIT_MARKER_FILE
            )
        })
    );
}

#[test]
fn manifest_builder_bad_file_hash() {
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(
        &FileInfo {
            relative_path: PathBuf::from(SYSTEM_METADATA_FILE),
            size_bytes: 0,
            hash: [0u8; 32],
        },
        &[],
    );

    assert_matches!(
        builder.build(),
        Err(ManifestValidationError::InvalidFileHash { .. })
    );
}

#[test]
fn split_manifest_unsupported_version() {
    let manifest = Manifest::new(StateSyncVersion::V2, vec![], vec![]);

    assert_matches!(
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &RoutingTable::default(),
        ),
        Err(ManifestValidationError::UnsupportedManifestVersion { .. })
    );
}

#[test]
fn split_manifest_unassigned_canister() {
    let canister_id = CanisterId::from_u64(13);
    let manifest = Manifest::new(
        CURRENT_STATE_SYNC_VERSION,
        vec![empty_file_info(&canister_pbuf_path(canister_id))],
        vec![],
    );

    assert_eq!(
        Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "canister {} is mapped to neither subnet A' ({}) nor subnet B ({})",
                canister_id, SUBNET_0, SUBNET_1
            )
        }),
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &RoutingTable::default(),
        )
    );
}

#[test]
fn split_manifest_state_already_splitting() {
    let manifest = Manifest::new(
        CURRENT_STATE_SYNC_VERSION,
        vec![empty_file_info(SPLIT_MARKER_FILE)],
        vec![],
    );

    assert_eq!(
        Err(ManifestValidationError::InconsistentManifest {
            reason: "state is already undergoing a split".into()
        }),
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &RoutingTable::default(),
        )
    );
}

#[test]
fn split_manifest_unknown_file() {
    let manifest = Manifest::new(
        CURRENT_STATE_SYNC_VERSION,
        vec![empty_file_info("unknown_file.pbuf")],
        vec![],
    );

    assert_eq!(
        Err(ManifestValidationError::InconsistentManifest {
            reason: "unknown file in manifest: unknown_file.pbuf".into()
        }),
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &RoutingTable::default(),
        )
    );
}

#[test]
fn split_manifest_split_marker_last() {
    let manifest = Manifest::new(
        CURRENT_STATE_SYNC_VERSION,
        vec![empty_file_info(INGRESS_HISTORY_FILE)],
        vec![],
    );

    // Expecting identical manifests on both sides, consisting of the original
    // ingress history plus a split marker.
    let (split_marker_file_info, split_marker_chunk_info) = expected_split_marker();
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(&empty_file_info(INGRESS_HISTORY_FILE), &[]);
    builder.append(&split_marker_file_info, &[split_marker_chunk_info]);
    let expected_manifest = builder.build().unwrap();

    assert_eq!(
        Ok((expected_manifest.clone(), expected_manifest)),
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &RoutingTable::default(),
        )
    );
}
/*
#[test]
fn split_manifest_3_canisters() {
    const CANISTER_1: CanisterId = CanisterId::from_u64(1);
    const CANISTER_2: CanisterId = CanisterId::from_u64(2);
    const CANISTER_3: CanisterId = CanisterId::from_u64(3);
    const CANISTER_4: CanisterId = CanisterId::from_u64(4);
    let snapshot_1: SnapshotId = SnapshotId::from((CANISTER_1, 0));

    // A manifest with 3 canisters; system metadata; and non-empty ingress history
    // and subnet queues.
    let mut builder = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_1)), &[]);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_2)), &[]);
    builder.append(&empty_file_info(&canister_pbuf_path(CANISTER_3)), &[]);
    let (ingress_history_file_info, ingress_history_chunk_info) =
        non_empty_file_and_chunk_infos(INGRESS_HISTORY_FILE);
    builder.append(
        &ingress_history_file_info,
        &[ingress_history_chunk_info.clone()],
    );
    builder.append(&empty_file_info(&snapshot_pbuf_path(snapshot_1)), &[]);
    let (subnet_queues_file_info, subnet_queues_chunk_info) =
        non_empty_file_and_chunk_infos(SUBNET_QUEUES_FILE);
    builder.append(
        &subnet_queues_file_info,
        &[subnet_queues_chunk_info.clone()],
    );
    builder.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
    let manifest = builder.build().unwrap();

    // A routing table mapping `CANISTER_2..CANISTER_4` to `SUBNET_1` and everything
    // else to `SUBNET_0`.
    let mut routing_table = RoutingTable::new();
    // Assigns the given ranges in `routing_table` to the given subnet.
    let mut assign_ranges = |ranges: Vec<CanisterIdRange>, subnet_id: SubnetId| {
        CanisterIdRanges::try_from(ranges.clone())
            .and_then(|ranges| routing_table.assign_ranges(ranges, subnet_id))
            .map_err(|e| format!("Failed to assign ranges {:?}: {:?}", ranges, e))
    };
    // Start off with everything assigned to `SUBNET_0`.
    assign_ranges(
        vec![CanisterIdRange {
            start: CanisterId::from_u64(0),
            end: CanisterId::from_u64(u64::MAX),
        }],
        SUBNET_0,
    )
    .unwrap();
    // Reassign `CANISTER_2..CANISTER_4` to `SUBNET_1`.
    assign_ranges(
        vec![CanisterIdRange {
            start: CANISTER_2,
            end: CANISTER_4,
        }],
        SUBNET_1,
    )
    .unwrap();

    // Expect the same split marker on both sides.
    let (split_marker_file_info, split_marker_chunk_info) = expected_split_marker();

    // Expecting the post-split subnet 0 manifest to contain everything except the
    // `CANISTER_2` and `CANISTER_3` states; plus the split marker.
    let mut builder_0 = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder_0.append(&empty_file_info(&canister_pbuf_path(CANISTER_1)), &[]);
    builder_0.append(
        &ingress_history_file_info,
        &[ingress_history_chunk_info.clone()],
    );
    builder_0.append(&empty_file_info(&snapshot_pbuf_path(snapshot_1)), &[]);
    builder_0.append(&split_marker_file_info, &[split_marker_chunk_info.clone()]);
    builder_0.append(&subnet_queues_file_info, &[subnet_queues_chunk_info]);
    builder_0.append(&empty_file_info(SYSTEM_METADATA_FILE), &[]);
    let expected_manifest_0 = builder_0.build().unwrap();

    // Expecting the post-split subnet 1 manifest to contain:
    //  * the `CANISTER_2` and `CANISTER_3` states;
    //  * the original ingress history;
    //  * the same split marker as `SUBNET_0`;
    //  * empty subnet queues; and
    //  * replaced system metadata.
    let mut builder_1 = ManifestBuilder::new(CURRENT_STATE_SYNC_VERSION);
    builder_1.append(&empty_file_info(&canister_pbuf_path(CANISTER_2)), &[]);
    builder_1.append(&empty_file_info(&canister_pbuf_path(CANISTER_3)), &[]);
    builder_1.append(&ingress_history_file_info, &[ingress_history_chunk_info]);
    builder_1.append(&split_marker_file_info.clone(), &[split_marker_chunk_info]);
    builder_1.append(&empty_file_info(SUBNET_QUEUES_FILE), &[]);
    let (system_metadata_file_info, system_metadata_chunk_info) =
        expected_subnet_1_system_metadata();
    builder_1.append(&system_metadata_file_info, &[system_metadata_chunk_info]);
    let expected_manifest_1 = builder_1.build().unwrap();

    assert_eq!(
        Ok((expected_manifest_0, expected_manifest_1)),
        split_manifest(
            &manifest,
            SUBNET_0,
            SUBNET_1,
            SubnetType::Application,
            BATCH_TIME,
            &routing_table,
        )
    );
}
*/
/// Returns a `FileInfo` for a zero length file with the given relative path.
fn empty_file_info(path: &str) -> FileInfo {
    FileInfo {
        relative_path: PathBuf::from(path),
        size_bytes: 0,
        hash: EMPTY_FILE_HASH,
    }
}
/*
/// Generates a valid `(FileInfo, ChunkInfo)` pair for a non-empty file with
/// the given relative path..
fn non_empty_file_and_chunk_infos(path: &str) -> (FileInfo, ChunkInfo) {
    (
        FileInfo {
            relative_path: PathBuf::from(path),
            size_bytes: 1234,
            hash: [
                217, 158, 192, 49, 225, 119, 140, 128, 19, 99, 6, 129, 241, 96, 101, 141, 119, 128,
                26, 192, 93, 38, 226, 85, 228, 107, 177, 153, 164, 20, 235, 49,
            ],
        },
        ChunkInfo {
            file_index: 13,
            size_bytes: 1234,
            offset: 0,
            hash: [13u8; 32],
        },
    )
}
*/
/// Returns the relative path to the `canister.pbuf` for the given canister.
fn canister_pbuf_path(canister_id: CanisterId) -> String {
    // Empty root so that all paths are relative like in the manifest.
    let checkpoint_layout =
        CheckpointLayout::<ReadOnly>::new_untracked("".into(), Height::new(0)).unwrap();

    checkpoint_layout
        .canister(&canister_id)
        .unwrap()
        .canister()
        .raw_path()
        .to_str()
        .unwrap()
        .to_string()
}
/*
/// Returns the relative path to the `snapshot.pbuf` for the given snapshot.
fn snapshot_pbuf_path(snapshot_id: SnapshotId) -> String {
    // Empty root so that all paths are relative like in the manifest.
    let checkpoint_layout =
        CheckpointLayout::<ReadOnly>::new_untracked("".into(), Height::new(0)).unwrap();

    checkpoint_layout
        .snapshot(&snapshot_id)
        .unwrap()
        .snapshot()
        .raw_path()
        .to_str()
        .unwrap()
        .to_string()
}
*/
/// Returns the expected `FileInfo` and `ChunkInfo` for the split marker from
/// `SUBNET_0`.
fn expected_split_marker() -> (FileInfo, ChunkInfo) {
    (
        FileInfo {
            relative_path: PathBuf::from(SPLIT_MARKER_FILE),
            size_bytes: 16,
            hash: [
                232, 254, 158, 246, 6, 59, 141, 144, 45, 54, 253, 159, 199, 38, 128, 142, 232, 135,
                58, 121, 198, 70, 62, 56, 216, 120, 182, 253, 126, 47, 21, 137,
            ],
        },
        ChunkInfo {
            file_index: 13,
            size_bytes: 16,
            offset: 0,
            hash: [
                251, 82, 21, 141, 222, 179, 76, 96, 45, 135, 204, 160, 177, 218, 133, 50, 0, 19,
                228, 50, 190, 131, 243, 72, 80, 219, 103, 46, 142, 229, 252, 6,
            ],
        },
    )
}
/*
/// Returns the expected `FileInfo` and `ChunkInfo` for the system metadata of
/// `SUBNET_1`.
fn expected_subnet_1_system_metadata() -> (FileInfo, ChunkInfo) {
    (
        FileInfo {
            relative_path: PathBuf::from(SYSTEM_METADATA_FILE),
            size_bytes: 63,
            hash: [
                122, 238, 38, 137, 170, 83, 240, 133, 62, 48, 18, 112, 233, 148, 191, 115, 239,
                115, 135, 234, 25, 157, 24, 45, 161, 179, 219, 112, 242, 95, 10, 217,
            ],
        },
        ChunkInfo {
            file_index: 13,
            size_bytes: 63,
            offset: 0,
            hash: [
                167, 162, 133, 251, 148, 255, 80, 204, 229, 63, 140, 219, 43, 228, 234, 250, 69,
                49, 7, 200, 173, 216, 136, 186, 183, 255, 101, 117, 229, 161, 238, 156,
            ],
        },
    )
}
*/
