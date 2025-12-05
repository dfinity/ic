use super::*;
use crate::{
    CheckpointMetrics, ManifestMetrics, NUMBER_OF_CHECKPOINT_THREADS, StateManagerMetrics,
    checkpoint::make_unvalidated_checkpoint,
    flush_canister_snapshots_and_page_maps,
    manifest::RehashManifest,
    state_sync::types::{FileInfo, Manifest},
    tip::{flush_tip_channel, spawn_tip_thread},
};
use assert_matches::assert_matches;
use ic_base_types::{CanisterId, NumSeconds, SnapshotId, subnet_id_try_from_protobuf};
use ic_config::state_manager::lsmt_config_default;
use ic_error_types::{ErrorCode, UserError};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CheckpointLoadingMetrics, ReplicatedState, SystemMetadata,
    canister_snapshots::CanisterSnapshot, page_map::TestPageAllocatorFileDescriptorImpl,
    testing::ReplicatedStateTesting,
};
use ic_state_layout::{
    CANISTER_FILE, CANISTER_STATES_DIR, CHECKPOINTS_DIR, INGRESS_HISTORY_FILE, ProtoFileWith,
    REFUNDS_FILE, SPLIT_MARKER_FILE, SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE, StateLayout,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::new_canister_state_with_execution;
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::{
    ids::{SUBNET_1, SUBNET_2, user_test_id},
    messages::RequestBuilder,
};
use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;
use ic_types::{
    Cycles, Height,
    ingress::{IngressState, IngressStatus},
    malicious_flags::MaliciousFlags,
    messages::MessageId,
    time::UNIX_EPOCH,
};
use std::{path::Path, sync::Arc, time::Duration};
use tempfile::TempDir;

/// ID of original subnet A. And of subnet A' after the split.
const SUBNET_A: SubnetId = SUBNET_1;
/// Subnet B ID.
const SUBNET_B: SubnetId = SUBNET_2;

/// Fictitious controller of all other canisters.
const CANISTER_0: CanisterId = CanisterId::from_u64(0);
const CANISTER_1: CanisterId = CanisterId::from_u64(1);
const CANISTER_2: CanisterId = CanisterId::from_u64(2);
const CANISTER_3: CanisterId = CanisterId::from_u64(3);
/// Inexistent canister, but part of the ID ranges to be hosted by subnet B.
const CANISTER_4: CanisterId = CanisterId::from_u64(4);

/// Canister ID ranges to be hosted by subnet A' after the split. Includes
/// canisters 1 and 3.
const SUBNET_A_RANGES: &[CanisterIdRange] = &[
    CanisterIdRange {
        start: CANISTER_1,
        end: CANISTER_1,
    },
    CanisterIdRange {
        start: CANISTER_3,
        end: CANISTER_3,
    },
];

/// Canister ID ranges to be hosted by subnet B after the split. Includes
/// canister 2 and inexistent canister 4.
const SUBNET_B_RANGES: &[CanisterIdRange] = &[
    CanisterIdRange {
        start: CANISTER_2,
        end: CANISTER_2,
    },
    CanisterIdRange {
        start: CANISTER_4,
        end: CANISTER_4,
    },
];

/// Full list of files expected to be listed in the manifest of subnet A.
/// Note that any queue files are missing as they would be empty.
fn subnet_a_files() -> &'static [&'static str] {
    &[
        "canister_states/00000000000000010101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000010101/canister.pbuf",
        "canister_states/00000000000000010101/software.wasm",
        "canister_states/00000000000000020101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000020101/canister.pbuf",
        "canister_states/00000000000000020101/software.wasm",
        "canister_states/00000000000000030101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000030101/canister.pbuf",
        "canister_states/00000000000000030101/software.wasm",
        INGRESS_HISTORY_FILE,
        REFUNDS_FILE,
        "snapshots/00000000000000010101/000000000000000000000000000000010101/snapshot.pbuf",
        "snapshots/00000000000000010101/000000000000000000000000000000010101/software.wasm",
        SUBNET_QUEUES_FILE,
        SYSTEM_METADATA_FILE,
    ]
}

/// Full list of files expected to be listed in the manifest of subnet A'.
fn subnet_a_prime_files() -> &'static [&'static str] {
    &[
        "canister_states/00000000000000010101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000010101/canister.pbuf",
        "canister_states/00000000000000010101/software.wasm",
        "canister_states/00000000000000030101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000030101/canister.pbuf",
        "canister_states/00000000000000030101/software.wasm",
        INGRESS_HISTORY_FILE,
        REFUNDS_FILE,
        "snapshots/00000000000000010101/000000000000000000000000000000010101/snapshot.pbuf",
        "snapshots/00000000000000010101/000000000000000000000000000000010101/software.wasm",
        SPLIT_MARKER_FILE,
        SUBNET_QUEUES_FILE,
        SYSTEM_METADATA_FILE,
    ]
}

/// Full list of files expected to be listed in the manifest of subnet B.
fn subnet_b_files() -> &'static [&'static str] {
    &[
        "canister_states/00000000000000020101/000000000000002a_0000_log_memory_store.overlay",
        "canister_states/00000000000000020101/canister.pbuf",
        "canister_states/00000000000000020101/software.wasm",
        INGRESS_HISTORY_FILE,
        SPLIT_MARKER_FILE,
        SYSTEM_METADATA_FILE,
    ]
}

const HEIGHT: Height = Height::new(42);
const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

#[test]
fn read_write_roundtrip() {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let (tmp, _) = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();
        let metrics_registry = MetricsRegistry::new();
        let layout = StateLayout::try_new(log.clone(), root.clone(), &metrics_registry).unwrap();
        let mut thread_pool = Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
        // Sanity check: ensure that we have a single checkpoint.
        assert_eq!(1, layout.checkpoint_heights().unwrap().len());

        // Compute the manifest of the original checkpoint.
        let metrics = StateManagerMetrics::new(&metrics_registry, log.clone());
        let manifest_metrics = &metrics.manifest_metrics;
        let (manifest_before, height_before) = compute_manifest(&layout, manifest_metrics, &log);

        // Read the latest checkpoint into a state.
        let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());
        let (cp, state) = read_checkpoint(&layout, &mut thread_pool, fd_factory.clone(), &metrics)
            .expect("failed to read checkpoint");

        // Sanity check: ensure that `split_from` is not set by default.
        assert_eq!(None, state.metadata.split_from);

        // Write back the state as a new checkpoint.
        write_checkpoint(
            state,
            layout.clone(),
            &cp,
            &mut thread_pool,
            &Config::new(root),
            fd_factory.clone(),
            &metrics,
            log.clone(),
        )
        .expect("failed to write checkpoint");
        // Sanity check: ensure that we now have exactly two checkpoints.
        assert_eq!(2, layout.checkpoint_heights().unwrap().len());

        // Compute the manifest of the newly written checkpoint.
        let (manifest_after, height_after) = compute_manifest(&layout, manifest_metrics, &log);

        // The two checkpoints' manifests should be identical.
        assert_eq!(manifest_before, manifest_after);
        // And their checkpoint heights should differ by 1.
        assert_eq!(height_before.increment(), height_after);
    })
}

/// Tests splitting subnet A' (to host canisters 1 and 3; same subnet ID) from
/// subnet A (hosting canisters 1, 2, and 3).
#[test]
fn split_subnet_a_prime() {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let (tmp, _) = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();

        let (manifest_a, height_a) = compute_manifest_for_root(&root, &log);
        assert_eq!(subnet_a_files(), manifest_files(&manifest_a).as_slice());

        split(
            root.clone(),
            SUBNET_A.get(),
            Vec::from(SUBNET_A_RANGES).try_into().unwrap(),
            None,
            &MetricsRegistry::new(),
            log.clone(),
        )
        .unwrap();

        let (manifest_a_prime, height_a_prime) = compute_manifest_for_root(&root, &log);
        assert_eq!(
            subnet_a_prime_files(),
            manifest_files(&manifest_a_prime).as_slice()
        );

        // Checkpoint heights should differ by 1.
        assert_eq!(height_a.increment(), height_a_prime);

        // Compare the 2 manifests.
        for &file in subnet_a_prime_files() {
            if file == SPLIT_MARKER_FILE {
                assert_eq!(SUBNET_A, deserialize_split_from(&root, height_a_prime));
            } else {
                // All other files should be unmodified.
                assert_eq!(
                    file_info(file, &manifest_a),
                    file_info(file, &manifest_a_prime)
                )
            }
        }
    })
}

/// Tests splitting subnet A' while providing an explicit `batch_time`.
#[test]
fn split_subnet_a_prime_with_batch_time() {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let (tmp, batch_time) = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();

        let res = split(
            root,
            SUBNET_A.get(),
            Vec::from(SUBNET_A_RANGES).try_into().unwrap(),
            Some(batch_time),
            &MetricsRegistry::new(),
            log,
        );

        assert_matches!(res, Err(_));
    })
}

/// Common logic for splitting subnet B with or without a provided `batch_time`.
/// Tests splitting subnet B (to host canisters 2 and 4; different subnet ID)
/// from subnet A (hosting canisters 1, 2, and 3; no canister 4).
///
/// `new_subnet_batch_time_delta` is a `Duration` to be added to the
/// `batch_time` of the last checkpoint to produce a `new_subnet_batch_time` to
/// pass to the `split()` function. If `None`, then `None` is previded as the
/// `new_subnet_batch_time`.
fn split_subnet_b_helper(new_subnet_batch_time_delta: Option<Duration>) {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let (tmp, batch_time) = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();

        let new_subnet_batch_time = new_subnet_batch_time_delta.map(|delta| batch_time + delta);

        let (manifest_a, height_a) = compute_manifest_for_root(&root, &log);
        assert_eq!(subnet_a_files(), manifest_files(&manifest_a).as_slice());

        split(
            root.clone(),
            SUBNET_B.get(),
            Vec::from(SUBNET_B_RANGES).try_into().unwrap(),
            new_subnet_batch_time,
            &MetricsRegistry::new(),
            log.clone(),
        )
        .unwrap();

        let (manifest_b, height_b) = compute_manifest_for_root(&root, &log);
        assert_eq!(subnet_b_files(), manifest_files(&manifest_b).as_slice());

        // Checkpoint heights should differ by 1.
        assert_eq!(height_a.increment(), height_b);

        // Assuming that both (i) the binary that produces the expected manifest
        // (whether replica or state tool); and (ii) the binary that splits the
        // state; are supposed to be built from the same source code; persisting
        // equal Rust structs should yield identical binary representations.
        //
        // Anything else would mean that either the roundtrip conversion or prost's
        // encoding are non-deterministic.
        //
        // Hence, for files that we expect to be different after the split it is
        // safe to compare the resulding Rust structs for equality.
        for &file in subnet_b_files() {
            if file == SPLIT_MARKER_FILE {
                assert_eq!(SUBNET_A, deserialize_split_from(&root, height_b));
            } else if file == SYSTEM_METADATA_FILE {
                let mut expected = SystemMetadata::new(SUBNET_B, SubnetType::Application);
                // `batch_time` should be the provided `new_subnet_batch_time` (if `Some`); or
                // else the original subnet's `batch_time`.
                expected.batch_time = new_subnet_batch_time.unwrap_or(batch_time);
                assert_eq!(expected, deserialize_system_metadata(&root, height_b, &log))
            } else {
                // All other files should be unmodified (`subnet_queues.pbuf` was never
                // populated in this test, so it happens to be identical).
                assert_eq!(file_info(file, &manifest_a), file_info(file, &manifest_b))
            }
        }
    })
}

/// Test splitting subnet B without an explicit `new_subnet_batch_delta`.
#[test]
fn split_subnet_b() {
    split_subnet_b_helper(None);
}

/// Test splitting subnet B with `new_subnet_batch_delta == batch_delta`.
#[test]
fn split_subnet_b_with_equal_batch_delta() {
    split_subnet_b_helper(Some(Duration::from_nanos(0)));
}

/// Test splitting subnet B with `new_subnet_batch_delta > batch_delta`.
#[test]
fn split_subnet_b_with_greater_batch_delta() {
    split_subnet_b_helper(Some(Duration::from_nanos(13)));
}

/// Creates a state layout under a temporary directory, with 3 canisters:
/// `CANISTER_1`, `CANISTER_2` and `CANISTER_3`.
///
/// Returns a handle to the `TempDir` holding the state layoutl; and the batch
/// time of the last (and only) checkpoint within.
fn new_state_layout(log: ReplicaLogger) -> (TempDir, Time) {
    let tmp = tmpdir("checkpoint");
    let root = tmp.path().to_path_buf();
    let metrics_registry = MetricsRegistry::new();
    let layout = StateLayout::try_new(log.clone(), root.clone(), &metrics_registry).unwrap();
    let tip_handler = layout.capture_tip_handler();
    let state_manager_metrics = StateManagerMetrics::new(&metrics_registry, log.clone());
    let (_tip_thread, tip_channel) = spawn_tip_thread(
        log,
        tip_handler,
        layout.clone(),
        lsmt_config_default(),
        state_manager_metrics.clone(),
        MaliciousFlags::default(),
    );

    let mut state = ReplicatedState::new(SUBNET_A, SubnetType::Application);
    state.put_canister_state(new_canister_state_with_execution(
        CANISTER_1,
        CANISTER_0.get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    ));
    state.put_canister_state(new_canister_state_with_execution(
        CANISTER_2,
        CANISTER_0.get(),
        INITIAL_CYCLES * 2usize,
        NumSeconds::from(200_000),
    ));
    state.put_canister_state(new_canister_state_with_execution(
        CANISTER_3,
        CANISTER_0.get(),
        INITIAL_CYCLES * 3usize,
        NumSeconds::from(300_000),
    ));
    state.metadata.ingress_history.insert(
        MessageId::from([13; 32]),
        IngressStatus::Known {
            receiver: CANISTER_1.get(),
            user_id: user_test_id(123),
            time: UNIX_EPOCH,
            state: IngressState::Failed(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "Canister rejected the message",
            )),
        },
        UNIX_EPOCH,
        (1u64 << 30).into(),
        |_| {},
    );
    state.metadata.batch_time = Time::from_secs_since_unix_epoch(1234567890).unwrap();
    state.add_refund(CANISTER_0, Cycles::new(1 << 20));

    let snapshot_id = SnapshotId::from((CANISTER_1, 0));
    let snapshot =
        CanisterSnapshot::from_canister(state.canister_state(&CANISTER_1).unwrap(), state.time())
            .unwrap();
    state.take_snapshot(snapshot_id, Arc::new(snapshot));

    // Make subnet_queues non-empty
    state
        .push_input(
            RequestBuilder::default()
                .receiver(state.metadata.own_subnet_id.into())
                .build()
                .into(),
            &mut (10 << 30),
        )
        .unwrap();

    flush_canister_snapshots_and_page_maps(&mut state, HEIGHT, &tip_channel);

    let mut thread_pool = thread_pool();
    let (state, cp_layout) = make_unvalidated_checkpoint(
        state,
        HEIGHT,
        &tip_channel,
        &state_manager_metrics.checkpoint_metrics,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap_or_else(|err| panic!("Expected make_unvalidated_checkpoint to succeed, got {err:?}"));
    flush_tip_channel(&tip_channel);
    let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());
    validate_and_finalize_checkpoint_and_remove_unverified_marker(
        &cp_layout,
        None,
        SubnetType::Application,
        fd_factory.clone(),
        &state_manager_metrics.checkpoint_metrics,
        Some(&mut thread_pool),
    )
    .unwrap();

    // Sanity checks.
    assert_eq!(layout.checkpoint_heights().unwrap(), vec![HEIGHT]);
    let checkpoint = layout.checkpoint_verified(HEIGHT).unwrap();
    assert_eq!(
        checkpoint.canister_ids().unwrap(),
        vec![CANISTER_1, CANISTER_2, CANISTER_3]
    );

    let checkpoint_path = root.join(CHECKPOINTS_DIR).join("000000000000002a");

    let mut expected_paths = vec![
        checkpoint_path.join(INGRESS_HISTORY_FILE),
        checkpoint_path.join(SUBNET_QUEUES_FILE),
        checkpoint_path.join(SYSTEM_METADATA_FILE),
    ];
    for canister in &[CANISTER_1, CANISTER_2] {
        let canister_path = checkpoint_path
            .join(CANISTER_STATES_DIR)
            .join(hex::encode(canister.get_ref().as_slice()));
        expected_paths.push(canister_path.join(CANISTER_FILE));
    }

    for path in expected_paths {
        assert!(path.exists(), "Expected path {} to exist", path.display());
        assert!(
            path.metadata().unwrap().permissions().readonly(),
            "Expected path {} to be readonly",
            path.display()
        );
    }

    (tmp, state.metadata.batch_time)
}

#[test]
fn test_resolve_retain() {
    let retain = make_range(3, 4);
    assert_eq!(
        CanisterIdRanges::try_from(vec![retain]),
        resolve(vec![retain], vec![])
    );
}

#[test]
fn test_resolve_drop() {
    let drop = make_range(3, 4);
    assert_eq!(
        CanisterIdRanges::try_from(vec![make_range(0, 2), make_range(5, u64::MAX)]),
        resolve(vec![], vec![drop])
    );
}

#[test]
fn test_resolve_not_well_formed() {
    let retain = make_range(4, 3);
    resolve(vec![retain], vec![]).unwrap_err();
}

#[test]
#[should_panic]
fn test_resolve_both_non_empty() {
    let range = make_range(3, 4);
    resolve(vec![range], vec![range]).ok();
}

#[test]
#[should_panic]
fn test_resolve_both_empty() {
    resolve(vec![], vec![]).ok();
}

fn make_range(start: u64, end: u64) -> CanisterIdRange {
    CanisterIdRange {
        start: CanisterId::from_u64(start),
        end: CanisterId::from_u64(end),
    }
}

/// Computes the manifest of the last checkpoint under `state_layout`.
fn compute_manifest(
    state_layout: &StateLayout,
    manifest_metrics: &ManifestMetrics,
    log: &ReplicaLogger,
) -> (Manifest, Height) {
    let last_checkpoint_height = state_layout.checkpoint_heights().unwrap().pop().unwrap();
    let last_checkpoint_layout = state_layout
        .checkpoint_verified(last_checkpoint_height)
        .unwrap();
    let manifest = crate::manifest::compute_manifest(
        &mut thread_pool(),
        manifest_metrics,
        log,
        CURRENT_STATE_SYNC_VERSION,
        &last_checkpoint_layout,
        1024,
        None,
        RehashManifest::No,
    )
    .expect("failed to compute manifest");

    (manifest, last_checkpoint_height)
}

/// Creates a thread pool to be used for checkpointing.
fn thread_pool() -> scoped_threadpool::Pool {
    scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS)
}

/// Extracts the list of relative file names from the manifest.
fn manifest_files(manifest: &Manifest) -> Vec<String> {
    manifest
        .file_table
        .iter()
        .map(|file_info| {
            file_info
                .relative_path
                .as_os_str()
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

/// Retrieves the `FileInfo` for `file` from `manifest`. Panics if not found.
fn file_info<'a>(file: &str, manifest: &'a Manifest) -> &'a FileInfo {
    for file_info in manifest.file_table.iter() {
        if file_info.relative_path.as_os_str().to_string_lossy() == file {
            return file_info;
        }
    }
    panic!("file '{file}' not found in manifest: {manifest:?}")
}

/// Computes the manifest of the latest checkpoint under the state layout at
/// `root`.
fn compute_manifest_for_root(root: &Path, log: &ReplicaLogger) -> (Manifest, Height) {
    let metrics_registry = MetricsRegistry::new();
    let layout = StateLayout::try_new(log.clone(), root.to_path_buf(), &metrics_registry).unwrap();

    // Compute the manifest of the original checkpoint.
    let metrics = StateManagerMetrics::new(&metrics_registry, log.clone());
    let manifest_metrics = &metrics.manifest_metrics;
    compute_manifest(&layout, manifest_metrics, log)
}

fn deserialize_split_from(root: &Path, height: Height) -> SubnetId {
    let split_from: ProtoFileWith<ic_protobuf::state::system_metadata::v1::SplitFrom, ReadOnly> =
        root.join(CHECKPOINTS_DIR)
            .join(StateLayout::checkpoint_name(height))
            .join(SPLIT_MARKER_FILE)
            .into();
    subnet_id_try_from_protobuf(split_from.deserialize().unwrap().subnet_id.unwrap()).unwrap()
}

fn deserialize_system_metadata(root: &Path, height: Height, log: &ReplicaLogger) -> SystemMetadata {
    let system_metadata: ProtoFileWith<
        ic_protobuf::state::system_metadata::v1::SystemMetadata,
        ReadOnly,
    > = root
        .join(CHECKPOINTS_DIR)
        .join(StateLayout::checkpoint_name(height))
        .join(SYSTEM_METADATA_FILE)
        .into();
    (
        system_metadata.deserialize().unwrap(),
        &CheckpointMetrics::new(&MetricsRegistry::new(), log.clone())
            as &dyn CheckpointLoadingMetrics,
    )
        .try_into()
        .unwrap()
}
