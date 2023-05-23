use super::*;
use crate::{
    checkpoint::make_checkpoint, tip::spawn_tip_thread, ManifestMetrics, StateManagerMetrics,
    NUMBER_OF_CHECKPOINT_THREADS,
};
use ic_base_types::{subnet_id_try_from_protobuf, CanisterId, NumSeconds};
use ic_error_types::{ErrorCode, UserError};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map::TestPageAllocatorFileDescriptorImpl, ReplicatedState, SystemMetadata,
};
use ic_state_layout::{ProtoFileWith, StateLayout};
use ic_test_utilities::{
    mock_time,
    state::new_canister_state,
    types::ids::{user_test_id, SUBNET_1, SUBNET_2},
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_tmpdir::tmpdir;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    malicious_flags::MaliciousFlags,
    messages::MessageId,
    state_sync::{FileInfo, Manifest, StateSyncVersion},
    Cycles, Height,
};
use std::{path::Path, sync::Arc};
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
const SUBNET_A_FILES: &[&str] = &[
    "canister_states/00000000000000010101/canister.pbuf",
    "canister_states/00000000000000010101/queues.pbuf",
    "canister_states/00000000000000020101/canister.pbuf",
    "canister_states/00000000000000020101/queues.pbuf",
    "canister_states/00000000000000030101/canister.pbuf",
    "canister_states/00000000000000030101/queues.pbuf",
    "ingress_history.pbuf",
    "subnet_queues.pbuf",
    "system_metadata.pbuf",
];

/// Full list of files expected to be listed in the manifest of subnet A'.
const SUBNET_A_PRIME_FILES: &[&str] = &[
    "canister_states/00000000000000010101/canister.pbuf",
    "canister_states/00000000000000010101/queues.pbuf",
    "canister_states/00000000000000030101/canister.pbuf",
    "canister_states/00000000000000030101/queues.pbuf",
    "ingress_history.pbuf",
    "split_from.pbuf",
    "subnet_queues.pbuf",
    "system_metadata.pbuf",
];

/// Full list of files expected to be listed in the manifest of subnet B.
const SUBNET_B_FILES: &[&str] = &[
    "canister_states/00000000000000020101/canister.pbuf",
    "canister_states/00000000000000020101/queues.pbuf",
    "ingress_history.pbuf",
    "split_from.pbuf",
    "subnet_queues.pbuf",
    "system_metadata.pbuf",
];

const HEIGHT: Height = Height::new(42);
const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

#[test]
fn read_write_roundtrip() {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let tmp = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();
        let metrics_registry = MetricsRegistry::new();
        let layout = StateLayout::try_new(log.clone(), root, &metrics_registry).unwrap();
        let mut thread_pool = Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
        // Sanity check: ensure that we have a single checkpoint.
        assert_eq!(1, layout.checkpoint_heights().unwrap().len());

        // Compute the manifest of the original checkpoint.
        let metrics = StateManagerMetrics::new(&metrics_registry);
        let manifest_metrics = &metrics.manifest_metrics;
        let (manifest_before, height_before) = compute_manifest_v3(&layout, manifest_metrics, &log);

        // Read the latest checkpoint into a state.
        let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());
        let (cp, state) = read_checkpoint(&layout, &mut thread_pool, fd_factory.clone(), &metrics)
            .expect("failed to read checkpoint");

        // Sanity check: ensure that `split_from` is not set by default.
        assert_eq!(None, state.metadata.split_from);

        // Write back the state as a new checkpoint.
        write_checkpoint(
            &state,
            layout.clone(),
            &cp,
            &mut thread_pool,
            fd_factory,
            &metrics,
            log.clone(),
        )
        .expect("failed to write checkpoint");
        // Sanity check: ensure that we now have exactly two checkpoints.
        assert_eq!(2, layout.checkpoint_heights().unwrap().len());

        // Compute the manifest of the newly written checkpoint.
        let (manifest_after, height_after) = compute_manifest_v3(&layout, manifest_metrics, &log);

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
        let tmp = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();

        let (manifest_a, height_a) = compute_manifest_v3_for_root(&root, &log);
        assert_eq!(SUBNET_A_FILES, manifest_files(&manifest_a).as_slice());

        split(
            root.clone(),
            SUBNET_A.get(),
            Vec::from(SUBNET_A_RANGES).try_into().unwrap(),
            &MetricsRegistry::new(),
            log.clone(),
        )
        .unwrap();

        let (manifest_a_prime, height_a_prime) = compute_manifest_v3_for_root(&root, &log);
        assert_eq!(
            SUBNET_A_PRIME_FILES,
            manifest_files(&manifest_a_prime).as_slice()
        );

        // Checkpoint heights should differ by 1.
        assert_eq!(height_a.increment(), height_a_prime);

        // Compare the 2 manifests.
        for &file in SUBNET_A_PRIME_FILES {
            if file == "split_from.pbuf" {
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

/// Tests splitting subnet B (to host canisters 2 and 4; different subnet ID)
/// from subnet A (hosting canisters 1, 2, and 3; no canister 4).
#[test]
fn split_subnet_b() {
    with_test_replica_logger(|log| {
        // Create a new state layout.
        let tmp = new_state_layout(log.clone());
        let root = tmp.path().to_path_buf();

        let (manifest_a, height_a) = compute_manifest_v3_for_root(&root, &log);
        assert_eq!(SUBNET_A_FILES, manifest_files(&manifest_a).as_slice());

        split(
            root.clone(),
            SUBNET_B.get(),
            Vec::from(SUBNET_B_RANGES).try_into().unwrap(),
            &MetricsRegistry::new(),
            log.clone(),
        )
        .unwrap();

        let (manifest_b, height_b) = compute_manifest_v3_for_root(&root, &log);
        assert_eq!(SUBNET_B_FILES, manifest_files(&manifest_b).as_slice());

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
        for &file in SUBNET_B_FILES {
            if file == "split_from.pbuf" {
                assert_eq!(SUBNET_A, deserialize_split_from(&root, height_b));
            } else if file == "system_metadata.pbuf" {
                let expected = SystemMetadata::new(SUBNET_B, SubnetType::Application);
                assert_eq!(expected, deserialize_system_metadata(&root, height_b))
            } else {
                // All other files should be unmodified (`subnet_queues.pbuf` was never
                // populated in this test, so it happens to be identical).
                assert_eq!(file_info(file, &manifest_a), file_info(file, &manifest_b))
            }
        }
    })
}

/// Creates a state layout under a temporary directory, with 3 canisters:
/// `CANISTER_1`, `CANISTER_2` and `CANISTER_3`.
fn new_state_layout(log: ReplicaLogger) -> TempDir {
    let tmp = tmpdir("checkpoint");
    let root = tmp.path().to_path_buf();
    let metrics_registry = MetricsRegistry::new();
    let layout = StateLayout::try_new(log.clone(), root.clone(), &metrics_registry).unwrap();
    let tip_handler = layout.capture_tip_handler();
    let state_manager_metrics = StateManagerMetrics::new(&metrics_registry);
    let (_tip_thread, tip_channel) = spawn_tip_thread(
        log,
        tip_handler,
        layout.clone(),
        state_manager_metrics.clone(),
        MaliciousFlags::default(),
    );

    let mut state = ReplicatedState::new(SUBNET_A, SubnetType::Application);
    state.put_canister_state(new_canister_state(
        CANISTER_1,
        CANISTER_0.get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    ));
    state.put_canister_state(new_canister_state(
        CANISTER_2,
        CANISTER_0.get(),
        INITIAL_CYCLES * 2usize,
        NumSeconds::from(200_000),
    ));
    state.put_canister_state(new_canister_state(
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
            time: mock_time(),
            state: IngressState::Failed(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "Canister rejected the message",
            )),
        },
        mock_time(),
        (1u64 << 30).into(),
    );

    let _state = make_checkpoint(
        &state,
        HEIGHT,
        &tip_channel,
        &state_manager_metrics.checkpoint_metrics,
        &mut thread_pool(),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap_or_else(|err| panic!("Expected make_checkpoint to succeed, got {:?}", err))
    .1;

    // Sanity checks.
    assert_eq!(layout.checkpoint_heights().unwrap(), vec![HEIGHT]);
    let checkpoint = layout.checkpoint(HEIGHT).unwrap();
    assert_eq!(
        checkpoint.canister_ids().unwrap(),
        vec![CANISTER_1, CANISTER_2, CANISTER_3]
    );

    let checkpoint_path = root.join("checkpoints").join("000000000000002a");

    let mut expected_paths = vec![
        checkpoint_path.join("ingress_history.pbuf"),
        checkpoint_path.join("subnet_queues.pbuf"),
        checkpoint_path.join("system_metadata.pbuf"),
    ];
    for canister in &[CANISTER_1, CANISTER_2] {
        let canister_path = checkpoint_path
            .join("canister_states")
            .join(hex::encode(canister.get_ref().as_slice()));
        expected_paths.push(canister_path.join("queues.pbuf"));
        expected_paths.push(canister_path.join("canister.pbuf"));
    }

    for path in expected_paths {
        assert!(path.exists(), "Expected path {} to exist", path.display());
        assert!(
            path.metadata().unwrap().permissions().readonly(),
            "Expected path {} to be readonly",
            path.display()
        );
    }

    tmp
}

/// Computes the `V3` manifest of the last checkpoint under `state_layout`.
fn compute_manifest_v3(
    state_layout: &StateLayout,
    manifest_metrics: &ManifestMetrics,
    log: &ReplicaLogger,
) -> (Manifest, Height) {
    let last_checkpoint_height = state_layout.checkpoint_heights().unwrap().pop().unwrap();
    let last_checkpoint_layout = state_layout.checkpoint(last_checkpoint_height).unwrap();
    let manifest = crate::manifest::compute_manifest(
        &mut thread_pool(),
        manifest_metrics,
        log,
        StateSyncVersion::V3,
        &last_checkpoint_layout,
        1024,
        None,
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
    panic!("file '{}' not found in manifest: {:?}", file, manifest)
}

/// Computes the V3 manifest of the latest checkpoint under the state layout at
/// `root`.
fn compute_manifest_v3_for_root(root: &Path, log: &ReplicaLogger) -> (Manifest, Height) {
    let metrics_registry = MetricsRegistry::new();
    let layout = StateLayout::try_new(log.clone(), root.to_path_buf(), &metrics_registry).unwrap();

    // Compute the manifest of the original checkpoint.
    let metrics = StateManagerMetrics::new(&metrics_registry);
    let manifest_metrics = &metrics.manifest_metrics;
    compute_manifest_v3(&layout, manifest_metrics, log)
}

fn deserialize_split_from(root: &Path, height: Height) -> SubnetId {
    let split_from: ProtoFileWith<ic_protobuf::state::system_metadata::v1::SplitFrom, ReadOnly> =
        root.join("checkpoints")
            .join(StateLayout::checkpoint_name(height))
            .join("split_from.pbuf")
            .into();
    subnet_id_try_from_protobuf(split_from.deserialize().unwrap().subnet_id.unwrap()).unwrap()
}

fn deserialize_system_metadata(root: &Path, height: Height) -> SystemMetadata {
    let system_metadata: ProtoFileWith<
        ic_protobuf::state::system_metadata::v1::SystemMetadata,
        ReadOnly,
    > = root
        .join("checkpoints")
        .join(StateLayout::checkpoint_name(height))
        .join("system_metadata.pbuf")
        .into();
    system_metadata.deserialize().unwrap().try_into().unwrap()
}
