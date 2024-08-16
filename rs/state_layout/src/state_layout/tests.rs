use super::*;

use ic_management_canister_types::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallMode, IC_00,
};
use ic_replicated_state::{
    canister_state::system_state::CanisterHistory,
    metadata_state::subnet_call_context_manager::InstallCodeCallId, page_map::Shard, NumWasmPages,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, ResponseBuilder};
use ic_test_utilities_types::{ids::canister_test_id, ids::user_test_id};
use ic_types::messages::{CanisterCall, CanisterMessage, CanisterMessageOrTask};
use ic_types::time::UNIX_EPOCH;
use itertools::Itertools;
use proptest::prelude::*;
use std::fs::File;
use std::sync::Arc;

fn default_canister_state_bits() -> CanisterStateBits {
    CanisterStateBits {
        controllers: BTreeSet::new(),
        last_full_execution_round: ExecutionRound::from(0),
        call_context_manager: None,
        compute_allocation: ComputeAllocation::try_from(0).unwrap(),
        accumulated_priority: AccumulatedPriority::default(),
        priority_credit: AccumulatedPriority::default(),
        long_execution_mode: LongExecutionMode::default(),
        execution_state_bits: None,
        memory_allocation: MemoryAllocation::default(),
        wasm_memory_threshold: NumBytes::new(0),
        freeze_threshold: NumSeconds::from(0),
        cycles_balance: Cycles::zero(),
        cycles_debit: Cycles::zero(),
        reserved_balance: Cycles::zero(),
        reserved_balance_limit: None,
        status: CanisterStatus::Stopped,
        scheduled_as_first: 0,
        skipped_round_due_to_no_messages: 0,
        executed: 0,
        interrupted_during_execution: 0,
        certified_data: vec![],
        consumed_cycles: NominalCycles::from(0),
        stable_memory_size: NumWasmPages::from(0),
        heap_delta_debit: NumBytes::from(0),
        install_code_debit: NumInstructions::from(0),
        time_of_last_allocation_charge_nanos: 0,
        task_queue: vec![],
        global_timer_nanos: None,
        canister_version: 0,
        consumed_cycles_by_use_cases: BTreeMap::new(),
        canister_history: CanisterHistory::default(),
        wasm_chunk_store_metadata: WasmChunkStoreMetadata::default(),
        total_query_stats: TotalQueryStats::default(),
        log_visibility: Default::default(),
        canister_log: Default::default(),
        wasm_memory_limit: None,
        next_snapshot_id: 0,
        snapshots_memory_usage: NumBytes::from(0),
    }
}

#[test]
fn test_state_layout_diverged_state_paths() {
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path.clone(), &metrics_registry).unwrap();
        state_layout
            .create_diverged_state_marker(Height::new(1))
            .unwrap();
        assert_eq!(
            state_layout.diverged_state_heights().unwrap(),
            vec![Height::new(1)],
        );
        assert!(state_layout
            .diverged_state_marker_path(Height::new(1))
            .starts_with(root_path.join("diverged_state_markers")));
        state_layout
            .remove_diverged_state_marker(Height::new(1))
            .unwrap();
        assert!(state_layout.diverged_state_heights().unwrap().is_empty());
    });
}

#[test]
fn test_encode_decode_empty_controllers() {
    // A canister state with empty controllers.
    let canister_state_bits = default_canister_state_bits();

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    // Controllers are still empty, as expected.
    assert_eq!(canister_state_bits.controllers, BTreeSet::new());
}

#[test]
fn test_encode_decode_non_empty_controllers() {
    let mut controllers = BTreeSet::new();
    controllers.insert(IC_00.into());
    controllers.insert(canister_test_id(0).get());

    // A canister state with non-empty controllers.
    let canister_state_bits = CanisterStateBits {
        controllers,
        ..default_canister_state_bits()
    };

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    let mut expected_controllers = BTreeSet::new();
    expected_controllers.insert(canister_test_id(0).get());
    expected_controllers.insert(IC_00.into());
    assert_eq!(canister_state_bits.controllers, expected_controllers);
}

#[test]
fn test_encode_decode_empty_history() {
    let canister_history = CanisterHistory::default();

    // A canister state with empty history.
    let canister_state_bits = CanisterStateBits {
        canister_history: canister_history.clone(),
        ..default_canister_state_bits()
    };

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_state_bits.canister_history, canister_history);
}

#[test]
fn test_encode_decode_non_empty_history() {
    let mut canister_history = CanisterHistory::default();
    canister_history.add_canister_change(CanisterChange::new(
        42,
        0,
        CanisterChangeOrigin::from_user(user_test_id(42).get()),
        CanisterChangeDetails::canister_creation(vec![
            canister_test_id(777).get(),
            user_test_id(42).get(),
        ]),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        123,
        1,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::CanisterCodeUninstall,
    ));
    canister_history.add_canister_change(CanisterChange::new(
        222,
        2,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), Some(777)),
        CanisterChangeDetails::code_deployment(CanisterInstallMode::Install, [0; 32]),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        222,
        3,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), Some(888)),
        CanisterChangeDetails::code_deployment(CanisterInstallMode::Upgrade, [1; 32]),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        222,
        4,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), Some(999)),
        CanisterChangeDetails::code_deployment(CanisterInstallMode::Reinstall, [2; 32]),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        333,
        5,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::controllers_change(vec![
            canister_test_id(123).into(),
            user_test_id(666).get(),
        ]),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        444,
        6,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::controllers_change(vec![]),
    ));

    // A canister state with non-empty history.
    let canister_state_bits = CanisterStateBits {
        canister_history: canister_history.clone(),
        ..default_canister_state_bits()
    };

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_state_bits.canister_history, canister_history);
}

#[test]
fn test_canister_snapshots_decode() {
    let canister_id = canister_test_id(7);
    let canister_snapshot_bits = CanisterSnapshotBits {
        snapshot_id: SnapshotId::from((canister_id, 5)),
        canister_id,
        taken_at_timestamp: UNIX_EPOCH,
        canister_version: 3,
        binary_hash: Some(WasmHash::from(&CanisterModule::new(vec![2, 3, 4]))),
        certified_data: vec![3, 4, 7],
        wasm_chunk_store_metadata: WasmChunkStoreMetadata::default(),
        stable_memory_size: NumWasmPages::new(10),
        wasm_memory_size: NumWasmPages::new(10),
        total_size: NumBytes::new(100),
    };

    let pb_bits =
        pb_canister_snapshot_bits::CanisterSnapshotBits::from(canister_snapshot_bits.clone());
    let new_canister_snapshot_bits = CanisterSnapshotBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_snapshot_bits, new_canister_snapshot_bits);
}

#[test]
fn test_encode_decode_task_queue() {
    let ingress = Arc::new(IngressBuilder::new().method_name("test_ingress").build());
    let request = Arc::new(RequestBuilder::new().method_name("test_request").build());
    let response = Arc::new(
        ResponseBuilder::new()
            .respondent(canister_test_id(42))
            .build(),
    );
    for task in [
        ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Ingress(Arc::clone(&ingress)),
            prepaid_execution_cycles: Cycles::new(1),
            call_id: InstallCodeCallId::new(0),
        },
        ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Message(CanisterMessage::Request(Arc::clone(&request))),
            prepaid_execution_cycles: Cycles::new(2),
        },
        ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Request(Arc::clone(&request)),
            prepaid_execution_cycles: Cycles::new(3),
            call_id: InstallCodeCallId::new(3u64),
        },
        ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Message(CanisterMessage::Response(Arc::clone(&response))),
            prepaid_execution_cycles: Cycles::new(4),
        },
        ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Message(CanisterMessage::Ingress(Arc::clone(&ingress))),
            prepaid_execution_cycles: Cycles::new(5),
        },
    ] {
        let task_queue = vec![task];
        let canister_state_bits = CanisterStateBits {
            task_queue: task_queue.clone(),
            ..default_canister_state_bits()
        };

        let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
        let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();
        assert_eq!(canister_state_bits.task_queue, task_queue);
    }
}

#[test]
fn test_removal_when_last_dropped() {
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path, &metrics_registry).unwrap();
        let scratchpad_dir = tmpdir("scratchpad");
        let cp1 = state_layout
            .scratchpad_to_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("1"),
                    Height::new(1),
                )
                .unwrap(),
                Height::new(1),
                None,
            )
            .unwrap();
        let cp2 = state_layout
            .scratchpad_to_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("2"),
                    Height::new(2),
                )
                .unwrap(),
                Height::new(2),
                None,
            )
            .unwrap();
        // Add one checkpoint so that we never remove the last one and crash
        let _cp3 = state_layout
            .scratchpad_to_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("3"),
                    Height::new(3),
                )
                .unwrap(),
                Height::new(3),
                None,
            )
            .unwrap();
        assert_eq!(
            vec![Height::new(1), Height::new(2), Height::new(3)],
            state_layout.checkpoint_heights().unwrap(),
        );

        std::mem::drop(cp1);
        state_layout.remove_checkpoint_when_unused(Height::new(1));
        state_layout.remove_checkpoint_when_unused(Height::new(2));
        assert_eq!(
            vec![Height::new(2), Height::new(3)],
            state_layout.checkpoint_heights().unwrap(),
        );

        std::mem::drop(cp2);
        assert_eq!(
            vec![Height::new(3)],
            state_layout.checkpoint_heights().unwrap(),
        );
    });
}

#[test]
#[should_panic]
#[cfg(debug_assertions)]
fn test_last_removal_panics_in_debug() {
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path, &metrics_registry).unwrap();
        let scratchpad_dir = tmpdir("scratchpad");
        let cp1 = state_layout
            .scratchpad_to_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("1"),
                    Height::new(1),
                )
                .unwrap(),
                Height::new(1),
                None,
            )
            .unwrap();
        state_layout.remove_checkpoint_when_unused(Height::new(1));
        std::mem::drop(cp1);
    });
}

#[test]
fn test_can_remove_unverified_marker_file_twice() {
    // Double removal of the marker file could happen when the state sync and `commit_and_certify` try to promote a scratchpad
    // to the checkpoint folder at the same height.
    // It should be fine that both threads are verifying the checkpoint and try to remove the marker file.
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path, &metrics_registry).unwrap();

        let height = Height::new(1);
        let state_sync_scratchpad = state_layout.state_sync_scratchpad(height).unwrap();
        let scratchpad_layout =
            CheckpointLayout::<RwPolicy<()>>::new_untracked(state_sync_scratchpad, height)
                .expect("failed to create checkpoint layout");
        // Create at least a file in the scratchpad layout. Otherwise, empty folders can be overridden without errors
        // and calling "scratchpad_to_checkpoint" twice will not fail as expected.
        File::create(scratchpad_layout.raw_path().join(SYSTEM_METADATA_FILE)).unwrap();

        let tip_path = state_layout.tip_path();
        let tip = CheckpointLayout::<RwPolicy<()>>::new_untracked(tip_path, height)
            .expect("failed to create tip layout");
        File::create(tip.raw_path().join(SYSTEM_METADATA_FILE)).unwrap();

        // Create marker files in both the scratchpad and tip and try to promote them to a checkpoint.
        scratchpad_layout
            .create_unverified_checkpoint_marker()
            .unwrap();
        tip.create_unverified_checkpoint_marker().unwrap();

        let checkpoint = state_layout
            .scratchpad_to_checkpoint(scratchpad_layout, height, None)
            .unwrap();
        checkpoint.remove_unverified_checkpoint_marker().unwrap();

        // The checkpoint already exists, therefore promoting the tip to checkpoint should fail.
        // However, it can still access the checkpoint and try to remove the marker file again from its side.
        let checkpoint_result = state_layout.scratchpad_to_checkpoint(tip, height, None);
        assert!(checkpoint_result.is_err());

        let res = state_layout
            .checkpoint_in_verification(height)
            .unwrap()
            .remove_unverified_checkpoint_marker();
        assert!(res.is_ok());
    });
}

#[test]
fn test_canister_id_from_path() {
    assert_eq!(
        Some(CanisterId::from_u64(1)),
        canister_id_from_path(Path::new(
            "canister_states/00000000000000010101/canister.pbuf"
        ))
    );
    assert_eq!(
        Some(CanisterId::from_u64(2)),
        canister_id_from_path(Path::new(
            "canister_states/00000000000000020101/queues.pbuf"
        ))
    );
    assert_eq!(
        None,
        canister_id_from_path(Path::new(
            "foo/canister_states/00000000000000030101/queues.pbuf"
        ))
    );
    assert_eq!(None, canister_id_from_path(Path::new(SUBNET_QUEUES_FILE)));
    assert_eq!(None, canister_id_from_path(Path::new("canister_states")));
    assert_eq!(
        None,
        canister_id_from_path(Path::new("canister_states/not-a-canister-ID/queues.pbuf"))
    );
}

// A strategy to create a randomly sampled and strictly monotonic sequence of `Height`.
fn random_sorted_unique_heights(max_length: usize) -> impl Strategy<Value = Vec<Height>> {
    // Take a vector of length max_length, sort it and remove duplicate entries.
    let unsorted = prop::collection::vec(0u64.., max_length);
    unsorted.prop_map(|heights| {
        let mut heights: Vec<Height> = heights.iter().map(|h| Height::new(*h)).collect();
        heights.sort();
        heights.into_iter().unique().collect()
    })
}

// A strategy to create random snapshot ids.
fn random_unique_snapshot_ids(
    max_length: usize,
    canister_count: u64,
    snapshots_per_canister_count: u64,
) -> impl Strategy<Value = Vec<SnapshotId>> {
    let canisters = prop::collection::vec(0..canister_count, max_length);
    let local_ids = prop::collection::vec(0..snapshots_per_canister_count, max_length);
    (canisters, local_ids)
        .prop_map(|(canisters, local_ids)| {
            let mut snapshot_ids: Vec<SnapshotId> = canisters
                .into_iter()
                .zip(local_ids)
                .map(|(canister, local_id)| {
                    let canister_id = canister_test_id(canister);
                    (canister_id, local_id).into()
                })
                .collect();
            snapshot_ids.sort();
            snapshot_ids.into_iter().unique().collect()
        })
        .prop_shuffle()
}

#[test]
fn overlay_height_test() {
    let page_map_layout = PageMapLayout::<WriteOnly> {
        root: PathBuf::new(),
        name_stem: "42".into(),
        permissions_tag: PhantomData,
    };

    assert_eq!(
        page_map_layout
            .overlay_height(&PathBuf::from(
                "/a/b/c/0000000000001000_0000_vmemory.overlay"
            ))
            .unwrap(),
        Height::new(4096)
    );
    assert!(page_map_layout
        .overlay_height(&PathBuf::from("/a/b/c/vmemory.overlay"))
        .is_err());
    // Test that parsing is consistent with encoding.
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new(tmp.path().to_owned()).unwrap();
    assert_eq!(
        page_map_layout
            .overlay_height(
                &canister_layout
                    .stable_memory()
                    .overlay(Height::new(100), Shard::new(3))
            )
            .unwrap(),
        Height::new(100)
    );
}

#[test]
fn overlay_shard_test() {
    let page_map_layout = PageMapLayout::<WriteOnly> {
        root: PathBuf::new(),
        name_stem: "42".into(),
        permissions_tag: PhantomData,
    };

    assert_eq!(
        page_map_layout
            .overlay_shard(&PathBuf::from(
                "/a/b/c/0000000000001000_0010_vmemory.overlay"
            ))
            .unwrap(),
        Shard::new(16)
    );
    assert!(page_map_layout
        .overlay_shard(&PathBuf::from(
            "/a/b/c/0000000000001000_0Q10_vmemory.overlay"
        ))
        .is_err());
    // Test that parsing is consistent with encoding.
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new(tmp.path().to_owned()).unwrap();
    assert_eq!(
        page_map_layout
            .overlay_shard(
                &canister_layout
                    .stable_memory()
                    .overlay(Height::new(100), Shard::new(30))
            )
            .unwrap(),
        Shard::new(30)
    );
}

proptest! {
#[test]
fn read_back_wasm_memory_overlay_file_names(heights in random_sorted_unique_heights(10)) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new(tmp.path().to_owned()).unwrap();
    let overlay_names: Vec<PathBuf> = heights
        .iter()
        .map(|h| canister_layout.vmemory_0().overlay(*h, Shard::new(0)))
        .collect();

    // Create the overlay files in the directory.
    for overlay in &overlay_names {
        File::create(overlay).unwrap();
    }

    // Create some other files that should be ignored.
    File::create(canister_layout.raw_path().join("otherfile")).unwrap();
    File::create(canister_layout.stable_memory().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.wasm_chunk_store().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.vmemory_0().base()).unwrap();

    let existing_overlays = canister_layout.vmemory_0().existing_overlays().unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test]
fn read_back_stable_memory_overlay_file_names(heights in random_sorted_unique_heights(10)) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new(tmp.path().to_owned()).unwrap();
    let overlay_names: Vec<PathBuf> = heights
        .iter()
        .map(|h| canister_layout.stable_memory().overlay(*h, Shard::new(0)))
        .collect();

    // Create the overlay files in the directory.
    for overlay in &overlay_names {
        File::create(overlay).unwrap();
    }

    // Create some other files that should be ignored.
    File::create(canister_layout.raw_path().join("otherfile")).unwrap();
    File::create(canister_layout.vmemory_0().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.wasm_chunk_store().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.stable_memory().base()).unwrap();

    let existing_overlays = canister_layout.stable_memory().existing_overlays().unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test]
fn read_back_wasm_chunk_store_overlay_file_names(heights in random_sorted_unique_heights(10)) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new(tmp.path().to_owned()).unwrap();
    let overlay_names: Vec<PathBuf> = heights
        .iter()
        .map(|h| canister_layout.wasm_chunk_store().overlay(*h, Shard::new(0)))
        .collect();

    // Create the overlay files in the directory.
    for overlay in &overlay_names {
        File::create(overlay).unwrap();
    }

    // Create some other files that should be ignored.
    File::create(canister_layout.raw_path().join("otherfile")).unwrap();
    File::create(canister_layout.vmemory_0().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.stable_memory().overlay(Height::new(42), Shard::new(0))).unwrap();
    File::create(canister_layout.wasm_chunk_store().base()).unwrap();

    let existing_overlays = canister_layout.wasm_chunk_store().existing_overlays().unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test]
fn read_back_checkpoint_directory_names(heights in random_sorted_unique_heights(10)) {
    with_test_replica_logger(|log| {
        let tmp = tmpdir("state_layout");
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, tmp.path().to_owned(), &metrics_registry).unwrap();

        let checkpoint_names: Vec<PathBuf> = heights
            .iter()
            .map(|h| state_layout.checkpoints().join(StateLayout::checkpoint_name(*h)))
            .collect();

        // Create the (empty) checkpoint directories.
        for checkpoint in &checkpoint_names {
            std::fs::create_dir(checkpoint).unwrap();
        }

        let existing_heights = state_layout.checkpoint_heights().unwrap();

        // We expect the list of heights to be the same including ordering.
        assert_eq!(heights, existing_heights);
    });
}

#[test]
fn read_back_canister_snapshot_ids(mut snapshot_ids in random_unique_snapshot_ids(10, 10, 10)) {
    let tmp = tmpdir("checkpoint");
    let checkpoint_layout: CheckpointLayout<WriteOnly> =
        CheckpointLayout::new_untracked(tmp.path().to_owned(), Height::new(0)).unwrap();
    for snapshot_id in &snapshot_ids {
        checkpoint_layout.snapshot(snapshot_id).unwrap(); // Creates the directory as side effect.
    }

    let actual_snapshot_ids = checkpoint_layout.snapshot_ids().unwrap();
    snapshot_ids.sort();

    prop_assert_eq!(snapshot_ids, actual_snapshot_ids);
}

#[test]
fn can_add_and_delete_canister_snapshots(snapshot_ids in random_unique_snapshot_ids(10, 10, 10)) {
    let tmp = tmpdir("checkpoint");
    let checkpoint_layout: CheckpointLayout<WriteOnly> =
        CheckpointLayout::new_untracked(tmp.path().to_owned(), Height::new(0)).unwrap();

    fn check_snapshot_layout(checkpoint_layout: &CheckpointLayout<WriteOnly>, expected_snapshot_ids: &[SnapshotId]) {
        let actual_snapshot_ids = checkpoint_layout.snapshot_ids().unwrap();
        let mut expected_snapshot_ids = expected_snapshot_ids.to_vec();
        expected_snapshot_ids.sort();

        assert_eq!(expected_snapshot_ids, actual_snapshot_ids);

        let num_unique_canisters = actual_snapshot_ids.iter().map(|snapshot_id| snapshot_id.get_canister_id()).unique().count();

        let num_canister_directories = std::fs::read_dir(checkpoint_layout.raw_path().join(SNAPSHOTS_DIR)).unwrap().count();
        assert_eq!(num_unique_canisters, num_canister_directories);
    }

    for i in 0..snapshot_ids.len() {
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[..i]);
        checkpoint_layout.snapshot(&snapshot_ids[i]).unwrap(); // Creates the directory as side effect.
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[..(i+1)]);
    }

    for i in 0..snapshot_ids.len() {
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[i..]);
        checkpoint_layout.snapshot(&snapshot_ids[i]).unwrap().delete_dir().unwrap();
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[(i+1)..]);
    }
}

}
