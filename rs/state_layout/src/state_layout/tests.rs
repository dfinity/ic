use super::*;

use ic_management_canister_types_private::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallMode, IC_00,
};
use ic_replicated_state::ExecutionTask;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::{
    NumWasmPages, canister_state::system_state::CanisterHistory,
    metadata_state::subnet_call_context_manager::InstallCodeCallId, page_map::Shard,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, ResponseBuilder};
use ic_test_utilities_types::{ids::canister_test_id, ids::user_test_id};
use ic_types::default_aggregate_log_memory_limit;
use ic_types::messages::{CanisterCall, CanisterMessage, CanisterMessageOrTask, CanisterTask};
use ic_types::time::UNIX_EPOCH;
use itertools::Itertools;
use proptest::prelude::*;
use std::fs::File;
use std::sync::Arc;

fn default_canister_state_bits() -> CanisterStateBits {
    CanisterStateBits {
        controllers: BTreeSet::new(),
        last_full_execution_round: ExecutionRound::from(0),
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
        task_queue: TaskQueue::default(),
        global_timer_nanos: None,
        canister_version: 0,
        consumed_cycles_by_use_cases: BTreeMap::new(),
        canister_history: CanisterHistory::default(),
        wasm_chunk_store_metadata: WasmChunkStoreMetadata::default(),
        total_query_stats: TotalQueryStats::default(),
        log_visibility: Default::default(),
        log_memory_limit: default_aggregate_log_memory_limit(),
        canister_log: Default::default(),
        wasm_memory_limit: None,
        next_snapshot_id: 0,
        snapshots_memory_usage: NumBytes::from(0),
        environment_variables: BTreeMap::new(),
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
        assert!(
            state_layout
                .diverged_state_marker_path(Height::new(1))
                .starts_with(root_path.join("diverged_state_markers"))
        );
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
        CanisterChangeDetails::canister_creation(
            vec![canister_test_id(777).get(), user_test_id(42).get()],
            Some([4; 32]),
        ),
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
    canister_history.add_canister_change(CanisterChange::new(
        555,
        7,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::settings_change(None, Some([1; 32])),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        555,
        7,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::settings_change(Some(vec![]), Some([1; 32])),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        555,
        7,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::settings_change(
            Some(vec![canister_test_id(123).into()]),
            Some([1; 32]),
        ),
    ));
    canister_history.add_canister_change(CanisterChange::new(
        555,
        7,
        CanisterChangeOrigin::from_canister(canister_test_id(123).get(), None),
        CanisterChangeDetails::settings_change(Some(vec![canister_test_id(123).into()]), None),
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
        binary_hash: WasmHash::from(&CanisterModule::new(vec![2, 3, 4])),
        certified_data: vec![3, 4, 7],
        wasm_chunk_store_metadata: WasmChunkStoreMetadata::default(),
        stable_memory_size: NumWasmPages::new(10),
        wasm_memory_size: NumWasmPages::new(10),
        total_size: NumBytes::new(100),
        exported_globals: vec![Global::I32(1), Global::I64(2), Global::F64(0.1)],
        source: SnapshotSource::taken_from_canister(),
        global_timer: Some(CanisterTimer::Inactive),
        on_low_wasm_memory_hook_status: Some(OnLowWasmMemoryHookStatus::ConditionNotSatisfied),
    };

    let pb_bits =
        pb_canister_snapshot_bits::CanisterSnapshotBits::from(canister_snapshot_bits.clone());
    let new_canister_snapshot_bits = CanisterSnapshotBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_snapshot_bits, new_canister_snapshot_bits);
}

#[test]
fn test_encode_decode_empty_environment_variables() {
    // A canister state with empty environment variables.
    let canister_state_bits = CanisterStateBits {
        environment_variables: BTreeMap::new(),
        ..default_canister_state_bits()
    };
    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);

    let decoded_canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();
    assert_eq!(
        decoded_canister_state_bits.environment_variables,
        BTreeMap::new()
    );
}

#[test]
fn test_encode_decode_non_empty_environment_variables() {
    let mut environment_variables = BTreeMap::new();
    environment_variables.insert("KEY1".to_string(), "VALUE1".to_string());
    environment_variables.insert("KEY2".to_string(), "VALUE2".to_string());

    // A canister state with non-empty environment variables.
    let canister_state_bits = CanisterStateBits {
        environment_variables: environment_variables.clone(),
        ..default_canister_state_bits()
    };
    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let decoded_canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();
    assert_eq!(
        decoded_canister_state_bits.environment_variables,
        environment_variables
    );
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
        let mut task_queue = TaskQueue::default();
        task_queue.enqueue(task);
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
            .promote_scratchpad_to_unverified_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("1"),
                    Height::new(1),
                )
                .unwrap(),
                Height::new(1),
            )
            .unwrap()
            .as_readonly();
        cp1.finalize_and_remove_unverified_marker(None).unwrap();
        let cp2 = state_layout
            .promote_scratchpad_to_unverified_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("2"),
                    Height::new(2),
                )
                .unwrap(),
                Height::new(2),
            )
            .unwrap()
            .as_readonly();
        cp2.finalize_and_remove_unverified_marker(None).unwrap();
        // Add one checkpoint so that we never remove the last one and crash
        let cp3 = state_layout
            .promote_scratchpad_to_unverified_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("3"),
                    Height::new(3),
                )
                .unwrap(),
                Height::new(3),
            )
            .unwrap()
            .as_readonly();
        cp3.finalize_and_remove_unverified_marker(None).unwrap();
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
fn checkpoints_files_are_removed_after_flushing_removal_channel() {
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path, &metrics_registry).unwrap();
        let scratchpad_dir = tmpdir("scratchpad");

        let create_checkpoint_with_dummy_files = |h: Height| -> CheckpointLayout<ReadOnly> {
            let scratchpad_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
                scratchpad_dir
                    .path()
                    .to_path_buf()
                    .join(h.get().to_string()),
                h,
            )
            .unwrap();

            // Write 500 dummy files to the scratchpad directory so that removing checkpoint files takes longer than dropping a `CheckpointLayout`.
            // This is to create some backlog in the checkpoint removal channel.
            for i in 0..500 {
                let file_path = scratchpad_layout.raw_path().join(i.to_string());
                File::create(file_path).unwrap();
            }
            let cp = state_layout
                .promote_scratchpad_to_unverified_checkpoint(scratchpad_layout, h)
                .unwrap()
                .as_readonly();
            cp.finalize_and_remove_unverified_marker(None).unwrap();
            cp
        };

        let mut checkpoints = vec![];
        for i in 1..=20 {
            checkpoints.push(create_checkpoint_with_dummy_files(Height::new(i)));
        }
        for i in 1..=19 {
            state_layout.remove_checkpoint_when_unused(Height::new(i));
        }
        drop(checkpoints);

        // Dropping `CheckpointLayout` should immediately remove checkpoints 1 through 19
        // from the checkpoints directory, leaving only checkpoint @20.
        assert_eq!(
            vec![Height::new(20)],
            state_layout.checkpoint_heights().unwrap(),
        );

        state_layout.flush_checkpoint_removal_channel();
        // After flushing the removal channel, all temporary folders of checkpoints should be cleared from the `fs_tmp` directory.
        assert!(
            state_layout.fs_tmp().read_dir().unwrap().next().is_none(),
            "fs_tmp directory is not empty"
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
            .promote_scratchpad_to_unverified_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("1"),
                    Height::new(1),
                )
                .unwrap(),
                Height::new(1),
            )
            .unwrap()
            .as_readonly();
        cp1.finalize_and_remove_unverified_marker(None).unwrap();
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
        let state_sync_scratchpad = state_layout.state_sync_scratchpad(height);
        let scratchpad_layout =
            CheckpointLayout::<RwPolicy<()>>::new_untracked(state_sync_scratchpad, height)
                .expect("failed to create checkpoint layout");
        // Create at least a file in the scratchpad layout. Otherwise, empty folders can be overridden without errors
        // and calling "promote_scratchpad_to_unverified_checkpoint" twice will not fail as expected.
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
            .promote_scratchpad_to_unverified_checkpoint(scratchpad_layout, height)
            .unwrap()
            .as_readonly();
        checkpoint
            .finalize_and_remove_unverified_marker(None)
            .unwrap();

        // The checkpoint already exists, therefore promoting the tip to checkpoint should fail.
        // However, it can still access the checkpoint and try to remove the marker file again from its side.
        let checkpoint_result =
            state_layout.promote_scratchpad_to_unverified_checkpoint(tip, height);
        assert!(checkpoint_result.is_err());

        let res = state_layout
            .checkpoint_in_verification(height)
            .unwrap()
            .finalize_and_remove_unverified_marker(None);
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
        _checkpoint: None,
    };

    assert_eq!(
        page_map_layout
            .overlay_height(&PathBuf::from(
                "/a/b/c/0000000000001000_0000_vmemory.overlay"
            ))
            .unwrap(),
        Height::new(4096)
    );
    assert!(
        page_map_layout
            .overlay_height(&PathBuf::from("/a/b/c/vmemory.overlay"))
            .is_err()
    );
    // Test that parsing is consistent with encoding.
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmp.path().to_owned()).unwrap();
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
        _checkpoint: None,
    };

    assert_eq!(
        page_map_layout
            .overlay_shard(&PathBuf::from(
                "/a/b/c/0000000000001000_0010_vmemory.overlay"
            ))
            .unwrap(),
        Shard::new(16)
    );
    assert!(
        page_map_layout
            .overlay_shard(&PathBuf::from(
                "/a/b/c/0000000000001000_0Q10_vmemory.overlay"
            ))
            .is_err()
    );
    // Test that parsing is consistent with encoding.
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmp.path().to_owned()).unwrap();
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

#[test]
fn test_all_existing_pagemaps() {
    let tmp = tmpdir("checkpoint");
    let checkpoint_layout: CheckpointLayout<RwPolicy<()>> =
        CheckpointLayout::new_untracked(tmp.path().to_owned(), Height::new(0)).unwrap();
    assert!(
        checkpoint_layout
            .all_existing_pagemaps()
            .unwrap()
            .is_empty()
    );
    let canister_layout = checkpoint_layout.canister(&canister_test_id(123)).unwrap();
    let canister_wasm_base = canister_layout.wasm_chunk_store().base();
    File::create(&canister_wasm_base).unwrap();
    let snapshot_layout = checkpoint_layout
        .snapshot(&SnapshotId::from((canister_test_id(123), 4)))
        .unwrap();
    let snapshot_overlay = snapshot_layout.stable_memory().overlay(5.into(), 6.into());
    File::create(&snapshot_overlay).unwrap();
    let pagemaps = checkpoint_layout.all_existing_pagemaps().unwrap();
    assert_eq!(pagemaps.len(), 2);
    assert_eq!(pagemaps[0].base(), canister_wasm_base,);
    assert_eq!(
        pagemaps[1].existing_overlays().unwrap(),
        vec![snapshot_overlay],
    );
}

#[test]
fn test_all_existing_wasm_files() {
    let tmp = tmpdir("checkpoint");
    let checkpoint_layout: CheckpointLayout<RwPolicy<()>> =
        CheckpointLayout::new_untracked(tmp.path().to_owned(), Height::new(0)).unwrap();
    assert!(
        checkpoint_layout
            .all_existing_wasm_files()
            .unwrap()
            .is_empty()
    );

    // Create directories for a canister and its corresponding snapshot, both containing wasm files.
    let wasm_path_1 = checkpoint_layout
        .canister(&canister_test_id(42))
        .unwrap()
        .wasm()
        .path()
        .to_path_buf();
    File::create(&wasm_path_1).unwrap();

    let wasm_path_2 = checkpoint_layout
        .snapshot(&SnapshotId::from((canister_test_id(42), 4)))
        .unwrap()
        .wasm()
        .path()
        .to_path_buf();
    File::create(&wasm_path_2).unwrap();

    // Create a canister directory with a wasm file.
    let wasm_path_3 = checkpoint_layout
        .canister(&canister_test_id(43))
        .unwrap()
        .wasm()
        .path()
        .to_path_buf();
    File::create(&wasm_path_3).unwrap();

    // Create a snapshot directory with a wasm file.
    let wasm_path_4 = checkpoint_layout
        .snapshot(&SnapshotId::from((canister_test_id(44), 4)))
        .unwrap()
        .wasm()
        .path()
        .to_path_buf();
    File::create(&wasm_path_4).unwrap();

    // Create a canister directory without wasm files.
    let _ = checkpoint_layout.canister(&canister_test_id(45)).unwrap();

    let wasm_files = checkpoint_layout.all_existing_wasm_files().unwrap();
    assert_eq!(wasm_files.len(), 4);
    let wasm_paths: BTreeSet<_> = wasm_files
        .iter()
        .map(|w| w.raw_path().to_path_buf())
        .collect();

    assert_eq!(wasm_paths.len(), 4);
    assert_eq!(
        wasm_paths,
        BTreeSet::from([wasm_path_1, wasm_path_2, wasm_path_3, wasm_path_4])
    )
}

#[test]
fn wasm_can_be_serialized_to_and_loaded_from_a_file() {
    let wasm_in_memory = CanisterModule::new(vec![0x00, 0x61, 0x73, 0x6d]);
    let wasm_hash = wasm_in_memory.module_hash();
    let len = wasm_in_memory.len();

    let tmpdir = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmpdir.path().to_owned()).unwrap();
    let wasm_file = canister_layout.wasm();
    wasm_file
        .serialize(&wasm_in_memory)
        .expect("failed to write Wasm to disk");

    let canister_layout: CanisterLayout<ReadOnly> =
        CanisterLayout::new_untracked(tmpdir.path().to_owned()).unwrap();
    let wasm_on_disk =
        CanisterModule::new_from_file(Box::new(canister_layout.wasm()), wasm_hash.into(), None)
            .expect("failed to read Wasm from disk");

    let wasm_on_disk_with_len = CanisterModule::new_from_file(
        Box::new(canister_layout.wasm()),
        wasm_hash.into(),
        Some(len),
    )
    .expect("failed to read Wasm from disk");

    assert!(!wasm_in_memory.is_file());
    assert!(wasm_on_disk.wasm_file_not_loaded_and_path_matches(wasm_file.path.as_path()));
    assert_eq!(wasm_in_memory.as_slice(), wasm_on_disk.as_slice());
    assert_eq!(wasm_in_memory, wasm_on_disk);

    assert!(wasm_on_disk_with_len.wasm_file_not_loaded_and_path_matches(wasm_file.path.as_path()));
    assert_eq!(wasm_on_disk, wasm_on_disk_with_len);
    assert_eq!(wasm_on_disk.len(), wasm_on_disk_with_len.len());
    assert_eq!(wasm_on_disk.as_slice(), wasm_on_disk_with_len.as_slice());
}

#[test]
fn wasm_file_can_hold_checkpoint_for_lazy_loading() {
    with_test_replica_logger(|log| {
        let tempdir = tmpdir("state_layout");
        let root_path = tempdir.path().to_path_buf();
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout = StateLayout::try_new(log, root_path.clone(), &metrics_registry).unwrap();
        let scratchpad_dir = tmpdir("scratchpad");

        let scratchpad = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            scratchpad_dir.path().to_path_buf().join("1"),
            Height::new(1),
        )
        .unwrap();

        let canister_layout = scratchpad.canister(&canister_test_id(42)).unwrap();
        let wasm_in_memory = CanisterModule::new(vec![0x00, 0x61, 0x73, 0x6d]);

        // Write a wasm file to the scratchpad layout.
        canister_layout
            .wasm()
            .serialize(&wasm_in_memory)
            .expect("failed to write Wasm to disk");

        let cp1 = state_layout
            .promote_scratchpad_to_unverified_checkpoint(scratchpad, Height::new(1))
            .unwrap()
            .as_readonly();

        cp1.finalize_and_remove_unverified_marker(None).unwrap();

        // Create another checkpoint at height 2 so that we can remove the first one.
        let cp2 = state_layout
            .promote_scratchpad_to_unverified_checkpoint(
                CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    scratchpad_dir.path().to_path_buf().join("2"),
                    Height::new(2),
                )
                .unwrap(),
                Height::new(2),
            )
            .unwrap()
            .as_readonly();
        cp2.finalize_and_remove_unverified_marker(None).unwrap();

        // Create a `CanisterModule` that holds the checkpoint layout at height 1.
        let wasm_on_disk = CanisterModule::new_from_file(
            Box::new(cp1.canister(&canister_test_id(42)).unwrap().wasm()),
            wasm_in_memory.module_hash().into(),
            None,
        )
        .expect("failed to read Wasm from disk");

        drop(cp1);
        state_layout.remove_checkpoint_when_unused(Height::new(1));

        // The checkpoint at height 1 still exists because `wasm_on_disk` is alive.
        assert_eq!(
            vec![Height::new(1), Height::new(2)],
            state_layout.checkpoint_heights().unwrap(),
        );

        // The wasm file is still accessible and the content can be correctly read.
        // Calling `as_slice()` on the canister module will drop the wasm file as well as the checkpoint layout.
        assert_eq!(wasm_in_memory.as_slice(), wasm_on_disk.as_slice());
        assert_eq!(
            vec![Height::new(2)],
            state_layout.checkpoint_heights().unwrap(),
        );

        // The cached mmap is still accessible after the checkpoint is removed.
        assert_eq!(wasm_in_memory.as_slice(), wasm_on_disk.as_slice());
    });
}

#[test_strategy::proptest]
fn read_back_wasm_memory_overlay_file_names(
    #[strategy(random_sorted_unique_heights(
        10, // max_length
    ))]
    heights: Vec<Height>,
) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmp.path().to_owned()).unwrap();
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
    File::create(
        canister_layout
            .stable_memory()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(
        canister_layout
            .wasm_chunk_store()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(canister_layout.vmemory_0().base()).unwrap();

    let existing_overlays = canister_layout.vmemory_0().existing_overlays().unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test_strategy::proptest]
fn read_back_stable_memory_overlay_file_names(
    #[strategy(random_sorted_unique_heights(
        10, // max_length
    ))]
    heights: Vec<Height>,
) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmp.path().to_owned()).unwrap();
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
    File::create(
        canister_layout
            .vmemory_0()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(
        canister_layout
            .wasm_chunk_store()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(canister_layout.stable_memory().base()).unwrap();

    let existing_overlays = canister_layout.stable_memory().existing_overlays().unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test_strategy::proptest]
fn read_back_wasm_chunk_store_overlay_file_names(
    #[strategy(random_sorted_unique_heights(
        10, // max_length
    ))]
    heights: Vec<Height>,
) {
    let tmp = tmpdir("canister");
    let canister_layout: CanisterLayout<WriteOnly> =
        CanisterLayout::new_untracked(tmp.path().to_owned()).unwrap();
    let overlay_names: Vec<PathBuf> = heights
        .iter()
        .map(|h| {
            canister_layout
                .wasm_chunk_store()
                .overlay(*h, Shard::new(0))
        })
        .collect();

    // Create the overlay files in the directory.
    for overlay in &overlay_names {
        File::create(overlay).unwrap();
    }

    // Create some other files that should be ignored.
    File::create(canister_layout.raw_path().join("otherfile")).unwrap();
    File::create(
        canister_layout
            .vmemory_0()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(
        canister_layout
            .stable_memory()
            .overlay(Height::new(42), Shard::new(0)),
    )
    .unwrap();
    File::create(canister_layout.wasm_chunk_store().base()).unwrap();

    let existing_overlays = canister_layout
        .wasm_chunk_store()
        .existing_overlays()
        .unwrap();

    // We expect the list of paths to be the same including ordering.
    prop_assert_eq!(overlay_names, existing_overlays);
}

#[test_strategy::proptest]
fn read_back_checkpoint_directory_names(
    #[strategy(random_sorted_unique_heights(
        10, // max_length
    ))]
    heights: Vec<Height>,
) {
    with_test_replica_logger(|log| {
        let tmp = tmpdir("state_layout");
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let state_layout =
            StateLayout::try_new(log, tmp.path().to_owned(), &metrics_registry).unwrap();

        let checkpoint_names: Vec<PathBuf> = heights
            .iter()
            .map(|h| {
                state_layout
                    .checkpoints()
                    .join(StateLayout::checkpoint_name(*h))
            })
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

#[test_strategy::proptest]
fn read_back_canister_snapshot_ids(
    #[strategy(random_unique_snapshot_ids(
        10, // max_length
        10, // canister_count
        10, // snapshots_per_canister_count
    ))]
    mut snapshot_ids: Vec<SnapshotId>,
) {
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

#[test_strategy::proptest]
fn can_add_and_delete_canister_snapshots(
    #[strategy(random_unique_snapshot_ids(
        10, // max_length
        10, // canister_count
        10, // snapshots_per_canister_count
    ))]
    snapshot_ids: Vec<SnapshotId>,
) {
    let tmp = tmpdir("checkpoint");
    let checkpoint_layout: CheckpointLayout<WriteOnly> =
        CheckpointLayout::new_untracked(tmp.path().to_owned(), Height::new(0)).unwrap();

    fn check_snapshot_layout(
        checkpoint_layout: &CheckpointLayout<WriteOnly>,
        expected_snapshot_ids: &[SnapshotId],
    ) {
        let actual_snapshot_ids = checkpoint_layout.snapshot_ids().unwrap();
        let mut expected_snapshot_ids = expected_snapshot_ids.to_vec();
        expected_snapshot_ids.sort();

        assert_eq!(expected_snapshot_ids, actual_snapshot_ids);

        let num_unique_canisters = actual_snapshot_ids
            .iter()
            .map(|snapshot_id| snapshot_id.get_canister_id())
            .unique()
            .count();

        let num_canister_directories =
            std::fs::read_dir(checkpoint_layout.raw_path().join(SNAPSHOTS_DIR))
                .unwrap()
                .count();
        assert_eq!(num_unique_canisters, num_canister_directories);
    }

    for i in 0..snapshot_ids.len() {
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[..i]);
        checkpoint_layout.snapshot(&snapshot_ids[i]).unwrap(); // Creates the directory as side effect.
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[..(i + 1)]);
    }

    for i in 0..snapshot_ids.len() {
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[i..]);
        checkpoint_layout
            .snapshot(&snapshot_ids[i])
            .unwrap()
            .delete_dir()
            .unwrap();
        check_snapshot_layout(&checkpoint_layout, &snapshot_ids[(i + 1)..]);
    }
}

#[test]
fn test_encode_decode_empty_task_queue() {
    let task_queue = TaskQueue::default();
    // A canister state with empty TaskQueue.
    let canister_state_bits = CanisterStateBits {
        task_queue: task_queue.clone(),
        ..default_canister_state_bits()
    };

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_state_bits.task_queue, task_queue);
}

#[test]
fn test_encode_decode_non_empty_task_queue() {
    let mut task_queue = TaskQueue::default();
    task_queue.enqueue(ExecutionTask::OnLowWasmMemory);

    task_queue.enqueue(ExecutionTask::AbortedExecution {
        input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        prepaid_execution_cycles: Cycles::zero(),
    });

    // A canister state with non empty TaskQueue.
    let canister_state_bits = CanisterStateBits {
        task_queue: task_queue.clone(),
        ..default_canister_state_bits()
    };

    let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
    let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

    assert_eq!(canister_state_bits.task_queue, task_queue);
}

#[test]
#[should_panic = "Attempt to serialize ephemeral task"]
fn test_encode_task_queue_with_paused_task_fails() {
    let mut task_queue = TaskQueue::default();
    task_queue.enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(1)));

    // A canister state with non empty TaskQueue.
    let canister_state_bits = CanisterStateBits {
        task_queue: task_queue.clone(),
        ..default_canister_state_bits()
    };

    let _ = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
}
