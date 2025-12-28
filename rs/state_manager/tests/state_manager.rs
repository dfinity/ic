use assert_matches::assert_matches;
use ic_base_types::SnapshotId;
use ic_canonical_state::encoding::encode_subnet_canister_ranges;
use ic_config::state_manager::{Config, lsmt_config_default};
use ic_crypto_tree_hash::{
    Label, LabeledTree, LookupStatus, MatchPattern, MixedHashTree, Path as LabelPath, flatmap,
    sparse_labeled_tree_from_paths,
};
use ic_interfaces::certification::Verifier;
use ic_interfaces::p2p::state_sync::{ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_state_manager::*;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallModeV2, CanisterSnapshotDataKind,
    InstallChunkedCodeArgs, LoadCanisterSnapshotArgs, ReadCanisterSnapshotDataArgs,
    TakeCanisterSnapshotArgs, UploadChunkArgs,
};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    ExecutionState, ExportedFunctions, Memory, NetworkTopology, NumWasmPages, PageMap,
    ReplicatedState, Stream, SubnetTopology,
    canister_snapshots::CanisterSnapshot,
    canister_state::{execution_state::WasmBinary, system_state::wasm_chunk_store::WasmChunkStore},
    metadata_state::ApiBoundaryNodeEntry,
    page_map::{PageIndex, Shard, StorageLayout},
    testing::ReplicatedStateTesting,
};
use ic_state_layout::{
    CANISTER_FILE, CheckpointLayout, ReadOnly, SYSTEM_METADATA_FILE, StateLayout, WASM_FILE,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_state_manager::manifest::{build_meta_manifest, manifest_from_path, validate_manifest};
use ic_state_manager::{
    NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY, StateManagerImpl,
    state_sync::{
        StateSync,
        types::{
            DEFAULT_CHUNK_SIZE, FILE_GROUP_CHUNK_ID_OFFSET, MANIFEST_CHUNK_ID_OFFSET,
            META_MANIFEST_CHUNK, StateSyncMessage,
        },
    },
    testing::StateManagerTesting,
};
use ic_sys::PAGE_SIZE;
use ic_test_utilities_consensus::fake::FakeVerifier;
use ic_test_utilities_io::{make_mutable, make_readonly, write_all_at};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    Labels, fetch_gauge, fetch_histogram_vec_stats, fetch_int_counter_vec, fetch_int_gauge,
};
use ic_test_utilities_state::{arb_stream, arb_stream_slice, canister_ids};
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::{
    ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
    messages::RequestBuilder,
};
use ic_types::batch::{
    BatchSummary, CanisterCyclesCostSchedule, CanisterQueryStats, QueryStats, QueryStatsPayload,
    RawQueryStats, TotalQueryStats,
};
use ic_types::state_manager::StateManagerError;
use ic_types::{
    CanisterId, CryptoHashOfPartialState, CryptoHashOfState, Height, NodeId, NumBytes, PrincipalId,
    crypto::CryptoHash,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::CallbackId,
    time::{Time, UNIX_EPOCH},
    xnet::{StreamIndex, StreamIndexedQueue},
};
use ic_types::{QueryStatsEpoch, epoch_from_height};
use maplit::{btreemap, btreeset};
use nix::sys::time::TimeValLike;
use nix::sys::{
    stat::{UtimensatFlags, utimensat},
    time::TimeSpec,
};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
};

pub mod common;
use common::*;

const NUM_THREADS: u32 = 3;

fn tree_payload(t: MixedHashTree) -> LabeledTree<Vec<u8>> {
    t.try_into().unwrap()
}

fn label<T: Into<Label>>(t: T) -> Label {
    t.into()
}

/// Combined size of wasm memory including overlays.
fn vmemory_size(canister_layout: &ic_state_layout::CanisterLayout<ReadOnly>) -> u64 {
    canister_layout
        .vmemory_0()
        .existing_overlays()
        .unwrap()
        .into_iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .sum::<u64>()
        + std::fs::metadata(canister_layout.vmemory_0().base()).map_or(0, |metadata| metadata.len())
}

/// Combined size of stable memory including overlays.
fn stable_memory_size(canister_layout: &ic_state_layout::CanisterLayout<ReadOnly>) -> u64 {
    canister_layout
        .stable_memory()
        .existing_overlays()
        .unwrap()
        .into_iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .sum::<u64>()
        + std::fs::metadata(canister_layout.stable_memory().base())
            .map_or(0, |metadata| metadata.len())
}

/// Combined size of wasm chunk store including overlays.
fn wasm_chunk_store_size(canister_layout: &ic_state_layout::CanisterLayout<ReadOnly>) -> u64 {
    canister_layout
        .wasm_chunk_store()
        .existing_overlays()
        .unwrap()
        .into_iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .sum::<u64>()
        + std::fs::metadata(canister_layout.wasm_chunk_store().base())
            .map_or(0, |metadata| metadata.len())
}

/// This is a canister that keeps a counter on the heap and allows to increment it.
/// The counter can also be read and persisted to and loaded from stable memory.
const TEST_CANISTER: &str = r#"
(module
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "stable_read"
    (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "stable_write"
    (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

    (func $inc

    ;; load the old counter value, increment, and store it back
    (i32.store

        ;; store at the beginning of the heap
        (i32.const 0) ;; store at the beginning of the heap

        ;; increment heap[0]
        (i32.add

        ;; the old value at heap[0]
        (i32.load (i32.const 0))

        ;; "1"
        (i32.const 1)
        )
    )
    (call $msg_reply_data_append (i32.const 0) (i32.const 0))
    (call $msg_reply)
    )

    (func $read
    ;; now we copied the counter address into heap[0]
    (call $msg_reply_data_append
        (i32.const 0) ;; the counter address from heap[0]
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $persist
    (call $stable_write
        (i32.const 0) ;; offset
        (i32.const 0) ;; src
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $load
    (call $stable_read
        (i32.const 0) ;; dst
        (i32.const 0) ;; offset
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $grow_page
    (drop (call $stable_grow (i32.const 1)))
    (call $msg_reply)
    )

    (func $write (param $address i32) (param $end i32) (param $step i32)
            ;; Precondition: (end - address) % step == 0
            ;; let value = *address + 1;
            ;; while (address != end) {
            ;;   *address = value;
            ;;   address += step;
            ;; }
            (local $value i64)
            (local.set $value (i64.load (local.get $address)))
            (local.set $value (i64.add (local.get $value) (i64.const 1)))
            (loop $loop
                    (i64.store (local.get $address) (local.get $value))
                    (local.tee $address (i32.add (local.get $address) (local.get $step)))
                    (local.get $end)
                    (i32.ne)
                    (br_if $loop)
            )
    )
    (func (export "canister_update write_heap_64k")
        (call $write (i32.const 0) (i32.const 65536) (i32.const 4096))
	(call $msg_reply)
    )
    (func (export "canister_update write_heap_60k")
        (call $write (i32.const 4096) (i32.const 61440) (i32.const 4096))
	(call $msg_reply)
    )
    (memory $memory 1)
    (export "memory" (memory $memory))
    (export "canister_update inc" (func $inc))
    (export "canister_query read" (func $read))
    (export "canister_update persist" (func $persist))
    (export "canister_update load" (func $load))
    (export "canister_update grow_page" (func $grow_page))
)"#;

fn to_int(v: Vec<u8>) -> i32 {
    i32::from_le_bytes(v.try_into().unwrap())
}

fn read_and_assert_eq(env: &StateMachine, canister_id: CanisterId, expected: i32) {
    assert_eq!(
        to_int(
            env.execute_ingress(canister_id, "read", vec![])
                .unwrap()
                .bytes()
        ),
        expected
    );
}

#[test]
fn lsmt_merge_overhead() {
    fn checkpoint_size(checkpoint: &CheckpointLayout<ReadOnly>) -> f64 {
        let mut size = 0.0;
        for canister_id in checkpoint.canister_ids().unwrap() {
            let canister = checkpoint.canister(&canister_id).unwrap();
            for entry in std::fs::read_dir(canister.raw_path()).unwrap() {
                size += std::fs::metadata(entry.unwrap().path()).unwrap().len() as f64;
            }
        }
        size
    }
    fn last_checkpoint_size(env: &StateMachine) -> f64 {
        let state_layout = env.state_manager.state_layout();
        let checkpoint_heights = state_layout.checkpoint_heights().unwrap();
        if checkpoint_heights.is_empty() {
            return 0.0;
        }
        let last_height = *checkpoint_heights.last().unwrap();
        checkpoint_size(&state_layout.checkpoint_verified(last_height).unwrap())
    }
    fn tip_size(env: &StateMachine) -> f64 {
        checkpoint_size(
            &CheckpointLayout::new_untracked(
                env.state_manager.state_layout().raw_path().join("tip"),
                height(0),
            )
            .unwrap(),
        )
    }
    fn state_in_memory(env: &StateMachine) -> f64 {
        env.metrics_registry()
            .prometheus_registry()
            .gather()
            .into_iter()
            .filter(|x| x.get_name() == "canister_memory_usage_bytes")
            .map(|x| x.get_metric()[0].get_gauge().get_value())
            .next()
            .unwrap()
    }

    let env = StateMachineBuilder::new()
        .with_lsmt_override(Some(lsmt_with_sharding()))
        .build();

    let canister_ids = (0..10)
        .map(|_| env.install_canister_wat(TEST_CANISTER, vec![], None))
        .collect::<Vec<_>>();
    for i in 0..30 {
        env.set_checkpoints_enabled(false);
        for canister_id in &canister_ids {
            env.execute_ingress(*canister_id, "write_heap_64k", vec![])
                .unwrap();
        }
        env.set_checkpoints_enabled(true);
        env.tick();
        env.state_manager.flush_tip_channel();
        // We should merge when overhead reaches 2.5 and stop merging the moment we go under 2.5.
        if i >= 3 {
            assert_ne!(tip_size(&env), 0.0);
            assert_ne!(state_in_memory(&env), 0.0);
            assert!(tip_size(&env) / state_in_memory(&env) > 2.0);
            assert!(tip_size(&env) / state_in_memory(&env) <= 2.5);
        }
    }
    // Create a checkpoint from the tip without writing any more data. As we merge in tip, the
    // result is visible at the next checkpoint.
    env.tick();
    env.state_manager.flush_tip_channel();
    assert_ne!(last_checkpoint_size(&env), 0.0);
    assert_ne!(state_in_memory(&env), 0.0);
    assert!(last_checkpoint_size(&env) / state_in_memory(&env) > 2.0);
    assert!(last_checkpoint_size(&env) / state_in_memory(&env) <= 2.5);
}

#[test]
fn lazy_pagemaps() {
    fn page_maps_by_status(status: &str, env: &StateMachine) -> i64 {
        env.metrics_registry()
            .prometheus_registry()
            .gather()
            .into_iter()
            .filter(|x| x.get_name() == "state_manager_num_page_maps_by_load_status")
            .map(|x| -> f64 {
                x.get_metric()
                    .iter()
                    .find(|x| {
                        for l in x.get_label() {
                            if l.get_name() == "status" && l.get_value() == status {
                                return true;
                            }
                        }
                        false
                    })
                    .unwrap()
                    .get_gauge()
                    .get_value()
            })
            .next()
            .unwrap() as i64
    }

    let env = StateMachineBuilder::new()
        .with_lsmt_override(Some(lsmt_with_sharding()))
        .build();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.tick();
    assert_eq!(page_maps_by_status("loaded", &env), 1);
    assert!(page_maps_by_status("not_loaded", &env) > 0);

    env.execute_ingress(canister_id, "write_heap_64k", vec![])
        .unwrap();
    assert!(page_maps_by_status("loaded", &env) > 0);
}

#[test]
fn lazy_wasms() {
    fn wasm_files_by_source(source: &str, env: &StateMachine) -> i64 {
        env.metrics_registry()
            .prometheus_registry()
            .gather()
            .into_iter()
            .filter(|x| x.get_name() == "state_manager_num_loaded_wasm_files_by_source")
            .map(|x| -> f64 {
                x.get_metric()
                    .iter()
                    .find(|x| {
                        for l in x.get_label() {
                            if l.get_name() == "source" && l.get_value() == source {
                                return true;
                            }
                        }
                        false
                    })
                    .unwrap()
                    .get_gauge()
                    .get_value()
            })
            .next()
            .unwrap() as i64
    }

    // Enable snapshot downloading.
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .build();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.tick();

    // The execution layer stores the compilation cache.
    // Therefore, executing the ingress message does not require loading the wasm file.
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(wasm_files_by_source("canister", &env), 0);
    assert_eq!(wasm_files_by_source("snapshot", &env), 0);

    // Restarting the node clears the in-memory compilation cache.
    // The next execution requires loading the wasm binary from disk.
    let env = env.restart_node_with_snapshot_download_enabled();
    env.tick();
    assert_eq!(wasm_files_by_source("canister", &env), 0);
    assert_eq!(wasm_files_by_source("snapshot", &env), 0);

    read_and_assert_eq(&env, canister_id, 1);
    // After the restart, the wasm binary is loaded from the checkpoint, so we expect a file load from the "canister" source.
    assert_eq!(wasm_files_by_source("canister", &env), 1);
    assert_eq!(wasm_files_by_source("snapshot", &env), 0);

    // Create a snapshot of the canister.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        })
        .unwrap()
        .snapshot_id();

    // Because state machine performs checkpointing every round,
    // here the snapshot wasm binary has already switched to the file in snapshot layout.
    // Therefore, metrics from "canister" source and "snapshot" source won't affect each other.
    let args = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::WasmModule { offset: 0, size: 1 },
    );
    let _ = env
        .read_canister_snapshot_data(&args)
        .expect("Error reading snapshot data");

    assert_eq!(wasm_files_by_source("canister", &env), 0);
    assert_eq!(wasm_files_by_source("snapshot", &env), 1);
}

#[test]
fn rejoining_node_doesnt_accumulate_states() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            for i in 1..=3 {
                let mut state = src_state_manager.take_tip().1;
                insert_dummy_canister(&mut state, canister_test_id(100 + i));
                src_state_manager.commit_and_certify(
                    state,
                    height(i),
                    CertificationScope::Full,
                    None,
                );

                let hash = wait_for_checkpoint(&*src_state_manager, height(i));
                let id = StateSyncArtifactId {
                    height: height(i),
                    hash: hash.get(),
                };
                let msg = src_state_sync
                    .get(&id)
                    .expect("failed to get state sync messages");
                let chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
                pipe_state_sync(msg.clone(), chunkable);
                assert_eq!(
                    src_state_manager.get_latest_state().take(),
                    dst_state_manager.get_latest_state().take()
                );
                assert_eq!(
                    dst_state_manager.checkpoint_heights(),
                    (1..=i).map(height).collect::<Vec<_>>()
                );
            }

            dst_state_manager.remove_states_below(height(3));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(3)]);

            assert_error_counters(src_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn temporary_directory_gets_cleaned() {
    state_manager_restart_test(|state_manager, restart_fn| {
        // write something to some file in the tmp directory
        let test_file = state_manager.state_layout().tmp().join("some_file");
        std::fs::write(test_file, "some stuff").expect("failed to write to test file");

        // same for fs_tmp
        let test_file = state_manager.state_layout().fs_tmp().join("some_file");
        std::fs::write(test_file, "some stuff").expect("failed to write to test file");

        // restart the state_manager
        let state_manager = restart_fn(state_manager, None);

        // check the tmp directory is empty
        assert!(
            state_manager
                .state_layout()
                .tmp()
                .read_dir()
                .unwrap()
                .next()
                .is_none(),
            "tmp directory is not empty"
        );
        // check the fs_tmp directory is empty
        assert!(
            state_manager
                .state_layout()
                .fs_tmp()
                .read_dir()
                .unwrap()
                .next()
                .is_none(),
            "tmp directory is not empty"
        );
    });
}

#[test]
fn checkpoint_marked_ro_at_restart() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        let canister_100_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();

        // Make sure we don't do asynchronous operations with checkpoint.
        state_manager.flush_tip_channel();
        let canister_100_wasm = canister_100_layout.wasm().raw_path().to_path_buf();
        make_mutable(&canister_100_wasm).unwrap();

        // Check that there are mutable files before the restart...
        let checkpoints_path = state_manager.state_layout().checkpoints();

        assert!(
            std::panic::catch_unwind(|| {
                assert_all_files_are_readonly(&checkpoints_path);
            })
            .is_err()
        );

        // ...but not after.
        restart_fn(state_manager, None);
        assert_all_files_are_readonly(&checkpoints_path);
    });
}

#[test]
fn tip_can_be_recovered_if_no_checkpoint_exists() {
    // three scenarios
    // Tip is clean after crash but no checkpoints have happened.
    // Post checkpoint tip contains what was checkpointed
    // Post multiple checkpoint tip contains the latest checkpoint

    state_manager_restart_test(|state_manager, restart_fn| {
        let tip_path = state_manager.state_layout().raw_path().join("tip");
        let test_dir = tip_path.join("should_get_deleted");
        std::fs::create_dir_all(test_dir.as_path()).unwrap();
        assert!(test_dir.exists());

        restart_fn(state_manager, None);

        let test_dir = tip_path.join("should_get_deleted");
        assert!(!test_dir.exists());
    });
}

#[test]
fn tip_can_be_recovered_from_empty_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let state_manager = restart_fn(state_manager, None);

        // verify we can continue to recovered tip from empty checkpoint
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
    });
}

#[test]
fn tip_can_be_recovered_from_metadata_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let state_manager = restart_fn(state_manager, None);

        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), vec![]);
    });
}

#[test]
fn tip_can_be_recovered_from_valid_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let state_manager = restart_fn(state_manager, None);

        let canister_id: CanisterId = canister_test_id(100);
        let (_height, recovered_tip) = state_manager.take_tip();

        assert_eq!(canister_ids(&recovered_tip), vec![canister_id]);
    });
}

#[test]
fn tip_can_be_recovered_from_latest_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let state_manager = restart_fn(state_manager, None);

        let canister_id: Vec<CanisterId> = vec![canister_test_id(100), canister_test_id(200)];
        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), canister_id);
    });
}

#[test]
fn tip_can_be_recovered_from_earlier_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let state_manager = restart_fn(state_manager, Some(height(1)));

        let canister_id: Vec<CanisterId> = vec![canister_test_id(100)];
        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), canister_id);
    });
}

#[test]
fn starting_height_independent_of_remove_states_below() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(300));
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(2));
        state_manager.flush_deallocation_channel();

        let canister_id: Vec<CanisterId> = vec![
            canister_test_id(100),
            canister_test_id(200),
            canister_test_id(300),
        ];
        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), canister_id);

        let state_manager = restart_fn(state_manager, Some(height(3)));

        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), canister_id);

        let state_manager = restart_fn(state_manager, Some(height(2)));

        let canister_id: Vec<CanisterId> = vec![canister_test_id(100), canister_test_id(200)];
        let (_height, recovered_tip) = state_manager.take_tip();
        assert_eq!(canister_ids(&recovered_tip), canister_id);
    });
}

#[test]
fn query_stats_are_persisted() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let canister_id: CanisterId = canister_test_id(100);
        let proposer_id: NodeId = node_test_id(42);

        let (_curr_height, mut state) = state_manager.take_tip();

        let epoch = QueryStatsEpoch::from(42);
        let test_query_stats: QueryStats = QueryStats {
            num_calls: 1337,
            num_instructions: 100000,
            ingress_payload_size: 100001,
            egress_payload_size: 100002,
        };

        let mut inner = BTreeMap::new();
        inner.insert(canister_id, test_query_stats.clone());

        let mut records = BTreeMap::new();
        records.insert(epoch, inner);

        let mut stats = BTreeMap::new();
        stats.insert(proposer_id, records);

        state.epoch_query_stats = RawQueryStats {
            highest_aggregated_epoch: Some(epoch),
            stats,
        };

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let state_manager = restart_fn(state_manager, None);

        let (_height, recovered_tip) = state_manager.take_tip();

        let recovered_stats = recovered_tip.epoch_query_stats;
        assert_eq!(recovered_stats.highest_aggregated_epoch, Some(epoch));
        assert_eq!(recovered_stats.stats.len(), 1);
        assert_eq!(
            recovered_stats
                .stats
                .get(&proposer_id)
                .unwrap()
                .get(&epoch)
                .unwrap()
                .get(&canister_id)
                .unwrap(),
            &test_query_stats
        );
    });
}

#[test]
fn stable_memory_is_persisted() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state
            .execution_state
            .as_mut()
            .unwrap()
            .stable_memory
            .size = NumWasmPages::new(2);
        canister_state
            .execution_state
            .as_mut()
            .unwrap()
            .stable_memory
            .page_map = PageMap::from(&[1; 100][..]);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, state) = state_manager.take_tip();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert_eq!(
            NumWasmPages::new(2),
            canister_state
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .size
        );
        assert_eq!(
            PageMap::from(&[1; 100][..]),
            canister_state
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .page_map
        );

        let state_manager = restart_fn(state_manager, None);

        let recovered = state_manager.get_latest_state();
        assert_eq!(height(1), recovered.height());
        let state = recovered.take();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert_eq!(
            NumWasmPages::new(2),
            canister_state
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .size
        );
        assert_eq!(
            PageMap::from(&[1; 100][..]),
            canister_state
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .page_map
        );
    });
}

#[test]
fn missing_stable_memory_file_is_handled() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state.execution_state = None;
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Since the canister has no execution state, there should be no stable memory
        // file.
        let state_layout = state_manager.state_layout();
        let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            state_layout
                .checkpoint_verified(height(1))
                .unwrap()
                .raw_path()
                .to_path_buf(),
            height(1),
        )
        .unwrap();

        let canister_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();
        let canister_stable_memory = canister_layout.stable_memory().base();
        assert!(!canister_stable_memory.exists());

        let state_manager = restart_fn(state_manager, None);

        let recovered = state_manager.get_latest_state();
        assert_eq!(height(1), recovered.height());
        let state = recovered.take();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert!(canister_state.execution_state.is_none());
    });
}

#[test]
/// When the chunk store is first deployed, the replicated state won't have
/// checkpoint files for the Wasm chunk store.
fn missing_wasm_chunk_store_is_handled() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        // Make sure Tip Thread isn't doing anything while we hack into the Checkpoint files.
        state_manager.flush_tip_channel();

        // Since the canister has no execution state, there should be no stable memory
        // file.
        let state_layout = state_manager.state_layout();
        let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            state_layout
                .checkpoint_verified(height(1))
                .unwrap()
                .raw_path()
                .to_path_buf(),
            height(1),
        )
        .unwrap();

        let canister_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();
        let canister_wasm_chunk_store = canister_layout.wasm_chunk_store().base();
        if canister_wasm_chunk_store.exists() {
            std::fs::remove_file(&canister_wasm_chunk_store).unwrap();
        }
        for overlay in canister_layout
            .wasm_chunk_store()
            .existing_overlays()
            .unwrap()
        {
            std::fs::remove_file(&overlay).unwrap();
        }

        let state_manager = restart_fn(state_manager, None);
        let (recovered_height, recovered) = state_manager.take_tip();
        assert_eq!(height(1), recovered_height);

        assert!(!canister_wasm_chunk_store.exists());
        state_manager.commit_and_certify(recovered, height(2), CertificationScope::Full, None);
    });
}

fn state_manager_crash_test<Test>(
    fixtures: Vec<
        Box<dyn FnOnce(StateManagerImpl) + std::panic::UnwindSafe + std::panic::RefUnwindSafe>,
    >,
    test: Test,
) where
    Test: FnOnce(&MetricsRegistry, StateManagerImpl),
{
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    with_test_replica_logger(|log| {
        for (i, fixture) in fixtures.into_iter().enumerate() {
            std::panic::catch_unwind(|| {
                fixture(StateManagerImpl::new(
                    Arc::new(FakeVerifier::new()),
                    subnet_test_id(42),
                    SubnetType::Application,
                    log.clone(),
                    &MetricsRegistry::new(),
                    &config,
                    None,
                    ic_types::malicious_flags::MaliciousFlags::default(),
                ));
            })
            .expect_err(&format!("Crash test fixture {i} did not crash"));
        }

        let metrics = MetricsRegistry::new();

        test(
            &metrics,
            StateManagerImpl::new(
                Arc::new(FakeVerifier::new()),
                subnet_test_id(42),
                SubnetType::Application,
                log,
                &metrics,
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            ),
        );
    });
}

#[test]
fn commit_remembers_state() {
    state_manager_test(|_metrics, state_manager| {
        const HEIGHT: Height = height(1);
        assert!(state_manager.get_state_at(HEIGHT).is_err());

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, HEIGHT, CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, HEIGHT);

        assert!(state_manager.get_state_at(HEIGHT).is_ok());
        assert!(state_manager.get_state_hash_at(HEIGHT).is_ok());
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), HEIGHT]
        );
    });
}

#[test]
fn can_get_initial_state() {
    state_manager_test(|_metrics, state_manager| {
        assert_eq!(
            state_manager.get_state_at(height(0)).unwrap().height(),
            height(0)
        );
    });
}

#[test]
fn latest_state_height_updated_on_commit() {
    state_manager_test(|_metrics, state_manager| {
        let (_, tip) = state_manager.take_tip();
        assert_eq!(height(0), state_manager.latest_state_height());

        state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata, None);
        assert_eq!(height(1), state_manager.latest_state_height());

        let (_, tip) = state_manager.take_tip();
        state_manager.commit_and_certify(tip, height(2), CertificationScope::Full, None);
        assert_eq!(height(2), state_manager.latest_state_height());
    })
}

#[test]
fn populates_prev_state_hash() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (_height, state_1) = state_manager.take_tip();
        state_manager.commit_and_certify(state_1, height(2), CertificationScope::Metadata, None);
        let state_2 = state_manager.get_latest_state().take();

        let hashes = state_manager.list_state_hashes_to_certify();

        assert_eq!(2, hashes.len());
        assert_ne!(hashes[0].1, hashes[1].1);
        assert_eq!(
            Some(hashes[0].1.clone()),
            state_2.system_metadata().prev_state_hash
        );
    });
}

#[test]
fn returns_state_no_committed_for_future_states() {
    state_manager_test(|_metrics, state_manager| {
        let h = height(5);
        let latest_state = state_manager.latest_state_height();
        assert!(
            latest_state < h,
            "Expected latest state to be < {h}, got {latest_state}"
        );
        assert_eq!(
            state_manager.get_state_at(h),
            Err(StateManagerError::StateNotCommittedYet(h))
        );
    });
}

#[test]
#[should_panic(expected = "different hashes")]
fn panics_on_forked_history() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (_height, mut state) = state_manager.take_tip();
        state.modify_streams(|streams| {
            streams.insert(subnet_test_id(1), Stream::default());
        });
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
    });
}

#[test]
fn can_commit_same_state_twice() {
    state_manager_test(|_metrics, state_manager| {
        let (tip_height, state) = state_manager.take_tip();
        assert_eq!(tip_height, height(0));
        let state_copy = state.clone();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (tip_height, _state) = state_manager.take_tip();
        assert_eq!(tip_height, height(1));
        // _state and state_copy will differ in metadata.prev_state_height,
        // so to commit the same state twice we need to commit the copy.
        state_manager.commit_and_certify(state_copy, height(1), CertificationScope::Metadata, None);

        let (tip_height, _state) = state_manager.take_tip();
        assert_eq!(tip_height, height(1));
    });
}

#[test]
fn checkpoints_outlive_state_manager() {
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());

    with_test_replica_logger(|log| {
        let canister_id: CanisterId = canister_test_id(100);

        {
            let metrics_registry = MetricsRegistry::new();
            let own_subnet = subnet_test_id(42);
            let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

            let state_manager = StateManagerImpl::new(
                verifier,
                own_subnet,
                SubnetType::Application,
                log.clone(),
                &metrics_registry,
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );
            let (_height, mut state) = state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_id);

            state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata, None);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(4), CertificationScope::Metadata, None);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(5), CertificationScope::Full, None);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(6), CertificationScope::Full, None);
        }

        let metrics_registry = MetricsRegistry::new();
        let own_subnet = subnet_test_id(42);
        let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());
        let state_manager = StateManagerImpl::new(
            verifier,
            own_subnet,
            SubnetType::Application,
            log,
            &metrics_registry,
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(1), height(2), height(5), height(6)]
        );

        let checkpointed_state = state_manager.get_latest_state();

        assert_eq!(checkpointed_state.height(), height(6));
        assert_eq!(
            canister_ids(checkpointed_state.get_ref()),
            vec![canister_id]
        );
    });
}

#[test]
fn certifications_are_not_persisted() {
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    with_test_replica_logger(|log| {
        {
            let metrics_registry = MetricsRegistry::new();
            let state_manager = StateManagerImpl::new(
                Arc::new(FakeVerifier::new()),
                subnet_test_id(42),
                SubnetType::Application,
                log.clone(),
                &metrics_registry,
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
            assert_eq!(vec![height(1)], heights_to_certify(&state_manager));
            certify_height(&state_manager, height(1));
            assert_eq!(Vec::<Height>::new(), heights_to_certify(&state_manager));
        }
        {
            let metrics_registry = MetricsRegistry::new();
            let state_manager = StateManagerImpl::new(
                Arc::new(FakeVerifier::new()),
                subnet_test_id(42),
                SubnetType::Application,
                log,
                &metrics_registry,
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );
            assert_eq!(vec![height(1)], heights_to_certify(&state_manager));
        }
    });
}

#[test]
fn all_manifests_are_persisted() {
    state_manager_restart_test_with_metrics(|_metrics, state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(1));

        let (metrics, state_manager) = restart_fn(state_manager, None);

        wait_for_checkpoint(&state_manager, height(1));

        // No manifest computations happened
        assert_eq!(
            0,
            fetch_int_counter_vec(&metrics, "state_manager_manifest_chunk_bytes")
                .values()
                .sum::<u64>()
        );
    });
}

#[test]
fn missing_manifests_are_recomputed() {
    state_manager_restart_test_deleting_metadata(|_metrics, state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_metrics, state_manager) = restart_fn(state_manager, None);

        wait_for_checkpoint(&state_manager, height(1));
    });
}

/// Tests that the manifest is computed incrementally using a delta relative to the manifest at a
/// lower height. Steps are:
///
/// - Compute the manifest at height 2 using the delta from the manifest at height 1.
/// - Compute the manifest at height 3 using the delta from the manifest at height 2.
/// - Compute the manifests at height 2 and 3 using the deltas from the manifest at height 1.
///
/// The third step consists of the first step + a new manifest computation that is expected to
/// require more hashing than the second step since it's done from height 1.
///
/// Asserting that more hashing is required in step 3 ensures two things:
/// - The computation in the second step was actually done from height 2 since it required less
///   hashing.
/// - Incremental manifest computation can be done from a height further back than the previous one
///   (at the cost of more hashing).
#[test]
fn missing_manifest_is_computed_incrementally() {
    state_manager_restart_test_with_metrics(|_metrics, state_manager, restart_fn| {
        use ic_state_manager::testing::StateManagerTesting;

        let hashed_key = maplit::btreemap! {"type".to_string() => "hashed".to_string()};
        let reused_key = maplit::btreemap! {"type".to_string() => "reused".to_string()};
        let hashed_and_compared_key =
            maplit::btreemap! {"type".to_string() => "hashed_and_compared".to_string()};

        let insert_canister_and_write_checkpoint = |state_manager: StateManagerImpl,
                                                    height: Height,
                                                    canister_id: CanisterId|
         -> StateManagerImpl {
            let (_height, mut state) = state_manager.take_tip();

            insert_dummy_canister(&mut state, canister_id);
            state
                .canister_state_mut(&canister_id)
                .unwrap()
                .execution_state
                .as_mut()
                .unwrap()
                .stable_memory
                .page_map
                .update(&[(PageIndex::new(1), &[1_u8; PAGE_SIZE])]);

            state_manager.commit_and_certify(state, height, CertificationScope::Full, None);
            wait_for_checkpoint(&state_manager, height);
            state_manager.flush_tip_channel();

            state_manager
        };

        let purge_manifests_and_restart = |mut state_manager: StateManagerImpl,
                                           purge_manifest_heights: &[Height],
                                           restart_height: Height|
         -> (StateManagerImpl, u64, u64) {
            for h in purge_manifest_heights {
                assert!(state_manager.purge_manifest(*h));
            }
            let (metrics, state_manager) = restart_fn(state_manager, Some(restart_height));
            wait_for_checkpoint(&state_manager, restart_height);

            let chunk_bytes = fetch_int_counter_vec(&metrics, "state_manager_manifest_chunk_bytes");

            // Return the state manager along with the number of reused bytes and the
            // number of bytes hashed.
            (
                state_manager,
                chunk_bytes[&reused_key] + chunk_bytes[&hashed_and_compared_key],
                chunk_bytes[&hashed_key],
            )
        };

        // Create two checkpoints @1 and @2.
        let state_manager =
            insert_canister_and_write_checkpoint(state_manager, height(1), canister_test_id(1));
        let state_manager =
            insert_canister_and_write_checkpoint(state_manager, height(2), canister_test_id(2));

        // Trigger an incremental manifest computation @2 with a delta 1 -> 2.
        let (state_manager, incremental_at_2_from_1, hashed_at_2_from_1) =
            purge_manifests_and_restart(
                state_manager,
                &[height(2)], // Purge manifest @2.
                height(2),    // Restart the state manager @2.
            );
        // For an incremental manifest computation, something must have been incremental.
        assert_ne!(0, incremental_at_2_from_1);

        // Create a checkpoint @3.
        let state_manager =
            insert_canister_and_write_checkpoint(state_manager, height(3), canister_test_id(3));

        // Trigger an incremental manifest computation @3 with a delta 2 -> 3.
        let (state_manager, incremental_at_3_from_2, hashed_at_3_from_2) =
            purge_manifests_and_restart(
                state_manager,
                &[height(3)], // Purge manifest at height 3.
                height(3),    // Restart the state manager at height 3.
            );
        // For an incremental manifest computation, something must have been incremental.
        assert_ne!(0, incremental_at_3_from_2);

        // Trigger incremental manifest computations @2 and @3 with deltas 1 -> 2 and 1 -> 3.
        let (_, incremental_at_2_and_3_from_1, hashed_at_2_and_3_from_1) =
            purge_manifests_and_restart(
                state_manager,
                &[height(2), height(3)], // Purge manifest at height 2 and 3.
                height(3),               // Restart the state manager at height 3.
            );
        // For an incremental manifest computation, something must have been incremental;
        // since the both manifest computations are expected to be incremental, it
        // must be larger than the one in step 1.
        assert!(incremental_at_2_and_3_from_1 > incremental_at_2_from_1);

        let hashed_at_3_from_1 = hashed_at_2_and_3_from_1 - hashed_at_2_from_1;
        assert!(hashed_at_3_from_1 > hashed_at_3_from_2);
    });
}

#[test]
fn validate_replicated_state_is_called() {
    fn validate_was_called(metrics: &MetricsRegistry) -> bool {
        let request_duration = fetch_histogram_vec_stats(
            metrics,
            "state_manager_tip_handler_request_duration_seconds",
        );
        for (label, _stats) in request_duration.iter() {
            if label.get("request") == Some(&"validate_replicated_state_and_finalize".to_string()) {
                return true;
            }
        }
        false
    }

    state_manager_test(|metrics, state_manager| {
        assert!(!validate_was_called(metrics));
        let (_, tip) = state_manager.take_tip();
        state_manager.commit_and_certify(tip, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert!(validate_was_called(metrics));
    });
}

fn any_manifest_was_incremental(metrics: &MetricsRegistry) -> bool {
    // We detect that the manifest computation was incremental by checking that at least some bytes
    // are either "reused" or "hashed_and_compared"
    let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
    let reused_key = maplit::btreemap! {"type".to_string() => "reused".to_string()};
    let hashed_and_compared_key =
        maplit::btreemap! {"type".to_string() => "hashed_and_compared".to_string()};
    chunk_bytes[&reused_key] + chunk_bytes[&hashed_and_compared_key] != 0
}

#[test]
fn first_manifest_after_restart_is_incremental() {
    state_manager_restart_test_with_metrics(|metrics, state_manager, restart_fn| {
        let (_height, mut state) = state_manager.take_tip();

        // We need at least one canister, as incremental manifest computation only considers
        // heap and stable memory
        insert_dummy_canister(&mut state, canister_test_id(1));
        let canister_state = state.canister_state_mut(&canister_test_id(1)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();

        const NEW_WASM_PAGE: u64 = 300;
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[1u8; PAGE_SIZE]),
            (PageIndex::new(NEW_WASM_PAGE), &[2u8; PAGE_SIZE]),
        ]);
        const NEW_STABLE_PAGE: u64 = 500;
        execution_state.stable_memory.page_map.update(&[
            (PageIndex::new(1), &[1u8; PAGE_SIZE]),
            (PageIndex::new(NEW_STABLE_PAGE), &[2u8; PAGE_SIZE]),
        ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(1));
        assert!(!any_manifest_was_incremental(metrics));

        let (metrics, state_manager) = restart_fn(state_manager, None);

        wait_for_checkpoint(&state_manager, height(1)); // Make sure the base manifest is available
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(2));

        assert!(any_manifest_was_incremental(&metrics));
    });
}

#[test]
fn can_filter_by_certification_mask() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(4), CertificationScope::Full, None);

        for h in 1..=2 {
            certify_height(&state_manager, height(h));
        }

        assert_eq!(
            state_manager.list_state_heights(CERT_CERTIFIED),
            vec![height(1), height(2)]
        );
        assert_eq!(
            state_manager.list_state_heights(CERT_UNCERTIFIED),
            vec![height(0), height(3), height(4)]
        );
    })
}

#[test]
fn should_archive_checkpoints_correctly() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..14 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }

        assert_eq!(height(13), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(13), latest_state.height());

        state_manager.flush_tip_channel();
        // Manually marks checkpoint at height 6 and 10 as unverified, and it should be archived on restart.
        let marker_file_6 = state_manager
            .state_layout()
            .checkpoint_verified(height(6))
            .unwrap()
            .unverified_checkpoint_marker();
        std::fs::File::create(marker_file_6).expect("failed to write to marker file");

        let marker_file_10 = state_manager
            .state_layout()
            .checkpoint_verified(height(10))
            .unwrap()
            .unverified_checkpoint_marker();
        std::fs::File::create(marker_file_10).expect("failed to write to marker file");

        let state_manager = restart_fn(state_manager, Some(height(6)));

        // The unverified checkpoints at height 6 and 10, and any checkpoints at or above height 8 are archived.
        // However, at most one checkpoint will be stored in the backups directory after cleanup.
        assert_eq!(
            state_manager.state_layout().backup_heights().unwrap(),
            vec![height(12)],
        );

        // The checkpoints at height 2 and 4 should not be accidentally archived.
        assert_eq!(
            state_manager.checkpoint_heights(),
            vec![height(2), height(4)],
        );

        // State manager should restart from checkpoint at height 4 instead of 6 or 8.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(2), height(4)],
        );
        assert_eq!(height(4), state_manager.latest_state_height());
        let (latest_height, _) = state_manager.take_tip();
        assert_eq!(height(4), latest_height);
    });
}

#[test]
fn can_remove_checkpoints() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(4));
        state_manager.flush_deallocation_channel();

        for h in 1..4 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(4),
                height(5),
                height(6),
                height(7),
                height(8),
                height(9)
            ],
        );

        let state_manager = restart_fn(state_manager, Some(height(4)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(4),],
        );
    });
}

#[test]
fn cannot_remove_height_zero() {
    state_manager_test(|_metrics, state_manager| {
        assert_eq!(state_manager.list_state_heights(CERT_ANY), vec![height(0),],);

        state_manager.remove_states_below(height(0));
        state_manager.flush_deallocation_channel();
        state_manager.remove_inmemory_states_below(height(0), &BTreeSet::new());

        assert_eq!(state_manager.list_state_heights(CERT_ANY), vec![height(0),],);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(1)],
        );

        state_manager.remove_states_below(height(0));
        state_manager.flush_deallocation_channel();
        state_manager.remove_inmemory_states_below(height(0), &BTreeSet::new());

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(1)],
        );
    });
}

#[test]
fn cannot_remove_latest_height_or_checkpoint() {
    state_manager_test(|_metrics, state_manager| {
        for i in 1..11 {
            let (_height, state) = state_manager.take_tip();

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(10))
        );

        // We need to wait for hashing to complete, otherwise the
        // checkpoint can be retained until the hashing is complete.
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(20));
        state_manager.remove_inmemory_states_below(height(20), &BTreeSet::new());
        state_manager.flush_deallocation_channel();

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(10))
        );

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(11), CertificationScope::Metadata, None);

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(11))
        );

        // 10 is the latest checkpoint, hence cannot have been deleted
        assert!(state_manager.checkpoint_heights().contains(&height(10)));

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(20));
        state_manager.remove_inmemory_states_below(height(20), &BTreeSet::new());
        state_manager.flush_deallocation_channel();

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(11))
        );

        assert!(state_manager.checkpoint_heights().contains(&height(10)));
    });
}

#[test]
fn can_remove_checkpoints_and_noncheckpoints_separately() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        // We need to wait for hashing to complete, otherwise the
        // checkpoint can be retained until the hashing is complete.
        state_manager.flush_tip_channel();

        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.remove_inmemory_states_below(height(6), &BTreeSet::new());

        // Snapshots from @1 to @5 are purged are removed while no checkpoints are removed.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6), height(7), height(8), height(9)],
        );
        assert_eq!(
            state_manager.checkpoint_heights(),
            vec![height(2), height(4), height(6), height(8)]
        );

        state_manager.remove_states_below(height(4));
        state_manager.flush_deallocation_channel();

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6), height(7), height(8), height(9)],
        );
        // Checkpoints at @2 is removed.
        assert_eq!(
            state_manager.checkpoint_heights(),
            vec![height(4), height(6), height(8)]
        );

        let state_manager = restart_fn(state_manager, Some(height(6)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(4), height(6)],
        );
    });
}

#[test]
fn remove_inmemory_states_below_can_keep_extra_states() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        // We need to wait for hashing to complete, otherwise the
        // checkpoint can be retained until the hashing is complete.
        state_manager.flush_tip_channel();

        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);

        // Tests the behavior of `remove_inmemory_states_below` for various scenarios involving extra heights to keep.
        // This call covers another two cases:
        // Case 1:
        //   Extra heights to keep exist in memory and are below the requested height to remove.
        //   Expected: These heights are retained.
        // Case 2:
        //   Extra heights to keep exist in memory and are at or above the requested height to remove.
        //   Expected: No effect.
        state_manager
            .remove_inmemory_states_below(height(5), &btreeset![height(1), height(4), height(7)]);

        // State at height 1 is kept because of it is included in `extra_heights_to_keep`.
        // State at 2 is removed because it is below the requested height and are not asked to keep in addition.
        // Note that although state at 2 has a checkpoint, we don't treat it differently when removing in-memory states.
        // State at 4 is kept because of it is protected by `extra_heights_to_keep`.
        // The additional protection on the state at height 7 has no effect since it is above the requested height.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(1),
                height(4),
                height(5),
                height(6),
                height(7),
                height(8),
                height(9)
            ],
        );

        // This call covers another two cases:
        // Case 3:
        //   Extra heights to keep do not exist in memory, and are below the requested height to remove.
        //   Expected: No effect.
        // Case 4:
        //   Extra heights to keep do not exist in memory, and are at or above the requested height to remove.
        //   Expected: No effect.
        state_manager.remove_inmemory_states_below(
            height(9),
            &btreeset![height(2), height(7), height(8), height(10)],
        );

        // Asking to keep state at 2 has no effect since it is already removed.
        // State at height 7 and 8 are kept because they are included in `extra_heights_to_keep`.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(7), height(8), height(9)],
        );

        certify_height(&state_manager, height(8));

        state_manager.remove_inmemory_states_below(height(10), &BTreeSet::new());

        // There remain only the latest state, the latest certified height and the initial state.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(8), height(9)],
        );

        // Checkpoints are all present because we have not called `remove_states_below` yet.
        assert_eq!(
            state_manager.checkpoint_heights(),
            vec![height(2), height(4), height(6), height(8)]
        );

        state_manager.remove_states_below(height(10));
        state_manager.flush_deallocation_channel();

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(8), height(9)],
        );

        assert_eq!(state_manager.checkpoint_heights(), vec![height(8)]);

        let state_manager = restart_fn(state_manager, Some(height(8)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(8)],
        );
    });
}

#[test]
fn can_keep_last_checkpoint_and_higher_states_after_removal() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(10));
        state_manager.flush_deallocation_channel();

        for h in 1..=7 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        // Although snapshot at height 8 is removed,  `get_state_at` will load the checkpoint at height to serve the state.
        assert!(state_manager.get_state_at(height(8)).is_ok());

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(9)],
        );

        assert_eq!(height(9), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(9), latest_state.height());

        let state_manager = restart_fn(state_manager, Some(height(10)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(8),],
        );
        assert_eq!(height(8), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(8), latest_state.height());
    });
}

#[test]
fn can_keep_latest_verified_checkpoint_after_removal_with_unverified_checkpoints_present() {
    use ic_state_layout::RwPolicy;
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();

        let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            state_manager
                .state_layout()
                .checkpoint_verified(height(8))
                .unwrap()
                .raw_path()
                .to_path_buf(),
            height(8),
        )
        .unwrap();
        mutable_cp_layout
            .create_unverified_checkpoint_marker()
            .unwrap();

        state_manager.remove_states_below(height(10));
        state_manager.flush_deallocation_channel();

        for h in (1..=5).chain(7..=7) {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        assert_eq!(state_manager.checkpoint_heights(), vec![height(6)]);
        assert_eq!(
            state_manager
                .state_layout()
                .unfiltered_checkpoint_heights()
                .expect("failed to get unfiltered checkpoint heights"),
            vec![height(6), height(8)]
        );
        // Although snapshot at height 6 is removed,  `get_state_at` will load the checkpoint at height to serve the state.
        assert!(state_manager.get_state_at(height(6)).is_ok());
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(9)],
        );

        assert_eq!(height(9), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(9), latest_state.height());

        let state_manager = restart_fn(state_manager, Some(height(10)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6),],
        );
        assert_eq!(height(6), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(6), latest_state.height());
    });
}

#[test]
fn should_restart_from_the_latest_checkpoint_requested_to_remove() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let mut heights = vec![height(0)];
        for i in 1..14 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(7));
        state_manager.flush_deallocation_channel();

        for h in 1..6 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        // The checkpoint at height 6 is the latest checkpoint requested to remove.
        // Therefore, the checkpoint should be kept while the snapshot is removed.
        assert!(state_manager.checkpoint_heights().contains(&height(6)));
        // Although snapshot at height 6 is removed,  `get_state_at` will load the checkpoint at height to serve the state.
        assert!(state_manager.get_state_at(height(6)).is_ok());
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(7),
                height(8),
                height(9),
                height(10),
                height(11),
                height(12),
                height(13)
            ],
        );

        assert_eq!(height(13), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(13), latest_state.height());

        let state_manager = restart_fn(state_manager, Some(height(6)));

        // The checkpoint at height 8 is ignored.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6)],
        );

        // State manager should restart from checkpoint at height 6 instead of 8.
        assert_eq!(height(6), state_manager.latest_state_height());
        let (latest_height, _) = state_manager.take_tip();
        assert_eq!(height(6), latest_height);
    });
}

#[test]
fn should_be_able_to_restart_twice_from_the_same_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        for (h, scope) in [
            (height(1), CertificationScope::Full),
            (height(2), CertificationScope::Metadata),
            (height(3), CertificationScope::Metadata),
            (height(4), CertificationScope::Full),
        ]
        .iter()
        {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, *h, scope.clone(), None);
        }

        state_manager.remove_states_below(height(3));
        state_manager.flush_deallocation_channel();

        let state_manager = restart_fn(state_manager, Some(height(3)));

        assert_eq!(height(1), state_manager.latest_state_height());
        assert_eq!(
            vec![height(4)],
            state_manager.state_layout().backup_heights().unwrap(),
        );

        for (h, scope) in [
            (height(2), CertificationScope::Metadata),
            (height(3), CertificationScope::Metadata),
            (height(4), CertificationScope::Full),
        ]
        .iter()
        {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, *h, scope.clone(), None);
        }

        let state_manager = restart_fn(state_manager, Some(height(3)));

        assert_eq!(height(1), state_manager.latest_state_height());
        assert_eq!(
            vec![height(4)],
            state_manager.state_layout().backup_heights().unwrap(),
        );
    });
}

#[test]
fn should_keep_the_last_checkpoint_on_restart() {
    state_manager_restart_test(|state_manager, restart_fn| {
        for (h, scope) in [
            (height(1), CertificationScope::Metadata),
            (height(2), CertificationScope::Metadata),
            (height(3), CertificationScope::Metadata),
            (height(4), CertificationScope::Full),
        ]
        .iter()
        {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, *h, scope.clone(), None);
        }

        state_manager.remove_states_below(height(3));
        state_manager.flush_deallocation_channel();

        let state_manager = restart_fn(state_manager, Some(height(3)));

        assert_eq!(height(4), state_manager.latest_state_height());
        assert!(
            state_manager
                .state_layout()
                .backup_heights()
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn backup_checkpoint_is_complete() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let state_hash = wait_for_checkpoint(&state_manager, height(2));

        let state_manager = restart_fn(state_manager, Some(height(1)));

        // check that the backup checkpoint has the same manifest as before
        let manifest = manifest_from_path(
            &state_manager
                .state_layout()
                .backup_checkpoint_path(height(2)),
        )
        .unwrap();
        validate_manifest(&manifest, &state_hash).unwrap()
    });
}

#[test]
fn should_not_remove_latest_state_after_restarting_without_checkpoints() {
    state_manager_restart_test(|state_manager, restart_fn| {
        for i in 0..10 {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata, None);
            state_manager.remove_states_below(height(i));
            state_manager.flush_deallocation_channel();
        }

        let state_manager = restart_fn(state_manager, Some(height(10)));
        for i in 0..10 {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata, None);
            state_manager.remove_states_below(height(9));
            state_manager.flush_deallocation_channel();
            assert_eq!(height(i), state_manager.latest_state_height());
        }
    });
}

#[test]
fn can_keep_the_latest_snapshot_after_removal() {
    state_manager_test(|_metrics, state_manager| {
        let mut heights = vec![height(0)];
        for i in 1..10 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 2 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        state_manager.flush_tip_channel();
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);

        for i in 1..20 {
            state_manager.remove_states_below(height(i));
            state_manager.flush_deallocation_channel();
            assert_eq!(height(9), state_manager.latest_state_height());
            let latest_state = state_manager.get_latest_state();
            assert_eq!(height(9), latest_state.height());
        }
    })
}

/// Test if `remove_states_below` behaves as expected after enabling purging
/// intermediate snapshots.
#[test]
fn can_purge_intermediate_snapshots() {
    state_manager_test(|_metrics, state_manager| {
        let mut heights = vec![height(0)];
        for i in 1..23 {
            let (_height, state) = state_manager.take_tip();
            heights.push(height(i));

            let scope = if i % 5 == 0 {
                CertificationScope::Full
            } else {
                CertificationScope::Metadata
            };

            state_manager.commit_and_certify(state, height(i), scope.clone(), None);
        }
        state_manager.flush_tip_channel();
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);

        // Intermediate snapshots from @1 to @8 are purged.
        state_manager.remove_states_below(height(9));
        state_manager.flush_deallocation_channel();
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(9),
                height(10),
                height(11),
                height(12),
                height(13),
                height(14),
                height(15),
                height(16),
                height(17),
                height(18),
                height(19),
                height(20),
                height(21),
                height(22)
            ],
        );

        // Intermediate states from @10 to @18 are purged.
        state_manager.remove_states_below(height(19));
        state_manager.flush_deallocation_channel();
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(19), height(20), height(21), height(22)],
        );

        // Test calling `remove_states_below` at the latest checkpoint height.
        // Intermediate states from @16 to @19 are purged. @15 is purged, as
        // no inmemory states depend on it anymore.
        state_manager.remove_states_below(height(20));
        state_manager.flush_deallocation_channel();
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(20), height(21), height(22)],
        );

        // Test calling `remove_states_below` at the latest state height.
        // The intermediate state @21 is purged.
        state_manager.remove_states_below(height(22));
        state_manager.flush_deallocation_channel();
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(22)],
        );

        // Test calling `remove_states_below` at a higher height than the latest state
        // height.
        // The intermediate state @21 is purged.
        // The latest state should always be kept.
        state_manager.remove_states_below(height(25));
        state_manager.flush_deallocation_channel();
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(22)],
        );
    })
}

#[test]
fn latest_certified_state_is_not_removed() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
        certify_height(&state_manager, height(1));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(4), CertificationScope::Metadata, None);

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(4));
        state_manager.flush_deallocation_channel();
        assert_eq!(height(4), state_manager.latest_state_height());
        assert_eq!(height(1), state_manager.latest_certified_height());

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            // 1 is protected as latest certified state
            vec![height(0), height(1), height(4)],
        );
    });
}

#[test]
fn can_return_and_remember_certifications() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);

        assert_eq!(
            vec![height(1), height(2)],
            heights_to_certify(&state_manager)
        );
        certify_height(&state_manager, height(1));

        assert_eq!(vec![height(2)], heights_to_certify(&state_manager));
    });
}

#[test]
fn certifications_of_transient_states_are_not_cached() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        certify_height(&state_manager, height(1));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);
        certify_height(&state_manager, height(2));

        assert_eq!(Vec::<Height>::new(), heights_to_certify(&state_manager));

        let state_manager = restart_fn(state_manager, None);

        assert_eq!(height(1), state_manager.latest_state_height());
        let (_height, state) = state_manager.take_tip();
        // Commit the same state again. The certification should be re-used.
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);
        assert_eq!(
            vec![Height::from(1), Height::from(2)],
            heights_to_certify(&state_manager)
        );
    })
}

#[test]
fn uses_latest_certified_state_to_decode_certified_streams() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let subnet = subnet_test_id(42);

        // no streams yet
        assert_eq!(
            state_manager.encode_certified_stream_slice(subnet, None, None, None, None),
            Err(EncodeStreamError::NoStreamForSubnet(subnet))
        );

        certify_height(&state_manager, height(1));

        let (_height, mut state) = state_manager.take_tip();
        state.modify_streams(|streams| {
            streams.insert(subnet, Stream::default());
        });

        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);
        // Have a stream, but this state is not certified yet.
        assert_eq!(
            state_manager.encode_certified_stream_slice(subnet, None, None, None, None),
            Err(EncodeStreamError::NoStreamForSubnet(subnet))
        );

        let certification = certify_height(&state_manager, height(2));

        let slice = state_manager
            .encode_certified_stream_slice(subnet, None, None, None, None)
            .expect("failed to encode certified stream");

        assert_eq!(certification, slice.certification);
    });
}

#[test]
fn encode_stream_index_is_checked() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        let subnet = subnet_test_id(42);
        state.modify_streams(|streams| {
            streams.insert(subnet, Stream::default());
        });

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
        certify_height(&state_manager, height(1));

        let zero_idx = StreamIndex::from(0);
        let request_from = StreamIndex::from(1);

        assert_eq!(
            state_manager.encode_certified_stream_slice(
                subnet,
                Some(request_from),
                Some(request_from),
                None,
                None
            ),
            Err(EncodeStreamError::InvalidSliceBegin {
                slice_begin: request_from,
                stream_begin: zero_idx,
                stream_end: zero_idx,
            })
        );
    });
}

#[test]
fn delivers_state_adverts_once() {
    state_manager_test_with_state_sync(|_metrics, state_manager, state_sync| {
        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        assert!(state_sync.get(&id).is_some());
        assert!(state_sync.get(&id).is_some());
    });
}

#[test]
fn recomputes_metadata_on_restart_if_missing() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        std::fs::remove_file(state_manager.state_layout().states_metadata())
            .expect("Failed to remove states metadata");
        let cert_hashes = state_manager.list_state_hashes_to_certify();
        assert_eq!(1, cert_hashes.len());
        assert_eq!(height(1), cert_hashes[0].0);

        let state_manager = restart_fn(state_manager, None);

        assert_eq!(cert_hashes, state_manager.list_state_hashes_to_certify());
    })
}

#[test]
fn state_sync_message_contains_manifest() {
    state_manager_test_with_state_sync(|_metrics, state_manager, state_sync| {
        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let msg = state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        // Expecting 1 file (system_metadata.pbuf), as we don't have canisters in the default state.
        // Two files, subnet_queues.pbuf and ingress_history.pbuf, are empty and therefore omitted.
        assert_eq!(1, msg.manifest.file_table.len());

        // Check that all the files are accessible
        for file_info in msg.manifest.file_table.iter() {
            let absolute_path = msg.checkpoint_root.join(&file_info.relative_path);
            assert!(
                absolute_path.exists(),
                "Expected checkpoint path {} to exist",
                absolute_path.display()
            );
        }
    });
}

#[test]
fn state_sync_priority_fn_respects_states_to_fetch() {
    state_manager_test_with_state_sync(|_metrics, state_manager, state_sync| {
        fn hash(n: u8) -> CryptoHashOfState {
            CryptoHashOfState::from(CryptoHash(vec![n; 32]))
        }

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);

        for (h, p) in [(1, false), (2, false), (3, false)].iter() {
            assert_eq!(
                *p,
                state_sync.should_download(&StateSyncArtifactId {
                    height: height(*h),
                    hash: hash(*h as u8).get(),
                },)
            );
        }

        // Request fetching of state 3.
        state_manager.fetch_state(height(3), hash(3), Height::new(99));
        // Good hash
        assert!(state_sync.should_download(&StateSyncArtifactId {
            height: height(3),
            hash: hash(3).get(),
        }));
        // Wrong hash
        assert!(!state_sync.should_download(&StateSyncArtifactId {
            height: height(3),
            hash: hash(4).get(),
        }));

        // Request fetching of newer state 4.
        state_manager.fetch_state(height(4), hash(4), Height::new(99));
        assert!(!state_sync.should_download(&StateSyncArtifactId {
            height: height(3),
            hash: hash(3).get(),
        },));
        assert!(state_sync.should_download(&StateSyncArtifactId {
            height: height(4),
            hash: hash(4).get(),
        }));
    });
}

/// Asserts that all error counters in the state manager are still 0
fn assert_error_counters(metrics: &MetricsRegistry) {
    assert_eq!(
        0,
        fetch_int_counter_vec(metrics, "critical_errors")
            .values()
            .sum::<u64>()
    );
}

fn assert_no_remaining_chunks(metrics: &MetricsRegistry) {
    assert_eq!(
        0,
        fetch_gauge(metrics, "state_sync_remaining_chunks").unwrap() as i64
    );
}

// This is a helper function only for testing purpose.
// It first sets the `fetch_state` in the state manager with the height and hash
// from a state sync artifact ID and then starts the state sync with the same ID.
// It should only be called when the state manager does not have the state at the height
// and there is no ongoing state sync.
// For more complex testing scenarios, use `fetch_state` and `maybe_start_state_sync` separately with proper arguments.
fn set_fetch_state_and_start_state_sync(
    state_manager: &Arc<StateManagerImpl>,
    state_sync: &StateSync,
    id: &StateSyncArtifactId,
) -> Box<dyn Chunkable<StateSyncMessage> + Send> {
    state_manager.fetch_state(
        id.height,
        CryptoHashOfState::from(id.hash.clone()),
        Height::new(499),
    );
    state_sync
        .maybe_start_state_sync(id)
        .expect("failed to start state sync")
}

#[test]
fn can_do_simple_state_sync_transfer() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            pipe_state_sync(msg, chunkable);

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);

            let mut tip = dst_state_manager.take_tip().1;
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata
                .prev_state_hash
                .clone_from(&state.metadata.prev_state_hash);
            assert_eq!(*state.as_ref(), tip);
            assert_eq!(vec![height(1)], heights_to_certify(&*dst_state_manager));

            assert_error_counters(dst_metrics);
            assert_no_remaining_chunks(dst_metrics);
        })
    })
}

#[test]
fn test_start_and_cancel_state_sync() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(101));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash1 = wait_for_checkpoint(&*src_state_manager, height(1));

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(102));
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        let hash2 = wait_for_checkpoint(&*src_state_manager, height(2));

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(103));
        src_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        let hash3 = wait_for_checkpoint(&*src_state_manager, height(3));

        let id1 = StateSyncArtifactId {
            height: height(1),
            hash: hash1.clone().get(),
        };

        let id2 = StateSyncArtifactId {
            height: height(2),
            hash: hash2.clone().get(),
        };

        let id3 = StateSyncArtifactId {
            height: height(3),
            hash: hash3.clone().get(),
        };

        let state = src_state_manager.get_latest_state().take();

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // the dst state manager is not requested to download any state.
            assert!(dst_state_sync.maybe_start_state_sync(&id1).is_none());

            // Request fetching of state @1.
            dst_state_manager.fetch_state(height(1), hash1, Height::new(499));

            // the dst state manager just reaches state height @1.
            let (_height, mut dst_state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut dst_state, canister_test_id(101));
            dst_state_manager.commit_and_certify(
                dst_state,
                height(1),
                CertificationScope::Full,
                None,
            );
            wait_for_checkpoint(&*dst_state_manager, height(1));

            // the dst state manager won't fetch any state which it has reached.
            assert!(dst_state_sync.maybe_start_state_sync(&id1).is_none());

            // Request fetching of state @2.
            dst_state_manager.fetch_state(height(2), hash2.clone(), Height::new(499));

            // the dst state manager won't fetch the state with a mismatched hash.
            let malicious_id = StateSyncArtifactId {
                height: height(2),
                hash: CryptoHash(vec![0; 32]),
            };
            assert!(
                dst_state_sync
                    .maybe_start_state_sync(&malicious_id)
                    .is_none()
            );

            // the dst state manager won't fetch the state with a mismatched height.
            let malicious_id = StateSyncArtifactId {
                height: height(100),
                hash: hash2.get(),
            };
            assert!(
                dst_state_sync
                    .maybe_start_state_sync(&malicious_id)
                    .is_none()
            );

            // starting state sync for state @2 should succeed with the correct artifact ID.
            let chunkable = dst_state_sync
                .maybe_start_state_sync(&id2)
                .expect("failed to start state sync");

            // a new state sync won't be started if there is already an ongoing one no matter whether they are in the same height or not.
            assert!(dst_state_sync.maybe_start_state_sync(&id2).is_none());

            // Request fetching of state @3.
            dst_state_manager.fetch_state(height(3), hash3, Height::new(499));
            // a new state sync won't be started if there is already an ongoing one no matter whether they are in the same height or not.
            assert!(dst_state_sync.maybe_start_state_sync(&id3).is_none());

            // When `EXTRA_CHECKPOINTS_TO_KEEP` is set as 0, we should cancel an ongoing state sync if requested to fetch a newer state.
            assert!(dst_state_sync.cancel_if_running(&id2));
            drop(chunkable);

            // starting state sync for state @3 should succeed after the old one is cancelled.
            let mut chunkable = dst_state_sync
                .maybe_start_state_sync(&id3)
                .expect("failed to start state sync");
            // The dst state manager has not reached the state @3 yet. It is not requested to fetch a newer state either.
            // We should not cancel this ongoing state sync for state @3.
            assert!(!dst_state_sync.cancel_if_running(&id3));

            let msg = src_state_sync
                .get(&id3)
                .expect("failed to get state sync messages");

            let omit: HashSet<ChunkId> =
                maplit::hashset! {ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};
            let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
            assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");
            // The state sync is not finished yet. We should not cancel this ongoing state sync for state @3.
            assert!(!dst_state_sync.cancel_if_running(&id3));

            pipe_state_sync(msg, chunkable);
            let recovered_state = dst_state_manager
                .get_state_at(height(3))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(3), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);

            let mut tip = dst_state_manager.take_tip().1;
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata
                .prev_state_hash
                .clone_from(&state.metadata.prev_state_hash);
            assert_eq!(*state.as_ref(), tip);
            assert_eq!(
                vec![height(1), height(3)],
                heights_to_certify(&*dst_state_manager)
            );

            assert_error_counters(dst_metrics);
            assert_no_remaining_chunks(dst_metrics);
        })
    })
}

#[test]
fn state_sync_message_returns_none_for_invalid_chunk_requests() {
    state_manager_test_with_state_sync(|_, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        let normal_chunk_id_end_exclusive = msg.manifest.chunk_table.len() as u32 + 1;

        let file_group_chunk_id_end_exclusive =
            FILE_GROUP_CHUNK_ID_OFFSET + msg.state_sync_file_group.len() as u32;

        let sub_manifest_chunk_id_end_exclusive =
            MANIFEST_CHUNK_ID_OFFSET + msg.meta_manifest.sub_manifest_hashes.len() as u32;

        let src = Box::new(msg);

        assert!(src.clone().get_chunk(META_MANIFEST_CHUNK).is_some());

        for i in 1..normal_chunk_id_end_exclusive {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_some());
        }

        assert!(normal_chunk_id_end_exclusive <= FILE_GROUP_CHUNK_ID_OFFSET);
        for i in (normal_chunk_id_end_exclusive..FILE_GROUP_CHUNK_ID_OFFSET).step_by(100) {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_none());
        }

        for i in FILE_GROUP_CHUNK_ID_OFFSET..file_group_chunk_id_end_exclusive {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_some());
        }

        assert!(file_group_chunk_id_end_exclusive <= MANIFEST_CHUNK_ID_OFFSET);
        for i in (file_group_chunk_id_end_exclusive..MANIFEST_CHUNK_ID_OFFSET).step_by(100) {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_none());
        }

        for i in MANIFEST_CHUNK_ID_OFFSET..sub_manifest_chunk_id_end_exclusive {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_some());
        }

        for i in (sub_manifest_chunk_id_end_exclusive..=u32::MAX).step_by(100) {
            assert!(src.clone().get_chunk(ChunkId::new(i)).is_none());
        }
    })
}

#[test]
fn can_state_sync_from_cache() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        insert_dummy_canister(&mut state, canister_test_id(200));

        // Modify the first canister to ensure that its chunks are not identical to the
        // other canister
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state.system_state.add_canister_change(
            Time::from_nanos_since_unix_epoch(42),
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::canister_creation(vec![user_test_id(42).get()], None),
        );
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .stable_memory
            .page_map
            .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(0), &[2u8; PAGE_SIZE])]);

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash1 = wait_for_checkpoint(&*src_state_manager, height(1));
        let id1 = StateSyncArtifactId {
            height: height(1),
            hash: hash1.get_ref().clone(),
        };

        let msg1 = src_state_sync
            .get(&id1)
            .expect("failed to get state sync messages");

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash2 = wait_for_checkpoint(&*src_state_manager, height(2));
        let id2 = StateSyncArtifactId {
            height: height(2),
            hash: hash2.get_ref().clone(),
        };
        let state2 = src_state_manager.get_latest_state().take();
        let msg2 = src_state_sync
            .get(&id2)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Not all chunk ids to be omitted will work for the purpose of this test
            // They have to be (1) not included in a file group chunk and (2) not identical
            // to another chunk that is not omitted.
            //
            // Here we choose the `system_metadata.pbuf` because it is never empty and unlikely to be identical to others.
            // `system_metadata.pbuf` is also the only file that changes between checkpoints.
            //   file idx  |  file size | chunk idx |                         path
            // ------------+------------+---------- +------------------------------------------------------
            //           0 |        259 |     0     | canister_states/00000000000000640101/canister.pbuf
            //           1 |         18 |     1     | canister_states/00000000000000640101/software.wasm
            //           2 |       4096 |     2     | canister_states/00000000000000640101/stable_memory.bin
            //           3 |       4096 |     3     | canister_states/00000000000000640101/vmemory_0.bin
            //           4 |          0 |    N/A    | canister_states/00000000000000640101/wasm_chunk_store.bin
            //           5 |        221 |     4     | canister_states/00000000000000c80101/canister.pbuf
            //           6 |         18 |     5     | canister_states/00000000000000c80101/software.wasm
            //           7 |          0 |    N/A    | canister_states/00000000000000c80101/stable_memory.bin
            //           8 |          0 |    N/A    | canister_states/00000000000000c80101/vmemory_0.bin
            //           9 |          0 |    N/A    | canister_states/00000000000000c80101/wasm_chunk_store.bin
            //          10 |         86 |     6     | system_metadata.pbuf
            //
            // Given the current state layout, the chunk for `system_metadata.pbuf` is the last one in the chunk table.
            // If there are changes to the state layout and it changes the position of `system_metadata.pbuf` in the chunk table,
            // the assertion below will panic and we need to adjust the selected chunk id accordingly for this test.
            let chunk_table_idx_to_omit = msg1.manifest.chunk_table.len() - 1;
            let chunk_id_to_omit = ChunkId::new(chunk_table_idx_to_omit as u32 + 1);
            let file_table_idx_to_omit =
                msg1.manifest.chunk_table[chunk_table_idx_to_omit].file_index as usize;
            let file_path = &msg1.manifest.file_table[file_table_idx_to_omit].relative_path;
            // Make sure the chunk to omit is from file `system_metadata.pbuf`.
            assert!(file_path.ends_with(SYSTEM_METADATA_FILE));

            let omit: HashSet<ChunkId> =
                maplit::hashset! {chunk_id_to_omit, ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};

            // First state sync is destroyed before completion
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id1);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks, and then ask for all chunks afterwards,
                // but never receive the chunk for `system_metadata.pbuf` and FILE_GROUP_CHUNK_ID_OFFSET
                let completion = pipe_partial_state_sync(&msg1, &mut *chunkable, &omit, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");
            }
            assert_no_remaining_chunks(dst_metrics);
            // Second state sync continues from first state and successfully finishes
            {
                // Compared to the checkpoint at height 1, the only different file in checkpoint at height 2 is `system_metadata.pbuf`.
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id2);

                let result = pipe_meta_manifest(&msg2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                let file_group_chunks: HashSet<ChunkId> = msg2
                    .state_sync_file_group
                    .keys()
                    .copied()
                    .map(ChunkId::from)
                    .collect();

                let fetch_chunks: HashSet<ChunkId> =
                    omit.union(&file_group_chunks).copied().collect();

                // Only the chunks not fetched in the first state sync plus chunks of the file group should still be requested
                assert_eq!(fetch_chunks, chunkable.chunks_to_download().collect());

                // Download chunk 1
                pipe_state_sync(msg2.clone(), chunkable);

                let recovered_state = dst_state_manager
                    .get_state_at(height(2))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(2), dst_state_manager.latest_state_height());
                assert_eq!(state2, recovered_state);
                assert_eq!(
                    *state2.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(vec![height(2)], heights_to_certify(&*dst_state_manager));
            }
            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_from_cache_alone() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        insert_dummy_canister(&mut state, canister_test_id(200));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get_ref().clone(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        let state = src_state_manager.get_latest_state().take();
        assert_error_counters(src_metrics);
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // In the first state sync, we omit the `software.wasm` of the first canister, which is the same as the other one.
            // The state sync won't complete because all the chunks have to be fetched from scratch.
            //   file idx  |  file size | chunk idx |                         path
            // ------------+------------+---------- +------------------------------------------------------
            //           0 |        331 |     0     | canister_states/00000000000000640101/canister.pbuf
            //           1 |         18 |     1     | canister_states/00000000000000640101/software.wasm
            //           2 |          0 |    N/A    | canister_states/00000000000000640101/stable_memory.bin
            //           3 |          0 |    N/A    | canister_states/00000000000000640101/vmemory_0.bin
            //           4 |          0 |    N/A    | canister_states/00000000000000640101/wasm_chunk_store.bin
            //           5 |        331 |     2     | canister_states/00000000000000c80101/canister.pbuf
            //           6 |         18 |     3     | canister_states/00000000000000c80101/software.wasm
            //           7 |          0 |    N/A    | canister_states/00000000000000c80101/stable_memory.bin
            //           8 |          0 |    N/A    | canister_states/00000000000000c80101/vmemory_0.bin
            //           9 |          0 |    N/A    | canister_states/00000000000000c80101/wasm_chunk_store.bin
            //          10 |         97 |     4     | system_metadata.pbuf
            // Given the current state layout, the chunk for `software.wasm` of the first canister has the index 1.
            // If there are changes to the state layout that affect the chunk's position in the chunk table,
            // the assertion below will panic and we need to adjust the selected chunk id accordingly for this test.
            let chunk_table_idx_to_omit = 1;
            let chunk_id_to_omit = ChunkId::new(chunk_table_idx_to_omit as u32 + 1);
            let file_table_idx_to_omit =
                msg.manifest.chunk_table[chunk_table_idx_to_omit].file_index as usize;
            let file_path = &msg.manifest.file_table[file_table_idx_to_omit].relative_path;
            // Make sure the chunk to omit is from file `software.wasm`.
            assert!(file_path.ends_with(WASM_FILE));

            let omit: HashSet<ChunkId> = maplit::hashset! {chunk_id_to_omit};

            // First state sync is destroyed before completion
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks, and then ask for all chunks afterwards,
                // but never receive the chunk for `software.wasm` of the first canister
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync",);
            }
            assert_no_remaining_chunks(dst_metrics);
            // Second state sync of the same state continues from the cache and successfully finishes
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                // The meta-manifest and manifest are enough to complete the sync
                // This is because the omitted file `canister_states/00000000000000640101/software.wasm` in the first state sync
                // is the same as the other one. As a result, it will be copied and does not need to be fetched.
                let _res = pipe_meta_manifest(&msg, &mut *chunkable, false);
                let is_finished = pipe_manifest(&msg, &mut *chunkable, false);
                assert_matches!(is_finished, Ok(true), "State sync should have completed.");

                let recovered_state = dst_state_manager
                    .get_state_at(height(1))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(1), dst_state_manager.latest_state_height());
                assert_eq!(state, recovered_state);
                assert_eq!(
                    *state.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(vec![height(1)], heights_to_certify(&*dst_state_manager));
            }
            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn copied_chunks_from_file_group_can_be_skipped_when_applying() {
    use std::os::unix::fs::MetadataExt;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    /// Snapshot of file metadata fields that are useful for checking if a file has been touched.
    /// These fields include device and inode (to uniquely identify the file), size, and timestamps for modification and change.
    struct FileMetadataSnapshot {
        dev: u64,
        ino: u64,
        size: u64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
    }
    fn get_file_metadata_snapshot(path: &Path) -> FileMetadataSnapshot {
        let metadata = std::fs::metadata(path).unwrap();
        FileMetadataSnapshot {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        insert_dummy_canister(&mut state, canister_test_id(200));

        // Modify the first canister to ensure that its chunks are not identical to the
        // other canister
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state.system_state.add_canister_change(
            Time::from_nanos_since_unix_epoch(42),
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::canister_creation(vec![user_test_id(42).get()], None),
        );
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .stable_memory
            .page_map
            .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(0), &[2u8; PAGE_SIZE])]);

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get_ref().clone(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");
        let state = src_state_manager.get_latest_state().take();

        assert_error_counters(src_metrics);
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Not all chunk ids to be omitted will work for the purpose of this test
            // They have to be (1) not included in a file group chunk and (2) not identical
            // to another chunk that is not omitted.
            //
            // Here we choose the `system_metadata.pbuf` because it is never empty and unlikely to be identical to others.
            // Given the current state layout, the chunk for `system_metadata.pbuf` is the last one in the chunk table.
            // If there are changes to the state layout and it changes the position of `system_metadata.pbuf` in the chunk table,
            // the assertion below will panic and we need to adjust the selected chunk id accordingly for this test.
            let chunk_table_idx_to_omit = msg.manifest.chunk_table.len() - 1;
            let chunk_id_to_omit = ChunkId::new(chunk_table_idx_to_omit as u32 + 1);
            let file_table_idx_to_omit =
                msg.manifest.chunk_table[chunk_table_idx_to_omit].file_index as usize;
            let file_path = &msg.manifest.file_table[file_table_idx_to_omit].relative_path;
            // Make sure the chunk to omit is from file `system_metadata.pbuf`.
            assert!(file_path.ends_with(SYSTEM_METADATA_FILE));

            let omit1: HashSet<ChunkId> = maplit::hashset! {chunk_id_to_omit};
            // Drop the first state sync during the loading phase,
            // mimicking a scenario where P2P loses all peer connections before completion.
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks, and then ask for all chunks afterwards,
                // but never receive the chunk for `system_metadata.pbuf`
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit1, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");
            }
            assert_no_remaining_chunks(dst_metrics);

            // The second state sync targets the same state at height 1 based on the cache from the first state sync.
            // Here, canister.pbuf files are both copied and fetched via file group chunks. However, we don't fetch any chunks.
            // This is to test that the remaining_chunks metric is correctly updated to 0 during drop.
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
            }
            assert_no_remaining_chunks(dst_metrics);

            // The third state sync targets the same state at height 1 based on the cache from the second state sync.
            // Here, canister.pbuf files are both copied and fetched via file group chunks.
            // This is to test that when applying file group chunks, any already-copied individual chunks are properly skipped.
            // We verify this behavior by asserting that the remaining chunks metric never becomes negative.
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
                let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                let file_group_chunks: HashSet<ChunkId> = msg
                    .state_sync_file_group
                    .keys()
                    .copied()
                    .map(ChunkId::from)
                    .collect();

                let fetch_chunks: HashSet<ChunkId> =
                    omit1.union(&file_group_chunks).copied().collect();
                // Only the chunks not fetched in the previous state syncs plus chunks of the file group should still be requested
                assert_eq!(fetch_chunks, chunkable.chunks_to_download().collect());

                // Only finish the copy phase by omitting the chunks to fetch
                let omit2: HashSet<ChunkId> = fetch_chunks;
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit2, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");

                let state_sync_root = dst_state_manager
                    .state_layout()
                    .state_sync_scratchpad(height(1));

                let canister_pbuf_files: Vec<_> = msg
                    .manifest
                    .file_table
                    .iter()
                    .filter(|file| file.relative_path.ends_with(CANISTER_FILE))
                    .map(|file| state_sync_root.join(&file.relative_path))
                    .collect();
                assert!(!canister_pbuf_files.is_empty());

                // All canister.pbuf files should be already copied to the scratchpad and we take a snapshot of the metadata.
                let original_metadata_snapshots: Vec<_> = canister_pbuf_files
                    .iter()
                    .map(|file| get_file_metadata_snapshot(file))
                    .collect();

                // Download the file group chunks
                let omit3: HashSet<ChunkId> = maplit::hashset! {chunk_id_to_omit};
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit3, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");

                // Assert that all canister.pbuf files are not touched.
                let new_metadata_snapshots: Vec<_> = canister_pbuf_files
                    .iter()
                    .map(|file| get_file_metadata_snapshot(file))
                    .collect();
                assert_eq!(original_metadata_snapshots, new_metadata_snapshots);

                pipe_state_sync(msg.clone(), chunkable);
                // Remaining chunks should be 0 before dropping the `IncompleteState` object.
                assert_no_remaining_chunks(dst_metrics);

                let recovered_state = dst_state_manager
                    .get_state_at(height(1))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(1), dst_state_manager.latest_state_height());
                assert_eq!(state, recovered_state);
                assert_eq!(
                    *state.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(vec![height(1)], heights_to_certify(&*dst_state_manager));
            }

            // After dropping the `IncompleteState` object, the remaining chunks should also be 0.
            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn state_sync_can_hardlink_files_from_checkpoint_or_cache_to_scratchpad() {
    use ic_state_layout::RwPolicy;
    use std::os::unix::fs::MetadataExt;

    fn assert_files_are_hardlinked_and_readonly(path1: &Path, path2: &Path) {
        let metadata1 = std::fs::metadata(path1).unwrap();
        let metadata2 = std::fs::metadata(path2).unwrap();
        assert!(metadata1.permissions().readonly());
        assert!(metadata2.permissions().readonly());
        assert_eq!(metadata1.dev(), metadata2.dev());
        assert_eq!(metadata1.ino(), metadata2.ino());
    }

    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        let canister_state = state.canister_state_mut(&canister_test_id(200)).unwrap();
        canister_state.system_state.add_canister_change(
            Time::from_nanos_since_unix_epoch(42),
            CanisterChangeOrigin::from_user(user_test_id(42).get()),
            CanisterChangeDetails::canister_creation(vec![user_test_id(42).get()], None),
        );
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .stable_memory
            .page_map
            .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(0), &[2u8; PAGE_SIZE])]);

        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));
        let id_2 = StateSyncArtifactId {
            height: height(2),
            hash: hash_2.get(),
        };
        let msg_2 = src_state_sync
            .get(&id_2)
            .expect("failed to get state sync message");

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        let hash_3 = wait_for_checkpoint(&*src_state_manager, height(3));
        let id_3 = StateSyncArtifactId {
            height: height(3),
            hash: hash_3.get(),
        };
        let msg_3 = src_state_sync
            .get(&id_3)
            .expect("failed to get state sync message");
        let src_state = src_state_manager.get_latest_state().take();

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            wait_for_checkpoint(&*dst_state_manager, height(1));

            // Case 1: Hardlink from readonly file in checkpoint,
            // for example, wasm file of the first canister.
            {
                let mut chunkable = set_fetch_state_and_start_state_sync(
                    &dst_state_manager,
                    &dst_state_sync,
                    &id_2,
                );

                let wasm_file_in_checkpoint = dst_state_manager
                    .state_layout()
                    .checkpoint_verified(height(1))
                    .unwrap()
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();
                assert!(
                    wasm_file_in_checkpoint
                        .metadata()
                        .unwrap()
                        .permissions()
                        .readonly()
                );

                let result = pipe_meta_manifest(&msg_2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg_2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                let state_sync_root = dst_state_manager
                    .state_layout()
                    .state_sync_scratchpad(height(2));

                let scratchpad_layout =
                    CheckpointLayout::<RwPolicy<()>>::new_untracked(state_sync_root, height(2))
                        .expect("failed to create checkpoint layout");

                let wasm_file_in_scratchpad = scratchpad_layout
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();

                assert_files_are_hardlinked_and_readonly(
                    &wasm_file_in_checkpoint,
                    &wasm_file_in_scratchpad,
                );
            }
            assert_no_remaining_chunks(dst_metrics);

            // Case 2: Hardlink from readonly file in cache at the same height as the scratchpad,
            // for example, wasm file of the first canister.
            {
                let mut chunkable = set_fetch_state_and_start_state_sync(
                    &dst_state_manager,
                    &dst_state_sync,
                    &id_2,
                );

                let cache_root = dst_state_manager
                    .state_layout()
                    .state_sync_cache(height(2))
                    .expect("failed to get directory for state sync cache");

                let cache_layout =
                    CheckpointLayout::<RwPolicy<()>>::new_untracked(cache_root, height(2))
                        .expect("failed to create cache layout");

                let wasm_file_in_cache = cache_layout
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();
                // assert the wasm file is readonly
                assert!(
                    wasm_file_in_cache
                        .metadata()
                        .unwrap()
                        .permissions()
                        .readonly()
                );

                let result = pipe_meta_manifest(&msg_2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg_2, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                let scratchpad_root = dst_state_manager
                    .state_layout()
                    .state_sync_scratchpad(height(2));

                let scratchpad_layout =
                    CheckpointLayout::<RwPolicy<()>>::new_untracked(scratchpad_root, height(2))
                        .expect("failed to create scratchpad layout");

                let wasm_file_in_scratchpad = scratchpad_layout
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();

                assert_files_are_hardlinked_and_readonly(
                    &wasm_file_in_cache,
                    &wasm_file_in_scratchpad,
                );

                // Download some chunks but intentionally do not complete the state sync.
                // Skip the `system_metadata.pbuf` chunk, as it is always non-empty, rarely identical to other chunks, and changes between checkpoints.
                // Given the current state layout, the chunk for `system_metadata.pbuf` is the last one in the chunk table.
                let chunk_table_idx_to_omit = msg_2.manifest.chunk_table.len() - 1;
                let chunk_id_to_omit = ChunkId::new(chunk_table_idx_to_omit as u32 + 1);
                let file_table_idx_to_omit =
                    msg_2.manifest.chunk_table[chunk_table_idx_to_omit].file_index as usize;
                let file_path = &msg_2.manifest.file_table[file_table_idx_to_omit].relative_path;
                // Make sure the chunk to omit is from file `system_metadata.pbuf`.
                assert!(file_path.ends_with(SYSTEM_METADATA_FILE));

                let omit = maplit::hashset! {chunk_id_to_omit};
                let completion = pipe_partial_state_sync(&msg_2, &mut *chunkable, &omit, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");
            }
            assert_no_remaining_chunks(dst_metrics);

            {
                let mut chunkable = set_fetch_state_and_start_state_sync(
                    &dst_state_manager,
                    &dst_state_sync,
                    &id_3,
                );

                let cache_root = dst_state_manager
                    .state_layout()
                    .state_sync_cache(height(2))
                    .expect("failed to get directory for state sync cache");

                let cache_layout =
                    CheckpointLayout::<RwPolicy<()>>::new_untracked(cache_root, height(2))
                        .expect("failed to create cache layout");

                let wasm_file_in_cache = cache_layout
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();
                // assert the wasm file is readonly
                assert!(
                    wasm_file_in_cache
                        .metadata()
                        .unwrap()
                        .permissions()
                        .readonly()
                );

                let stable_memory_overlay_file_in_cache = cache_layout
                    .canister(&canister_test_id(200))
                    .unwrap()
                    .stable_memory()
                    .existing_overlays()
                    .unwrap()
                    .remove(0);
                // assert the stable memory overlay file is writable as it was downloaded in the previous state sync
                assert!(
                    !stable_memory_overlay_file_in_cache
                        .metadata()
                        .unwrap()
                        .permissions()
                        .readonly()
                );

                let result = pipe_meta_manifest(&msg_3, &mut *chunkable, false);
                assert_matches!(result, Ok(false));
                let result = pipe_manifest(&msg_3, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                // Case 3(a): Hardlink from readonly file in cache at previous height,
                // for example, wasm file of the first canister.
                let scratchpad_root = dst_state_manager
                    .state_layout()
                    .state_sync_scratchpad(height(3));

                let scratchpad_layout =
                    CheckpointLayout::<RwPolicy<()>>::new_untracked(scratchpad_root, height(3))
                        .expect("failed to create scratchpad layout");

                let wasm_file_in_scratchpad = scratchpad_layout
                    .canister(&canister_test_id(100))
                    .unwrap()
                    .wasm()
                    .raw_path()
                    .to_path_buf();

                assert_files_are_hardlinked_and_readonly(
                    &wasm_file_in_cache,
                    &wasm_file_in_scratchpad,
                );

                // Case 3(b): Hardlink from writable file in cache at previous height,,
                // for example, stable memory overlay file of the second canister.
                let stable_memory_overlay_file_in_scratchpad = scratchpad_layout
                    .canister(&canister_test_id(200))
                    .unwrap()
                    .stable_memory()
                    .existing_overlays()
                    .unwrap()
                    .remove(0);

                assert_files_are_hardlinked_and_readonly(
                    &stable_memory_overlay_file_in_cache,
                    &stable_memory_overlay_file_in_scratchpad,
                );

                pipe_state_sync(msg_3, chunkable);

                let recovered_state = dst_state_manager
                    .get_state_at(height(3))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(3), dst_state_manager.latest_state_height());
                assert_eq!(src_state, recovered_state);
                assert_eq!(
                    *src_state.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(
                    vec![height(1), height(3)],
                    heights_to_certify(&*dst_state_manager)
                );
            }
            assert_no_remaining_chunks(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_after_aborting_in_prep_phase() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();

        // Insert large number of canisters so that the encoded manifest is larger than 1 MiB.
        let num_canisters = 5000;
        for id in 100..(100 + num_canisters) {
            insert_dummy_canister(&mut state, canister_test_id(id));
        }

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get_ref().clone(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        let meta_manifest = build_meta_manifest(&msg.manifest);
        assert!(
            meta_manifest.sub_manifest_hashes.len() >= 2,
            "The test should run with the manifest chunked in multiple pieces."
        );

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Omit the second piece of the manifest.
            let omit: HashSet<ChunkId> =
                maplit::hashset! {ChunkId::new(MANIFEST_CHUNK_ID_OFFSET + 1)};

            // First state sync is destroyed when fetching the manifest chunks in the Prep phase
            {
                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks but never receive chunk(MANIFEST_CHUNK_ID_OFFSET + 1).
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");
            }
            assert_no_remaining_chunks(dst_metrics);
            // Second state sync starts from scratch and successfully finishes
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(2),
                    hash: hash.get_ref().clone(),
                };

                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                // Chunks in the Prep phase are not involved in the cache mechanism. Therefore, all the manifest chunks have to requested again.
                let manifest_chunks: HashSet<ChunkId> = (MANIFEST_CHUNK_ID_OFFSET
                    ..(MANIFEST_CHUNK_ID_OFFSET + meta_manifest.sub_manifest_hashes.len() as u32))
                    .map(ChunkId::from)
                    .collect();
                assert_eq!(manifest_chunks, chunkable.chunks_to_download().collect());

                let result = pipe_manifest(&msg, &mut *chunkable, false);
                assert_matches!(result, Ok(false));

                pipe_state_sync(msg.clone(), chunkable);

                let recovered_state = dst_state_manager
                    .get_state_at(height(2))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(2), dst_state_manager.latest_state_height());
                assert_eq!(state, recovered_state);
                assert_eq!(
                    *state.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(vec![height(2)], heights_to_certify(&*dst_state_manager));
            }
            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn state_sync_can_reject_invalid_chunks() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();

        // Insert large number of canisters so that the encoded manifest is larger than 1 MiB.
        let num_canisters = 5000;
        for id in 100..(100 + num_canisters) {
            insert_dummy_canister(&mut state, canister_test_id(id));
        }

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        let meta_manifest = build_meta_manifest(&msg.manifest);
        assert!(
            meta_manifest.sub_manifest_hashes.len() >= 2,
            "The test should run with the manifest chunked in multiple pieces."
        );

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Provide bad meta-manifest to dst
            let mut chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            let result = pipe_meta_manifest(&msg, &mut *chunkable, true);
            assert_matches!(
                result,
                Err(StateSyncErrorCode::MetaManifestVerificationFailed)
            );

            // Provide correct meta-manifest to dst
            let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
            assert_matches!(result, Ok(false));

            // Provide bad sub-manifests to dst
            // Each time, alter the chunk in the middle of remaining chunks for the current phase. The first half of chunks should be added correctly in this way.
            loop {
                let remaining_chunks_before = chunkable.chunks_to_download().count() as i32;
                let result = pipe_manifest(&msg, &mut *chunkable, true);
                assert_matches!(result, Err(StateSyncErrorCode::ManifestVerificationFailed));
                let remaining_chunks_after = chunkable.chunks_to_download().count() as i32;
                let added_chunks = remaining_chunks_before - remaining_chunks_after;
                // Assert that half of the remaining chunks are added correctly each time.
                assert_eq!(added_chunks, remaining_chunks_before / 2);
                // If no more chunks are added, break out of the loop.
                if added_chunks == 0 {
                    // Assert that there should be only 1 chunk left in this case.
                    assert_eq!(remaining_chunks_after, 1);
                    break;
                }
            }

            // Provide correct sub-manifests to dst
            let result = pipe_manifest(&msg, &mut *chunkable, false);
            assert_matches!(result, Ok(false));

            // Provide bad chunks to dst
            // Each time, alter the chunk in the middle of remaining chunks for the current phase. The first half of chunks should be added correctly in this way.
            loop {
                let remaining_chunks_before = chunkable.chunks_to_download().count() as i32;
                let result =
                    pipe_partial_state_sync(&msg, &mut *chunkable, &Default::default(), true);
                assert_matches!(
                    result,
                    Err(StateSyncErrorCode::OtherChunkVerificationFailed)
                );
                let remaining_chunks_after = chunkable.chunks_to_download().count() as i32;
                let added_chunks = remaining_chunks_before - remaining_chunks_after;
                // Assert that half of the remaining chunks are added correctly each time.
                assert_eq!(added_chunks, remaining_chunks_before / 2);
                // If no more chunks are added, break out of the loop.
                if added_chunks == 0 {
                    // Assert that there should be only 1 chunk left in this case.
                    assert_eq!(remaining_chunks_after, 1);
                    break;
                }
            }

            // Provide correct chunks to dst
            pipe_state_sync(msg.clone(), chunkable);

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);
            assert_eq!(
                *state.as_ref(),
                *dst_state_manager.get_latest_state().take()
            );
            assert_eq!(vec![height(1)], heights_to_certify(&*dst_state_manager));

            assert_error_counters(dst_metrics);
            assert_no_remaining_chunks(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_into_existing_checkpoint() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(
            state.clone(),
            height(1),
            CertificationScope::Full,
            None,
        );
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(
                state.clone(),
                height(1),
                CertificationScope::Full,
                None,
            );

            pipe_state_sync(msg, chunkable);

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_group_small_files_in_state_sync() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        let num_canisters = 200;
        for id in 100..(100 + num_canisters) {
            insert_canister_with_many_controllers(&mut state, canister_test_id(id), 400);
        }

        // With 20,000 controllers' Principal ID serialized to the 'canister.pbuf' file,
        // the size will be larger than the file grouping limit and thus it will not be grouped.
        insert_canister_with_many_controllers(
            &mut state,
            canister_test_id(100 + num_canisters),
            20_000,
        );

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        let num_files: usize = msg
            .state_sync_file_group
            .iter()
            .map(|(_, indices)| indices.len())
            .sum();

        // `canister.pbuf` files of all the canisters should be grouped, except for the one with 20,000 controllers.
        assert_eq!(num_files, num_canisters as usize);

        // In this test, each canister has a `canister.pubf` file of about 6.0 KiB in the checkpoint.
        // Therefore, it needs more than one 1-MiB chunk to group these files.
        //
        // Note that the file size estimation in this test is based on the current serialization mechanism
        // and if the assertion does not hold, we will need to revisit this test and check the file size.
        let num_file_group_chunks = msg.state_sync_file_group.len();
        assert!(num_file_group_chunks > 1);

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let mut chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
            assert_matches!(result, Ok(false));

            let result = pipe_manifest(&msg, &mut *chunkable, false);
            assert_matches!(result, Ok(false));

            assert!(
                chunkable
                    .chunks_to_download()
                    .any(|chunk_id| chunk_id.get() == FILE_GROUP_CHUNK_ID_OFFSET)
            );

            pipe_state_sync(msg, chunkable);

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);

            assert_error_counters(dst_metrics);
            assert_no_remaining_chunks(dst_metrics);
        })
    })
}

#[test]
fn can_commit_after_prev_state_is_gone() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut tip) = src_state_manager.take_tip();
        insert_dummy_canister(&mut tip, canister_test_id(100));
        src_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata, None);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(2), CertificationScope::Metadata, None);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(3), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(3));
        let id = StateSyncArtifactId {
            height: height(3),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut tip) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut tip, canister_test_id(100));
            dst_state_manager.commit_and_certify(
                tip,
                height(1),
                CertificationScope::Metadata,
                None,
            );

            let (_height, tip) = dst_state_manager.take_tip();

            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            pipe_state_sync(msg, chunkable);

            dst_state_manager.remove_states_below(height(2));
            dst_state_manager.flush_deallocation_channel();

            assert_eq!(height(3), dst_state_manager.latest_state_height());
            assert_eq!(
                dst_state_manager.get_state_at(height(1)),
                Err(StateManagerError::StateRemoved(height(1)))
            );

            // Check that we can still commit the old tip.
            dst_state_manager.commit_and_certify(
                tip,
                height(2),
                CertificationScope::Metadata,
                None,
            );

            // Check that after committing an old state, the state manager can still get the right tip and commit it.
            let (tip_height, tip) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            dst_state_manager.commit_and_certify(
                tip,
                height(4),
                CertificationScope::Metadata,
                None,
            );

            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_commit_without_prev_hash_mismatch_after_taking_tip_at_the_synced_height() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut tip) = src_state_manager.take_tip();
        insert_dummy_canister(&mut tip, canister_test_id(100));
        src_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata, None);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(2), CertificationScope::Metadata, None);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(3), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(3));
        let id = StateSyncArtifactId {
            height: height(3),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut tip) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut tip, canister_test_id(100));
            dst_state_manager.commit_and_certify(
                tip,
                height(1),
                CertificationScope::Metadata,
                None,
            );

            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            pipe_state_sync(msg, chunkable);

            assert_eq!(height(3), dst_state_manager.latest_state_height());
            let (tip_height, tip) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            // Check that we can still commit the new tip at the synced checkpoint height without prev state hash mismatch.
            dst_state_manager.commit_and_certify(
                tip,
                height(4),
                CertificationScope::Metadata,
                None,
            );

            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_based_on_old_checkpoint() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash.get(),
        };
        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            wait_for_checkpoint(&*dst_state_manager, height(1));

            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            pipe_state_sync(msg, chunkable);

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);

            let mut tip = dst_state_manager.take_tip().1;
            let state = expected_state.take();
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata
                .prev_state_hash
                .clone_from(&state.metadata.prev_state_hash);
            assert_eq!(tip, *state.as_ref());

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    });
}

#[test]
fn state_sync_doesnt_load_already_existing_cp() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };
        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            dst_state_manager.take_tip();

            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            let state_layout = dst_state_manager.state_layout();
            let cp1_path = state_layout
                .raw_path()
                .join("checkpoints")
                .join("0000000000000001");
            assert!(state_layout.checkpoint_in_verification(height(1)).is_err());
            std::fs::create_dir(&cp1_path).unwrap();
            assert!(state_layout.checkpoint_in_verification(height(1)).is_ok());
            std::fs::create_dir(cp1_path.join("garbage")).unwrap(); // rust successfully renames a directory into another if destination is empty

            pipe_state_sync(msg, chunkable);

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    });
}

#[test]
fn can_recover_from_corruption_on_state_sync() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};

    let pages_per_chunk = DEFAULT_CHUNK_SIZE as u64 / PAGE_SIZE as u64;
    assert_eq!(DEFAULT_CHUNK_SIZE as usize % PAGE_SIZE, 0);

    let populate_original_state = |state: &mut ReplicatedState| {
        insert_dummy_canister(state, canister_test_id(90));
        insert_dummy_canister(state, canister_test_id(100));
        insert_dummy_canister(state, canister_test_id(110));

        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);

        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state
            .execution_state
            .as_mut()
            .unwrap()
            .stable_memory
            .page_map
            .update(&[(PageIndex::new(0), &[255u8; PAGE_SIZE])]);
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[100u8; PAGE_SIZE]),
            (PageIndex::new(3000), &[100u8; PAGE_SIZE]),
        ]);

        let canister_state = state.canister_state_mut(&canister_test_id(110)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(0), &[111u8; PAGE_SIZE]),
            (PageIndex::new(pages_per_chunk - 1), &[0; PAGE_SIZE]),
            (PageIndex::new(pages_per_chunk), &[112u8; PAGE_SIZE]),
            (PageIndex::new(2 * pages_per_chunk - 1), &[0; PAGE_SIZE]),
        ]);
    };

    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        // Create initial state with a single canister.
        let (_height, mut state) = src_state_manager.take_tip();
        populate_original_state(&mut state);
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let hash_1 = wait_for_checkpoint(&*src_state_manager, height(1));

        // Create another state with an extra canister.
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));

        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        // Add a new page much further in the file so that the first one could
        // be re-used as a chunk, and so that there are all-zero chunks inbetween.
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(3000), &[2u8; PAGE_SIZE])]);

        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        // Add a new page much further in the file so that the first one could
        // be re-used as a chunk.
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(300), &[3u8; PAGE_SIZE])]);

        // Exchange pages in the canister heap to check applying chunks out of order.
        let canister_state = state.canister_state_mut(&canister_test_id(110)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(0), &[112u8; PAGE_SIZE]),
            (PageIndex::new(pages_per_chunk), &[111u8; PAGE_SIZE]),
        ]);

        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2.get(),
        };
        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, mut dst_state_sync| {
            let (_height, mut state) = dst_state_manager.take_tip();
            populate_original_state(&mut state);
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            let hash_dst_1 = wait_for_checkpoint(&*dst_state_manager, height(1));
            assert_eq!(hash_1, hash_dst_1);

            // Ensure all tip requests are completed before corrupting the checkpoint,
            // otherwise `reset_tip_to` may fail due to writable checkpoint files.
            dst_state_manager.flush_tip_channel();

            // Corrupt some files in the destination checkpoint.
            let state_layout = dst_state_manager.state_layout();
            let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
                state_layout
                    .checkpoint_verified(height(1))
                    .unwrap()
                    .raw_path()
                    .to_path_buf(),
                height(1),
            )
            .unwrap();

            // There are 5 types of ways to trigger corruption recovery:
            //
            //   * The file should be fully copied, but some chunks don't pass validation.
            //
            //   * The file should be fully copied, but it's larger than stated in the
            //     manifest.
            //
            //   * The file should be fully copied, but it's so corrupted that some chunks
            //     are out of range.
            //
            //   * The file should be reused partially, but some chunks don't pass
            //     validation.
            //
            //   * The file should be reused partially, but it's so corrupted that some
            //     chunks are out of range.
            //
            // The code below prepares all 5 types of corruption.

            let canister_90_layout = mutable_cp_layout.canister(&canister_test_id(90)).unwrap();
            let canister_90_memory = canister_90_layout
                .vmemory_0()
                .existing_overlays()
                .unwrap()
                .remove(0);
            make_mutable(&canister_90_memory).unwrap();
            std::fs::write(&canister_90_memory, b"Garbage").unwrap();
            make_readonly(&canister_90_memory).unwrap();

            let canister_90_raw_pb = canister_90_layout.canister().raw_path().to_path_buf();
            make_mutable(&canister_90_raw_pb).unwrap();
            write_all_at(&canister_90_raw_pb, b"Garbage", 0).unwrap();
            make_readonly(&canister_90_raw_pb).unwrap();

            let canister_100_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();

            let canister_100_memory = canister_100_layout
                .vmemory_0()
                .existing_overlays()
                .unwrap()
                .remove(0);
            make_mutable(&canister_100_memory).unwrap();
            write_all_at(&canister_100_memory, &[3u8; PAGE_SIZE], 4).unwrap();
            make_readonly(&canister_100_memory).unwrap();

            let canister_100_stable_memory = canister_100_layout
                .stable_memory()
                .existing_overlays()
                .unwrap()
                .remove(0);
            make_mutable(&canister_100_stable_memory).unwrap();
            write_all_at(
                &canister_100_stable_memory,
                &[3u8; PAGE_SIZE],
                PAGE_SIZE as u64,
            )
            .unwrap();
            make_readonly(&canister_100_stable_memory).unwrap();

            let canister_100_raw_pb = canister_100_layout.canister().raw_path().to_path_buf();
            make_mutable(&canister_100_raw_pb).unwrap();
            std::fs::write(&canister_100_raw_pb, b"Garbage").unwrap();
            make_readonly(&canister_100_raw_pb).unwrap();

            // Force validation during state sync for testing corruption recovery.
            // Normally validation only occurs when base checkpoint height <= started_height
            // (i.e., after state manager restart), but we override this for testing purposes.
            //
            // This test is to verify that the validation logic can detect various types of corruption
            // listed above. Note that we cannot simply trigger validation by restarting the state manager because
            // those types of corruption are not loadable and state manager would crash upon restart.
            //
            // For testing normal validation behavior after restart, see `state_sync_can_handle_corrupted_base_checkpoint_after_restart`
            use ic_state_manager::testing::StateSyncTesting;
            dst_state_sync.set_test_force_validate();

            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            pipe_state_sync(msg, chunkable);

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);

            let mut tip = dst_state_manager.take_tip().1;
            let state = expected_state.take();
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata
                .prev_state_hash
                .clone_from(&state.metadata.prev_state_hash);
            assert_eq!(tip, *state.as_ref());

            assert_no_remaining_chunks(dst_metrics);

            // NOTE: since we are forcing validation on a non-restarted state manager,
            // we expect critical errors when corrupted chunks are detected
            // that wouldn't normally be validated.
            assert_ne!(0, count_critical_errors(dst_metrics));
        })
    });
}

#[test]
fn state_sync_can_handle_corrupted_base_checkpoint_after_restart() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    use std::panic::{self, AssertUnwindSafe};

    let populate_original_state = |state: &mut ReplicatedState| {
        insert_dummy_canister(state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        for i in 0..10000 {
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(i), &[99u8; PAGE_SIZE])]);
        }
    };

    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        use std::os::unix::fs::FileExt;
        let (_height, mut state) = src_state_manager.take_tip();

        populate_original_state(&mut state);

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash_1 = wait_for_checkpoint(&*src_state_manager, height(1));

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));

        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2.get(),
        };
        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync message");

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        let hash_3 = wait_for_checkpoint(&*src_state_manager, height(3));

        assert_error_counters(src_metrics);

        state_manager_restart_test_with_state_sync(
            |dst_metrics, dst_state_manager, dst_state_sync, restart_fn| {
                let (_height, mut state) = dst_state_manager.take_tip();
                populate_original_state(&mut state);
                dst_state_manager.commit_and_certify(
                    state,
                    height(1),
                    CertificationScope::Full,
                    None,
                );

                let dst_hash_1 = wait_for_checkpoint(&*dst_state_manager, height(1));
                assert_eq!(hash_1, dst_hash_1);
                // Ensure all tip requests are completed before corrupting the checkpoint,
                // otherwise `reset_tip_to` may fail due to writable checkpoint files.
                dst_state_manager.flush_tip_channel();

                // Corrupt some data
                let state_layout = dst_state_manager.state_layout();
                let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    state_layout
                        .checkpoint_verified(height(1))
                        .unwrap()
                        .raw_path()
                        .to_path_buf(),
                    height(1),
                )
                .unwrap();

                let canister_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();
                let canister_memory = canister_layout
                    .vmemory_0()
                    .existing_overlays()
                    .unwrap()
                    .remove(0);
                make_mutable(&canister_memory).unwrap();
                for i in 0..10000 {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(false)
                        .truncate(false)
                        .open(&canister_memory)
                        .unwrap()
                        .write_all_at(b"Garbage", i * 4096)
                        .unwrap();
                }
                make_readonly(&canister_memory).unwrap();

                assert_eq!(0, count_critical_errors(dst_metrics));
                // After the first manifest, we expect to detect a divergence and raise critical errors counter.
                let (_height, state) = dst_state_manager.take_tip();
                dst_state_manager.commit_and_certify(
                    state,
                    height(2),
                    CertificationScope::Full,
                    None,
                );
                dst_state_manager.flush_tip_channel();
                assert_ne!(0, count_critical_errors(dst_metrics));

                // Emulate a state manager crash when encountering a diverged checkpoint.
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    dst_state_manager.report_diverged_checkpoint(height(2));
                }));
                assert!(result.is_err());

                drop(dst_state_sync);
                // Restart the dst state manager.
                // restart_fn() needs to take the ownership of state manager to drop it.
                // We need to manually ensure all other `Arc<StateManagerImpl>` have been dropped.
                let dst_state_manager = match Arc::try_unwrap(dst_state_manager) {
                    Ok(sm) => sm,
                    Err(_) => panic!(
                        "Please make sure other strong references of dst_state_manager have been dropped"
                    ),
                };
                // State manager restarts and archives the diverged checkpoint.
                let (dst_metrics, dst_state_manager, dst_state_sync) =
                    restart_fn(dst_state_manager, None);

                // Only checkpoint @1 remains in the checkpoints folder and the state manager should recover from this checkpoint.
                assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(1)]);
                assert_eq!(dst_state_manager.latest_state_height(), height(1));

                // Main testing scenario:
                // State manager restarts on a broken but loadable checkpoint and start state sync based on it.
                // State sync should valiate the base checkpoint, detect corruption and fetch the chunks instead.
                // State sync should finish successfully and state manager should continue execution and create the checkpoint @3.
                let chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
                pipe_state_sync(msg, chunkable);

                // Verify the metrics: state sync should detect corruption during the `hardlink_files` phase.
                let source_key =
                    maplit::btreemap! {"source".to_string() => "hardlink_files".to_string()};
                let corrupted_chunks =
                    fetch_int_counter_vec(&dst_metrics, "state_sync_corrupted_chunks")[&source_key];
                assert!(corrupted_chunks > 0);
                assert_no_remaining_chunks(&dst_metrics);

                let (_height, state) = dst_state_manager.take_tip();
                dst_state_manager.commit_and_certify(
                    state,
                    height(3),
                    CertificationScope::Full,
                    None,
                );
                let dst_hash_3 = wait_for_checkpoint(&*dst_state_manager, height(3));
                assert_eq!(hash_3, dst_hash_3);

                let expected_state = src_state_manager.get_latest_state();

                assert_eq!(dst_state_manager.get_latest_state(), expected_state);

                let mut tip = dst_state_manager.take_tip().1;
                let state = expected_state.take();
                // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
                tip.metadata
                    .prev_state_hash
                    .clone_from(&state.metadata.prev_state_hash);
                assert_eq!(tip, *state.as_ref());
            },
        )
    });
}

fn count_critical_errors(metrics: &MetricsRegistry) -> u64 {
    fetch_int_counter_vec(metrics, "critical_errors")
        .values()
        .sum::<u64>()
}

#[test]
fn can_detect_divergence_with_rehash() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};

    state_manager_test(|metrics, state_manager| {
        use std::os::unix::fs::FileExt;
        let (_height, mut state) = state_manager.take_tip();

        insert_dummy_canister(&mut state, canister_test_id(100));

        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        for i in 0..10000 {
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(i), &[99u8; PAGE_SIZE])]);
        }

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        // Ensure all tip requests are completed before corrupting the checkpoint,
        // otherwise `reset_tip_to` may fail due to writable checkpoint files.
        state_manager.flush_tip_channel();

        // Corrupt some data
        let state_layout = state_manager.state_layout();
        let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            state_layout
                .checkpoint_verified(height(1))
                .unwrap()
                .raw_path()
                .to_path_buf(),
            height(1),
        )
        .unwrap();

        let canister_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();
        let canister_memory = canister_layout
            .vmemory_0()
            .existing_overlays()
            .unwrap()
            .remove(0);
        make_mutable(&canister_memory).unwrap();
        for i in 0..10000 {
            std::fs::OpenOptions::new()
                .write(true)
                .create(false)
                .truncate(false)
                .open(&canister_memory)
                .unwrap()
                .write_all_at(b"Garbage", i * 4096)
                .unwrap();
        }
        make_readonly(&canister_memory).unwrap();

        assert_eq!(0, count_critical_errors(metrics));
        // After the first manifest, we expect to detect a divergence and raise critical errors counter.
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert_ne!(0, count_critical_errors(metrics));

        // For the second manifest we expect a full recomputation of the manifest, no new critical errors.
        let (_height, state) = state_manager.take_tip();
        let reused_key = maplit::btreemap! {"type".to_string() => "reused".to_string()};
        let reused_bytes =
            fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes")[&reused_key];
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert_eq!(
            reused_bytes,
            fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes")[&reused_key]
        );
    });
}

#[test]
fn do_not_crash_in_loop_due_to_corrupted_state_sync() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    use std::panic::{self, AssertUnwindSafe};

    let populate_original_state = |state: &mut ReplicatedState| {
        insert_dummy_canister(state, canister_test_id(90));

        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);
    };

    let update_state = |state: &mut ReplicatedState| {
        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(300), &[3u8; PAGE_SIZE])]);
    };

    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        // Create initial state with a single canister.
        let (_height, mut state) = src_state_manager.take_tip();
        populate_original_state(&mut state);
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let hash_1 = wait_for_checkpoint(&*src_state_manager, height(1));

        // Update the canister state.
        let (_height, mut state) = src_state_manager.take_tip();
        update_state(&mut state);
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2.clone().get(),
        };
        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_restart_test_with_state_sync(
            |dst_metrics, dst_state_manager, dst_state_sync, restart_fn| {
                let (_height, mut state) = dst_state_manager.take_tip();
                populate_original_state(&mut state);
                dst_state_manager.commit_and_certify(
                    state,
                    height(1),
                    CertificationScope::Full,
                    None,
                );

                let hash_dst_1 = wait_for_checkpoint(&*dst_state_manager, height(1));
                assert_eq!(hash_1, hash_dst_1);

                let mut chunkable =
                    set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

                // Omit one chunk and corrupt some files in the state sync scratchpad before adding the final chunk.
                let omit: HashSet<ChunkId> =
                    maplit::hashset! {ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
                assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");

                let state_sync_scratchpad = dst_state_manager
                    .state_layout()
                    .state_sync_scratchpad(height(2));

                let state_sync_scratchpad_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
                    state_sync_scratchpad,
                    height(2),
                )
                .unwrap();

                // Write garbage to the system_metadata.pbuf file so that loading will fail.
                let system_metadata = state_sync_scratchpad_layout
                    .system_metadata()
                    .raw_path()
                    .to_path_buf();
                make_mutable(&system_metadata).unwrap();
                std::fs::write(&system_metadata, b"Garbage").unwrap();
                make_readonly(&system_metadata).unwrap();

                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    pipe_state_sync(msg, chunkable);
                }));

                assert!(result.is_err());

                // Restart the dst state manager.
                // restart_fn() needs to take the ownership of state manager to drop it.
                // We need to manually ensure all other `Arc<StateManagerImpl>` have been dropped.
                drop(dst_state_sync);
                let dst_state_manager = match Arc::try_unwrap(dst_state_manager) {
                    Ok(sm) => sm,
                    Err(_) => panic!(
                        "Please make sure other strong references of dst_state_manager have been dropped"
                    ),
                };
                // State manager restarts and won't crash again due to the corrupted checkpoint because it will be archived.
                let (_metrics, dst_state_manager, _dst_state_sync) =
                    restart_fn(dst_state_manager, None);

                // Unverified checkpoint @2 should be archived and moved to the backups folder.
                let backup_heights = dst_state_manager
                    .state_layout()
                    .backup_heights()
                    .expect("failed to get backup heights");
                assert_eq!(backup_heights, vec![height(2)]);

                // Only checkpoint @1 remains in the checkpoints folder and the state manager should recover from this checkpoint.
                assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(1)]);
                assert_eq!(dst_state_manager.latest_state_height(), height(1));

                // Continue execution and create the checkpoint @2.
                let (_height, mut state) = dst_state_manager.take_tip();
                update_state(&mut state);

                dst_state_manager.commit_and_certify(
                    state,
                    height(2),
                    CertificationScope::Full,
                    None,
                );

                let hash_dst_2 = wait_for_checkpoint(&*dst_state_manager, height(2));

                let expected_state = src_state_manager.get_latest_state();

                assert_eq!(dst_state_manager.get_latest_state(), expected_state);
                assert_eq!(hash_dst_2, hash_2);

                let mut tip = dst_state_manager.take_tip().1;
                let state = expected_state.take();
                // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
                tip.metadata
                    .prev_state_hash
                    .clone_from(&state.metadata.prev_state_hash);
                assert_eq!(tip, *state.as_ref());

                assert_no_remaining_chunks(dst_metrics);
                assert_error_counters(dst_metrics);
            },
        )
    });
}

#[test]
fn can_handle_state_sync_and_commit_race_condition() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(
            state.clone(),
            height(1),
            CertificationScope::Full,
            None,
        );

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(2));

        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            // The state sync is started before the state manager has the state at height 2.
            let mut chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            // Start the state sync when the state manager is below height 2.
            // Omit one chunk and corrupt some files in the state sync scratchpad before adding the final chunk.
            let omit: HashSet<ChunkId> =
                maplit::hashset! {ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};
            let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
            assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
            dst_state_manager.flush_tip_channel();

            // Continue to perform the state sync after the state manager reaches height 2.
            // It should be OK to load the checkpoint again from the state sync thread and try to remove the marker twice.
            pipe_state_sync(msg, chunkable);

            assert_eq!(
                dst_state_manager.checkpoint_heights(),
                vec![height(1), height(2)]
            );

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);

            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            assert_eq!(dst_state_manager.latest_state_height(), height(3));
            // State 1 should be removable.
            dst_state_manager.flush_tip_channel();
            dst_state_manager.remove_states_below(height(3));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(3)]);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn should_not_leak_checkpoint_when_state_sync_into_existing_snapshot_height() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(
            state.clone(),
            height(1),
            CertificationScope::Full,
            None,
        );

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));

        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);

        wait_for_checkpoint(&*src_state_manager, height(3));

        certify_height(&*src_state_manager, height(1));
        certify_height(&*src_state_manager, height(2));

        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
            dst_state_manager.flush_tip_channel();
            certify_height(&*dst_state_manager, height(1));

            // The state sync is started before the state manager has the state at height 2.
            let mut chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            // Start the state sync when the state manager is below height 2.
            // Omit one chunk and corrupt some files in the state sync scratchpad before adding the final chunk.
            let omit: HashSet<ChunkId> =
                maplit::hashset! {ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};
            let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
            assert_matches!(completion, Ok(false), "Unexpectedly completed state sync");

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
            certify_height(&*dst_state_manager, height(2));

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
            dst_state_manager.flush_tip_channel();

            dst_state_manager.remove_states_below(height(3));
            dst_state_manager.flush_deallocation_channel();

            // Checkpoint @2 should be removed
            // while checkpoint @1 is still kept because it is referenced by state sync as a base.
            assert_eq!(
                dst_state_manager.checkpoint_heights(),
                vec![height(1), height(3)]
            );

            assert_eq!(
                dst_state_manager.list_state_heights(CERT_CERTIFIED),
                vec![height(2)]
            );

            // Continue to perform the state sync at height 2 after the state manager reaches height 3.
            pipe_state_sync(msg, chunkable);

            // State sync adds back checkpoint @2 into the state manager.
            assert_eq!(
                dst_state_manager.checkpoint_heights(),
                vec![height(2), height(3)]
            );

            // There should not exist duplicate entries for snapshot height 2.
            assert_eq!(
                dst_state_manager.list_state_heights(CERT_CERTIFIED),
                vec![height(2)]
            );

            assert_eq!(
                dst_state_manager.list_state_heights(CERT_ANY),
                vec![height(0), height(2), height(3)]
            );

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(
                state,
                height(4),
                CertificationScope::Metadata,
                None,
            );
            certify_height(&*dst_state_manager, height(3));
            certify_height(&*dst_state_manager, height(4));
            assert_eq!(dst_state_manager.latest_certified_height(), height(4));

            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(4));
            assert_eq!(dst_state_manager.latest_state_height(), height(4));
            // checkpoint @2 should be removable.
            dst_state_manager.flush_tip_channel();
            dst_state_manager.remove_states_below(height(4));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(3)]);
            assert_eq!(dst_state_manager.latest_certified_height(), height(4));
            // Snapshots below 4 should be removable.
            assert_eq!(
                dst_state_manager.list_state_heights(CERT_ANY),
                vec![height(0), height(4)]
            );
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_commit_below_state_sync() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let hash = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);
            pipe_state_sync(msg, chunkable);
            // Check committing an old state doesn't panic
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
            dst_state_manager.flush_tip_channel();

            // take_tip should update the tip to the synced checkpoint
            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(2));
            assert_eq!(dst_state_manager.latest_state_height(), height(2));
            // state 1 should be removable
            dst_state_manager.remove_states_below(height(2));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(2)]);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_below_commit() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(
            state.clone(),
            height(1),
            CertificationScope::Full,
            None,
        );
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));

        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.get(),
        };

        let msg = src_state_sync
            .get(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // the state sync is started before the state manager has the state at height 1.
            let chunkable =
                set_fetch_state_and_start_state_sync(&dst_state_manager, &dst_state_sync, &id);

            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
            dst_state_manager.flush_tip_channel();

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.remove_states_below(height(2));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(2)]);
            // Perform the state sync after the state manager reaches height 2.
            pipe_state_sync(msg, chunkable);

            assert_eq!(
                dst_state_manager.checkpoint_heights(),
                vec![height(1), height(2)]
            );
            dst_state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);

            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            assert_eq!(dst_state_manager.latest_state_height(), height(3));
            // state 1 should be removable
            dst_state_manager.flush_tip_channel();
            dst_state_manager.remove_states_below(height(3));
            dst_state_manager.flush_deallocation_channel();
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(3)]);
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_short_circuit_state_sync() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let hash_at_1 = wait_for_checkpoint(&state_manager, height(1));

        state_manager.fetch_state(height(1000), hash_at_1.clone(), Height::new(999));
        let hash_at_1000 = wait_for_checkpoint(&state_manager, height(1000));

        assert_eq!(hash_at_1, hash_at_1000);
        assert_eq!(state_manager.latest_state_height(), height(1000));

        let (tip_height, _) = state_manager.take_tip();
        assert_eq!(tip_height, height(1000));
    })
}

#[test]
fn can_reuse_chunk_hashes_when_computing_manifest() {
    use ic_state_manager::ManifestMetrics;
    use ic_state_manager::manifest::{RehashManifest, compute_manifest, validate_manifest};
    use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;

    state_manager_test(|metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(1));
        let canister_state = state.canister_state_mut(&canister_test_id(1)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();

        const WASM_PAGES: u64 = 300;
        for i in 0..WASM_PAGES {
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(i), &[i as u8; PAGE_SIZE])]);
        }
        const STABLE_PAGES: u64 = 500;
        for i in 0..STABLE_PAGES {
            execution_state
                .stable_memory
                .page_map
                .update(&[(PageIndex::new(i), &[i as u8; PAGE_SIZE])]);
        }

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(1));
        state_manager.flush_tip_channel();

        let mut reused_label = Labels::new();
        reused_label.insert("type".to_string(), "reused".to_string());
        let mut compared_label = Labels::new();
        compared_label.insert("type".to_string(), "hashed_and_compared".to_string());

        // First checkpoint: no chunks to reuse yet.
        let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
        assert_eq!(0, chunk_bytes[&reused_label]);

        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        let state_2_hash = wait_for_checkpoint(&state_manager, height(2));
        state_manager.flush_tip_channel();

        // Second checkpoint can leverage heap chunks computed previously as well as the wasm binary.
        let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
        let expected_size_estimate =
            PAGE_SIZE as u64 * (WASM_PAGES + STABLE_PAGES) + empty_wasm_size() as u64;
        let size = chunk_bytes[&reused_label] + chunk_bytes[&compared_label];
        // We compute manifest then rehash, so twice the size
        assert!(((expected_size_estimate as f64 * 2.2) as u64) > size);
        assert!(((expected_size_estimate as f64 * 2.0) as u64) < size);

        let checkpoint = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap();

        let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);

        let manifest = compute_manifest(
            &mut thread_pool,
            &ManifestMetrics::new(&MetricsRegistry::new()),
            &no_op_logger(),
            CURRENT_STATE_SYNC_VERSION,
            &checkpoint,
            DEFAULT_CHUNK_SIZE,
            None,
            RehashManifest::No,
        )
        .expect("failed to compute manifest");

        // Check that the manifest that state manager computed incrementally is the same
        // as the manifest we computed from scratch.
        validate_manifest(&manifest, &state_2_hash).unwrap();
    });
}

#[test]
fn certified_read_can_certify_ingress_history_entry() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(1)) => LabeledTree::Leaf(())
                })
        });

        assert_eq!(None, state_manager.read_certified_state(&path));
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&path)
            .expect("failed to read certified state");

        assert_eq!(cert, delivered_certification);
        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("request_status") =>
                    SubTree(flatmap! {
                        label(message_test_id(1)) =>
                            SubTree(flatmap! {
                                label("status") => Leaf(b"replied".to_vec()),
                                label("reply") => Leaf(b"done".to_vec()),
                            })
                    })
            })
        );
    })
}

#[test]
fn certified_read_can_certify_time() {
    use LabeledTree::*;
    use std::time::Duration;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.metadata.batch_time += Duration::new(0, 100);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("time") => Leaf(())
        });

        assert_eq!(None, state_manager.read_certified_state(&path));
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&path)
            .expect("failed to read certified state");

        assert_eq!(cert, delivered_certification);
        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap!(label("time") => Leaf(vec![100])))
        );
    })
}

#[test]
fn certified_read_can_certify_canister_data() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        let canister_id: CanisterId = canister_test_id(100);
        insert_dummy_canister(&mut state, canister_id);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path = SubTree(flatmap! {
            label("canister") => SubTree(
                flatmap! {
                    label(canister_test_id(100).get_ref()) => SubTree(
                        flatmap!(label("certified_data") => Leaf(()))
                    )
                })
        });
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&path)
            .expect("failed to read certified state");

        assert_eq!(cert, delivered_certification);
        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("canister") =>
                    SubTree(flatmap! {
                        label(canister_test_id(100).get_ref()) =>
                            SubTree(flatmap! {
                                label("certified_data") => Leaf(vec![]),
                            })
                    })
            })
        );
    })
}

#[test]
fn certified_read_can_certify_node_public_keys_since_v12() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        let canister_id: CanisterId = canister_test_id(100);
        insert_dummy_canister(&mut state, canister_id);

        state.metadata.batch_time += std::time::Duration::new(0, 100);
        let mut subnets = BTreeMap::new();

        let mut node_public_keys: BTreeMap<NodeId, Vec<u8>> = BTreeMap::new();
        for i in 0..40 {
            node_public_keys.insert(node_test_id(i), vec![i as u8; 44]);
        }

        subnets.insert(
            subnet_test_id(42), // its own subnet id
            SubnetTopology {
                public_key: vec![1u8; 133],
                nodes: node_public_keys.keys().cloned().collect(),
                subnet_type: SubnetType::System,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            },
        );

        let network_topology = NetworkTopology {
            subnets,
            nns_subnet_id: subnet_test_id(42),
            ..Default::default()
        };

        state.metadata.network_topology = network_topology;
        state.metadata.node_public_keys = node_public_keys;

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let subnet_id = subnet_test_id(42).get();
        let node_id = node_test_id(39).get();
        let path: Vec<&[u8]> = vec![
            b"subnet",
            subnet_id.as_ref(),
            b"node",
            node_id.as_ref(),
            b"public_key",
        ];

        let label_path = LabelPath::new(path.iter().map(label).collect::<Vec<_>>());

        let labeled_tree =
            sparse_labeled_tree_from_paths(&[label_path]).expect("failed to create labeled tree");
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&labeled_tree)
            .expect("failed to read certified state");
        assert_eq!(cert, delivered_certification);

        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("subnet") => SubTree(
                    flatmap! {
                        label(subnet_test_id(42).get_ref()) => SubTree(
                            flatmap!{
                                label("node") => SubTree(
                                    flatmap! {
                                        label(node_test_id(39).get_ref()) => SubTree(
                                            flatmap!(label("public_key") => Leaf(vec![39u8; 44]))
                                        ),
                                    })
                        })
                    })
            })
        );
    })
}

#[test]
fn certified_read_can_certify_api_boundary_nodes_since_v16() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.metadata.api_boundary_nodes = btreemap! {
            node_test_id(11) => ApiBoundaryNodeEntry {
                domain: "api-bn11-example.com".to_string(),
                ipv4_address: Some("127.0.0.1".to_string()),
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
                pubkey: None,
            },
            node_test_id(12) => ApiBoundaryNodeEntry {
                domain: "api-bn12-example.com".to_string(),
                ipv4_address: None,
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7335".to_string(),
                pubkey: None,
            },
        };

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let api_bn_id = node_test_id(11).get();
        let path: Vec<&[u8]> = vec![b"api_boundary_nodes", api_bn_id.as_ref()];

        let label_path = LabelPath::new(path.iter().map(label).collect::<Vec<_>>());

        let labeled_tree =
            sparse_labeled_tree_from_paths(&[label_path]).expect("failed to create labeled tree");
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&labeled_tree)
            .expect("failed to read certified state");
        assert_eq!(cert, delivered_certification);

        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("api_boundary_nodes") => SubTree(
                    flatmap! {
                        label(node_test_id(11).get_ref()) => SubTree(
                            flatmap!{
                                label("domain") => Leaf("api-bn11-example.com".to_string().into_bytes()),
                                label("ipv4_address") => Leaf("127.0.0.1".to_string().into_bytes()),
                                label("ipv6_address") => Leaf("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string().into_bytes()),
                        })
                    })
            })
        );
    })
}

#[test]
fn certified_read_succeeds_for_empty_forks() {
    state_manager_test(|_metrics, state_manager| {
        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("api_boundary_nodes") => LabeledTree::Leaf(()),
            label("canister") => LabeledTree::Leaf(()),
            label("streams") => LabeledTree::Leaf(()),
        });

        certify_height(&state_manager, height(1));
        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();
        let lookup_canister = mixed_tree.lookup(&[&b"canister"[..]]);
        let lookup_streams = mixed_tree.lookup(&[&b"streams"[..]]);
        let lookup_api_boundary_nodes = mixed_tree.lookup(&[&b"api_boundary_nodes"[..]]);

        assert_matches!(
            lookup_canister,
            LookupStatus::Found(&ic_crypto_tree_hash::MixedHashTree::Empty)
        );

        assert_matches!(
            lookup_streams,
            LookupStatus::Found(&ic_crypto_tree_hash::MixedHashTree::Empty)
        );

        // If there are no api boundary nodes present, the lookup status should be `MixedHashTree::Empty`.
        // This behavior is in consistent with looking up  `/streams` and `/canister`.
        assert_matches!(
            lookup_api_boundary_nodes,
            LookupStatus::Found(&ic_crypto_tree_hash::MixedHashTree::Empty)
        );
    })
}

#[test]
fn certified_read_succeeds_for_empty_tree() {
    use ic_crypto_tree_hash::MixedHashTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {});

        certify_height(&state_manager, height(1));
        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();

        assert!(
            matches!(&mixed_tree, Pruned(_)),
            "mixed_tree: {mixed_tree:#?}"
        );
    })
}

#[test]
fn certified_read_returns_absence_proof_for_non_existing_entries() {
    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(2).as_bytes()) => LabeledTree::Leaf(())
                })
        });

        certify_height(&state_manager, height(1));
        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();
        assert!(
            mixed_tree
                .lookup(&[&b"request_status"[..], &message_test_id(2).as_bytes()[..]])
                .is_absent(),
            "mixed_tree: {mixed_tree:#?}"
        );

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(0).as_bytes()) => LabeledTree::Leaf(())
                })
        });

        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();
        assert!(
            mixed_tree
                .lookup(&[&b"request_status"[..], &message_test_id(0).as_bytes()[..]])
                .is_absent(),
            "mixed_tree: {mixed_tree:#?}"
        );
    })
}

#[test]
fn certified_read_returns_absence_proof_for_non_existing_entries_in_empty_state() {
    state_manager_test(|_metrics, state_manager| {
        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(2).as_bytes()) => LabeledTree::Leaf(())
                })
        });

        certify_height(&state_manager, height(1));
        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();
        assert!(
            mixed_tree
                .lookup(&[&b"request_status"[..], &message_test_id(2).as_bytes()[..]])
                .is_absent(),
            "mixed_tree: {mixed_tree:#?}"
        );
    })
}

#[test]
fn certified_read_can_fetch_multiple_entries_in_one_go() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(1)) => LabeledTree::Leaf(()),
                    label(message_test_id(2)) => LabeledTree::Leaf(()),
                })
        });

        assert_eq!(None, state_manager.read_certified_state(&path));
        let delivered_certification = certify_height(&state_manager, height(1));

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state(&path)
            .expect("failed to read certified state");

        assert_eq!(cert, delivered_certification);
        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("request_status") =>
                    SubTree(flatmap! {
                        label(message_test_id(1)) =>
                            SubTree(flatmap! {
                                label("status") => Leaf(b"replied".to_vec()),
                                label("reply") => Leaf(b"done".to_vec()),
                            }),
                        label(message_test_id(2)) =>
                            SubTree(flatmap! {
                                label("status") => Leaf(b"processing".to_vec()),
                            })

                    })
            })
        );
    })
}

#[test]
fn certified_read_can_produce_proof_of_absence() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            message_test_id(3),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: UNIX_EPOCH,
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            label("request_status") => LabeledTree::SubTree(
                flatmap! {
                    label(message_test_id(1)) => LabeledTree::Leaf(()),
                    label(message_test_id(2)) => LabeledTree::Leaf(()),
                })
        });

        certify_height(&state_manager, height(1));

        let (_state, mixed_tree, _cert) = state_manager
            .read_certified_state(&path)
            .expect("failed to read certified state");

        assert!(
            mixed_tree
                .lookup(&[&b"request_status"[..], &message_test_id(2).as_bytes()[..]])
                .is_absent(),
            "mixed_tree: {mixed_tree:#?}"
        );

        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("request_status") =>
                    SubTree(flatmap! {
                        label(message_test_id(1)) =>
                            SubTree(flatmap! {
                                label("status") => Leaf(b"replied".to_vec()),
                                label("reply") => Leaf(b"done".to_vec()),
                            }),
                    })
            })
        );
    })
}

#[test]
fn certified_read_can_exclude_canister_ranges() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        let mut subnets = BTreeMap::new();
        let mut routing_table = RoutingTable::new();

        for i in 0..4 {
            let subnet_id = subnet_test_id(i);
            subnets.insert(
                subnet_id,
                SubnetTopology {
                    public_key: vec![i as u8; 133],
                    nodes: Default::default(),
                    subnet_type: SubnetType::Application,
                    subnet_features: SubnetFeatures::default(),
                    chain_keys_held: BTreeSet::new(),
                    cost_schedule: CanisterCyclesCostSchedule::Normal,
                },
            );
            routing_table
                .insert(
                    CanisterIdRange {
                        start: canister_test_id(1000 * i + 1),
                        end: canister_test_id(1000 * (i + 1)),
                    },
                    subnet_id,
                )
                .unwrap();
        }

        let network_topology = NetworkTopology {
            subnets,
            routing_table: Arc::new(routing_table),
            ..Default::default()
        };

        state.metadata.network_topology = network_topology;

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);

        let path = SubTree(flatmap! {
            label("subnet") => Leaf(())
        });
        let delivered_certification = certify_height(&state_manager, height(1));

        // Drop all `canister_ranges` leafs except for `some_subnet_id`
        let some_subnet_id = subnet_test_id(1);
        let exclusion = vec![
            MatchPattern::Inclusive("subnet".into()),
            MatchPattern::Exclusive(label(some_subnet_id.get_ref())),
            MatchPattern::Inclusive("canister_ranges".into()),
        ];

        let (_state, mixed_tree, cert) = state_manager
            .read_certified_state_with_exclusion(&path, Some(&exclusion))
            .expect("failed to read certified state");

        assert_eq!(cert, delivered_certification);
        assert_eq!(
            tree_payload(mixed_tree),
            SubTree(flatmap! {
                label("subnet") =>
                    SubTree(flatmap! {
                        label(subnet_test_id(0).get_ref()) =>
                            SubTree(flatmap! {
                                label("public_key") => Leaf(vec![0_u8; 133]),
                            }),
                        label(subnet_test_id(1).get_ref()) =>
                            SubTree(flatmap! {
                                label("canister_ranges") => Leaf(
                                    encode_subnet_canister_ranges(
                                        Some(&vec![(canister_test_id(1001).get(), canister_test_id(2000).get())])
                                    )
                                ),
                                label("public_key") => Leaf(vec![1_u8; 133]),
                            }),
                        label(subnet_test_id(2).get_ref()) =>
                            SubTree(flatmap! {
                                label("public_key") => Leaf(vec![2_u8; 133]),
                            }),
                        label(subnet_test_id(3).get_ref()) =>
                            SubTree(flatmap! {
                                label("public_key") => Leaf(vec![3_u8; 133]),
                            })
                    })
            })
        );
    })
}

// For a divergence we expect the first of the diverged state to get stored for troubleshooting
// and the state to reset to the pre-divergence checkpoint.
#[test]
fn report_diverged_checkpoint() {
    let now_ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    state_manager_crash_test(
        vec![Box::new(|state_manager: StateManagerImpl| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
            wait_for_checkpoint(&state_manager, height(3));

            // If the Tip thread is active while we report diverged checkpoint, it may crash
            // which is OK in production but confuses debug assertions.
            state_manager.flush_tip_channel();

            // This could only happen if calculating the manifest and certification of height 2
            // completed after reaching height 3
            state_manager.report_diverged_checkpoint(height(2))
        })],
        |metrics, state_manager| {
            assert_eq!(
                height(1),
                state_manager.get_latest_state().height(),
                "Expected diverged checkpoint@2 and checkpoint@3 to go away"
            );
            // We have diverged at state 2. This implies that height 3 diverges as a result but only
            // height 2 is valuable for debugging.
            assert_eq!(
                vec![height(2)],
                state_manager
                    .state_layout()
                    .diverged_checkpoint_heights()
                    .unwrap()
            );
            assert!(
                state_manager
                    .state_layout()
                    .diverged_state_heights()
                    .unwrap()
                    .is_empty()
            );
            let last_diverged = fetch_int_gauge(
                metrics,
                "state_manager_last_diverged_state_timestamp_seconds",
            )
            .unwrap();
            assert!(last_diverged > now_ts);
        },
    );
}

#[test]
fn diverged_checkpoint_is_complete() {
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());

    with_test_replica_logger(|log| {
        let state_manager = StateManagerImpl::new(
            Arc::new(FakeVerifier::new()),
            subnet_test_id(42),
            SubnetType::Application,
            log.clone(),
            &MetricsRegistry::new(),
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);

        let state_hash = wait_for_checkpoint(&state_manager, height(2));

        drop(state_manager);

        std::panic::catch_unwind(|| {
            let state_manager = StateManagerImpl::new(
                Arc::new(FakeVerifier::new()),
                subnet_test_id(42),
                SubnetType::Application,
                log.clone(),
                &MetricsRegistry::new(),
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );
            // If the Tip thread is active while we report diverged checkpoint, it may crash
            // which is OK in production but confuses debug assertions.
            state_manager.flush_tip_channel();

            state_manager.report_diverged_checkpoint(height(2));
        })
        .unwrap_err();

        let state_manager = StateManagerImpl::new(
            Arc::new(FakeVerifier::new()),
            subnet_test_id(42),
            SubnetType::Application,
            log,
            &MetricsRegistry::new(),
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        // check that the diverged checkpoint has the same manifest as before
        let manifest = manifest_from_path(
            &state_manager
                .state_layout()
                .diverged_checkpoint_path(height(2)),
        )
        .unwrap();
        validate_manifest(&manifest, &state_hash).unwrap()
    });
}

#[test]
fn report_diverged_state() {
    let now_ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    state_manager_crash_test(
        vec![Box::new(|state_manager: StateManagerImpl| {
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut certification = certify_height(&state_manager, height(1));
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);
            // Hack the certification so it is a divergence
            certification.height = height(2);

            state_manager.deliver_state_certification(certification);
        })],
        |metrics, state_manager| {
            assert_eq!(
                vec![height(2)],
                state_manager
                    .state_layout()
                    .diverged_state_heights()
                    .unwrap()
            );
            assert!(
                state_manager
                    .state_layout()
                    .diverged_checkpoint_heights()
                    .unwrap()
                    .is_empty()
            );
            let last_diverged = fetch_int_gauge(
                metrics,
                "state_manager_last_diverged_state_timestamp_seconds",
            )
            .unwrap();
            assert!(last_diverged > now_ts);
        },
    );
}

#[test]
fn remove_too_many_diverged_checkpoints() {
    fn diverge_at(state_manager: StateManagerImpl, divergence: u64) {
        let last_correct_checkpoint = state_manager
            .state_layout()
            .checkpoint_heights()
            .unwrap()
            .last()
            .unwrap_or(&height(0))
            .get();
        for i in last_correct_checkpoint..(divergence - 1) {
            let (j, state) = state_manager.take_tip();
            debug_assert_eq!(height(i), j);
            state_manager.commit_and_certify(state, height(i + 1), CertificationScope::Full, None);
            state_manager.flush_tip_channel();
        }

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(divergence), CertificationScope::Full, None);
        // If the Tip thread is active while we report diverged checkpoint, it may crash
        // which is OK in production but confuses debug assertions.
        state_manager.flush_tip_channel();
        state_manager.report_diverged_checkpoint(height(divergence));
    }
    state_manager_crash_test(
        vec![
            Box::new(|state_manager: StateManagerImpl| diverge_at(state_manager, 1)),
            Box::new(|state_manager: StateManagerImpl| diverge_at(state_manager, 2)),
            Box::new(|state_manager: StateManagerImpl| diverge_at(state_manager, 3)),
        ],
        |_metrics, state_manager| {
            assert_eq!(
                vec![height(3)],
                state_manager
                    .state_layout()
                    .diverged_checkpoint_heights()
                    .unwrap()
            );
        },
    );
}

#[test]
fn remove_old_diverged_checkpoint() {
    state_manager_crash_test(
        vec![
            Box::new(|state_manager: StateManagerImpl| {
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
                wait_for_checkpoint(&state_manager, height(1));
                // If the Tip thread is active while we report diverged checkpoint, it may crash
                // which is OK in production but confuses debug assertions.
                state_manager.flush_tip_channel();

                state_manager.report_diverged_checkpoint(height(1))
            }),
            Box::new(|state_manager: StateManagerImpl| {
                // Mark diverged checkpoint as old.
                // As we are still in state_manager_crash_test() we have to crash in
                // order for the test not to fail.
                let path = state_manager
                    .state_layout()
                    .diverged_checkpoint_path(height(1));
                let Ok(_) = utimensat(
                    None,
                    &path,
                    &TimeSpec::zero(),
                    &TimeSpec::zero(),
                    UtimensatFlags::NoFollowSymlink,
                ) else {
                    return;
                };
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
                wait_for_checkpoint(&state_manager, height(2));

                panic!();
            }),
        ],
        |metrics, state_manager| {
            assert!(
                state_manager
                    .state_layout()
                    .diverged_checkpoint_heights()
                    .unwrap()
                    .is_empty()
            );
            let last_diverged = fetch_int_gauge(
                metrics,
                "state_manager_last_diverged_state_timestamp_seconds",
            )
            .unwrap();
            assert_eq!(last_diverged, 0);
        },
    );
}

#[test]
fn checkpoints_have_growing_mtime() {
    state_manager_test(|_metrics, state_manager| {
        let checkpoint_age = |h| {
            state_manager
                .state_layout()
                .checkpoint_verified(height(h))
                .unwrap()
                .raw_path()
                .metadata()
                .unwrap()
                .modified()
                .unwrap()
        };
        // The first checkpoint is special since the tip was created from scratch, compare two next
        // ones.
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(1));
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(2));
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        wait_for_checkpoint(&state_manager, height(3));
        assert!(checkpoint_age(2) < checkpoint_age(3));
    });
}

#[test]
fn dont_remove_diverged_checkpoint_if_there_was_no_progress() {
    state_manager_crash_test(
        vec![
            Box::new(|state_manager: StateManagerImpl| {
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
                wait_for_checkpoint(&state_manager, height(2));

                // If the Tip thread is active while we report diverged checkpoint, it may crash
                // which is OK in production but confuses debug assertions.
                state_manager.flush_tip_channel();

                state_manager.report_diverged_checkpoint(height(2))
            }),
            Box::new(|state_manager: StateManagerImpl| {
                // Mark diverged checkpoint as old.
                // As we are still in state_manager_crash_test() we have to crash in
                // order for the test not to fail.
                let path = state_manager
                    .state_layout()
                    .diverged_checkpoint_path(height(2));
                let Ok(_) = utimensat(
                    None,
                    &path,
                    &TimeSpec::zero(),
                    &TimeSpec::zero(),
                    UtimensatFlags::NoFollowSymlink,
                ) else {
                    return;
                };

                panic!();
            }),
        ],
        |_metrics, state_manager| {
            assert_eq!(
                vec![height(2)],
                state_manager
                    .state_layout()
                    .diverged_checkpoint_heights()
                    .unwrap()
            );
        },
    );
}

#[test]
fn remove_too_many_diverged_state_markers() {
    fn diverge_state_at(state_manager: StateManagerImpl, divergence: u64) {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
        let mut certification = certify_height(&state_manager, height(1));
        for i in 2..(divergence + 1) {
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata, None);
        }
        // Hack the certification so it is a divergence
        certification.height = height(divergence);

        state_manager.deliver_state_certification(certification);
    }
    let mut divergences = std::vec::Vec::<
        Box<dyn FnOnce(StateManagerImpl) + std::panic::RefUnwindSafe + std::panic::UnwindSafe>,
    >::new();

    for i in 2..301 {
        divergences.push(Box::new(move |state_manager: StateManagerImpl| {
            diverge_state_at(state_manager, i)
        }));
    }
    state_manager_crash_test(divergences, |_metrics, state_manager| {
        let num_markers = state_manager
            .state_layout()
            .diverged_state_heights()
            .unwrap()
            .len();
        assert_eq!(
            state_manager
                .state_layout()
                .diverged_state_heights()
                .unwrap()[num_markers - 1],
            height(300)
        );
        assert!(num_markers <= 100);
    });
}

#[test]
fn can_write_multiple_checkpoints() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        for _ in 1..10 {
            let (h, mut state) = state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            state_manager.commit_and_certify(
                state,
                height(h.get() + 1),
                CertificationScope::Full,
                None,
            );
        }

        wait_for_checkpoint(&state_manager, height(10));
    });
}

#[test]
fn can_reset_memory() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // One canister with some data.
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(0), &[99u8; PAGE_SIZE]),
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(2), &[99u8; PAGE_SIZE]),
            (PageIndex::new(3), &[99u8; PAGE_SIZE]),
            (PageIndex::new(4), &[99u8; PAGE_SIZE]),
            (PageIndex::new(5), &[99u8; PAGE_SIZE]),
            (PageIndex::new(6), &[99u8; PAGE_SIZE]),
            (PageIndex::new(7), &[99u8; PAGE_SIZE]),
        ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        // Check the data is written to disk.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(vmemory_size(&canister_layout) >= 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();

        // Wipe data and write different data
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(0), &[100u8; PAGE_SIZE]),
            (PageIndex::new(1), &[100u8; PAGE_SIZE]),
        ]);

        // Check no remnants of the old data remain.
        assert_eq!(
            execution_state
                .wasm_memory
                .page_map
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            execution_state
                .wasm_memory
                .page_map
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check file in checkpoint does not contain old data by checking its size.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(vmemory_size(&canister_layout) < 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();

        // Check again after checkpoint that no remnants of old data remain.
        assert_eq!(
            execution_state
                .wasm_memory
                .page_map
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            execution_state
                .wasm_memory
                .page_map
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        // Wipe data completely.
        execution_state.wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // File should be empty after wiping and checkpoint.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert_eq!(vmemory_size(&canister_layout), 0);

        assert_error_counters(metrics);
    });
}

#[test]
fn can_reset_memory_state_machine() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    read_and_assert_eq(&env, canister_id, 0);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 1);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 2);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 2);

    env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);
    read_and_assert_eq(&env, canister_id, 0);

    env.execute_ingress(canister_id, "load", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 2);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 3);

    // Checkpoints should not affect the data even after a recent upgrade
    env.set_checkpoints_enabled(true);
    env.tick();
    env.set_checkpoints_enabled(false);
    read_and_assert_eq(&env, canister_id, 3);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 4);

    env.set_checkpoints_enabled(true);
    env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);
    env.set_checkpoints_enabled(false);
    read_and_assert_eq(&env, canister_id, 0);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 1);

    env.set_checkpoints_enabled(true);
    env.tick();
    read_and_assert_eq(&env, canister_id, 1);
}

#[test]
fn can_upgrade_and_uninstall_canister_after_many_checkpoints() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(true);
    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    for i in 1..100 {
        env.execute_ingress(canister_id, "inc", vec![]).unwrap();
        read_and_assert_eq(&env, canister_id, i);
        if i == 50 {
            env.execute_ingress(canister_id, "grow_page", vec![])
                .unwrap();
            env.execute_ingress(canister_id, "persist", vec![]).unwrap();
        }
    }

    env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);
    env.execute_ingress(canister_id, "load", vec![]).unwrap();

    for i in 1..100 {
        env.execute_ingress(canister_id, "inc", vec![]).unwrap();
        read_and_assert_eq(&env, canister_id, 50 + i);
    }

    env.uninstall_code(canister_id).unwrap();
}

#[test]
fn can_reset_stable_memory() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // One canister with some data.
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.stable_memory.page_map.update(&[
            (PageIndex::new(0), &[99u8; PAGE_SIZE]),
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(2), &[99u8; PAGE_SIZE]),
            (PageIndex::new(3), &[99u8; PAGE_SIZE]),
            (PageIndex::new(4), &[99u8; PAGE_SIZE]),
            (PageIndex::new(5), &[99u8; PAGE_SIZE]),
            (PageIndex::new(6), &[99u8; PAGE_SIZE]),
            (PageIndex::new(7), &[99u8; PAGE_SIZE]),
        ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        // Check the data is written to disk.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(stable_memory_size(&canister_layout) >= 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();

        // Wipe data and write different data
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.stable_memory =
            Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));
        execution_state.stable_memory.page_map.update(&[
            (PageIndex::new(0), &[100u8; PAGE_SIZE]),
            (PageIndex::new(1), &[100u8; PAGE_SIZE]),
        ]);

        // Check no remnants of the old data remain.
        assert_eq!(
            execution_state
                .stable_memory
                .page_map
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            execution_state
                .stable_memory
                .page_map
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check file in checkpoint does not contain old data by checking its size.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(stable_memory_size(&canister_layout) < 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();

        // Check again after checkpoint that no remnants of old data remain.
        assert_eq!(
            execution_state
                .stable_memory
                .page_map
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            execution_state
                .stable_memory
                .page_map
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        // Wipe data completely.
        execution_state.stable_memory =
            Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // File should be empty after wiping and checkpoint.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert_eq!(stable_memory_size(&canister_layout), 0);

        assert_error_counters(metrics);
    });
}

#[test]
fn can_reset_wasm_chunk_store() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // One canister with some data.
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .update(&[
                (PageIndex::new(0), &[99u8; PAGE_SIZE]),
                (PageIndex::new(1), &[99u8; PAGE_SIZE]),
                (PageIndex::new(2), &[99u8; PAGE_SIZE]),
                (PageIndex::new(3), &[99u8; PAGE_SIZE]),
                (PageIndex::new(4), &[99u8; PAGE_SIZE]),
                (PageIndex::new(5), &[99u8; PAGE_SIZE]),
                (PageIndex::new(6), &[99u8; PAGE_SIZE]),
                (PageIndex::new(7), &[99u8; PAGE_SIZE]),
            ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        // Check the data is written to disk.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(wasm_chunk_store_size(&canister_layout) >= 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();

        // Wipe data and write different data.
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state.system_state.wasm_chunk_store = WasmChunkStore::new_for_testing();
        canister_state
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .update(&[
                (PageIndex::new(0), &[100u8; PAGE_SIZE]),
                (PageIndex::new(1), &[100u8; PAGE_SIZE]),
            ]);

        // Check no remnants of the old data remain.
        assert_eq!(
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map()
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map()
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check file in checkpoint does not contain old data by checking its size.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert!(wasm_chunk_store_size(&canister_layout) < 8 * PAGE_SIZE as u64);

        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();

        // Check again after checkpoint that no remnants of old data remain.
        assert_eq!(
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map()
                .get_page(PageIndex::new(1)),
            &[100u8; PAGE_SIZE]
        );
        assert_eq!(
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map()
                .get_page(PageIndex::new(300)),
            &[0u8; PAGE_SIZE]
        );

        // Wipe data completely.
        canister_state.system_state.wasm_chunk_store = WasmChunkStore::new_for_testing();

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // File should be empty after wiping and checkpoint.
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        assert_eq!(wasm_chunk_store_size(&canister_layout), 0);

        assert_error_counters(metrics);
    });
}

#[test]
fn can_delete_canister() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // Insert a canister and a write checkpoint
        insert_dummy_canister(&mut state, canister_test_id(100));

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check the checkpoint has the canister.
        let canister_path = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .raw_path();
        assert!(std::fs::metadata(canister_path).unwrap().is_dir());

        let (_height, mut state) = state_manager.take_tip();

        // Delete the canister
        let _deleted_canister = state.take_canister_state(&canister_test_id(100));

        // Commit two rounds, once without checkpointing and once with
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check that the checkpoint does not contain the canister
        assert!(
            !state_manager
                .state_layout()
                .checkpoint_verified(height(3))
                .unwrap()
                .canister(&canister_test_id(100))
                .unwrap()
                .raw_path()
                .exists()
        );

        assert_error_counters(metrics);
    });
}

#[test]
fn can_uninstall_code() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // Insert a canister a write checkpoint
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);
        execution_state.stable_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check the checkpoint has the canister
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        let canister_path = canister_layout.raw_path();
        assert!(std::fs::metadata(canister_path).unwrap().is_dir());

        // WASM binary, WASM memory and stable memory should all be present.
        assert_ne!(vmemory_size(&canister_layout), 0);
        assert_ne!(stable_memory_size(&canister_layout), 0);
        assert!(canister_layout.wasm().raw_path().exists());

        let (_height, mut state) = state_manager.take_tip();

        // Remove the execution state
        state
            .canister_state_mut(&canister_test_id(100))
            .unwrap()
            .execution_state = None;

        // Commit two rounds, once without checkpointing and once with
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);

        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check that the checkpoint does contains the canister
        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();

        assert!(canister_layout.raw_path().exists());

        // WASM and stable memory should be empty after checkpoint.
        assert_eq!(vmemory_size(&canister_layout), 0);
        assert_eq!(stable_memory_size(&canister_layout), 0);
        // WASM binary should be missing
        assert!(!canister_layout.wasm().raw_path().exists());

        assert_error_counters(metrics);
    });
}

#[test]
fn can_uninstall_code_state_machine() {
    let env = StateMachineBuilder::new().build();
    let layout = env.state_manager.state_layout();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    read_and_assert_eq(&env, canister_id, 0);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    read_and_assert_eq(&env, canister_id, 1);
    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();

    env.set_checkpoints_enabled(true);
    env.tick();
    env.state_manager.flush_tip_channel();

    let canister_layout = layout
        .checkpoint_verified(*layout.checkpoint_heights().unwrap().last().unwrap())
        .unwrap()
        .canister(&canister_id)
        .unwrap();
    assert!(canister_layout.wasm().raw_path().exists());
    assert_ne!(vmemory_size(&canister_layout), 0);
    assert_ne!(stable_memory_size(&canister_layout), 0);

    env.uninstall_code(canister_id).unwrap();

    env.state_manager.flush_tip_channel();
    let canister_layout = layout
        .checkpoint_verified(*layout.checkpoint_heights().unwrap().last().unwrap())
        .unwrap()
        .canister(&canister_id)
        .unwrap();
    assert!(!canister_layout.wasm().raw_path().exists());
    assert_eq!(vmemory_size(&canister_layout), 0);
    assert_eq!(stable_memory_size(&canister_layout), 0);
}

#[test]
fn tip_is_initialized_correctly() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // One canister with some data
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(1), &[99u8; PAGE_SIZE])]);
        execution_state
            .stable_memory
            .page_map
            .update(&[(PageIndex::new(1), &[99u8; PAGE_SIZE])]);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);

        state_manager.flush_tip_channel();

        let tip_layout = CheckpointLayout::<ReadOnly>::new_untracked(
            state_manager.state_layout().raw_path().join("tip"),
            height(1),
        )
        .unwrap();

        // No protobuf files in the tip
        assert!(!tip_layout.system_metadata().raw_path().exists());
        assert!(!tip_layout.subnet_queues().raw_path().exists());
        assert_eq!(tip_layout.canister_ids().unwrap().len(), 1);
        let canister_layout = tip_layout
            .canister(&tip_layout.canister_ids().unwrap()[0])
            .unwrap();
        assert!(!canister_layout.queues().raw_path().exists());
        assert!(canister_layout.wasm().raw_path().exists());
        assert!(
            canister_layout.vmemory_0().base().exists()
                || canister_layout.vmemory_0().existing_overlays().unwrap()[0].exists()
        );
        assert!(
            canister_layout.stable_memory().base().exists()
                || canister_layout.stable_memory().existing_overlays().unwrap()[0].exists()
        );

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        let checkpoint_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap();

        // All files are in the checkpoint
        assert!(checkpoint_layout.system_metadata().raw_path().exists());
        assert!(!checkpoint_layout.subnet_queues().raw_path().exists()); // empty
        assert_eq!(checkpoint_layout.canister_ids().unwrap().len(), 1);
        let canister_layout = checkpoint_layout
            .canister(&checkpoint_layout.canister_ids().unwrap()[0])
            .unwrap();
        assert!(!canister_layout.queues().raw_path().exists()); // empty
        assert!(canister_layout.canister().raw_path().exists());
        assert!(canister_layout.wasm().raw_path().exists());
        assert!(
            canister_layout.vmemory_0().base().exists()
                || canister_layout.vmemory_0().existing_overlays().unwrap()[0].exists()
        );
        assert!(
            canister_layout.stable_memory().base().exists()
                || canister_layout.stable_memory().existing_overlays().unwrap()[0].exists()
        );
    });
}

#[test]
fn can_recover_ingress_history() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        let (_height, mut state) = state_manager.take_tip();

        // Add a message to the ingress history, to later verify that it gets recovered.
        state.set_ingress_status(
            message_test_id(7),
            IngressStatus::Known {
                state: IngressState::Done,
                receiver: subnet_test_id(42).get(),
                user_id: user_test_id(1),
                time: ic_types::time::UNIX_EPOCH,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );

        state_manager.commit_and_certify(state.clone(), height(2), CertificationScope::Full, None);
        let (_height, state2) = state_manager.take_tip();
        state
            .metadata
            .prev_state_hash
            .clone_from(&state2.metadata.prev_state_hash);
        assert_eq!(state2, state);
    });
}

/// Check that all the files (i.e. non-directories) with paths starting with provided path are
/// readonly.
fn assert_all_files_are_readonly(path: &Path) {
    if path.is_dir() {
        for entry in path.read_dir().unwrap() {
            assert_all_files_are_readonly(&entry.unwrap().path());
        }
    } else {
        assert!(path.metadata().unwrap().permissions().readonly());
    }
}

/// Check that all checkpoints in `layout` are readonly in the sense that all non-directories are marked readonly.
fn assert_checkpoints_are_readonly(layout: &StateLayout) {
    assert_all_files_are_readonly(&layout.checkpoints())
}

#[test]
fn checkpoints_are_readonly() {
    state_manager_test(|_metrics, state_manager| {
        // We flush the tip channel so that asynchronous tip initialization cannot hide the issue
        state_manager.flush_tip_channel();
        assert_checkpoints_are_readonly(state_manager.state_layout());

        // Add a canister
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(1), &[1u8; PAGE_SIZE])]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert_checkpoints_are_readonly(state_manager.state_layout());

        // Modify the canister
        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(1), &[2u8; PAGE_SIZE])]);

        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata, None);
        state_manager.flush_tip_channel();
        assert_checkpoints_are_readonly(state_manager.state_layout());

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert_checkpoints_are_readonly(state_manager.state_layout());

        // Modify the canister again
        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state
            .wasm_memory
            .page_map
            .update(&[(PageIndex::new(1), &[4u8; PAGE_SIZE])]);

        state_manager.commit_and_certify(state, height(4), CertificationScope::Full, None);
        state_manager.flush_tip_channel();
        assert_checkpoints_are_readonly(state_manager.state_layout());
    });
}

#[test]
fn can_merge_unexpected_number_of_files() {
    state_manager_restart_test_with_lsmt(
        lsmt_with_sharding(),
        |_metrics, state_manager, restart_fn| {
            let (_height, mut state) = state_manager.take_tip();

            insert_dummy_canister(&mut state, canister_test_id(1));
            let canister_state = state.canister_state_mut(&canister_test_id(1)).unwrap();
            let execution_state = canister_state.execution_state.as_mut().unwrap();

            const NUM_PAGES: usize = 100;
            for page in 0..NUM_PAGES {
                execution_state
                    .wasm_memory
                    .page_map
                    .update(&[(PageIndex::new(page as u64), &[1u8; PAGE_SIZE])]);
            }

            state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
            const HEIGHT: u64 = 30;
            for i in 2..HEIGHT {
                let (_height, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(i), CertificationScope::Full, None);
            }

            wait_for_checkpoint(&state_manager, height(HEIGHT - 1));
            let pm_layout = state_manager
                .state_layout()
                .checkpoint_verified(height(HEIGHT - 1))
                .unwrap()
                .canister(&canister_test_id(1))
                .unwrap()
                .vmemory_0();
            let existing_overlays = pm_layout.existing_overlays().unwrap();
            assert_eq!(existing_overlays.len(), NUM_PAGES); // single page per shard
            state_manager.flush_tip_channel();

            // Copy each shard for heights 1..HEIGHT; now each file is beyond the hard limit,
            // triggering forced merge for all shards back to one overlay.
            #[allow(clippy::needless_range_loop)]
            for shard in 0..NUM_PAGES {
                assert_eq!(
                    existing_overlays[shard],
                    pm_layout.overlay(height(1), Shard::new(shard as u64))
                );
                for h in 2..HEIGHT {
                    std::fs::copy(
                        &existing_overlays[shard],
                        pm_layout.overlay(height(h), Shard::new(shard as u64)),
                    )
                    .unwrap();
                }
            }
            assert_eq!(
                pm_layout.existing_overlays().unwrap().len(),
                (HEIGHT as usize - 1) * NUM_PAGES
            );
            let (_metrics, state_manager) = restart_fn(state_manager, None, lsmt_with_sharding());
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(HEIGHT), CertificationScope::Full, None);
            wait_for_checkpoint(&state_manager, height(HEIGHT));
            assert_eq!(
                state_manager
                    .state_layout()
                    .checkpoint_verified(height(HEIGHT))
                    .unwrap()
                    .canister(&canister_test_id(1))
                    .unwrap()
                    .vmemory_0()
                    .existing_overlays()
                    .unwrap()
                    .len(),
                NUM_PAGES
            );
        },
    );
}

#[test]
fn batch_summary_is_respected_for_writing_overlay_files() {
    state_manager_restart_test_with_lsmt(
        lsmt_without_sharding(),
        |_metrics, state_manager, _restart_fn| {
            let checkpoint_interval = 200;
            let (_, mut state) = state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(1));
            state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata, None);
            state_manager.flush_tip_channel();

            let tip_layout: CheckpointLayout<ReadOnly> = CheckpointLayout::new_untracked(
                state_manager.state_layout().raw_path().join("tip"),
                height(0),
            )
            .unwrap();
            let tip_vmemory_layout = tip_layout
                .canister(&canister_test_id(1))
                .unwrap()
                .vmemory_0();

            for h in 2_u64..600 {
                let (_, mut state) = state_manager.take_tip();
                let canister_state = state.canister_state_mut(&canister_test_id(1)).unwrap();
                let execution_state = canister_state.execution_state.as_mut().unwrap();
                execution_state
                    .wasm_memory
                    .page_map
                    .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);

                let scope = if h % checkpoint_interval == 0 {
                    CertificationScope::Full
                } else {
                    CertificationScope::Metadata
                };
                let batch_summary = BatchSummary {
                    next_checkpoint_height: height(
                        (h / checkpoint_interval + 1) * checkpoint_interval,
                    ),
                    current_interval_length: height(checkpoint_interval),
                };

                state_manager.commit_and_certify(
                    state,
                    height(h),
                    scope.clone(),
                    Some(batch_summary.clone()),
                );
                state_manager.flush_tip_channel();

                let expect_file = scope == CertificationScope::Full
                    || h + NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY
                        == batch_summary.next_checkpoint_height.get();

                let has_file = tip_vmemory_layout
                    .overlay(height(h), Shard::new(0))
                    .exists();

                assert_eq!(expect_file, has_file);
            }
        },
    );
}

#[test]
fn lsmt_shard_size_is_stable() {
    // Changing shard after LSMT launch is dangerous as it would crash merging older sharded files.
    // Change the config with care.
    assert_eq!(lsmt_config_default().shard_num_pages, 10 * 1024 * 1024);
}

/// Mock version of CanisterManager::load_canister_snapshot that only does the bits relevant to the state manager
fn restore_snapshot(snapshot_id: SnapshotId, canister_id: CanisterId, state: &mut ReplicatedState) {
    let snapshot = state.canister_snapshots.get(snapshot_id).unwrap().clone();
    let mut canister = state.take_canister_state(&canister_id).unwrap();

    canister.system_state.wasm_chunk_store = snapshot.chunk_store().clone();
    canister.execution_state = Some(ExecutionState::new(
        Default::default(),
        WasmBinary::new(snapshot.execution_snapshot().wasm_binary.clone()),
        ExportedFunctions::new(Default::default()),
        Memory::from(&snapshot.execution_snapshot().wasm_memory),
        Memory::from(&snapshot.execution_snapshot().stable_memory),
        Default::default(),
        Default::default(),
    ));

    state
        .metadata
        .unflushed_checkpoint_ops
        .load_snapshot(canister_id, snapshot_id);
    state.put_canister_state(canister);
}

#[test]
fn can_create_and_delete_canister_snapshot() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // Insert a canister and a write checkpoint
        insert_dummy_canister(&mut state, canister_test_id(100));

        let new_snapshot = CanisterSnapshot::from_canister(
            state.canister_state(&canister_test_id(100)).unwrap(),
            state.time(),
        )
        .unwrap();
        let snapshot_id = SnapshotId::from((canister_test_id(100), 0));

        state.take_snapshot(snapshot_id, Arc::new(new_snapshot));

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check the checkpoint has the canister.
        let canister_path = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .raw_path();
        assert!(std::fs::metadata(canister_path.clone()).unwrap().is_dir());

        // Check the checkpoint has the snapshot.
        let snapshot_path = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .snapshot(&snapshot_id)
            .unwrap()
            .raw_path();
        assert!(std::fs::metadata(&snapshot_path).unwrap().is_dir());

        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check the next checkpoint still has the snapshot.
        let snapshot_path = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap()
            .snapshot(&snapshot_id)
            .unwrap()
            .raw_path();
        assert!(std::fs::metadata(&snapshot_path).unwrap().is_dir());

        let (_height, mut state) = state_manager.take_tip();

        state.canister_snapshots.remove(snapshot_id);

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Check the next checkpoint does not contain the snapshot anymore
        let snapshot_path = state_manager
            .state_layout()
            .checkpoint_verified(height(3))
            .unwrap()
            .snapshot(&snapshot_id)
            .unwrap()
            .raw_path();
        assert!(!snapshot_path.exists());
        assert!(!snapshot_path.parent().unwrap().exists());

        assert_error_counters(metrics);
    });
}

#[test]
fn wasm_binaries_can_be_correctly_switched_from_memory_to_checkpoint() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        let canister_id = canister_test_id(100);

        // Insert a canister, create a snapshot from it and write checkpoint
        insert_dummy_canister(&mut state, canister_id);

        let new_snapshot = CanisterSnapshot::from_canister(
            state.canister_state(&canister_id).unwrap(),
            state.time(),
        )
        .unwrap();
        let snapshot_id = SnapshotId::from((canister_id, 0));
        state.take_snapshot(snapshot_id, Arc::new(new_snapshot));

        let canister_wasm_binary = &state
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary;

        let snapshot_wasm_binary = &state
            .canister_snapshots
            .get(snapshot_id)
            .unwrap()
            .execution_snapshot()
            .wasm_binary;

        // Before checkpointing, wasm binaries of both the canister and the snapshot are in memory.
        assert!(!canister_wasm_binary.is_file());
        assert!(!snapshot_wasm_binary.is_file());

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        let checkpoint_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap();
        let canister_layout = checkpoint_layout.canister(&canister_id).unwrap();
        let snapshot_layout = checkpoint_layout.snapshot(&snapshot_id).unwrap();

        let (_height, state) = state_manager.take_tip();

        let canister_wasm_binary = &state
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary;

        let snapshot_wasm_binary = &state
            .canister_snapshots
            .get(snapshot_id)
            .unwrap()
            .execution_snapshot()
            .wasm_binary;

        // After checkpointing, wasm binaries of both the canister and the snapshot are backed by files in checkpoint@1
        // and file contents can be correctly read.
        // Note that `wasm_file_not_loaded_and_path_matches()` needs to be called before `as_slice()`
        // because the path is no longer visible after we load the wasm file and thus cannot be checked.
        assert!(
            canister_wasm_binary
                .wasm_file_not_loaded_and_path_matches(canister_layout.wasm().raw_path())
        );
        assert_eq!(canister_wasm_binary.as_slice(), EMPTY_WASM);

        assert!(
            snapshot_wasm_binary
                .wasm_file_not_loaded_and_path_matches(snapshot_layout.wasm().raw_path())
        );
        assert_eq!(snapshot_wasm_binary.as_slice(), EMPTY_WASM);

        assert_error_counters(metrics);
    });
}

#[test]
fn wasm_binaries_can_be_correctly_switched_from_checkpoint_to_checkpoint() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        let canister_id = canister_test_id(100);

        // Insert a canister and a write checkpoint
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        let canister_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(1))
            .unwrap()
            .canister(&canister_id)
            .unwrap();

        let (_height, mut state) = state_manager.take_tip();

        let canister_wasm_binary = &state
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary;

        // After checkpointing at height 1, wasm binary the canister is backed by file in checkpoint@1.
        assert!(
            canister_wasm_binary
                .wasm_file_not_loaded_and_path_matches(canister_layout.wasm().raw_path())
        );
        assert_eq!(canister_wasm_binary.as_slice(), EMPTY_WASM);

        // We create a snapshot from the canister, which already has wasm binary backed by file on disk.
        let new_snapshot = CanisterSnapshot::from_canister(
            state.canister_state(&canister_id).unwrap(),
            state.time(),
        )
        .unwrap();
        let snapshot_id = SnapshotId::from((canister_id, 0));
        state.take_snapshot(snapshot_id, Arc::new(new_snapshot));

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full, None);
        state_manager.flush_tip_channel();

        // Remove checkpoint@1
        drop(canister_layout);
        state_manager.remove_states_below(height(2));
        state_manager.flush_deallocation_channel();

        let checkpoint_layout = state_manager
            .state_layout()
            .checkpoint_verified(height(2))
            .unwrap();

        let canister_layout = checkpoint_layout.canister(&canister_id).unwrap();
        let snapshot_layout = checkpoint_layout.snapshot(&snapshot_id).unwrap();

        let (_height, state) = state_manager.take_tip();

        let canister_wasm_binary = &state
            .canister_state(&canister_id)
            .unwrap()
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary;

        let snapshot_wasm_binary = &state
            .canister_snapshots
            .get(snapshot_id)
            .unwrap()
            .execution_snapshot()
            .wasm_binary;

        // After checkpointing at height 2, wasm binaries of both the canister and the snapshot are backed by files in checkpoint@2
        // and file contents can be correctly read.
        assert!(
            canister_wasm_binary
                .wasm_file_not_loaded_and_path_matches(canister_layout.wasm().raw_path())
        );
        assert_eq!(canister_wasm_binary.as_slice(), EMPTY_WASM);

        assert!(
            snapshot_wasm_binary
                .wasm_file_not_loaded_and_path_matches(snapshot_layout.wasm().raw_path())
        );
        assert_eq!(snapshot_wasm_binary.as_slice(), EMPTY_WASM);

        assert_error_counters(metrics);
    });
}

#[test]
fn can_create_and_restore_snapshot() {
    fn can_create_and_restore_snapshot_impl(certification_scope: CertificationScope) {
        state_manager_test(|metrics, state_manager| {
            let canister_id = canister_test_id(100);

            // Install a canister and give it some initial state
            let (_height, mut state) = state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_id);
            let canister_state = state.canister_state_mut(&canister_id).unwrap();
            let execution_state = canister_state.execution_state.as_mut().unwrap();
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);
            execution_state
                .stable_memory
                .page_map
                .update(&[(PageIndex::new(0), &[2u8; PAGE_SIZE])]);
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map_mut()
                .update(&[(PageIndex::new(0), &[3u8; PAGE_SIZE])]);
            state_manager.commit_and_certify(state, height(1), certification_scope.clone(), None);

            // Take a snapshot of the canister
            let (_height, mut state) = state_manager.take_tip();
            let new_snapshot = CanisterSnapshot::from_canister(
                state.canister_state(&canister_id).unwrap(),
                state.time(),
            )
            .unwrap();
            let snapshot_id = SnapshotId::from((canister_id, 0));
            state.take_snapshot(snapshot_id, Arc::new(new_snapshot));
            state_manager.commit_and_certify(state, height(2), certification_scope.clone(), None);

            // Modify the canister.
            let (_height, mut state) = state_manager.take_tip();
            let canister_state = state.canister_state_mut(&canister_id).unwrap();
            let execution_state = canister_state.execution_state.as_mut().unwrap();
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(0), &[4u8; PAGE_SIZE])]);
            execution_state
                .stable_memory
                .page_map
                .update(&[(PageIndex::new(0), &[5u8; PAGE_SIZE])]);
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map_mut()
                .update(&[(PageIndex::new(0), &[6u8; PAGE_SIZE])]);
            state_manager.commit_and_certify(state, height(3), certification_scope.clone(), None);

            // Restore the canister.
            let (_height, mut state) = state_manager.take_tip();
            restore_snapshot(snapshot_id, canister_id, &mut state);

            // Verify the correct canister state across a couple of checkpoints.
            let verify_state = |state: &ReplicatedState| {
                let canister_state = state.canister_state(&canister_id).unwrap();
                let execution_state = canister_state.execution_state.as_ref().unwrap();
                assert_eq!(
                    execution_state
                        .wasm_memory
                        .page_map
                        .get_page(PageIndex::new(0)),
                    &[1u8; PAGE_SIZE]
                );
                assert_eq!(
                    execution_state
                        .stable_memory
                        .page_map
                        .get_page(PageIndex::new(0)),
                    &[2u8; PAGE_SIZE]
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .wasm_chunk_store
                        .page_map()
                        .get_page(PageIndex::new(0)),
                    &[3u8; PAGE_SIZE]
                );
            };

            verify_state(&state);
            state_manager.commit_and_certify(state, height(4), CertificationScope::Full, None);

            for h in 5..8 {
                let (_height, state) = state_manager.take_tip();
                verify_state(&state);
                state_manager.commit_and_certify(state, height(h), CertificationScope::Full, None);
            }

            assert_error_counters(metrics);
        });
    }

    // Backup then restore. Two closely related variants, one where everything happens in one checkpoint interval, and one where it
    // happens across checkpoints.
    can_create_and_restore_snapshot_impl(CertificationScope::Metadata);
    can_create_and_restore_snapshot_impl(CertificationScope::Full);
}

#[test]
fn restore_heap_from_snapshot() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    // Snapshot has 1 in the heap counter.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        })
        .unwrap()
        .snapshot_id();

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );

    // We want to test that the snapshot is still the same after checkpointing.
    env.checkpointed_tick();

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    env.checkpointed_tick();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );
}

#[test]
fn restore_stable_memory_from_snapshot() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );

    // Snapshot has 2 in heap and 1 in stable memory
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        })
        .unwrap()
        .snapshot_id();

    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    env.execute_ingress(canister_id, "load", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );

    // We want to test that the snapshot is still the same after checkpointing.
    env.checkpointed_tick();

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    env.execute_ingress(canister_id, "load", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    env.checkpointed_tick();
    env.execute_ingress(canister_id, "load", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );
}

#[test]
fn restore_binary_from_snapshot() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    // Snapshot is running TEST_CANISTER.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        })
        .unwrap()
        .snapshot_id();

    env.upgrade_canister(canister_id, EMPTY_WASM.to_vec(), vec![])
        .unwrap();
    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.upgrade_canister(canister_id, EMPTY_WASM.to_vec(), vec![])
        .unwrap();
    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);

    // We want to test that the snapshot is still the same after checkpointing.
    env.checkpointed_tick();

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(1_i32.to_le_bytes().to_vec())
    );

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    env.checkpointed_tick();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(2_i32.to_le_bytes().to_vec())
    );
}

#[test]
fn restore_chunk_store_from_snapshot() {
    let env = StateMachineBuilder::new().build();
    env.set_checkpoints_enabled(false);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(0_i32.to_le_bytes().to_vec())
    );

    let chunk_hash = env
        .upload_chunk(UploadChunkArgs {
            canister_id: canister_id.into(),
            chunk: EMPTY_WASM.to_vec(),
        })
        .unwrap()
        .hash;

    // Snapshot contains the EMPTY_WASM in the wasm chunk store, but TEST_CANISTER as binary.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.into(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        })
        .unwrap()
        .snapshot_id();

    env.install_chunked_code(InstallChunkedCodeArgs::new(
        CanisterInstallModeV2::Upgrade(None),
        canister_id,
        None,
        vec![chunk_hash.clone()],
        empty_wasm().module_hash().to_vec(),
        vec![],
    ))
    .unwrap();

    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);

    env.clear_chunk_store(canister_id).unwrap();
    assert!(
        env.install_chunked_code(InstallChunkedCodeArgs::new(
            CanisterInstallModeV2::Upgrade(None),
            canister_id,
            None,
            vec![chunk_hash.clone()],
            empty_wasm().module_hash().to_vec(),
            vec![],
        ))
        .is_err()
    );

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(0_i32.to_le_bytes().to_vec())
    );

    env.install_chunked_code(InstallChunkedCodeArgs::new(
        CanisterInstallModeV2::Upgrade(None),
        canister_id,
        None,
        vec![chunk_hash.clone()],
        empty_wasm().module_hash().to_vec(),
        vec![],
    ))
    .unwrap();

    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);

    env.clear_chunk_store(canister_id).unwrap();
    assert!(
        env.install_chunked_code(InstallChunkedCodeArgs::new(
            CanisterInstallModeV2::Upgrade(None),
            canister_id,
            None,
            vec![chunk_hash.clone()],
            empty_wasm().module_hash().to_vec(),
            vec![],
        ))
        .is_err()
    );

    // We want to test that the snapshot is still the same after checkpointing.
    env.checkpointed_tick();

    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        snapshot_id,
        None,
    ))
    .unwrap();
    assert_eq!(
        env.execute_ingress(canister_id, "read", vec![],).unwrap(),
        WasmResult::Reply(0_i32.to_le_bytes().to_vec())
    );

    env.install_chunked_code(InstallChunkedCodeArgs::new(
        CanisterInstallModeV2::Upgrade(None),
        canister_id,
        None,
        vec![chunk_hash],
        empty_wasm().module_hash().to_vec(),
        vec![],
    ))
    .unwrap();

    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);
    env.checkpointed_tick();
    assert!(env.execute_ingress(canister_id, "read", vec![],).is_err(),);
}

/// Simplified version of canister migration that only does the parts relevant to the state manager.
fn migrate_canister(state: &mut ReplicatedState, old_id: CanisterId, new_id: CanisterId) {
    // Take canister out.
    let mut canister = state.take_canister_state(&old_id).unwrap();

    canister.system_state.canister_id = new_id;
    state
        .metadata
        .unflushed_checkpoint_ops
        .rename_canister(old_id, new_id);

    // Put canister with the new id
    state.put_canister_state(canister);
}

#[test]
fn can_rename_canister() {
    fn can_rename_canister_impl(certification_scope: CertificationScope) {
        state_manager_test(|_metrics, state_manager| {
            let canister_id = canister_test_id(100);
            let new_canister_id = canister_test_id(101);

            // Install a canister and give it some initial state
            let (_height, mut state) = state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_id);
            let canister_state = state.canister_state_mut(&canister_id).unwrap();
            let execution_state = canister_state.execution_state.as_mut().unwrap();
            execution_state
                .wasm_memory
                .page_map
                .update(&[(PageIndex::new(0), &[1u8; PAGE_SIZE])]);
            execution_state
                .stable_memory
                .page_map
                .update(&[(PageIndex::new(0), &[2u8; PAGE_SIZE])]);
            canister_state
                .system_state
                .wasm_chunk_store
                .page_map_mut()
                .update(&[(PageIndex::new(0), &[3u8; PAGE_SIZE])]);
            state_manager.commit_and_certify(state, height(1), certification_scope.clone(), None);

            let (_height, mut state) = state_manager.take_tip();
            migrate_canister(&mut state, canister_id, new_canister_id);

            // Take a snapshot to make sure we can do both in the same round.
            let new_snapshot = CanisterSnapshot::from_canister(
                state.canister_state(&new_canister_id).unwrap(),
                state.time(),
            )
            .unwrap();
            let snapshot_id = SnapshotId::from((new_canister_id, 0));
            state.take_snapshot(snapshot_id, Arc::new(new_snapshot));

            // Trigger a flush either at the checkpoint or by committing exactly
            // `NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY` rounds before the checkpoint.
            if certification_scope == CertificationScope::Full {
                state_manager.commit_and_certify(
                    state,
                    height(2),
                    certification_scope.clone(),
                    None,
                );
            } else {
                state_manager.commit_and_certify(
                    state,
                    height(2),
                    certification_scope.clone(),
                    Some(BatchSummary {
                        next_checkpoint_height: height(
                            2 + NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY,
                        ),
                        current_interval_length: height(500),
                    }),
                );
            }
            state_manager.flush_tip_channel();
            let tip = CheckpointLayout::<ReadOnly>::new_untracked(
                state_manager.state_layout().raw_path().join("tip"),
                height(0),
            )
            .unwrap();
            assert_eq!(tip.canister_ids().unwrap(), vec![new_canister_id]);
            assert_eq!(tip.snapshot_ids().unwrap(), vec![snapshot_id]);
            let (_height, state) = state_manager.take_tip();
            assert!(state.system_metadata().unflushed_checkpoint_ops.is_empty());
        });
    }
    can_rename_canister_impl(CertificationScope::Metadata);
    can_rename_canister_impl(CertificationScope::Full);
}

#[test_strategy::proptest]
fn stream_store_encode_decode(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        None,
        /* certification verification should succeed  */
        true,
        /* modification between encoding and decoding  */
        |_state_manager, slice| {
            // we do not modify the slice before decoding it again - so this should succeed
            slice
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InvalidSignature")]
fn stream_store_decode_with_modified_hash_fails(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        None,
        /* certification verification should succeed  */
        true,
        /* modification between encoding and decoding  */
        |_state_manager, mut slice| {
            let mut hash = slice.certification.signed.content.hash.get();
            *hash.0.first_mut().unwrap() = hash.0.first().unwrap().overflowing_add(1).0;
            slice.certification.signed.content.hash = CryptoHashOfPartialState::from(hash);

            slice
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "Failed to deserialize witness")]
fn stream_store_decode_with_empty_witness_fails(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        None,
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding  */
        |_state_manager, mut slice| {
            slice.merkle_proof = vec![];
            slice
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InconsistentPartialTree")]
fn stream_store_decode_slice_push_additional_message(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        None,
        /* custom destination subnet */
        None,
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding */
        |state_manager, slice| {
            /* generate replacement stream for slice.payload  */
            modify_encoded_stream_helper(state_manager, slice, |decoded_slice| {
                let mut messages = match decoded_slice.messages() {
                    None => StreamIndexedQueue::default(),
                    Some(messages) => messages.clone(),
                };

                let req = RequestBuilder::default()
                    .sender(CanisterId::unchecked_from_principal(
                        PrincipalId::try_from(&[2][..]).unwrap(),
                    ))
                    .receiver(CanisterId::unchecked_from_principal(
                        PrincipalId::try_from(&[3][..]).unwrap(),
                    ))
                    .method_name("test".to_string())
                    .sender_reply_callback(CallbackId::from(999))
                    .build();

                messages.push(req.into());

                let signals_end = decoded_slice.header().signals_end();

                Stream::new(messages, signals_end)
            })
        },
    );
}

/// Depending on the specific input, may fail with either `InvalidSignature` or
/// `InconsistentPartialTree`. Hence, only a generic `should_panic`.
#[test_strategy::proptest]
#[should_panic]
fn stream_store_decode_slice_modify_message_begin(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        None,
        /* custom destination subnet */
        None,
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding  */
        |state_manager, slice| {
            /* generate replacement stream for slice.payload  */
            modify_encoded_stream_helper(state_manager, slice, |decoded_slice| {
                let mut messages = StreamIndexedQueue::with_begin(StreamIndex::from(99999));
                let signals_end = decoded_slice.header().signals_end();

                if let Some(decoded_messages) = decoded_slice.messages() {
                    for (_index, msg) in decoded_messages.iter() {
                        messages.push(msg.clone());
                    }
                }

                Stream::new(messages, signals_end)
            })
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InvalidSignature")]
fn stream_store_decode_slice_modify_signals_end(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        None,
        /* custom destination subnet */
        None,
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding  */
        |state_manager, slice| {
            /* generate replacement stream for slice.payload  */
            modify_encoded_stream_helper(state_manager, slice, |decoded_slice| {
                let messages = decoded_slice
                    .messages()
                    .unwrap_or(&StreamIndexedQueue::default())
                    .clone();
                let signals_end = decoded_slice.header().signals_end() + 99999.into();

                Stream::new(messages, signals_end)
            })
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InvalidSignature")]
fn stream_store_decode_slice_push_signal(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        None,
        /* custom destination subnet */
        None,
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding  */
        |state_manager, slice| {
            /* generate replacement stream for slice.payload  */
            modify_encoded_stream_helper(state_manager, slice, |decoded_slice| {
                let messages = decoded_slice
                    .messages()
                    .unwrap_or(&StreamIndexedQueue::default())
                    .clone();
                let mut signals_end = decoded_slice.header().signals_end();

                signals_end.inc_assign();

                Stream::new(messages, signals_end)
            })
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InvalidDestination")]
fn stream_store_decode_with_invalid_destination(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        Some(subnet_test_id(1)),
        /* certification verification should succeed */
        true,
        /* modification between encoding and decoding  */
        |_state_manager, slice| {
            // Do not modify the slice before decoding it again - the wrong
            // destination subnet should already make it fail
            slice
        },
    );
}

#[test_strategy::proptest]
#[should_panic(expected = "InvalidSignature")]
fn stream_store_decode_with_rejecting_verifier(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        None,
        /* certification verification should fail */
        false,
        /* modification between encoding and decoding  */
        |_state_manager, slice| {
            // Do not modify the slice before decoding it again - the signature validation
            // failure caused by passing the `RejectingVerifier` should already make it fail.
            slice
        },
    );
}

/// If both signature verification and slice decoding would fail, we expect to
/// see an error about the former.
#[test_strategy::proptest]
#[should_panic(expected = "InvalidSignature")]
fn stream_store_decode_with_invalid_destination_and_rejecting_verifier(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..20usize)] size_limit: usize,
) {
    encode_decode_stream_test(
        /* stream to be used */
        stream,
        /* size limit used upon encoding */
        Some(size_limit),
        /* custom destination subnet */
        Some(subnet_test_id(1)),
        /* certification verification should fail  */
        false,
        /* modification between encoding and decoding  */
        |_state_manager, slice| {
            // Do not modify the slice, the wrong destination subnet and rejecting verifier
            // should make it fail regardless.
            slice
        },
    );
}

#[test_strategy::proptest]
fn stream_store_encode_partial(
    #[strategy(arb_stream_slice(
        1, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    test_slice: (Stream, StreamIndex, usize),
    #[strategy(0..1000usize)] byte_limit: usize,
) {
    let (stream, begin, count) = test_slice;
    // Partial slice with messages beginning at `begin + 1`.
    encode_partial_slice_test(stream, begin, begin.increment(), count - 1, byte_limit);
}

// 1 test case is sufficient to test index validation.
#[test_strategy::proptest(ProptestConfig::with_cases(1))]
#[should_panic(expected = "failed to encode certified stream: InvalidSliceIndices")]
fn stream_store_encode_partial_bad_indices(
    #[strategy(arb_stream_slice(
        1, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    test_slice: (Stream, StreamIndex, usize),
    #[strategy(0..1000usize)] byte_limit: usize,
) {
    let (stream, begin, count) = test_slice;
    // `witness_begin` (`== begin + 1`) after `msg_begin` (`== begin`).
    encode_partial_slice_test(stream, begin.increment(), begin, count, byte_limit);
}

/// Test if query stats are correctly aggregated into the canister state.
///
/// Delivers QUERY_STATS_EPOCH_LENGTH batches with query stats. This will
/// trigger exactly one aggregation.
///
/// This test also tests that stats for non-existing canisters are simply ignored.
///
/// It also assumes NUM_MALICIOUS malicious nodes, which send bogus values, which
/// do not impact the values added to the canister state.
#[test]
fn query_stats_are_collected() {
    let mut env = StateMachineBuilder::new().build();
    let query_stats_epoch_length = ic_config::execution_environment::QUERY_STATS_EPOCH_LENGTH;

    const INITIAL_VALUES: u128 = 42;

    const NUM_NODES: usize = 13;
    const NUM_MALICIOUS: usize = 4;
    let proposers: Vec<NodeId> = (0..NUM_NODES)
        .map(|i| NodeId::from(PrincipalId::new_node_test_id(i as u64)))
        .collect();

    // Install two canister
    let test_canister_id = env.install_canister_wat(TEST_CANISTER, vec![1], None);

    // Install a canister for which only malicious nodes will attempt to charge
    // Send a different payload to ensure the ingress message gets executed.
    let malicious_overreporting = env.install_canister_wat(TEST_CANISTER, vec![2], None);
    let malicious_underreporting = env.install_canister_wat(TEST_CANISTER, vec![3], None);

    // Set initial query stats for all canisters
    for canister in [
        &test_canister_id,
        &malicious_overreporting,
        &malicious_underreporting,
    ] {
        env.set_query_stats(
            canister,
            TotalQueryStats {
                num_calls: INITIAL_VALUES,
                num_instructions: INITIAL_VALUES,
                ingress_payload_size: INITIAL_VALUES,
                egress_payload_size: INITIAL_VALUES,
            },
        );
    }

    // Create a fake canister ID. This canister should not be part of the replicated state.
    // The ID choosen here has to be larger than the number of canister installed above.
    let uninstalled_canister = canister_test_id(1337);

    // Verify initial state of the query stats
    fn check_query_stats_unmodified(env: &StateMachine, canister_id: &CanisterId) {
        let canister_state = env.query_stats(canister_id);
        assert!(canister_state.num_calls == INITIAL_VALUES);
        assert!(canister_state.num_instructions == INITIAL_VALUES);
        assert!(canister_state.ingress_payload_size == INITIAL_VALUES);
        assert!(canister_state.egress_payload_size == INITIAL_VALUES);
    }

    // Run for an entire epoch and then deliver `NUM_NODES` more batches to ensure query stats get aggregated to the canister state.
    // In practise, some batches have already been delivered (e.g. ingress messages for canister installation).
    for i in 0..query_stats_epoch_length as usize + NUM_NODES {
        let mut stats = vec![];

        // Append query stats the first time each node is a block maker.
        if i < NUM_NODES {
            stats.push(CanisterQueryStats {
                canister_id: test_canister_id,
                stats: QueryStats {
                    num_calls: if i < NUM_MALICIOUS {
                        1337 // "Malicious" nodes send too large values, but that should not affect what is being charged
                    } else {
                        1
                    },
                    num_instructions: 2,
                    ingress_payload_size: 3,
                    egress_payload_size: 4,
                },
            });

            // This canister does not exist in the replicated state.
            // We simply want to make sure nothing crashes in the case where we have stats for a canister
            // that does not exist (e.g. it got uninstalled).
            stats.push(CanisterQueryStats {
                canister_id: uninstalled_canister,
                stats: QueryStats {
                    num_calls: 1,
                    num_instructions: 2,
                    ingress_payload_size: 3,
                    egress_payload_size: 4,
                },
            });

            if i < NUM_MALICIOUS {
                // Simulate malicious nodes sending stats for a canister that does not execute any queries
                stats.push(CanisterQueryStats {
                    canister_id: malicious_overreporting,
                    stats: QueryStats {
                        num_calls: 1,
                        num_instructions: 2,
                        ingress_payload_size: 3,
                        egress_payload_size: 4,
                    },
                });
            } else {
                // Simulate malicious nodes not sending (under-reporting) stats for a canister that does execute queries
                stats.push(CanisterQueryStats {
                    canister_id: malicious_underreporting,
                    stats: QueryStats {
                        num_calls: 1,
                        num_instructions: 2,
                        ingress_payload_size: 3,
                        egress_payload_size: 4,
                    },
                });
            }
        }

        let height = env.deliver_query_stats(QueryStatsPayload {
            proposer: proposers[i % NUM_NODES],
            stats,
            epoch: epoch_from_height(Height::from(i as u64), query_stats_epoch_length),
        });

        if height.get() < query_stats_epoch_length {
            // Query stats in the canister state should only be changed after more than QUERY_STATS_EPOCH_LENGTH batches.
            // have been delivered. Before, they should be unchanged.
            println!("Checking query stats in round {i}");
            check_query_stats_unmodified(&env, &test_canister_id);
            check_query_stats_unmodified(&env, &malicious_overreporting);
            check_query_stats_unmodified(&env, &malicious_underreporting);
        }
    }

    // As each proposer in that epoch proposed the same value, we should see that value * 13 in the canister state
    // after one epoch.
    // The same should be the case even for canister where malicious nodes have not been sending query stats.
    for canister in [&test_canister_id, &malicious_underreporting] {
        let canister_state = env.query_stats(canister);
        assert!(canister_state.num_calls == NUM_NODES as u128 + INITIAL_VALUES);
        assert!(canister_state.num_instructions == 2 * NUM_NODES as u128 + INITIAL_VALUES);
        assert!(canister_state.ingress_payload_size == 3 * NUM_NODES as u128 + INITIAL_VALUES);
        assert!(canister_state.egress_payload_size == 4 * NUM_NODES as u128 + INITIAL_VALUES);
    }

    // The imbalanced canister should not have been charged, as only malicious nodes
    // (incorrectly) report query statistics for this canister.
    check_query_stats_unmodified(&env, &malicious_overreporting);
}

/// An operation against a state machine running a single `TEST_CANISTER`,
/// including various update calls, checkpointing, canister upgrades and replica upgrades
/// with different LSMT flags.
#[derive(Clone, Debug)]
enum TestCanisterOp {
    UpdateCall(&'static str),
    TriggerMerge,
    CanisterUpgrade,
    CanisterReinstall,
    Checkpoint,
    Restart,
}

/// A strategy with an arbitrary enum element, including a selection of update functions
/// on TEST_CANISTER.
fn arbitrary_test_canister_op() -> impl Strategy<Value = TestCanisterOp> {
    prop_oneof! {
        Just(TestCanisterOp::UpdateCall("inc")),
        Just(TestCanisterOp::UpdateCall("persist")),
        Just(TestCanisterOp::UpdateCall("load")),
        Just(TestCanisterOp::UpdateCall("write_heap_64k")),
        Just(TestCanisterOp::UpdateCall("write_heap_60k")),
        Just(TestCanisterOp::TriggerMerge),
        Just(TestCanisterOp::CanisterUpgrade),
        Just(TestCanisterOp::CanisterReinstall),
        Just(TestCanisterOp::Checkpoint),
        Just(TestCanisterOp::Restart),
    }
}

#[test_strategy::proptest(ProptestConfig {
    // Fork to prevent flaky timeouts due to closed sandbox fds
    fork: true,
    // We go for fewer, but longer runs
    ..ProptestConfig::with_cases(5)
})]
fn random_canister_input(
    #[strategy(proptest::collection::vec(arbitrary_test_canister_op(), 1..50))] ops: Vec<
        TestCanisterOp,
    >,
) {
    /// Execute op against the state machine `env`
    fn execute_op(env: StateMachine, canister_id: CanisterId, op: TestCanisterOp) -> StateMachine {
        match op {
            TestCanisterOp::UpdateCall(func) => {
                env.execute_ingress(canister_id, func, vec![]).unwrap();
                env
            }
            TestCanisterOp::TriggerMerge => {
                // This writes 10 overlay files if LSMT is enabled, so that it has to merge.
                // In principle the same pattern can occur without this op, but this makes
                // it much more likely to be covered each run.
                let mut env = env;
                for _ in 0..10 {
                    env = execute_op(env, canister_id, TestCanisterOp::UpdateCall("inc"));
                    env = execute_op(env, canister_id, TestCanisterOp::Checkpoint);
                }
                env
            }
            TestCanisterOp::CanisterUpgrade => {
                env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);
                env
            }
            TestCanisterOp::CanisterReinstall => {
                env.reinstall_canister_wat(canister_id, TEST_CANISTER, vec![]);
                env.execute_ingress(canister_id, "grow_page", vec![])
                    .unwrap();
                env
            }
            TestCanisterOp::Checkpoint => {
                env.set_checkpoints_enabled(true);
                env.tick();
                env.set_checkpoints_enabled(false);
                env
            }
            TestCanisterOp::Restart => {
                let env = execute_op(env, canister_id, TestCanisterOp::Checkpoint);

                env.restart_node_with_lsmt_override(Some(lsmt_with_sharding()))
            }
        }
    }

    // Setup two state machines with a single TEST_CANISTER installed.
    let mut env = StateMachineBuilder::new()
        .with_lsmt_override(Some(lsmt_with_sharding()))
        .build();

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();

    // Execute all operations the state machine.
    for op in ops {
        env = execute_op(env, canister_id, op.clone());
    }
}
