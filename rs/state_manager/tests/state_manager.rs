use ic_certification_version::{CertificationVersion::V11, CURRENT_CERTIFICATION_VERSION};
use ic_config::state_manager::Config;
use ic_crypto_tree_hash::{
    flatmap, sparse_labeled_tree_from_paths, Label, LabeledTree, MixedHashTree, Path as LabelPath,
};
use ic_ic00_types::{CanisterChangeDetails, CanisterChangeOrigin};
use ic_interfaces::artifact_manager::{ArtifactClient, ArtifactProcessor};
use ic_interfaces::{artifact_pool::UnvalidatedArtifact, certification::Verifier};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_state_manager::*;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map::PageIndex, testing::ReplicatedStateTesting, Memory, NetworkTopology, NumWasmPages,
    PageMap, ReplicatedState, Stream, SubnetTopology,
};
use ic_state_layout::{CheckpointLayout, ReadOnly, SYSTEM_METADATA_FILE};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_state_manager::manifest::{build_meta_manifest, manifest_from_path, validate_manifest};
use ic_state_manager::{DirtyPageMap, FileType, PageMapType, StateManagerImpl};
use ic_sys::PAGE_SIZE;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    mock_time,
    state::{arb_stream, arb_stream_slice, canister_ids},
    types::{
        ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::RequestBuilder,
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, fetch_int_gauge, Labels};
use ic_test_utilities_tmpdir::tmpdir;
use ic_types::{
    artifact::{Priority, StateSyncArtifactId},
    chunkable::{ChunkId, ChunkableArtifact},
    crypto::CryptoHash,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::CallbackId,
    state_sync::{FILE_GROUP_CHUNK_ID_OFFSET, MANIFEST_CHUNK_ID_OFFSET, META_MANIFEST_CHUNK},
    time::Time,
    xnet::{StreamIndex, StreamIndexedQueue},
    CanisterId, CryptoHashOfPartialState, CryptoHashOfState, Height, NodeId, NumBytes, PrincipalId,
};
use nix::sys::time::TimeValLike;
use nix::sys::{
    stat::{utimensat, UtimensatFlags},
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

fn make_mutable(path: &Path) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_all_at(path: &Path, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;

    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;
    f.write_all_at(buf, offset)?;
    Ok(())
}

fn tree_payload(t: MixedHashTree) -> LabeledTree<Vec<u8>> {
    t.try_into().unwrap()
}

fn label<T: Into<Label>>(t: T) -> Label {
    t.into()
}

/// This is a canister that keeps a counter on the heap and allows to increment it.
/// The counter can also be read and persisted to and loaded from stable memory
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
fn skipping_flushing_is_invisible_for_state() {
    fn skips(env: &StateMachine) -> f64 {
        env.metrics_registry()
            .prometheus_registry()
            .gather()
            .into_iter()
            .filter(|x| x.get_name() == "state_manager_page_map_flush_skips")
            .map(|x| x.get_metric()[0].get_counter().get_value())
            .next()
            .unwrap()
    }
    fn execute(block_tip: bool) -> CryptoHashOfState {
        let env = StateMachine::new();
        env.set_checkpoints_enabled(false);

        let canister_id0 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        let canister_id1 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        let canister_id2 = env.install_canister_wat(TEST_CANISTER, vec![], None);

        // One wait occupies the TipHandler thread, the second (nop) makes queue non-empty
        // to cause flush skips. 0-size channel blocks send in the TipHandler until we call recv()
        let (send_wait, recv_wait) = crossbeam_channel::bounded::<()>(0);
        let (send_nop, recv_nop) = crossbeam_channel::unbounded();
        env.state_manager
            .test_only_send_wait_to_tip_channel(send_wait);
        env.state_manager
            .test_only_send_wait_to_tip_channel(send_nop);
        if !block_tip {
            recv_wait.recv().unwrap();
            recv_nop.recv().unwrap();
        }
        let skips_before = skips(&env);
        env.execute_ingress(canister_id0, "inc", vec![]).unwrap();
        env.execute_ingress(canister_id1, "inc", vec![]).unwrap();
        env.execute_ingress(canister_id2, "inc", vec![]).unwrap();

        // Second inc on canister_id0 to trigger overwriting a previously written page.
        env.execute_ingress(canister_id0, "inc", vec![]).unwrap();

        let skips_after = skips(&env);
        if block_tip {
            recv_wait.recv().unwrap();
            recv_nop.recv().unwrap();
        }
        env.set_checkpoints_enabled(true);
        if block_tip {
            assert_eq!(skips_after - skips_before, 4.0)
        } else {
            assert_eq!(skips_after - skips_before, 0.0)
        }
        env.tick();
        read_and_assert_eq(&env, canister_id0, 2);
        read_and_assert_eq(&env, canister_id1, 1);
        read_and_assert_eq(&env, canister_id2, 1);

        let env = env.restart_node();
        env.tick();

        read_and_assert_eq(&env, canister_id0, 2);
        read_and_assert_eq(&env, canister_id1, 1);
        read_and_assert_eq(&env, canister_id2, 1);

        env.await_state_hash()
    }

    assert_eq!(execute(false), execute(true));
}

#[test]
fn rejoining_node_doesnt_accumulate_states() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            for i in 1..=3 {
                let mut state = src_state_manager.take_tip().1;
                insert_dummy_canister(&mut state, canister_test_id(100 + i));
                src_state_manager.commit_and_certify(state, height(i), CertificationScope::Full);
                let time_source = ic_test_utilities::FastForwardTimeSource::new();

                let hash = wait_for_checkpoint(&*src_state_manager, height(i));
                let id = StateSyncArtifactId {
                    height: height(i),
                    hash,
                };
                let msg = src_state_sync
                    .get_validated_by_identifier(&id)
                    .expect("failed to get state sync messages");

                let chunkable = dst_state_sync.create_chunkable_state(&id);
                let dst_msg = pipe_state_sync(msg.clone(), chunkable);
                dst_state_sync.process_changes(
                    time_source.as_ref(),
                    vec![UnvalidatedArtifact {
                        message: dst_msg,
                        peer_id: node_test_id(0),
                        timestamp: mock_time(),
                    }],
                );

                assert_eq!(
                    src_state_manager.get_latest_state().take(),
                    dst_state_manager.get_latest_state().take()
                );
                assert_eq!(
                    dst_state_manager.checkpoint_heights(),
                    (1..=i).map(|i| height(i)).collect::<Vec<_>>()
                );
            }

            dst_state_manager.remove_states_below(height(3));
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let state_manager = restart_fn(state_manager, None);

        // verify we can continue to recovered tip from empty checkpoint
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
    });
}

#[test]
fn tip_can_be_recovered_from_metadata_checkpoint() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let canister_id: CanisterId = canister_test_id(100);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_id);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(300));
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full);

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(2));

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        // Since the canister has no execution state, there should be no stable memory
        // file.
        let state_layout = state_manager.state_layout();
        let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
            state_layout
                .checkpoint(height(1))
                .unwrap()
                .raw_path()
                .to_path_buf(),
            height(1),
        )
        .unwrap();

        let canister_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();
        let canister_stable_memory = canister_layout.stable_memory_blob();
        assert!(!canister_stable_memory.exists());

        let state_manager = restart_fn(state_manager, None);

        let recovered = state_manager.get_latest_state();
        assert_eq!(height(1), recovered.height());
        let state = recovered.take();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert!(canister_state.execution_state.is_none());
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
            .expect_err(&format!("Crash test fixture {} did not crash", i));
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
        state_manager.commit_and_certify(state, HEIGHT, CertificationScope::Full);
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

        state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata);
        assert_eq!(height(1), state_manager.latest_state_height());

        let (_, tip) = state_manager.take_tip();
        state_manager.commit_and_certify(tip, height(2), CertificationScope::Full);
        assert_eq!(height(2), state_manager.latest_state_height());
    })
}

#[test]
fn populates_prev_state_hash() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, state_1) = state_manager.take_tip();
        state_manager.commit_and_certify(state_1, height(2), CertificationScope::Metadata);
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
            "Expected latest state to be < {}, got {}",
            h,
            latest_state
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, mut state) = state_manager.take_tip();
        state.modify_streams(|streams| {
            streams.insert(subnet_test_id(1), Stream::default());
        });
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
    });
}

#[test]
fn can_commit_same_state_twice() {
    state_manager_test(|_metrics, state_manager| {
        let (tip_height, state) = state_manager.take_tip();
        assert_eq!(tip_height, height(0));
        let state_copy = state.clone();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (tip_height, _state) = state_manager.take_tip();
        assert_eq!(tip_height, height(1));
        // _state and state_copy will differ in metadata.prev_state_height,
        // so to commit the same state twice we need to commit the copy.
        state_manager.commit_and_certify(state_copy, height(1), CertificationScope::Metadata);

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

            state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(4), CertificationScope::Metadata);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(5), CertificationScope::Full);

            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(6), CertificationScope::Full);
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
            state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_metrics, state_manager) = restart_fn(state_manager, None);

        wait_for_checkpoint(&state_manager, height(1));
    });
}

#[test]
fn first_manifest_after_restart_is_incremental() {
    state_manager_restart_test_with_metrics(|_metrics, state_manager, restart_fn| {
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        wait_for_checkpoint(&state_manager, height(1));

        let (metrics, state_manager) = restart_fn(state_manager, None);

        wait_for_checkpoint(&state_manager, height(1)); // Make sure the base manifest is available
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
        wait_for_checkpoint(&state_manager, height(2));

        // We detect that the manifest computation was incremental by checking that at least some bytes
        // are either "reused" or "hashed_and_compared"
        let chunk_bytes = fetch_int_counter_vec(&metrics, "state_manager_manifest_chunk_bytes");
        let reused_key = maplit::btreemap! {"type".to_string() => "reused".to_string()};
        let hashed_and_compared_key =
            maplit::btreemap! {"type".to_string() => "hashed_and_compared".to_string()};
        assert_ne!(
            0,
            chunk_bytes[&reused_key] + chunk_bytes[&hashed_and_compared_key]
        );
    });
}

#[test]
fn can_filter_by_certification_mask() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(4), CertificationScope::Full);

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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(4));

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
        state_manager.remove_inmemory_states_below(height(0));

        assert_eq!(state_manager.list_state_heights(CERT_ANY), vec![height(0),],);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(1)],
        );

        state_manager.remove_states_below(height(0));
        state_manager.remove_inmemory_states_below(height(0));

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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(10))
        );

        // We need to wait for hashing to complete, otherwise the
        // checkpoint can be retained until the hashing is complete.
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(20));
        state_manager.remove_inmemory_states_below(height(20));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(10))
        );

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(11), CertificationScope::Metadata);

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(11))
        );

        // 10 is the latest checkpoint, hence cannot have been deleted
        assert!(state_manager
            .list_state_heights(CERT_ANY)
            .contains(&height(10)));

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(20));
        state_manager.remove_inmemory_states_below(height(20));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY).last(),
            Some(&height(11))
        );

        assert!(state_manager
            .list_state_heights(CERT_ANY)
            .contains(&height(10)));
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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        // We need to wait for hashing to complete, otherwise the
        // checkpoint can be retained until the hashing is complete.
        state_manager.flush_tip_channel();

        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.remove_inmemory_states_below(height(6));

        // Only odd heights should have been removed
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(2),
                height(4),
                height(6),
                height(7),
                height(8),
                height(9)
            ],
        );

        state_manager.remove_states_below(height(4));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(4),
                height(6),
                height(7),
                height(8),
                height(9)
            ],
        );

        let state_manager = restart_fn(state_manager, Some(height(6)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(4), height(6)],
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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(10));

        for h in 1..=7 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(8), height(9)],
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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(7));

        for h in 1..6 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        // The checkpoint at height 6 is the latest checkpoint requested to remove.
        // Therefore, it should be kept.
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(6),
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
            state_manager.commit_and_certify(state, *h, scope.clone());
        }

        state_manager.remove_states_below(height(3));

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
            state_manager.commit_and_certify(state, *h, scope.clone());
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
            state_manager.commit_and_certify(state, *h, scope.clone());
        }

        state_manager.remove_states_below(height(3));

        let state_manager = restart_fn(state_manager, Some(height(3)));

        assert_eq!(height(4), state_manager.latest_state_height());
        assert!(state_manager
            .state_layout()
            .backup_heights()
            .unwrap()
            .is_empty());
    });
}

#[test]
fn backup_checkpoint_is_complete() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

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
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata);
            state_manager.remove_states_below(height(i));
        }

        let state_manager = restart_fn(state_manager, Some(height(10)));
        for i in 0..10 {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata);
            state_manager.remove_states_below(height(9));
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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        state_manager.flush_tip_channel();
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);

        for i in 1..20 {
            state_manager.remove_states_below(height(i));
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

            state_manager.commit_and_certify(state, height(i), scope.clone());
        }
        state_manager.flush_tip_channel();
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);

        // Checkpoint @5 is kept because it is the latest checkpoint at or below the
        // requested height 9.
        // Intermediate states from @6 to @8 are purged.
        state_manager.remove_states_below(height(9));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(5),
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

        // Checkpoint @20 is kept because it is the most recent
        // checkpoint. @15 is kept because @19 depends on it.
        // Intermediate states from @16 to @18 are purged.
        state_manager.remove_states_below(height(19));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![
                height(0),
                height(15),
                height(19),
                height(20),
                height(21),
                height(22)
            ],
        );

        // Test calling `remove_states_below` at the latest checkpoint height.
        // Intermediate states from @16 to @19 are purged. @15 is purged, as
        // no inmemory states depend on it anymore.
        state_manager.remove_states_below(height(20));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(20), height(21), height(22)],
        );

        // Test calling `remove_states_below` at the latest state height.
        // The intermediate state @21 is purged.
        state_manager.remove_states_below(height(22));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(20), height(22)],
        );

        // Test calling `remove_states_below` at a higher height than the latest state
        // height.
        // The intermediate state @21 is purged.
        // The latest state should always be kept.
        state_manager.remove_states_below(height(25));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(20), height(22)],
        );
    })
}

#[test]
fn latest_certified_state_is_not_removed() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
        certify_height(&state_manager, height(1));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(4), CertificationScope::Metadata);

        state_manager.flush_tip_channel();
        state_manager.remove_states_below(height(4));
        assert_eq!(height(4), state_manager.latest_state_height());
        assert_eq!(height(1), state_manager.latest_certified_height());

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            // 1 is protected as latest certified state, 2 is protected as latest checkpoint
            vec![height(0), height(1), height(2), height(4)],
        );
    });
}

#[test]
fn can_return_and_remember_certifications() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        certify_height(&state_manager, height(1));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);
        certify_height(&state_manager, height(2));

        assert_eq!(Vec::<Height>::new(), heights_to_certify(&state_manager));

        let state_manager = restart_fn(state_manager, None);

        assert_eq!(height(1), state_manager.latest_state_height());
        let (_height, state) = state_manager.take_tip();
        // Commit the same state again. The certification should be re-used.
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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

        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
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
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let (adverts, _) = state_sync.process_changes(time_source.as_ref(), Default::default());
        assert_eq!(adverts.len(), 1);
        assert_eq!(adverts[0].id, id);
        assert!(state_sync.has_artifact(&id));

        let (adverts, _) = state_sync.process_changes(time_source.as_ref(), Default::default());
        assert_eq!(adverts.len(), 0);
        assert!(state_sync.has_artifact(&id));
    });
}

#[test]
fn recomputes_metadata_on_restart_if_missing() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = state_sync
            .get_validated_by_identifier(&id)
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);

        let priority_fn = state_sync.get_priority_function();
        for (h, p) in [
            (1, Priority::Drop),
            (2, Priority::Drop),
            (3, Priority::Stash),
        ]
        .iter()
        {
            assert_eq!(
                *p,
                priority_fn(
                    &StateSyncArtifactId {
                        height: height(*h),
                        hash: hash(*h as u8),
                    },
                    &()
                )
            );
        }

        // Request fetching of state 3.
        state_manager.fetch_state(height(3), hash(3), Height::new(99));
        let priority_fn = state_sync.get_priority_function();
        // Good hash
        assert_eq!(
            Priority::Fetch,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(3),
                    hash: hash(3),
                },
                &()
            )
        );
        // Wrong hash
        assert_eq!(
            Priority::Drop,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(3),
                    hash: hash(4),
                },
                &()
            )
        );

        // Request fetching of newer state 4.
        state_manager.fetch_state(height(4), hash(4), Height::new(99));
        let priority_fn = state_sync.get_priority_function();
        assert_eq!(
            Priority::Drop,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(3),
                    hash: hash(3),
                },
                &()
            )
        );
        assert_eq!(
            Priority::Fetch,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(4),
                    hash: hash(4),
                },
                &()
            )
        );
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
        fetch_int_gauge(metrics, "state_sync_remaining_chunks").unwrap()
    );
}

#[test]
fn can_do_simple_state_sync_transfer() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let chunkable = dst_state_sync.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);

            let mut tip = dst_state_manager.take_tip().1;
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata.prev_state_hash = state.metadata.prev_state_hash.clone();
            assert_eq!(*state.as_ref(), tip);
            assert_eq!(vec![height(1)], heights_to_certify(&*dst_state_manager));

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

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
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
            CanisterChangeDetails::canister_creation(vec![user_test_id(42).get()]),
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

        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.clone(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");
        assert_error_counters(src_metrics);
        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Not all chunk ids to be omitted will work for the purpose of this test
            // They have to be (1) not included in a file group chunk and (2) not identical
            // to another chunk that is not omitted.
            //
            // Here we choose the `system_metadata.pbuf` because it is never empty and unlikely to be identical to others.
            //   file idx  |  file size | chunk idx |                         path
            // ------------+------------+---------- +------------------------------------------------------
            //           0 |        259 |     0     | canister_states/00000000000000640101/canister.pbuf
            //           1 |          0 |    N/A    | canister_states/00000000000000640101/queues.pbuf
            //           2 |         18 |     1     | canister_states/00000000000000640101/software.wasm
            //           3 |       4096 |     2     | canister_states/00000000000000640101/stable_memory.bin
            //           4 |       4096 |     3     | canister_states/00000000000000640101/vmemory_0.bin
            //           5 |        221 |     4     | canister_states/00000000000000c80101/canister.pbuf
            //           6 |          0 |    N/A    | canister_states/00000000000000c80101/queues.pbuf
            //           7 |         18 |     5     | canister_states/00000000000000c80101/software.wasm
            //           8 |          0 |    N/A    | canister_states/00000000000000c80101/stable_memory.bin
            //           9 |          0 |    N/A    | canister_states/00000000000000c80101/vmemory_0.bin
            //          10 |          0 |    N/A    | ingress_history.pbuf
            //          11 |          0 |    N/A    | subnet_queues.pbuf
            //          12 |         86 |     6     | system_metadata.pbuf
            //
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

            let omit: HashSet<ChunkId> =
                maplit::hashset! {chunk_id_to_omit, ChunkId::new(FILE_GROUP_CHUNK_ID_OFFSET)};

            // First state sync is destroyed before completion
            {
                let mut chunkable = dst_state_sync.create_chunkable_state(&id);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks, and then ask for all chunks afterwards,
                // but never receive the chunk for `system_metadata.pbuf` and FILE_GROUP_CHUNK_ID_OFFSET
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
                assert!(
                    matches!(completion, Err(StateSyncErrorCode::ChunksMoreNeeded)),
                    "Unexpectedly completed state sync"
                );
            }
            assert_no_remaining_chunks(dst_metrics);
            // Second state sync continues from first state and successfully finishes
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(2),
                    hash: hash.clone(),
                };

                let mut chunkable = dst_state_sync.create_chunkable_state(&id);

                let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
                assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));
                let result = pipe_manifest(&msg, &mut *chunkable, false);
                assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

                let file_group_chunks: HashSet<ChunkId> = msg
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
                let dst_msg = pipe_state_sync(msg.clone(), chunkable);
                dst_state_sync.process_changes(
                    time_source.as_ref(),
                    vec![UnvalidatedArtifact {
                        message: dst_msg,
                        peer_id: node_test_id(0),
                        timestamp: mock_time(),
                    }],
                );

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
            // Third state sync can copy all chunks immediately
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(3),
                    hash,
                };

                let mut chunkable = dst_state_sync.create_chunkable_state(&id);

                // The meta-manifest and manifest are enough to complete the sync
                let _res = pipe_meta_manifest(&msg, &mut *chunkable, false);
                let dst_msg = pipe_manifest(&msg, &mut *chunkable, false).unwrap();

                dst_state_sync.process_changes(
                    time_source.as_ref(),
                    vec![UnvalidatedArtifact {
                        message: dst_msg,
                        peer_id: node_test_id(0),
                        timestamp: mock_time(),
                    }],
                );

                let recovered_state = dst_state_manager
                    .get_state_at(height(3))
                    .expect("Destination state manager didn't receive the state")
                    .take();

                assert_eq!(height(3), dst_state_manager.latest_state_height());
                assert_eq!(state, recovered_state);
                assert_eq!(
                    *state.as_ref(),
                    *dst_state_manager.get_latest_state().take()
                );
                assert_eq!(
                    vec![height(2), height(3)],
                    heights_to_certify(&*dst_state_manager)
                );
            }

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
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

        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.clone(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
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
                let mut chunkable = dst_state_sync.create_chunkable_state(&id);

                // First fetch chunk 0 (the meta-manifest) and manifest chunks but never receive chunk(MANIFEST_CHUNK_ID_OFFSET + 1).
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit, false);
                assert!(
                    matches!(completion, Err(StateSyncErrorCode::ChunksMoreNeeded)),
                    "Unexpectedly completed state sync"
                );
            }
            assert_no_remaining_chunks(dst_metrics);
            // Second state sync starts from scratch and successfully finishes
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(2),
                    hash: hash.clone(),
                };

                let mut chunkable = dst_state_sync.create_chunkable_state(&id);

                let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
                assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

                // Chunks in the Prep phase are not involved in the cache mechanism. Therefore, all the manifest chunks have to requested again.
                let manifest_chunks: HashSet<ChunkId> = (MANIFEST_CHUNK_ID_OFFSET
                    ..(MANIFEST_CHUNK_ID_OFFSET + meta_manifest.sub_manifest_hashes.len() as u32))
                    .map(ChunkId::from)
                    .collect();
                assert_eq!(manifest_chunks, chunkable.chunks_to_download().collect());

                let result = pipe_manifest(&msg, &mut *chunkable, false);
                assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

                let dst_msg = pipe_state_sync(msg.clone(), chunkable);
                dst_state_sync.process_changes(
                    time_source.as_ref(),
                    vec![UnvalidatedArtifact {
                        message: dst_msg,
                        peer_id: node_test_id(0),
                        timestamp: mock_time(),
                    }],
                );

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
        let num_canisters = 2000;
        for id in 100..(100 + num_canisters) {
            insert_dummy_canister(&mut state, canister_test_id(id));
        }

        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            // Provide bad meta-manifest to dst
            let mut chunkable = dst_state_sync.create_chunkable_state(&id);
            let result = pipe_meta_manifest(&msg, &mut *chunkable, true);
            assert!(matches!(
                result,
                Err(StateSyncErrorCode::MetaManifestVerificationFailed)
            ));

            // Provide correct meta-manifest to dst
            let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
            assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

            // Provide bad sub-manifests to dst
            // Each time, alter the chunk in the middle of remaining chunks for the current phase. The first half of chunks should be added correctly in this way.
            loop {
                let remaining_chunks_before = chunkable.chunks_to_download().count() as i32;
                let result = pipe_manifest(&msg, &mut *chunkable, true);
                assert!(matches!(
                    result,
                    Err(StateSyncErrorCode::ManifestVerificationFailed)
                ));
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
            assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

            // Provide bad chunks to dst
            // Each time, alter the chunk in the middle of remaining chunks for the current phase. The first half of chunks should be added correctly in this way.
            loop {
                let remaining_chunks_before = chunkable.chunks_to_download().count() as i32;
                let result =
                    pipe_partial_state_sync(&msg, &mut *chunkable, &Default::default(), true);
                assert!(matches!(
                    result,
                    Err(StateSyncErrorCode::OtherChunkVerificationFailed)
                ));
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
            let dst_msg = pipe_state_sync(msg.clone(), chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

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
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state.clone(), height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let chunkable = dst_state_sync.create_chunkable_state(&id);

            dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(
                state.clone(),
                height(1),
                CertificationScope::Full,
            );

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

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
        let time_source = ic_test_utilities::FastForwardTimeSource::new();
        for id in 100..(100 + num_canisters) {
            insert_canister_with_many_controllers(&mut state, canister_test_id(id), 400);
        }

        // With 1000 controllers' Principal ID serialized to the 'canister.pbuf' file,
        // the size will be larger than the `MAX_FILE_SIZE_TO_GROUP` and thus it will not be grouped.
        insert_canister_with_many_controllers(
            &mut state,
            canister_test_id(100 + num_canisters),
            1000,
        );

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        let num_files: usize = msg
            .state_sync_file_group
            .iter()
            .map(|(_, indices)| indices.len())
            .sum();

        // `canister.pbuf` files of all the canisters should be grouped, except for the one with 1000 controllers.
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
            let mut chunkable = dst_state_sync.create_chunkable_state(&id);

            let result = pipe_meta_manifest(&msg, &mut *chunkable, false);
            assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

            let result = pipe_manifest(&msg, &mut *chunkable, false);
            assert!(matches!(result, Err(StateSyncErrorCode::ChunksMoreNeeded)));

            assert!(chunkable
                .chunks_to_download()
                .any(|chunk_id| chunk_id.get() == FILE_GROUP_CHUNK_ID_OFFSET));

            let dst_msg = pipe_state_sync(msg, chunkable);

            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

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
        src_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata);
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(2), CertificationScope::Metadata);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(3), CertificationScope::Full);

        let hash = wait_for_checkpoint(&*src_state_manager, height(3));
        let id = StateSyncArtifactId {
            height: height(3),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut tip) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut tip, canister_test_id(100));
            dst_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata);

            let (_height, tip) = dst_state_manager.take_tip();

            let chunkable = dst_state_sync.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

            dst_state_manager.remove_states_below(height(2));

            assert_eq!(height(3), dst_state_manager.latest_state_height());
            assert_eq!(
                dst_state_manager.get_state_at(height(1)),
                Err(StateManagerError::StateRemoved(height(1)))
            );

            // Check that we can still commit the old tip.
            dst_state_manager.commit_and_certify(tip, height(2), CertificationScope::Metadata);

            // Check that after committing an old state, the state manager can still get the right tip and commit it.
            let (tip_height, tip) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            dst_state_manager.commit_and_certify(tip, height(4), CertificationScope::Metadata);

            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_commit_without_prev_hash_mismatch_after_taking_tip_at_the_synced_height() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut tip) = src_state_manager.take_tip();
        insert_dummy_canister(&mut tip, canister_test_id(100));
        src_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata);
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(2), CertificationScope::Metadata);

        let (_height, tip) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip, height(3), CertificationScope::Full);

        let hash = wait_for_checkpoint(&*src_state_manager, height(3));
        let id = StateSyncArtifactId {
            height: height(3),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut tip) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut tip, canister_test_id(100));
            dst_state_manager.commit_and_certify(tip, height(1), CertificationScope::Metadata);

            let chunkable = dst_state_sync.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

            assert_eq!(height(3), dst_state_manager.latest_state_height());
            let (tip_height, tip) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            // Check that we can still commit the new tip at the synced checkpoint height without prev state hash mismatch.
            dst_state_manager.commit_and_certify(tip, height(4), CertificationScope::Metadata);

            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_based_on_old_checkpoint() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let hash = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash,
        };
        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            wait_for_checkpoint(&*dst_state_manager, height(1));

            let chunkable = dst_state_sync.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);

            let mut tip = dst_state_manager.take_tip().1;
            let state = expected_state.take();
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata.prev_state_hash = state.metadata.prev_state_hash.clone();
            assert_eq!(tip, *state.as_ref());

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    });
}

#[test]
fn can_recover_from_corruption_on_state_sync() {
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    use ic_state_manager::manifest::DEFAULT_CHUNK_SIZE;

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
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

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

        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let hash_2 = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2,
        };
        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (_height, mut state) = dst_state_manager.take_tip();
            populate_original_state(&mut state);
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            let hash_dst_1 = wait_for_checkpoint(&*dst_state_manager, height(1));
            assert_eq!(hash_1, hash_dst_1);

            // Corrupt some files in the destination checkpoint.
            let state_layout = dst_state_manager.state_layout();
            let mutable_cp_layout = CheckpointLayout::<RwPolicy<()>>::new_untracked(
                state_layout
                    .checkpoint(height(1))
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
            let canister_90_memory = canister_90_layout.vmemory_0();
            make_mutable(&canister_90_memory).unwrap();
            std::fs::write(&canister_90_memory, b"Garbage").unwrap();

            let canister_90_raw_pb = canister_90_layout.canister().raw_path().to_path_buf();
            make_mutable(&canister_90_raw_pb).unwrap();
            write_all_at(&canister_90_raw_pb, b"Garbage", 0).unwrap();

            let canister_100_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();

            let canister_100_memory = canister_100_layout.vmemory_0();
            make_mutable(&canister_100_memory).unwrap();
            write_all_at(&canister_100_memory, &[3u8; PAGE_SIZE], 4).unwrap();

            let canister_100_stable_memory = canister_100_layout.stable_memory_blob();
            make_mutable(&canister_100_stable_memory).unwrap();
            write_all_at(
                &canister_100_stable_memory,
                &[3u8; PAGE_SIZE],
                PAGE_SIZE as u64,
            )
            .unwrap();

            let canister_100_raw_pb = canister_100_layout.canister().raw_path().to_path_buf();
            make_mutable(&canister_100_raw_pb).unwrap();
            std::fs::write(&canister_100_raw_pb, b"Garbage").unwrap();

            let chunkable = dst_state_sync.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);

            let mut tip = dst_state_manager.take_tip().1;
            let state = expected_state.take();
            // Because `take_tip()` modifies the `prev_state_hash`, we change it back to compare the rest of state.
            tip.metadata.prev_state_hash = state.metadata.prev_state_hash.clone();
            assert_eq!(tip, *state.as_ref());

            assert_no_remaining_chunks(dst_metrics);
            assert_error_counters(dst_metrics);
        })
    });
}

#[test]
fn can_commit_below_state_sync() {
    state_manager_test_with_state_sync(|src_metrics, src_state_manager, src_state_sync| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let (_height, state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let hash = wait_for_checkpoint(&*src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            let chunkable = dst_state_sync.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );
            // Check committing an old state doesn't panic
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
            dst_state_manager.flush_tip_channel();

            // take_tip should update the tip to the synced checkpoint
            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(2));
            assert_eq!(dst_state_manager.latest_state_height(), height(2));
            // state 1 should be removeable
            dst_state_manager.remove_states_below(height(2));
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
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        src_state_manager.commit_and_certify(state.clone(), height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&*src_state_manager, height(1));

        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = src_state_sync
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test_with_state_sync(|dst_metrics, dst_state_manager, dst_state_sync| {
            let (tip_height, state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(0));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
            dst_state_manager.flush_tip_channel();

            let (_height, state) = dst_state_manager.take_tip();
            dst_state_manager.remove_states_below(height(2));
            assert_eq!(dst_state_manager.checkpoint_heights(), vec![height(2)]);
            let chunkable = dst_state_sync.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_sync.process_changes(
                time_source.as_ref(),
                vec![UnvalidatedArtifact {
                    message: dst_msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                }],
            );
            assert_eq!(
                dst_state_manager.checkpoint_heights(),
                vec![height(1), height(2)]
            );
            dst_state_manager.commit_and_certify(state, height(3), CertificationScope::Full);

            let (tip_height, _state) = dst_state_manager.take_tip();
            assert_eq!(tip_height, height(3));
            assert_eq!(dst_state_manager.latest_state_height(), height(3));
            // state 1 should be removeable
            dst_state_manager.flush_tip_channel();
            dst_state_manager.remove_states_below(height(3));
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash_at_1 = wait_for_checkpoint(&state_manager, height(1));

        state_manager.fetch_state(height(1000), hash_at_1.clone(), Height::new(999));
        let hash_at_1000 = wait_for_checkpoint(&state_manager, height(1000));

        assert_eq!(hash_at_1, hash_at_1000);
        assert_eq!(state_manager.latest_state_height(), height(1000));

        let (tip_height, _) = state_manager.take_tip();
        assert_eq!(tip_height, height(1000));
    })
}

/// Test if `get_dirty_pages` returns correct dirty pages of canisters.
#[test]
fn can_get_dirty_pages() {
    use ic_replicated_state::page_map::PageIndex;
    use ic_state_manager::get_dirty_pages;
    use ic_state_manager::Snapshot;

    fn update_state(state: &mut ReplicatedState, canister_id: CanisterId) {
        let canister_state = state.canister_state_mut(&canister_id).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);
        execution_state.stable_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);
    }

    fn drop_page_map(state: &mut ReplicatedState, canister_id: CanisterId) {
        let canister_state = state.canister_state_mut(&canister_id).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map = PageMap::new_for_testing();
    }

    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        let snapshot0 = Snapshot {
            height: height(0),
            state: Arc::new(state.clone()),
        };
        insert_dummy_canister(&mut state, canister_test_id(80));
        insert_dummy_canister(&mut state, canister_test_id(90));
        insert_dummy_canister(&mut state, canister_test_id(100));

        update_state(&mut state, canister_test_id(80));
        let dirty_pages = get_dirty_pages(&state, Some(&snapshot0));
        // dirty_pages should be empty because there is no base checkpoint for the page
        // deltas and the canister binaries are new.
        assert!(dirty_pages.is_empty());

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        let snapshot1 = Snapshot {
            height: height(1),
            state: Arc::new(state.clone()),
        };
        update_state(&mut state, canister_test_id(90));
        let mut dirty_pages = get_dirty_pages(&state, Some(&snapshot1));
        let mut expected_dirty_pages = vec![
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::WasmMemory(canister_test_id(80))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(80))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::WasmMemory(canister_test_id(90))),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(90))),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::WasmMemory(canister_test_id(100))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(100))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::WasmBinary(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::WasmBinary(canister_test_id(90)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                file_type: FileType::WasmBinary(canister_test_id(100)),
                page_delta_indices: vec![],
            },
        ];

        dirty_pages.sort();
        expected_dirty_pages.sort();
        assert_eq!(dirty_pages, expected_dirty_pages);

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        let snapshot2 = Snapshot {
            height: height(2),
            state: Arc::new(state.clone()),
        };
        update_state(&mut state, canister_test_id(100));
        // It could happen during canister upgrade.
        drop_page_map(&mut state, canister_test_id(100));
        update_state(&mut state, canister_test_id(100));
        replace_wasm(&mut state, canister_test_id(100));
        let mut dirty_pages = get_dirty_pages(&state, Some(&snapshot2));
        // wasm memory was dropped, but stable memory wasn't
        let mut expected_dirty_pages = vec![
            DirtyPageMap {
                height: height(2),
                file_type: FileType::PageMap(PageMapType::WasmMemory(canister_test_id(80))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(80))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::PageMap(PageMapType::WasmMemory(canister_test_id(90))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(90))),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::PageMap(PageMapType::StableMemory(canister_test_id(100))),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::WasmBinary(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                file_type: FileType::WasmBinary(canister_test_id(90)),
                page_delta_indices: vec![],
            },
        ];

        dirty_pages.sort();
        expected_dirty_pages.sort();
        assert_eq!(dirty_pages, expected_dirty_pages);

        assert_error_counters(metrics);
    })
}

#[test]
fn can_reuse_chunk_hashes_when_computing_manifest() {
    use ic_state_manager::manifest::{compute_manifest, validate_manifest, DEFAULT_CHUNK_SIZE};
    use ic_state_manager::ManifestMetrics;
    use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;

    state_manager_test(|metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        wait_for_checkpoint(&state_manager, height(1));

        let mut reused_label = Labels::new();
        reused_label.insert("type".to_string(), "reused".to_string());
        let mut compared_label = Labels::new();
        compared_label.insert("type".to_string(), "hashed_and_compared".to_string());

        // First checkpoint: no chunks to reuse yet.
        let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
        assert_eq!(0, chunk_bytes[&reused_label]);

        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
        let state_2_hash = wait_for_checkpoint(&state_manager, height(2));

        // Second checkpoint can leverage heap chunks computed previously as well as the wasm binary
        let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
        assert_eq!(
            PAGE_SIZE as u64 * ((NEW_WASM_PAGE + 1) + (NEW_STABLE_PAGE + 1))
                + empty_wasm_size() as u64,
            chunk_bytes[&reused_label] + chunk_bytes[&compared_label]
        );

        let checkpoint = state_manager.state_layout().checkpoint(height(2)).unwrap();

        let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);

        let manifest = compute_manifest(
            &mut thread_pool,
            &ManifestMetrics::new(&MetricsRegistry::new()),
            &no_op_logger(),
            CURRENT_STATE_SYNC_VERSION,
            &checkpoint,
            DEFAULT_CHUNK_SIZE,
            None,
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
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
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
    use std::time::Duration;
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.metadata.batch_time += Duration::new(0, 100);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
                ecdsa_keys_held: BTreeSet::new(),
            },
        );

        let network_topology = NetworkTopology {
            subnets,
            nns_subnet_id: subnet_test_id(42),
            ..Default::default()
        };

        state.metadata.network_topology = network_topology;
        state.metadata.node_public_keys = node_public_keys;

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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

        if CURRENT_CERTIFICATION_VERSION > V11 {
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
        } else {
            assert!(
                mixed_tree.lookup(&path[..]).is_absent(),
                "mixed_tree: {:#?}",
                mixed_tree
            );
        }
    })
}

#[test]
fn certified_read_succeeds_for_empty_tree() {
    use ic_crypto_tree_hash::MixedHashTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {});

        certify_height(&state_manager, height(1));
        let (_, mixed_tree, _) = state_manager.read_certified_state(&path).unwrap();

        assert!(
            matches!(&mixed_tree, Pruned(_)),
            "mixed_tree: {:#?}",
            mixed_tree
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
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
            "mixed_tree: {:#?}",
            mixed_tree
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
            "mixed_tree: {:#?}",
            mixed_tree
        );
    })
}

#[test]
fn certified_read_returns_absence_proof_for_non_existing_entries_in_empty_state() {
    state_manager_test(|_metrics, state_manager| {
        let (_, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
            "mixed_tree: {:#?}",
            mixed_tree
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
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: mock_time(),
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
                time: mock_time(),
                state: IngressState::Completed(WasmResult::Reply(b"done".to_vec())),
            },
            NumBytes::from(u64::MAX),
        );
        state.set_ingress_status(
            message_test_id(3),
            IngressStatus::Known {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: mock_time(),
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
        );
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

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
            "mixed_tree: {:#?}",
            mixed_tree
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
            state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(3), CertificationScope::Full);
            wait_for_checkpoint(&state_manager, height(3));

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
            assert!(state_manager
                .state_layout()
                .diverged_state_heights()
                .unwrap()
                .is_empty());
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

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
            state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
            std::thread::sleep(std::time::Duration::from_secs(2));
            let mut certification = certify_height(&state_manager, height(1));
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);
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
            assert!(state_manager
                .state_layout()
                .diverged_checkpoint_heights()
                .unwrap()
                .is_empty());
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
            state_manager.commit_and_certify(state, height(i + 1), CertificationScope::Full);
            state_manager.flush_tip_channel();
        }

        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(divergence), CertificationScope::Full);
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
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
                wait_for_checkpoint(&state_manager, height(1));

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
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
                wait_for_checkpoint(&state_manager, height(2));

                panic!();
            }),
        ],
        |metrics, state_manager| {
            assert!(state_manager
                .state_layout()
                .diverged_checkpoint_heights()
                .unwrap()
                .is_empty());
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
                .checkpoint(height(h))
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        wait_for_checkpoint(&state_manager, height(1));
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
        wait_for_checkpoint(&state_manager, height(2));
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (_, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Full);
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
                state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
                let (_, state) = state_manager.take_tip();
                state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
                wait_for_checkpoint(&state_manager, height(2));

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
        let mut certification = certify_height(&state_manager, height(1));
        for i in 2..(divergence + 1) {
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(i), CertificationScope::Metadata);
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
fn can_reset_memory() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // One canister with some data
        insert_dummy_canister(&mut state, canister_test_id(100));
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);

        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, mut state) = state_manager.take_tip();

        // Wipe data and write different data
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));
        execution_state.wasm_memory.page_map.update(&[
            (PageIndex::new(1), &[100u8; PAGE_SIZE]),
            (PageIndex::new(100), &[100u8; PAGE_SIZE]),
        ]);

        // Check no remnants of the old data remain
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

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        // Check file in checkpoint does not contain old data by checking its size
        let memory_path = state_manager
            .state_layout()
            .checkpoint(height(2))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .vmemory_0();
        assert_eq!(
            std::fs::metadata(memory_path).unwrap().len(),
            101 * PAGE_SIZE as u64
        );

        let (_height, mut state) = state_manager.take_tip();
        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();

        // Check again after checkpoint that no remnants of old data remain
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

        // Wipe data completely
        execution_state.wasm_memory = Memory::new(PageMap::new_for_testing(), NumWasmPages::new(0));

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full);

        // File should be empty after wiping and checkpoint
        let memory_path = state_manager
            .state_layout()
            .checkpoint(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .vmemory_0();
        assert_eq!(std::fs::metadata(memory_path).unwrap().len(), 0);

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
fn can_delete_canister() {
    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        // Insert a canister and a write checkpoint
        insert_dummy_canister(&mut state, canister_test_id(100));

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        // Check the checkpoint has the canister
        let canister_path = state_manager
            .state_layout()
            .checkpoint(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .raw_path();
        assert!(std::fs::metadata(canister_path).unwrap().is_dir());

        let (_height, mut state) = state_manager.take_tip();

        // Delete the canister
        let _deleted_canister = state.take_canister_state(&canister_test_id(100));

        // Commit two rounds, once without checkpointing and once with
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full);

        // Check that the checkpoint does not contain the canister
        assert!(!state_manager
            .state_layout()
            .checkpoint(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap()
            .raw_path()
            .exists());

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

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        // Check the checkpoint has the canister
        let canister_layout = state_manager
            .state_layout()
            .checkpoint(height(1))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();
        let canister_path = canister_layout.raw_path();
        assert!(std::fs::metadata(canister_path).unwrap().is_dir());

        // WASM binary and memory stable memory should all be present
        assert_ne!(
            std::fs::metadata(canister_layout.vmemory_0())
                .unwrap()
                .len(),
            0
        );
        assert_ne!(
            std::fs::metadata(canister_layout.stable_memory_blob())
                .unwrap()
                .len(),
            0
        );
        assert!(canister_layout.wasm().raw_path().exists());

        let (_height, mut state) = state_manager.take_tip();

        // Remove the execution state
        state
            .canister_state_mut(&canister_test_id(100))
            .unwrap()
            .execution_state = None;

        // Commit two rounds, once without checkpointing and once with
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(3), CertificationScope::Full);

        // Check that the checkpoint does contains the canister
        let canister_layout = state_manager
            .state_layout()
            .checkpoint(height(3))
            .unwrap()
            .canister(&canister_test_id(100))
            .unwrap();

        assert!(canister_layout.raw_path().exists());

        // WASM and stable memory should be empty after checkpoint
        assert_eq!(
            std::fs::metadata(canister_layout.vmemory_0())
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            std::fs::metadata(canister_layout.stable_memory_blob())
                .unwrap()
                .len(),
            0
        );
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

    let canister_layout = layout
        .checkpoint(*layout.checkpoint_heights().unwrap().last().unwrap())
        .unwrap()
        .canister(&canister_id)
        .unwrap();
    assert_ne!(
        std::fs::metadata(canister_layout.vmemory_0())
            .unwrap()
            .len(),
        0
    );
    assert_ne!(
        std::fs::metadata(canister_layout.stable_memory_blob())
            .unwrap()
            .len(),
        0
    );
    assert!(canister_layout.wasm().raw_path().exists());

    env.uninstall_code(canister_id).unwrap();

    let canister_layout = layout
        .checkpoint(*layout.checkpoint_heights().unwrap().last().unwrap())
        .unwrap()
        .canister(&canister_id)
        .unwrap();
    assert_eq!(
        std::fs::metadata(canister_layout.vmemory_0())
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(canister_layout.stable_memory_blob())
            .unwrap()
            .len(),
        0
    );
    assert!(!canister_layout.wasm().raw_path().exists());
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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

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
        assert!(canister_layout.vmemory_0().exists());
        assert!(canister_layout.stable_memory_blob().exists());

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let checkpoint_layout = state_manager.state_layout().checkpoint(height(2)).unwrap();

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
        assert!(canister_layout.vmemory_0().exists());
        assert!(canister_layout.stable_memory_blob().exists());
    });
}

#[test]
fn can_recover_ingress_history() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
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
        );

        state_manager.commit_and_certify(state.clone(), height(2), CertificationScope::Full);
        let (_height, state2) = state_manager.take_tip();
        state.metadata.prev_state_hash = state2.metadata.prev_state_hash.clone();
        assert_eq!(state2, state);
    });
}

proptest! {
    #[test]
    fn stream_store_encode_decode(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, slice| {
                // we do not modify the slice before decoding it again - so this should succeed
                (state_manager, slice)
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_with_modified_hash_fails(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, mut slice| {
                let mut hash = slice.certification.signed.content.hash.get();
                *hash.0.first_mut().unwrap() = hash.0.first().unwrap().overflowing_add(1).0;
                slice.certification.signed.content.hash = CryptoHashOfPartialState::from(hash);

                (state_manager, slice)
            }
        );
    }

    #[test]
    #[should_panic(expected = "Failed to deserialize witness")]
    fn stream_store_decode_with_empty_witness_fails(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, mut slice| {
                slice.merkle_proof = vec![];

                (state_manager, slice)
            }
        );
    }

    #[test]
    #[should_panic(expected = "InconsistentPartialTree")]
    fn stream_store_decode_slice_push_additional_message(stream in arb_stream(0, 10, 0, 10)) {
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
                        .sender(CanisterId::new(PrincipalId::try_from(&[2][..]).unwrap()).unwrap())
                        .receiver(CanisterId::new(PrincipalId::try_from(&[3][..]).unwrap()).unwrap())
                        .method_name("test".to_string())
                        .sender_reply_callback(CallbackId::from(999))
                        .build();

                    messages.push(req.into());

                    let signals_end = decoded_slice.header().signals_end;

                    Stream::new(messages, signals_end)
                })
            }
        );
    }

    /// Depending on the specific input, may fail with either `InvalidSignature` or
    /// `InconsistentPartialTree`. Hence, only a generic `should_panic`.
    #[test]
    #[should_panic]
    fn stream_store_decode_slice_modify_message_begin(stream in arb_stream(0, 10, 0, 10)) {
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
                modify_encoded_stream_helper(
                    state_manager,
                    slice,
                    |decoded_slice| {
                    let mut messages = StreamIndexedQueue::with_begin(StreamIndex::from(99999));
                    let signals_end = decoded_slice.header().signals_end;

                    if let Some(decoded_messages) = decoded_slice.messages() {
                        for (_index, msg) in decoded_messages.iter() {
                            messages.push(msg.clone());
                        }
                    }

                    Stream::new(messages, signals_end)
                })
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_slice_modify_signals_end(stream in arb_stream(0, 10, 0, 10)) {
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
                    let messages = decoded_slice.messages()
                        .unwrap_or(&StreamIndexedQueue::default()).clone();
                    let signals_end = decoded_slice.header().signals_end + 99999.into();

                    Stream::new(messages, signals_end)
                })
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_slice_push_signal(stream in arb_stream(0, 10, 0, 10)) {
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
                    let messages = decoded_slice.messages()
                        .unwrap_or(&StreamIndexedQueue::default()).clone();
                    let mut signals_end = decoded_slice.header().signals_end;

                    signals_end.inc_assign();

                    Stream::new(messages, signals_end)
                })
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidDestination")]
    fn stream_store_decode_with_invalid_destination(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, slice| {
                // Do not modify the slice before decoding it again - the wrong
                // destination subnet should already make it fail
                (state_manager, slice)
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_with_rejecting_verifier(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, slice| {
                // Do not modify the slice before decoding it again - the signature validation
                // failure caused by passing the `RejectingVerifier` should already make it fail.
                (state_manager, slice)
            }
        );
    }

    /// If both signature verification and slice decoding would fail, we expect to
    /// see an error about the former.
    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_with_invalid_destination_and_rejecting_verifier(stream in arb_stream(0, 10, 0, 10), size_limit in 0..20usize) {
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
            |state_manager, slice| {
                // Do not modify the slice, the wrong destination subnet and rejecting verifier
                // should make it fail regardless.
                (state_manager, slice)
            }
        );
    }

    #[test]
    fn stream_store_encode_partial((stream, begin, count) in arb_stream_slice(1, 10, 0, 10), byte_limit in 0..1000usize) {
        // Partial slice with messages beginning at `begin + 1`.
        encode_partial_slice_test(
            stream,
            begin,
            begin.increment(),
            count - 1,
            byte_limit
        );
    }
}

// 1 test case is sufficient to test index validation.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]

    #[test]
    #[should_panic(expected = "failed to encode certified stream: InvalidSliceIndices")]
    fn stream_store_encode_partial_bad_indices((stream, begin, count) in arb_stream_slice(1, 10, 0, 10), byte_limit in 0..1000usize) {
        // `witness_begin` (`== begin + 1`) after `msg_begin` (`== begin`).
        encode_partial_slice_test(
            stream,
            begin.increment(),
            begin,
            count,
            byte_limit
        );
    }
}
