use ic_base_types::NumBytes;
use ic_config::state_manager::Config;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, MixedHashTree};
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactProcessor},
    certification::Verifier,
    certified_stream_store::{CertifiedStreamStore, EncodeStreamError},
};
use ic_interfaces_state_manager::*;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    page_map::PageIndex, testing::ReplicatedStateTesting, NumWasmPages, PageMap, ReplicatedState,
    Stream,
};
use ic_state_manager::{BitcoinPageMap, DirtyPageMap, PageMapType, StateManagerImpl};
use ic_sys::PAGE_SIZE;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    metrics::{fetch_int_counter_vec, fetch_int_gauge, Labels},
    mock_time,
    state::{arb_stream, arb_stream_slice, canister_ids},
    types::{
        ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::RequestBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{
    artifact::{Priority, StateSyncArtifactId, StateSyncAttribute},
    chunkable::ChunkId,
    crypto::CryptoHash,
    ingress::{IngressStatus, WasmResult},
    messages::{CallbackId, RequestOrResponse},
    xnet::{StreamIndex, StreamIndexedQueue},
    CanisterId, CryptoHashOfPartialState, CryptoHashOfState, Height, PrincipalId,
};
use proptest::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
};
use tempfile::Builder;

pub mod common;
use common::*;
use ic_registry_subnet_type::SubnetType;

const NUM_THREADS: u32 = 3;

fn make_mutable(path: &Path) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
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

#[test]
fn temporary_directory_gets_cleaned() {
    state_manager_restart_test(|state_manager, restart_fn| {
        // write something to some file in the tmp directory
        let test_file = state_manager
            .state_layout()
            .tmp()
            .expect("failed to get tmp directory path")
            .join("some_file");
        std::fs::write(&test_file, "some stuff").expect("failed to write to test file");

        // restart the state_manager
        let state_manager = restart_fn(state_manager, None);

        // check the tmp directory is empty
        assert!(
            state_manager
                .state_layout()
                .tmp()
                .unwrap()
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
        let test_dir = state_manager
            .state_layout()
            .tip_path()
            .join("should_get_deleted");
        std::fs::create_dir_all(test_dir.as_path()).unwrap();
        assert!(test_dir.exists());

        let state_manager = restart_fn(state_manager, None);

        let test_dir = state_manager
            .state_layout()
            .tip_path()
            .join("should_get_deleted");
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

        state_manager.remove_states_below(height(3));

        let canister_id: Vec<CanisterId> = vec![
            canister_test_id(100),
            canister_test_id(200),
            canister_test_id(300),
        ];
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
        let mutable_cp_layout = CheckpointLayout::<RwPolicy>::new(
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

fn state_manager_crash_test<Fixture, Test>(fixture: Fixture, test: Test)
where
    Fixture: FnOnce(StateManagerImpl) + std::panic::UnwindSafe,
    Test: FnOnce(&MetricsRegistry, StateManagerImpl),
{
    let tmp = Builder::new().prefix("test").tempdir().unwrap();
    let config = Config::new(tmp.path().into());
    with_test_replica_logger(|log| {
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
        .expect_err("Crash test fixture did not crash");

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
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (tip_height, state) = state_manager.take_tip();
        assert_eq!(tip_height, height(1));
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
    });
}

#[test]
fn checkpoints_outlive_state_manager() {
    let tmp = Builder::new().prefix("test").tempdir().unwrap();
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
            vec![height(0), height(1), height(2)]
        );

        let checkpointed_state = state_manager.get_latest_state();

        assert_eq!(checkpointed_state.height(), height(2));
        assert_eq!(
            canister_ids(checkpointed_state.get_ref()),
            vec![canister_id]
        );
        assert!(state_manager.get_state_at(height(1)).is_ok());
    });
}

#[test]
fn certifications_are_not_persisted() {
    let tmp = Builder::new().prefix("test").tempdir().unwrap();
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

            if scope == CertificationScope::Full {
                // We need to wait for hashing to complete, otherwise the
                // checkpoint can be retained until the hashing is complete.
                wait_for_checkpoint(&state_manager, height(i));
            }
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
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

            if scope == CertificationScope::Full {
                // We need to wait for hashing to complete, otherwise the
                // checkpoint can be retained until the hashing is complete.
                wait_for_checkpoint(&state_manager, height(i));
            }
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
        state_manager.remove_states_below(height(10));

        for h in 1..4 {
            assert_eq!(
                state_manager.get_state_at(height(h)),
                Err(StateManagerError::StateRemoved(height(h)))
            );
        }

        assert_eq!(
            state_manager.get_state_at(height(5)),
            Err(StateManagerError::StateRemoved(height(5)))
        );

        assert_eq!(
            state_manager.get_state_at(height(7)),
            Err(StateManagerError::StateRemoved(height(7)))
        );

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6), height(8), height(9)],
        );

        assert_eq!(height(9), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(9), latest_state.height());

        let state_manager = restart_fn(state_manager, Some(height(10)));

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(6), height(8),],
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

            if scope == CertificationScope::Full {
                // We need to wait for hashing to complete, otherwise the
                // checkpoint can be retained until the hashing is complete.
                wait_for_checkpoint(&state_manager, height(i));
            }
        }
        assert_eq!(state_manager.list_state_heights(CERT_ANY), heights);
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

            if scope == CertificationScope::Full {
                // We need to wait for hashing to complete, otherwise the
                // checkpoint can be retained until the hashing is complete.
                wait_for_checkpoint(&state_manager, height(i));
            }
        }
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
            if scope == CertificationScope::Full {
                wait_for_checkpoint(&state_manager, height(i));
            }
        }
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

        // Checkpoints @15 and @20 are kept because they are the two most recent
        // checkpoints.
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
        // Intermediate states from @16 to @19 are purged.
        state_manager.remove_states_below(height(20));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(15), height(20), height(21), height(22)],
        );

        // Test calling `remove_states_below` at the latest state height.
        // The intermediate state @21 is purged.
        state_manager.remove_states_below(height(22));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(15), height(20), height(22)],
        );

        // Test calling `remove_states_below` at a higher height than the latest state
        // height.
        // The intermediate state @21 is purged.
        // The latest state should always be kept.
        state_manager.remove_states_below(height(25));
        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(15), height(20), height(22)],
        );
    })
}

#[test]
fn latest_certified_state_is_updated_on_state_removal() {
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);
        certify_height(&state_manager, height(1));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata);

        state_manager.remove_states_below(height(3));
        assert_eq!(height(3), state_manager.latest_state_height());
        assert_eq!(height(0), state_manager.latest_certified_height());
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
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();
        let time_source = ic_test_utilities::FastForwardTimeSource::new();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let (adverts, _) = state_manager.process_changes(time_source.as_ref(), Default::default());
        assert_eq!(adverts.len(), 1);
        assert_eq!(adverts[0].advert.id, id);
        assert!(state_manager.has_artifact(&id));

        let (adverts, _) = state_manager.process_changes(time_source.as_ref(), Default::default());
        assert_eq!(adverts.len(), 0);
        assert!(state_manager.has_artifact(&id));
    });
}

#[test]
fn recomputes_metadata_on_restart_if_missing() {
    state_manager_restart_test(|state_manager, restart_fn| {
        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        std::fs::remove_file(&state_manager.state_layout().states_metadata())
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
    state_manager_test(|_metrics, state_manager| {
        let (_height, state) = state_manager.take_tip();

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Expecting 6 files, as we don't have canisters in the default state.
        //
        // 1. "system_metadata.pbuf"
        // 2. "subnet_queues.pbuf"
        // 3. "bitcoin/testnet/state.pbuf"
        // 4. "bitcoin/testnet/utxos_small.pbuf"
        // 5. "bitcoin/testnet/utxos_medium.pbuf"
        // 6. "bitcoin/testnet/address_outpoints.pbuf"
        assert_eq!(6, msg.manifest.file_table.len());

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
    state_manager_test(|_metrics, state_manager| {
        fn hash(n: u8) -> CryptoHashOfState {
            CryptoHashOfState::from(CryptoHash(vec![n; 32]))
        }

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(1), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(2), CertificationScope::Metadata);

        let priority_fn = state_manager
            .get_priority_function()
            .expect("state manager returned no priority function");

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
                    &StateSyncAttribute {
                        height: height(*h),
                        root_hash: hash(*h as u8),
                    }
                )
            );
        }

        // Request fetching of state 3.
        state_manager.fetch_state(height(3), hash(3), Height::new(99));
        let priority_fn = state_manager
            .get_priority_function()
            .expect("state manager returned no priority function");
        // Good hash
        assert_eq!(
            Priority::Fetch,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(3),
                    hash: hash(3),
                },
                &StateSyncAttribute {
                    height: height(3),
                    root_hash: hash(3),
                }
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
                &StateSyncAttribute {
                    height: height(3),
                    root_hash: hash(4),
                }
            )
        );

        // Request fetching of newer state 4.
        state_manager.fetch_state(height(4), hash(4), Height::new(99));
        let priority_fn = state_manager
            .get_priority_function()
            .expect("state manager returned no priority function");
        assert_eq!(
            Priority::Drop,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(3),
                    hash: hash(3),
                },
                &StateSyncAttribute {
                    height: height(3),
                    root_hash: hash(3),
                }
            )
        );
        assert_eq!(
            Priority::Fetch,
            priority_fn(
                &StateSyncArtifactId {
                    height: height(4),
                    hash: hash(4),
                },
                &StateSyncAttribute {
                    height: height(4),
                    root_hash: hash(4),
                }
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

#[test]
fn can_do_simple_state_sync_transfer() {
    state_manager_test(|src_metrics, src_state_manager| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_manager
                .check_artifact_acceptance(dst_msg, &node_test_id(0))
                .expect("Failed to process state sync artifact");

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);
            assert_eq!(*state.as_ref(), dst_state_manager.take_tip().1);
            assert_eq!(vec![height(1)], heights_to_certify(&dst_state_manager));

            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_from_cache() {
    state_manager_test(|src_metrics, src_state_manager| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash: hash.clone(),
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let omit: HashSet<ChunkId> = maplit::hashset! {ChunkId::new(1)};

            // First state sync is destroyed before completion
            {
                let mut chunkable = dst_state_manager.create_chunkable_state(&id);

                // First fetch chunk 0 (the manifest), and then ask for chunk 1,2,3 afterwards,
                // but only receive 2,3
                let completion = pipe_partial_state_sync(&msg, &mut *chunkable, &omit);
                assert!(completion.is_none(), "Unexpectedly completed state sync");
            }
            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            // Second state sync continues from first state and successfully finishes
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(2),
                    hash: hash.clone(),
                };

                let mut chunkable = dst_state_manager.create_chunkable_state(&id);

                let result = pipe_manifest(&msg, &mut *chunkable);
                assert!(result.is_none());

                // Only the chunks not fetched in the first state sync should still be requested
                assert_eq!(omit, chunkable.chunks_to_download().collect());

                // Download chunk 1
                let dst_msg = pipe_state_sync(msg.clone(), chunkable);
                dst_state_manager
                    .check_artifact_acceptance(dst_msg, &node_test_id(0))
                    .expect("Failed to process state sync artifact");

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
                assert_eq!(vec![height(2)], heights_to_certify(&dst_state_manager));
            }
            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            // Third state sync can copy all chunks immediately
            {
                // Same state just higher height
                let id = StateSyncArtifactId {
                    height: height(3),
                    hash,
                };

                let mut chunkable = dst_state_manager.create_chunkable_state(&id);

                // The manifest alone is enough to complete the sync
                let dst_msg = pipe_manifest(&msg, &mut *chunkable).unwrap();

                dst_state_manager
                    .check_artifact_acceptance(dst_msg, &node_test_id(0))
                    .expect("Failed to process state sync artifact");

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
                    heights_to_certify(&dst_state_manager)
                );
            }

            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_into_existing_checkpoint() {
    state_manager_test(|src_metrics, src_state_manager| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state.clone(), height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(
                state.clone(),
                height(1),
                CertificationScope::Full,
            );

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_manager
                .check_artifact_acceptance(dst_msg, &node_test_id(0))
                .expect("Failed to process state sync artifact");

            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            assert_error_counters(dst_metrics);
        })
    })
}

#[test]
fn can_state_sync_based_on_old_checkpoint() {
    state_manager_test(|src_metrics, src_state_manager| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(200));
        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let hash = wait_for_checkpoint(&src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash,
        };
        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let (_height, mut state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            wait_for_checkpoint(&dst_state_manager, height(1));

            let chunkable = dst_state_manager.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_manager
                .check_artifact_acceptance(dst_msg, &node_test_id(0))
                .expect("failed to process state sync artifact");

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);
            assert_eq!(
                dst_state_manager.take_tip().1,
                *expected_state.take().as_ref()
            );

            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
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

    state_manager_test(|src_metrics, src_state_manager| {
        // Create initial state with a single canister.
        let (_height, mut state) = src_state_manager.take_tip();
        populate_original_state(&mut state);
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let hash_1 = wait_for_checkpoint(&src_state_manager, height(1));

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

        let hash_2 = wait_for_checkpoint(&src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2,
        };
        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync message");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let (_height, mut state) = dst_state_manager.take_tip();
            populate_original_state(&mut state);
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

            let hash_dst_1 = wait_for_checkpoint(&dst_state_manager, height(1));
            assert_eq!(hash_1, hash_dst_1);

            // Corrupt some files in the destination checkpoint.
            let state_layout = dst_state_manager.state_layout();
            let mutable_cp_layout = CheckpointLayout::<RwPolicy>::new(
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

            let chunkable = dst_state_manager.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_manager
                .check_artifact_acceptance(dst_msg, &node_test_id(0))
                .expect("failed to process state sync artifact");

            let expected_state = src_state_manager.get_latest_state();

            assert_eq!(dst_state_manager.get_latest_state(), expected_state);
            assert_eq!(
                dst_state_manager.take_tip().1,
                *expected_state.take().as_ref()
            );

            assert_eq!(
                0,
                fetch_int_gauge(dst_metrics, "state_sync_remaining_chunks").unwrap()
            );
            assert_error_counters(dst_metrics);
        })
    });
}

#[test]
fn can_commit_below_state_sync() {
    state_manager_test(|src_metrics, src_state_manager| {
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));

        src_state_manager.commit_and_certify(state.clone(), height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        assert_error_counters(src_metrics);

        state_manager_test(|dst_metrics, dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            dst_state_manager
                .check_artifact_acceptance(dst_msg, &node_test_id(0))
                .expect("Failed to process state sync artifact");

            dst_state_manager.take_tip();
            // Check committing an old state doesn't panic
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

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

    fn update_bitcoin_page_maps(state: &mut ReplicatedState) {
        state.bitcoin_testnet_mut().utxo_set.utxos_small.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(100), &[99u8; PAGE_SIZE]),
        ]);

        state.bitcoin_testnet_mut().utxo_set.utxos_medium.update(&[
            (PageIndex::new(2), &[99u8; PAGE_SIZE]),
            (PageIndex::new(200), &[99u8; PAGE_SIZE]),
        ]);

        state
            .bitcoin_testnet_mut()
            .utxo_set
            .address_outpoints
            .update(&[
                (PageIndex::new(3), &[99u8; PAGE_SIZE]),
                (PageIndex::new(300), &[99u8; PAGE_SIZE]),
            ]);
    }

    fn drop_page_map(state: &mut ReplicatedState, canister_id: CanisterId) {
        let canister_state = state.canister_state_mut(&canister_id).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.wasm_memory.page_map = PageMap::default();
    }

    state_manager_test(|metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(80));
        insert_dummy_canister(&mut state, canister_test_id(90));
        insert_dummy_canister(&mut state, canister_test_id(100));

        update_state(&mut state, canister_test_id(80));
        update_bitcoin_page_maps(&mut state);
        let dirty_pages = get_dirty_pages(&state);
        // dirty_pages should be empty because there is no base checkpoint for the page
        // deltas.
        assert!(dirty_pages.is_empty());

        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        update_state(&mut state, canister_test_id(90));
        update_bitcoin_page_maps(&mut state);
        let mut dirty_pages = get_dirty_pages(&state);
        let mut expected_dirty_pages = vec![
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::WasmMemory(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::StableMemory(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::WasmMemory(canister_test_id(90)),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::StableMemory(canister_test_id(90)),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::WasmMemory(canister_test_id(100)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::StableMemory(canister_test_id(100)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::UtxosSmall),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(100)],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::UtxosMedium),
                page_delta_indices: vec![PageIndex::new(2), PageIndex::new(200)],
            },
            DirtyPageMap {
                height: height(1),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::AddressOutpoints),
                page_delta_indices: vec![PageIndex::new(3), PageIndex::new(300)],
            },
        ];

        dirty_pages.sort();
        expected_dirty_pages.sort();
        assert_eq!(dirty_pages, expected_dirty_pages);

        state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let (_height, mut state) = state_manager.take_tip();
        update_state(&mut state, canister_test_id(100));
        // It could happen during canister upgrade.
        drop_page_map(&mut state, canister_test_id(100));
        update_state(&mut state, canister_test_id(100));
        let mut dirty_pages = get_dirty_pages(&state);
        // wasm memory was dropped, but stable memory wasn't
        let mut expected_dirty_pages = vec![
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::WasmMemory(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::StableMemory(canister_test_id(80)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::WasmMemory(canister_test_id(90)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::StableMemory(canister_test_id(90)),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::StableMemory(canister_test_id(100)),
                page_delta_indices: vec![PageIndex::new(1), PageIndex::new(300)],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::UtxosSmall),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::UtxosMedium),
                page_delta_indices: vec![],
            },
            DirtyPageMap {
                height: height(2),
                page_type: PageMapType::Bitcoin(BitcoinPageMap::AddressOutpoints),
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
    use ic_state_manager::manifest::{
        compute_manifest, validate_manifest, CURRENT_STATE_SYNC_VERSION, DEFAULT_CHUNK_SIZE,
    };
    use ic_state_manager::ManifestMetrics;

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
        const NEW_UTXOS_SMALL_PAGE: u64 = 700;
        state.bitcoin_testnet_mut().utxo_set.utxos_small.update(&[
            (PageIndex::new(1), &[1u8; PAGE_SIZE]),
            (PageIndex::new(NEW_UTXOS_SMALL_PAGE), &[2u8; PAGE_SIZE]),
        ]);
        const NEW_UTXOS_MEDIUM_PAGE: u64 = 800;
        state.bitcoin_testnet_mut().utxo_set.utxos_medium.update(&[
            (PageIndex::new(1), &[1u8; PAGE_SIZE]),
            (PageIndex::new(NEW_UTXOS_MEDIUM_PAGE), &[2u8; PAGE_SIZE]),
        ]);
        const NEW_ADDRESS_OUTPOINTS_PAGE: u64 = 900;
        state
            .bitcoin_testnet_mut()
            .utxo_set
            .address_outpoints
            .update(&[
                (PageIndex::new(1), &[1u8; PAGE_SIZE]),
                (
                    PageIndex::new(NEW_ADDRESS_OUTPOINTS_PAGE),
                    &[2u8; PAGE_SIZE],
                ),
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

        // Second checkpoint can leverage heap chunks computed previously.
        let chunk_bytes = fetch_int_counter_vec(metrics, "state_manager_manifest_chunk_bytes");
        assert_eq!(
            PAGE_SIZE as u64
                * ((NEW_WASM_PAGE + 1)
                    + (NEW_STABLE_PAGE + 1)
                    + (NEW_UTXOS_SMALL_PAGE + 1)
                    + (NEW_UTXOS_MEDIUM_PAGE + 1)
                    + (NEW_ADDRESS_OUTPOINTS_PAGE + 1)),
            chunk_bytes[&reused_label] + chunk_bytes[&compared_label]
        );

        let checkpoint_root = state_manager
            .state_layout()
            .checkpoint(height(2))
            .unwrap()
            .raw_path()
            .to_path_buf();

        let mut thread_pool = scoped_threadpool::Pool::new(NUM_THREADS);

        let manifest = compute_manifest(
            &mut thread_pool,
            &ManifestMetrics::new(&MetricsRegistry::new()),
            &no_op_logger(),
            CURRENT_STATE_SYNC_VERSION,
            &checkpoint_root,
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
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
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
fn certified_read_returns_none_for_non_existing_entries() {
    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
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

        assert_eq!(None, state_manager.read_certified_state(&path));
    })
}

#[test]
fn certified_read_can_fetch_multiple_entries_in_one_go() {
    use LabeledTree::*;

    state_manager_test(|_metrics, state_manager| {
        let (_, mut state) = state_manager.take_tip();
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
            },
            NumBytes::from(u64::MAX),
        );
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Processing {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: mock_time(),
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
fn deletes_diverged_states() {
    state_manager_crash_test(
        |state_manager| {
            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
            wait_for_checkpoint(&state_manager, height(1));

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
            wait_for_checkpoint(&state_manager, height(2));

            let (_, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(3), CertificationScope::Metadata);

            state_manager.report_diverged_state(height(3))
        },
        |metrics, state_manager| {
            assert_eq!(
                height(1),
                state_manager.get_latest_state().height(),
                "Expected diverged checkpoint@2 to go away"
            );
            let last_diverged =
                fetch_int_gauge(metrics, "state_manager_last_diverged_state_timestamp").unwrap();

            assert!(last_diverged > 0);
        },
    );
}

proptest! {
    #[test]
    fn stream_store_encode_decode(stream in arb_stream(0, 10), size_limit in 0..20usize) {
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
    fn stream_store_decode_with_modified_hash_fails(stream in arb_stream(0, 10), size_limit in 0..20usize) {
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
    fn stream_store_decode_with_empty_witness_fails(stream in arb_stream(0, 10), size_limit in 0..20usize) {
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
    fn stream_store_decode_slice_push_additional_message(stream in arb_stream(0, 10)) {
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

                    messages.push(RequestOrResponse::Request(req));

                    let signals_end = decoded_slice.header().signals_end;

                    Stream::new(messages, signals_end)
                })
            }
        );
    }

    #[test]
    #[should_panic]
    fn stream_store_decode_slice_modify_message_begin(stream in arb_stream(0, 10)) {
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
    fn stream_store_decode_slice_modify_signals_end(stream in arb_stream(0, 10)) {
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
    fn stream_store_decode_slice_push_signal(stream in arb_stream(0, 10)) {
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
    fn stream_store_decode_with_invalid_destination(stream in arb_stream(0, 10), size_limit in 0..20usize) {
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
                // we do not modify the slice before decoding it again - the wrong
                // destination subnet should already make it fail
                (state_manager, slice)
            }
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn stream_store_decode_with_rejecting_verifier(stream in arb_stream(0, 10), size_limit in 0..20usize) {
        encode_decode_stream_test(
            /* stream to be used */
            stream,
            /* size limit used upon encoding */
            Some(size_limit),
            /* custom destination subnet */
            None,
            /* certification verification should succeed */
            false,
            /* modification between encoding and decoding  */
            |state_manager, slice| {
                // we do not modify the slice before decoding it again - the signature validation
                // failure caused by passing the `RejectingVerifier` should already make it fail.
                (state_manager, slice)
            }
        );
    }

    #[test]
    fn stream_store_encode_partial((stream, begin, count) in arb_stream_slice(1, 10), byte_limit in 0..1000usize) {
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
    fn stream_store_encode_partial_bad_indices((stream, begin, count) in arb_stream_slice(1, 10), byte_limit in 0..1000usize) {
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
