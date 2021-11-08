use ic_config::state_manager::Config;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, MixedHashTree};
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactProcessor},
    certification::Verifier,
    certified_stream_store::{CertifiedStreamStore, EncodeStreamError},
    state_manager::*,
};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    testing::ReplicatedStateTesting, NumWasmPages64, PageMap, ReplicatedState, Stream,
};
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    metrics::fetch_int_gauge,
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
    crypto::CryptoHash,
    ingress::{IngressStatus, WasmResult},
    messages::{CallbackId, RequestOrResponse},
    xnet::{StreamIndex, StreamIndexedQueue},
    CanisterId, CryptoHashOfPartialState, CryptoHashOfState, Height, PrincipalId,
};
use proptest::prelude::*;
use std::convert::{TryFrom, TryInto};
use std::path::Path;
use std::sync::Arc;
use tempfile::Builder;

pub mod common;
use common::*;
use ic_registry_subnet_type::SubnetType;

fn make_mutable(path: &Path) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_at(path: &Path, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;

    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;
    f.write_at(buf, offset)?;
    Ok(())
}

fn tree_payload(t: MixedHashTree) -> LabeledTree<Vec<u8>> {
    t.try_into().unwrap()
}

fn label<T: Into<Label>>(t: T) -> Label {
    t.into()
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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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
        canister_state.system_state.stable_memory_size = NumWasmPages64::new(2);
        canister_state.system_state.stable_memory = PageMap::from(&[1; 100][..]);
        state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, state) = state_manager.take_tip();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert_eq!(
            NumWasmPages64::new(2),
            canister_state.system_state.stable_memory_size
        );
        assert_eq!(
            PageMap::from(&[1; 100][..]),
            canister_state.system_state.stable_memory
        );

        let state_manager = restart_fn(state_manager);

        let recovered = state_manager.get_latest_state();
        assert_eq!(height(1), recovered.height());
        let state = recovered.take();
        let canister_state = state.canister_state(&canister_test_id(100)).unwrap();
        assert_eq!(
            NumWasmPages64::new(2),
            canister_state.system_state.stable_memory_size
        );
        assert_eq!(
            PageMap::from(&[1; 100][..]),
            canister_state.system_state.stable_memory
        );
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
                ic_types::malicious_flags::MaliciousFlags::default(),
            ),
        );
    });
}

#[test]
fn commit_remembers_state() {
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
        assert_eq!(
            state_manager.get_state_at(height(0)).unwrap().height(),
            height(0)
        );
    });
}

#[test]
fn latest_state_height_updated_on_commit() {
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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
                ic_types::malicious_flags::MaliciousFlags::default(),
            );
            assert_eq!(vec![height(1)], heights_to_certify(&state_manager));
        }
    });
}

#[test]
fn can_filter_by_certification_mask() {
    state_manager_test(|state_manager| {
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

        let state_manager = restart_fn(state_manager);

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
            vec![height(0), height(4), height(6), height(8), height(9)],
        );

        assert_eq!(height(9), state_manager.latest_state_height());
        let latest_state = state_manager.get_latest_state();
        assert_eq!(height(9), latest_state.height());

        let state_manager = restart_fn(state_manager);

        assert_eq!(
            state_manager.list_state_heights(CERT_ANY),
            vec![height(0), height(4), height(6), height(8),],
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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);

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

        let state_manager = restart_fn(state_manager);
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
    state_manager_test(|state_manager| {
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

#[test]
fn can_remove_below_future_states_once_reached() {
    state_manager_test(|state_manager| {
        let commit_state = |h| {
            let (_height, state) = state_manager.take_tip();
            state_manager.commit_and_certify(state, height(h), CertificationScope::Full);
            wait_for_checkpoint(&state_manager, height(h));
        };

        commit_state(1);
        commit_state(2);
        commit_state(3);
        assert!(state_manager.get_state_at(height(2)).is_ok());

        state_manager.remove_states_below(height(6));

        assert_eq!(state_manager.latest_state_height(), height(3));

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(4), CertificationScope::Metadata);

        let (_height, state) = state_manager.take_tip();
        state_manager.commit_and_certify(state, height(5), CertificationScope::Metadata);

        commit_state(6);

        assert_eq!(
            state_manager.get_state_at(height(4)),
            Err(StateManagerError::StateRemoved(height(4)))
        );

        // The state at height 5 still exists because it is still the latest in-memory
        // state when the `remove_states_below(6)` is called in commit_state(6)
        assert!(state_manager.get_state_at(height(5)).is_ok());

        state_manager.remove_states_below(height(6));
        assert_eq!(
            state_manager.get_state_at(height(5)),
            Err(StateManagerError::StateRemoved(height(5)))
        );

        assert_eq!(state_manager.latest_state_height(), height(6));
    });
}

#[test]
fn latest_certified_state_is_updated_on_state_removal() {
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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

        let state_manager = restart_fn(state_manager);

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
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
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

        let state_manager = restart_fn(state_manager);

        assert_eq!(cert_hashes, state_manager.list_state_hashes_to_certify());
    })
}

#[test]
fn state_sync_message_contains_manifest() {
    state_manager_test(|state_manager| {
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
        // Only "system_metadata.cbor" and "subnet_queues.cbor" as we don't have
        // any canisters in the default state.
        assert_eq!(2, msg.manifest.file_table.len());

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
    state_manager_test(|state_manager| {
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

#[test]
fn can_do_simple_state_sync_transfer() {
    state_manager_test(|src_state_manager| {
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

        state_manager_test(|dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
            assert!(
                result.is_ok(),
                "Failed to process state sync artifact: {:?}",
                result
            );

            let recovered_state = dst_state_manager
                .get_state_at(height(1))
                .expect("Destination state manager didn't receive the state")
                .take();

            assert_eq!(height(1), dst_state_manager.latest_state_height());
            assert_eq!(state, recovered_state);
            assert_eq!(*state.as_ref(), dst_state_manager.take_tip().1);
            assert_eq!(vec![height(1)], heights_to_certify(&dst_state_manager));
        })
    })
}

#[test]
fn can_state_sync_into_existing_checkpoint() {
    state_manager_test(|src_state_manager| {
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

        state_manager_test(|dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            dst_state_manager.take_tip();
            dst_state_manager.commit_and_certify(
                state.clone(),
                height(1),
                CertificationScope::Full,
            );

            let dst_msg = pipe_state_sync(msg, chunkable);
            let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
            assert!(
                result.is_ok(),
                "Failed to process state sync artifact: {:?}",
                result
            );
        })
    })
}

#[test]
fn can_state_sync_based_on_old_checkpoint() {
    state_manager_test(|src_state_manager| {
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

        state_manager_test(|dst_state_manager| {
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
        })
    });
}

#[test]
fn can_recover_from_corruption_on_state_sync() {
    use ic_replicated_state::page_map::PageIndex;
    use ic_state_layout::{CheckpointLayout, RwPolicy};
    use ic_sys::PAGE_SIZE;

    fn populate_original_state(state: &mut ReplicatedState) {
        insert_dummy_canister(state, canister_test_id(90));
        insert_dummy_canister(state, canister_test_id(100));

        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.page_map.update(&[
            (PageIndex::new(1), &[99u8; PAGE_SIZE]),
            (PageIndex::new(300), &[99u8; PAGE_SIZE]),
        ]);

        let canister_state = state.canister_state_mut(&canister_test_id(100)).unwrap();
        canister_state
            .system_state
            .stable_memory
            .update(&[(PageIndex::new(0), &[255u8; PAGE_SIZE])]);
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        execution_state.page_map.update(&[
            (PageIndex::new(1), &[100u8; PAGE_SIZE]),
            (PageIndex::new(300), &[100u8; PAGE_SIZE]),
        ]);
    }

    state_manager_test(|src_state_manager| {
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
        // be re-used as a chunk.
        execution_state
            .page_map
            .update(&[(PageIndex::new(300), &[2u8; PAGE_SIZE])]);

        let canister_state = state.canister_state_mut(&canister_test_id(90)).unwrap();
        let execution_state = canister_state.execution_state.as_mut().unwrap();
        // Add a new page much further in the file so that the first one could
        // be re-used as a chunk.
        execution_state
            .page_map
            .update(&[(PageIndex::new(300), &[3u8; PAGE_SIZE])]);

        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);

        let hash_2 = wait_for_checkpoint(&src_state_manager, height(2));
        let id = StateSyncArtifactId {
            height: height(2),
            hash: hash_2,
        };
        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync message");

        state_manager_test(|dst_state_manager| {
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
            write_at(&canister_90_raw_pb, b"Garbage", 0).unwrap();

            let canister_100_layout = mutable_cp_layout.canister(&canister_test_id(100)).unwrap();

            let canister_100_memory = canister_100_layout.vmemory_0();
            make_mutable(&canister_100_memory).unwrap();
            write_at(&canister_100_memory, &[3u8; PAGE_SIZE], 4).unwrap();

            let canister_100_stable_memory = canister_100_layout.stable_memory_blob();
            make_mutable(&canister_100_stable_memory).unwrap();
            write_at(
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
        })
    });
}

#[test]
fn can_commit_below_state_sync() {
    state_manager_test(|src_state_manager| {
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

        state_manager_test(|dst_state_manager| {
            let chunkable = dst_state_manager.create_chunkable_state(&id);

            let dst_msg = pipe_state_sync(msg, chunkable);
            let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
            assert!(
                result.is_ok(),
                "Failed to process state sync artifact: {:?}",
                result
            );

            dst_state_manager.take_tip();
            // Check committing an old state doesn't panic
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        })
    })
}

#[test]
fn can_short_circuit_state_sync() {
    state_manager_test(|state_manager| {
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

#[test]
fn certified_read_can_certify_ingress_history_entry() {
    use LabeledTree::*;

    state_manager_test(|state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
            },
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

    state_manager_test(|state_manager| {
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

    state_manager_test(|state_manager| {
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
    state_manager_test(|state_manager| {
        let (_, mut state) = state_manager.take_tip();

        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
            },
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

    state_manager_test(|state_manager| {
        let (_, mut state) = state_manager.take_tip();
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Completed {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                result: WasmResult::Reply(b"done".to_vec()),
                time: mock_time(),
            },
        );
        state.set_ingress_status(
            message_test_id(2),
            IngressStatus::Processing {
                receiver: canister_test_id(1).get(),
                user_id: user_test_id(1),
                time: mock_time(),
            },
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
