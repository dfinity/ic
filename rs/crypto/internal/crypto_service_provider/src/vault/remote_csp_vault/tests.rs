// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::LocalCspVault;
use crate::RemoteCspVault;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::CspVault;
use crate::vault::remote_csp_vault::TarpcCspVaultServerImpl;
use crate::vault::test_utils;
use assert_matches::assert_matches;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::setup_listener;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_for_test;
use std::sync::Arc;
use std::time::Duration;

fn new_remote_csp_vault(rt_handle: &tokio::runtime::Handle) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    Arc::new(
        RemoteCspVault::builder(socket_path, rt_handle.clone())
            .build()
            .expect("Could not create RemoteCspVault"),
    )
}

fn new_remote_csp_vault_with_local_csp_vault<C: CspVault + 'static>(
    rt_handle: &tokio::runtime::Handle,
    local_csp_vault: Arc<C>,
) -> Arc<dyn CspVault> {
    let (socket_path, sks_dir, listener) = setup_listener(rt_handle);
    let server = TarpcCspVaultServerImpl::builder_for_test(local_csp_vault).build(listener);

    rt_handle.spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    Arc::new(
        RemoteCspVault::builder(socket_path, rt_handle.clone())
            .build()
            .expect("Could not create RemoteCspVault"),
    )
}

// Starts a fresh CSP Vault server instance for testing, and creates a CSP Vault client
// that is connected to the server.  Returns the resulting `CspVault`-object, which will
// use the specified `timeout` when making RPC calls to the server.
fn new_csp_vault_for_test_with_timeout(
    timeout: Duration,
    rt_handle: &tokio::runtime::Handle,
) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    Arc::new(
        RemoteCspVault::builder(socket_path, rt_handle.clone())
            .with_rpc_timeout(timeout)
            .with_long_rpc_timeout(timeout)
            .build()
            .expect("Could not create RemoteCspVault"),
    )
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
}

mod timeout {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateFsKeyError;
    use ic_types::NodeId;
    use ic_types::PrincipalId;

    #[test]
    fn should_fail_with_deadline_exceeded() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault =
            new_csp_vault_for_test_with_timeout(Duration::from_millis(1), tokio_rt.handle());
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1u64));
        let gen_key_result = csp_vault.gen_dealing_encryption_key_pair(node_id);

        assert_matches!(gen_key_result,
            Err(CspDkgCreateFsKeyError::TransientInternalError ( internal_error ))
            if internal_error.contains("the request exceeded its deadline")
        );
    }
}

mod ni_dkg {
    use super::*;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
    use ic_types_test_utils::ids::NODE_42;
    use mockall::Sequence;
    use std::io;

    #[test]
    fn test_retention() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_retention(|| new_remote_csp_vault(tokio_rt.handle()));
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_1() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [1; 32],
            MockNetwork::MIN_SIZE,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [2; 32],
            MockNetwork::MIN_SIZE + 1,
            1,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [3; 32],
            MockNetwork::MIN_SIZE + 1,
            2,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn create_dealing_should_detect_errors_1() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [11; 32],
            MockNetwork::MIN_SIZE,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [22; 32],
            MockNetwork::MIN_SIZE + 2,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [33; 32],
            MockNetwork::DEFAULT_MAX_SIZE - 1,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    #[test]
    fn should_generate_dealing_encryption_key_pair_and_store_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::ni_dkg::should_generate_dealing_encryption_key_pair_and_store_keys(csp_vault);
    }

    #[test]
    fn should_store_dealing_encryption_secret_key_before_public_key() {
        let local_vault = {
            let mut seq = Sequence::new();
            let mut sks = MockSecretKeyStore::new();
            sks.expect_insert()
                .times(1)
                .returning(|_key, _key_id, _scope| Ok(()))
                .in_sequence(&mut seq);
            let mut pks = MockPublicKeyStore::new();
            pks.expect_set_once_ni_dkg_dealing_encryption_pubkey()
                .times(1)
                .returning(|_key| Ok(()))
                .in_sequence(&mut seq);
            LocalCspVault::builder_for_test()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        assert!(
            remote_vault
                .gen_dealing_encryption_key_pair(NODE_42)
                .is_ok()
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_dealing_encryption_key_already_set() {
        let local_vault = {
            let mut pks_returning_already_set_error = MockPublicKeyStore::new();
            pks_returning_already_set_error
                .expect_set_once_ni_dkg_dealing_encryption_pubkey()
                .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
            LocalCspVault::builder_for_test()
                .with_public_key_store(pks_returning_already_set_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::ni_dkg::should_fail_with_internal_error_if_ni_dkg_dealing_encryption_key_already_set(
            remote_vault,
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_dealing_encryption_key_generated_more_than_once() {
        let tokio_rt = new_tokio_runtime();
        let vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::ni_dkg::should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once(
            vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_dealing_encryption_key_persistence_fails() {
        let local_vault = {
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            let io_error = io::Error::other("oh no!");
            pks_returning_io_error
                .expect_set_once_ni_dkg_dealing_encryption_pubkey()
                .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
            LocalCspVault::builder_for_test()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::ni_dkg::should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails(
            remote_vault,
        );
    }
}

mod idkg {
    use super::*;
    use crate::public_key_store::PublicKeyAddError;
    use mockall::Sequence;

    #[test]
    fn should_generate_and_store_dealing_encryption_key_pair_multiple_times() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::idkg::should_generate_and_store_dealing_encryption_key_pair_multiple_times(
            csp_vault,
        );
    }

    #[test]
    fn should_store_idkg_secret_key_before_public_key() {
        let local_vault = {
            let mut seq = Sequence::new();
            let mut sks = MockSecretKeyStore::new();
            sks.expect_insert()
                .times(1)
                .returning(|_key, _key_id, _scope| Ok(()))
                .in_sequence(&mut seq);
            let mut pks = MockPublicKeyStore::new();
            pks.expect_add_idkg_dealing_encryption_pubkey()
                .times(1)
                .return_once(|_key| Ok(()))
                .in_sequence(&mut seq);
            LocalCspVault::builder_for_test()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };

        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        assert!(remote_vault.idkg_gen_dealing_encryption_key_pair().is_ok())
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails() {
        let local_vault = {
            let io_error = std::io::Error::other("oh no!");
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            pks_returning_io_error
                .expect_add_idkg_dealing_encryption_pubkey()
                .return_once(|_| Err(PublicKeyAddError::Io(io_error)));
            LocalCspVault::builder_for_test()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::idkg::should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(remote_vault);
    }
}

mod logging {
    use super::*;
    use crate::CryptoMetrics;
    use ic_logger::ReplicaLogger;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use slog::Level;

    #[test]
    fn should_log_payload_size_transmitted_over_rpc_socket() {
        let in_memory_logger = InMemoryReplicaLogger::new();
        let tokio_rt = new_tokio_runtime();
        let socket_path = start_new_remote_csp_vault_server_for_test(tokio_rt.handle());
        let csp_vault = RemoteCspVault::new(
            &socket_path,
            tokio_rt.handle().clone(),
            ReplicaLogger::from(&in_memory_logger),
            Arc::new(CryptoMetrics::none()),
        )
        .expect("failed instantiating remote CSP vault client");

        csp_vault
            .gen_node_signing_key_pair()
            .expect("failed to generate keys");

        let logs = in_memory_logger.drain_logs();

        LogEntriesAssert::assert_that(logs)
            .has_len(5)
            .has_only_one_message_containing(&Level::Debug, "Instantiated remote CSP vault client")
            .has_only_one_message_containing(
                &Level::Debug,
                "CSP vault client sent 37 bytes (request to 'gen_node_signing_key_pair')",
            )
            .has_only_one_message_containing(
                &Level::Debug,
                "CSP vault client received 38 bytes (response of 'gen_node_signing_key_pair')",
            );
    }
}

mod single_call_bincode {
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use rand::{Rng, RngCore};
    use serde::Serialize;
    use std::pin::Pin;
    use tokio_serde::Serializer;

    fn flip(bytes: &[u8]) -> Vec<u8> {
        let mut result = bytes.to_vec();
        for b in result.iter_mut() {
            *b = !*b;
        }
        result
    }

    #[derive(Default)]
    struct IncrementOnSerialization {
        counter: std::cell::RefCell<usize>,
        pub dummy: Vec<u8>,
    }

    impl IncrementOnSerialization {
        pub fn counter(&self) -> usize {
            *self.counter.borrow()
        }
    }

    impl Serialize for IncrementOnSerialization {
        // flips bits of `dummy` on serialization
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            *self.counter.borrow_mut() += 1;
            flip(self.dummy.as_slice()).serialize(serializer)
        }
    }

    #[test]
    fn should_call_serialization_once_and_have_consistent_encoding() {
        let rng = &mut reproducible_rng();
        let len: usize = rng.gen_range(0..1000);
        let mut dummy = vec![0; len];
        rng.fill_bytes(dummy.as_mut_slice());
        // tokio serde implemented the Bincode object using
        // `Options::serialize()`, which calls the serialization twice: once to
        // determine the size of the object and once to serialize it
        let bytes_tokio_bincode = {
            let inc_on_ser = IncrementOnSerialization {
                dummy: dummy.clone(),
                ..Default::default()
            };
            assert_eq!(inc_on_ser.counter(), 0);
            let mut bincode = tokio_serde::formats::Bincode::<
                IncrementOnSerialization,
                IncrementOnSerialization,
            >::default();
            let bytes = Pin::new(&mut bincode)
                .serialize(&inc_on_ser)
                .expect("failed to serialize");
            assert_eq!(inc_on_ser.counter(), 2);
            bytes
        };
        // we implement the Bincode object using `Options::serialize_into()`,
        // which should call the serialization only once
        let bytes_our_bincode = {
            let inc_on_ser = IncrementOnSerialization {
                dummy,
                ..Default::default()
            };
            assert_eq!(inc_on_ser.counter(), 0);
            let mut bincode = crate::vault::remote_csp_vault::codec::Bincode::<
                IncrementOnSerialization,
                IncrementOnSerialization,
            >::default();
            let bytes = Pin::new(&mut bincode)
                .serialize(&inc_on_ser)
                .expect("failed to serialize");
            assert_eq!(inc_on_ser.counter(), 1);
            bytes
        };
        assert_eq!(bytes_tokio_bincode, bytes_our_bincode);
    }
}

mod worker_thread_pool {
    // This test is to ensure that the number of threads returned by
    // `std::thread::available_parallelism()` is the same as was set by the
    // `threadpool`s `Builder` that uses the `num_cpus` crate.
    // The goal is to ensure that we have the same number of threads after
    // replacing `threadpool` with `rayon`.
    #[test]
    fn std_available_parallelism_consistent_with_num_cpus_get() {
        assert_eq!(
            std::thread::available_parallelism()
                .expect("failed to obtain number of threads from std")
                .get(),
            num_cpus::get()
        );
    }
}
