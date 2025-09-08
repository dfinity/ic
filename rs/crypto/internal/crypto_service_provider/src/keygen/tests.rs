use crate::Csp;
use crate::CspPublicKey;
use crate::KeyId;
use crate::LocalCspVault;
use crate::keygen::fixtures::multi_bls_test_vector;
use crate::keygen::utils::node_signing_pk_to_proto;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use assert_matches::assert_matches;
use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_byte_vec};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types_test_utils::ids::node_test_id;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const FIXED_SEED: u64 = 42;

mod gen_node_siging_key_pair_tests {
    use super::*;
    use crate::vault::api::CspBasicSignatureKeygenError;

    #[test]
    fn should_correctly_generate_node_signing_keys() {
        let csp = csp_with_fixed_seed();
        let public_key = csp.csp_vault.gen_node_signing_key_pair().unwrap();
        let key_id = KeyId::from(&public_key);

        assert_eq!(
            key_id,
            KeyId::from(hex_to_32_bytes(
                "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
            )),
        );
        assert_eq!(
            public_key,
            CspPublicKey::ed25519_from_hex(
                "78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"
            )
        );
        assert_eq!(
            csp.csp_vault
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys")
                .node_signing_public_key
                .expect("missing key"),
            node_signing_pk_to_proto(public_key)
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_public_key_already_set() {
        let csp = Csp::builder_for_test().build();

        assert!(csp.csp_vault.gen_node_signing_key_pair().is_ok());
        let result = csp.csp_vault.gen_node_signing_key_pair();

        assert_matches!(result,
            Err(CspBasicSignatureKeygenError::InternalError { internal_error })
            if internal_error.contains("node signing public key already set")
        );

        assert_matches!(csp.csp_vault.gen_node_signing_key_pair(),
            Err(CspBasicSignatureKeygenError::InternalError { internal_error })
            if internal_error.contains("node signing public key already set")
        );
    }

    #[test]
    fn should_not_panic_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(
                        secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
                    )
                    .build(),
            )
            .build();

        let result = csp.csp_vault.gen_node_signing_key_pair();

        assert_matches!(result, Err(CspBasicSignatureKeygenError::DuplicateKeyId {key_id}) if key_id == duplicated_key_id)
    }
}

mod gen_key_pair_with_pop_tests {
    use crate::keygen::utils::committee_signing_pk_to_proto;
    use crate::vault::api::CspMultiSignatureKeygenError;

    use super::*;

    #[test]
    fn should_correctly_generate_committee_signing_keys() {
        let test_vector = multi_bls_test_vector();
        let csp = csp_seeded_with(test_vector.seed);
        let (public_key, pop) = csp.csp_vault.gen_committee_signing_key_pair().unwrap();
        let key_id = KeyId::from(&public_key);

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
        assert_eq!(pop, test_vector.proof_of_possession);

        assert_eq!(
            csp.csp_vault
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys")
                .committee_signing_public_key
                .expect("missing key"),
            committee_signing_pk_to_proto((public_key, pop))
        );
    }

    #[test]
    fn should_not_panic_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(
                        secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
                    )
                    .build(),
            )
            .build();

        let result = csp.csp_vault.gen_committee_signing_key_pair();

        assert_matches!(result, Err(CspMultiSignatureKeygenError::DuplicateKeyId {key_id}) if key_id == duplicated_key_id)
    }

    #[test]
    fn should_fail_with_internal_error_if_committee_signing_public_key_already_set() {
        let csp = Csp::builder_for_test().build();

        assert!(csp.csp_vault.gen_committee_signing_key_pair().is_ok());

        // the attempts after the first one should fail
        for _ in 0..5 {
            assert_matches!(csp.csp_vault.gen_committee_signing_key_pair(),
                Err(CspMultiSignatureKeygenError::InternalError { internal_error })
                if internal_error.contains("committee signing public key already set")
            );
        }
    }
}

mod idkg_create_mega_key_pair_tests {
    use super::*;
    use crate::api::CspCreateMEGaKeyError;
    use crate::keygen::fixtures::mega_test_vector;
    use crate::vault::test_utils::sks::{
        secret_key_store_with_io_error_on_insert,
        secret_key_store_with_serialization_error_on_insert,
    };

    #[test]
    fn should_correctly_create_mega_key_pair() {
        let test_vector = mega_test_vector();
        let csp = csp_seeded_with(test_vector.seed);
        let public_key = csp
            .csp_vault
            .idkg_gen_dealing_encryption_key_pair()
            .expect("failed creating MEGa key pair");

        assert_eq!(public_key, test_vector.public_key);
    }

    #[test]
    fn should_fail_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(
                        secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
                    )
                    .build(),
            )
            .build();

        let result = csp.csp_vault.idkg_gen_dealing_encryption_key_pair();

        assert_matches!(
            result,
            Err(CspCreateMEGaKeyError::DuplicateKeyId { key_id }) if key_id == duplicated_key_id
        );
    }

    #[test]
    fn should_handle_serialization_failure_upon_insert() {
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(
                        secret_key_store_with_serialization_error_on_insert(),
                    )
                    .build(),
            )
            .build();

        let result = csp.csp_vault.idkg_gen_dealing_encryption_key_pair();

        assert_matches!(
            result,
            Err(CspCreateMEGaKeyError::InternalError { internal_error })
            if internal_error.to_lowercase().contains("serialization error")
        );
    }

    #[test]
    fn should_handle_io_error_upon_insert() {
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_with_io_error_on_insert())
                    .build(),
            )
            .build();

        let result = csp.csp_vault.idkg_gen_dealing_encryption_key_pair();

        assert_matches!(
            result,
            Err(CspCreateMEGaKeyError::TransientInternalError { internal_error })
            if internal_error.to_lowercase().contains("io error")
        );
    }
}

#[test]
/// If this test fails, old key IDs in the SKS will no longer work!
fn should_correctly_convert_tls_cert_hash_as_key_id() {
    // openssl-generated example X509 cert.
    let cert_der = hex_to_byte_vec(
        "308201423081f5a00302010202147dfa\
         b83de61da8c8aa957cbc6ad9645f2bbc\
         c9f8300506032b657030173115301306\
         035504030c0c4446494e495459205465\
         7374301e170d32313036303331373337\
         35305a170d3231303730333137333735\
         305a30173115301306035504030c0c44\
         46494e4954592054657374302a300506\
         032b657003210026c5e95c453549621b\
         2dc6475e0dde204caa3e4f326f4728fd\
         0458e7771ac03ca3533051301d060355\
         1d0e0416041484696f2370163c1c489c\
         095dfea6574a3fa88ad5301f0603551d\
         2304183016801484696f2370163c1c48\
         9c095dfea6574a3fa88ad5300f060355\
         1d130101ff040530030101ff30050603\
         2b65700341009b0e731565bcfaedb6c7\
         0805fa75066ff931b8bc6993c10bf020\
         2c14b96ab5abd0704f163cb0a6b57621\
         2b2eb8ddf74ab60d5cdc59f906acc8a1\
         24678c290e06",
    );
    let cert = TlsPublicKeyCert::new_from_der(cert_der)
        .expect("failed to build TlsPublicKeyCert from DER");

    let key_id = KeyId::from(&cert);

    // We expect the following hard coded key id:
    let expected_key_id = KeyId::from(hex_to_32_bytes(
        "bc1f70570a2aaa0904069e1a77b710c729ac1bf026a02f14ad8613c3627b211a",
    ));
    assert_matches!(key_id, actual if actual == expected_key_id);
}

mod tls {
    use super::*;
    use crate::vault::api::CspTlsKeygenError;

    const NODE_1: u64 = 4241;

    #[test]
    fn should_correctly_generate_tls_certificate() {
        let csp = csp_with_fixed_seed();
        let cert = csp
            .csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("Generation of TLS keys failed.");
        let key_id = KeyId::from(&cert);

        assert_eq!(
            key_id,
            KeyId::from(hex_to_32_bytes(
                "3315cdead5f0368cfff6cb9c4c162ec49c14f1e912d4887271fba940a46efa68"
            )),
        );
        assert_eq!(
            &csp.csp_vault
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys")
                .tls_certificate
                .expect("missing tls certificate")
                .certificate_der,
            cert.as_der()
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_public_key_already_set() {
        let csp = Csp::builder_for_test().build();

        assert!(csp.csp_vault.gen_tls_key_pair(node_test_id(NODE_1)).is_ok());
        let result = csp.csp_vault.gen_tls_key_pair(node_test_id(NODE_1));

        assert_matches!(result,
            Err(CspTlsKeygenError::InternalError { internal_error })
            if internal_error.contains("TLS certificate already set")
        );

        assert_matches!(csp.csp_vault.gen_tls_key_pair(node_test_id(NODE_1)),
            Err(CspTlsKeygenError::InternalError { internal_error })
            if internal_error.contains("TLS certificate already set")
        );
    }

    #[test]
    fn should_not_panic_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(
                        secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
                    )
                    .build(),
            )
            .build();

        let result = csp.csp_vault.gen_tls_key_pair(node_test_id(NODE_1));

        assert_matches!(result, Err(CspTlsKeygenError::DuplicateKeyId {key_id}) if key_id == duplicated_key_id)
    }
}

fn csp_seeded_with(seed: u64) -> Csp {
    Csp::builder_for_test()
        .with_vault(
            LocalCspVault::builder_for_test()
                .with_rng(ChaCha20Rng::seed_from_u64(seed))
                .build(),
        )
        .build()
}

fn csp_with_fixed_seed() -> Csp {
    csp_seeded_with(FIXED_SEED)
}
