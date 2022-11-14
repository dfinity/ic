#![allow(clippy::unwrap_used)]

use super::*;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::api::NodePublicKeyData;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_test_utils::empty_fake_registry;
use ic_interfaces::crypto::KeyManager;
use ic_interfaces_registry::RegistryClient;
use ic_types_test_utils::ids::node_test_id;

mod node_public_key_data {
    use super::*;

    #[test]
    #[should_panic(expected = "Missing dkg dealing encryption key id")]
    fn should_panic_when_no_dkg_encryption_key() {
        CryptoConfig::run_with_temp_config(|config| {
            let csp = csp_for_config(&config, None);
            let _ = csp.dkg_dealing_encryption_key_id();
        })
    }

    #[test]
    fn should_get_dkg_dealing_encryption_key_id() {
        CryptoConfig::run_with_temp_config(|config| {
            let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
            let generated_dkg_dealing_enc_pk = CspFsEncryptionPublicKey::try_from(
                node_pks
                    .dkg_dealing_encryption_public_key
                    .expect("no dkg key"),
            )
            .expect("invalid dkg encryption key");
            let csp = csp_for_config(&config, None);

            let key_id = csp.dkg_dealing_encryption_key_id();

            assert_eq!(key_id, KeyId::from(&generated_dkg_dealing_enc_pk))
        })
    }

    #[test]
    fn should_get_correct_node_public_keys() {
        CryptoConfig::run_with_temp_config(|config| {
            let (generated_node_pks, _node_id) =
                get_node_keys_or_generate_if_missing(&config, None);
            let csp = csp_for_config(&config, None);

            let csp_pks = csp.current_node_public_keys();

            assert_eq!(generated_node_pks, csp_pks);
        })
    }
}

#[test]
fn should_have_the_csp_public_keys_that_were_previously_generated() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let csp = csp_for_config(&config, None);
        assert_eq!(node_pks, csp.current_node_public_keys());
    })
}

#[test]
fn should_generate_all_keys_for_a_node_without_public_keys() {
    CryptoConfig::run_with_temp_config(|config| {
        let csp = csp_for_config(&config, None);
        assert_eq!(
            csp.current_node_public_keys(),
            CurrentNodePublicKeys {
                node_signing_public_key: None,
                committee_signing_public_key: None,
                tls_certificate: None,
                dkg_dealing_encryption_public_key: None,
                idkg_dealing_encryption_public_key: None
            }
        );

        let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&config, None);

        ensure_node_keys_are_generated_correctly(&node_pks, &node_id);
        let csp = csp_for_config(&config, None);
        assert_eq!(node_pks, csp.current_node_public_keys());
    })
}

fn ensure_node_keys_are_generated_correctly(node_pks: &CurrentNodePublicKeys, node_id: &NodeId) {
    assert!(all_node_keys_are_present(node_pks));

    let node_signing_pk = node_pks
        .node_signing_public_key
        .as_ref()
        .expect("Missing node signing public key");
    let derived_node_id = derive_node_id(node_signing_pk);
    assert_eq!(*node_id, derived_node_id);
}

#[test]
#[should_panic(expected = "inconsistent key material")]
fn should_panic_if_node_has_inconsistent_keys() {
    let (temp_crypto, _node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_node_signing_key(),
        );
        node_keys2.node_signing_pk
    };

    // Store different_node_signing_pk in temp_crypto's crypto_root.
    store_public_keys(
        temp_crypto.temp_dir_path(),
        &NodePublicKeys {
            node_signing_pk: different_node_signing_pk,
            ..Default::default()
        },
    );
    let config = CryptoConfig::new(temp_crypto.temp_dir_path().to_path_buf());
    let (_node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
}

#[test]
fn check_keys_locally_returns_none_if_no_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let result = check_keys_locally(&config, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    })
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_node_signing_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_node_signing_key(),
        );
        node_keys2.node_signing_pk
    };
    assert_ne!(node_keys.node_signing_pk, different_node_signing_pk);
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            node_signing_pk: different_node_signing_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::Ed25519
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_committee_signing_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_committee_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_committee_signing_key(),
        );
        node_keys2.committee_signing_pk
    };
    assert_ne!(
        node_keys.committee_signing_pk,
        different_committee_signing_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            committee_signing_pk: different_committee_signing_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::MultiBls12_381
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_dkg_dealing_encryption_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_dkg_dealing_enc_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_dkg_dealing_encryption_key(),
        );
        node_keys2.dkg_dealing_encryption_pk
    };
    assert_ne!(
        node_keys.dkg_dealing_encryption_pk,
        different_dkg_dealing_enc_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            dkg_dealing_encryption_pk: different_dkg_dealing_enc_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::Groth20_Bls12_381
    ));
}

#[test]
fn should_fail_check_keys_locally_for_new_node_if_no_matching_idkg_dealing_encryption_secret_key_is_present(
) {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_idkg_dealing_enc_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_idkg_dealing_encryption_key(),
        );
        node_keys2
            .idkg_dealing_encryption_pks
            .first()
            .expect("no idkg dealing encryption key")
            .clone()
    };
    assert_ne!(
        node_keys
            .idkg_dealing_encryption_pks
            .first()
            .expect("no idkg dealing encryption key"),
        &different_idkg_dealing_enc_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            idkg_dealing_encryption_pks: vec![different_idkg_dealing_enc_pk],
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::MegaSecp256k1
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_tls_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_tls_cert = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_tls_key_and_cert(),
        );
        node_keys2.tls_certificate
    };
    assert_ne!(node_keys.tls_certificate, different_tls_cert);
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            tls_certificate: different_tls_cert,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::TlsSecretKeyNotFound { .. })
    ));
}

#[test]
fn should_fail_check_keys_locally_if_idkg_dealing_encryption_public_key_is_missing() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            idkg_dealing_encryption_pks: vec![],
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::MalformedPublicKey { algorithm, internal_error, .. })
        if algorithm == AlgorithmId::MegaSecp256k1 && internal_error.contains("missing iDKG dealing encryption key in local public key store")
    ));
}

#[test]
fn should_succeed_check_keys_locally_if_all_keys_are_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    store_public_keys(crypto_root.as_path(), &node_keys);

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(result, Ok(Some(_))));
}

#[test]
fn should_succeed_check_keys_locally_if_no_keys_are_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::none(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    store_public_keys(crypto_root.as_path(), &node_keys);

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(result, Ok(None)));
}

fn all_node_keys_are_present(node_pks: &CurrentNodePublicKeys) -> bool {
    node_pks.node_signing_public_key.is_some()
        && node_pks.committee_signing_public_key.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_public_key.is_some()
        && node_pks.idkg_dealing_encryption_public_key.is_some()
}

fn store_public_keys(crypto_root: &Path, node_pks: &NodePublicKeys) {
    public_key_store::store_node_public_keys(crypto_root, node_pks).unwrap();
}

fn crypto_with_node_keys_generation(
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
    selector: NodeKeysToGenerate,
) -> (TempCryptoComponent, NodePublicKeys) {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(registry_client)
        .with_node_id(node_id)
        .with_keys(selector)
        .build();
    let current_node_public_keys = temp_crypto.current_node_public_keys();
    let node_public_keys = NodePublicKeys::from(current_node_public_keys);
    (temp_crypto, node_public_keys)
}

mod tls {
    use super::generate_tls_keys;
    use super::local_csp_in_temp_dir;
    use ic_types_test_utils::ids::node_test_id;
    use openssl::x509::X509VerifyResult;
    use openssl::{asn1::Asn1Time, nid::Nid, x509::X509NameEntryRef, x509::X509};

    const NODE_ID: u64 = 123;

    #[test]
    fn should_return_self_signed_certificate() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();
        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_not_set_subject_alt_name() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();
        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let subject_alt_names = x509_cert.subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_cert_issuer_and_subject_cn_as_node_id() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();

        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let issuer_cn = issuer_cn(x509_cert);
        let subject_cn = subject_cn(x509_cert);
        let expected_cn = node_test_id(NODE_ID).get().to_string();
        assert_eq!(expected_cn.as_bytes(), issuer_cn.data().as_slice());
        assert_eq!(expected_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        const RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE: &str = "99991231235959Z";
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();

        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let expected_not_after =
            Asn1Time::from_str_x509(RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE).unwrap();
        assert!(cert.as_x509().not_after() == expected_not_after);
    }

    fn subject_cn(x509_cert: &X509) -> &X509NameEntryRef {
        x509_cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
    }

    fn issuer_cn(x509_cert: &X509) -> &X509NameEntryRef {
        x509_cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
    }
}

mod idkg {
    use super::*;
    use crate::IDkgDealingEncryptionKeysGenerationError;
    use std::fs;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn should_correctly_generate_idkg_dealing_encryption_key() {
        CryptoConfig::run_with_temp_config(|config| {
            let mut csp = csp_for_config(&config, None);
            let public_key = generate_idkg_dealing_encryption_keys(&mut csp)
                .expect("error generation I-DKG dealing encryption keys");
            assert_eq!(public_key.version, 0);
            assert_eq!(public_key.algorithm, AlgorithmIdProto::MegaSecp256k1 as i32);
            assert!(!public_key.key_value.is_empty());
            assert!(public_key.proof_data.is_none());
            assert!(public_key.timestamp.is_none());
        })
    }

    #[test]
    fn should_fail_to_generate_idkg_dealing_encryption_keys_when_crypto_root_dir_write_protected() {
        let (mut csp, temp_dir) = local_csp_in_temp_dir();

        // make the crypto root directory non-writeable, causing
        // ic_utils::fs::write_protobuf_using_tmp_file to fail
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o400))
            .expect("Could not set the permissions of the temp dir.");

        assert!(matches!(
            generate_idkg_dealing_encryption_keys(&mut csp),
            Err(IDkgDealingEncryptionKeysGenerationError::TransientInternalError(msg))
            if msg.to_lowercase().contains("secret key store internal error writing protobuf using tmp file: permission denied")
        ));
    }
}
