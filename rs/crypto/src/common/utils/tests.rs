#![allow(clippy::unwrap_used)]

use super::*;
use ic_config::crypto::CryptoConfig;
use ic_test_utilities::crypto::empty_fake_registry;
use ic_test_utilities::types::ids::node_test_id;

fn store_public_keys(crypto_root: &Path, node_pks: &NodePublicKeys) {
    public_key_store::store_node_public_keys(crypto_root, node_pks).unwrap();
}

#[test]
fn should_generate_all_keys_for_new_node() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config.crypto_root);
        assert!(all_node_keys_are_present(&node_pks));
        let result = check_keys_locally(&config.crypto_root);
        assert!(result.is_ok());
        let maybe_pks = result.unwrap();
        assert!(maybe_pks.is_some());
        assert_eq!(maybe_pks.unwrap(), node_pks);
        // TODO(CRP-356): add a check for the derived node_id.
    })
}

#[test]
fn should_generate_all_keys_for_a_node_without_public_keys() {
    CryptoConfig::run_with_temp_config(|config| {
        let first_node_signing_pk = generate_node_signing_keys(&config.crypto_root);
        // first_node_signing_pk NOT saved.
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config.crypto_root);
        assert!(all_node_keys_are_present(&node_pks));
        let result = check_keys_locally(&config.crypto_root);
        assert!(result.is_ok());
        let maybe_pks = result.unwrap();
        assert!(maybe_pks.is_some());
        let node_pks = maybe_pks.unwrap();
        assert_ne!(first_node_signing_pk, node_pks.node_signing_pk.unwrap());
        // TODO(CRP-356): add a check for the derived node_id.
    })
}

#[test]
#[should_panic(expected = "inconsistent key material")]
fn should_panic_if_node_has_inconsistent_keys() {
    let (temp_crypto, _node_keys) = TempCryptoComponent::new_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = TempCryptoComponent::new_with_node_keys_generation(
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
    let (_node_pks, _node_id) = get_node_keys_or_generate_if_missing(temp_crypto.temp_dir_path());
}

#[test]
fn check_keys_locally_returns_none_if_no_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let result = check_keys_locally(&config.crypto_root);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    })
}

#[test]
fn check_keys_locally_returns_none_if_no_public_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let _node_signing_pk = generate_node_signing_keys(&config.crypto_root);
        // _node_signing_pk NOT saved.
        let result = check_keys_locally(&config.crypto_root);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    })
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_secret_key_is_present() {
    let (temp_crypto, node_keys) = TempCryptoComponent::new_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let crypto_root = temp_crypto.temp_dir_path();
    let node_signing_pk = node_keys.node_signing_pk;
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = TempCryptoComponent::new_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_node_signing_key(),
        );
        node_keys2.node_signing_pk
    };

    // Fail the check if `different_node_signing_pk` is stored.
    store_public_keys(
        crypto_root,
        &NodePublicKeys {
            node_signing_pk: different_node_signing_pk,
            ..Default::default()
        },
    );
    let result = check_keys_locally(crypto_root);
    assert!(result.is_err());

    // Succeed the check if node_signing_pk is stored.
    store_public_keys(
        crypto_root,
        &NodePublicKeys {
            node_signing_pk,
            ..Default::default()
        },
    );
    let result = check_keys_locally(crypto_root);
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn should_succeed_check_keys_locally_if_all_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let node_signing_pk = Some(generate_node_signing_keys(&config.crypto_root));
        store_public_keys(
            &config.crypto_root,
            &NodePublicKeys {
                node_signing_pk,
                ..Default::default()
            },
        );
        let result = check_keys_locally(&config.crypto_root);
        assert!(result.is_ok());
    })
}

mod tls {
    use super::super::generate_tls_keys;
    use ic_test_utilities::crypto::temp_dir::temp_dir;
    use ic_test_utilities::types::ids::node_test_id;
    use openssl::x509::X509VerifyResult;
    use openssl::{asn1::Asn1Time, nid::Nid, x509::X509NameEntryRef, x509::X509};

    const NODE_ID: u64 = 123;

    #[test]
    fn should_return_self_signed_certificate() {
        let temp_dir = temp_dir();

        let cert = generate_tls_keys(&temp_dir.into_path(), node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_not_set_subject_alt_name() {
        let temp_dir = temp_dir();

        let cert = generate_tls_keys(&temp_dir.into_path(), node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let subject_alt_names = x509_cert.subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_cert_issuer_and_subject_cn_as_node_id() {
        let temp_dir = temp_dir();

        let cert = generate_tls_keys(&temp_dir.into_path(), node_test_id(NODE_ID));

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
        let temp_dir = temp_dir();

        let cert = generate_tls_keys(&temp_dir.into_path(), node_test_id(NODE_ID));

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

mod committee_signing {
    use super::super::generate_committee_signing_keys;
    use ic_config::crypto::CryptoConfig;
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;

    #[test]
    fn should_generate_committee_signing_key_with_version_0() {
        CryptoConfig::run_with_temp_config(|config| {
            let public_key = generate_committee_signing_keys(&config.crypto_root);
            assert_eq!(public_key.version, 0);
        })
    }

    #[test]
    fn should_generate_committee_signing_key_with_correct_algorithm() {
        CryptoConfig::run_with_temp_config(|config| {
            let public_key = generate_committee_signing_keys(&config.crypto_root);
            assert_eq!(public_key.algorithm, AlgorithmIdProto::MultiBls12381 as i32);
        })
    }

    #[test]
    fn should_generate_committee_signing_key_with_non_empty_key_value() {
        CryptoConfig::run_with_temp_config(|config| {
            let public_key = generate_committee_signing_keys(&config.crypto_root);
            assert!(!public_key.key_value.is_empty());
        })
    }

    #[test]
    fn should_generate_committee_signing_key_with_proof_data() {
        CryptoConfig::run_with_temp_config(|config| {
            let public_key = generate_committee_signing_keys(&config.crypto_root);
            assert!(public_key.proof_data.is_some());
        })
    }
}

fn all_node_keys_are_present(node_pks: &NodePublicKeys) -> bool {
    node_pks.node_signing_pk.is_some()
        && node_pks.committee_signing_pk.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_pk.is_some()
}
