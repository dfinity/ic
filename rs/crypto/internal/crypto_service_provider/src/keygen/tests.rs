#![allow(clippy::unwrap_used)]
use super::*;
use crate::keygen::fixtures::multi_bls_test_vector;
use crate::keygen::utils::node_signing_pk_to_proto;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_byte_vec};
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::X509NameEntries;
use openssl::{asn1::Asn1Time, bn::BigNum, nid::Nid, x509::X509};
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod gen_node_siging_key_pair_tests {
    use super::*;
    use crate::NodePublicKeyData;

    #[test]
    fn should_correctly_generate_node_signing_keys() {
        let csp = Csp::with_rng(rng());
        let public_key = csp.gen_node_signing_key_pair().unwrap();
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
            csp.current_node_public_keys()
                .node_signing_public_key
                .expect("missing key"),
            node_signing_pk_to_proto(public_key)
        );
        assert!(csp.sks_contains(&key_id).is_ok());
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_public_key_already_set() {
        let csp = Csp::with_rng(rng());

        assert!(csp.gen_node_signing_key_pair().is_ok());
        let result = csp.gen_node_signing_key_pair();

        assert!(matches!(result,
            Err(CryptoError::InternalError { internal_error })
            if internal_error.contains("node signing public key already set")
        ));

        assert!(matches!(csp.gen_node_signing_key_pair(),
            Err(CryptoError::InternalError { internal_error })
            if internal_error.contains("node signing public key already set")
        ));
    }

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::of(
            rng(),
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
            MockPublicKeyStore::new(),
        );

        let _ = csp.gen_node_signing_key_pair();
    }
}

mod gen_key_pair_with_pop_tests {
    use crate::{api::NodePublicKeyData, keygen::utils::committee_signing_pk_to_proto};

    use super::*;

    #[test]
    fn should_correctly_generate_committee_signing_keys() {
        let test_vector = multi_bls_test_vector();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::with_rng(csprng);
        let (public_key, pop) = csp.gen_committee_signing_key_pair().unwrap();
        let key_id = KeyId::from(&public_key);

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
        assert_eq!(pop, test_vector.proof_of_possession);

        assert_eq!(
            csp.current_node_public_keys()
                .committee_signing_public_key
                .expect("missing key"),
            committee_signing_pk_to_proto((public_key, pop))
        );
    }

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::of(
            rng(),
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
            MockPublicKeyStore::new(),
        );

        let _ = csp.gen_committee_signing_key_pair();
    }

    #[test]
    fn should_fail_with_internal_error_if_committee_signing_public_key_already_set() {
        let csp = Csp::with_rng(rng());

        assert!(csp.gen_committee_signing_key_pair().is_ok());

        // the attemtps after the first one should fail
        for _ in 0..5 {
            assert!(matches!(csp.gen_committee_signing_key_pair(),
                Err(CryptoError::InvalidArgument { message })
                if message.contains("committee signing public key already set")
            ));
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
    use crate::CspIDkgProtocol;

    #[test]
    fn should_correctly_create_mega_key_pair() {
        let test_vector = mega_test_vector();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::with_rng(csprng);
        let public_key = csp
            .idkg_gen_dealing_encryption_key_pair()
            .expect("failed creating MEGa key pair");

        assert_eq!(public_key, test_vector.public_key);
    }

    #[test]
    fn should_fail_upon_duplicate_key() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::of(
            rng(),
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
            MockPublicKeyStore::new(),
        );

        let result = csp.idkg_gen_dealing_encryption_key_pair();

        assert!(matches!(
            result,
            Err(CspCreateMEGaKeyError::DuplicateKeyId { key_id }) if key_id == duplicated_key_id
        ));
    }

    #[test]
    fn should_handle_serialization_failure_upon_insert() {
        let csp = Csp::of(
            rng(),
            secret_key_store_with_serialization_error_on_insert(),
            MockPublicKeyStore::new(),
        );

        let result = csp.idkg_gen_dealing_encryption_key_pair();

        assert!(matches!(
            result,
            Err(CspCreateMEGaKeyError::InternalError { internal_error }) if internal_error.to_lowercase().contains("serialization error")
        ));
    }

    #[test]
    fn should_handle_io_error_upon_insert() {
        let csp = Csp::of(
            rng(),
            secret_key_store_with_io_error_on_insert(),
            MockPublicKeyStore::new(),
        );

        let result = csp.idkg_gen_dealing_encryption_key_pair();

        assert!(matches!(
            result,
            Err(CspCreateMEGaKeyError::TransientInternalError { internal_error }) if internal_error.to_lowercase().contains("io error")
        ));
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
    let expected_key_id =
        hex_to_32_bytes("bc1f70570a2aaa0904069e1a77b710c729ac1bf026a02f14ad8613c3627b211a");
    assert_eq!(key_id, KeyId::from(expected_key_id));
}

fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

mod tls {
    use super::*;
    use openssl::x509::X509VerifyResult;
    use std::collections::BTreeSet;

    const NODE_1: u64 = 4241;
    const FIXED_SEED: u64 = 42;
    const NOT_AFTER: &str = "25670102030405Z";

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_if_secret_key_insertion_yields_duplicate_error() {
        let duplicated_key_id = KeyId::from([42; 32]);
        let csp = Csp::of(
            rng(),
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id),
            MockPublicKeyStore::new(),
        );

        let _ = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let csp = Csp::with_rng(rng());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let csp = Csp::with_rng(rng());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let x509_cert = cert.as_x509();
        assert_eq!(cn_entries(x509_cert).count(), 1);
        let subject_cn = cn_entries(x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let csp = Csp::with_rng(rng());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let subject_cn = cn_entries(cert.as_x509()).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let csp = Csp::with_rng(rng());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let issuer_cn = cert
            .as_x509()
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let csp = Csp::with_rng(rng());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let subject_alt_names = cert.as_x509().subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp = Csp::with_rng(csprng_seeded_with(FIXED_SEED));

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let cert_serial = cert.as_x509().serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for i in 0..SAMPLE_SIZE {
            let cert = Csp::with_rng(csprng_seeded_with(i as u64))
                .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
                .expect("error generating TLS certificate");
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let csp = Csp::with_rng(rng());
        let not_after = NOT_AFTER;

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), not_after)
            .expect("error generating TLS certificate");

        assert!(cert.as_x509().not_after() == Asn1Time::from_str_x509(not_after).unwrap());
    }

    #[test]
    fn should_panic_on_invalid_not_after_date() {
        let csp = Csp::with_rng(rng());
        let invalid_not_after = "invalid_not_after_date";

        let result = csp.gen_tls_key_pair(node_test_id(NODE_1), invalid_not_after);
        assert!(
            matches!(result, Err(CryptoError::InvalidNotAfterDate { message, not_after })
                if message.eq("invalid X.509 certificate expiration date (not_after)") && not_after.eq(invalid_not_after)
            )
        );
    }

    #[test]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let csp = Csp::with_rng(rng());
        let date_in_the_past = "20211004235959Z";

        let result = csp.gen_tls_key_pair(node_test_id(NODE_1), date_in_the_past);
        assert!(
            matches!(result, Err(CryptoError::InvalidNotAfterDate { message, not_after })
                if message.eq("'not after' date must not be in the past") && not_after.eq(date_in_the_past)
            )
        );
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
        cert.as_x509().serial_number().to_bn().unwrap()
    }

    #[test]
    fn should_fail_with_internal_error_if_tls_public_key_certificate_already_set() {
        let csp = Csp::with_rng(rng());

        assert!(csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .is_ok());

        // the attemtps after the first one should fail
        for _ in 0..5 {
            assert!(matches!(csp
                .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER),
                Err(CryptoError::InternalError { internal_error })
                if internal_error.contains("TLS certificate already set")
            ));
        }
    }
}

fn rng() -> impl CryptoRng + Rng {
    csprng_seeded_with(42)
}
