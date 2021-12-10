#![allow(clippy::unwrap_used)]
use super::*;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_byte_vec};
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::X509NameEntries;
use openssl::{asn1::Asn1Time, bn::BigNum, nid::Nid, x509::X509};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn should_correctly_generate_ed25519_keys() {
    let csprng = csprng_seeded_with(42);
    let csp = Csp::of(csprng, volatile_key_store());

    let (key_id, pk) = csp.gen_key_pair(AlgorithmId::Ed25519).unwrap();

    assert_eq!(
        key_id,
        KeyId::from(hex_to_32_bytes(
            "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
        )),
    );
    assert_eq!(
        pk,
        CspPublicKey::ed25519_from_hex(
            "78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"
        )
    );
}

#[test]
fn should_retrieve_newly_generated_secret_key_from_store() {
    let csprng = csprng_seeded_with(42);
    let csp = Csp::of(csprng, volatile_key_store());
    let (key_id, _) = csp.gen_key_pair(AlgorithmId::Ed25519).unwrap();

    let retrieved_sk = csp.csp_vault.get_secret_key(&key_id);

    assert_eq!(
        retrieved_sk,
        Some(CspSecretKey::ed25519_from_hex(
            "7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a"
        ))
    );
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

    let key_id = tls_cert_hash_as_key_id(&cert);

    // We expect the following hard coded key id:
    let expected_key_id =
        hex_to_32_bytes("bc1f70570a2aaa0904069e1a77b710c729ac1bf026a02f14ad8613c3627b211a");
    assert_eq!(key_id, KeyId(expected_key_id));
}

fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng + Clone {
    ChaCha20Rng::seed_from_u64(seed)
}

fn volatile_key_store() -> VolatileSecretKeyStore {
    VolatileSecretKeyStore::new()
}

mod multi {
    use super::*;
    use ic_crypto_internal_multi_sig_bls12381::types::{PopBytes, PublicKeyBytes};
    use ic_crypto_internal_test_vectors::unhex::{hex_to_48_bytes, hex_to_96_bytes};

    struct TestVector {
        seed: u64,
        key_id: KeyId,
        public_key: CspPublicKey,
        proof_of_possession: CspPop,
    }

    fn test_vector_42() -> TestVector {
        TestVector {
            seed: 42,
            key_id: KeyId::from(hex_to_32_bytes(
                "f8782b0bc403eb23770b72bebe9f3efbedb98f7a2fdf2c2b7b312e894bd39a44",
            )),
            public_key: CspPublicKey::MultiBls12_381(PublicKeyBytes(hex_to_96_bytes(
                "986b177ef16c61c633e13769c42b079791cfa9702decd36eeb347be21bd98e8d1c4\
                 d9f2a1f16f2e09b995ae7ff856a830d382d0081c6ae253a7d2abf97de945f70a42e\
                 677ca30b129bcd08c91f78f8573fe2463a86afacf870e9fe4960f5c55f",
            ))),
            proof_of_possession: CspPop::MultiBls12_381(PopBytes(hex_to_48_bytes(
                "8e1e3a79a9f0bf69b9e256041eedef82db44e7755d9920a17dd07ea9f039a0f0f79013c135678aa355e9695f36886b54",
            ))),
        }
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let (key_id, public_key) = csp.gen_key_pair(AlgorithmId::MultiBls12_381).unwrap();

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_with_pop_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let (key_id, public_key, pop) = csp
            .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
            .expect("Failed to generate key pair with PoP");

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
        assert_eq!(pop, test_vector.proof_of_possession);
    }
}

mod tls {
    use super::*;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::vault::api::CspVault;
    use openssl::pkey::{Id, PKey};
    use openssl::x509::X509VerifyResult;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const NODE_1: u64 = 4241;
    const FIXED_SEED: u64 = 42;
    const NOT_AFTER: &str = "25670102030405Z";

    #[test]
    fn should_insert_secret_key_into_store_in_der_format() {
        let sks = volatile_key_store();
        let mut csp = Csp::of(rng(), sks);

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let secret_key = secret_key_from_store(Arc::clone(&csp.csp_vault), cert.as_x509().clone());
        if let CspSecretKey::TlsEd25519(sk_der_bytes) = secret_key {
            let private_key = PKey::private_key_from_der(&sk_der_bytes.bytes)
                .expect("unable to parse DER secret key");
            assert_eq!(private_key.id(), Id::ED25519);
        } else {
            panic!("secret key has the wrong type");
        }
    }

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_if_secret_key_insertion_yields_duplicate_error() {
        let mut sks_returning_error_on_insert = MockSecretKeyStore::new();
        sks_returning_error_on_insert
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::DuplicateKeyId(KeyId::from(
                [42; 32],
            ))));

        let mut csp = Csp::of(rng(), sks_returning_error_on_insert);

        let _ = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = cert.as_x509();
        assert_eq!(cn_entries(x509_cert).count(), 1);
        let subject_cn = cn_entries(x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_cn = cn_entries(cert.as_x509()).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

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
        let mut csp = Csp::of(rng(), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let subject_alt_names = cert.as_x509().subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let mut csp = Csp::of(csprng_seeded_with(FIXED_SEED), volatile_key_store());

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let cert_serial = cert.as_x509().serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for _i in 0..SAMPLE_SIZE {
            let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let mut csp = Csp::of(rng(), volatile_key_store());
        let not_after = NOT_AFTER;

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), not_after);

        assert!(cert.as_x509().not_after() == Asn1Time::from_str_x509(not_after).unwrap());
    }

    #[test]
    #[should_panic(expected = "invalid X.509 certificate expiration date (not_after)")]
    fn should_panic_on_invalid_not_after_date() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let _panic = csp.gen_tls_key_pair(node_test_id(NODE_1), "invalid_not_after_date");
    }

    #[test]
    #[should_panic(expected = "'not after' date must not be in the past")]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let mut csp = Csp::of(rng(), volatile_key_store());
        let date_in_the_past = "20211004235959Z";

        let _panic = csp.gen_tls_key_pair(node_test_id(NODE_1), date_in_the_past);
    }

    fn rng() -> impl CryptoRng + Rng + Clone {
        csprng_seeded_with(42)
    }

    fn secret_key_from_store(csp_vault: Arc<dyn CspVault>, x509_cert: X509) -> CspSecretKey {
        let cert = TlsPublicKeyCert::new_from_x509(x509_cert)
            .expect("failed to convert X509 into TlsPublicKeyCert");
        let key_id = tls_keygen::tls_cert_hash_as_key_id(&cert);
        csp_vault
            .get_secret_key(&key_id)
            .expect("secret key not found")
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
        cert.as_x509().serial_number().to_bn().unwrap()
    }
}
