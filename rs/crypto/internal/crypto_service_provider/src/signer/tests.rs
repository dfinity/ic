#![allow(clippy::unwrap_used)]

use super::*;
use crate::api::CspSigner;
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::key_id::KeyId;
use crate::public_key_store::temp_pubkey_store::TempPublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::local_csp_vault::builder::LocalCspVaultBuilder;
use crate::{LocalCspVault, SecretKeyStore};
use assert_matches::assert_matches;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
use ic_crypto_internal_test_vectors::multi_bls12_381::{
    TESTVEC_MULTI_BLS12_381_1_PK, TESTVEC_MULTI_BLS12_381_1_SIG,
};
use ic_crypto_internal_test_vectors::test_data;
use ic_crypto_secrets_containers::SecretArray;
use ic_crypto_standalone_sig_verifier::user_public_key_from_bytes;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use rand::Rng;
use std::collections::HashSet;
use strum::IntoEnumIterator;

const KEY_ID: [u8; 32] = [0u8; 32];

mod sign_common {
    use super::*;

    #[test]
    fn should_fail_with_secret_key_not_found_if_secret_key_not_found_in_key_store() {
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_returning_none())
                    .build(),
            )
            .build();

        let result = csp.sign(AlgorithmId::Ed25519, b"msg".to_vec(), KeyId::from(KEY_ID));

        assert!(result.unwrap_err().is_secret_key_not_found());
    }

    #[test]
    #[should_panic]
    fn should_panic_when_secret_key_store_panics() {
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_panicking_on_usage())
                    .build(),
            )
            .build();

        let _ = csp.sign(AlgorithmId::Ed25519, b"msg".to_vec(), KeyId::from(KEY_ID));
    }
}

mod sign_ed25519 {
    use super::*;

    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.
    #[test]
    fn should_correctly_sign() {
        let (sk, _, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_with(KeyId::from(KEY_ID), sk))
                    .build(),
            )
            .build();

        assert_eq!(
            csp.sign(AlgorithmId::Ed25519, msg, KeyId::from(KEY_ID))
                .unwrap(),
            sig
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let sk_with_wrong_type = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes::new(
            SecretArray::new_and_dont_zeroize_argument(&[0u8; multi_types::SecretKeyBytes::SIZE]),
        ));
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_with(
                        KeyId::from(KEY_ID),
                        sk_with_wrong_type,
                    ))
                    .build(),
            )
            .build();

        let result = csp.sign(AlgorithmId::Ed25519, b"msg".to_vec(), KeyId::from(KEY_ID));

        assert!(result.unwrap_err().is_invalid_argument());
    }
}

mod verify_common {
    use super::*;

    #[test]
    fn should_not_use_secret_key_store_during_verification() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let csp = Csp::builder_for_test()
            .with_vault(
                LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_node_secret_key_store(secret_key_store_panicking_on_usage())
                    .build(),
            )
            .build();

        assert!(csp.verify(&sig, &msg, AlgorithmId::Ed25519, pk).is_ok());
    }
}

mod verify_ecdsa_p256 {
    use super::*;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types::SignatureBytes;
    use ic_types::crypto::AlgorithmId::EcdsaP256;
    use std::convert::TryFrom;

    const EMPTY_MSG: &[u8] = &[0; 0];

    #[test]
    fn should_correctly_verify_chrome_ecdsa_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::CHROME_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::CHROME_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();

        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_correctly_verify_firefox_ecdsa_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::FIREFOX_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();

        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_correctly_verify_safari_ecdsa_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::SAFARI_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();

        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (csp_pk, wrong_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&wrong_sig, EMPTY_MSG, EcdsaP256, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::SAFARI_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let wrong_msg = b"wrong message";
        assert_ne!(EMPTY_MSG, wrong_msg);

        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&csp_sig, wrong_msg, EcdsaP256, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signature_has_wrong_type() {
        let (csp_pk, _csp_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::SAFARI_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let sig_with_wrong_type =
            CspSignature::multi_bls12381_individual_from_hex(TESTVEC_MULTI_BLS12_381_1_SIG);
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&sig_with_wrong_type, EMPTY_MSG, EcdsaP256, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signer_public_key_has_wrong_type() {
        let (_csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::SAFARI_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let pk_with_wrong_type =
            CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, pk_with_wrong_type);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    fn get_csp_pk_and_sig(pk_hex: &[u8], sig_hex: &[u8]) -> (CspPublicKey, CspSignature) {
        let der_pk = hex::decode(pk_hex).unwrap();
        let (user_pk, _) = user_public_key_from_bytes(&der_pk).unwrap();
        let csp_pk = CspPublicKey::try_from(&user_pk).unwrap();
        let sig_bytes = SignatureBytes::try_from(hex::decode(sig_hex).unwrap()).unwrap();
        let csp_sig = CspSignature::EcdsaP256(sig_bytes);
        (csp_pk, csp_sig)
    }
}

mod verify_secp256k1 {
    use super::*;
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types::SignatureBytes;
    use ic_types::crypto::AlgorithmId::EcdsaSecp256k1;
    use std::convert::TryFrom;

    const EMPTY_MSG: &[u8] = &[0; 0];
    const PK: &[u8] = test_data::ECDSA_SECP256K1_PK_DER_HEX.as_bytes();
    const SIG: &[u8] = test_data::ECDSA_SECP256K1_SIG_RAW_HEX.as_bytes();

    #[test]
    fn should_correctly_verify_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        assert!(csp
            .verify(&csp_sig, EMPTY_MSG, EcdsaSecp256k1, csp_pk)
            .is_ok());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (csp_pk, wrong_sig) =
            get_csp_pk_and_sig(PK, test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref());
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&wrong_sig, EMPTY_MSG, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let wrong_msg = b"wrong message";
        assert_ne!(EMPTY_MSG, wrong_msg);

        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&csp_sig, wrong_msg, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signature_has_wrong_type() {
        let (csp_pk, _csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let sig_with_wrong_type =
            CspSignature::multi_bls12381_individual_from_hex(TESTVEC_MULTI_BLS12_381_1_SIG);
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&sig_with_wrong_type, EMPTY_MSG, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signer_public_key_has_wrong_type() {
        let (_csp_pk, csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let pk_with_wrong_type =
            CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);
        let csp = Csp::builder_for_test()
            .with_vault(LocalCspVault::builder_for_test().with_mock_stores().build())
            .build();
        let result = csp.verify(&csp_sig, EMPTY_MSG, EcdsaSecp256k1, pk_with_wrong_type);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    fn get_csp_pk_and_sig(pk_hex: &[u8], sig_hex: &[u8]) -> (CspPublicKey, CspSignature) {
        let der_pk = hex::decode(pk_hex).unwrap();
        let (user_pk, _) = user_public_key_from_bytes(&der_pk).unwrap();
        let csp_pk = CspPublicKey::try_from(&user_pk).unwrap();
        let sig_bytes = SignatureBytes::try_from(hex::decode(sig_hex).unwrap()).unwrap();
        let csp_sig = CspSignature::EcdsaSecp256k1(sig_bytes);
        (csp_pk, csp_sig)
    }
}

mod verify_ed25519 {
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    use super::*;
    use rand::{CryptoRng, Rng};

    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.
    #[test]
    fn should_correctly_verify() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk, sig } = Fixture::new(&msg[..], rng);

        assert_eq!(csp.verify(&sig, &msg, AlgorithmId::Ed25519, pk), Ok(()));
    }

    #[test]
    fn should_correctly_verify_with_other_csp() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp: _, pk, sig } = Fixture::new(&msg[..], rng);

        assert_eq!(
            utils::new_csp(rng).verify(&sig, &msg, AlgorithmId::Ed25519, pk),
            Ok(())
        );
    }

    #[test]
    fn should_fail_to_verify_under_signature_with_wrong_public_key() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk, sig } = Fixture::new(&msg[..], rng);
        let Fixture { sig: wrong_sig, .. } = Fixture::new(&msg[..], rng);
        assert_ne!(sig, wrong_sig);

        assert_matches!(
            csp.verify(&wrong_sig, &msg, AlgorithmId::Ed25519, pk),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk, sig } = Fixture::new(&msg[..], rng);
        let wrong_msg = b"wrong message";
        assert_ne!(msg, wrong_msg);

        assert_matches!(
            csp.verify(&sig, wrong_msg, AlgorithmId::Ed25519, pk),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_fail_to_verify_under_wrong_public_key() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk, sig } = Fixture::new(&msg[..], rng);
        let Fixture { pk: wrong_pk, .. } = Fixture::new(&msg[..], rng);
        assert_ne!(pk, wrong_pk);

        assert_matches!(
            csp.verify(&sig, &msg, AlgorithmId::Ed25519, wrong_pk),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_fail_to_verify_if_signature_has_wrong_type() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk, sig: _ } = Fixture::new(&msg[..], rng);
        let sig_with_wrong_type =
            CspSignature::multi_bls12381_individual_from_hex(TESTVEC_MULTI_BLS12_381_1_SIG);

        assert_matches!(
            csp.verify(&sig_with_wrong_type, &msg, AlgorithmId::Ed25519, pk),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_fail_to_verify_if_signer_public_key_has_wrong_type() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);
        let Fixture { csp, pk: _, sig } = Fixture::new(&msg[..], rng);
        let pk_with_wrong_type =
            CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);

        assert_matches!(
            csp.verify(&sig, &msg, AlgorithmId::Ed25519, pk_with_wrong_type),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_fail_to_verify_under_wrong_algorithm_id() {
        let rng = &mut reproducible_rng();
        let msg = utils::random_message(rng);

        let Fixture { csp, pk, sig } = Fixture::new(&msg[..], rng);

        for wrong_algorithm_id in AlgorithmId::iter().filter(|id| *id != AlgorithmId::Ed25519) {
            assert_matches!(
                csp.verify(&sig, &msg[..], wrong_algorithm_id, pk.to_owned()),
                Err(CryptoError::SignatureVerification { .. })
            );
        }
    }

    mod utils {
        use super::*;

        const RANDOM_MSG_MAX_LEN: usize = 100;

        pub fn new_csp<R: Rng + CryptoRng>(rng: &mut R) -> Csp {
            Csp::builder_for_test()
                .with_vault(
                    LocalCspVault::builder_for_test()
                        .with_rng(Seed::from_rng(rng).into_rng())
                        .build(),
                )
                .build()
        }

        pub fn random_message<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
            let mut msg = vec![0u8; rng.gen_range(0..RANDOM_MSG_MAX_LEN)];
            rng.fill_bytes(&mut msg[..]);
            msg
        }
    }

    pub struct Fixture {
        pub csp: Csp,
        pub pk: CspPublicKey,
        pub sig: CspSignature,
    }

    impl Fixture {
        /// * Generates a [`Csp`] seeded with `rng`.
        /// * Generates a random Ed25519 key pair by copying the `csp`'s node signing key pair.
        /// * Signs `msg` using the private key.
        pub fn new<R: Rng + CryptoRng>(msg: &[u8], rng: &mut R) -> Self {
            let csp = utils::new_csp(rng);
            let pk = csp
                .csp_vault
                .gen_node_signing_key_pair()
                .expect("Failed to generate a key pair");

            let sig = csp
                .csp_vault
                .as_ref()
                .sign(
                    AlgorithmId::Ed25519,
                    msg.to_vec(),
                    KeyId::try_from(&pk).expect("Failed to convert CspPublicKey to KeyId"),
                )
                .expect("Failed to generate a signature");

            Self { csp, pk, sig }
        }
    }
}

fn secret_key_store_returning_none() -> impl SecretKeyStore {
    let mut sks = MockSecretKeyStore::new();
    sks.expect_get().returning(|_| None);
    sks
}

fn secret_key_store_with(key_id: KeyId, secret_key: CspSecretKey) -> impl SecretKeyStore {
    let mut temp_store = TempSecretKeyStore::new();
    let scope = None;
    temp_store.insert(key_id, secret_key, scope).unwrap();
    temp_store
}

fn secret_key_store_panicking_on_usage() -> MockSecretKeyStore {
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert().never();
    sks.expect_get().never();
    sks.expect_contains().never();
    sks.expect_remove().never();
    sks
}

#[test]
#[should_panic]
fn should_panic_when_panicking_secret_key_store_is_used() {
    let sks = secret_key_store_panicking_on_usage();
    let _ = sks.get(&KeyId::from(KEY_ID));
}

mod multi {
    use super::*;

    #[test]
    fn pop_verifies() {
        let csp0 = Csp::builder_for_test().build();
        let (public_key0, pop0) = csp0
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        assert!(csp0
            .verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key0)
            .is_ok());
    }

    #[test]
    fn pop_verifies_using_any_csp() {
        // in other words, pop verification doesn't depend on the state of the CSP
        let [csp0, csp1] = csp_with_different_seeds();
        let (public_key0, pop0) = csp0
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        let (public_key1, pop1) = csp1
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        assert!(csp0
            .verify_pop(&pop1, AlgorithmId::MultiBls12_381, public_key1)
            .is_ok());
        assert!(csp1
            .verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key0)
            .is_ok());
    }

    #[test]
    fn pop_verification_fails_for_mismatched_public_key_or_pop() {
        let [csp0, csp1] = csp_with_different_seeds();
        let (public_key0, pop0) = csp0
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        let (public_key1, pop1) = csp1
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        // mismatched public key
        assert_matches!(
            csp0.verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key1.clone()),
            Err(CryptoError::PopVerification { .. })
        );
        assert_matches!(
            csp1.verify_pop(&pop1, AlgorithmId::MultiBls12_381, public_key0.clone()),
            Err(CryptoError::PopVerification { .. })
        );

        // mismathced PoP
        assert_matches!(
            csp0.verify_pop(&pop1, AlgorithmId::MultiBls12_381, public_key0),
            Err(CryptoError::PopVerification { .. })
        );
        assert_matches!(
            csp1.verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key1),
            Err(CryptoError::PopVerification { .. })
        );
    }

    #[test]
    fn pop_verification_fails_gracefully_on_incompatible_public_key() {
        let [csp, verifier] = csp_and_verifier_with_different_seeds();
        let algorithm = AlgorithmId::MultiBls12_381;
        let (_public_key, pop) = csp
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("PoP creation failed");
        let incompatible_public_key = csp.csp_vault.gen_node_signing_key_pair().unwrap();

        let result = verifier.verify_pop(&pop, algorithm, incompatible_public_key);
        assert!(result.unwrap_err().is_pop_verification_error());
    }

    #[test]
    fn pop_verification_fails_gracefully_on_incompatible_algorithm_id() {
        let [csp, verifier] = csp_and_verifier_with_different_seeds();
        let incompatible_algorithm = AlgorithmId::Ed25519;
        let (public_key, pop) = csp
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("PoP creation failed");
        let result = verifier.verify_pop(&pop, incompatible_algorithm, public_key);
        assert!(result.unwrap_err().is_pop_verification_error());
    }

    #[test]
    fn individual_signatures_verify() {
        let [csp, verifier] = csp_and_verifier_with_different_seeds();
        let (public_key, _pop) = csp
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let message = b"Three turtle doves";
        let key_id = KeyId::try_from(&public_key).unwrap();
        let signature = csp
            .sign(AlgorithmId::MultiBls12_381, message.to_vec(), key_id)
            .expect("Signing failed");
        assert!(verifier
            .verify(&signature, message, AlgorithmId::MultiBls12_381, public_key)
            .is_ok());
    }

    #[test]
    fn signature_verification_fails_gracefully_on_incompatible_signature() {
        let algorithm = AlgorithmId::MultiBls12_381;
        let incompatible_algorithm = AlgorithmId::Ed25519;
        let message = b"Three turtle doves";
        let [csp, verifier] = csp_and_verifier_with_different_seeds();
        let (public_key, _pop) = csp.csp_vault.gen_committee_signing_key_pair().unwrap();
        let incompatible_signature = {
            let incompatible_public_key = csp.csp_vault.gen_node_signing_key_pair().unwrap();
            let incompatible_key_id = KeyId::try_from(&incompatible_public_key).unwrap();
            csp.sign(
                incompatible_algorithm,
                message.to_vec(),
                incompatible_key_id,
            )
            .expect("Signing failed")
        };

        let result = verifier.verify(&incompatible_signature, message, algorithm, public_key);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn individual_signature_verification_fails_for_incompatible_public_key() {
        let algorithm = AlgorithmId::MultiBls12_381;
        let [csp, verifier] = csp_and_verifier_with_different_seeds();
        let (public_key, _pop) = csp.csp_vault.gen_committee_signing_key_pair().unwrap();
        let key_id = KeyId::try_from(&public_key).unwrap();
        let incompatible_public_key = csp.csp_vault.gen_node_signing_key_pair().unwrap();
        let message = b"Three turtle doves";
        let signature = csp
            .sign(algorithm, message.to_vec(), key_id)
            .expect("Signing failed");

        let result = verifier.verify(&signature, message, algorithm, incompatible_public_key);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn combined_signature_verifies() {
        // Actors:
        let [csp1, csp2, verifier] = csp_and_verifier_with_different_seeds();

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::try_from(&public_key1).unwrap();
        let (public_key2, _pop2) = csp2
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id2 = KeyId::try_from(&public_key2).unwrap();

        // Two signatures combined should verify:
        let message = b"Three turtle doves";
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, message.to_vec(), key_id1)
            .expect("Signing failed");
        let signature2 = csp2
            .sign(AlgorithmId::MultiBls12_381, message.to_vec(), key_id2)
            .expect("Signing failed");
        let combined_signature = verifier
            .combine_sigs(
                vec![
                    (public_key1.clone(), signature1),
                    (public_key2.clone(), signature2),
                ],
                AlgorithmId::MultiBls12_381,
            )
            .expect("Failed to combine signatures");

        assert!(verifier
            .verify_multisig(
                vec![public_key1, public_key2],
                combined_signature,
                message,
                AlgorithmId::MultiBls12_381,
            )
            .is_ok());
    }

    #[test]
    fn combining_signatures_fails_gracefully_for_unsuitable_algorithm_id() {
        // Actors:
        let [csp1, csp2, verifier] = csp_and_verifier_with_different_seeds();

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::try_from(&public_key1).unwrap();
        let (public_key2, _pop2) = csp2
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id2 = KeyId::try_from(&public_key2).unwrap();

        // Two signatures combined should verify:
        let message = b"Three turtle doves";
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, message.to_vec(), key_id1)
            .expect("Signing failed");
        let signature2 = csp2
            .sign(AlgorithmId::MultiBls12_381, message.to_vec(), key_id2)
            .expect("Signing failed");
        let combined_signature = verifier
            .combine_sigs(
                vec![
                    (public_key1.clone(), signature1),
                    (public_key2.clone(), signature2),
                ],
                AlgorithmId::MultiBls12_381,
            )
            .expect("Failed to combine signatures");

        let result = verifier.verify_multisig(
            vec![public_key1, public_key2],
            combined_signature,
            message,
            AlgorithmId::Ed25519,
        );
        assert!(result.unwrap_err().is_algorithm_not_supported());
    }

    #[test]
    fn combining_signatures_fails_gracefully_for_mixed_algorithm_ids() {
        // Actors:
        let [csp1, verifier] = csp_and_verifier_with_different_seeds();

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::try_from(&public_key1).unwrap();

        // An incompatible signature:
        let (_, incompatible_public_key2, message, incompatible_signature2) =
            csp_testvec(RFC8032_ED25519_SHA_ABC);

        // A compatible signature:
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, message, key_id1)
            .expect("Signing failed");

        // Combining should fail:
        let combination = verifier.combine_sigs(
            vec![
                (public_key1, signature1),
                (incompatible_public_key2, incompatible_signature2),
            ],
            AlgorithmId::MultiBls12_381,
        );
        assert!(combination.unwrap_err().is_algorithm_not_supported());
    }
}

fn vault_builder_with_different_seeds<const N: usize>() -> [LocalCspVaultBuilder<
    rand_chacha::ChaCha20Rng,
    TempSecretKeyStore,
    TempSecretKeyStore,
    TempPublicKeyStore,
>; N] {
    assert!(N > 0);
    let rng = &mut ReproducibleRng::new();
    let mut vault_builders = Vec::with_capacity(N);
    let mut seeds = HashSet::with_capacity(N);
    for _ in 0..N {
        let seed: [u8; 32] = rng.gen();
        vault_builders
            .push(LocalCspVault::builder_for_test().with_rng(Seed::from_bytes(&seed).into_rng()));
        assert!(seeds.insert(seed));
    }
    vault_builders
        .try_into()
        .map_err(|_err| "cannot convert to fixed size array".to_string())
        .unwrap()
}

/// Instantiate an array of `N` Csps where the last element
/// plays the role of the verifier. This is a Csp instantiated using a vault with mocked
/// stores
fn csp_and_verifier_with_different_seeds<const N: usize>() -> [Csp; N] {
    let vaults: [LocalCspVaultBuilder<_, _, _, _>; N] = vault_builder_with_different_seeds();
    let mut csps = Vec::with_capacity(N);
    for (i, vault_builder) in vaults.into_iter().enumerate() {
        let csp = if i == N - 1 {
            Csp::builder_for_test()
                .with_vault(
                    vault_builder
                        .with_mock_stores()
                        .with_node_secret_key_store(secret_key_store_panicking_on_usage())
                        .build(),
                )
                .build()
        } else {
            Csp::builder_for_test()
                .with_vault(vault_builder.build())
                .build()
        };
        csps.push(csp);
    }
    csps.try_into()
        .map_err(|_err| "cannot convert to fixed size array".to_string())
        .unwrap()
}

fn csp_with_different_seeds<const N: usize>() -> [Csp; N] {
    let vaults: [LocalCspVaultBuilder<_, _, _, _>; N] = vault_builder_with_different_seeds();
    vaults
        .into_iter()
        .map(|vault| Csp::builder_for_test().with_vault(vault.build()).build())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_err| "cannot convert to fixed size array".to_string())
        .unwrap()
}
