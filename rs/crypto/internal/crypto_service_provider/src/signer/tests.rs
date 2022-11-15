#![allow(clippy::unwrap_used)]
use super::*;
use crate::api::CspSigner;
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::imported_utilities::sign_utils::user_public_key_from_bytes;
use crate::key_id::KeyId;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::secret_key_store::test_utils::MockSecretKeyStore;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::types::{CspPublicKey, CspSecretKey, CspSignature};
use crate::SecretKeyStore;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::{
    RFC8032_ED25519_1, RFC8032_ED25519_SHA_ABC,
};
use ic_crypto_internal_test_vectors::multi_bls12_381::{
    TESTVEC_MULTI_BLS12_381_1_PK, TESTVEC_MULTI_BLS12_381_1_SIG,
};
use ic_crypto_internal_test_vectors::test_data;
use ic_types::crypto::AlgorithmId::Ed25519;
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const KEY_ID: [u8; 32] = [0u8; 32];

mod sign_common {
    use super::*;

    #[test]
    fn should_fail_with_secret_key_not_found_if_secret_key_not_found_in_key_store() {
        let csp = Csp::of(
            csprng(),
            secret_key_store_returning_none(),
            MockPublicKeyStore::new(),
        );

        let result = csp.sign(Ed25519, b"msg", KeyId::from(KEY_ID));

        assert!(result.unwrap_err().is_secret_key_not_found());
    }

    #[test]
    #[should_panic]
    fn should_panic_when_secret_key_store_panics() {
        let csp = Csp::of(
            csprng(),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );

        let _ = csp.sign(Ed25519, b"msg", KeyId::from(KEY_ID));
    }
}

mod sign_ed25519 {
    use super::*;

    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.
    #[test]
    fn should_correctly_sign() {
        let (sk, _, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

        let csp = Csp::of(
            csprng(),
            secret_key_store_with(KeyId::from(KEY_ID), sk),
            MockPublicKeyStore::new(),
        );

        assert_eq!(csp.sign(Ed25519, &msg, KeyId::from(KEY_ID)).unwrap(), sig);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let sk_with_wrong_type = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes(
            [0u8; multi_types::SecretKeyBytes::SIZE],
        ));
        let csp = Csp::of(
            csprng(),
            secret_key_store_with(KeyId::from(KEY_ID), sk_with_wrong_type),
            MockPublicKeyStore::new(),
        );

        let result = csp.sign(Ed25519, b"msg", KeyId::from(KEY_ID));

        assert!(result.unwrap_err().is_invalid_argument());
    }
}

mod verify_common {
    use super::*;

    #[test]
    fn should_not_use_secret_key_store_during_verification() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

        let csp = Csp::of(
            csprng(),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );

        assert!(csp.verify(&sig, &msg, Ed25519, pk).is_ok());
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
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_correctly_verify_firefox_ecdsa_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::FIREFOX_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_correctly_verify_safari_ecdsa_signature() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::SAFARI_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        assert!(csp.verify(&csp_sig, EMPTY_MSG, EcdsaP256, csp_pk).is_ok());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (csp_pk, wrong_sig) = get_csp_pk_and_sig(
            test_data::SAFARI_ECDSA_P256_PK_DER_HEX.as_ref(),
            test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref(),
        );
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
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

        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
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
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
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
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
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
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        assert!(csp
            .verify(&csp_sig, EMPTY_MSG, EcdsaSecp256k1, csp_pk)
            .is_ok());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (csp_pk, wrong_sig) =
            get_csp_pk_and_sig(PK, test_data::FIREFOX_ECDSA_P256_SIG_RAW_HEX.as_ref());
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        let result = csp.verify(&wrong_sig, EMPTY_MSG, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let (csp_pk, csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let wrong_msg = b"wrong message";
        assert_ne!(EMPTY_MSG, wrong_msg);

        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        let result = csp.verify(&csp_sig, wrong_msg, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signature_has_wrong_type() {
        let (csp_pk, _csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let sig_with_wrong_type =
            CspSignature::multi_bls12381_individual_from_hex(TESTVEC_MULTI_BLS12_381_1_SIG);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
        let result = csp.verify(&sig_with_wrong_type, EMPTY_MSG, EcdsaSecp256k1, csp_pk);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signer_public_key_has_wrong_type() {
        let (_csp_pk, csp_sig) = get_csp_pk_and_sig(PK, SIG);
        let pk_with_wrong_type =
            CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );
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
    use super::*;

    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.
    #[test]
    fn should_correctly_verify() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        assert!(csp.verify(&sig, &msg, Ed25519, pk).is_ok());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let (_, _, _, wrong_sig) = csp_testvec(RFC8032_ED25519_1);
        assert_ne!(sig, wrong_sig);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        let result = csp.verify(&wrong_sig, &msg, Ed25519, pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_message() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let wrong_msg = b"wrong message";
        assert_ne!(msg, wrong_msg);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        let result = csp.verify(&sig, wrong_msg, Ed25519, pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_under_wrong_public_key() {
        let (_, pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let (_, wrong_pk, _, _) = csp_testvec(RFC8032_ED25519_1);
        assert_ne!(pk, wrong_pk);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        let result = csp.verify(&sig, &msg, Ed25519, wrong_pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signature_has_wrong_type() {
        let (_, pk, msg, _) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let sig_with_wrong_type =
            CspSignature::multi_bls12381_individual_from_hex(TESTVEC_MULTI_BLS12_381_1_SIG);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        let result = csp.verify(&sig_with_wrong_type, &msg, Ed25519, pk);

        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_if_signer_public_key_has_wrong_type() {
        let (_, _, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);
        let pk_with_wrong_type =
            CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK);
        let csp = Csp::of(
            csprng(),
            MockSecretKeyStore::new(),
            MockPublicKeyStore::new(),
        );

        let result = csp.verify(&sig, &msg, Ed25519, pk_with_wrong_type);

        assert!(result.unwrap_err().is_signature_verification_error());
    }
}

fn csprng() -> impl CryptoRng + Rng {
    ChaCha20Rng::seed_from_u64(42)
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

fn secret_key_store_panicking_on_usage() -> impl SecretKeyStore {
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert().never();
    sks.expect_get().never();
    sks.expect_contains().never();
    sks.expect_remove().never();
    sks
}

// fn public_key_store() -> impl PublicKeyStore {
//     MockPublicKeyStore::new()
// }

#[test]
#[should_panic]
fn should_panic_when_panicking_secret_key_store_is_used() {
    let sks = secret_key_store_panicking_on_usage();
    let _ = sks.get(&KeyId::from(KEY_ID));
}

mod multi {
    use super::*;
    use crate::api::CspKeyGenerator;

    #[test]
    fn pop_verifies() {
        let csp0 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (public_key0, pop0) = csp0
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        assert!(csp0
            .verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key0)
            .is_ok());
    }

    #[test]
    fn pop_verifies_using_any_csp() {
        // in other words, pop verification doesn't depend on the state of the CSP
        let csp0 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (public_key0, pop0) = csp0
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        let csp1 = Csp::with_rng(ChaCha20Rng::seed_from_u64(53));
        let (public_key1, pop1) = csp1
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
        let csp0 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (public_key0, pop0) = csp0
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        let csp1 = Csp::with_rng(ChaCha20Rng::seed_from_u64(53));
        let (public_key1, pop1) = csp1
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");

        // mismathced public key
        assert!(matches!(
            csp0.verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key1.clone()),
            Err(CryptoError::PopVerification { .. })
        ));
        assert!(matches!(
            csp1.verify_pop(&pop1, AlgorithmId::MultiBls12_381, public_key0.clone()),
            Err(CryptoError::PopVerification { .. })
        ));

        // mismathced PoP
        assert!(matches!(
            csp0.verify_pop(&pop1, AlgorithmId::MultiBls12_381, public_key0),
            Err(CryptoError::PopVerification { .. })
        ));
        assert!(matches!(
            csp1.verify_pop(&pop0, AlgorithmId::MultiBls12_381, public_key1),
            Err(CryptoError::PopVerification { .. })
        ));
    }

    #[test]
    fn pop_verification_fails_gracefully_on_incompatible_public_key() {
        let algorithm = AlgorithmId::MultiBls12_381;
        let csp = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (_public_key, pop) = csp
            .gen_committee_signing_key_pair()
            .expect("PoP creation failed");
        let incompatible_public_key = csp.gen_node_signing_key_pair().unwrap();
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );
        let result = verifier.verify_pop(&pop, algorithm, incompatible_public_key);
        assert!(result.unwrap_err().is_pop_verification_error());
    }
    #[test]
    fn pop_verification_fails_gracefully_on_incompatible_algorithm_id() {
        let incompatible_algorithm = AlgorithmId::Ed25519;
        let csp = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (public_key, pop) = csp
            .gen_committee_signing_key_pair()
            .expect("PoP creation failed");
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );
        let result = verifier.verify_pop(&pop, incompatible_algorithm, public_key);
        assert!(result.unwrap_err().is_pop_verification_error());
    }

    #[test]
    fn individual_signatures_verify() {
        let csp = Csp::with_rng(ChaCha20Rng::seed_from_u64(69));
        let (public_key, _pop) = csp
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let message = b"Three turtle doves";
        let key_id = KeyId::from(&public_key);
        let signature = csp
            .sign(AlgorithmId::MultiBls12_381, message, key_id)
            .expect("Signing failed");
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );
        assert!(verifier
            .verify(&signature, message, AlgorithmId::MultiBls12_381, public_key)
            .is_ok());
    }

    #[test]
    fn signature_verification_fails_gracefully_on_incompatible_signature() {
        let algorithm = AlgorithmId::MultiBls12_381;
        let incompatible_algorithm = AlgorithmId::Ed25519;
        let message = b"Three turtle doves";
        let csp = Csp::with_rng(ChaCha20Rng::seed_from_u64(69));
        let (public_key, _pop) = csp.gen_committee_signing_key_pair().unwrap();
        let incompatible_signature = {
            let incompatible_public_key = csp.gen_node_signing_key_pair().unwrap();
            let incompatible_key_id = KeyId::from(&incompatible_public_key);
            csp.sign(incompatible_algorithm, message, incompatible_key_id)
                .expect("Signing failed")
        };
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(80),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );
        let result = verifier.verify(&incompatible_signature, message, algorithm, public_key);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn individual_signature_verification_fails_for_incompatible_public_key() {
        let algorithm = AlgorithmId::MultiBls12_381;
        let csp = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let (public_key, _pop) = csp.gen_committee_signing_key_pair().unwrap();
        let key_id = KeyId::from(&public_key);
        let incompatible_public_key = csp.gen_node_signing_key_pair().unwrap();
        let message = b"Three turtle doves";
        let signature = csp
            .sign(algorithm, message, key_id)
            .expect("Signing failed");
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );
        let result = verifier.verify(&signature, message, algorithm, incompatible_public_key);
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn combined_signature_verifies() {
        // Actors:
        let csp1 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let csp2 = Csp::with_rng(ChaCha20Rng::seed_from_u64(7_832_645));
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::from(&public_key1);
        let (public_key2, _pop2) = csp2
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id2 = KeyId::from(&public_key2);

        // Two signatures combined should verify:
        let message = b"Three turtle doves";
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, message, key_id1)
            .expect("Signing failed");
        let signature2 = csp2
            .sign(AlgorithmId::MultiBls12_381, message, key_id2)
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
                AlgorithmId::MultiBls12_381
            )
            .is_ok());
    }

    #[test]
    fn combining_signatures_fails_gracefully_for_unsuitable_algorithm_id() {
        // Actors:
        let csp1 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let csp2 = Csp::with_rng(ChaCha20Rng::seed_from_u64(7_832_645));
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::from(&public_key1);
        let (public_key2, _pop2) = csp2
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id2 = KeyId::from(&public_key2);

        // Two signatures combined should verify:
        let message = b"Three turtle doves";
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, message, key_id1)
            .expect("Signing failed");
        let signature2 = csp2
            .sign(AlgorithmId::MultiBls12_381, message, key_id2)
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
        let csp1 = Csp::with_rng(ChaCha20Rng::seed_from_u64(42));
        let verifier = Csp::of(
            ChaCha20Rng::seed_from_u64(69),
            secret_key_store_panicking_on_usage(),
            MockPublicKeyStore::new(),
        );

        // The signatories need keys:
        let (public_key1, _pop1) = csp1
            .gen_committee_signing_key_pair()
            .expect("Failed to generate key pair with PoP");
        let key_id1 = KeyId::from(&public_key1);

        // An incompatible signature:
        let (_, incompatible_public_key2, message, incompatible_signature2) =
            csp_testvec(RFC8032_ED25519_SHA_ABC);

        // A compatible signature:
        let signature1 = csp1
            .sign(AlgorithmId::MultiBls12_381, &message, key_id1)
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
