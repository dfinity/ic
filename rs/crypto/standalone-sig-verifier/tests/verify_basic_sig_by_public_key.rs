use assert_matches::assert_matches;
use ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use strum::IntoEnumIterator;

const SUPPORTED_ALGORITHM_IDS: [AlgorithmId; 4] = [
    AlgorithmId::Ed25519,
    AlgorithmId::EcdsaP256,
    AlgorithmId::EcdsaSecp256k1,
    AlgorithmId::RsaSha256,
];

#[test]
fn should_error_when_algorithm_unsupported() {
    for wrong_algorithm_id in AlgorithmId::iter().filter(|id| !SUPPORTED_ALGORITHM_IDS.contains(id))
    {
        let result = verify_basic_sig_by_public_key(wrong_algorithm_id, &[], &[], &[]);

        assert_matches!(result, Err(CryptoError::AlgorithmNotSupported { algorithm, .. }) if algorithm == wrong_algorithm_id);
    }
}

mod ed25519 {
    use crate::assert_wrong_algorithm_used;
    use assert_matches::assert_matches;
    use ic_crypto_internal_test_vectors::ed25519::{Ed25519TestVector, crypto_lib_testvec};
    use ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key;
    use ic_types::crypto::{AlgorithmId, CryptoError};
    use strum::IntoEnumIterator;

    #[test]
    fn should_accept_valid_signature_smoke_test() {
        let (_sk, pk, msg, sig) = crypto_lib_testvec(Ed25519TestVector::RFC8032_ED25519_1);
        let result = verify_basic_sig_by_public_key(AlgorithmId::Ed25519, &msg, &sig, &pk);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_reject_invalid_signature_smoke_test() {
        let (_sk, pk, msg, mut sig) = crypto_lib_testvec(Ed25519TestVector::RFC8032_ED25519_1);
        sig[0] ^= 0x01;
        let result = verify_basic_sig_by_public_key(AlgorithmId::Ed25519, &msg, &sig, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_error_on_every_other_algorithm_ids() {
        for wrong_algorithm_id in AlgorithmId::iter().filter(|id| *id != AlgorithmId::Ed25519) {
            let (_sk, pk, msg, sig) = crypto_lib_testvec(Ed25519TestVector::RFC8032_ED25519_1);
            let result = verify_basic_sig_by_public_key(wrong_algorithm_id, &msg, &sig, &pk);
            assert_wrong_algorithm_used(result, wrong_algorithm_id);
        }
    }
}

mod ecdsa_secp_256r1 {
    use crate::assert_wrong_algorithm_used;
    use assert_matches::assert_matches;
    use ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key;
    use ic_types::crypto::{AlgorithmId, CryptoError};
    use strum::IntoEnumIterator;

    #[test]
    fn should_accept_valid_signature_smoke_test() {
        let (msg, sig, pk) = test_vector();
        let result = verify_basic_sig_by_public_key(AlgorithmId::EcdsaP256, &msg, &sig, &pk);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_reject_invalid_signature_smoke_test() {
        let (msg, mut sig, pk) = test_vector();
        sig.as_mut_slice()[0] ^= 0x01;
        let result = verify_basic_sig_by_public_key(AlgorithmId::EcdsaP256, &msg, &sig, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_error_on_every_other_algorithm_ids() {
        for wrong_algorithm_id in AlgorithmId::iter().filter(|id| *id != AlgorithmId::EcdsaP256) {
            let (msg, sig, pk) = test_vector();
            let result = verify_basic_sig_by_public_key(wrong_algorithm_id, &msg, &sig, &pk);
            assert_wrong_algorithm_used(result, wrong_algorithm_id);
        }
    }

    fn test_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let msg = hex::decode("e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3").expect("valid hex string");
        let sig = hex::decode("bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c").expect("valid hex string");
        let pk = hex::decode("04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927").expect("valid hex string");
        (msg, sig, pk)
    }
}

mod ecdsa_secp_256k1 {
    use crate::assert_wrong_algorithm_used;
    use assert_matches::assert_matches;
    use ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key;
    use ic_types::crypto::{AlgorithmId, CryptoError};
    use strum::IntoEnumIterator;

    #[test]
    fn should_accept_valid_signature_smoke_test() {
        let (msg, sig, pk) = test_vector();
        let result = verify_basic_sig_by_public_key(AlgorithmId::EcdsaSecp256k1, &msg, &sig, &pk);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_reject_invalid_signature_smoke_test() {
        let (msg, mut sig, pk) = test_vector();
        sig.as_mut_slice()[0] ^= 0x01;
        let result = verify_basic_sig_by_public_key(AlgorithmId::EcdsaSecp256k1, &msg, &sig, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_error_on_every_other_algorithm_ids() {
        for wrong_algorithm_id in
            AlgorithmId::iter().filter(|id| *id != AlgorithmId::EcdsaSecp256k1)
        {
            let (msg, sig, pk) = test_vector();
            let result = verify_basic_sig_by_public_key(wrong_algorithm_id, &msg, &sig, &pk);
            assert_wrong_algorithm_used(result, wrong_algorithm_id);
        }
    }

    fn test_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let msg = hex::decode("4d61617274656e20426f64657765732067656e6572617465642074686973207465737420766563746f72206f6e20323031362d31312d3038").expect("valid hex string");
        let sig = hex::decode("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e").expect("valid hex string");
        let pk = hex::decode("04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f").expect("valid hex string");
        (msg, sig, pk)
    }
}

mod rsa_sha_256 {
    use crate::assert_wrong_algorithm_used;
    use assert_matches::assert_matches;
    use ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key;
    use ic_types::crypto::{AlgorithmId, CryptoError};
    use strum::IntoEnumIterator;

    #[test]
    fn should_accept_valid_signature_smoke_test() {
        let (msg, sig, pk) = test_vector();
        let result = verify_basic_sig_by_public_key(AlgorithmId::RsaSha256, &msg, &sig, &pk);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_reject_invalid_signature_smoke_test() {
        let (msg, mut sig, pk) = test_vector();
        sig.as_mut_slice()[0] ^= 0x01;
        let result = verify_basic_sig_by_public_key(AlgorithmId::RsaSha256, &msg, &sig, &pk);
        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_error_on_every_other_algorithm_ids() {
        for wrong_algorithm_id in AlgorithmId::iter().filter(|id| *id != AlgorithmId::RsaSha256) {
            let (msg, sig, pk) = test_vector();
            let result = verify_basic_sig_by_public_key(wrong_algorithm_id, &msg, &sig, &pk);
            assert_wrong_algorithm_used(result, wrong_algorithm_id);
        }
    }

    fn test_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let msg = hex::decode("616263").expect("valid hex string");
        let sig = hex::decode("7416E0A20E46CEF9FC09FA87D4C324502839EB8DEAFEF7CA5ADEC1044523232E66B32F4A497AA84FC4069182AD4A921B43DBCBD3ACCA870F887299692E23555086169F89EA1DD4856DC9FEB4E96B1661F803B784B4BE9A0E36B739A38126996912D92343688DB58F24CF8066250E2B04EE166A1C9C924D1AA9DED87D8A24E07CF35B02CA487B1632BA2508FF2B28F880983926A75D67EB83292BF77EE9B283337D841F04253C846BD66E63E50D8B326DCE1EC67A95A9D31DBDF3DCA5E8C09CA8CCE2026A3A5AE56250EC57CDE67A745FA1B1CC83473BA167AD1F8311A3D071184D03380B80C7921457CE282B9222FE805E506B53C5F798917B1A45044D2E896D").expect("valid hex string");
        let pk = hex::decode("30820122300D06092A864886F70D01010105000382010F003082010A0282010100A7078A1A8FDE64C537AE5CA8D4B3A9139D68050CF76E45E77DBE47CECEB162F7095ADB6260998775203AA42A444F865DEB995C2B70B548ECEE01695DEB069ED18744C12FD24AEACDA4B2B7A5E97E7167CAF7D4B8904CE20CA9A8928978CA957FF2D9FCAE0859618B0AD74C164FAF5AB1DE7D7228A89BD3F8B497CEF9E45E1203CC40EE252140157C331A584F3916E569A8C39573D542A3577FB12332EBD3C9F421C9EF8A23D5ACF6BA439F7C3D6B73BA4E56B9B8EFBC42A2E5E734B99FDF7AB046813E43C65C926793919A7AE54F71AAF57C6876001A0558BC847D7555B1AE71F56A70272D786BE69A23A21A56C426371BD9882D40E7ECA6B7DA5D8169B7030F0203010001").expect("valid hex string");
        (msg, sig, pk)
    }
}

fn assert_wrong_algorithm_used(result: CryptoResult<()>, wrong_algorithm_id: AlgorithmId) {
    assert_matches!(
        result,
        Err(CryptoError::AlgorithmNotSupported { algorithm, .. }) |
        Err(CryptoError::SignatureVerification { algorithm, .. }) |
        Err(CryptoError::MalformedPublicKey { algorithm, .. }) |
        Err(CryptoError::MalformedSignature { algorithm, .. })
        if algorithm == wrong_algorithm_id
    );
}
