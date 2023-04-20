use ic_crypto_internal_csp::key_id::KeyId;
use ic_types::crypto::AlgorithmId;
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::prelude::BoxedStrategy;
use proptest::strategy::Strategy;
use proptest::{prop_compose, prop_oneof};

#[cfg(test)]
mod tests;

pub use common::arb_algorithm_id;
pub use common::arb_key_id;
pub use csp_basic_signature_error::arb_csp_basic_signature_error;
pub use csp_basic_signature_keygen_error::arb_csp_basic_signature_keygen_error;
pub use csp_multi_signature_error::arb_csp_multi_signature_error;
pub use csp_multi_signature_keygen_error::arb_csp_multi_signature_keygen_error;
pub use csp_pop::arb_csp_pop;
pub use csp_public_key::arb_csp_public_key;
pub use csp_signature::arb_csp_signature;
pub use csp_threshold_sign_error::arb_csp_threshold_sign_error;

mod common {
    use super::*;
    use proptest::array::uniform24;

    pub(crate) const MAX_ALGORITHM_ID_INDEX: i32 = 16;

    prop_compose! {
        pub fn arb_key_id()(id in uniform32(any::<u8>())) -> KeyId {
            KeyId::from(id)
        }
    }

    prop_compose! {
        pub fn arb_algorithm_id()(id in 0..MAX_ALGORITHM_ID_INDEX) -> AlgorithmId {
            AlgorithmId::from(id)
        }
    }

    prop_compose! {
        pub (crate) fn arb_48_bytes()(left in uniform24(any::<u8>()), right in uniform24(any::<u8>())) -> [u8; 48] {
            [left, right].concat().try_into().unwrap()
        }
    }

    prop_compose! {
        pub (crate) fn arb_64_bytes()(left in uniform32(any::<u8>()), right in uniform32(any::<u8>())) -> [u8; 64] {
            [left, right].concat().try_into().unwrap()
        }
    }

    prop_compose! {
        pub (crate) fn arb_96_bytes()(left in uniform32(any::<u8>()), middle in uniform32(any::<u8>()), right in uniform32(any::<u8>())) -> [u8; 96] {
            [left, middle, right].concat().try_into().unwrap()
        }
    }
}

mod csp_basic_signature_error {
    use super::*;
    use crate::common::arb_algorithm_id;
    use crate::common::arb_key_id;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;

    prop_compose! {
        pub(super) fn arb_secret_key_not_found_error()(algorithm in arb_algorithm_id(), key_id in arb_key_id()) -> CspBasicSignatureError {
            CspBasicSignatureError::SecretKeyNotFound { algorithm, key_id }
        }
    }

    prop_compose! {
        pub(super) fn arb_unsupported_algorithm_error()(algorithm in arb_algorithm_id()) -> CspBasicSignatureError {
            CspBasicSignatureError::UnsupportedAlgorithm { algorithm }
        }
    }

    prop_compose! {
        pub(super) fn arb_wrong_secret_key_type_error()(algorithm in arb_algorithm_id(), secret_key_variant in ".*") -> CspBasicSignatureError {
            CspBasicSignatureError::WrongSecretKeyType { algorithm, secret_key_variant }
        }
    }

    prop_compose! {
        pub(super) fn arb_malformed_secret_key_error()(algorithm in arb_algorithm_id()) -> CspBasicSignatureError {
            CspBasicSignatureError::MalformedSecretKey { algorithm }
        }
    }

    prop_compose! {
        pub(super) fn arb_internal_error()(internal_error in ".*") -> CspBasicSignatureError {
            CspBasicSignatureError::InternalError { internal_error }
        }
    }

    pub fn arb_csp_basic_signature_error() -> BoxedStrategy<CspBasicSignatureError> {
        prop_oneof![
            arb_secret_key_not_found_error(),
            arb_unsupported_algorithm_error(),
            arb_wrong_secret_key_type_error(),
            arb_malformed_secret_key_error(),
            arb_internal_error()
        ]
        .boxed()
    }
}

mod csp_signature {
    use super::*;
    use crate::common::arb_64_bytes;
    use crate::csp_signature::multi_bls12_381_signature::arb_multi_bls12_381_signature;
    use crate::csp_signature::thres_bls12_381_signature::arb_thres_bls12_381_signature;
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_internal_csp::types::CspSignature;

    prop_compose! {
       pub(super) fn arb_ecdsa_p256_signature()(bytes in arb_64_bytes()) -> CspSignature {
            CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes(bytes))
       }
    }

    prop_compose! {
       pub(super) fn arb_ecdsa_secp_256k1_signature()(bytes in arb_64_bytes()) -> CspSignature {
            CspSignature::EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes(bytes))
       }
    }

    prop_compose! {
       pub(super) fn arb_ed25519_signature()(bytes in arb_64_bytes()) -> CspSignature {
            CspSignature::Ed25519(ed25519_types::SignatureBytes(bytes))
       }
    }

    prop_compose! {
         pub(super) fn arb_multi_bls12_381_csp_signature()(signature in arb_multi_bls12_381_signature()) -> CspSignature {
            CspSignature::MultiBls12_381(signature)
         }
    }

    prop_compose! {
         pub(super) fn arb_thres_bls12_381_csp_signature()(signature in arb_thres_bls12_381_signature()) -> CspSignature {
            CspSignature::ThresBls12_381(signature)
         }
    }

    prop_compose! {
        pub(super) fn arb_rsa_sha256_signature()(bytes in vec(any::<u8>(), 0..100)) -> CspSignature {
            CspSignature::RsaSha256(bytes)
        }
    }

    pub fn arb_csp_signature() -> BoxedStrategy<CspSignature> {
        prop_oneof![
            arb_ecdsa_p256_signature(),
            arb_ecdsa_secp_256k1_signature(),
            arb_ed25519_signature(),
            arb_multi_bls12_381_csp_signature(),
            arb_thres_bls12_381_csp_signature(),
            arb_rsa_sha256_signature()
        ]
        .boxed()
    }

    pub(super) mod multi_bls12_381_signature {
        use super::*;
        use crate::common::arb_48_bytes;
        use ic_crypto_internal_csp::types::MultiBls12_381_Signature;
        use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
        use proptest::prelude::BoxedStrategy;
        use proptest::{prop_compose, prop_oneof};

        prop_compose! {
            pub(crate)  fn arb_individual()(bytes in arb_48_bytes()) -> MultiBls12_381_Signature {
               MultiBls12_381_Signature::Individual(multi_types::IndividualSignatureBytes(bytes))
            }
        }

        prop_compose! {
            pub(crate) fn arb_combined()(bytes in arb_48_bytes()) -> MultiBls12_381_Signature {
               MultiBls12_381_Signature::Combined(multi_types::CombinedSignatureBytes(bytes))
            }
        }

        pub fn arb_multi_bls12_381_signature() -> BoxedStrategy<MultiBls12_381_Signature> {
            prop_oneof![arb_individual(), arb_combined()].boxed()
        }
    }

    pub(super) mod thres_bls12_381_signature {
        use super::*;
        use crate::common::arb_48_bytes;
        use ic_crypto_internal_csp::types::ThresBls12_381_Signature;
        use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;

        prop_compose! {
            pub(crate) fn arb_individual()(bytes in arb_48_bytes()) -> ThresBls12_381_Signature {
               ThresBls12_381_Signature::Individual(threshold_types::IndividualSignatureBytes(bytes))
            }
        }

        prop_compose! {
            pub(crate)  fn arb_combined()(bytes in arb_48_bytes()) -> ThresBls12_381_Signature {
               ThresBls12_381_Signature::Combined(threshold_types::CombinedSignatureBytes(bytes))
            }
        }

        pub fn arb_thres_bls12_381_signature() -> BoxedStrategy<ThresBls12_381_Signature> {
            prop_oneof![arb_individual(), arb_combined()].boxed()
        }
    }
}

mod csp_public_key {
    use super::*;
    use crate::common::arb_96_bytes;
    use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
    use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
    use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
    use ic_crypto_internal_basic_sig_rsa_pkcs1::RsaPublicKey;
    use ic_crypto_internal_csp::types::CspPublicKey;
    use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

    prop_compose! {
        pub(super)  fn arb_ecdsa_p256_public_key()(bytes in vec(any::<u8>(), 0..100)) -> CspPublicKey {
            CspPublicKey::EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes(bytes))
        }
    }

    prop_compose! {
        pub(super) fn arb_ecdsa_secp_256k1_public_key()(bytes in vec(any::<u8>(), 0..100)) -> CspPublicKey {
            CspPublicKey::EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes(bytes))
        }
    }

    prop_compose! {
        pub(super) fn arb_ed25519_public_key()(bytes in uniform32(any::<u8>())) -> CspPublicKey {
            CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(bytes))
        }
    }

    prop_compose! {
        pub(super) fn arb_multi_bls12_381_public_key()(bytes in arb_96_bytes()) -> CspPublicKey {
            CspPublicKey::MultiBls12_381(multi_types::PublicKeyBytes(bytes))
        }
    }

    prop_compose! {
        //minimal size of RSA public key is 2048 bits, corresponding to 512 hexadecimal characters
        //the first character must be such that its binary representation does not have any leading zeroes,
        //to ensure that the key will contain 2048 bits.
        //the last character must correspond to an odd number to ensure the modulus being odd
        pub(super) fn arb_rsa_sha_256_public_key()(modulus_in_hex in "[8-9a-f]{1}[0-9a-f]{510}[13579bdf]{1}") -> CspPublicKey {
            let n = hex::decode(modulus_in_hex).expect("invalid hexadecimal");
            let e = [1,0,1];
            let rsa_public_key = RsaPublicKey::from_components(&e, &n).expect("invalid RSA public key");
            CspPublicKey::RsaSha256(rsa_public_key)
        }
    }

    pub fn arb_csp_public_key() -> BoxedStrategy<CspPublicKey> {
        prop_oneof![
            arb_ecdsa_p256_public_key(),
            arb_ecdsa_secp_256k1_public_key(),
            arb_multi_bls12_381_public_key(),
            arb_rsa_sha_256_public_key()
        ]
        .boxed()
    }
}

mod csp_pop {
    use super::*;
    use crate::common::arb_48_bytes;
    use ic_crypto_internal_csp::types::CspPop;
    use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

    prop_compose! {
        pub(super)  fn arb_multi_bls12_381()(bytes in arb_48_bytes()) -> CspPop {
           CspPop::MultiBls12_381(multi_types::PopBytes(bytes))
        }
    }

    pub fn arb_csp_pop() -> BoxedStrategy<CspPop> {
        arb_multi_bls12_381().boxed()
    }
}

mod csp_basic_signature_keygen_error {
    use super::*;
    use crate::common::arb_key_id;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;

    prop_compose! {
        pub(super) fn arb_internal_error()(internal_error in ".*") -> CspBasicSignatureKeygenError {
            CspBasicSignatureKeygenError::InternalError { internal_error }
        }
    }

    prop_compose! {
        pub(super) fn arb_duplicated_key_id_error()(key_id in arb_key_id()) -> CspBasicSignatureKeygenError {
            CspBasicSignatureKeygenError::DuplicateKeyId {key_id}
        }
    }

    prop_compose! {
        pub(super) fn arb_transient_internal_error()(internal_error in ".*") -> CspBasicSignatureKeygenError {
            CspBasicSignatureKeygenError::TransientInternalError { internal_error }
        }
    }

    pub fn arb_csp_basic_signature_keygen_error() -> BoxedStrategy<CspBasicSignatureKeygenError> {
        prop_oneof![
            arb_internal_error(),
            arb_duplicated_key_id_error(),
            arb_transient_internal_error()
        ]
        .boxed()
    }
}

mod csp_multi_signature_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureError;

    prop_compose! {
        pub(super)fn arb_secret_key_not_found_error()(algorithm in arb_algorithm_id(), key_id in arb_key_id()) -> CspMultiSignatureError {
            CspMultiSignatureError::SecretKeyNotFound { algorithm, key_id }
        }
    }

    prop_compose! {
       pub(super) fn arb_unsupported_algorithm_error()(algorithm in arb_algorithm_id()) -> CspMultiSignatureError {
            CspMultiSignatureError::UnsupportedAlgorithm { algorithm }
        }
    }

    prop_compose! {
       pub(super) fn arb_wrong_secret_key_type_error()(algorithm in arb_algorithm_id(), secret_key_variant in ".*") -> CspMultiSignatureError {
            CspMultiSignatureError::WrongSecretKeyType { algorithm, secret_key_variant }
        }
    }

    prop_compose! {
       pub(super) fn arb_internal_error()(internal_error in ".*") -> CspMultiSignatureError {
            CspMultiSignatureError::InternalError { internal_error }
        }
    }

    pub fn arb_csp_multi_signature_error() -> BoxedStrategy<CspMultiSignatureError> {
        prop_oneof![
            arb_secret_key_not_found_error(),
            arb_unsupported_algorithm_error(),
            arb_wrong_secret_key_type_error(),
            arb_internal_error(),
        ]
        .boxed()
    }
}

mod csp_multi_signature_keygen_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureKeygenError;

    prop_compose! {
        pub(super) fn arb_malformed_public_key_error()(algorithm in arb_algorithm_id(), key_bytes in proptest::option::of(vec(any::<u8>(), 0..100)), internal_error in ".*") -> CspMultiSignatureKeygenError {
            CspMultiSignatureKeygenError::MalformedPublicKey { algorithm, key_bytes, internal_error }
        }
    }

    prop_compose! {
       pub(super) fn arb_internal_error()(internal_error in ".*") -> CspMultiSignatureKeygenError {
            CspMultiSignatureKeygenError::InternalError { internal_error }
        }
    }

    prop_compose! {
        pub(super) fn arb_duplicated_key_id_error()(key_id in arb_key_id()) -> CspMultiSignatureKeygenError {
            CspMultiSignatureKeygenError::DuplicateKeyId {key_id}
        }
    }

    prop_compose! {
        pub(super) fn arb_transient_internal_error()(internal_error in ".*") -> CspMultiSignatureKeygenError {
            CspMultiSignatureKeygenError::TransientInternalError { internal_error }
        }
    }

    pub fn arb_csp_multi_signature_keygen_error() -> BoxedStrategy<CspMultiSignatureKeygenError> {
        prop_oneof![
            arb_malformed_public_key_error(),
            arb_internal_error(),
            arb_duplicated_key_id_error(),
            arb_transient_internal_error()
        ]
        .boxed()
    }
}

mod csp_threshold_sign_error {
    use super::*;
    use ic_crypto_internal_csp::api::CspThresholdSignError;
    use proptest::prelude::Just;

    prop_compose! {
        pub(super) fn arb_secret_key_not_found_error()(algorithm in arb_algorithm_id(), key_id in arb_key_id()) -> CspThresholdSignError {
            CspThresholdSignError::SecretKeyNotFound { algorithm, key_id }
        }
    }

    prop_compose! {
        pub(super) fn arb_unsupported_algorithm_error()(algorithm in arb_algorithm_id()) -> CspThresholdSignError {
            CspThresholdSignError::UnsupportedAlgorithm { algorithm }
        }
    }

    pub(super) fn arb_wrong_secret_key_type_error() -> impl Strategy<Value = CspThresholdSignError>
    {
        Just(CspThresholdSignError::WrongSecretKeyType {})
    }

    prop_compose! {
        pub(super) fn arb_malformed_secret_key_error()(algorithm in arb_algorithm_id()) -> CspThresholdSignError {
            CspThresholdSignError::MalformedSecretKey { algorithm }
        }
    }

    prop_compose! {
        pub(super) fn arb_internal_error()(internal_error in ".*") -> CspThresholdSignError {
            CspThresholdSignError::InternalError { internal_error }
        }
    }

    pub fn arb_csp_threshold_sign_error() -> BoxedStrategy<CspThresholdSignError> {
        prop_oneof![
            arb_secret_key_not_found_error(),
            arb_unsupported_algorithm_error(),
            arb_wrong_secret_key_type_error(),
            arb_malformed_secret_key_error(),
            arb_internal_error()
        ]
        .boxed()
    }
}
