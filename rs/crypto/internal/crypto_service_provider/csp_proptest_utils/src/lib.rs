use ic_crypto_internal_csp::key_id::KeyId;
use ic_types::crypto::AlgorithmId;
use paste::paste;
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::prop_compose;

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

/// Creates a proptest strategy for a given enum variant.
macro_rules! proptest_strategy_for_enum_variant {
    // Match simple enum variant struct without any fields,
    // like CspThresholdSignError::WrongSecretKeyType {}
    ($enum_name:ty, $variant:ident => {}) => {
        paste! {
            pub(super) fn [<arb_ $variant:snake _variant>]() -> impl proptest::strategy::Strategy<Value=$enum_name> {
                proptest::prelude::Just($enum_name::$variant {})
            }
        }
    };
    // Match enum variant struct with fields,
    // like CspThresholdSignError::SecretKeyNotFound{ algorithm, key_id }
    ($enum_name:ty, $variant:ident => {$($field:pat in $strategy:expr),+ $(,)?}) => {
        paste! {
            proptest::prop_compose! {
                pub(super) fn [<arb_ $variant:snake _variant>]()($($field in $strategy),+) -> $enum_name {
                    $enum_name::$variant { $($field),+ }
                }
            }
        }
    };
    // Match enum variant tuple structs,
    // like CspSignature::RsaSha256(Vec<u8>)
    ($enum_name:ty, $variant:ident => ($($field:pat in $strategy:expr),+ $(,)?)) => {
        paste! {
            proptest::prop_compose! {
                pub(super) fn [<arb_ $variant:snake _variant>]()($($field in $strategy),+) -> $enum_name {
                    $enum_name::$variant ( $($field),+ )
                }
            }
        }
    };
    // Match enum variant tuple structs wrapping a type,
    // like CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes)
    ($enum_name:ty, $variant:ident => ($tuple_type:ty: $($field:pat in $strategy:expr),+ $(,)?)) => {
        paste! {
            proptest::prop_compose! {
                pub(super) fn [<arb_ $variant:snake _variant>]()($($field in $strategy),+) -> $enum_name {
                    $enum_name::$variant ( $tuple_type ($($field),+ ) )
                }
            }
        }
    };
}
/// Creates a proptest strategy for a whole enum:
/// * Creates a strategy per enum variant. This strategy will only produce the given enum variant.
/// * Creates a wrapper strategy for the whole enum, where one of the strategies for a variant will be chosen.
macro_rules! proptest_strategy_for_enum {
    ($enum_name:ty;
    $($variant:ident => $args:tt),+ $(,)?) => {
        $(
           proptest_strategy_for_enum_variant!($enum_name, $variant => $args);
        )*
        paste! {
           pub fn [<arb_ $enum_name:snake >]() -> proptest::prelude::BoxedStrategy<$enum_name> {
               proptest::strategy::Strategy::boxed(
                   proptest::prop_oneof![
                       $([<arb_ $variant:snake _variant>](),)*
                   ]
               )
           }
        }
    };
}

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

    proptest_strategy_for_enum!(CspBasicSignatureError;
        SecretKeyNotFound => {algorithm in arb_algorithm_id(), key_id in arb_key_id()},
        UnsupportedAlgorithm => {algorithm in arb_algorithm_id()},
        WrongSecretKeyType => {algorithm in arb_algorithm_id(), secret_key_variant in ".*"},
        MalformedSecretKey => {algorithm in arb_algorithm_id()},
        InternalError => {internal_error in ".*"}
    );
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

    proptest_strategy_for_enum!(CspSignature;
        EcdsaP256 => (ecdsa_secp256r1_types::SignatureBytes: bytes in arb_64_bytes()),
        EcdsaSecp256k1 => (ecdsa_secp256k1_types::SignatureBytes: bytes in arb_64_bytes()),
        Ed25519 => (ed25519_types::SignatureBytes: bytes in arb_64_bytes()),
        MultiBls12_381 => (signature in arb_multi_bls12_381_signature()),
        ThresBls12_381 => (signature in arb_thres_bls12_381_signature()),
        RsaSha256 => (bytes in vec(any::<u8>(), 0..100))
    );
}

mod multi_bls12_381_signature {
    use super::*;
    use crate::common::arb_48_bytes;
    use ic_crypto_internal_csp::types::MultiBls12_381_Signature;
    use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

    proptest_strategy_for_enum!(MultiBls12_381_Signature;
        Individual => (multi_types::IndividualSignatureBytes: bytes in arb_48_bytes()),
        Combined => (multi_types::CombinedSignatureBytes: bytes in arb_48_bytes()),
    );
}

mod thres_bls12_381_signature {
    use super::*;
    use crate::common::arb_48_bytes;
    use ic_crypto_internal_csp::types::ThresBls12_381_Signature;
    use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;

    proptest_strategy_for_enum!(ThresBls12_381_Signature;
        Individual => (threshold_types::IndividualSignatureBytes: bytes in arb_48_bytes()),
        Combined => (threshold_types::CombinedSignatureBytes: bytes in arb_48_bytes()),
    );
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

    proptest_strategy_for_enum!(CspPublicKey;
        EcdsaP256 => (ecdsa_secp256r1_types::PublicKeyBytes: bytes in vec(any::<u8>(), 0..100)),
        EcdsaSecp256k1 => (ecdsa_secp256k1_types::PublicKeyBytes: bytes in vec(any::<u8>(), 0..100)),
        Ed25519 => (ed25519_types::PublicKeyBytes: bytes in uniform32(any::<u8>())),
        MultiBls12_381 => (multi_types::PublicKeyBytes: bytes in arb_96_bytes()),
        RsaSha256 => (public_key in arb_rsa_public_key())
    );

    prop_compose! {
        //minimal size of RSA public key is 2048 bits, corresponding to 512 hexadecimal characters
        //the first character must be such that its binary representation does not have any leading zeroes,
        //to ensure that the key will contain 2048 bits.
        //the last character must correspond to an odd number to ensure the modulus being odd
        pub(super) fn arb_rsa_public_key()(modulus_in_hex in "[8-9a-f]{1}[0-9a-f]{510}[13579bdf]{1}") -> RsaPublicKey {
            let n = hex::decode(modulus_in_hex).expect("invalid hexadecimal");
            let e = [1,0,1];
            RsaPublicKey::from_components(&e, &n).expect("valid RSA public key")
        }
    }
}

mod csp_pop {
    use super::*;
    use crate::common::arb_48_bytes;
    use ic_crypto_internal_csp::types::CspPop;
    use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

    proptest_strategy_for_enum!(CspPop;
        MultiBls12_381 => (multi_types::PopBytes: bytes in arb_48_bytes())
    );
}

mod csp_basic_signature_keygen_error {
    use super::*;
    use crate::common::arb_key_id;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;

    proptest_strategy_for_enum!(CspBasicSignatureKeygenError;
        InternalError => {internal_error in ".*"},
        DuplicateKeyId => {key_id in arb_key_id()},
        TransientInternalError => {internal_error in ".*"}
    );
}

mod csp_multi_signature_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureError;

    proptest_strategy_for_enum!(CspMultiSignatureError;
        SecretKeyNotFound => {algorithm in arb_algorithm_id(), key_id in arb_key_id()},
        UnsupportedAlgorithm => {algorithm in arb_algorithm_id()},
        WrongSecretKeyType => {algorithm in arb_algorithm_id(), secret_key_variant in ".*"},
        InternalError => {internal_error in ".*"}
    );
}

mod csp_multi_signature_keygen_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspMultiSignatureKeygenError;

    proptest_strategy_for_enum!(CspMultiSignatureKeygenError;
        MalformedPublicKey => {algorithm in arb_algorithm_id(), key_bytes in proptest::option::of(vec(any::<u8>(), 0..100)), internal_error in ".*"},
        InternalError => {internal_error in ".*"},
        DuplicateKeyId => {key_id in arb_key_id()},
        TransientInternalError => {internal_error in ".*"}
    );
}

mod csp_threshold_sign_error {
    use super::*;
    use ic_crypto_internal_csp::api::CspThresholdSignError;

    proptest_strategy_for_enum!(CspThresholdSignError;
        SecretKeyNotFound => {algorithm in arb_algorithm_id(), key_id in arb_key_id()},
        UnsupportedAlgorithm => {algorithm in arb_algorithm_id()},
        WrongSecretKeyType => {},
        MalformedSecretKey => {algorithm in arb_algorithm_id()},
        InternalError => {internal_error in ".*"}
    );
}
