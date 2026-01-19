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
pub use common::arb_node_id;
pub use common::arb_seed;
pub use crypto_error::arb_crypto_error;
pub use csp_basic_signature_error::arb_csp_basic_signature_error;
pub use csp_basic_signature_keygen_error::arb_csp_basic_signature_keygen_error;
pub use csp_multi_signature_error::arb_csp_multi_signature_error;
pub use csp_multi_signature_keygen_error::arb_csp_multi_signature_keygen_error;
pub use csp_pop::arb_csp_pop;
pub use csp_public_key::arb_csp_public_key;
pub use csp_public_key_store_error::arb_csp_public_key_store_error;
pub use csp_secret_key_store_contains_error::arb_csp_secret_key_store_contains_error;
pub use csp_signature::arb_csp_signature;
pub use csp_threshold_sign_error::arb_csp_threshold_sign_error;
pub use csp_tls_keygen_error::arb_csp_tls_keygen_error;
pub use csp_tls_sign_error::arb_csp_tls_sign_error;
pub use node_public_keys::arb_current_node_public_keys;
pub use node_public_keys::arb_external_public_keys;
pub use pks_and_sks_contains_errors::arb_pks_and_sks_contains_errors;
pub use public_random_seed_generator_error::arb_public_random_seed_generator_error;
pub use validate_pks_and_sks_error::arb_validate_pks_and_sks_error;

/// Creates a proptest strategy for a given enum variant.
macro_rules! proptest_strategy_for_enum_variant {
    // Match simple enum variant struct without any data,
    // like ValidatePksAndSksKeyPairError::PublicKeyNotFound
    ($enum_name:ty, $variant:ident) => {
        paste! {
            pub(super) fn [<arb_ $variant:snake _variant>]() -> impl proptest::strategy::Strategy<Value=$enum_name> {
                proptest::prelude::Just($enum_name::$variant)
            }
        }
    };
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
    ($enum_name:ty, $variant:ident => {$($field:pat in $strategy:expr_2021),+ $(,)?}) => {
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
    ($enum_name:ty, $variant:ident => ($($field:pat in $strategy:expr_2021),+ $(,)?)) => {
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
    ($enum_name:ty, $variant:ident => ($tuple_type:ty: $($field:pat in $strategy:expr_2021),+ $(,)?)) => {
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
    $($variant:ident $(=> $args:tt)?),+ $(,)?) => {
        $(
           proptest_strategy_for_enum_variant!($enum_name, $variant $(=> $args)?);
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
    use ic_crypto_internal_seed::Seed;
    use ic_types::NodeId;
    use ic_types::PrincipalId;
    use ic_types::RegistryVersion;
    use ic_types::SubnetId;
    use ic_types::crypto::KeyPurpose;
    use proptest::array::uniform24;
    use proptest::prelude::{Strategy, prop};
    use strum::IntoEnumIterator;

    pub(crate) const MAX_ALGORITHM_ID_INDEX: i32 = 20;

    prop_compose! {
        pub fn arb_key_id()(id in uniform32(any::<u8>())) -> KeyId {
            KeyId::from(id)
        }
    }

    pub fn arb_key_purpose() -> impl Strategy<Value = KeyPurpose> {
        prop::sample::select(KeyPurpose::iter().collect::<Vec<_>>())
    }

    prop_compose! {
        pub fn arb_node_id()(id in any::<u64>()) -> NodeId {
            NodeId::from(PrincipalId::new_node_test_id(id))
        }
    }

    prop_compose! {
        pub fn arb_seed()(bytes in uniform32(any::<u8>())) -> Seed {
            Seed::from_bytes(&bytes)
        }
    }

    prop_compose! {
        pub fn arb_subnet_id()(id in any::<u64>()) -> SubnetId {
            SubnetId::from(PrincipalId::new_subnet_test_id(id))
        }
    }

    prop_compose! {
        pub fn arb_registry_version()(version in any::<u64>()) -> RegistryVersion {
            RegistryVersion::from(version)
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
    use crate::common::arb_key_id;
    use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;

    proptest_strategy_for_enum!(CspBasicSignatureError;
        PublicKeyNotFound,
        MalformedPublicKey => (error in ".*"),
        SecretKeyNotFound => (key_id in arb_key_id()),
        WrongSecretKeyType => {secret_key_variant in ".*"},
        TransientInternalError => {internal_error in ".*"},
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
        TransientInternalError => {internal_error in ".*"}
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
        KeyIdInstantiationError => (error in ".*"),
        TransientInternalError => {internal_error in ".*"}
    );
}

mod csp_secret_key_store_contains_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspSecretKeyStoreContainsError;

    proptest_strategy_for_enum!(CspSecretKeyStoreContainsError;
        TransientInternalError => {internal_error in ".*"}
    );
}

pub mod registry_client_error {
    use super::*;
    use crate::common::arb_registry_version;
    use ic_types::registry::{RegistryClientError, RegistryDataProviderError};
    use proptest::prelude::Just;
    use proptest::prelude::{BoxedStrategy, Strategy};
    use proptest::prop_oneof;

    proptest_strategy_for_enum!(RegistryClientError;
        VersionNotAvailable => {version in arb_registry_version()},
        NoVersionsBefore => {timestamp_nanoseconds in any::<u64>()},
        DataProviderQueryFailed => {source in  arb_registry_data_provider_error()},
        PollLockFailed => {error in ".*"},
        PollingLatestVersionFailed => {retries in any::<usize>()},
        DecodeError => {error in ".*"},
    );

    fn arb_registry_data_provider_error() -> BoxedStrategy<RegistryDataProviderError> {
        prop_oneof![
            Just(RegistryDataProviderError::Timeout),
            ".*".prop_map(|source| RegistryDataProviderError::Transfer { source })
        ]
        .boxed()
    }
}

mod crypto_error {
    use super::*;
    use crate::common::{arb_key_purpose, arb_node_id, arb_registry_version, arb_subnet_id};
    use crate::registry_client_error::arb_registry_client_error;
    use ic_types::Height;
    use ic_types::crypto::CryptoError;
    use ic_types::crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
    };
    use proptest::collection::btree_set;
    use proptest::prelude::{BoxedStrategy, Just, Strategy};
    use proptest::prop_oneof;

    proptest_strategy_for_enum!(CryptoError;
        InvalidArgument => {message in ".*"},
        PublicKeyNotFound => {node_id in arb_node_id(), key_purpose in arb_key_purpose(), registry_version in arb_registry_version()},
        TlsCertNotFound => {node_id in arb_node_id(), registry_version in arb_registry_version()},
        SecretKeyNotFound => {algorithm in arb_algorithm_id(), key_id in ".*"},
        TlsSecretKeyNotFound => {certificate_der in vec(any::<u8>(), 0..100)},
        MalformedSecretKey => {algorithm in arb_algorithm_id(), internal_error in ".*"},
        MalformedPublicKey => {algorithm in arb_algorithm_id(), key_bytes in proptest::option::of(vec(any::<u8>(), 0..100)), internal_error in ".*"},
        MalformedSignature => {algorithm in arb_algorithm_id(), sig_bytes in vec(any::<u8>(), 0..100), internal_error in ".*"},
        MalformedPop => {algorithm in arb_algorithm_id(), pop_bytes in vec(any::<u8>(), 0..100), internal_error in ".*"},
        SignatureVerification => {algorithm in arb_algorithm_id(), public_key_bytes in vec(any::<u8>(), 0..100), sig_bytes in vec(any::<u8>(), 0..100), internal_error in ".*"},
        PopVerification => {algorithm in arb_algorithm_id(), public_key_bytes in vec(any::<u8>(), 0..100), pop_bytes in vec(any::<u8>(), 0..100), internal_error in ".*"},
        InconsistentAlgorithms => {algorithms in btree_set(arb_algorithm_id(), 0..10), key_purpose in arb_key_purpose(), registry_version in arb_registry_version()},
        AlgorithmNotSupported => {algorithm in arb_algorithm_id(), reason in ".*"},
        RegistryClient => (error in arb_registry_client_error()),
        ThresholdSigDataNotFound => {dkg_id in arb_nidkg_id()},
        DkgTranscriptNotFound => {subnet_id in arb_subnet_id(), registry_version in arb_registry_version()},
        RootSubnetPublicKeyNotFound => {registry_version in arb_registry_version()},
        InternalError => {internal_error in ".*"},
        TransientInternalError => {internal_error in ".*"},
    );

    prop_compose! {
        fn arb_nidkg_id()(height in any::<u64>(), dealer_subnet in arb_subnet_id(), dkg_tag in arb_nidkg_tag(), target_subnet in arb_nidkg_target_subnet()) -> NiDkgId {
            NiDkgId {
                start_block_height: Height::new(height),
                dealer_subnet,
                dkg_tag,
                target_subnet
            }
        }
    }

    fn arb_nidkg_tag() -> BoxedStrategy<NiDkgTag> {
        prop_oneof![Just(NiDkgTag::LowThreshold), Just(NiDkgTag::HighThreshold)].boxed()
    }

    fn arb_nidkg_target_subnet() -> BoxedStrategy<NiDkgTargetSubnet> {
        prop_oneof![
            Just(NiDkgTargetSubnet::Local),
            uniform32(any::<u8>()).prop_map(|id| NiDkgTargetSubnet::Remote(NiDkgTargetId::new(id)))
        ]
        .boxed()
    }
}

mod csp_public_key_store_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspPublicKeyStoreError;

    proptest_strategy_for_enum!(CspPublicKeyStoreError;
        TransientInternalError => (error in ".*")
    );
}

mod node_public_keys {
    use super::*;
    use ic_crypto_internal_csp::types::ExternalPublicKeys;
    use ic_protobuf::registry::crypto::v1::{
        PublicKey as PublicKeyProto, X509PublicKeyCert as X509PublicKeyCertProto,
    };
    use ic_types::crypto::CurrentNodePublicKeys;

    prop_compose! {
        fn arb_public_key_proto()(
            version in any::<u32>(),
            algorithm in any::<i32>(),
            key_value in vec(any::<u8>(), 0..100),
            proof_data in proptest::option::of(vec(any::<u8>(), 0..100)),
            timestamp in proptest::option::of(any::<u64>())
        ) -> PublicKeyProto {
            PublicKeyProto {
                version,
                algorithm,
                key_value,
                proof_data,
                timestamp
            }
        }
    }
    prop_compose! {
        fn arb_x509_public_key_cert_proto()(certificate_der in vec(any::<u8>(), 0..100)) -> X509PublicKeyCertProto {
            X509PublicKeyCertProto {
                certificate_der
            }
        }
    }

    prop_compose! {
        pub fn arb_current_node_public_keys()(
            node_signing_public_key in proptest::option::of(arb_public_key_proto()),
            committee_signing_public_key in proptest::option::of(arb_public_key_proto()),
            tls_certificate in proptest::option::of(arb_x509_public_key_cert_proto()),
            dkg_dealing_encryption_public_key in proptest::option::of(arb_public_key_proto()),
            idkg_dealing_encryption_public_key in proptest::option::of(arb_public_key_proto())
        ) -> CurrentNodePublicKeys {
            CurrentNodePublicKeys {
                node_signing_public_key,
                committee_signing_public_key,
                tls_certificate,
                dkg_dealing_encryption_public_key,
                idkg_dealing_encryption_public_key
            }
        }
    }

    prop_compose! {
        pub fn arb_external_public_keys()(
            node_signing_public_key in arb_public_key_proto(),
            committee_signing_public_key in arb_public_key_proto(),
            tls_certificate in arb_x509_public_key_cert_proto(),
            dkg_dealing_encryption_public_key in arb_public_key_proto(),
            idkg_dealing_encryption_public_key in arb_public_key_proto()
        ) -> ExternalPublicKeys {
            ExternalPublicKeys {
                node_signing_public_key,
                committee_signing_public_key,
                tls_certificate,
                dkg_dealing_encryption_public_key,
                idkg_dealing_encryption_public_key
            }
        }
    }
}

mod pks_and_sks_contains_errors {
    use super::*;
    use ic_crypto_internal_csp::vault::api::{
        ExternalPublicKeyError, LocalPublicKeyError, NodeKeysError, NodeKeysErrors,
        PksAndSksContainsErrors, SecretKeyError,
    };
    use proptest::prelude::{Just, Strategy};
    use proptest::prop_oneof;

    proptest_strategy_for_enum!(PksAndSksContainsErrors;
        NodeKeysErrors => (errors in arb_node_keys_errors()),
        TransientInternalError => (error in ".*")
    );

    prop_compose! {
        fn arb_node_keys_errors()(
            node_signing_key_error in proptest::option::of(arb_node_keys_error()),
            committee_signing_key_error in proptest::option::of(arb_node_keys_error()),
            tls_certificate_error in proptest::option::of(arb_node_keys_error()),
            dkg_dealing_encryption_key_error in proptest::option::of(arb_node_keys_error()),
            idkg_dealing_encryption_key_error in proptest::option::of(arb_node_keys_error()),
        ) -> NodeKeysErrors {
            NodeKeysErrors {
                node_signing_key_error,
                committee_signing_key_error,
                tls_certificate_error,
                dkg_dealing_encryption_key_error,
                idkg_dealing_encryption_key_error
            }
        }
    }

    prop_compose! {
        fn arb_node_keys_error()(
            external_public_key_error in proptest::option::of(arb_external_public_key_error()),
            local_public_key_error in proptest::option::of(arb_local_public_key_error()),
            secret_key_error in proptest::option::of(arb_secret_key_error()),
        ) -> NodeKeysError {
            NodeKeysError {
                external_public_key_error,
                local_public_key_error,
                secret_key_error
            }
        }
    }

    fn arb_external_public_key_error() -> impl Strategy<Value = ExternalPublicKeyError> {
        ".*".prop_map(|error| ExternalPublicKeyError(Box::new(error)))
    }

    fn arb_local_public_key_error() -> impl Strategy<Value = LocalPublicKeyError> {
        prop_oneof![
            Just(LocalPublicKeyError::NotFound),
            Just(LocalPublicKeyError::Mismatch),
        ]
    }

    fn arb_secret_key_error() -> impl Strategy<Value = SecretKeyError> {
        prop_oneof![
            Just(SecretKeyError::CannotComputeKeyId),
            Just(SecretKeyError::NotFound)
        ]
    }
}

mod validate_pks_and_sks_key_pair_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::ValidatePksAndSksKeyPairError;

    proptest_strategy_for_enum!(ValidatePksAndSksKeyPairError;
        PublicKeyNotFound,
        PublicKeyInvalid => (s in ".*"),
        SecretKeyNotFound => {key_id in ".*"}
    );
}

mod validate_pks_and_sks_error {
    use super::*;
    use crate::validate_pks_and_sks_key_pair_error::arb_validate_pks_and_sks_key_pair_error;
    use ic_crypto_internal_csp::vault::api::ValidatePksAndSksError;

    proptest_strategy_for_enum!(ValidatePksAndSksError;
        EmptyPublicKeyStore,
        NodeSigningKeyError => (error in arb_validate_pks_and_sks_key_pair_error()),
        CommitteeSigningKeyError => (error in arb_validate_pks_and_sks_key_pair_error()),
        TlsCertificateError => (error in arb_validate_pks_and_sks_key_pair_error()),
        DkgDealingEncryptionKeyError => (error in arb_validate_pks_and_sks_key_pair_error()),
        IdkgDealingEncryptionKeyError => (error in arb_validate_pks_and_sks_key_pair_error()),
        TransientInternalError => (error in ".*")
    );
}

mod public_random_seed_generator_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;

    proptest_strategy_for_enum!(PublicRandomSeedGeneratorError;
        TransientInternalError => {internal_error in ".*"}
    );
}

mod csp_tls_keygen_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspTlsKeygenError;

    proptest_strategy_for_enum!(CspTlsKeygenError;
        InvalidArguments => {message in ".*"},
        InternalError => {internal_error in ".*"},
        DuplicateKeyId => {key_id in arb_key_id()},
        TransientInternalError => {internal_error in ".*"},
    );
}

mod csp_tls_sign_error {
    use super::*;
    use ic_crypto_internal_csp::vault::api::CspTlsSignError;

    proptest_strategy_for_enum!(CspTlsSignError;
        SecretKeyNotFound => { key_id in arb_key_id()},
        WrongSecretKeyType => {algorithm in arb_algorithm_id(), secret_key_variant in ".*"},
        MalformedSecretKey => {error in ".*"},
        TransientInternalError => {internal_error in ".*"}
    );
}
