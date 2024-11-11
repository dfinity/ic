#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

/// Some key related utils
pub mod utils {
    use crate::types::{CspPop, CspPublicKey};
    use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
    use ic_crypto_internal_types::encrypt::forward_secure::{
        CspFsEncryptionPop, CspFsEncryptionPublicKey,
    };
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
    use ic_types::crypto::AlgorithmId;

    /// Form a protobuf structure of the public key and proof of possession
    pub fn dkg_dealing_encryption_pk_to_proto(
        pk: CspFsEncryptionPublicKey,
        pop: CspFsEncryptionPop,
    ) -> PublicKeyProto {
        match (pk, pop) {
            (
                CspFsEncryptionPublicKey::Groth20_Bls12_381(fs_enc_pk),
                CspFsEncryptionPop::Groth20WithPop_Bls12_381(_),
            ) => PublicKeyProto {
                algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
                key_value: fs_enc_pk.as_bytes().to_vec(),
                version: 0,
                proof_data: Some(serde_cbor::to_vec(&pop).expect(
                    "Failed to serialize DKG dealing encryption key proof of possession (PoP) to CBOR",
                )),
                timestamp: None
            },
        }
    }

    pub fn node_signing_pk_to_proto(public_key: CspPublicKey) -> PublicKeyProto {
        match public_key {
            CspPublicKey::Ed25519(pk) => PublicKeyProto {
                algorithm: AlgorithmId::Ed25519 as i32,
                key_value: pk.0.to_vec(),
                version: 0,
                proof_data: None,
                timestamp: None,
            },
            _ => panic!("Unexpected types"),
        }
    }

    pub fn committee_signing_pk_to_proto(public_key: (CspPublicKey, CspPop)) -> PublicKeyProto {
        match public_key {
            (CspPublicKey::MultiBls12_381(pk_bytes), CspPop::MultiBls12_381(pop_bytes)) => {
                PublicKeyProto {
                    algorithm: AlgorithmIdProto::MultiBls12381 as i32,
                    key_value: pk_bytes.0.to_vec(),
                    version: 0,
                    proof_data: Some(pop_bytes.0.to_vec()),
                    timestamp: None,
                }
            }
            _ => panic!("Unexpected types"),
        }
    }

    pub fn idkg_dealing_encryption_pk_to_proto(public_key: MEGaPublicKey) -> PublicKeyProto {
        PublicKeyProto {
            version: 0,
            algorithm: AlgorithmIdProto::MegaSecp256k1 as i32,
            key_value: public_key.serialize(),
            proof_data: None,
            timestamp: None,
        }
    }

    #[derive(Clone, Eq, PartialEq, Debug)]
    pub enum MEGaPublicKeyFromProtoError {
        UnsupportedAlgorithm {
            algorithm_id: Option<AlgorithmIdProto>,
        },
        MalformedPublicKey {
            key_bytes: Vec<u8>,
        },
    }

    /// Deserialize a Protobuf public key to a MEGaPublicKey.
    pub fn mega_public_key_from_proto(
        proto: &PublicKeyProto,
    ) -> Result<MEGaPublicKey, MEGaPublicKeyFromProtoError> {
        let curve_type = match AlgorithmIdProto::try_from(proto.algorithm).ok() {
            Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
            alg_id => Err(MEGaPublicKeyFromProtoError::UnsupportedAlgorithm {
                algorithm_id: alg_id,
            }),
        }?;

        MEGaPublicKey::deserialize(curve_type, &proto.key_value).map_err(|_| {
            MEGaPublicKeyFromProtoError::MalformedPublicKey {
                key_bytes: proto.key_value.clone(),
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use assert_matches::assert_matches;
        use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;

        #[test]
        fn should_convert_mega_proto() {
            let mega_proto = valid_idkg_dealing_encryption_public_key();
            let mega_public_key = mega_public_key_from_proto(&mega_proto);
            assert_matches!(mega_public_key, Ok(key) if key.serialize() == mega_proto.key_value)
        }

        #[test]
        fn should_fail_to_convert_mega_pubkey_from_proto_if_algorithm_unsupported() {
            let mut mega_proto = valid_idkg_dealing_encryption_public_key();
            mega_proto.algorithm = AlgorithmIdProto::Ed25519 as i32;

            let result = mega_public_key_from_proto(&mega_proto);

            assert_matches!(
                result,
                Err(MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { .. })
            );
        }

        #[test]
        fn should_fail_to_convert_mega_pubkey_from_proto_if_pubkey_malformed() {
            let mut mega_proto = valid_idkg_dealing_encryption_public_key();
            mega_proto.key_value = b"malformed public key".to_vec();

            let result = mega_public_key_from_proto(&mega_proto);

            assert_matches!(
                result,
                Err(MEGaPublicKeyFromProtoError::MalformedPublicKey { .. })
            );
        }
    }
}
