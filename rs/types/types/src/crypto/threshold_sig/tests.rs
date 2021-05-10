use super::*;

#[test]
fn should_arrive_at_original_threshold_sig_pubkey_when_converting_via_publickey_protobuf() {
    let threshold_sig_pubkey = threshold_sig_pubkey(123);

    assert_eq!(
        ThresholdSigPublicKey::try_from(PublicKeyProto::from(threshold_sig_pubkey)).unwrap(),
        threshold_sig_pubkey,
    )
}

#[test]
fn should_fail_constructing_threshold_sig_pubkey_from_protobuf_with_wrong_algorithm() {
    let wrong_algorithm = AlgorithmIdProto::MultiBls12381 as i32;
    let key_value = [123; bls12_381::PublicKeyBytes::SIZE];
    let proto_with_wrong_algorithm = PublicKeyProto {
        algorithm: wrong_algorithm,
        key_value: key_value.to_vec(),
        version: 0,
        proof_data: None,
    };

    assert_eq!(
        ThresholdSigPublicKey::try_from(proto_with_wrong_algorithm).unwrap_err(),
        ThresholdSigPublicKeyBytesConversionError::Malformed {
            key_bytes: Some(key_value.to_vec()),
            internal_error: format!(
                "Invalid algorithm: expected {:?} but got {:?}",
                AlgorithmId::ThresBls12_381,
                AlgorithmId::from(wrong_algorithm)
            ),
        },
    );
}

#[test]
fn should_fail_constructing_threshold_sig_pubkey_from_protobuf_with_wrong_length() {
    const WRONG_LENGTH: usize = bls12_381::PublicKeyBytes::SIZE - 1;
    let key_value = [123; WRONG_LENGTH];
    let proto_with_wrong_length = PublicKeyProto {
        algorithm: AlgorithmIdProto::ThresBls12381 as i32,
        key_value: key_value.to_vec(),
        version: 0,
        proof_data: None,
    };

    assert_eq!(
        ThresholdSigPublicKey::try_from(proto_with_wrong_length).unwrap_err(),
        ThresholdSigPublicKeyBytesConversionError::Malformed {
            internal_error: format!(
                "Invalid length: expected {} but got {}",
                bls12_381::PublicKeyBytes::SIZE,
                WRONG_LENGTH,
            ),
            key_bytes: Some(key_value.to_vec()),
        }
    );
}

fn threshold_sig_pubkey(data: u8) -> ThresholdSigPublicKey {
    ThresholdSigPublicKey {
        internal: CspThresholdSigPublicKey::ThresBls12_381(bls12_381::PublicKeyBytes(
            [data; bls12_381::PublicKeyBytes::SIZE],
        )),
    }
}
