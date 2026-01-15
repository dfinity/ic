use super::*;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;

#[test]
fn should_fail_if_pubkey_conversion_fails() {
    let pubkey_proto_with_incorrect_key_value_length = PublicKeyProto {
        key_value: vec![42],
        ..valid_dkg_dealing_encryption_key()
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_with_incorrect_key_value_length);

    assert_malformed_fs_encryption_pubkey_error_containing(&result, "Wrong data length");
}

#[test]
fn should_fail_if_pop_conversion_fails() {
    let pubkey_proto_without_proof_data = {
        let mut key = valid_dkg_dealing_encryption_key();
        if let Some(pop_bytes) = key.proof_data.as_mut() {
            pop_bytes.pop();
        }
        key
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_without_proof_data);

    assert_malformed_fs_encryption_pop_error_containing(
        &result,
        "Malformed proof of possession (PoP)",
    );
}

#[test]
fn should_fail_if_internal_conversion_fails() {
    let pubkey_proto_with_corrupted_key_value = {
        let mut key = valid_dkg_dealing_encryption_key();
        key.key_value = vec![0; key.key_value.len()];
        key
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_with_corrupted_key_value);

    assert_internal_conversion_error(&result);
}

fn valid_dkg_dealing_encryption_key() -> PublicKeyProto {
    use ic_types::crypto::AlgorithmId;

    PublicKeyProto {
        version: 0,
        algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
        key_value: hex::decode(
            "ad36a01cbd40dcfa36ec21a96bedcab17372a9cd2b9eba6171ebeb28dd041a\
                  d5cbbdbb4bed55f59938e8ffb3dd69e386",
        )
        .expect("invalid hex data"),
        proof_data: Some(
            hex::decode(
                "a1781847726f7468323057697468506f705f42\
                6c7331325f333831a367706f705f6b65795830b751c9585044139f80abdebf38d7f30\
                aeb282f178a5e8c284f279eaad1c90d9927e56cac0150646992bce54e08d317ea6963\
                68616c6c656e676558203bb20c5e9c75790f63aae921316912ffc80d6d03946dd21f8\
                5c35159ca030ec668726573706f6e7365582063d6cf189635c0f3111f97e69ae0af8f\
                1594b0f00938413d89dbafc326340384",
            )
            .expect("invalid hex data"),
        ),
        timestamp: None,
    }
}

fn assert_malformed_fs_encryption_pubkey_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().expect_err("Unexpected success.");
    if let FsNiDkgPubkeyFromPubkeyProtoError::PublicKeyConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!("expected MalformedFsEncryptionPublicKey error, but got {error}")
    }
}

fn assert_malformed_fs_encryption_pop_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().expect_err("Unexpected success.");
    if let FsNiDkgPubkeyFromPubkeyProtoError::PopConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!("expected MalformedFsEncryptionPop error, but got {error}")
    }
}

#[allow(clippy::assertions_on_constants)]
fn assert_internal_conversion_error(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
) {
    let error = result.clone().expect_err("Unexpected success.");
    if let FsNiDkgPubkeyFromPubkeyProtoError::InternalConversion = error {
        assert!(true)
    } else {
        panic!("expected InternalConversion error, but got {error}")
    }
}
