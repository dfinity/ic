use super::*;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
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
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let (pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
    pks.dkg_dealing_encryption_pk
        .expect("missing dkg dealing encryption public key")
}

fn assert_malformed_fs_encryption_pubkey_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::PublicKeyConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!(
            "expected MalformedFsEncryptionPublicKey error, but got {}",
            error
        )
    }
}

fn assert_malformed_fs_encryption_pop_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::PopConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!("expected MalformedFsEncryptionPop error, but got {}", error)
    }
}

#[allow(clippy::assertions_on_constants)]
fn assert_internal_conversion_error(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::InternalConversion = error {
        assert!(true)
    } else {
        panic!("expected InternalConversion error, but got {}", error)
    }
}
