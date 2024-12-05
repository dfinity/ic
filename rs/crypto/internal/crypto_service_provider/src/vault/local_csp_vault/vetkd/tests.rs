use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::types::CspSecretKey;
use crate::vault::api::{VetKdCspVault, VetKdEncryptedKeyShareCreationVaultError};
use crate::{key_id::KeyId, LocalCspVault};
use assert_matches::assert_matches;
use ic_crypto_internal_bls12_381_vetkd::{G2Affine, Scalar, TransportSecretKey};
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::vetkd::VetKdEncryptedKeyShareContent;
use ic_types::crypto::ExtendedDerivationPath;
use ic_types_test_utils::ids::canister_test_id;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn should_correctly_create_encrypted_vetkd_key_share() {
    let rng = reproducible_rng();

    let result = create_encrypted_vetkd_key_share(rng);

    assert_matches!(result, Ok(_));
}

#[test]
fn should_correctly_create_encrypted_vetkd_key_share_for_smoke_test_vector() {
    let rng = ChaCha20Rng::seed_from_u64(123);

    let result = create_encrypted_vetkd_key_share(rng);

    assert_eq!(
        result,
        Ok(VetKdEncryptedKeyShareContent(
            hex::decode(
                "8fb20ba0025e22ebc546852eca21e324cfc96c8b7b127b9c6790d5f5a2d1a7\
                2ad7c18c852215b44e3fe0315203b9565fafc0c7d8178ba92f0d6dca8c79d48\
                8c9f9ebf1469af0ebad6908c0edbd4c546a21ba9e1530732de2748f1c54ddbb\
                2a6406a9ad976f0487ec4d0063aec5f27301eeaeb47d3977d9a472dacdc8ad7\
                546c1f26453229d6f1aa612ea109e1ad4a05d9352b91693c734f7207002e2f9\
                da6ac9dac0aefe136247b46d44c763d33718604c6340e8c9c9fe388af7e3c93\
                3fc9255",
            )
            .expect("invalid test vector")
        ))
    );
}

fn create_encrypted_vetkd_key_share<R: Rng + CryptoRng + 'static>(
    mut rng: R,
) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError> {
    let master_secret_key = Scalar::random(&mut rng);
    let master_public_key = G2Affine::from(G2Affine::generator() * &master_secret_key);
    let encryption_public_key = TransportSecretKey::generate(&mut rng).public_key();
    let key_id = KeyId::from([123; 32]);

    let mut node_sks = MockSecretKeyStore::new();
    node_sks
        .expect_get()
        .times(1)
        .withf(move |key_id_| *key_id_ == key_id)
        .return_const(Some(CspSecretKey::ThresBls12_381(
            threshold_types::SecretKeyBytes::from(&master_secret_key),
        )));

    let derivation_path = ExtendedDerivationPath {
        caller: canister_test_id(234).get(),
        derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
    };
    let derivation_id = b"some-derivation-id".to_vec();

    let vault = LocalCspVault::builder_for_test()
        .with_rng(rng)
        .with_mock_stores()
        .with_node_secret_key_store(node_sks)
        .build();

    vault.create_encrypted_vetkd_key_share(
        key_id,
        master_public_key.serialize().to_vec(),
        encryption_public_key.serialize().to_vec(),
        derivation_path,
        derivation_id,
    )
}

#[test]
fn should_fail_to_create_key_share_with_invalid_master_public_key() {
    let rng = &mut reproducible_rng();

    let invalid_master_public_key = b"invalid-master-public-key".to_vec();
    let encryption_public_key = TransportSecretKey::generate(rng).public_key();
    let key_id = KeyId::from([123; 32]);

    let derivation_path = ExtendedDerivationPath {
        caller: canister_test_id(234).get(),
        derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
    };
    let derivation_id = b"some-derivation-id".to_vec();

    let vault = LocalCspVault::builder_for_test().with_mock_stores().build();

    let result = vault.create_encrypted_vetkd_key_share(
        key_id,
        invalid_master_public_key,
        encryption_public_key.serialize().to_vec(),
        derivation_path,
        derivation_id,
    );

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("invalid master public key")
    );
}

#[test]
fn should_fail_to_create_key_share_with_invalid_encryption_public_key() {
    let mut rng = reproducible_rng();

    let master_secret_key = Scalar::random(&mut rng);
    let master_public_key = G2Affine::from(G2Affine::generator() * &master_secret_key);
    let invalid_encryption_public_key = b"invalid-encryption-public-key".to_vec();
    let key_id = KeyId::from([123; 32]);

    let derivation_path = ExtendedDerivationPath {
        caller: canister_test_id(234).get(),
        derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
    };
    let derivation_id = b"some-derivation-id".to_vec();

    let vault = LocalCspVault::builder_for_test()
        .with_rng(rng)
        .with_mock_stores()
        .build();

    let result = vault.create_encrypted_vetkd_key_share(
        key_id,
        master_public_key.serialize().to_vec(),
        invalid_encryption_public_key,
        derivation_path,
        derivation_id,
    );

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("invalid encryption public key")
    );
}

#[test]
fn should_fail_to_create_key_share_if_key_is_missing_in_secret_key_store() {
    let mut rng = reproducible_rng();

    let master_secret_key = Scalar::random(&mut rng);
    let master_public_key = G2Affine::from(G2Affine::generator() * &master_secret_key);
    let encryption_public_key = TransportSecretKey::generate(&mut rng).public_key();
    let key_id = KeyId::from([123; 32]);

    let mut node_sks = MockSecretKeyStore::new();
    node_sks
        .expect_get()
        .times(1)
        .withf(move |key_id_| *key_id_ == key_id)
        .return_const(None);

    let derivation_path = ExtendedDerivationPath {
        caller: canister_test_id(234).get(),
        derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
    };
    let derivation_id = b"some-derivation-id".to_vec();

    let vault = LocalCspVault::builder_for_test()
        .with_rng(rng)
        .with_mock_stores()
        .with_node_secret_key_store(node_sks)
        .build();

    let result = vault.create_encrypted_vetkd_key_share(
        key_id,
        master_public_key.serialize().to_vec(),
        encryption_public_key.serialize().to_vec(),
        derivation_path,
        derivation_id,
    );

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("missing key with ID")
    );
}

#[test]
fn should_fail_to_create_key_share_if_key_in_secret_key_store_has_wrong_type() {
    let mut rng = reproducible_rng();

    let master_secret_key = Scalar::random(&mut rng);
    let master_public_key = G2Affine::from(G2Affine::generator() * &master_secret_key);
    let encryption_public_key = TransportSecretKey::generate(&mut rng).public_key();
    let key_id = KeyId::from([123; 32]);

    let mut node_sks = MockSecretKeyStore::new();
    node_sks
        .expect_get()
        .times(1)
        .withf(move |key_id_| *key_id_ == key_id)
        .return_const(Some(CspSecretKey::MultiBls12_381(
            multi_types::SecretKeyBytes::from(&master_secret_key),
        )));

    let derivation_path = ExtendedDerivationPath {
        caller: canister_test_id(234).get(),
        derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
    };
    let derivation_id = b"some-derivation-id".to_vec();

    let vault = LocalCspVault::builder_for_test()
        .with_rng(rng)
        .with_mock_stores()
        .with_node_secret_key_store(node_sks)
        .build();

    let result = vault.create_encrypted_vetkd_key_share(
        key_id,
        master_public_key.serialize().to_vec(),
        encryption_public_key.serialize().to_vec(),
        derivation_path,
        derivation_id,
    );

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("wrong secret key type")
    );
}
