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
    let rng = &mut reproducible_rng();

    let result = create_encrypted_vetkd_key_share(rng);

    assert_matches!(result, Ok(_));
}

#[test]
fn should_correctly_create_encrypted_vetkd_key_share_for_smoke_test_vector() {
    let rng = &mut ChaCha20Rng::seed_from_u64(123);

    let result = create_encrypted_vetkd_key_share(rng);

    assert_eq!(
        result,
        Ok(VetKdEncryptedKeyShareContent(
            hex::decode(
                "a8d7c58088640a9639267c5843824ee31f6ed8c6a90ea31e05a12459ea2498\
                f3e68e13f62604d027660883213c90ea72810bcecee58b883fb62118e538243\
                03718e6876ea400d083beb0439d3934122a4c4b2e58e3f145305b9a0c0a00e3\
                2dd808574dec2605dbc7f122fe593ca0c07ca92720d0f17b7d53c9c68dbb93d\
                489078859e5e5fe2b6612ac9536fe7f8b463cac948e6db97908b7f5a67b33b3\
                e60a1c160889ef49448519a84be1aba0611829a7cca180cbbdf94f7b2cda2db\
                6b14c65",
            )
            .expect("invalid test vector")
        ))
    );
}

fn create_encrypted_vetkd_key_share<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError> {
    let test_env = CreateVetKdKeyShareTestSetup::new(rng);

    test_env.create_encrypted_vetkd_key_share()
}

#[test]
fn should_fail_to_create_key_share_with_invalid_master_public_key() {
    let rng = &mut reproducible_rng();

    let mut test_env = CreateVetKdKeyShareTestSetup::new(rng);
    test_env.master_public_key = b"invalid-master-public-key".to_vec();
    test_env.secret_key_store_override = Some(MockSecretKeyStore::new());

    let result = test_env.create_encrypted_vetkd_key_share();

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("invalid master public key")
    );
}

#[test]
fn should_fail_to_create_key_share_with_invalid_encryption_public_key() {
    let rng = &mut reproducible_rng();

    let mut test_env = CreateVetKdKeyShareTestSetup::new(rng);
    test_env.transport_public_key = b"invalid-encryption-public-key".to_vec();
    test_env.secret_key_store_override = Some(MockSecretKeyStore::new());

    let result = test_env.create_encrypted_vetkd_key_share();

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("invalid encryption public key")
    );
}

#[test]
fn should_fail_to_create_key_share_if_key_is_missing_in_secret_key_store() {
    let mut rng = reproducible_rng();
    let mut test_env = CreateVetKdKeyShareTestSetup::new(&mut rng);

    test_env.secret_key_store_return_override = Some(None);

    let result = test_env.create_encrypted_vetkd_key_share();

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("missing key with ID")
    );
}

#[test]
fn should_fail_to_create_key_share_if_key_in_secret_key_store_has_wrong_type() {
    let mut rng = reproducible_rng();
    let mut test_env = CreateVetKdKeyShareTestSetup::new(&mut rng);

    test_env.secret_key_store_return_override = Some(Some(CspSecretKey::MultiBls12_381(
        multi_types::SecretKeyBytes::from(&test_env.master_secret_key),
    )));

    let result = test_env.create_encrypted_vetkd_key_share();

    assert_matches!(
        result, Err(VetKdEncryptedKeyShareCreationVaultError::InvalidArgument(error))
        if error.contains("wrong secret key type")
    );
}

struct CreateVetKdKeyShareTestSetup {
    key_id: KeyId,
    master_public_key: Vec<u8>,
    transport_public_key: Vec<u8>,
    derivation_path: ExtendedDerivationPath,
    derivation_id: Vec<u8>,
    master_secret_key: Scalar,
    rng: ChaCha20Rng,
    secret_key_store_override: Option<MockSecretKeyStore>,
    secret_key_store_return_override: Option<Option<CspSecretKey>>,
}

impl CreateVetKdKeyShareTestSetup {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let master_secret_key = Scalar::random(rng);
        let master_public_key = G2Affine::from(G2Affine::generator() * &master_secret_key);
        let transport_secret_key = TransportSecretKey::generate(rng);
        let key_id = KeyId::from([123; 32]);
        let derivation_path = ExtendedDerivationPath {
            caller: canister_test_id(234).get(),
            derivation_path: vec![b"some".to_vec(), b"derivation".to_vec(), b"path".to_vec()],
        };
        let derivation_id = b"some-derivation-id".to_vec();
        let rng = ChaCha20Rng::from_seed(rng.gen());

        Self {
            master_secret_key,
            master_public_key: master_public_key.serialize().to_vec(),
            transport_public_key: transport_secret_key.public_key().serialize().to_vec(),
            key_id,
            derivation_path,
            derivation_id,
            rng,
            secret_key_store_override: None,
            secret_key_store_return_override: None,
        }
    }

    pub fn create_encrypted_vetkd_key_share(
        self,
    ) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError> {
        let node_sks = if let Some(node_sks_override) = self.secret_key_store_override {
            node_sks_override
        } else {
            let return_value = if let Some(opt_sk) = self.secret_key_store_return_override {
                opt_sk
            } else {
                Some(CspSecretKey::ThresBls12_381(
                    threshold_types::SecretKeyBytes::from(&self.master_secret_key),
                ))
            };
            let mut node_sks = MockSecretKeyStore::new();
            node_sks
                .expect_get()
                .times(1)
                .withf({
                    let self_key_id = self.key_id;
                    move |key_id_| key_id_ == &self_key_id
                })
                .return_const(return_value);
            node_sks
        };

        let vault = LocalCspVault::builder_for_test()
            .with_rng(self.rng)
            .with_mock_stores()
            .with_node_secret_key_store(node_sks)
            .build();

        vault.create_encrypted_vetkd_key_share(
            self.key_id,
            self.master_public_key.clone(),
            self.transport_public_key.clone(),
            self.derivation_path.clone(),
            self.derivation_id.clone(),
        )
    }
}
