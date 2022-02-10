#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::{CryptoRegistryKey, CryptoRegistryRecord};
use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;
use ic_crypto_internal_csp::secret_key_store::SecretKeyStore;
use ic_crypto_internal_csp::types::CspSecretKey;
use ic_crypto_internal_csp_test_utils::secret_key_store_test_utils::{
    MockSecretKeyStore, TempSecretKeyStore,
};
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::make_crypto_node_key;
use ic_test_utilities::registry::MockRegistryClient;
use ic_test_utilities::types::ids::{NODE_1, SUBNET_27};
use ic_types::crypto::{AlgorithmId, KeyId, KeyPurpose};
use ic_types::messages::MessageId;
use ic_types::registry::RegistryClientError;
use ic_types::RegistryVersion;
use openssl::sha::sha256;

pub const KEY_ID_1: [u8; 32] = [0u8; 32];
pub const KEY_ID_2: [u8; 32] = [1u8; 32];
// We don't use registry version 0 and 1 as they might be used as default
// versions.
pub const REG_V1: RegistryVersion = RegistryVersion::new(2);
pub const REG_V2: RegistryVersion = RegistryVersion::new(3);
pub const KEY_ID: [u8; 32] = KEY_ID_1;
pub const SUBNET_1: SubnetId = SUBNET_27;
pub const SUBNET_ID: SubnetId = SUBNET_1;

pub fn node_signing_record_with(
    node_id: NodeId,
    public_key: Vec<u8>,
    _key_id: KeyId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    CryptoRegistryRecord {
        key: CryptoRegistryKey {
            node_id,
            key_purpose: KeyPurpose::NodeSigning,
        },
        value: PublicKeyProto {
            algorithm: AlgorithmIdProto::Ed25519 as i32,
            key_value: public_key,
            version: 0,
            proof_data: None,
        },
        registry_version,
    }
}

pub fn committee_signing_record_with(
    node_id: NodeId,
    public_key: Vec<u8>,
    _key_id: KeyId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    CryptoRegistryRecord {
        key: CryptoRegistryKey {
            node_id,
            key_purpose: KeyPurpose::CommitteeSigning,
        },
        value: PublicKeyProto {
            algorithm: AlgorithmIdProto::MultiBls12381 as i32,
            key_value: public_key,
            version: 0,
            proof_data: None,
        },
        registry_version,
    }
}

pub fn dealing_encryption_pk_record_with(
    node_id: NodeId,
    key_value: Vec<u8>,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    CryptoRegistryRecord {
        key: CryptoRegistryKey {
            node_id,
            key_purpose: KeyPurpose::DkgDealingEncryption,
        },
        value: PublicKeyProto {
            algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
            key_value,
            version: 0,
            proof_data: None,
        },
        registry_version,
    }
}

pub fn mega_encryption_pk_record_with(
    node_id: NodeId,
    key_value: Vec<u8>,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    CryptoRegistryRecord {
        key: CryptoRegistryKey {
            node_id,
            key_purpose: KeyPurpose::IDkgMEGaEncryption,
        },
        value: PublicKeyProto {
            algorithm: AlgorithmIdProto::MegaSecp256k1 as i32,
            key_value,
            version: 0,
            proof_data: None,
        },
        registry_version,
    }
}

#[allow(dead_code)]
pub fn secret_key_store_with(key_id: KeyId, secret_key: CspSecretKey) -> impl SecretKeyStore {
    let mut temp_store = TempSecretKeyStore::new();
    let scope = None;
    temp_store.insert(key_id, secret_key, scope).unwrap();
    temp_store
}

pub fn to_new_registry_record(
    record: &CryptoRegistryRecord,
) -> (String, RegistryVersion, PublicKeyProto) {
    let key = make_crypto_node_key(record.key.node_id, record.key.key_purpose);
    let pk = PublicKeyProto {
        algorithm: record.value.algorithm as i32,
        key_value: record.value.key_value.clone(),
        version: 0,
        proof_data: None,
    };
    (key, record.registry_version, pk)
}

pub fn registry_with(key_record: CryptoRegistryRecord) -> Arc<dyn RegistryClient> {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let (key, version, value) = to_new_registry_record(&key_record);
    data_provider
        .add(&key, version, Some(value))
        .expect("Could not extend registry");
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
    // Need to poll the data provider at least once to update the cache.
    registry_client.update_to_latest_version();
    registry_client
}

pub fn registry_with_records(key_records: Vec<CryptoRegistryRecord>) -> Arc<dyn RegistryClient> {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());

    for key_record in key_records {
        let (key, version, value) = to_new_registry_record(&key_record);
        data_provider
            .add(&key, version, Some(value))
            .expect("Could not extend registry");
    }
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
    // Need to poll the data provider at least once to update the cache.
    registry_client.update_to_latest_version();
    registry_client
}

pub fn registry_returning_none() -> Arc<dyn RegistryClient> {
    let mut registry = MockRegistryClient::new();
    registry.expect_get_value().return_const(Ok(None));
    registry
        .expect_get_versioned_value()
        .returning(|key, version| {
            Ok(ic_interfaces::registry::RegistryVersionedRecord {
                key: key.to_string(),
                version,
                value: None,
            })
        });
    Arc::new(registry)
}

// TODO(DFN-1397): add exact error checks to the tests that
// expect a specific error.
#[allow(dead_code)]
pub fn registry_returning(error: RegistryClientError) -> Arc<dyn RegistryClient> {
    let mut registry = MockRegistryClient::new();
    registry
        .expect_get_value()
        .returning(move |_, _| Err(error.clone()));
    Arc::new(registry)
}

#[allow(dead_code)]
pub fn secret_key_store_returning_none() -> impl SecretKeyStore {
    let mut sks = MockSecretKeyStore::new();
    sks.expect_get().return_const(None);
    sks
}

pub fn secret_key_store_panicking_on_usage() -> impl SecretKeyStore {
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert().never();
    sks.expect_get().never();
    sks.expect_contains().never();
    sks.expect_remove().never();
    sks
}

#[test]
#[should_panic]
pub fn should_panic_when_panicking_secret_key_store_is_used() {
    let sks = secret_key_store_panicking_on_usage();
    let _ = sks.get(&KeyId::from(KEY_ID));
}

// Note: it is not necessary to explicitly set the expectation that the
// various methods of the trait are _never_ called with code like this
//    ```
//    let mut registry = MockRegistryClient::new();
//    registry.expect_get_value().never();
//    ```
// because this is the default behavior of mocks created with the mocking
// framework that we use (https://crates.io/crates/mockall)
pub fn registry_panicking_on_usage() -> Arc<dyn RegistryClient> {
    Arc::new(MockRegistryClient::new())
}

#[test]
#[should_panic]
fn should_panic_when_panicking_registry_is_used() {
    let registry = registry_panicking_on_usage();
    let key = make_crypto_node_key(NODE_1, KeyPurpose::QueryResponseSigning);
    let _ = registry.get_value(&key, REG_V1);
}

#[allow(dead_code)]
pub fn dummy_registry() -> Arc<dyn RegistryClient> {
    Arc::new(FakeRegistryClient::new(Arc::new(
        ProtoRegistryDataProvider::new(),
    )))
}

#[allow(dead_code)]
pub fn dummy_secret_key_store() -> impl SecretKeyStore {
    MockSecretKeyStore::new()
}

pub fn request_id_signature_and_public_key_with_domain_separator(
    domain_separator: &[u8],
    request_id: &MessageId,
    algorithm_id: AlgorithmId,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    use ed25519_dalek::Signer;
    let bytes_to_sign = {
        let mut buf = vec![];
        buf.extend_from_slice(domain_separator);
        buf.extend_from_slice(request_id.as_bytes());
        buf
    };
    let (pk_vec, signature_bytes_vec) = {
        match algorithm_id {
            AlgorithmId::EcdsaP256 => {
                let (sk, pk) = ecdsa_secp256r1::new_keypair().unwrap();
                let msg_hash = sha256(&bytes_to_sign);
                (
                    pk.0,
                    ecdsa_secp256r1::api::sign(&msg_hash, &sk)
                        .unwrap()
                        .0
                        .to_vec(),
                )
            }
            AlgorithmId::Ed25519 => {
                let ed25519_keypair = {
                    let mut rng = OsRng::default();
                    ed25519_dalek::Keypair::generate(&mut rng)
                };
                (
                    ed25519_keypair.public.to_bytes().to_vec(),
                    ed25519_keypair.sign(&bytes_to_sign).to_bytes().to_vec(),
                )
            }
            _ => panic!["unexpected algorithm id {:?}", algorithm_id],
        }
    };
    let signature: BasicSigOf<MessageId> = BasicSigOf::new(BasicSig(signature_bytes_vec));
    let public_key = UserPublicKey {
        key: pk_vec,
        algorithm_id,
    };
    (signature, public_key)
}

pub fn request_id_signature_and_public_key(
    request_id: &MessageId,
    algorithm_id: AlgorithmId,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    request_id_signature_and_public_key_with_domain_separator(
        DOMAIN_IC_REQUEST,
        request_id,
        algorithm_id,
    )
}
