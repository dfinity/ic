use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};

use ic_crypto_interfaces_sig_verification::BasicSigVerifierByPublicKey;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::{BasicSigVerifier, BasicSigner, KeyManager};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::{
    AlgorithmId, BasicSig, BasicSigOf, KeyPurpose, SignableMock, UserPublicKey, DOMAIN_IC_REQUEST,
};
use ic_types::messages::MessageId;
use ic_types::{NodeId, RegistryVersion};
use ic_types_test_utils::ids::{NODE_1, NODE_2};

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use strum::IntoEnumIterator;

const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(3);

#[derive(strum_macros::EnumIter, PartialEq, Copy, Clone, Default)]
enum VaultType {
    Local,
    #[default]
    Remote,
}

impl std::fmt::Debug for VaultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultType::Remote => write!(f, "remote_vault"),
            VaultType::Local => write!(f, "local_vault"),
        }
    }
}

fn crypto_basicsig_ed25519(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::Ed25519;

    for vault_type in VaultType::iter() {
        let group = &mut criterion
            .benchmark_group(format!("crypto_basicsig_{vault_type:?}/{:?}", algorithm_id));

        let rng = &mut reproducible_rng();

        if vault_type == VaultType::default() {
            crypto_basicsig_verifybypubkey(group, algorithm_id, rng, vault_type);
            crypto_ed25519_basicsig_verify(group, rng, vault_type);
        }

        crypto_ed25519_basicsig_sign(group, rng, vault_type);
    }
}

fn crypto_basicsig_p256(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::EcdsaP256;

    let vault_type = VaultType::default();
    let group = &mut criterion
        .benchmark_group(format!("crypto_basicsig_{vault_type:?}/{:?}", algorithm_id));

    let rng = &mut reproducible_rng();

    crypto_basicsig_verifybypubkey(group, algorithm_id, rng, vault_type);
}

fn crypto_basicsig_secp256k1(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::EcdsaSecp256k1;

    let vault_type = VaultType::default();
    let group = &mut criterion
        .benchmark_group(format!("crypto_basicsig_{vault_type:?}/{:?}", algorithm_id));

    let rng = &mut reproducible_rng();

    crypto_basicsig_verifybypubkey(group, algorithm_id, rng, vault_type);
}

fn crypto_basicsig_rsasha256(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::RsaSha256;

    let vault_type = VaultType::default();
    let group = &mut criterion
        .benchmark_group(format!("crypto_basicsig_{vault_type:?}/{:?}", algorithm_id));

    let rng = &mut reproducible_rng();

    crypto_basicsig_verifybypubkey(group, algorithm_id, rng, vault_type);
}

fn crypto_ed25519_basicsig_verify<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    rng: &mut R,
    vault_type: VaultType,
) {
    // NOTE: Only Ed25519 can use verify
    // (other basic-sig key types aren't held in the registry).
    let (temp_crypto, registry_data, registry) = temp_crypto(NODE_1, rng, vault_type);

    let request_id = MessageId::from(rng.gen::<[u8; 32]>());
    let (signature, public_key) =
        request_id_signature_from_random_keypair(&request_id, AlgorithmId::Ed25519, rng);

    add_node_signing_pubkey_to_registry(NODE_2, &public_key.key, &registry, &registry_data);

    group.bench_function("verification", |bench| {
        bench.iter(|| {
            assert!(temp_crypto
                .verify_basic_sig(&signature, &request_id, NODE_2, REGISTRY_VERSION,)
                .is_ok());
        })
    });
}

fn crypto_ed25519_basicsig_sign<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    rng: &mut R,
    vault_type: VaultType,
) {
    // NOTE: Only Ed25519 can use sign
    // (other basic-sig key types aren't held in the secret key store).

    let (temp_crypto, _registry_data, _registry) = temp_crypto(NODE_1, rng, vault_type);

    let message = SignableMock::new(rng.gen::<[u8; 32]>().to_vec());

    group.bench_function("sign", |bench| {
        bench.iter(|| {
            assert!(temp_crypto
                .sign_basic(&message, NODE_1, REGISTRY_VERSION)
                .is_ok());
        })
    });
}

fn crypto_basicsig_verifybypubkey<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    algorithm_id: AlgorithmId,
    rng: &mut R,
    vault_type: VaultType,
) {
    let (temp_crypto, _registry_data, _registry) = temp_crypto(NODE_1, rng, vault_type);

    let request_id = MessageId::from(rng.gen::<[u8; 32]>());
    let (signature, public_key) =
        request_id_signature_from_random_keypair(&request_id, algorithm_id, rng);

    group.bench_function("request_id_sig_verification", |bench| {
        bench.iter(|| {
            assert!(temp_crypto
                .verify_basic_sig_by_public_key(&signature, &request_id, &public_key,)
                .is_ok());
        })
    });
}

fn criterion_only_once() -> Criterion {
    Criterion::default().sample_size(20)
}

criterion_group! {
    name = benches;
    config = criterion_only_once();
    targets = crypto_basicsig_ed25519, crypto_basicsig_p256, crypto_basicsig_secp256k1, crypto_basicsig_rsasha256
}

criterion_main!(benches);

fn temp_crypto<R: Rng + CryptoRng>(
    node_id: NodeId,
    rng: &mut R,
    vault_type: VaultType,
) -> (
    TempCryptoComponentGeneric<ChaCha20Rng>,
    Arc<ProtoRegistryDataProvider>,
    Arc<FakeRegistryClient>,
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

    let mut crypto_builder = TempCryptoComponent::builder()
        .with_registry(Arc::clone(&registry) as Arc<_>)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(ChaCha20Rng::from_seed(rng.gen()));
    if vault_type == VaultType::Remote {
        crypto_builder = crypto_builder.with_remote_vault();
    }
    let crypto_component = crypto_builder.build();
    let node_pubkeys = crypto_component.current_node_public_keys().unwrap();

    add_node_signing_pubkey_to_registry(
        node_id,
        &node_pubkeys.node_signing_public_key.unwrap().key_value,
        &registry,
        &registry_data,
    );
    (crypto_component, registry_data, registry)
}

fn add_node_signing_pubkey_to_registry(
    node_id: NodeId,
    public_key_bytes: &[u8],
    registry: &Arc<FakeRegistryClient>,
    registry_data: &Arc<ProtoRegistryDataProvider>,
) {
    let pk = PublicKeyProto {
        algorithm: AlgorithmIdProto::Ed25519 as i32, // Nb. Only Ed25519 in registry
        key_value: public_key_bytes.to_vec(),
        version: 0,
        proof_data: None,
        timestamp: None,
    };

    registry_data
        .add(
            &make_crypto_node_key(node_id, KeyPurpose::NodeSigning),
            REGISTRY_VERSION,
            Some(pk),
        )
        .expect("Could not extend registry");

    // Need to poll the data provider at least once to update the cache.
    registry.reload();
}

fn request_id_signature_from_random_keypair<R: Rng + CryptoRng>(
    request_id: &MessageId,
    algorithm_id: AlgorithmId,
    rng: &mut R,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let bytes_to_sign = {
        let mut buf = vec![];
        buf.extend_from_slice(DOMAIN_IC_REQUEST);
        buf.extend_from_slice(request_id.as_bytes());
        buf
    };

    let (signature_bytes, public_key_bytes) = match algorithm_id {
        AlgorithmId::Ed25519 => {
            let signing_key = ed25519_consensus::SigningKey::new(rng);
            let signature_bytes = signing_key.sign(&bytes_to_sign).to_bytes().to_vec();
            let public_key_bytes = signing_key.verification_key().to_bytes().to_vec();
            (signature_bytes, public_key_bytes)
        }
        AlgorithmId::EcdsaP256 => ecdsa_secp256r1_signature_and_public_key(&bytes_to_sign, rng),
        AlgorithmId::EcdsaSecp256k1 => {
            ecdsa_secp256k1_signature_and_public_key(&bytes_to_sign, rng)
        }
        AlgorithmId::RsaSha256 => generate_rsa_key_and_sig(rng, &bytes_to_sign),
        _ => panic!("Unexpected signature algorithm"),
    };

    let signature: BasicSigOf<MessageId> = BasicSigOf::new(BasicSig(signature_bytes));
    let public_key = UserPublicKey {
        key: public_key_bytes,
        algorithm_id,
    };

    (signature, public_key)
}

fn ecdsa_secp256r1_signature_and_public_key<R: Rng + CryptoRng>(
    bytes_to_sign: &[u8],
    rng: &mut R,
) -> (Vec<u8>, Vec<u8>) {
    let sk = ic_crypto_ecdsa_secp256r1::PrivateKey::generate_using_rng(rng);
    let signature = sk.sign_message(bytes_to_sign).to_vec();
    let public_key = sk.public_key().serialize_sec1(false);
    (signature, public_key)
}

fn ecdsa_secp256k1_signature_and_public_key<R: Rng + CryptoRng>(
    bytes_to_sign: &[u8],
    rng: &mut R,
) -> (Vec<u8>, Vec<u8>) {
    let sk = ic_crypto_ecdsa_secp256k1::PrivateKey::generate_using_rng(rng);
    let signature = sk.sign_message(bytes_to_sign).to_vec();
    let public_key = sk.public_key().serialize_sec1(false);
    (signature, public_key)
}

fn generate_rsa_key_and_sig<R: Rng + CryptoRng>(
    rng: &mut R,
    bytes_to_sign: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use ic_crypto_internal_basic_sig_rsa_pkcs1 as basic_sig_rsa;
    use ic_crypto_sha2::Sha256;
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};

    let bitlength = 2048; // minimum allowed

    let priv_key = RsaPrivateKey::new(rng, bitlength).expect("failed to generate RSA key");

    let pub_key_bytes = basic_sig_rsa::RsaPublicKey::from_components(
        &priv_key.to_public_key().e().to_bytes_be(),
        &priv_key.to_public_key().n().to_bytes_be(),
    )
    .expect("failed to convert RSA key to internal type for serialization")
    .as_der()
    .to_vec();

    let signature = priv_key
        .sign(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            &Sha256::hash(bytes_to_sign),
        )
        .expect("failed signing with RSA key");

    (signature, pub_key_bytes)
}
