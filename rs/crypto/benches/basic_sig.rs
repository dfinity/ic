use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};

use ic_crypto::utils::{NodeKeysToGenerate, TempCryptoComponent};
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, BasicSigner, SignableMock, DOMAIN_IC_REQUEST,
};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::make_crypto_node_key;
use ic_test_utilities::types::ids::{NODE_1, NODE_2};
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, KeyPurpose, UserPublicKey};
use ic_types::messages::MessageId;
use ic_types::{NodeId, RegistryVersion};

use ed25519_dalek::Signer;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::sha::sha256;

use rand::prelude::*;
use rand_core::OsRng;
use std::sync::Arc;

const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(3);

fn crypto_basicsig_ed25519(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::Ed25519;

    let group = &mut criterion.benchmark_group(format!("crypto_basicsig/{:?}", algorithm_id));

    crypto_basicsig_verifybypubkey(group, algorithm_id);

    crypto_ed25519_basicsig_verify(group);

    crypto_ed25519_basicsig_sign(group);
}

fn crypto_basicsig_p256(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::EcdsaP256;

    let group = &mut criterion.benchmark_group(format!("crypto_basicsig/{:?}", algorithm_id));

    crypto_basicsig_verifybypubkey(group, algorithm_id);
}

fn crypto_basicsig_secp256k1(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::EcdsaSecp256k1;

    let group = &mut criterion.benchmark_group(format!("crypto_basicsig/{:?}", algorithm_id));

    crypto_basicsig_verifybypubkey(group, algorithm_id);
}

fn crypto_basicsig_rsasha256(criterion: &mut Criterion) {
    let algorithm_id = AlgorithmId::RsaSha256;

    let group = &mut criterion.benchmark_group(format!("crypto_basicsig/{:?}", algorithm_id));

    crypto_basicsig_verifybypubkey(group, algorithm_id);
}

fn crypto_ed25519_basicsig_verify<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    // NOTE: Only Ed25519 can use verify
    // (other basic-sig key types aren't held in the registry).
    let mut rng = thread_rng();
    let (temp_crypto, registry_data, registry) = temp_crypto(NODE_1);

    let request_id = MessageId::from(rng.gen::<[u8; 32]>());
    let (signature, public_key) =
        request_id_signature_from_random_keypair(&request_id, AlgorithmId::Ed25519);

    add_node_signing_pubkey_to_registry(NODE_2, &public_key.key, &registry, &registry_data);

    struct BenchData {
        signature: BasicSigOf<MessageId>,
        request_id: MessageId,
        temp_crypto: TempCryptoComponent,
    }
    let data = BenchData {
        signature,
        request_id,
        temp_crypto,
    };

    group.bench_with_input("verification", &data, |bench, data| {
        bench.iter(|| {
            assert!(data
                .temp_crypto
                .verify_basic_sig(&data.signature, &data.request_id, NODE_2, REGISTRY_VERSION,)
                .is_ok());
        })
    });
}

fn crypto_ed25519_basicsig_sign<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    // NOTE: Only Ed25519 can use sign
    // (other basic-sig key types aren't held in the secret key store).

    let mut rng = thread_rng();
    let (temp_crypto, _registry_data, _registry) = temp_crypto(NODE_1);

    let message = SignableMock::new(rng.gen::<[u8; 32]>().to_vec());

    struct BenchData {
        message: SignableMock,
        temp_crypto: TempCryptoComponent,
    }
    let data = BenchData {
        message,
        temp_crypto,
    };

    group.bench_with_input("sign", &data, |bench, data| {
        bench.iter(|| {
            assert!(data
                .temp_crypto
                .sign_basic(&data.message, NODE_1, REGISTRY_VERSION)
                .is_ok());
        })
    });
}

fn crypto_basicsig_verifybypubkey<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    algorithm_id: AlgorithmId,
) {
    let mut rng = thread_rng();
    let (temp_crypto, _registry_data, _registry) = temp_crypto(NODE_1);

    let request_id = MessageId::from(rng.gen::<[u8; 32]>());
    let (signature, public_key) =
        request_id_signature_from_random_keypair(&request_id, algorithm_id);

    struct BenchData {
        signature: BasicSigOf<MessageId>,
        request_id: MessageId,
        public_key: UserPublicKey,
        temp_crypto: TempCryptoComponent,
    }
    let data = BenchData {
        signature,
        request_id,
        public_key,
        temp_crypto,
    };

    group.bench_with_input("request_id_sig_verification", &data, |bench, data| {
        bench.iter(|| {
            assert!(
                data.temp_crypto
                    .verify_basic_sig_by_public_key(
                        &data.signature,
                        &data.request_id,
                        &data.public_key,
                    )
                    .is_ok()
            );
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

fn temp_crypto(
    node_id: NodeId,
) -> (
    TempCryptoComponent,
    Arc<ProtoRegistryDataProvider>,
    Arc<FakeRegistryClient>,
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

    let (crypto_component, node_pubkeys) = TempCryptoComponent::new_with_node_keys_generation(
        Arc::clone(&registry) as Arc<_>,
        node_id,
        NodeKeysToGenerate::only_node_signing_key(),
    );

    add_node_signing_pubkey_to_registry(
        node_id,
        &node_pubkeys.node_signing_pk.unwrap().key_value,
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

fn request_id_signature_from_random_keypair(
    request_id: &MessageId,
    algorithm_id: AlgorithmId,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    let bytes_to_sign = {
        let mut buf = vec![];
        buf.extend_from_slice(DOMAIN_IC_REQUEST);
        buf.extend_from_slice(request_id.as_bytes());
        buf
    };

    let mut rng = OsRng::default();

    let (signature_bytes, public_key_bytes) = match algorithm_id {
        AlgorithmId::Ed25519 => {
            let keypair = ed25519_dalek::Keypair::generate(&mut rng);
            let signature_bytes = keypair.sign(&bytes_to_sign).to_bytes().to_vec();
            let public_key_bytes = keypair.public.to_bytes().to_vec();
            (signature_bytes, public_key_bytes)
        }
        AlgorithmId::EcdsaP256 => generate_ecdsa_key_and_sig(Nid::X9_62_PRIME256V1, &bytes_to_sign),
        AlgorithmId::EcdsaSecp256k1 => generate_ecdsa_key_and_sig(Nid::SECP256K1, &bytes_to_sign),
        AlgorithmId::RsaSha256 => generate_rsa_key_and_sig(&mut rng, &bytes_to_sign),
        _ => panic!("Unexpected signature algorithm"),
    };

    let signature: BasicSigOf<MessageId> = BasicSigOf::new(BasicSig(signature_bytes));
    let public_key = UserPublicKey {
        key: public_key_bytes,
        algorithm_id,
    };

    (signature, public_key)
}

fn generate_ecdsa_key_and_sig(curve_name: Nid, bytes_to_sign: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(curve_name).expect("unable to create EC group");
    let ec_key = EcKey::generate(&group).expect("unable to generate EC key");
    let mut ctx = BigNumContext::new().expect("unable to create BigNumContext");

    let public_key_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .expect("unable to serialize EC public key");

    let signature = EcdsaSig::sign(&sha256(bytes_to_sign), &ec_key).expect("ECDSA signing failed");
    let r = signature.r().to_vec();
    let padding1 = vec![0; 32 - r.len()];
    let s = signature.s().to_vec();
    let padding2 = vec![0; 32 - s.len()];
    let signature_bytes = [padding1, r, padding2, s].concat();

    (signature_bytes, public_key_bytes)
}

fn generate_rsa_key_and_sig(rng: &mut OsRng, bytes_to_sign: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use ic_crypto_internal_basic_sig_rsa_pkcs1 as basic_sig_rsa;
    use ic_crypto_sha256::Sha256;
    use rsa::{Hash, PaddingScheme, PublicKeyParts, RSAPrivateKey};

    let bitlength = 2048; // minimum allowed

    let priv_key = RSAPrivateKey::new(rng, bitlength).expect("failed to generate RSA key");

    let pub_key_bytes = basic_sig_rsa::RsaPublicKey::from_components(
        &priv_key.to_public_key().e().to_bytes_be(),
        &priv_key.to_public_key().n().to_bytes_be(),
    )
    .expect("failed to convert RSA key to internal type for serialization")
    .as_der()
    .to_vec();

    let signature = priv_key
        .sign(
            PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            },
            &Sha256::hash(bytes_to_sign),
        )
        .expect("failed signing with RSA key");

    (signature, pub_key_bytes)
}
