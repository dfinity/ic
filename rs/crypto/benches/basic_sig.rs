use criterion::{criterion_group, criterion_main, Criterion};
use ic_crypto::utils::TempCryptoComponent;
use ic_interfaces::crypto::{BasicSigVerifierByPublicKey, DOMAIN_IC_REQUEST};
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, UserPublicKey};
use ic_types::messages::MessageId;
use rand::prelude::*;
use rand_core::OsRng;
use std::sync::Arc;

const NODE_ID: u64 = 42;

fn basic_sig(criterion: &mut Criterion) {
    let mut rng = thread_rng();
    let temp_crypto = crypto_component_with_state_in_temp_dir();

    let mut group = criterion.benchmark_group("crypto_basic_sig");
    group.bench_function("request_id_sig_verification", |bench| {
        struct BenchData {
            signature: BasicSigOf<MessageId>,
            request_id: MessageId,
            public_key: UserPublicKey,
        };

        bench.iter_with_setup(
            || {
                let request_id = MessageId::from(rng.gen::<[u8; 32]>());
                let (signature, public_key) = request_id_signature_from_random_keypair(&request_id);
                BenchData {
                    signature,
                    request_id,
                    public_key,
                }
            },
            |data| {
                assert!(temp_crypto
                    .verify_basic_sig_by_public_key(
                        &data.signature,
                        &data.request_id,
                        &data.public_key
                    )
                    .is_ok());
            },
        )
    });
}

fn criterion_only_once() -> Criterion {
    Criterion::default().sample_size(20)
}

criterion_group! {
    name = benches;
    config = criterion_only_once();
    targets = basic_sig
}

criterion_main!(benches);

fn crypto_component_with_state_in_temp_dir() -> TempCryptoComponent {
    let registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    // The node id is currently irrelevant for these tests, so we set it to a
    // constant for now.
    TempCryptoComponent::new(Arc::new(registry), node_test_id(NODE_ID))
}

fn request_id_signature_from_random_keypair(
    request_id: &MessageId,
) -> (BasicSigOf<MessageId>, UserPublicKey) {
    use ed25519_dalek::Signer;
    let ed25519_keypair = {
        let mut rng = OsRng::default();
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    let signature: BasicSigOf<MessageId> = {
        let bytes_to_sign = {
            let mut buf = vec![];
            buf.extend_from_slice(DOMAIN_IC_REQUEST);
            buf.extend_from_slice(request_id.as_bytes());
            buf
        };
        let signature_bytes = ed25519_keypair.sign(&bytes_to_sign).to_bytes();
        BasicSigOf::new(BasicSig(signature_bytes.to_vec()))
    };
    let public_key = UserPublicKey {
        key: ed25519_keypair.public.to_bytes().to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };
    (signature, public_key)
}
