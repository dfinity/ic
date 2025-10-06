use criterion::measurement::Measurement;
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};

use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::DummySizedVaultResponse;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::NodeId;
use ic_types_test_utils::ids::NODE_1;

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::Duration;

const ONE_KB: usize = 1024;
const ONE_BYTE: usize = 1;
const THREE_KB: usize = 3 * ONE_KB;
const FIFTY_KB: usize = 50 * ONE_KB;

const DEFAULT_MULTIPLES: [usize; 4] = [1, 5, 10, 20];

criterion_main!(benches);
criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(8));
    targets = vault_call_pattern_comparison
}

fn vault_call_pattern_comparison(criterion: &mut Criterion) {
    let rng = &mut reproducible_rng();
    let (temp_crypto, _registry_data, _registry) = temp_crypto(NODE_1, rng);

    // Resolve production scenarios to a list of scenarios to benchmark
    let mut scenarios = Vec::new();
    for scenario in production_scenarios() {
        for multiple in DEFAULT_MULTIPLES {
            scenarios.push(Scenario {
                name: format!("{}x{}", scenario.name, multiple),
                request_bytes: scenario.request_bytes * multiple,
                response_bytes: scenario.response_bytes * multiple,
            });
        }
    }

    let group = &mut criterion.benchmark_group("vault_call_pattern_comparison".to_string());

    for scenario in scenarios {
        benchmark_signature_scenario(scenario, group, &temp_crypto, rng);
    }
}

fn benchmark_signature_scenario<M: Measurement, R: Rng + CryptoRng>(
    scenario: Scenario,
    group: &mut BenchmarkGroup<'_, M>,
    temp_crypto: &TempCryptoComponentGeneric<ChaCha20Rng>,
    rng: &mut R,
) {
    group.bench_function(&scenario.name, |bench| {
        bench.iter_batched_ref(
            || {
                let input = random_input_of_size(scenario.request_bytes, rng);
                (input, scenario.response_bytes)
            },
            |(input, response_bytes)| {
                let actual_response_bytes = temp_crypto
                    .dummy_vault_response(input.clone(), *response_bytes)
                    .len();
                assert_eq!(actual_response_bytes, *response_bytes);
            },
            BatchSize::SmallInput,
        )
    });
}

#[derive(Clone)]
struct Scenario {
    name: String,
    request_bytes: usize,
    response_bytes: usize,
}

fn production_scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    scenarios.push(Scenario {
        name: "idkg_create_dealing".to_string(),
        request_bytes: THREE_KB,
        response_bytes: THREE_KB,
    });
    scenarios.push(Scenario {
        name: "idkg_load_transcript".to_string(),
        request_bytes: FIFTY_KB,
        response_bytes: ONE_BYTE,
    });
    scenarios.push(Scenario {
        name: "idkg_verify_dealing_private".to_string(),
        request_bytes: THREE_KB,
        response_bytes: ONE_BYTE,
    });
    scenarios.push(Scenario {
        name: "idkg_retain_active_keys".to_string(),
        request_bytes: THREE_KB,
        response_bytes: ONE_BYTE,
    });
    scenarios.push(Scenario {
        name: "create_ecdsa_sig_share".to_string(),
        request_bytes: THREE_KB,
        response_bytes: 128 * ONE_BYTE,
    });
    scenarios
}

fn temp_crypto<R: Rng + CryptoRng>(
    node_id: NodeId,
    rng: &mut R,
) -> (
    TempCryptoComponentGeneric<ChaCha20Rng>,
    Arc<ProtoRegistryDataProvider>,
    Arc<FakeRegistryClient>,
) {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

    let crypto_component = TempCryptoComponent::builder()
        .with_remote_vault()
        .with_registry(Arc::clone(&registry) as Arc<_>)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::none())
        .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
        .build();

    (crypto_component, registry_data, registry)
}

fn random_input_of_size<R: Rng + CryptoRng>(bytes_size: usize, rng: &mut R) -> Vec<u8> {
    let mut buffer = vec![99; bytes_size];
    rng.fill_bytes(&mut buffer);
    buffer
}
