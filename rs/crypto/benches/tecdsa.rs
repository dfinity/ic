use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_csp::Csp;
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils_canister_threshold_sigs::node::Node;
use ic_crypto_test_utils_canister_threshold_sigs::{
    generate_key_transcript, generate_tecdsa_protocol_inputs,
    random_crypto_component_not_in_receivers, sig_share_from_each_receiver,
    CanisterThresholdSigTestEnvironment,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::{ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
    ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::BTreeMap;

criterion_main!(benches);
criterion_group!(benches, crypto_tecdsa_benchmarks);

fn crypto_tecdsa_benchmarks(criterion: &mut Criterion) {
    let test_cases = vec![
        TestCase {
            num_of_nodes: 1,
            ..TestCase::default()
        },
        TestCase {
            num_of_nodes: 4,
            ..TestCase::default()
        },
        TestCase {
            num_of_nodes: 13,
            ..TestCase::default()
        },
        TestCase {
            num_of_nodes: 28,
            ..TestCase::default()
        },
        TestCase {
            num_of_nodes: 40,
            ..TestCase::default()
        },
    ];

    let mut rng = ReproducibleRng::new();
    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name());
        group
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        bench_sign_share(group, &test_case, &mut rng);
        bench_verify_sig_share(group, &test_case, &mut rng);
        bench_combine_sig_shares(group, &test_case, &mut rng);
        bench_verify_combined_sig(group, &test_case, &mut rng);
    }
}

fn bench_sign_share<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, rng);
    let signer = env.nodes.random_receiver(&key_transcript.receivers, rng);

    group.bench_function("sign_share", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    rng,
                );
                signer.load_input_transcripts(&inputs);
                inputs
            },
            |inputs| sign_share(signer, inputs),
            SmallInput,
        )
    });
}

fn sign_share(signer: &Node, inputs: &ThresholdEcdsaSigInputs) -> ThresholdEcdsaSigShare {
    signer.sign_share(inputs).unwrap_or_else(|error| {
        panic!(
            "failed to generate threshold ECDSA signature share for signer {:?} with inputs {:?}: {:?}",
            signer.id(),
            inputs,
            error
        )
    })
}

fn bench_verify_sig_share<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, rng);

    group.bench_function("verify_sig_share", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    rng,
                );
                let signer = env.nodes.random_receiver(&key_transcript.receivers, rng);
                signer.load_input_transcripts(&inputs);
                let sig_share = sign_share(signer, &inputs);
                let verifier = env.nodes.random_receiver(&key_transcript.receivers, rng);
                (verifier, signer.id(), inputs, sig_share)
            },
            |(verifier, signer_id, inputs, sig_share)| {
                verify_sig_share(verifier, *signer_id, inputs, sig_share)
            },
            SmallInput,
        )
    });
}

fn verify_sig_share(
    verifier: &Node,
    signer: NodeId,
    inputs: &ThresholdEcdsaSigInputs,
    share: &ThresholdEcdsaSigShare,
) {
    verifier.verify_sig_share(signer, inputs, share).unwrap_or_else(|error| {
        panic!(
            "Verifier {:?} failed to verify threshold ECDSA signature share {:?} from signer {:?} for inputs {:?}: {:?}",
            verifier.id(),
            share,
            signer,
            inputs,
            error
        )
    })
}

fn bench_combine_sig_shares<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function("combine_sig_shares", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    rng,
                );
                let sig_shares = sig_share_from_each_receiver(&env, &inputs);
                (inputs, sig_shares)
            },
            |(inputs, sig_shares)| combine_sig_shares(&combiner, inputs, sig_shares),
            SmallInput,
        )
    });
}

fn combine_sig_shares<R: Rng + CryptoRng + Sync + Send + 'static>(
    combiner: &TempCryptoComponentGeneric<Csp, R>,
    inputs: &ThresholdEcdsaSigInputs,
    shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
) -> ThresholdEcdsaCombinedSignature {
    combiner.combine_sig_shares(inputs, shares).unwrap_or_else(|error| {
        panic!(
            "Combiner {:?} failed to combine threshold ECDSA signature shares {:?} for inputs {:?}: {:?}",
            combiner.get_node_id(),
            shares,
            inputs,
            error
        )
    })
}

fn bench_verify_combined_sig<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);
    let verifier = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function("verify_combined_sig", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    rng,
                );
                let sig_shares = sig_share_from_each_receiver(&env, &inputs);
                let signature = combine_sig_shares(&combiner, &inputs, &sig_shares);
                (inputs, signature)
            },
            |(inputs, signature)| verify_combined_sig(&verifier, inputs, signature),
            SmallInput,
        )
    });
}

fn verify_combined_sig<R: Rng + CryptoRng + Sync + Send + 'static>(
    verifier: &TempCryptoComponentGeneric<Csp, R>,
    inputs: &ThresholdEcdsaSigInputs,
    signature: &ThresholdEcdsaCombinedSignature,
) {
    verifier
        .verify_combined_sig(inputs, signature)
        .unwrap_or_else(|error| {
            panic!(
            "Verifier {:?} failed to verify threshold ECDSA signature {:?} for inputs {:?}: {:?}",
            verifier.get_node_id(),
            signature,
            inputs,
            error
        )
        })
}

fn random_sig_inputs<R: Rng>(rng: &mut R) -> (ExtendedDerivationPath, Vec<u8>, Randomness) {
    let derivation_path = ExtendedDerivationPath {
        caller: PrincipalId::new_user_test_id(1),
        derivation_path: vec![],
    };
    let hashed_message = rng.gen::<[u8; 32]>();
    let seed = Randomness::from(rng.gen::<[u8; 32]>());
    (derivation_path, hashed_message.to_vec(), seed)
}

struct TestCase {
    sample_size: usize,
    sampling_mode: SamplingMode,
    num_of_nodes: usize,
}

impl Default for TestCase {
    fn default() -> Self {
        TestCase {
            sample_size: 100,
            sampling_mode: SamplingMode::Auto,
            num_of_nodes: 0,
        }
    }
}

impl TestCase {
    fn new_test_environment<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> CanisterThresholdSigTestEnvironment {
        CanisterThresholdSigTestEnvironment::new(self.num_of_nodes, rng)
    }

    fn name(&self) -> String {
        format!("crypto_tecdsa_{}_nodes", self.num_of_nodes,)
    }
}
