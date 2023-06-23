use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_csp::Csp;
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_canister_threshold_sigs::{
    generate_key_transcript, generate_tecdsa_protocol_inputs, load_input_transcripts,
    random_crypto_component_not_in_receivers, random_receiver_for_inputs,
    sig_share_from_each_receiver, CanisterThresholdSigTestEnvironment,
};
use ic_interfaces::crypto::{ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
    ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use rand::prelude::IteratorRandom;
use rand::{thread_rng, CryptoRng, Rng};
use std::collections::BTreeMap;

criterion_main!(benches);
criterion_group!(benches, crypto_tecdsa_benchmarks);

fn crypto_tecdsa_benchmarks(criterion: &mut Criterion) {
    let test_cases = vec![
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

    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name());
        group
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        bench_sign_share(group, &test_case);
        bench_verify_sig_share(group, &test_case);
        bench_combine_sig_shares(group, &test_case);
        bench_verify_combined_sig(group, &test_case);
    }
}

fn bench_sign_share<M: Measurement>(group: &mut BenchmarkGroup<'_, M>, test_case: &TestCase) {
    let mut rng = thread_rng();
    let env = test_case.new_test_environment(&mut rng);
    let key_transcript =
        generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &mut rng);
    let (_signer_index, signer_id) = key_transcript
        .receivers
        .iter()
        .choose(&mut rng)
        .expect("receivers in key transcript cannot be empty");
    let signer = crypto_for(signer_id, &env.crypto_components);

    group.bench_function("sign_share", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(&mut rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
                );
                load_input_transcripts(&env.crypto_components, signer_id, &inputs);
                inputs
            },
            |inputs| sign_share(signer, inputs),
            SmallInput,
        )
    });
}

fn sign_share<R: Rng + CryptoRng + Sync + Send + 'static>(
    signer: &TempCryptoComponentGeneric<Csp, R>,
    inputs: &ThresholdEcdsaSigInputs,
) -> ThresholdEcdsaSigShare {
    signer.sign_share(inputs).unwrap_or_else(|error| {
        panic!(
            "failed to generate threshold ECDSA signature share for signer {:?} with inputs {:?}: {:?}",
            signer.get_node_id(),
            inputs,
            error
        )
    })
}

fn bench_verify_sig_share<M: Measurement>(group: &mut BenchmarkGroup<'_, M>, test_case: &TestCase) {
    let mut rng = thread_rng();
    let env = test_case.new_test_environment(&mut rng);
    let key_transcript =
        generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &mut rng);

    group.bench_function("verify_sig_share", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(&mut rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
                );
                let signer_id = random_receiver_for_inputs(&inputs, &mut rng);
                let signer = crypto_for(signer_id, &env.crypto_components);
                load_input_transcripts(&env.crypto_components, signer_id, &inputs);
                let sig_share = sign_share(signer, &inputs);
                let verifier = crypto_for(
                    random_receiver_for_inputs(&inputs, &mut rng),
                    &env.crypto_components,
                );
                (verifier, signer_id, inputs, sig_share)
            },
            |(verifier, signer_id, inputs, sig_share)| {
                verify_sig_share(verifier, *signer_id, inputs, sig_share)
            },
            SmallInput,
        )
    });
}

fn verify_sig_share<R: Rng + CryptoRng + Sync + Send + 'static>(
    verifier: &TempCryptoComponentGeneric<Csp, R>,
    signer: NodeId,
    inputs: &ThresholdEcdsaSigInputs,
    share: &ThresholdEcdsaSigShare,
) {
    verifier.verify_sig_share(signer, inputs, share).unwrap_or_else(|error| {
        panic!(
            "Verifier {:?} failed to verify threshold ECDSA signature share {:?} from signer {:?} for inputs {:?}: {:?}",
            verifier.get_node_id(),
            share,
            signer,
            inputs,
            error
        )
    })
}

fn bench_combine_sig_shares<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let mut rng = thread_rng();
    let env = test_case.new_test_environment(&mut rng);
    let key_transcript =
        generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &mut rng);
    let combiner =
        random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, &mut rng);

    group.bench_function("combine_sig_shares", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(&mut rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
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

fn bench_verify_combined_sig<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let mut rng = thread_rng();
    let env = test_case.new_test_environment(&mut rng);
    let key_transcript =
        generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &mut rng);
    let combiner =
        random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, &mut rng);
    let verifier =
        random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, &mut rng);

    group.bench_function("verify_combined_sig", |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(&mut rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
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
