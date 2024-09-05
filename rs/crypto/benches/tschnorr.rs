use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_base_types::PrincipalId;
use ic_crypto_test_utils_canister_threshold_sigs::{
    generate_key_transcript, generate_tschnorr_protocol_inputs,
    random_crypto_component_not_in_receivers, schnorr_sig_share_from_each_receiver,
    CanisterThresholdSigTestEnvironment, IDkgParticipants,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::{ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use rand::{CryptoRng, Rng, RngCore};
use strum::IntoEnumIterator;

criterion_main!(benches);
criterion_group!(benches, crypto_tschnorr_benchmarks);

fn crypto_tschnorr_benchmarks(criterion: &mut Criterion) {
    let number_of_nodes = [1, 4, 13, 28, 40];

    let test_cases = generate_test_cases(&number_of_nodes);

    let rng = &mut ReproducibleRng::new();
    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name());
        group
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        for vault_type in VaultType::iter() {
            bench_create_sig_share(group, &test_case, vault_type, rng);
        }
        bench_verify_sig_share(group, &test_case, VaultType::default(), rng);
        bench_combine_sig_shares(group, &test_case, VaultType::default(), rng);
        bench_verify_combined_sig(group, &test_case, VaultType::default(), rng);
    }
}

fn bench_create_sig_share<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg, rng);
    let signer = env
        .nodes
        .random_filtered_by_receivers(&key_transcript.receivers, rng);

    group.bench_function(format!("create_sig_share_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, message, seed) = random_sig_inputs(rng);
                let inputs = generate_tschnorr_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message,
                    seed,
                    &derivation_path,
                    test_case.alg,
                    rng,
                );
                signer.load_tschnorr_sig_transcripts(&inputs);
                inputs
            },
            |inputs| {
                signer
                    .create_sig_share(inputs)
                    .expect("failed to create signature share")
            },
            SmallInput,
        )
    });
}

fn bench_verify_sig_share<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg, rng);

    group.bench_function(format!("verify_sig_share_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, message, seed) = random_sig_inputs(rng);
                let inputs = generate_tschnorr_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message,
                    seed,
                    &derivation_path,
                    test_case.alg,
                    rng,
                );
                let signer = env
                    .nodes
                    .random_filtered_by_receivers(&key_transcript.receivers, rng);
                signer.load_tschnorr_sig_transcripts(&inputs);
                let sig_share = signer
                    .create_sig_share(&inputs)
                    .expect("failed to create signature share");
                let verifier = env
                    .nodes
                    .random_filtered_by_receivers(&key_transcript.receivers, rng);
                (verifier, signer.id(), inputs, sig_share)
            },
            |(verifier, signer_id, inputs, sig_share)| {
                let signer = *signer_id;
                verifier
                    .verify_sig_share(signer, inputs, sig_share)
                    .expect("failed to verify signature share")
            },
            SmallInput,
        )
    });
}

fn bench_combine_sig_shares<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg, rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function(format!("combine_sig_shares_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, message, seed) = random_sig_inputs(rng);
                let inputs = generate_tschnorr_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message,
                    seed,
                    &derivation_path,
                    test_case.alg,
                    rng,
                );
                let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs);
                (inputs, sig_shares)
            },
            |(inputs, sig_shares)| {
                combiner
                    .combine_sig_shares(inputs, sig_shares)
                    .expect("failed to combine signature shares")
            },
            SmallInput,
        )
    });
}

fn bench_verify_combined_sig<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg, rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);
    let verifier = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function(format!("verify_combined_sig_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, message, seed) = random_sig_inputs(rng);
                let inputs = generate_tschnorr_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &message,
                    seed,
                    &derivation_path,
                    test_case.alg,
                    rng,
                );
                let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs);
                let signature = combiner
                    .combine_sig_shares(&inputs, &sig_shares)
                    .expect("failed to combine signature shares");
                (inputs, signature)
            },
            |(inputs, signature)| {
                verifier
                    .verify_combined_sig(inputs, signature)
                    .expect("failed to verify combined signature")
            },
            SmallInput,
        )
    });
}

fn random_sig_inputs<R: Rng>(rng: &mut R) -> (ExtendedDerivationPath, Vec<u8>, Randomness) {
    let derivation_path = ExtendedDerivationPath {
        caller: PrincipalId::new_user_test_id(1),
        derivation_path: vec![],
    };
    let message = rng.gen::<[u8; 32]>();
    let seed = Randomness::from(rng.gen::<[u8; 32]>());
    (derivation_path, message.to_vec(), seed)
}

struct TestCase {
    sample_size: usize,
    sampling_mode: SamplingMode,
    num_of_nodes: usize,
    alg: AlgorithmId,
}

impl TestCase {
    fn new_test_environment<R: Rng + CryptoRng>(
        &self,
        vault_type: VaultType,
        rng: &mut R,
    ) -> CanisterThresholdSigTestEnvironment {
        match vault_type {
            VaultType::Local => CanisterThresholdSigTestEnvironment::new(self.num_of_nodes, rng),
            VaultType::Remote => {
                CanisterThresholdSigTestEnvironment::new_with_remote_vault(self.num_of_nodes, rng)
            }
        }
    }

    fn name(&self) -> String {
        let alg = match self.alg {
            AlgorithmId::ThresholdSchnorrBip340 => "bip340",
            AlgorithmId::ThresholdEd25519 => "ed25519",
            unexpected => panic!("Unexpected testcase algorithm {}", unexpected),
        };
        format!("crypto_tschnorr_{alg}_{}_nodes", self.num_of_nodes)
    }
}

fn generate_test_cases(node_counts: &[usize]) -> Vec<TestCase> {
    let mut test_cases = vec![];

    let tschnorr_algs = AlgorithmId::all_threshold_schnorr_algorithms();

    for num_of_nodes in node_counts.iter().copied() {
        let sample_size = if num_of_nodes < 10 { 100 } else { 10 };

        for alg in tschnorr_algs {
            let tc = TestCase {
                num_of_nodes,
                sample_size,
                alg,
                sampling_mode: SamplingMode::Auto,
            };

            test_cases.push(tc);
        }
    }

    test_cases
}

#[derive(Copy, Clone, PartialEq, Default, strum_macros::EnumIter)]
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
