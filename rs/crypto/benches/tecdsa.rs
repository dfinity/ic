use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils_canister_threshold_sigs::node::Node;
use ic_crypto_test_utils_canister_threshold_sigs::{
    ecdsa_sig_share_from_each_receiver, generate_key_transcript, generate_tecdsa_protocol_inputs,
    random_crypto_component_not_in_receivers, CanisterThresholdSigTestEnvironment,
    IDkgParticipants,
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
use strum::IntoEnumIterator;

criterion_main!(benches);
criterion_group!(benches, crypto_tecdsa_benchmarks);

fn crypto_tecdsa_benchmarks(criterion: &mut Criterion) {
    let number_of_nodes = [1, 4, 13, 28, 40];

    let test_cases = generate_test_cases(&number_of_nodes);

    let rng = &mut ReproducibleRng::new();
    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name());
        group
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        for vault_type in VaultType::iter() {
            bench_sign_share(group, &test_case, vault_type, rng);
        }
        bench_verify_sig_share(group, &test_case, VaultType::default(), rng);
        bench_combine_sig_shares(group, &test_case, VaultType::default(), rng);
        bench_verify_combined_sig(group, &test_case, VaultType::default(), rng);
    }
}

fn bench_sign_share<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg(), rng);
    let signer = env
        .nodes
        .random_filtered_by_receivers(&key_transcript.receivers, rng);

    group.bench_function(format!("sign_share_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    test_case.alg(),
                    rng,
                );
                signer.load_tecdsa_sig_transcripts(&inputs);
                inputs
            },
            |inputs| sign_share(signer, inputs),
            SmallInput,
        )
    });
}

fn sign_share(signer: &Node, inputs: &ThresholdEcdsaSigInputs) -> ThresholdEcdsaSigShare {
    signer.create_sig_share(inputs).unwrap_or_else(|error| {
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
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg(), rng);

    group.bench_function(format!("verify_sig_share_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    test_case.alg(),
                    rng,
                );
                let signer = env
                    .nodes
                    .random_filtered_by_receivers(&key_transcript.receivers, rng);
                signer.load_tecdsa_sig_transcripts(&inputs);
                let sig_share = sign_share(signer, &inputs);
                let verifier = env
                    .nodes
                    .random_filtered_by_receivers(&key_transcript.receivers, rng);
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
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg(), rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function(format!("combine_sig_shares_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    test_case.alg(),
                    rng,
                );
                let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs);
                (inputs, sig_shares)
            },
            |(inputs, sig_shares)| combine_sig_shares(&combiner, inputs, sig_shares),
            SmallInput,
        )
    });
}

fn combine_sig_shares<R: Rng + CryptoRng + Sync + Send + 'static>(
    combiner: &TempCryptoComponentGeneric<R>,
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
    vault_type: VaultType,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(vault_type, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, test_case.alg(), rng);
    let combiner = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);
    let verifier = random_crypto_component_not_in_receivers(&env, &key_transcript.receivers, rng);

    group.bench_function(format!("verify_combined_sig_{vault_type:?}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (derivation_path, hashed_message, seed) = random_sig_inputs(rng);
                let inputs = generate_tecdsa_protocol_inputs(
                    &env,
                    &dealers,
                    &receivers,
                    &key_transcript,
                    &hashed_message,
                    seed,
                    &derivation_path,
                    test_case.alg(),
                    rng,
                );
                let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs);
                let signature = combine_sig_shares(&combiner, &inputs, &sig_shares);
                (inputs, signature)
            },
            |(inputs, signature)| verify_combined_sig(&verifier, inputs, signature),
            SmallInput,
        )
    });
}

fn verify_combined_sig<R: Rng + CryptoRng + Sync + Send + 'static>(
    verifier: &TempCryptoComponentGeneric<R>,
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
    alg: AlgorithmId,
}

impl Default for TestCase {
    fn default() -> Self {
        TestCase {
            sample_size: 100,
            sampling_mode: SamplingMode::Auto,
            num_of_nodes: 0,
            alg: AlgorithmId::ThresholdEcdsaSecp256k1,
        }
    }
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
        let curve = match self.alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 => "secp256k1",
            AlgorithmId::ThresholdEcdsaSecp256r1 => "secp256r1",
            unexpected => panic!("Unexpected testcase algorithm {}", unexpected),
        };
        format!("crypto_tecdsa_{}_{}_nodes", curve, self.num_of_nodes)
    }

    fn alg(&self) -> AlgorithmId {
        self.alg
    }
}

fn generate_test_cases(node_counts: &[usize]) -> Vec<TestCase> {
    let mut test_cases = vec![];

    let tecdsa_algs = AlgorithmId::all_threshold_ecdsa_algorithms();

    for num_of_nodes in node_counts.iter().copied() {
        let sample_size = if num_of_nodes < 10 { 100 } else { 10 };

        for alg in tecdsa_algs {
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
