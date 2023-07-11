use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_crypto_test_utils_canister_threshold_sigs::node::{Node, Nodes};
use ic_crypto_test_utils_canister_threshold_sigs::{
    build_params_from_previous, CanisterThresholdSigTestEnvironment, IDkgParticipants,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::IDkgProtocol;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealings, IDkgComplaint, IDkgDealers, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptOperation, IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::PreSignatureQuadruple;
use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, RngCore};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

criterion_main!(benches);
criterion_group!(benches, crypto_idkg_benchmarks);

fn crypto_idkg_benchmarks(criterion: &mut Criterion) {
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

        IDkgMode::iter().for_each(|mode| bench_create_dealing(group, &test_case, &mode, &mut rng));
        IDkgMode::iter()
            .for_each(|mode| bench_verify_dealing_public(group, &test_case, &mode, &mut rng));
        IDkgMode::iter()
            .for_each(|mode| bench_verify_dealing_private(group, &test_case, &mode, &mut rng));

        bench_verify_initial_dealings(group, &test_case, &mut rng);

        IDkgMode::iter()
            .for_each(|mode| bench_create_transcript(group, &test_case, &mode, &mut rng));
        IDkgMode::iter()
            .for_each(|mode| bench_verify_transcript(group, &test_case, &mode, &mut rng));
        IDkgMode::iter().for_each(|mode| bench_load_transcript(group, &test_case, &mode, &mut rng));

        bench_retain_active_transcripts(group, &test_case, 1, &mut rng);
    }
}

fn bench_create_dealing<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("create_dealing_{mode}"), |bench| {
        bench.iter_batched(
            || env.nodes.random_dealer(&params, rng),
            |dealer| create_dealing(dealer, &params),
            SmallInput,
        )
    });
}

fn bench_verify_dealing_public<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("verify_dealing_public_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let receiver = env.nodes.random_receiver(params.receivers(), rng);
                let dealer = env.nodes.random_dealer(&params, rng);
                let dealing = create_dealing(dealer, &params);
                (receiver, dealing)
            },
            |(receiver, dealing)| verify_dealing_public(receiver, &params, &dealing),
            SmallInput,
        )
    });
}

fn bench_verify_dealing_private<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("verify_dealing_private_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let receiver = env.nodes.random_receiver(params.receivers(), rng);
                let dealer = env.nodes.random_dealer(&params, rng);
                let dealing = create_dealing(dealer, &params);
                (receiver, dealing)
            },
            |(receiver, dealing)| verify_dealing_private(receiver, &params, &dealing),
            SmallInput,
        )
    });
}

fn bench_verify_initial_dealings<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let receiver = env.nodes.random_node(rng);

    group.bench_function("verify_initial_dealings", |bench| {
        bench.iter_batched(
            || {
                let initial_params = env.params_for_random_sharing(
                    &dealers,
                    &receivers,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    rng,
                );
                let initial_transcript =
                    run_idkg_without_complaint(&initial_params, &env.nodes, rng);

                let unmasked_params = build_params_from_previous(
                    initial_params,
                    IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
                    rng,
                );
                let unmasked_transcript =
                    run_idkg_without_complaint(&unmasked_params, &env.nodes, rng);

                let reshare_of_unmasked_params = build_params_from_previous(
                    unmasked_params,
                    IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
                    rng,
                );
                load_previous_transcripts_for_all_dealers(&reshare_of_unmasked_params, &env.nodes);
                let dealings = env.nodes.create_dealings(&reshare_of_unmasked_params);

                let initial_dealings = InitialIDkgDealings::new(
                    reshare_of_unmasked_params.clone(),
                    dealings.into_values().collect(),
                )
                .expect("failed to create initial dealings");
                (reshare_of_unmasked_params, initial_dealings)
            },
            |(params, initial_dealings)| {
                verify_initial_dealings(receiver, &params, &initial_dealings)
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("create_transcript_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let receiver = env.nodes.random_receiver(params.receivers(), rng);
                let dealings = env.nodes.create_dealings(&params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, &params);
                (receiver, dealings_with_receivers_support)
            },
            |(receiver, dealings)| create_transcript(receiver, &params, &dealings),
            SmallInput,
        )
    });
}

fn bench_verify_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("verify_transcript_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let dealings = env.nodes.create_dealings(&params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, &params);
                let receiver = env.nodes.random_receiver(params.receivers(), rng);
                let transcript =
                    create_transcript(receiver, &params, &dealings_with_receivers_support);
                let other_receiver = other_receiver_or_same_if_only_one(
                    params.receivers(),
                    receiver,
                    &env.nodes,
                    rng,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| verify_transcript(receiver, &params, &transcript),
            SmallInput,
        )
    });
}

fn bench_load_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: &IDkgMode,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = mode.setup_params(&env, &dealers, &receivers, rng);

    group.bench_function(format!("load_transcript_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let dealings = env.nodes.create_dealings(&params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, &params);
                let receiver = env.nodes.random_receiver(params.receivers(), rng);
                let transcript =
                    create_transcript(receiver, &params, &dealings_with_receivers_support);
                let other_receiver = other_receiver_or_same_if_only_one(
                    params.receivers(),
                    receiver,
                    &env.nodes,
                    rng,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| load_transcript(receiver, &transcript),
            SmallInput,
        )
    });
}

fn bench_retain_active_transcripts<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    num_pre_sig_quadruples: i32,
    rng: &mut R,
) {
    let env = test_case.new_test_environment(rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, rng);
    let transcripts_to_keep: HashSet<_> = vec![key_transcript.clone()].into_iter().collect();
    // For this benchmark we need a node which acts as receiver in *all* created transcripts.
    // This is the case because all nodes in CanisterThresholdSigTestEnvironment act as receivers
    // and all involved IDkgTranscriptParams include all nodes from CanisterThresholdSigTestEnvironment.
    let receiver = env.nodes.random_receiver(&key_transcript.receivers, rng);
    load_transcript(receiver, &key_transcript);

    let num_transcripts_to_delete = num_pre_sig_quadruples * 4;
    group.bench_function(
        format!(
            "retain_active_transcripts(keep=1,delete={})",
            num_transcripts_to_delete
        ),
        |bench| {
            bench.iter_batched(
                || {
                    for _ in 0..num_pre_sig_quadruples {
                        let pre_sig_quadruple = generate_pre_sig_quadruple(
                            &env,
                            &dealers,
                            &receivers,
                            key_transcript.clone(),
                            rng,
                        );
                        load_pre_signature_quadruple(receiver, &pre_sig_quadruple);
                    }
                },
                |_| retain_active_transcripts(receiver, &transcripts_to_keep),
                SmallInput,
            )
        },
    );
}

fn create_dealing(dealer: &Node, params: &IDkgTranscriptParams) -> SignedIDkgDealing {
    dealer.create_dealing(params).unwrap_or_else(|error| {
        panic!(
            "failed to create IDKG dealing for dealer {:?} with parameters {:?}: {:?}",
            dealer.id(),
            params,
            error
        )
    })
}

fn verify_dealing_public(
    receiver: &Node,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) {
    receiver
        .verify_dealing_public(params, signed_dealing)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify publicly IDKG dealing {:?} by {:?} with parameters {:?}: {:?}",
                signed_dealing,
                receiver.id(),
                params,
                error
            )
        })
}

fn verify_dealing_private(
    receiver: &Node,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) {
    receiver
        .verify_dealing_private(params, signed_dealing)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify privately IDKG dealing {:?} by {:?} with parameters {:?}: {:?}",
                signed_dealing,
                receiver.id(),
                params,
                error
            )
        })
}

fn verify_initial_dealings(
    receiver: &Node,
    params: &IDkgTranscriptParams,
    initial_dealings: &InitialIDkgDealings,
) {
    receiver
        .verify_initial_dealings(params, initial_dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify initial IDKG dealings {:?} by {:?} with parameters {:?}: {:?}",
                initial_dealings,
                receiver.id(),
                params,
                error
            )
        })
}

fn create_transcript(
    receiver: &Node,
    params: &IDkgTranscriptParams,
    dealings: &BatchSignedIDkgDealings,
) -> IDkgTranscript {
    receiver
        .create_transcript(params, dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to create IDKG transcript by receiver {:?} with parameters {:?}: {:?}",
                receiver.id(),
                params,
                error
            )
        })
}

fn run_idkg_without_complaint<R: RngCore + CryptoRng>(
    params: &IDkgTranscriptParams,
    nodes: &Nodes,
    rng: &mut R,
) -> IDkgTranscript {
    load_previous_transcripts_for_all_dealers(params, nodes);
    let receiver = nodes.random_receiver(params.receivers(), rng);
    let dealings = nodes.create_dealings(params);
    let dealings_with_receivers_support =
        nodes.support_dealings_from_all_receivers(dealings, params);
    create_transcript(receiver, params, &dealings_with_receivers_support)
}

fn load_previous_transcripts_for_all_dealers(params: &IDkgTranscriptParams, nodes: &Nodes) {
    let mut transcripts_to_load = Vec::with_capacity(2);
    match params.operation_type() {
        IDkgTranscriptOperation::Random => {}
        IDkgTranscriptOperation::ReshareOfMasked(transcript) => {
            transcripts_to_load.push(transcript)
        }
        IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
            transcripts_to_load.push(transcript)
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(transcript1, transcript2) => {
            transcripts_to_load.push(transcript1);
            transcripts_to_load.push(transcript2)
        }
    }

    nodes.dealers(params).for_each(|dealer| {
        transcripts_to_load.iter().for_each(|transcript| {
            assert_eq!(
                load_transcript(dealer, transcript),
                vec![],
                "did not expect any complaint"
            )
        });
    });
}

fn verify_transcript(receiver: &Node, params: &IDkgTranscriptParams, transcript: &IDkgTranscript) {
    receiver
        .verify_transcript(params, transcript)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify IDKG transcript by receiver {:?} with parameters {:?}: {:?}",
                receiver.id(),
                params,
                error
            )
        })
}

fn load_transcript(receiver: &Node, transcript: &IDkgTranscript) -> Vec<IDkgComplaint> {
    receiver
        .load_transcript(transcript)
        .unwrap_or_else(|error| {
            panic!(
                "failed to load IDKG transcript by receiver {:?}: {:?}",
                receiver.id(),
                error
            )
        })
}

fn load_pre_signature_quadruple(receiver: &Node, quadruple: &PreSignatureQuadruple) {
    assert_eq!(
        load_transcript(receiver, quadruple.kappa_unmasked()),
        vec![]
    );
    assert_eq!(load_transcript(receiver, quadruple.lambda_masked()), vec![]);
    assert_eq!(
        load_transcript(receiver, quadruple.kappa_times_lambda()),
        vec![]
    );
    assert_eq!(
        load_transcript(receiver, quadruple.key_times_lambda()),
        vec![]
    );
}

fn retain_active_transcripts(receiver: &Node, active_transcripts: &HashSet<IDkgTranscript>) {
    receiver
        .retain_active_transcripts(active_transcripts)
        .unwrap_or_else(|error| {
            panic!(
                "failed to retain active IDKG transcripts by receiver {:?}: {:?}",
                receiver.id(),
                error
            )
        })
}

fn generate_key_transcript<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    rng: &mut R,
) -> IDkgTranscript {
    let masked_key_params = env.params_for_random_sharing(
        dealers,
        receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let masked_key_transcript = run_idkg_without_complaint(&masked_key_params, &env.nodes, rng);

    let unmasked_key_params = build_params_from_previous(
        masked_key_params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
        rng,
    );

    run_idkg_without_complaint(&unmasked_key_params, &env.nodes, rng)
}

fn generate_pre_sig_quadruple<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    key_transcript: IDkgTranscript,
    rng: &mut R,
) -> PreSignatureQuadruple {
    let lambda_params = env.params_for_random_sharing(
        dealers,
        receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let lambda_transcript = run_idkg_without_complaint(&lambda_params, &env.nodes, rng);

    let kappa_transcript = {
        let masked_kappa_params = env.params_for_random_sharing(
            dealers,
            receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            rng,
        );
        let masked_kappa_transcript =
            run_idkg_without_complaint(&masked_kappa_params, &env.nodes, rng);

        let unmasked_kappa_params = build_params_from_previous(
            masked_kappa_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_kappa_transcript),
            rng,
        );
        run_idkg_without_complaint(&unmasked_kappa_params, &env.nodes, rng)
    };

    let kappa_times_lambda_transcript = {
        let kappa_times_lambda_params = build_params_from_previous(
            lambda_params.clone(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                kappa_transcript.clone(),
                lambda_transcript.clone(),
            ),
            rng,
        );

        run_idkg_without_complaint(&kappa_times_lambda_params, &env.nodes, rng)
    };

    let key_times_lambda_transcript = {
        let key_times_lambda_params = build_params_from_previous(
            lambda_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(key_transcript, lambda_transcript.clone()),
            rng,
        );

        run_idkg_without_complaint(&key_times_lambda_params, &env.nodes, rng)
    };

    PreSignatureQuadruple::new(
        kappa_transcript,
        lambda_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
    .unwrap_or_else(|error| panic!("failed to create pre-signature quadruple: {:?}", error))
}

fn other_receiver_or_same_if_only_one<'a, R: RngCore + CryptoRng>(
    receivers: &'a IDkgReceivers,
    exclusion: &Node,
    nodes: &'a Nodes,
    rng: &mut R,
) -> &'a Node {
    match receivers.get().len() {
        0 => panic!("IDkgReceivers is guaranteed to be non-empty"),
        1 => nodes.iter().next().expect("one node"),
        _ => nodes.random_receiver_excluding(exclusion, receivers, rng),
    }
}

fn setup_reshare_of_masked_params<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    rng: &mut R,
) -> IDkgTranscriptParams {
    let params = env.params_for_random_sharing(
        dealers,
        receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let masked_transcript = run_idkg_without_complaint(&params, &env.nodes, rng);
    let reshare_params = build_params_from_previous(
        params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_transcript),
        rng,
    );
    load_previous_transcripts_for_all_dealers(&reshare_params, &env.nodes);
    reshare_params
}

fn setup_reshare_of_unmasked_params<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    rng: &mut R,
) -> IDkgTranscriptParams {
    let params = env.params_for_random_sharing(
        dealers,
        receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let masked_transcript = run_idkg_without_complaint(&params, &env.nodes, rng);
    let unmasked_params = build_params_from_previous(
        params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_transcript),
        rng,
    );
    load_previous_transcripts_for_all_dealers(&unmasked_params, &env.nodes);
    let unmasked_transcript = run_idkg_without_complaint(&unmasked_params, &env.nodes, rng);
    let unmasked_reshare_params = build_params_from_previous(
        unmasked_params,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );
    load_previous_transcripts_for_all_dealers(&unmasked_reshare_params, &env.nodes);
    unmasked_reshare_params
}

fn setup_unmasked_times_masked_params<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    rng: &mut R,
) -> IDkgTranscriptParams {
    let masked_params = env.params_for_random_sharing(
        dealers,
        receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let masked_random_transcript = run_idkg_without_complaint(&masked_params, &env.nodes, rng);

    let unmasked_params = build_params_from_previous(
        masked_params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_random_transcript.clone()),
        rng,
    );
    load_previous_transcripts_for_all_dealers(&unmasked_params, &env.nodes);
    let unmasked_transcript = run_idkg_without_complaint(&unmasked_params, &env.nodes, rng);

    let product_params = build_params_from_previous(
        unmasked_params,
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_random_transcript),
        rng,
    );
    load_previous_transcripts_for_all_dealers(&product_params, &env.nodes);
    product_params
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
    fn new_test_environment<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> CanisterThresholdSigTestEnvironment {
        CanisterThresholdSigTestEnvironment::new(self.num_of_nodes, rng)
    }

    fn name(&self) -> String {
        format!(
            "crypto_idkg_{}_nodes_{}_dealers_{}_receivers",
            self.num_of_nodes,
            self.num_of_dealers(),
            self.num_of_receivers()
        )
    }

    fn num_of_dealers(&self) -> usize {
        self.num_of_nodes
    }

    fn num_of_receivers(&self) -> usize {
        self.num_of_nodes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, EnumIter)]
enum IDkgMode {
    Random,
    ReshareOfMasked,
    ReshareOfUnmasked,
    UnmaskedTimesMasked,
}

impl IDkgMode {
    fn setup_params<R: RngCore + CryptoRng>(
        &self,
        env: &CanisterThresholdSigTestEnvironment,
        dealers: &IDkgDealers,
        receivers: &IDkgReceivers,
        rng: &mut R,
    ) -> IDkgTranscriptParams {
        match self {
            IDkgMode::Random => env.params_for_random_sharing(
                dealers,
                receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                rng,
            ),
            IDkgMode::ReshareOfMasked => {
                setup_reshare_of_masked_params(env, dealers, receivers, rng)
            }
            IDkgMode::ReshareOfUnmasked => {
                setup_reshare_of_unmasked_params(env, dealers, receivers, rng)
            }
            IDkgMode::UnmaskedTimesMasked => {
                setup_unmasked_times_masked_params(env, dealers, receivers, rng)
            }
        }
    }
}

impl Display for IDkgMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IDkgMode::Random => "random",
                IDkgMode::ReshareOfMasked => "reshare_of_masked",
                IDkgMode::ReshareOfUnmasked => "reshare_of_unmasked",
                IDkgMode::UnmaskedTimesMasked => "product",
            }
        )
    }
}
