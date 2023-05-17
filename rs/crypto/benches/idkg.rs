use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};
use ic_base_types::NodeId;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_canister_threshold_sigs::{
    batch_sign_signed_dealings, build_params_from_previous, random_dealer_id, random_receiver_id,
    random_receiver_id_excluding, CanisterThresholdSigTestEnvironment,
};
use ic_interfaces::crypto::IDkgProtocol;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgComplaint, IDkgTranscript, IDkgTranscriptOperation,
    IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::PreSignatureQuadruple;
use ic_types::crypto::AlgorithmId;
use rand::prelude::IteratorRandom;
use rand::thread_rng;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Formatter};

criterion_main!(benches);
criterion_group!(benches, crypto_idkg_benchmarks);

fn crypto_idkg_benchmarks(criterion: &mut Criterion) {
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

        bench_create_dealing(group, &test_case);
        bench_verify_dealing_public(group, &test_case);
        bench_verify_dealing_private(group, &test_case);
        bench_verify_initial_dealings(group, &test_case);
        bench_create_transcript(group, &test_case);
        bench_verify_transcript(group, &test_case);
        bench_load_transcript(group, &test_case);
        bench_retain_active_transcripts(group, &test_case, 1);
    }
}

fn bench_create_dealing<M: Measurement>(group: &mut BenchmarkGroup<'_, M>, test_case: &TestCase) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("create_dealing", |bench| {
        bench.iter_batched(
            || crypto_for(random_dealer_id(&params), &env.crypto_components),
            |dealer| create_dealing(dealer, &params),
            SmallInput,
        )
    });
}

fn bench_verify_dealing_public<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("verify_dealing_public", |bench| {
        bench.iter_batched(
            || {
                let receiver = crypto_for(random_receiver_id(&params), &env.crypto_components);
                let dealer = crypto_for(random_dealer_id(&params), &env.crypto_components);
                let dealing = create_dealing(dealer, &params);
                (receiver, dealing)
            },
            |(receiver, dealing)| verify_dealing_public(receiver, &params, &dealing),
            SmallInput,
        )
    });
}

fn bench_verify_dealing_private<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("verify_dealing_private", |bench| {
        bench.iter_batched(
            || {
                let receiver = crypto_for(random_receiver_id(&params), &env.crypto_components);
                let dealer = crypto_for(random_dealer_id(&params), &env.crypto_components);
                let dealing = create_dealing(dealer, &params);
                (receiver, dealing)
            },
            |(receiver, dealing)| verify_dealing_private(receiver, &params, &dealing),
            SmallInput,
        )
    });
}

fn bench_verify_initial_dealings<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let env = test_case.new_test_environment();

    group.bench_function("verify_initial_dealings", |bench| {
        bench.iter_batched(
            || {
                let initial_params =
                    env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
                let initial_transcript =
                    run_idkg_without_complaint(&initial_params, &env.crypto_components);

                let unmasked_params = build_params_from_previous(
                    initial_params,
                    IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
                );
                let unmasked_transcript =
                    run_idkg_without_complaint(&unmasked_params, &env.crypto_components);

                let reshare_of_unmasked_params = build_params_from_previous(
                    unmasked_params,
                    IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
                );
                load_previous_transcripts_for_all_dealers(
                    &reshare_of_unmasked_params,
                    &env.crypto_components,
                );
                let dealings = create_dealings(&reshare_of_unmasked_params, &env.crypto_components);

                let receiver = crypto_for(
                    random_receiver_id(&reshare_of_unmasked_params),
                    &env.crypto_components,
                );
                let initial_dealings = InitialIDkgDealings::new(
                    reshare_of_unmasked_params.clone(),
                    dealings.into_values().collect(),
                )
                .expect("failed to create initial dealings");
                (receiver, reshare_of_unmasked_params, initial_dealings)
            },
            |(receiver, params, initial_dealings)| {
                verify_initial_dealings(receiver, &params, &initial_dealings)
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("create_transcript", |bench| {
        bench.iter_batched(
            || {
                let receiver = crypto_for(random_receiver_id(&params), &env.crypto_components);
                let dealings = create_dealings(&params, &env.crypto_components);
                let dealings_with_receivers_support =
                    batch_sign_signed_dealings(&params, &env.crypto_components, dealings);
                (receiver, dealings_with_receivers_support)
            },
            |(receiver, dealings)| create_transcript(receiver, &params, &dealings),
            SmallInput,
        )
    });
}

fn bench_verify_transcript<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("verify_transcript", |bench| {
        bench.iter_batched(
            || {
                let dealings = create_dealings(&params, &env.crypto_components);
                let dealings_with_receivers_support =
                    batch_sign_signed_dealings(&params, &env.crypto_components, dealings);
                let receiver = crypto_for(random_receiver_id(&params), &env.crypto_components);
                let transcript =
                    create_transcript(receiver, &params, &dealings_with_receivers_support);
                let other_receiver = crypto_for(
                    random_receiver_id_excluding(params.receivers(), receiver.get_node_id()),
                    &env.crypto_components,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| verify_transcript(receiver, &params, &transcript),
            SmallInput,
        )
    });
}

fn bench_load_transcript<M: Measurement>(group: &mut BenchmarkGroup<'_, M>, test_case: &TestCase) {
    let env = test_case.new_test_environment();
    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    group.bench_function("load_transcript", |bench| {
        bench.iter_batched(
            || {
                let dealings = create_dealings(&params, &env.crypto_components);
                let dealings_with_receivers_support =
                    batch_sign_signed_dealings(&params, &env.crypto_components, dealings);
                let receiver = crypto_for(random_receiver_id(&params), &env.crypto_components);
                let transcript =
                    create_transcript(receiver, &params, &dealings_with_receivers_support);
                let other_receiver = crypto_for(
                    random_receiver_id_excluding(params.receivers(), receiver.get_node_id()),
                    &env.crypto_components,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| load_transcript(receiver, &transcript),
            SmallInput,
        )
    });
}

fn bench_retain_active_transcripts<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    num_pre_sig_quadruples: usize,
) {
    let env = test_case.new_test_environment();
    let key_transcript = generate_key_transcript(&env);
    let transcripts_to_keep: HashSet<_> = vec![key_transcript.clone()].into_iter().collect();
    // For this benchmark we need a node which acts as receiver in *all* created transcripts.
    // This is the case because all nodes in CanisterThresholdSigTestEnvironment act as receivers
    // and all involved IDkgTranscriptParams include all nodes from CanisterThresholdSigTestEnvironment.
    let receiver_id = env
        .receivers()
        .into_iter()
        .choose(&mut thread_rng())
        .expect("receivers cannot be empty");
    let receiver = crypto_for(receiver_id, &env.crypto_components);
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
                        let pre_sig_quadruple =
                            generate_pre_sig_quadruple(&env, key_transcript.clone());
                        load_pre_signature_quadruple(receiver, &pre_sig_quadruple);
                    }
                },
                |_| retain_active_transcripts(receiver, &transcripts_to_keep),
                SmallInput,
            )
        },
    );
}

fn create_dealing(
    dealer: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
) -> SignedIDkgDealing {
    dealer.create_dealing(params).unwrap_or_else(|error| {
        panic!(
            "failed to create IDKG dealing for dealer {:?} with parameters {:?}: {:?}",
            dealer.get_node_id(),
            params,
            error
        )
    })
}

fn create_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, SignedIDkgDealing> {
    params
        .dealers()
        .get()
        .iter()
        .map(|dealer_id| {
            let dealing = create_dealing(crypto_for(*dealer_id, crypto_components), params);
            (*dealer_id, dealing)
        })
        .collect()
}

fn verify_dealing_public(
    receiver: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) {
    receiver
        .verify_dealing_public(params, signed_dealing)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify publicly IDKG dealing {:?} by {:?} with parameters {:?}: {:?}",
                signed_dealing,
                receiver.get_node_id(),
                params,
                error
            )
        })
}

fn verify_dealing_private(
    receiver: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) {
    receiver
        .verify_dealing_private(params, signed_dealing)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify privately IDKG dealing {:?} by {:?} with parameters {:?}: {:?}",
                signed_dealing,
                receiver.get_node_id(),
                params,
                error
            )
        })
}

fn verify_initial_dealings(
    receiver: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
    initial_dealings: &InitialIDkgDealings,
) {
    receiver
        .verify_initial_dealings(params, initial_dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify initial IDKG dealings {:?} by {:?} with parameters {:?}: {:?}",
                initial_dealings,
                receiver.get_node_id(),
                params,
                error
            )
        })
}

fn create_transcript(
    receiver: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
    dealings: &BTreeMap<NodeId, BatchSignedIDkgDealing>,
) -> IDkgTranscript {
    receiver
        .create_transcript(params, dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to create IDKG transcript by receiver {:?} with parameters {:?}: {:?}",
                receiver.get_node_id(),
                params,
                error
            )
        })
}

fn run_idkg_without_complaint(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> IDkgTranscript {
    load_previous_transcripts_for_all_dealers(params, crypto_components);
    let receiver = crypto_for(random_receiver_id(params), crypto_components);
    let dealings = create_dealings(params, crypto_components);
    let dealings_with_receivers_support =
        batch_sign_signed_dealings(params, crypto_components, dealings);
    create_transcript(receiver, params, &dealings_with_receivers_support)
}

fn load_previous_transcripts_for_all_dealers(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
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
    params.dealers().get().iter().for_each(|dealer_id| {
        let dealer = crypto_for(*dealer_id, crypto_components);
        transcripts_to_load.iter().for_each(|transcript| {
            assert_eq!(
                load_transcript(dealer, transcript),
                vec![],
                "did not expect any complaint"
            )
        });
    });
}

fn verify_transcript(
    receiver: &TempCryptoComponent,
    params: &IDkgTranscriptParams,
    transcript: &IDkgTranscript,
) {
    receiver
        .verify_transcript(params, transcript)
        .unwrap_or_else(|error| {
            panic!(
                "failed to verify IDKG transcript by receiver {:?} with parameters {:?}: {:?}",
                receiver.get_node_id(),
                params,
                error
            )
        })
}

fn load_transcript(
    receiver: &TempCryptoComponent,
    transcript: &IDkgTranscript,
) -> Vec<IDkgComplaint> {
    receiver
        .load_transcript(transcript)
        .unwrap_or_else(|error| {
            panic!(
                "failed to load IDKG transcript by receiver {:?}: {:?}",
                receiver.get_node_id(),
                error
            )
        })
}

fn load_pre_signature_quadruple(receiver: &TempCryptoComponent, quadruple: &PreSignatureQuadruple) {
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

fn retain_active_transcripts(
    receiver: &TempCryptoComponent,
    active_transcripts: &HashSet<IDkgTranscript>,
) {
    receiver
        .retain_active_transcripts(active_transcripts)
        .unwrap_or_else(|error| {
            panic!(
                "failed to retain active IDKG transcripts by receiver {:?}: {:?}",
                receiver.get_node_id(),
                error
            )
        })
}

fn generate_key_transcript(env: &CanisterThresholdSigTestEnvironment) -> IDkgTranscript {
    let masked_key_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let masked_key_transcript =
        run_idkg_without_complaint(&masked_key_params, &env.crypto_components);

    let unmasked_key_params = build_params_from_previous(
        masked_key_params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
    );

    run_idkg_without_complaint(&unmasked_key_params, &env.crypto_components)
}

fn generate_pre_sig_quadruple(
    env: &CanisterThresholdSigTestEnvironment,
    key_transcript: IDkgTranscript,
) -> PreSignatureQuadruple {
    let lambda_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let lambda_transcript = run_idkg_without_complaint(&lambda_params, &env.crypto_components);

    let kappa_transcript = {
        let masked_kappa_params =
            env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let masked_kappa_transcript =
            run_idkg_without_complaint(&masked_kappa_params, &env.crypto_components);

        let unmasked_kappa_params = build_params_from_previous(
            masked_kappa_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_kappa_transcript),
        );
        run_idkg_without_complaint(&unmasked_kappa_params, &env.crypto_components)
    };

    let kappa_times_lambda_transcript = {
        let kappa_times_lambda_params = build_params_from_previous(
            lambda_params.clone(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                kappa_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_without_complaint(&kappa_times_lambda_params, &env.crypto_components)
    };

    let key_times_lambda_transcript = {
        let key_times_lambda_params = build_params_from_previous(
            lambda_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(key_transcript, lambda_transcript.clone()),
        );

        run_idkg_without_complaint(&key_times_lambda_params, &env.crypto_components)
    };

    PreSignatureQuadruple::new(
        kappa_transcript,
        lambda_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
    .unwrap_or_else(|error| panic!("failed to create pre-signature quadruple: {:?}", error))
}

struct TestCase {
    sample_size: usize,
    sampling_mode: SamplingMode,
    num_of_nodes: usize,
    operation_type: IDkgMode,
}

impl Default for TestCase {
    fn default() -> Self {
        TestCase {
            sample_size: 100,
            sampling_mode: SamplingMode::Auto,
            num_of_nodes: 0,
            operation_type: IDkgMode::Random,
        }
    }
}

impl TestCase {
    fn new_test_environment(&self) -> CanisterThresholdSigTestEnvironment {
        CanisterThresholdSigTestEnvironment::new(self.num_of_nodes)
    }

    fn name(&self) -> String {
        format!(
            "crypto_idkg_{}_{}_nodes_{}_dealers_{}_receivers",
            self.operation_type,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum IDkgMode {
    Random,
    // TODO CRP-1471: add benchmarks for resharing and product
    // ReshareOfMasked,
    // UnmaskedTimesMasked,
}

impl Display for IDkgMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IDkgMode::Random => "random",
                // TODO CRP-1471: add benchmarks for resharing and product
                // IDkgMode::ReshareOfMasked => "reshare",
                // IDkgMode::UnmaskedTimesMasked => "product",
            }
        )
    }
}
