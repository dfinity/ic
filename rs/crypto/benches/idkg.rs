use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, Criterion, SamplingMode, criterion_group, criterion_main};
use ic_crypto_test_utils_canister_threshold_sigs::node::{Node, Nodes};
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgMode, IDkgModeTestContext, IDkgParticipants,
    IDkgTestContextForComplaint, create_transcript_or_panic,
    generate_and_verify_openings_for_complaint, generate_ecdsa_presig_quadruple,
    load_previous_transcripts_for_all_dealers, load_transcript_or_panic, random_transcript_id,
    run_idkg_without_complaint, setup_unmasked_random_params,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::IDkgProtocol;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::EcdsaPreSignatureQuadruple;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealers, IDkgReceivers, IDkgTranscript, IDkgTranscriptOperation, IDkgTranscriptParams,
    InitialIDkgDealings, SignedIDkgDealing,
};
use rand::{CryptoRng, RngCore};
use std::cell::OnceCell;
use std::collections::HashSet;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

const WARMUP_TIME: std::time::Duration = std::time::Duration::from_millis(300);

#[derive(Copy, Clone, PartialEq, Default, EnumIter)]
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

criterion_main!(benches);
criterion_group!(benches, crypto_idkg_benchmarks);

fn crypto_idkg_benchmarks(criterion: &mut Criterion) {
    let nums_of_nodes = [34];
    let test_cases = generate_test_cases(&nums_of_nodes);

    let rng = &mut ReproducibleRng::new();
    for test_case in test_cases {
        for vault_type in VaultType::iter() {
            let group =
                &mut criterion.benchmark_group(format!("{}_{vault_type:?}", test_case.name()));
            group
                .warm_up_time(WARMUP_TIME)
                .sample_size(test_case.sample_size)
                .sampling_mode(test_case.sampling_mode);

            for mode in IDkgMode::iter() {
                bench_create_dealing(group, &test_case, mode, vault_type, rng);
                bench_verify_dealing_private(group, &test_case, mode, vault_type, rng);
                bench_load_transcript(group, &test_case, mode, vault_type, rng);
                if test_case.num_of_nodes >= mode.min_subnet_size_for_complaint() {
                    bench_open_transcript(group, &test_case, mode, vault_type, rng);
                    bench_load_transcript_with_openings(group, &test_case, mode, vault_type, rng);
                }
            }

            bench_retain_active_transcripts(group, &test_case, 1, vault_type, rng);

            // The following benchmarks are not affected by the choice of the
            // vault, we benchmark them only once with the default vault type.
            if vault_type == VaultType::default() {
                for mode in IDkgMode::iter() {
                    bench_verify_dealing_public(group, &test_case, mode, vault_type, rng);
                    bench_create_transcript(group, &test_case, mode, vault_type, rng);
                    bench_verify_transcript(group, &test_case, mode, vault_type, rng);
                    if test_case.num_of_nodes >= mode.min_subnet_size_for_complaint() {
                        bench_verify_complaint(group, &test_case, mode, vault_type, rng);
                        bench_verify_opening(group, &test_case, mode, vault_type, rng);
                    }
                }

                bench_verify_initial_dealings(group, &test_case, vault_type, rng);
            }
        }
    }
}

fn bench_create_dealing<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("create_dealing_{mode}"), |bench| {
        bench.iter_batched(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params: IDkgTranscriptParams =
                        context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });

                env.nodes.random_dealer(params, rng)
            },
            |dealer| {
                let (_, _, params) = bench_context.get().unwrap();
                create_dealing(dealer, params)
            },
            SmallInput,
        )
    });
}

fn bench_verify_dealing_public<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("verify_dealing_public_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params = context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });
                let receiver = env
                    .nodes
                    .random_filtered_by_receivers(params.receivers(), rng);
                let dealer = env.nodes.random_dealer(params, rng);
                let dealing = create_dealing(dealer, params);
                (receiver, dealing)
            },
            |(receiver, dealing)| {
                let (_, _, params) = bench_context.get().unwrap();
                verify_dealing_public(receiver, params, dealing)
            },
            SmallInput,
        )
    });
}

fn bench_verify_dealing_private<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("verify_dealing_private_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params = context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });
                let receiver = env
                    .nodes
                    .random_filtered_by_receivers(params.receivers(), rng);
                let dealer = env.nodes.random_dealer(params, rng);
                let dealing = create_dealing(dealer, params);
                (receiver, dealing)
            },
            |(receiver, dealing)| {
                let (_, _, params) = bench_context.get().unwrap();
                verify_dealing_private(receiver, params, dealing)
            },
            SmallInput,
        )
    });
}

fn bench_verify_initial_dealings<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function("verify_initial_dealings", |bench| {
        bench.iter_batched_ref(
            || {
                let (dealers_env, receivers_env, src_dealers, src_receivers, dst_receivers) =
                    bench_context.get_or_init(|| {
                        let dealers_env = test_case.new_test_environment(vault_type, rng);
                        let receivers_env =
                            CanisterThresholdSigTestEnvironment::new_with_existing_registry(
                                &dealers_env,
                                test_case.num_of_nodes,
                                rng,
                            );
                        dealers_env.registry.reload();
                        // `src` refers to the subnet where the key is initially generated. Here, both dealers and
                        // receivers are needed.
                        let (src_dealers, src_receivers) = dealers_env
                            .choose_dealers_and_receivers(
                                &IDkgParticipants::AllNodesAsDealersAndReceivers,
                                rng,
                            );
                        // `dst` refers to the subnet where the key is reshared to.
                        let (_dst_dealers, dst_receivers) = receivers_env
                            .choose_dealers_and_receivers(
                                &IDkgParticipants::AllNodesAsDealersAndReceivers,
                                rng,
                            );
                        (
                            dealers_env,
                            receivers_env,
                            src_dealers,
                            src_receivers,
                            dst_receivers,
                        )
                    });

                let initial_params = setup_unmasked_random_params(
                    dealers_env,
                    test_case.alg(),
                    src_dealers,
                    src_receivers,
                    rng,
                );
                let unmasked_transcript =
                    run_idkg_without_complaint(&initial_params, &dealers_env.nodes, rng);

                let reshare_of_unmasked_params = IDkgTranscriptParams::new(
                    random_transcript_id(rng),
                    src_dealers.get().clone(),
                    dst_receivers.get().clone(),
                    unmasked_transcript.registry_version,
                    unmasked_transcript.algorithm_id,
                    IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
                )
                .expect("invalid reshare of unmasked parameters");
                load_previous_transcripts_for_all_dealers(
                    &reshare_of_unmasked_params,
                    &dealers_env.nodes,
                );
                let dealings = dealers_env
                    .nodes
                    .create_dealings(&reshare_of_unmasked_params);

                let initial_dealings = InitialIDkgDealings::new(
                    reshare_of_unmasked_params.clone(),
                    dealings.into_values().collect(),
                )
                .expect("failed to create initial dealings");
                let receiver = receivers_env.nodes.random_node(rng);
                (reshare_of_unmasked_params, initial_dealings, receiver)
            },
            |(params, initial_dealings, receiver)| {
                verify_initial_dealings(receiver, params, initial_dealings)
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("create_transcript_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params = context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });
                let receiver = env
                    .nodes
                    .random_filtered_by_receivers(params.receivers(), rng);
                let dealings = env.nodes.create_dealings(params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, params);
                (receiver, dealings_with_receivers_support)
            },
            |(receiver, dealings)| {
                let (_, _, params) = bench_context.get().unwrap();
                create_transcript_or_panic(receiver, params, dealings)
            },
            SmallInput,
        )
    });
}

fn bench_verify_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("verify_transcript_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params = context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });
                let dealings = env.nodes.create_dealings(params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, params);
                let receiver = env
                    .nodes
                    .random_filtered_by_receivers(params.receivers(), rng);
                let transcript =
                    create_transcript_or_panic(receiver, params, &dealings_with_receivers_support);
                let other_receiver = other_receiver_or_same_if_only_one(
                    params.receivers(),
                    receiver,
                    &env.nodes,
                    rng,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| {
                let (_, _, params) = bench_context.get().unwrap();
                verify_transcript_or_panic(receiver, params, transcript)
            },
            SmallInput,
        )
    });
}

fn bench_load_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("load_transcript_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, _, params) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    let params = context.setup_params(&env, test_case.alg(), rng);
                    (env, context, params)
                });
                let dealings = env.nodes.create_dealings(params);
                let dealings_with_receivers_support = env
                    .nodes
                    .support_dealings_from_all_receivers(dealings, params);
                let receiver = env
                    .nodes
                    .random_filtered_by_receivers(params.receivers(), rng);
                let transcript =
                    create_transcript_or_panic(receiver, params, &dealings_with_receivers_support);
                let other_receiver = other_receiver_or_same_if_only_one(
                    params.receivers(),
                    receiver,
                    &env.nodes,
                    rng,
                );
                (other_receiver, transcript)
            },
            |(receiver, transcript)| load_transcript_or_panic(receiver, transcript),
            SmallInput,
        )
    });
}

fn bench_retain_active_transcripts<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    num_pre_sig_quadruples: i32,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context_cell = OnceCell::new();
    let receiver_cell = OnceCell::new();

    let num_transcripts_to_delete = num_pre_sig_quadruples * 4;
    group.bench_function(
        format!("retain_active_transcripts(keep=1,delete={num_transcripts_to_delete})"),
        |bench| {
            bench.iter_batched(
                || {
                    let (env, dealers, receivers, key_transcript, _) = bench_context_cell
                        .get_or_init(|| {
                            let env = test_case.new_test_environment(vault_type, rng);
                            let (dealers, receivers) = env.choose_dealers_and_receivers(
                                &IDkgParticipants::AllNodesAsDealersAndReceivers,
                                rng,
                            );
                            let key_transcript = generate_key_transcript(
                                &env,
                                test_case.alg(),
                                &dealers,
                                &receivers,
                                rng,
                            );
                            let transcripts_to_keep: HashSet<_> =
                                vec![key_transcript.clone()].into_iter().collect();
                            (env, dealers, receivers, key_transcript, transcripts_to_keep)
                        });
                    // For this benchmark we need a node which acts as receiver in *all* created transcripts.
                    // This is the case because all nodes in CanisterThresholdSigTestEnvironment act as receivers
                    // and all involved IDkgTranscriptParams include all nodes from CanisterThresholdSigTestEnvironment.
                    let receiver_ref = *receiver_cell.get_or_init(|| {
                        let receiver = env.nodes.random_filtered_by_receivers(receivers, rng);
                        load_transcript_or_panic(receiver, key_transcript);
                        receiver
                    });
                    for _ in 0..num_pre_sig_quadruples {
                        let ecdsa_pre_sig_quadruple = {
                            generate_ecdsa_presig_quadruple(
                                env,
                                dealers,
                                receivers,
                                test_case.alg(),
                                key_transcript,
                                rng,
                            )
                        };
                        load_ecdsa_pre_signature_quadruple(receiver_ref, &ecdsa_pre_sig_quadruple);
                    }
                },
                |()| {
                    let (_, _, _, _, transcripts_to_keep) = bench_context_cell.get().unwrap();
                    retain_active_transcripts(receiver_cell.get().unwrap(), transcripts_to_keep)
                },
                SmallInput,
            )
        },
    );
}

fn bench_verify_complaint<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("verify_complaint_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, context) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    (env, context)
                });
                context.setup_outputs_for_complaint(env, test_case.alg, rng)
            },
            |complaint_context| {
                let IDkgTestContextForComplaint {
                    transcript,
                    complaint,
                    complainer,
                    verifier,
                } = complaint_context;
                verifier
                    .verify_complaint(transcript, complainer.id(), complaint)
                    .expect("failed to verify complaint")
            },
            SmallInput,
        )
    });
}

fn bench_open_transcript<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("open_transcript_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, context) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    (env, context)
                });
                let complaint_context =
                    context.setup_outputs_for_complaint(env, test_case.alg, rng);
                let opener = {
                    env.nodes.random_filtered_by_receivers_excluding(
                        complaint_context.complainer,
                        complaint_context.transcript.receivers.clone(),
                        rng,
                    )
                };
                (complaint_context, opener)
            },
            |(complaint_context, opener)| {
                let IDkgTestContextForComplaint {
                    transcript,
                    complaint,
                    complainer,
                    ..
                } = complaint_context;
                opener
                    .open_transcript(transcript, complainer.id(), complaint)
                    .expect("failed to open transcript")
            },
            SmallInput,
        )
    });
}

fn bench_verify_opening<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("verify_opening_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, context) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    (env, context)
                });
                let complaint_context =
                    context.setup_outputs_for_complaint(env, test_case.alg, rng);
                let IDkgTestContextForComplaint {
                    transcript,
                    complaint,
                    verifier,
                    complainer,
                } = complaint_context;
                let opener = env.nodes.random_filtered_by_receivers_excluding(
                    complainer,
                    transcript.receivers.clone(),
                    rng,
                );
                let opening = opener
                    .open_transcript(&transcript, complainer.id(), &complaint)
                    .expect("Unexpected failure of open_transcript");
                (verifier, transcript, opener.id(), complaint, opening)
            },
            |(verifier, transcript, opener_id, complaint, opening)| {
                verifier
                    .verify_opening(transcript, *opener_id, opening, complaint)
                    .expect("failed to verify opening")
            },
            SmallInput,
        )
    });
}

fn bench_load_transcript_with_openings<M: Measurement, R: RngCore + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    mode: IDkgMode,
    vault_type: VaultType,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function(format!("load_transcript_with_openings_{mode}"), |bench| {
        bench.iter_batched_ref(
            || {
                let (env, context) = bench_context.get_or_init(|| {
                    let env = test_case.new_test_environment(vault_type, rng);
                    let context = IDkgModeTestContext::new(mode, &env, rng);
                    (env, context)
                });
                let complaint_context =
                    context.setup_outputs_for_complaint(env, test_case.alg, rng);
                let reconstruction_threshold = usize::try_from(
                    complaint_context
                        .transcript
                        .reconstruction_threshold()
                        .get(),
                )
                .expect("invalid number");
                let number_of_openings = reconstruction_threshold;
                let complaint_with_openings = generate_and_verify_openings_for_complaint(
                    number_of_openings,
                    &complaint_context.transcript,
                    env,
                    complaint_context.complainer,
                    complaint_context.complaint.clone(),
                );
                (complaint_context, complaint_with_openings)
            },
            |(complaint_context, complaint_with_openings)| {
                complaint_context.complainer.load_transcript_with_openings(
                    &complaint_context.transcript,
                    complaint_with_openings,
                )
            },
            SmallInput,
        )
    });
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

fn verify_transcript_or_panic(
    receiver: &Node,
    params: &IDkgTranscriptParams,
    transcript: &IDkgTranscript,
) {
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

fn load_ecdsa_pre_signature_quadruple(receiver: &Node, quadruple: &EcdsaPreSignatureQuadruple) {
    assert_eq!(
        load_transcript_or_panic(receiver, quadruple.kappa_unmasked()),
        vec![]
    );
    assert_eq!(
        load_transcript_or_panic(receiver, quadruple.lambda_masked()),
        vec![]
    );
    assert_eq!(
        load_transcript_or_panic(receiver, quadruple.kappa_times_lambda()),
        vec![]
    );
    assert_eq!(
        load_transcript_or_panic(receiver, quadruple.key_times_lambda()),
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
    alg: AlgorithmId,
    dealers: &IDkgDealers,
    receivers: &IDkgReceivers,
    rng: &mut R,
) -> IDkgTranscript {
    let unmasked_key_params = setup_unmasked_random_params(env, alg, dealers, receivers, rng);
    run_idkg_without_complaint(&unmasked_key_params, &env.nodes, rng)
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
        _ => nodes.random_filtered_by_receivers_excluding(exclusion, receivers, rng),
    }
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
    fn new_test_environment<R: RngCore + CryptoRng>(
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
            AlgorithmId::ThresholdEd25519 => "ed25519",
            unexpected => panic!("Unexpected testcase algorithm {unexpected}"),
        };
        format!("crypto_idkg_{}_{}_nodes", curve, self.num_of_nodes)
    }

    fn alg(&self) -> AlgorithmId {
        self.alg
    }
}

fn generate_test_cases(node_counts: &[usize]) -> Vec<TestCase> {
    let mut test_cases = vec![];

    // We don't include `AlgorithmId::ThresholdSchnorrBip340` because it uses the same curve
    // as `AlgorithmId::ThresholdEcdsaSecp256k1`, so the results are equivalent.
    let canister_threshold_algs = [
        AlgorithmId::ThresholdEcdsaSecp256k1,
        AlgorithmId::ThresholdEcdsaSecp256r1,
        AlgorithmId::ThresholdEd25519,
    ];

    for num_of_nodes in node_counts.iter().copied() {
        // reduce the number of samples for long-running benchmarks
        let sample_size = if num_of_nodes < 10 { 100 } else { 10 };

        for alg in canister_threshold_algs {
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
