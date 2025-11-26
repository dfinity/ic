use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main,
};
use ic_base_types::RegistryVersion;
use ic_crypto_test_utils_ni_dkg::{
    NiDkgTestEnvironment, RandomNiDkgConfig, create_dealing, create_dealings, create_transcript,
    load_transcript, retain_only_active_keys, run_ni_dkg_and_create_single_transcript,
    verify_dealing,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::NodeId;
use ic_types::consensus::get_faults_tolerated;
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgDealing, NiDkgTag, NiDkgTranscript, config::NiDkgConfig,
};
use rand::{CryptoRng, Rng};
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};

const WARMUP_TIME: std::time::Duration = std::time::Duration::from_millis(300);

criterion_main!(benches);
criterion_group!(benches, crypto_nidkg_benchmarks,);

fn crypto_nidkg_benchmarks(criterion: &mut Criterion) {
    let rng = &mut reproducible_rng();
    let test_cases = test_cases(&[13, 34, 40]);

    for test_case in test_cases {
        let group = &mut criterion.benchmark_group(test_case.name().to_string());
        group
            .warm_up_time(WARMUP_TIME)
            .sample_size(test_case.sample_size)
            .sampling_mode(test_case.sampling_mode);

        bench_create_initial_dealing(group, &test_case, rng);
        bench_create_reshare_dealing(group, &test_case, rng);
        bench_verify_dealing(group, &test_case, rng);
        bench_create_transcript(group, &test_case, rng);
        bench_load_transcript(group, &test_case, rng);
        bench_retain_keys(group, &test_case, rng);
    }
}

fn test_cases(num_dealers: &[usize]) -> Vec<TestCase> {
    let mut cases = vec![];
    for n in num_dealers {
        cases.push(TestCase::new(*n, NiDkgTag::LowThreshold));
        cases.push(TestCase::new(*n, NiDkgTag::HighThreshold));
    }
    cases
}

fn bench_create_initial_dealing<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function("create_initial_dealing", |bench| {
        bench.iter_batched_ref(
            || {
                let (env, config) = bench_context
                    .get_or_init(|| prepare_create_initial_dealing_test_vectors(test_case, rng));
                (env, config, config.random_dealer_id(rng))
            },
            |(env, config, creator_node_id)| {
                create_dealing(config.get(), &env.crypto_components, *creator_node_id)
            },
            SmallInput,
        )
    });
}

fn bench_create_reshare_dealing<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function("create_reshare_dealing", |bench| {
        bench.iter_batched(
            || {
                let (env, config) = bench_context
                    .get_or_init(|| prepare_create_reshare_dealing_test_vectors(test_case, rng));
                (env, config, config.random_dealer_id(rng))
            },
            |(env, config, creator_node_id)| {
                create_dealing(config.get(), &env.crypto_components, creator_node_id)
            },
            SmallInput,
        )
    });
}

fn bench_verify_dealing<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function("verify_dealing", |bench| {
        bench.iter_batched_ref(
            || {
                let (env, config, dealings) = bench_context
                    .get_or_init(|| prepare_verify_dealing_test_vectors(test_case, rng));
                let (dealer_id, dealing) = dealings
                    .get(rng.random_range(0..test_case.num_of_dealers))
                    .unwrap();

                let receiver_id = config.random_receiver_id(rng);

                (
                    config,
                    &env.crypto_components,
                    *dealer_id,
                    dealing,
                    receiver_id,
                )
            },
            |(config, crypto_components, dealer, dealing, receiver_id)| {
                verify_dealing(
                    config.get(),
                    crypto_components,
                    *dealer,
                    *receiver_id,
                    dealing,
                )
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    group.bench_function("create_transcript", |bench| {
        bench.iter_batched_ref(
            || {
                let (env, config, dealings, creator_node_id) = bench_context
                    .get_or_init(|| prepare_create_transcript_test_vectors(test_case, rng));

                (config, dealings, creator_node_id, &env.crypto_components)
            },
            |(config, dealings, creator_node_id, crypto_components)| {
                create_transcript(config, crypto_components, dealings, **creator_node_id)
            },
            SmallInput,
        )
    });
}

fn bench_load_transcript<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();

    let path = std::path::Path::new("load_transcript_env");

    group.bench_function("load_transcript", |bench| {
        bench.iter_batched_ref(
            || {
                let (env_to_copy, config, transcript_to_load) = bench_context
                    .get_or_init(|| prepare_load_transcript_test_vectors(test_case, rng));

                // clean-up the dir if it exists
                let _ = std::fs::remove_dir_all(path);

                env_to_copy.save_to_dir(path);
                (
                    NiDkgTestEnvironment::new_from_dir_with_remote_vault(path, rng),
                    transcript_to_load.clone(),
                    config.random_receiver_id(rng),
                )
            },
            |(env, transcript, loader_id)| {
                load_transcript(transcript, &env.crypto_components, *loader_id);
            },
            SmallInput,
        )
    });

    // clean-up the dir if the benchmark was enabled
    let _ = std::fs::remove_dir_all(path);
}

/// The complexity of `retain_active_keys` depends on the Hamming distance
/// between the previous and the new registry version. Thus, we perform
/// benchmarks where we set the initial registry version to 3 and increment it
/// by 2^exp. Note that the likelihood of "bigger registry version jumps"
/// continuously descreses in a real deployment.
fn bench_retain_keys<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    test_case: &TestCase,
    rng: &mut R,
) {
    let bench_context = OnceCell::new();
    let path = std::path::Path::new("retain_active_keys_env");

    for exp in [0, 1, 5, 15, 30].iter() {
        group.bench_with_input(
            BenchmarkId::new("retain_active_keys", exp),
            exp,
            |bench, exp| {
                bench.iter_batched(
                    || {
                        let (env_to_copy, config, transcript1, transcript2) = bench_context
                            .get_or_init(|| prepare_retain_keys_test_vectors(test_case, rng));

                        let retainer_node_id = config.random_receiver_id(rng);
                        // clean-up the dir if it exists
                        let _ = std::fs::remove_dir_all(path);
                        env_to_copy.save_to_dir(path);
                        let env = NiDkgTestEnvironment::new_from_dir_with_remote_vault(path, rng);

                        let mut transcripts = HashSet::new();
                        transcripts.insert(transcript1.clone());
                        transcripts.insert(transcript2.clone());

                        transcripts = increment_registry_version(transcripts.clone(), 1);
                        retain_only_active_keys(
                            &env.crypto_components,
                            retainer_node_id,
                            transcripts.clone(),
                        );

                        transcripts = increment_registry_version(transcripts.clone(), 1 << exp);

                        (env, retainer_node_id, transcripts.clone())
                    },
                    |(env, retainer_node_id, transcripts)| {
                        retain_only_active_keys(
                            &env.crypto_components,
                            retainer_node_id,
                            transcripts,
                        )
                    },
                    SmallInput,
                )
            },
        );
    }

    // clean-up the dir if the benchmark was enabled
    let _ = std::fs::remove_dir_all(path);
}

/// Adds `arg` to the registry version of each transcript in `transcript`
fn increment_registry_version(
    mut transcripts: HashSet<NiDkgTranscript>,
    arg: u64,
) -> HashSet<NiDkgTranscript> {
    let mut new_set = HashSet::new();
    for mut t in transcripts.drain() {
        t.registry_version += RegistryVersion::from(arg);
        new_set.insert(t);
    }
    new_set
}

pub struct TestCase {
    pub sample_size: usize,
    pub sampling_mode: SamplingMode,
    pub num_of_nodes: usize,
    pub num_of_dealers: usize,
    pub dkg_tag: NiDkgTag,
}

impl TestCase {
    pub fn name(&self) -> String {
        let tag_name = match self.dkg_tag {
            NiDkgTag::LowThreshold => "low",
            NiDkgTag::HighThreshold => "high",
            NiDkgTag::HighThresholdForKey(_) => unimplemented!(),
        };
        format!(
            "crypto_nidkg_{}_nodes_{}_dealers_{}",
            self.num_of_nodes, self.num_of_dealers, tag_name
        )
    }

    pub fn new(num_of_nodes: usize, dkg_tag: NiDkgTag) -> Self {
        match dkg_tag {
            NiDkgTag::LowThreshold => Self {
                sample_size: 10,
                sampling_mode: SamplingMode::Flat,
                num_of_nodes,
                num_of_dealers: num_of_nodes,
                dkg_tag,
            },
            NiDkgTag::HighThreshold => Self {
                sample_size: 10,
                sampling_mode: SamplingMode::Flat,
                num_of_nodes,
                num_of_dealers: num_of_nodes,
                dkg_tag,
            },
            NiDkgTag::HighThresholdForKey(_) => unimplemented!(),
        }
    }
}

fn retain_only(env: &mut NiDkgTestEnvironment, node_to_retain: &NodeId) {
    env.crypto_components.retain(|k, _| k == node_to_retain);
}

fn prepare_create_reshare_dealing_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (NiDkgTestEnvironment, RandomNiDkgConfig) {
    let config0 = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let mut env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config0.get(), rng);
    let transcript0 =
        run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);
    let config = RandomNiDkgConfig::reshare(transcript0, 0..=0, test_case.num_of_nodes, rng);
    env.update_for_config(config.get(), rng);
    for creator_node_id in config.dealer_ids() {
        load_transcript(
            config
                .get()
                .resharing_transcript()
                .as_ref()
                .expect("we know we have a resharing transcript"),
            &env.crypto_components,
            creator_node_id,
        );
    }

    (env, config)
}

fn prepare_create_initial_dealing_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (NiDkgTestEnvironment, RandomNiDkgConfig) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config.get(), rng);
    (env, config)
}

fn prepare_verify_dealing_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (
    NiDkgTestEnvironment,
    RandomNiDkgConfig,
    Vec<(NodeId, NiDkgDealing)>,
) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config.get(), rng);

    let mut dealers: Vec<_> = config.dealer_ids().drain().collect();
    dealers.sort_unstable();

    let dealings: Vec<_> = dealers
        .into_iter()
        .map(|dealer_id| {
            (
                dealer_id,
                create_dealing(config.get(), &env.crypto_components, dealer_id),
            )
        })
        .collect();

    (env, config, dealings)
}

fn prepare_create_transcript_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (
    NiDkgTestEnvironment,
    NiDkgConfig,
    BTreeMap<NodeId, NiDkgDealing>,
    NodeId,
) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let mut env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config.get(), rng);
    let dealings = create_dealings(config.get(), &env.crypto_components);
    let creator_node_id = config.random_receiver_id(rng);
    retain_only(&mut env, &creator_node_id);

    (env, config.get().to_owned(), dealings, creator_node_id)
}

fn prepare_load_transcript_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (NiDkgTestEnvironment, RandomNiDkgConfig, NiDkgTranscript) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config.get(), rng);
    let transcript = run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

    (env, config, transcript)
}

fn prepare_retain_keys_test_vectors<R: Rng + CryptoRng>(
    test_case: &TestCase,
    rng: &mut R,
) -> (
    NiDkgTestEnvironment,
    RandomNiDkgConfig,
    NiDkgTranscript,
    NiDkgTranscript,
) {
    // Create just the initial remote sharing and transcript (using requested
    // tag/threshold).
    let config0 = RandomNiDkgConfig::builder()
        .subnet_size(test_case.num_of_nodes)
        .dkg_tag(test_case.dkg_tag.clone())
        .dealer_count(test_case.num_of_dealers)
        .registry_version(ic_base_types::RegistryVersion::from(1))
        .max_corrupt_dealers(get_faults_tolerated(test_case.num_of_dealers))
        .build(rng);
    let mut env = NiDkgTestEnvironment::new_for_config_with_remote_vault(config0.get(), rng);
    let transcript0 =
        run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);

    // Reshare locally amongst the same subnet.
    let config1 = RandomNiDkgConfig::reshare(transcript0, 0..=0, test_case.num_of_nodes, rng);
    env.update_for_config(config1.get(), rng);
    let transcript1 =
        run_ni_dkg_and_create_single_transcript(config1.get(), &env.crypto_components);

    // Run an "inverted" DKG,
    // i.e. low if high is requested and high if low is requested
    // (the retain_only_active_keys_for_transcript checks that both
    // high- and low-threshold transcripts are retained)
    let config2 = config1.new_with_inverted_threshold(rng);
    env.update_for_config(config2.get(), rng);
    let transcript2 =
        run_ni_dkg_and_create_single_transcript(config2.get(), &env.crypto_components);

    // We'll retain only the last two transcripts (one high, one low).
    (env, config2, transcript1, transcript2)
}
