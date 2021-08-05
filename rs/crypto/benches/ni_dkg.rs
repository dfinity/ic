use ic_crypto_test_utils_threshold_sigs::non_interactive::{
    create_dealing, create_dealings, create_transcript, load_transcript, retain_only_active_keys,
    run_ni_dkg_and_create_single_transcript, verify_dealing, NiDkgTestEnvironment,
    RandomNiDkgConfig,
};
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTag;

use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode};

use std::collections::HashSet;

criterion_main!(benches);
criterion_group!(
    benches,
    crypto_nidkg_2_nodes_1_dealer_low,
    crypto_nidkg_4_nodes_3_dealers_high,
    crypto_nidkg_10_nodes_4_dealers_low,
    crypto_nidkg_10_nodes_7_dealers_high,
    crypto_nidkg_28_nodes_19_dealers_high,
);

fn crypto_nidkg_benchmark(
    criterion: &mut Criterion,
    name: &str,
    sample_size: usize,
    sampling_mode: SamplingMode,
    subnet_size: usize,
    num_of_dealers: usize,
    threshold: NiDkgTag,
) {
    let group = &mut criterion.benchmark_group(name);
    group.sample_size(sample_size).sampling_mode(sampling_mode);

    bench_create_initial_dealing_template(group, subnet_size, num_of_dealers, threshold);
    bench_create_reshare_dealing_template(group, subnet_size, num_of_dealers, threshold);
    bench_verify_dealing_template(group, subnet_size, num_of_dealers, threshold);
    bench_create_transcript_template(group, subnet_size, num_of_dealers, threshold);
    bench_load_transcript_template(group, subnet_size, num_of_dealers, threshold);
    bench_retain_keys_template(group, subnet_size, num_of_dealers, threshold);
}

fn crypto_nidkg_2_nodes_1_dealer_low(criterion: &mut Criterion) {
    crypto_nidkg_benchmark(
        criterion,
        "crypto_nidkg_2_nodes_1_dealer_low",
        50,
        SamplingMode::Flat,
        2,
        1,
        NiDkgTag::LowThreshold,
    );
}

fn crypto_nidkg_4_nodes_3_dealers_high(criterion: &mut Criterion) {
    crypto_nidkg_benchmark(
        criterion,
        "crypto_nidkg_4_nodes_3_dealers_high",
        30,
        SamplingMode::Flat,
        4,
        3,
        NiDkgTag::HighThreshold,
    );
}

fn crypto_nidkg_10_nodes_4_dealers_low(criterion: &mut Criterion) {
    crypto_nidkg_benchmark(
        criterion,
        "crypto_nidkg_10_nodes_4_dealers_low",
        10,
        SamplingMode::Flat,
        10,
        4,
        NiDkgTag::LowThreshold,
    );
}

fn crypto_nidkg_10_nodes_7_dealers_high(criterion: &mut Criterion) {
    crypto_nidkg_benchmark(
        criterion,
        "crypto_nidkg_10_nodes_7_dealers_high",
        10,
        SamplingMode::Flat,
        10,
        7,
        NiDkgTag::HighThreshold,
    );
}

fn crypto_nidkg_28_nodes_19_dealers_high(criterion: &mut Criterion) {
    crypto_nidkg_benchmark(
        criterion,
        "crypto_nidkg_28_nodes_19_dealers_high",
        10,
        SamplingMode::Flat,
        28,
        19,
        NiDkgTag::HighThreshold,
    );
}

fn bench_create_initial_dealing_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("create_initial_dealing", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                let config = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config.get());

                let dealer_node_id = config.random_dealer_id();

                (env, config, dealer_node_id)
            },
            |(env, config, dealer_node_id)| {
                create_dealing(config.get(), &env.crypto_components, dealer_node_id);
            },
            SmallInput,
        )
    });
}

fn bench_create_reshare_dealing_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("create_reshare_dealing", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                let config0 = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config0.get());

                let transcript0 =
                    run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);

                let config = RandomNiDkgConfig::reshare(transcript0, 0..=0, num_of_nodes_in_subnet);

                env.update_for_config(config.get());

                let dealer_node_id = config.random_dealer_id();

                (env, config, dealer_node_id)
            },
            |(env, config, dealer_node_id)| {
                create_dealing(config.get(), &env.crypto_components, dealer_node_id);
            },
            SmallInput,
        )
    });
}

fn bench_verify_dealing_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("verify_dealing", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                let config = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config.get());

                let dealer_node_id = config.random_dealer_id();

                let verifier_node_id = config.random_receiver_id();

                let dealing = create_dealing(config.get(), &env.crypto_components, dealer_node_id);

                (env, config, dealer_node_id, verifier_node_id, dealing)
            },
            |(env, config, dealer_node_id, verifier_node_id, dealing)| {
                verify_dealing(
                    config.get(),
                    &env.crypto_components,
                    dealer_node_id,
                    verifier_node_id,
                    &dealing,
                );
            },
            SmallInput,
        )
    });
}

fn bench_create_transcript_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("create_transcript", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                let config = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config.get());

                let dealings = create_dealings(config.get(), &env.crypto_components);

                let creator_node_id = config.random_receiver_id();

                (env, config, dealings, creator_node_id)
            },
            |(env, config, dealings, creator_node_id)| {
                create_transcript(
                    config.get(),
                    &env.crypto_components,
                    &dealings,
                    creator_node_id,
                );
            },
            SmallInput,
        )
    });
}

fn bench_load_transcript_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("load_transcript", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                let config = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config.get());

                let transcript =
                    run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

                let verifier_node_id = config.random_receiver_id();

                (transcript, env, verifier_node_id)
            },
            |(transcript, env, verifier_node_id)| {
                load_transcript(&transcript, &env.crypto_components, verifier_node_id);
            },
            SmallInput,
        )
    });
}

fn bench_retain_keys_template<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    num_of_dealers: usize,
    dkg_tag: NiDkgTag,
) {
    group.bench_function("retain_active_keys", |bench| {
        bench.iter_batched(
            || {
                let mut env = NiDkgTestEnvironment::new();

                // Create just the initial remote sharing and transcript (using requested
                // tag/threshold).
                let config0 = RandomNiDkgConfig::builder()
                    .subnet_size(num_of_nodes_in_subnet)
                    .dkg_tag(dkg_tag)
                    .dealer_count(num_of_dealers)
                    .build();
                env.update_for_config(config0.get());

                let transcript0 =
                    run_ni_dkg_and_create_single_transcript(config0.get(), &env.crypto_components);

                // Reshare locally amongst the same subnet.
                let config1 =
                    RandomNiDkgConfig::reshare(transcript0, 0..=0, num_of_nodes_in_subnet);
                env.update_for_config(config1.get());
                let transcript1 =
                    run_ni_dkg_and_create_single_transcript(config1.get(), &env.crypto_components);

                // Run an "inverted" DKG,
                // i.e. low if high is requested and high if low is requested
                // (the retain_only_active_keys_for_transcript checks that both
                // high- and low-threshold transcripts are retained)
                let config2 = config1.new_with_inverted_threshold();
                env.update_for_config(config2.get());
                let transcript2 =
                    run_ni_dkg_and_create_single_transcript(config2.get(), &env.crypto_components);

                // We'll retain only the last two transcripts (one high, one low).
                let mut retained_transcripts = HashSet::new();
                retained_transcripts.insert(transcript1);
                retained_transcripts.insert(transcript2);

                let retainer_node_id = config2.random_receiver_id();

                (retained_transcripts, env, retainer_node_id)
            },
            |(retained_transcripts, env, retainer_node_id)| {
                retain_only_active_keys(
                    &env.crypto_components,
                    retainer_node_id,
                    retained_transcripts,
                );
            },
            SmallInput,
        )
    });
}
