use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto::THRESHOLD_SIG_DATA_STORE_CAPACITY;
use ic_crypto_test_utils_threshold_sigs::non_interactive::{
    load_transcript, run_ni_dkg_and_create_single_transcript, sign_threshold_for_each,
    NiDkgTestEnvironment, RandomNiDkgConfig,
};
use ic_interfaces::crypto::{NiDkgAlgorithm, SignableMock, ThresholdSigVerifier, ThresholdSigner};
use ic_test_utilities::crypto::crypto_for;
use ic_types::consensus::Threshold;
use ic_types::crypto::threshold_sig::ni_dkg::{DkgId, NiDkgId, NiDkgTag, NiDkgTranscript};
use ic_types::{Height, NodeId};
use rand::prelude::*;
use rand::seq::SliceRandom;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::time::Duration;

criterion_main!(benches);
criterion_group!(
    benches,
    bench_threshold_sig_1_node_threshold_1,
    bench_threshold_sig_28_nodes_threshold_10,
    /* CRP-1176
     * bench_threshold_sig_100_nodes_threshold_34, */
);

fn bench_threshold_sig_1_node_threshold_1(criterion: &mut Criterion) {
    let group = &mut criterion.benchmark_group("crypto_threshold_sig_1_node_threshold_1");
    group.sample_size(25);
    bench_threshold_sig_n_nodes(group, 1, 1);
}

fn bench_threshold_sig_28_nodes_threshold_10(criterion: &mut Criterion) {
    let group = &mut criterion.benchmark_group("crypto_threshold_sig_28_nodes_threshold_10");
    group.sample_size(25);
    group.measurement_time(Duration::from_secs(7));
    bench_threshold_sig_n_nodes(group, 28, 10);
}

// CRP-1176: Loading the NI-DKG transcript for all nodes in such a large subnet
// takes too long.
//fn bench_threshold_sig_100_nodes_threshold_34(criterion: &mut Criterion) {
//    let group = &mut
// criterion.benchmark_group("crypto_threshold_sig_100_nodes_threshold_34");
//    group.sample_size(25);
//    group.measurement_time(Duration::from_secs(14));
//    bench_threshold_sig_n_nodes(group, 100, 34);
//}

fn bench_threshold_sig_n_nodes<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    num_of_nodes_in_subnet: usize,
    threshold: Threshold,
) {
    let dkg_tag = dkg_tag(num_of_nodes_in_subnet, threshold);
    let config = RandomNiDkgConfig::builder()
        .dkg_tag(dkg_tag)
        .subnet_size(num_of_nodes_in_subnet)
        .build();
    let env = NiDkgTestEnvironment::new_for_config(config.get());

    let nodes_in_subnet: Vec<_> = config.receiver_ids().iter().copied().collect();

    let transcript = run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);
    for &node_id in &nodes_in_subnet {
        load_transcript(&transcript, &env.crypto_components, node_id);
    }
    let dkg_id = transcript.dkg_id;

    bench_threshold_sign(group, &nodes_in_subnet, &env.crypto_components, dkg_id);
    bench_verify_threshold_sig_share_excl_loading_pubkey(
        group,
        &nodes_in_subnet,
        &env.crypto_components,
        dkg_id,
    );
    bench_verify_threshold_sig_share_incl_loading_pubkey(
        group,
        &nodes_in_subnet,
        &env.crypto_components,
        dkg_id,
        &transcript,
    );
    let threshold_many_random_subnet_nodes = random_nodes(&nodes_in_subnet, threshold);
    bench_combine_threshold_sig_shares(
        group,
        &threshold_many_random_subnet_nodes,
        &env.crypto_components,
        dkg_id,
    );
    bench_verify_threshold_sig_combined(
        group,
        &threshold_many_random_subnet_nodes,
        &env.crypto_components,
        dkg_id,
    );
}

fn bench_threshold_sign<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    nodes_in_subnet: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dkg_id: NiDkgId,
) {
    group.bench_function("threshold_sign", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let signer = crypto_for(random_node(nodes_in_subnet), crypto_components);
                (message, signer)
            },
            |(message, signer)| {
                assert!(signer
                    .sign_threshold(&message, DkgId::NiDkgId(dkg_id))
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_verify_threshold_sig_share_incl_loading_pubkey<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    nodes_in_subnet: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dkg_id: NiDkgId,
    transcript: &NiDkgTranscript,
) {
    group.bench_function("verify_threshold_sig_share_incl_loading_pubkey", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let signer_node_id = random_node(nodes_in_subnet);
                let signer = crypto_for(signer_node_id, crypto_components);
                let sig_share = signer
                    .sign_threshold(&message, DkgId::NiDkgId(dkg_id))
                    .expect("failed to threshold sign");

                let verifier_node_id = random_node(nodes_in_subnet);
                let verifier = crypto_for(verifier_node_id, crypto_components);

                // Because the public key used for verifying signature shares is
                // calculated _lazily_ and then stored in the verifier's threshold
                // signature data store, purge the verifier's data store before
                // performing the benchmark to ensure that the public key is
                // calculated as part of the benchmark. After purging, the
                // transcript is loaded again.
                purge_dkg_id_from_data_store(dkg_id, verifier, transcript);
                load_transcript(transcript, crypto_components, verifier_node_id);

                (sig_share, message, verifier, signer_node_id)
            },
            |(sig_share, message, verifier, signer_node_id)| {
                assert!(verifier
                    .verify_threshold_sig_share(
                        &sig_share,
                        &message,
                        DkgId::NiDkgId(dkg_id),
                        signer_node_id
                    )
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_verify_threshold_sig_share_excl_loading_pubkey<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    nodes_in_subnet: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dkg_id: NiDkgId,
) {
    group.bench_function("verify_threshold_sig_share_excl_loading_pubkey", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let signer_node_id = random_node(nodes_in_subnet);
                let signer = crypto_for(signer_node_id, crypto_components);
                let sig_share = signer
                    .sign_threshold(&message, DkgId::NiDkgId(dkg_id))
                    .expect("failed to threshold sign");
                let verifier = crypto_for(random_node(nodes_in_subnet), crypto_components);

                // Because the public key used for verifying signature shares is
                // calculated _lazily_ and then stored in the verifier's threshold
                // signature data store, verify the signature share once before
                // the benchmark is performed to ensure the public key is available
                // in the data store during the benchmark.
                assert!(verifier
                    .verify_threshold_sig_share(
                        &sig_share,
                        &message,
                        DkgId::NiDkgId(dkg_id),
                        signer_node_id
                    )
                    .is_ok());

                (sig_share, message, verifier, signer_node_id)
            },
            |(sig_share, message, verifier, signer_node_id)| {
                assert!(verifier
                    .verify_threshold_sig_share(
                        &sig_share,
                        &message,
                        DkgId::NiDkgId(dkg_id),
                        signer_node_id
                    )
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_combine_threshold_sig_shares<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    nodes: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dkg_id: NiDkgId,
) {
    group.bench_function("combine_threshold_sig_shares", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let sig_shares =
                    sign_threshold_for_each(nodes, &message, dkg_id, crypto_components);
                let combiner = crypto_for(random_node(nodes), crypto_components);
                (sig_shares, combiner)
            },
            |(sig_shares, combiner)| {
                assert!(combiner
                    .combine_threshold_sig_shares(sig_shares, DkgId::NiDkgId(dkg_id))
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_verify_threshold_sig_combined<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    nodes: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dkg_id: NiDkgId,
) {
    group.bench_function("verify_threshold_sig_combined", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let sig_shares =
                    sign_threshold_for_each(nodes, &message, dkg_id, crypto_components);
                let threshold_sig = crypto_for(random_node(nodes), crypto_components)
                    .combine_threshold_sig_shares(sig_shares, DkgId::NiDkgId(dkg_id))
                    .expect("failed to combine threshold signature shares");
                let verifier = crypto_for(random_node(nodes), crypto_components);
                (threshold_sig, message, verifier)
            },
            |(threshold_sig, message, verifier)| {
                assert!(verifier
                    .verify_threshold_sig_combined(&threshold_sig, &message, DkgId::NiDkgId(dkg_id))
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn random_bytes(n: u128) -> Vec<u8> {
    let rng = &mut thread_rng();
    (0..n).map(|_| rng.gen::<u8>()).collect()
}

fn random_node(nodes: &[NodeId]) -> NodeId {
    let rng = &mut thread_rng();
    *nodes.choose(rng).expect("nodes empty")
}

fn random_nodes(nodes: &[NodeId], n: usize) -> Vec<NodeId> {
    let rng = &mut thread_rng();
    nodes.choose_multiple(rng, n).cloned().collect()
}

/// Purge data for `dkg_id` from threshold sig data store of `node` by loading
/// dummy transcripts derived from `transcript` until the maximum storage
/// capacity is reached.
fn purge_dkg_id_from_data_store(
    dkg_id: NiDkgId,
    node: &TempCryptoComponent,
    transcript: &NiDkgTranscript,
) {
    let mut dummy_transcript = transcript.clone();

    for _i in 1..=THRESHOLD_SIG_DATA_STORE_CAPACITY
        .try_into()
        .expect("overflow")
    {
        dummy_transcript.dkg_id.start_block_height += Height::from(1);
        assert_ne!(dummy_transcript.dkg_id, dkg_id);

        assert!(node.load_transcript(&dummy_transcript).is_ok());
    }
}

fn signable_with_random_32_bytes() -> SignableMock {
    SignableMock::new(random_bytes(32))
}

fn dkg_tag(num_of_nodes_in_subnet: usize, threshold: Threshold) -> NiDkgTag {
    use NiDkgTag::HighThreshold;
    use NiDkgTag::LowThreshold;

    if threshold >= HighThreshold.threshold_for_subnet_of_size(num_of_nodes_in_subnet) {
        HighThreshold
    } else if threshold >= LowThreshold.threshold_for_subnet_of_size(num_of_nodes_in_subnet) {
        LowThreshold
    } else {
        panic!("insufficient nodes in subnet to meet threshold")
    }
}
