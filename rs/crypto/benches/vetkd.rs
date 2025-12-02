use std::collections::{BTreeMap, BTreeSet};

use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_crypto_temp_crypto::{CryptoComponentRng, TempCryptoComponentGeneric};
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_ni_dkg::{
    NiDkgTestEnvironment, RandomNiDkgConfig, run_ni_dkg_and_create_single_transcript,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::LoadTranscriptResult;
use ic_interfaces::crypto::NiDkgAlgorithm;
use ic_interfaces::crypto::VetKdProtocol;
use ic_management_canister_types_private::{VetKdCurve, VetKdKeyId};
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTranscript};
use ic_types::crypto::vetkd::{VetKdArgs, VetKdDerivationContext, VetKdEncryptedKeyShare};
use ic_types::{NodeId, NumberOfNodes};
use ic_types_test_utils::ids::canister_test_id;
use ic_vetkeys::TransportSecretKey;
use rand::prelude::*;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;

const WARMUP_TIME: std::time::Duration = std::time::Duration::from_millis(300);

criterion_main!(benches);
criterion_group!(benches, vetkd_bench);

fn vetkd_bench(criterion: &mut Criterion) {
    let rng = &mut ReproducibleRng::new();
    let dkg_tag = NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "dummy_key_name".to_string(),
    }));

    let number_of_nodes = [34];
    for subnet_size in number_of_nodes {
        let threshold = dkg_tag.threshold_for_subnet_of_size(subnet_size);

        let group = &mut criterion.benchmark_group(format!(
            "crypto_vetkd_{subnet_size}_nodes_threshold_{threshold}_remote_vault",
        ));

        group.warm_up_time(WARMUP_TIME);

        let (config, env) = setup_with_random_ni_dkg_config(&dkg_tag, subnet_size, rng);
        assert_eq!(config.threshold().get().get(), threshold as u32);

        run_ni_dkg_and_load_transcript_for_receivers(&config, &env);

        bench_create_encrypted_key_share(group, &config, &env, rng);
        bench_verify_encrypted_key_share(group, &config, &env, rng);
        bench_combine_encrypted_key_shares(group, &config, subnet_size, &env, rng);
        if threshold != subnet_size {
            bench_combine_encrypted_key_shares(group, &config, threshold, &env, rng);
        }
        bench_verify_encrypted_key(group, &config, &env, rng);
    }
}

fn bench_create_encrypted_key_share<M: Measurement, C: CryptoComponentRng>(
    group: &mut BenchmarkGroup<'_, M>,
    config: &NiDkgConfig,
    env: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    rng: &mut ReproducibleRng,
) {
    group.bench_function("create_encrypted_key_share", |b| {
        b.iter_batched_ref(
            || {
                let vetkd_args = VetKdArgs {
                    ni_dkg_id: config.dkg_id().clone(),
                    context: random_derivation_context_with_n_bytes(32, rng),
                    input: random_n_bytes(32, rng),
                    transport_public_key: random_transports_secret_key(rng).public_key(),
                };
                let creator = crypto_for(random_node_in(config.receivers().get(), rng), env);
                (creator, vetkd_args)
            },
            |(creator, vetkd_args)| {
                creator
                    .create_encrypted_key_share(vetkd_args.clone())
                    .expect("encrypted key share creation failed")
            },
            SmallInput,
        )
    });
}

fn bench_verify_encrypted_key_share<M: Measurement, C: CryptoComponentRng>(
    group: &mut BenchmarkGroup<'_, M>,
    config: &NiDkgConfig,
    env: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    rng: &mut ReproducibleRng,
) {
    group.bench_function("verify_encrypted_key_share", |b| {
        b.iter_batched_ref(
            || {
                let vetkd_args = VetKdArgs {
                    ni_dkg_id: config.dkg_id().clone(),
                    context: random_derivation_context_with_n_bytes(32, rng),
                    input: random_n_bytes(32, rng),
                    transport_public_key: random_transports_secret_key(rng).public_key(),
                };
                let creator_id = random_node_in(config.receivers().get(), rng);
                let creator = crypto_for(creator_id, env);
                let key_share = creator
                    .create_encrypted_key_share(vetkd_args.clone())
                    .expect("failed to create encrypted key share");
                let verifier = creator;
                (key_share, verifier, creator_id, vetkd_args)
            },
            |(key_share, verifier, creator_id, vetkd_args)| {
                verifier
                    .verify_encrypted_key_share(*creator_id, key_share, vetkd_args)
                    .expect("failed to verify key share")
            },
            SmallInput,
        )
    });
}

fn bench_combine_encrypted_key_shares<M: Measurement, C: CryptoComponentRng>(
    group: &mut BenchmarkGroup<'_, M>,
    config: &NiDkgConfig,
    num_of_shares_to_combine: usize,
    env: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    rng: &mut ReproducibleRng,
) {
    group.bench_function(
        format!("combine_encrypted_key_shares_{num_of_shares_to_combine}"),
        |b| {
            b.iter_batched_ref(
                || {
                    let vetkd_args = VetKdArgs {
                        ni_dkg_id: config.dkg_id().clone(),
                        context: random_derivation_context_with_n_bytes(32, rng),
                        input: random_n_bytes(32, rng),
                        transport_public_key: random_transports_secret_key(rng).public_key(),
                    };
                    let num_of_shares = NumberOfNodes::from(num_of_shares_to_combine as u32);
                    let key_shares = create_and_verify_key_shares_for_each(
                        &n_random_nodes_in(config.receivers().get(), num_of_shares, rng),
                        &vetkd_args,
                        env,
                    );
                    assert_eq!(key_shares.len(), num_of_shares_to_combine);
                    let combiner = crypto_for(random_node_in(config.receivers().get(), rng), env);
                    (key_shares, combiner, vetkd_args)
                },
                |(key_shares, combiner, vetkd_args)| {
                    combiner
                        .combine_encrypted_key_shares(key_shares, vetkd_args)
                        .expect("failed to combine signature shares")
                },
                SmallInput,
            )
        },
    );
}

fn bench_verify_encrypted_key<M: Measurement, C: CryptoComponentRng>(
    group: &mut BenchmarkGroup<'_, M>,
    config: &NiDkgConfig,
    env: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    rng: &mut ReproducibleRng,
) {
    group.bench_function("verify_encrypted_key", |b| {
        b.iter_batched_ref(
            || {
                let vetkd_args = VetKdArgs {
                    ni_dkg_id: config.dkg_id().clone(),
                    context: random_derivation_context_with_n_bytes(32, rng),
                    input: random_n_bytes(32, rng),
                    transport_public_key: random_transports_secret_key(rng).public_key(),
                };
                let num_of_shares = config.threshold().get();
                let key_shares = create_and_verify_key_shares_for_each(
                    &n_random_nodes_in(config.receivers().get(), num_of_shares, rng),
                    &vetkd_args,
                    env,
                );
                let combiner = crypto_for(random_node_in(config.receivers().get(), rng), env);
                let encrypted_key = combiner
                    .combine_encrypted_key_shares(&key_shares, &vetkd_args)
                    .expect("failed to combine signature shares");
                let verifier = combiner;
                (encrypted_key, verifier, vetkd_args)
            },
            |(encrypted_key, verifier, vetkd_args)| {
                verifier
                    .verify_encrypted_key(encrypted_key, vetkd_args)
                    .expect("failed to combine key shares")
            },
            SmallInput,
        )
    });
}

fn setup_with_random_ni_dkg_config<R: Rng + CryptoRng>(
    dkg_tag: &NiDkgTag,
    subnet_size: usize,
    rng: &mut R,
) -> (
    NiDkgConfig,
    BTreeMap<NodeId, TempCryptoComponentGeneric<ChaCha20Rng>>,
) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(subnet_size)
        .dkg_tag(dkg_tag.clone())
        .build(rng)
        .into_config();
    let crypto_components =
        NiDkgTestEnvironment::new_for_config_with_remote_vault(&config, rng).crypto_components;
    (config, crypto_components)
}

fn create_and_verify_key_shares_for_each<C: CryptoComponentRng>(
    key_share_creators: &[NodeId],
    vetkd_args: &VetKdArgs,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> BTreeMap<NodeId, VetKdEncryptedKeyShare> {
    key_share_creators
        .iter()
        .map(|creator| {
            let crypto = crypto_for(*creator, crypto_components);
            let key_share = crypto
                .create_encrypted_key_share(vetkd_args.clone())
                .unwrap_or_else(|e| {
                    panic!("vetKD encrypted key share creation by node {creator:?} failed: {e}")
                });
            assert_eq!(
                crypto.verify_encrypted_key_share(*creator, &key_share, vetkd_args),
                Ok(())
            );
            (*creator, key_share)
        })
        .collect()
}

fn run_ni_dkg_and_load_transcript_for_receivers<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> NiDkgTranscript {
    let transcript = run_ni_dkg_and_create_single_transcript(config, crypto_components);
    load_transcript_for_receivers_expecting_status(
        config,
        &transcript,
        crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );
    transcript
}

fn load_transcript_for_receivers_expecting_status<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    expected_status: Option<LoadTranscriptResult>,
) {
    for node_id in config.receivers().get() {
        let result = crypto_for(*node_id, crypto_components).load_transcript(transcript);

        if result.is_err() {
            panic!(
                "failed to load transcript {} for node {}: {}",
                transcript,
                *node_id,
                result.unwrap_err()
            );
        }

        if let Some(expected_status) = expected_status {
            let result = result.unwrap();
            assert_eq!(result, expected_status);
        }
    }
}

fn random_n_bytes<R: Rng + CryptoRng>(n: u128, rng: &mut R) -> Vec<u8> {
    (0..n).map(|_| rng.r#gen::<u8>()).collect()
}

fn random_node_in<R: Rng + CryptoRng>(nodes: &BTreeSet<NodeId>, rng: &mut R) -> NodeId {
    *nodes.iter().choose(rng).expect("nodes empty")
}

fn n_random_nodes_in<R: Rng + CryptoRng>(
    nodes: &BTreeSet<NodeId>,
    n: NumberOfNodes,
    rng: &mut R,
) -> Vec<NodeId> {
    let n_usize = usize::try_from(n.get()).expect("conversion to usize failed");
    let chosen = nodes.iter().copied().choose_multiple(rng, n_usize);
    assert_eq!(chosen.len(), n_usize);
    chosen
}

fn random_transports_secret_key<R: Rng + CryptoRng>(rng: &mut R) -> TransportSecretKey {
    ic_vetkeys::TransportSecretKey::from_seed(rng.r#gen::<[u8; 32]>().to_vec())
        .expect("failed to create transport secret key")
}

fn random_derivation_context_with_n_bytes<R: Rng + CryptoRng>(
    n: u128,
    rng: &mut R,
) -> VetKdDerivationContext {
    VetKdDerivationContext {
        caller: canister_test_id(rng.r#gen::<u64>()).get(),
        context: random_n_bytes(n, rng),
    }
}
