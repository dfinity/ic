use criterion::BatchSize::SmallInput;
use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};

use ic_crypto_test_utils_multi_sigs::MultiSigTestEnvironment;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::{MultiSigVerifier, MultiSigner};
use ic_types::crypto::SignableMock;
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
criterion_main!(benches);
criterion_group!(benches, bench_multi_sig,);

const WARMUP_TIME: std::time::Duration = std::time::Duration::from_millis(300);

fn bench_multi_sig(criterion: &mut Criterion) {
    let signer_counts = vec![1, 10, 50, 100];

    for num_of_signers in signer_counts {
        bench_multi_sig_n_signers(criterion, num_of_signers);
    }
}

fn bench_multi_sig_n_signers(criterion: &mut Criterion, num_of_signers: usize) {
    let group_name = format!("crypto_multi_sig_{num_of_signers}_signers");
    let group = &mut criterion.benchmark_group(group_name);
    group.warm_up_time(WARMUP_TIME);

    let rng = &mut reproducible_rng();

    // Nb. We ensure there's always enough nodes for separate verifier and combiner,
    // just to eliminate any potential cross-talk.
    let env = MultiSigTestEnvironment::new(num_of_signers + 2, rng);

    bench_multi_sig_sign(group, &env, rng);
    bench_multi_sig_verify_individual(group, &env, rng);
    bench_multi_sig_combine(group, &env, num_of_signers, rng);
    bench_multi_sig_verify_combined(group, &env, num_of_signers, rng);
}

fn bench_multi_sig_sign<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    rng: &mut R,
) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("sign_multi", |bench| {
        bench.iter_batched(
            || {
                let (signer_id, signer_crypto) = env.random_node(rng);
                let message = signable_with_random_32_bytes(rng);

                (signer_crypto, signer_id, message)
            },
            |(signer_crypto, signer_id, message)| {
                assert!(
                    signer_crypto
                        .sign_multi(&message, signer_id, env.registry_version)
                        .is_ok()
                );
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_verify_individual<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    rng: &mut R,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one signature share

    group.bench_function("verify_multi_sig_individual", |bench| {
        bench.iter_batched(
            || {
                let (signer_id, signer_crypto) = env.random_node(rng);
                let (_, verifier_crypto) = env.random_node_excluding(&[signer_id], rng);
                let message = signable_with_random_32_bytes(rng);
                let signature = signer_crypto
                    .sign_multi(&message, signer_id, env.registry_version)
                    .expect("failed to generate signature");

                (verifier_crypto, signature, message, signer_id)
            },
            |(verifier_crypto, signature, message, signer_id)| {
                assert!(
                    verifier_crypto
                        .verify_multi_sig_individual(
                            &signature,
                            &message,
                            signer_id,
                            env.registry_version
                        )
                        .is_ok()
                );
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_combine<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    num_of_signers: usize,
    rng: &mut R,
) {
    group.throughput(Throughput::Elements(as_u64(num_of_signers))); // each iteration combines num_of_signers signature shares

    group.bench_function("combine_multi_sig_individuals", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes(rng);
                let (combiner_id, combiner_crypto) = env.random_node(rng);
                let signers = env.choose_multiple_excluding(num_of_signers, &[combiner_id], rng);
                let signatures: BTreeMap<_, _> = signers
                    .iter()
                    .map(|(&signer_id, signer_crypto)| {
                        let signature = signer_crypto
                            .sign_multi(&message, signer_id, env.registry_version)
                            .expect("failed to generate signature");

                        (signer_id, signature)
                    })
                    .collect();
                assert_eq!(signatures.len(), num_of_signers);

                (combiner_crypto, signatures)
            },
            |(combiner_crypto, signatures)| {
                assert!(
                    combiner_crypto
                        .combine_multi_sig_individuals(signatures, env.registry_version)
                        .is_ok()
                );
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_verify_combined<M: Measurement, R: Rng + CryptoRng>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    num_of_signers: usize,
    rng: &mut R,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one combined signature

    group.bench_function("verify_multi_sig_combined", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes(rng);
                let (verifier_id, verifier_crypto) = env.random_node(rng);
                let (combiner_id, combiner_crypto) = env.random_node(rng);
                let signers_map =
                    env.choose_multiple_excluding(num_of_signers, &[combiner_id, verifier_id], rng);
                let combined_signature = {
                    let signatures: BTreeMap<_, _> = signers_map
                        .iter()
                        .map(|(&signer_id, signer_crypto)| {
                            let signature = signer_crypto
                                .sign_multi(&message, signer_id, env.registry_version)
                                .expect("failed to generate signature");

                            (signer_id, signature)
                        })
                        .collect();

                    combiner_crypto
                        .combine_multi_sig_individuals(signatures, env.registry_version)
                        .expect("failed to combine individual signatures")
                };
                let signers: BTreeSet<_> = signers_map.keys().copied().collect();
                assert_eq!(signers.len(), num_of_signers);

                (verifier_crypto, combined_signature, message, signers)
            },
            |(verifier_crypto, combined_signature, message, signers)| {
                assert!(
                    verifier_crypto
                        .verify_multi_sig_combined(
                            &combined_signature,
                            &message,
                            signers,
                            env.registry_version,
                        )
                        .is_ok()
                );
            },
            SmallInput,
        )
    });
}

fn signable_with_random_32_bytes<R: Rng + CryptoRng>(rng: &mut R) -> SignableMock {
    SignableMock::new((0..32).map(|_| rng.r#gen::<u8>()).collect())
}

fn as_u64(usize: usize) -> u64 {
    u64::try_from(usize).expect("failed to convert usize to u64")
}
