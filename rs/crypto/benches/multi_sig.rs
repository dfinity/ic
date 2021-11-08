use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};

use ic_crypto_test_utils_multi_sigs::MultiSigTestEnvironment;
use ic_interfaces::crypto::{MultiSigVerifier, MultiSigner, SignableMock};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

criterion_main!(benches);
criterion_group!(benches, bench_multi_sig,);

fn bench_multi_sig(criterion: &mut Criterion) {
    let signer_counts = vec![1, 10, 50, 100];

    for num_of_signers in signer_counts {
        bench_multi_sig_n_signers(criterion, num_of_signers);
    }
}

fn bench_multi_sig_n_signers(criterion: &mut Criterion, num_of_signers: usize) {
    let group_name = format!("crypto_multi_sig_{}_signers", num_of_signers);
    let group = &mut criterion.benchmark_group(group_name);

    // Nb. We ensure there's always enough nodes for separate verifier and combiner,
    // just to eliminate any potential cross-talk.
    let env = MultiSigTestEnvironment::new(num_of_signers + 2);

    bench_multi_sig_sign(group, &env);
    bench_multi_sig_verify_individual(group, &env);
    bench_multi_sig_combine(group, &env, num_of_signers);
    bench_multi_sig_verify_combined(group, &env, num_of_signers);
}

fn bench_multi_sig_sign<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration signs one message

    group.bench_function("sign_multi", |bench| {
        bench.iter_batched(
            || {
                let (signer_id, signer_crypto) = env.random_node();
                let message = signable_with_random_32_bytes();

                (signer_crypto, signer_id, message)
            },
            |(signer_crypto, signer_id, message)| {
                assert!(signer_crypto
                    .sign_multi(&message, signer_id, env.registry_version)
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_verify_individual<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one signature share

    group.bench_function("verify_multi_sig_individual", |bench| {
        bench.iter_batched(
            || {
                let (signer_id, signer_crypto) = env.random_node();
                let (_, verifier_crypto) = env.random_node_excluding(&[signer_id]);
                let message = signable_with_random_32_bytes();
                let signature = signer_crypto
                    .sign_multi(&message, signer_id, env.registry_version)
                    .expect("failed to generate signature");

                (verifier_crypto, signature, message, signer_id)
            },
            |(verifier_crypto, signature, message, signer_id)| {
                assert!(verifier_crypto
                    .verify_multi_sig_individual(
                        &signature,
                        &message,
                        signer_id,
                        env.registry_version
                    )
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_combine<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    num_of_signers: usize,
) {
    group.throughput(Throughput::Elements(as_u64(num_of_signers))); // each iteration combines num_of_signers signature shares

    group.bench_function("combine_multi_sig_individuals", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let (combiner_id, combiner_crypto) = env.random_node();
                let signers = env.choose_multiple_excluding(num_of_signers, &[combiner_id]);
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
                assert!(combiner_crypto
                    .combine_multi_sig_individuals(signatures, env.registry_version)
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn bench_multi_sig_verify_combined<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    env: &MultiSigTestEnvironment,
    num_of_signers: usize,
) {
    group.throughput(Throughput::Elements(1)); // each iteration verifies one combined signature

    group.bench_function("verify_multi_sig_combined", |bench| {
        bench.iter_batched(
            || {
                let message = signable_with_random_32_bytes();
                let (verifier_id, verifier_crypto) = env.random_node();
                let (combiner_id, combiner_crypto) = env.random_node();
                let signers_map =
                    env.choose_multiple_excluding(num_of_signers, &[combiner_id, verifier_id]);
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
                assert!(verifier_crypto
                    .verify_multi_sig_combined(
                        &combined_signature,
                        &message,
                        signers,
                        env.registry_version,
                    )
                    .is_ok());
            },
            SmallInput,
        )
    });
}

fn signable_with_random_32_bytes() -> SignableMock {
    fn random_bytes(n: u128) -> Vec<u8> {
        let rng = &mut thread_rng();
        (0..n).map(|_| rng.gen::<u8>()).collect()
    }

    SignableMock::new(random_bytes(32))
}

fn as_u64(usize: usize) -> u64 {
    use std::convert::TryFrom;

    u64::try_from(usize).expect("failed to convert usize to u64")
}
