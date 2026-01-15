use criterion::*;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::Epoch;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    SecretKey, create_forward_secure_key_pair, update_key_inplace_to_epoch,
};

fn fs_key_generation(c: &mut Criterion) {
    let rng = &mut Seed::from_bytes(b"ic-crypto-benchmark-fsnidkg").into_rng();

    let mut group = c.benchmark_group("fs_nidkg");
    group.sample_size(10);

    group.bench_function("create_forward_secure_key_pair", |b| {
        b.iter(|| create_forward_secure_key_pair(Seed::from_rng(rng), b"assoc-data"));
    });

    for stride in [1, 2, 1 << 5, 1 << 15, 1 << 30] {
        group.bench_function(BenchmarkId::new("update_key_pair", stride), |b| {
            b.iter_batched_ref(
                || {
                    let mut kpair = SecretKey::deserialize(
                        &create_forward_secure_key_pair(Seed::from_rng(rng), b"assoc-data")
                            .secret_key,
                    );
                    let epoch = 2;
                    let seed = Seed::from_rng(rng);
                    update_key_inplace_to_epoch(&mut kpair, Epoch::from(epoch), seed.clone());
                    (epoch, kpair, seed)
                },
                |(epoch, kpair, seed)| {
                    *epoch += stride;
                    update_key_inplace_to_epoch(kpair, Epoch::from(*epoch), seed.clone())
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, fs_key_generation);
criterion_main!(benches);
