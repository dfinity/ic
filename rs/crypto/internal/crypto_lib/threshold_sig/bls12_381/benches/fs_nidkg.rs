use criterion::*;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::Epoch;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    create_forward_secure_key_pair, update_key_inplace_to_epoch, SecretKey,
};

fn fs_key_generation(c: &mut Criterion) {
    let mut rng = Seed::from_bytes(b"ic-crypto-benchmark-fsnidkg").into_rng();

    let mut group = c.benchmark_group("fs_nidkg");
    group.sample_size(10);

    group.bench_function("create_forward_secure_key_pair", |b| {
        b.iter(|| create_forward_secure_key_pair(Seed::from_rng(&mut rng), b"assoc-data"));
    });

    let mut kpair = SecretKey::deserialize(
        &create_forward_secure_key_pair(Seed::from_rng(&mut rng), b"assoc-data").secret_key,
    );

    let mut epoch = 1;
    let seed = Seed::from_rng(&mut rng);
    group.bench_function("update_key_pair", |b| {
        b.iter(|| {
            epoch += 1;
            update_key_inplace_to_epoch(&mut kpair, Epoch::from(epoch), seed.clone())
        });
    });
}

criterion_group!(benches, fs_key_generation);
criterion_main!(benches);
