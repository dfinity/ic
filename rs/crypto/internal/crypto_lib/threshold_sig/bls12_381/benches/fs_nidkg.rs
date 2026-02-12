use criterion::*;
use ic_crypto_internal_bls12_381_type::Scalar;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::*;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::Epoch;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    create_forward_secure_key_pair, update_key_inplace_to_epoch, SecretKey,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng, RngCore};

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

fn setup_keys_and_ciphertext<R: RngCore + CryptoRng>(
    node_count: usize,
    epoch: Epoch,
    associated_data: &[u8],
    rng: &mut R,
) -> (
    Vec<(PublicKeyWithPop, SecretKey)>,
    FsEncryptionCiphertext,
) {
    let sys = SysParam::global();
    let key_gen_assoc_data = rng.r#gen::<[u8; 32]>();

    let mut keys = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        keys.push(kgen(&key_gen_assoc_data, sys, rng));
    }

    let ptext_chunks: Vec<_> = (0..node_count)
        .map(|_| {
            let s = Scalar::random(rng);
            (
                keys[0].0.public_key().clone(), // placeholder, replaced below
                PlaintextChunks::from_scalar(&s),
            )
        })
        .collect();

    let pks_and_chunks: Vec<_> = keys
        .iter()
        .map(|k| k.0.public_key().clone())
        .zip(ptext_chunks.into_iter().map(|(_, c)| c))
        .collect();

    let (crsz, _witness) = enc_chunks(&pks_and_chunks, epoch, associated_data, sys, rng);
    (keys, crsz)
}

fn fs_encrypt_decrypt(c: &mut Criterion) {
    let rng = &mut reproducible_rng();
    let epoch = Epoch::from(0);
    let associated_data = rng.r#gen::<[u8; 32]>();
    let sys = SysParam::global();

    let node_count = 28;
    let (keys, crsz) = setup_keys_and_ciphertext(node_count, epoch, &associated_data, rng);

    let mut group = c.benchmark_group("fs_nidkg_enc_dec");
    group.sample_size(10);

    group.bench_function(
        BenchmarkId::new("enc_chunks", node_count),
        |b| {
            let pks_and_chunks: Vec<_> = keys
                .iter()
                .map(|k| {
                    let s = Scalar::random(rng);
                    (k.0.public_key().clone(), PlaintextChunks::from_scalar(&s))
                })
                .collect();

            b.iter(|| enc_chunks(&pks_and_chunks, epoch, &associated_data, sys, rng))
        },
    );

    group.bench_function("verify_ciphertext_integrity", |b| {
        b.iter(|| verify_ciphertext_integrity(&crsz, epoch, &associated_data, sys))
    });

    group.bench_function("dec_chunks", |b| {
        b.iter(|| dec_chunks(&keys[0].1, 0, &crsz, epoch, &associated_data))
    });
}

criterion_group!(benches, fs_key_generation, fs_encrypt_decrypt);
criterion_main!(benches);
