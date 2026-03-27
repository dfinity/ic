use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use ic_ed25519::{PrivateKey, PublicKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xBEEF)
}

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("generate", |b| {
        let mut rng = rng();
        b.iter(|| PrivateKey::generate_using_rng(&mut rng))
    });

    group.bench_function("generate_from_seed", |b| {
        let seed = [42_u8; 32];
        b.iter(|| PrivateKey::generate_from_seed(black_box(&seed)))
    });

    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let sk = PrivateKey::generate_using_rng(&mut rng());
    let msg = [0x42_u8; 32];

    c.bench_function("sign", |b| b.iter(|| sk.sign_message(black_box(&msg))));
}

fn bench_verify(c: &mut Criterion) {
    let sk = PrivateKey::generate_using_rng(&mut rng());
    let pk = sk.public_key();
    let msg = [0x42_u8; 32];
    let sig = sk.sign_message(&msg);

    c.bench_function("verify", |b| {
        b.iter(|| pk.verify_signature(black_box(&msg), black_box(&sig)))
    });
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify");

    for batch_size in [13, 34, 40] {
        for msg_len in [32, 1024, 16 * 1024, 1024 * 1024] {
            let mut key_rng = rng();
            let keys: Vec<PrivateKey> = (0..batch_size)
                .map(|_| PrivateKey::generate_using_rng(&mut key_rng))
                .collect();
            let public_keys: Vec<PublicKey> = keys.iter().map(|k| k.public_key()).collect();
            let messages: Vec<Vec<u8>> = (0..batch_size)
                .map(|i| {
                    let mut m = vec![0_u8; msg_len];
                    m[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    m
                })
                .collect();
            let signatures: Vec<[u8; 64]> = keys
                .iter()
                .zip(messages.iter())
                .map(|(k, m)| k.sign_message(m))
                .collect();

            let messages_ref: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
            let signatures_ref: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();

            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                format!("batch_verify(sigs={},msg_len={})", batch_size, msg_len),
                &(&messages_ref, &signatures_ref, &public_keys),
                |b, (msgs, sigs, pks)| {
                    b.iter_batched(
                        rng,
                        |mut rng| {
                            PublicKey::batch_verify(
                                black_box(msgs),
                                black_box(sigs),
                                black_box(pks),
                                &mut rng,
                            )
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");

    let sk = PrivateKey::generate_using_rng(&mut rng());
    let pk = sk.public_key();

    for depth in [1, 2, 4, 8] {
        let path = ic_ed25519::DerivationPath::new(
            (0..depth)
                .map(|i| ic_ed25519::DerivationIndex(vec![i as u8; 4]))
                .collect(),
        );

        group.bench_with_input(BenchmarkId::new("public_key", depth), &path, |b, path| {
            b.iter(|| pk.derive_subkey(black_box(path)))
        });

        group.bench_with_input(BenchmarkId::new("private_key", depth), &path, |b, path| {
            b.iter(|| sk.derive_subkey(black_box(path)))
        });
    }

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let sk = PrivateKey::generate_using_rng(&mut rng());
    let pk = sk.public_key();

    let pk_raw = pk.serialize_raw();
    let pk_der = pk.serialize_rfc8410_der();
    let sk_raw = sk.serialize_raw();
    let sk_pkcs8 = sk.serialize_pkcs8(ic_ed25519::PrivateKeyFormat::Pkcs8v2);

    group.bench_function("public_key/serialize_raw", |b| {
        b.iter(|| pk.serialize_raw())
    });
    group.bench_function("public_key/deserialize_raw", |b| {
        b.iter(|| PublicKey::deserialize_raw(black_box(&pk_raw)))
    });
    group.bench_function("public_key/serialize_der", |b| {
        b.iter(|| pk.serialize_rfc8410_der())
    });
    group.bench_function("public_key/deserialize_der", |b| {
        b.iter(|| PublicKey::deserialize_rfc8410_der(black_box(&pk_der)))
    });

    group.bench_function("private_key/serialize_raw", |b| {
        b.iter(|| sk.serialize_raw())
    });
    group.bench_function("private_key/deserialize_raw", |b| {
        b.iter(|| PrivateKey::deserialize_raw(black_box(&sk_raw)))
    });
    group.bench_function("private_key/serialize_pkcs8", |b| {
        b.iter(|| sk.serialize_pkcs8(ic_ed25519::PrivateKeyFormat::Pkcs8v2))
    });
    group.bench_function("private_key/deserialize_pkcs8", |b| {
        b.iter(|| PrivateKey::deserialize_pkcs8(black_box(&sk_pkcs8)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_sign,
    bench_verify,
    bench_batch_verify,
    bench_key_derivation,
    bench_serialization,
);
criterion_main!(benches);
