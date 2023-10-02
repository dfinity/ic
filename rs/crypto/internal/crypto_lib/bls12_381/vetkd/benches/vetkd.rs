use criterion::*;
use ic_crypto_internal_bls12_381_vetkd::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

fn transport_key_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_transport_key");

    let rng = &mut reproducible_rng();

    group.bench_function("TransportSecretKey::generate", |b| {
        b.iter(|| TransportSecretKey::generate(rng))
    });

    group.bench_function("TransportSecretKey::serialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(rng),
            |key| key.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportSecretKey::deserialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(rng).serialize(),
            |key| TransportSecretKey::deserialize(&key),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportSecretKey::public_key", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(rng),
            |key| key.public_key(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportPublicKey::serialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(rng).public_key(),
            |key| key.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportPublicKey::deserialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(rng).public_key().serialize(),
            |key| TransportPublicKey::deserialize(&key),
            BatchSize::SmallInput,
        )
    });
}

fn vetkd_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_vetkd");

    let rng = &mut reproducible_rng();

    let tsk = TransportSecretKey::generate(rng);
    let tpk = tsk.public_key();

    let derivation_path = DerivationPath::new(&[1, 2, 3, 4], &[&[1, 2, 3]]);
    let did = rng.gen::<[u8; 32]>();

    for threshold in [9, 19] {
        let nodes = threshold + threshold / 2;

        let poly = Polynomial::random(threshold, rng);

        let master_sk = poly.coeff(0);
        let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

        let node_id = (rng.gen::<usize>() % nodes) as u32;
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_id));
        let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

        let dpk = DerivedPublicKey::compute_derived_key(&master_pk, &derivation_path);

        if threshold == 9 {
            group.bench_function("EncryptedKeyShare::create", |b| {
                b.iter(|| {
                    EncryptedKeyShare::create(
                        rng,
                        &master_pk,
                        &node_sk,
                        &tpk,
                        &derivation_path,
                        &did,
                    )
                })
            });

            let eks =
                EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &derivation_path, &did);

            group.bench_function("EncryptedKeyShare::serialize", |b| {
                b.iter(|| eks.serialize())
            });

            group.bench_function("EncryptedKeyShare::deserialize", |b| {
                b.iter_batched(
                    || eks.serialize(),
                    EncryptedKeyShare::deserialize,
                    BatchSize::SmallInput,
                )
            });

            group.bench_function("EncryptedKeyShare::is_valid", |b| {
                b.iter(|| eks.is_valid(&master_pk, &node_pk, &derivation_path, &did, &tpk))
            });
        }

        let mut node_info = Vec::with_capacity(nodes);

        for node in 0..nodes {
            let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
            let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

            let eks =
                EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &derivation_path, &did);

            node_info.push((node as u32, node_pk, eks));
        }

        group.bench_function(format!("EncryptedKey::combine (n={})", nodes), |b| {
            b.iter(|| {
                EncryptedKey::combine(
                    &node_info,
                    threshold,
                    &master_pk,
                    &tpk,
                    &derivation_path,
                    &did,
                )
                .unwrap()
            })
        });

        if threshold == 9 {
            let ek = EncryptedKey::combine(
                &node_info,
                threshold,
                &master_pk,
                &tpk,
                &derivation_path,
                &did,
            )
            .unwrap();

            group.bench_function("TransportSecretKey::decrypt", |b| {
                b.iter(|| tsk.decrypt(&ek, &dpk, &did).unwrap())
            });
        }
    }
}

criterion_group!(benches, transport_key_bench, vetkd_bench);
criterion_main!(benches);
