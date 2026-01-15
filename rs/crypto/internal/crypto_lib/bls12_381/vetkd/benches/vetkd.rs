use criterion::*;
use ic_crypto_internal_bls12_381_type::{Polynomial, Scalar};
use ic_crypto_internal_bls12_381_vetkd::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

fn vetkd_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_vetkd");

    let rng = &mut reproducible_rng();

    let tsk = Scalar::random(rng);
    let tpk =
        TransportPublicKey::deserialize(&(G1Affine::generator() * tsk).to_affine().serialize())
            .unwrap();

    let context = DerivationContext::new(&[1, 2, 3, 4], &[1, 2, 3]);
    let input = rng.r#gen::<[u8; 32]>();

    for threshold in [9, 23] {
        let nodes = threshold + threshold / 2;

        let poly = Polynomial::random(threshold, rng);

        let master_sk = poly.coeff(0);
        let master_pk = G2Affine::from(G2Affine::generator() * master_sk);

        let node_id = (rng.r#gen::<usize>() % nodes) as u32;
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_id));
        let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

        if threshold == 9 {
            group.bench_function("EncryptedKeyShare::create", |b| {
                b.iter(|| {
                    EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &context, &input)
                })
            });

            let eks = EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &context, &input);

            group.bench_function("EncryptedKeyShare::serialize", |b| {
                b.iter(|| eks.serialize())
            });

            group.bench_function("EncryptedKeyShare::deserialize", |b| {
                b.iter_batched(
                    || eks.serialize(),
                    |val| EncryptedKeyShare::deserialize(&val),
                    BatchSize::SmallInput,
                )
            });

            group.bench_function("EncryptedKeyShare::is_valid", |b| {
                b.iter(|| eks.is_valid(&master_pk, &node_pk, &context, &input, &tpk))
            });
        }

        let mut node_info = std::collections::BTreeMap::new();

        for node in 0..nodes {
            let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
            let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

            let eks = EncryptedKeyShare::create(rng, &master_pk, &node_sk, &tpk, &context, &input);

            node_info.insert(node as u32, (node_pk, eks));
        }

        group.bench_function(
            format!("EncryptedKey::combine_valid_shares (n={nodes})"),
            |b| {
                b.iter(|| {
                    EncryptedKey::combine_valid_shares(
                        &node_info, threshold, &master_pk, &tpk, &context, &input,
                    )
                    .unwrap()
                })
            },
        );
    }
}

criterion_group!(benches, vetkd_bench);
criterion_main!(benches);
