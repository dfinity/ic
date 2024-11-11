use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

fn zk_proofs(c: &mut Criterion) {
    let alg = IdkgProtocolAlgorithm::EcdsaSecp256k1;
    let curve = EccCurveType::K256;
    let rng = &mut reproducible_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_rng(rng);

    let secret = EccScalar::random(curve, rng);
    let masking = EccScalar::random(curve, rng);

    let pedersen = EccPoint::pedersen(&secret, &masking).unwrap();
    let simple = EccPoint::mul_by_g(&secret);

    c.bench_function("ProofOfEqualOpenings::create", |b| {
        b.iter(|| {
            zk::ProofOfEqualOpenings::create(seed.clone(), alg, &secret, &masking, &ad).unwrap()
        })
    });

    let proof =
        zk::ProofOfEqualOpenings::create(seed.clone(), alg, &secret, &masking, &ad).unwrap();

    c.bench_function("ProofOfEqualOpenings::verify", |b| {
        b.iter(|| proof.verify(alg, &pedersen, &simple, &ad).unwrap())
    });

    let lhs = EccScalar::random(curve, rng);
    let rhs = EccScalar::random(curve, rng);
    let rhs_masking = EccScalar::random(curve, rng);
    let product = lhs.mul(&rhs).unwrap();
    let product_masking = EccScalar::random(curve, rng);

    c.bench_function("ProofOfProduct::create", |b| {
        b.iter(|| {
            zk::ProofOfProduct::create(
                seed.clone(),
                alg,
                &lhs,
                &rhs,
                &rhs_masking,
                &product,
                &product_masking,
                &ad,
            )
            .unwrap()
        });
    });

    let proof = zk::ProofOfProduct::create(
        seed.clone(),
        alg,
        &lhs,
        &rhs,
        &rhs_masking,
        &product,
        &product_masking,
        &ad,
    )
    .unwrap();

    let lhs_c = EccPoint::mul_by_g(&lhs);
    let rhs_c = EccPoint::pedersen(&rhs, &rhs_masking).unwrap();
    let product_c = EccPoint::pedersen(&product, &product_masking).unwrap();

    c.bench_function("ProofOfProduct::verify", |b| {
        b.iter(|| proof.verify(alg, &lhs_c, &rhs_c, &product_c, &ad).unwrap());
    });

    let secret = EccScalar::random(curve, rng);
    let base1 = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), b"domain").unwrap();
    let base2 = EccPoint::hash_to_point(curve, &rng.gen::<[u8; 32]>(), b"domain").unwrap();

    c.bench_function("ProofOfDLogEquivalence::create", |b| {
        b.iter(|| {
            zk::ProofOfDLogEquivalence::create(seed.clone(), alg, &secret, &base1, &base2, &ad)
                .unwrap()
        });
    });

    let proof = zk::ProofOfDLogEquivalence::create(seed.clone(), alg, &secret, &base1, &base2, &ad)
        .unwrap();

    let b1s = base1.scalar_mul(&secret).unwrap();
    let b2s = base2.scalar_mul(&secret).unwrap();

    c.bench_function("ProofOfDLogEquivalence::verify", |b| {
        b.iter(|| proof.verify(alg, &base1, &base2, &b1s, &b2s, &ad).unwrap())
    });
}

criterion_group!(benches, zk_proofs);
criterion_main!(benches);
