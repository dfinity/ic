use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::Rng;

fn zk_proofs(c: &mut Criterion) {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let ad = rng.gen::<[u8; 32]>();

    let seed = Seed::from_bytes(&rng.gen::<[u8; 32]>());

    let secret = EccScalar::random(curve, &mut rng).unwrap();
    let masking = EccScalar::random(curve, &mut rng).unwrap();

    let pedersen = EccPoint::pedersen(&secret, &masking).unwrap();
    let simple = EccPoint::mul_by_g(&secret).unwrap();

    c.bench_function("ProofOfEqualOpenings::create", |b| {
        b.iter(|| zk::ProofOfEqualOpenings::create(seed.clone(), &secret, &masking, &ad).unwrap())
    });

    let proof = zk::ProofOfEqualOpenings::create(seed.clone(), &secret, &masking, &ad).unwrap();

    c.bench_function("ProofOfEqualOpenings::verify", |b| {
        b.iter(|| proof.verify(&pedersen, &simple, &ad).unwrap())
    });

    let lhs = EccScalar::random(curve, &mut rng).unwrap();
    let rhs = EccScalar::random(curve, &mut rng).unwrap();
    let rhs_masking = EccScalar::random(curve, &mut rng).unwrap();
    let product = lhs.mul(&rhs).unwrap();
    let product_masking = EccScalar::random(curve, &mut rng).unwrap();

    c.bench_function("ProofOfProduct::create", |b| {
        b.iter(|| {
            zk::ProofOfProduct::create(
                seed.clone(),
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
        &lhs,
        &rhs,
        &rhs_masking,
        &product,
        &product_masking,
        &ad,
    )
    .unwrap();

    let lhs_c = EccPoint::mul_by_g(&lhs).unwrap();
    let rhs_c = EccPoint::pedersen(&rhs, &rhs_masking).unwrap();
    let product_c = EccPoint::pedersen(&product, &product_masking).unwrap();

    c.bench_function("ProofOfProduct::verify", |b| {
        b.iter(|| proof.verify(&lhs_c, &rhs_c, &product_c, &ad).unwrap());
    });
}

criterion_group!(benches, zk_proofs);
criterion_main!(benches);
