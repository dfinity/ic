use criterion::*;
use fs_ni_dkg::nizk_sharing::*;
use fs_ni_dkg::utils::RAND_ChaCha20;
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg;

fn setup_sharing_instance_and_witness() -> (SharingInstance, SharingWitness) {
    const NODE_COUNT: usize = 28;
    const THRESHOLD: usize = 19;

    let mut rng = rand::thread_rng();

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let mut pk = Vec::with_capacity(NODE_COUNT);
    for _ in 0..NODE_COUNT {
        pk.push(G1Affine::from(g1 * Scalar::random(&mut rng)))
    }

    let mut a = Vec::new();
    let mut aa = Vec::new();

    for _ in 0..THRESHOLD {
        let apow = Scalar::random(&mut rng);
        a.push(apow);
        aa.push(G2Affine::from(g2 * apow));
    }

    let mut s = Vec::with_capacity(NODE_COUNT);
    // s = [sum [a_k ^ i^k | (a_k, k) <- zip a [0..t-1]] | i <- [1..n]]
    for i in 1..NODE_COUNT + 1 {
        let ibig = Scalar::from_u64(i as u64);
        let mut ipow = Scalar::one();
        let mut acc = Scalar::zero();
        for ak in &a {
            acc += *ak * ipow;
            ipow *= ibig;
        }
        s.push(acc);
    }

    let r = Scalar::random(&mut rng);
    let rr = G1Affine::from(g1 * r);

    let cc: Vec<_> = pk
        .iter()
        .zip(&s)
        .map(|(yi, si)| G1Projective::mul2(&yi.into(), &r, &g1.into(), si).to_affine())
        .collect();

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);

    (instance, witness)
}

fn zk_sharing_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_nidkg_sharing_proof");

    let (instance, witness) = setup_sharing_instance_and_witness();

    let rng = &mut RAND_ChaCha20::new([42; 32]);

    group.bench_function("prove_sharing", |b| {
        b.iter(|| prove_sharing(&instance, &witness, rng))
    });

    let proof = prove_sharing(&instance, &witness, rng);

    group.bench_function("verify_sharing", |b| {
        b.iter(|| verify_sharing(&instance, &proof))
    });
}

criterion_group!(benches, zk_sharing_proof,);
criterion_main!(benches);
