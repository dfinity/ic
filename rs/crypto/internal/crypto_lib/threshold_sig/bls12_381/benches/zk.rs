use criterion::*;
use fs_ni_dkg::nizk_chunking::*;
use fs_ni_dkg::nizk_sharing::*;
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::CHUNK_SIZE;

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

    let a = Scalar::batch_random(&mut rng, THRESHOLD);
    let aa = G2Affine::batch_mul(g2, &a);

    let mut s = Vec::with_capacity(NODE_COUNT);
    // s = [sum [a_k ^ i^k | (a_k, k) <- zip a [0..t-1]] | i <- [1..n]]
    for i in 1..NODE_COUNT + 1 {
        let ibig = Scalar::from_u64(i as u64);
        let mut ipow = Scalar::one();
        let mut acc = Scalar::zero();
        for ak in &a {
            acc += ak * &ipow;
            ipow *= &ibig;
        }
        s.push(acc);
    }

    let r = Scalar::random(&mut rng);
    let rr = G1Affine::from(g1 * &r);

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

    let mut rng = rand::thread_rng();

    group.bench_function("prove_sharing", |b| {
        b.iter(|| prove_sharing(&instance, &witness, &mut rng))
    });

    let proof = prove_sharing(&instance, &witness, &mut rng);

    group.bench_function("verify_sharing", |b| {
        b.iter(|| verify_sharing(&instance, &proof))
    });
}

fn setup_chunking_instance_and_witness() -> (ChunkingInstance, ChunkingWitness) {
    const NODE_COUNT: usize = 28;
    const THRESHOLD: usize = 19;

    let mut rng = rand::thread_rng();

    let g1 = G1Affine::generator();

    let mut y = Vec::with_capacity(NODE_COUNT);
    for _ in 0..NODE_COUNT {
        y.push(G1Affine::from(g1 * Scalar::random(&mut rng)));
    }

    let r = Scalar::batch_random(&mut rng, THRESHOLD);
    let rr = G1Affine::batch_mul(g1, &r);

    let mut s = Vec::with_capacity(y.len());
    let mut chunk = Vec::new();
    for y_i in &y {
        let mut s_i = Vec::new();
        let mut chunk_i = Vec::new();
        for r_j in &r {
            let s_ij = Scalar::random_within_range(&mut rng, CHUNK_SIZE as u64);
            chunk_i.push(G1Projective::mul2(&y_i.into(), r_j, &g1.into(), &s_ij).to_affine());
            s_i.push(s_ij);
        }
        s.push(s_i);
        chunk.push(chunk_i);
    }

    let instance = ChunkingInstance::new(y, chunk, rr);
    let witness = ChunkingWitness::new(r, s);
    (instance, witness)
}

fn zk_chunking_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_nidkg_chunking_proof");

    let (instance, witness) = setup_chunking_instance_and_witness();

    let mut rng = rand::thread_rng();

    group.bench_function("prove_chunking", |b| {
        b.iter(|| prove_chunking(&instance, &witness, &mut rng))
    });

    let proof = prove_chunking(&instance, &witness, &mut rng);

    group.bench_function("verify_chunking", |b| {
        b.iter(|| verify_chunking(&instance, &proof))
    });
}

criterion_group!(benches, zk_sharing_proof, zk_chunking_proof);
criterion_main!(benches);
