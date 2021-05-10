//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_fs_ni_dkg as dkg;

use dkg::forward_secure::CHUNK_SIZE;
use dkg::nizk_chunking::*;
use dkg::nizk_sharing::{
    prove_sharing, verify_sharing, ProofSharing, SharingInstance, SharingWitness,
    ZkProofSharingError,
};
use dkg::utils::RAND_ChaCha20;
use miracl_core::bls12381::big;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::rom;
use miracl_core::rand::RAND;

fn setup_sharing_instance_and_witness(
    rng: &mut impl RAND,
) -> (Vec<ECP>, Vec<ECP2>, ECP, Vec<ECP>, BIG, Vec<BIG>) {
    let g1 = ECP::generator();
    let g2 = ECP2::generator();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    let mut pk = Vec::new();
    let mut a = Vec::new();
    let mut aa = Vec::new();
    let node_count = 28;
    let threshold = 10;
    for _i in 1..node_count + 1 {
        pk.push(g1.mul(&BIG::randomnum(&spec_p, rng)));
    }
    for _i in 0..threshold {
        let apow = big::BIG::randomnum(&spec_p, rng);
        a.push(apow);
        aa.push(g2.mul(&apow));
    }
    let r = big::BIG::randomnum(&spec_p, rng);
    let rr = g1.mul(&r);
    let mut s = Vec::new();
    // s = [sum [a_k ^ i^k | (a_k, k) <- zip a [0..t-1]] | i <- [1..n]]
    for i in 1..node_count + 1 {
        let ibig = BIG::new_int(i);
        let mut ipow = BIG::new_int(1);
        let mut acc = BIG::new_int(0);
        for ak in &a {
            acc = BIG::modadd(&acc, &BIG::modmul(ak, &ipow, &spec_p), &spec_p);
            ipow = BIG::modmul(&ipow, &ibig, &spec_p);
        }
        s.push(acc);
    }
    let cc: Vec<_> = pk
        .iter()
        .zip(&s)
        .map(|(yi, si)| yi.mul2(&r, &g1, &si))
        .collect();
    (pk, aa, rr, cc, r, s)
}

#[test]
fn sharing_nizk_should_verify() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk,
        public_coefficients: aa,
        combined_randomizer: rr,
        combined_ciphertexts: cc,
    };
    let witness = SharingWitness {
        scalar_r: r,
        scalars_s: s,
    };
    let sharing_proof = prove_sharing(&instance, &witness, rng);
    assert_eq!(
        Ok(()),
        verify_sharing(&instance, &sharing_proof),
        "verify_sharing verifies NIZK proof"
    );
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_empty_coefficients() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (pk, _aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk,
        public_coefficients: vec![],
        combined_randomizer: rr,
        combined_ciphertexts: cc,
    };

    let witness = SharingWitness {
        scalar_r: r,
        scalars_s: s,
    };
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);
    pk.push(ECP::generator());
    let instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk,
        public_coefficients: aa,
        combined_randomizer: rr,
        combined_ciphertexts: cc,
    };

    let witness = SharingWitness {
        scalar_r: r,
        scalars_s: s,
    };
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
fn sharing_nizk_should_fail_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk.clone(),
        public_coefficients: aa.clone(),
        combined_randomizer: rr.clone(),
        combined_ciphertexts: cc.clone(),
    };
    pk.push(ECP::generator());
    let invalid_instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk,
        public_coefficients: aa,
        combined_randomizer: rr,
        combined_ciphertexts: cc,
    };

    let witness = SharingWitness {
        scalar_r: r,
        scalars_s: s,
    };
    let _panic_one = prove_sharing(&instance, &witness, rng);

    let sharing_proof = prove_sharing(&instance, &witness, rng);
    assert_eq!(
        Err(ZkProofSharingError::InvalidInstance),
        verify_sharing(&invalid_instance, &sharing_proof),
        "verify_sharing fails on invalid instance"
    );
}

#[test]
fn sharing_nizk_should_fail_on_invalid_proof() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance {
        g1_gen: ECP::generator(),
        g2_gen: ECP2::generator(),
        public_keys: pk,
        public_coefficients: aa,
        combined_randomizer: rr,
        combined_ciphertexts: cc,
    };

    let witness = SharingWitness {
        scalar_r: r,
        scalars_s: s,
    };
    let _panic_one = prove_sharing(&instance, &witness, rng);

    let sharing_proof = prove_sharing(&instance, &witness, rng);
    let invalid_proof = ProofSharing {
        ff: sharing_proof.ff,
        aa: sharing_proof.aa,
        yy: ECP::generator(),
        z_r: sharing_proof.z_r,
        z_alpha: sharing_proof.z_alpha,
    };
    assert_eq!(
        Err(ZkProofSharingError::InvalidProof),
        verify_sharing(&instance, &invalid_proof),
        "verify_sharing fails on invalid proof"
    );
}

fn setup_chunking_instance_and_witness(rng: &mut impl RAND) -> (ChunkingInstance, ChunkingWitness) {
    let g1 = ECP::generator();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    let n = 28;
    let spec_m = 16;
    let mut y = Vec::new();
    for _i in 1..n + 1 {
        y.push(g1.mul(&BIG::randomnum(&spec_p, rng)));
    }
    let mut r = Vec::new();
    let mut rr = Vec::new();
    for _i in 0..spec_m {
        let r_i = BIG::randomnum(&spec_p, rng);
        rr.push(g1.mul(&r_i));
        r.push(r_i);
    }
    let bb = BIG::new_int(CHUNK_SIZE);
    let mut s = Vec::new();
    let mut chunk = Vec::new();
    for y_i in &y {
        let mut s_i = Vec::new();
        let mut chunk_i = Vec::new();
        for r_j in &r {
            let s_ij = BIG::randomnum(&bb, rng);
            chunk_i.push(y_i.mul2(&r_j, &g1, &s_ij));
            s_i.push(s_ij);
        }
        s.push(s_i);
        chunk.push(chunk_i);
    }

    let instance = ChunkingInstance {
        g1_gen: ECP::generator(),
        public_keys: y,
        ciphertext_chunks: chunk,
        randomizers_r: rr,
    };
    let witness = ChunkingWitness {
        scalars_r: r,
        scalars_s: s,
    };
    (instance, witness)
}

#[test]
fn chunking_nizk_should_verify() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let nizk = prove_chunking(&instance, &witness, rng);
    assert_eq!(
        Ok(()),
        verify_chunking(&instance, &nizk),
        "verify_chunking verifies NIZK proof"
    );
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_empty_chunks() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let invalid_instance = ChunkingInstance {
        g1_gen: instance.g1_gen,
        public_keys: instance.public_keys,
        ciphertext_chunks: vec![],
        randomizers_r: instance.randomizers_r,
    };

    let _panic = prove_chunking(&invalid_instance, &witness, rng);
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut instance, witness) = setup_chunking_instance_and_witness(rng);

    instance.public_keys.push(ECP::generator());

    let _panic = prove_chunking(&instance, &witness, rng);
}

#[test]
fn chunking_nizk_should_fail_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut instance, witness) = setup_chunking_instance_and_witness(rng);

    let valid_instance = ChunkingInstance {
        g1_gen: instance.g1_gen.clone(),
        public_keys: instance.public_keys.clone(),
        ciphertext_chunks: instance.ciphertext_chunks.clone(),
        randomizers_r: instance.randomizers_r.clone(),
    };
    instance.public_keys.push(ECP::generator());
    let invalid_instance = instance;

    let chunking_proof = prove_chunking(&valid_instance, &witness, rng);
    assert_eq!(
        Err(ZkProofChunkingError::InvalidInstance),
        verify_chunking(&invalid_instance, &chunking_proof),
        "verify_chunking fails on invalid instance"
    );
}

#[test]
fn chunking_nizk_should_fail_on_invalid_proof() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let chunking_proof = prove_chunking(&instance, &witness, rng);

    let invalid_proof = ProofChunking {
        y0: ECP::generator(),
        bb: chunking_proof.bb,
        cc: chunking_proof.cc,
        dd: chunking_proof.dd,
        yy: chunking_proof.yy,
        z_r: chunking_proof.z_r,
        z_s: chunking_proof.z_s,
        z_beta: chunking_proof.z_beta,
    };

    assert_eq!(
        Err(ZkProofChunkingError::InvalidProof),
        verify_chunking(&instance, &invalid_proof),
        "verify_chunking fails on invalid proof"
    );
}
