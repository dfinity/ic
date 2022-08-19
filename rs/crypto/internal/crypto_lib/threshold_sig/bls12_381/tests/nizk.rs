//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg as dkg;

use dkg::forward_secure::CHUNK_SIZE;
use dkg::nizk_chunking::*;
use dkg::nizk_sharing::{
    prove_sharing, verify_sharing, ProofSharing, SharingInstance, SharingWitness,
    ZkProofSharingError,
};
use dkg::random_oracles::UniqueHash;
use dkg::utils::RAND_ChaCha20;
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
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
        let apow = BIG::randomnum(&spec_p, rng);
        a.push(apow);
        aa.push(g2.mul(&apow));
    }
    let r = BIG::randomnum(&spec_p, rng);
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
        .map(|(yi, si)| yi.mul2(&r, &g1, si))
        .collect();
    (pk, aa, rr, cc, r, s)
}

fn assert_expected_g1(pt: &G1Affine, expected: &'static str) {
    assert_eq!(hex::encode(pt.serialize()), expected);
}

fn assert_expected_g2(pt: &G2Affine, expected: &'static str) {
    assert_eq!(hex::encode(pt.serialize()), expected);
}

fn assert_expected_scalar(scalar: &Scalar, expected: &'static str) {
    assert_eq!(hex::encode(scalar.serialize()), expected);
}

#[test]
fn sharing_nizk_should_verify() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::from_miracl(pk, aa, rr, cc);

    let witness = SharingWitness::from_miracl(r, s);
    let sharing_proof = prove_sharing(&instance, &witness, rng);
    assert_eq!(
        Ok(()),
        verify_sharing(&instance, &sharing_proof),
        "verify_sharing verifies NIZK proof"
    );
}

#[test]
fn sharing_nizk_is_stable() {
    let rng = &mut RAND_ChaCha20::new([23; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    assert_expected_scalar(
        &Scalar::from_miracl(&r),
        "4fa6457b6d2e3fb03c251766c0967127b4f9e5ece7d54741187191a88ce0e047",
    );

    let instance = SharingInstance::from_miracl(pk, aa, rr, cc);

    assert_expected_scalar(
        &instance.hash_to_scalar(),
        "63fe81e364eab9c3ceae0c715e31c75e8c4e0dfa96c144f635a2e524326e2ace",
    );

    let witness = SharingWitness::from_miracl(r, s);

    let sharing_proof = prove_sharing(&instance, &witness, rng);

    assert_expected_g2(&sharing_proof.aa,
                       "8a64c96d5e3d4292ef6081a1b849ff70cf0dcb374eaf2149c539ff4e438661a73f1c3c08b7797ac5b926bc1d14cbfb3c183403feb57bea05486542e6f9e377b0f1cf3ca23982ad4b455831bc4a89e5301ce48103f2342fe9e7ec15a73e251088");

    assert_expected_g1(&sharing_proof.ff,
                       "84725ecf07cc1425e3daff4f71612a5cf87e9109499297c8662d322fb51e75090553782927233890bb9de4ce53355845");
    assert_expected_g1(&sharing_proof.yy,
                       "8d46f294d7b13a5ba6590bd4ea7839b29959d3264bda4b8037758e23ff15cdbc7649426e822437db90e9e98835f7ab6f");
    assert_expected_scalar(
        &sharing_proof.z_alpha,
        "06ef8486a4c8284201f3c1bfbba5d2b9a0d0132040eb44b954e7278f66d11ac4",
    );
    assert_expected_scalar(
        &sharing_proof.z_r,
        "13c306c8bf02384c68a78db7ff39069339ef337d0ed146ea791d5cfb46c52cee",
    );

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

    let instance = SharingInstance::from_miracl(pk, vec![], rr, cc);
    let witness = SharingWitness::from_miracl(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);
    pk.push(ECP::generator());

    let instance = SharingInstance::from_miracl(pk, aa, rr, cc);

    let witness = SharingWitness::from_miracl(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
fn sharing_nizk_should_fail_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::from_miracl(pk.clone(), aa.clone(), rr.clone(), cc.clone());

    pk.push(ECP::generator());

    let invalid_instance = SharingInstance::from_miracl(pk, aa, rr, cc);

    let witness = SharingWitness::from_miracl(r, s);
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

    let instance = SharingInstance::from_miracl(pk, aa, rr, cc);

    let witness = SharingWitness::from_miracl(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);

    let sharing_proof = prove_sharing(&instance, &witness, rng);
    let invalid_proof = ProofSharing {
        ff: sharing_proof.ff,
        aa: sharing_proof.aa,
        yy: G1Affine::generator(),
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
            chunk_i.push(y_i.mul2(r_j, &g1, &s_ij));
            s_i.push(s_ij);
        }
        s.push(s_i);
        chunk.push(chunk_i);
    }

    let instance = ChunkingInstance::from_miracl(y, chunk, rr);
    let witness = ChunkingWitness::from_miracl(r, s);
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
    let (mut instance, witness) = setup_chunking_instance_and_witness(rng);

    // invalidate the instance:
    instance.ciphertext_chunks = vec![];

    let _panic = prove_chunking(&instance, &witness, rng);
}

#[test]
fn chunking_nizk_is_stable() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    assert_eq!(
        hex::encode(instance.unique_hash()),
        "d416b0537ed3ff323d508f87bc5d79475ef850026c0333e5bff4ba80286aa3f6"
    );

    let nizk_cbor =
        serde_cbor::to_vec(&prove_chunking(&instance, &witness, rng).serialize()).unwrap();

    assert_eq!(nizk_cbor.len(), 6942);
    let sha256_nizk_cbor = ic_crypto_sha::Sha256::hash(&nizk_cbor);
    assert_eq!(
        hex::encode(&sha256_nizk_cbor),
        "45352f825e1e1f03eee5eae368f6e7ed9e6fad3bb0665c6005a7efdf070ab4f5"
    );
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut instance, witness) = setup_chunking_instance_and_witness(rng);

    instance.public_keys.push(G1Affine::generator());

    let _panic = prove_chunking(&instance, &witness, rng);
}

#[test]
fn chunking_nizk_should_fail_on_invalid_instance() {
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (valid_instance, witness) = setup_chunking_instance_and_witness(rng);

    let mut invalid_instance = valid_instance.clone();
    invalid_instance.public_keys.push(G1Affine::generator());

    let chunking_proof = prove_chunking(&valid_instance, &witness, rng);
    assert_eq!(
        Err(ZkProofChunkingError::InvalidInstance),
        verify_chunking(&invalid_instance, &chunking_proof),
        "verify_chunking fails on invalid instance"
    );
}

#[test]
fn chunking_nizk_should_fail_on_invalid_proof() {
    use ic_crypto_internal_bls12_381_type::G1Affine;

    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let chunking_proof = prove_chunking(&instance, &witness, rng);

    let invalid_proof = {
        let mut zkproof = chunking_proof.serialize();
        zkproof.first_move_y0.0 = G1Affine::generator().serialize();
        ProofChunking::deserialize(&zkproof).expect("Parseable")
    };

    assert_eq!(
        Err(ZkProofChunkingError::InvalidProof),
        verify_chunking(&instance, &invalid_proof),
        "verify_chunking fails on invalid proof"
    );
}
