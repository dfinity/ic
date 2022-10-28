//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg as dkg;

use dkg::forward_secure::CHUNK_SIZE;
use dkg::nizk_chunking::*;
use dkg::nizk_sharing::{
    prove_sharing, verify_sharing, ProofSharing, SharingInstance, SharingWitness,
    ZkProofSharingError,
};
use dkg::random_oracles::UniqueHash;
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, G2Affine, Scalar};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn setup_sharing_instance_and_witness<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (
    Vec<G1Affine>,
    Vec<G2Affine>,
    G1Affine,
    Vec<G1Affine>,
    Scalar,
    Vec<Scalar>,
) {
    const NODE_COUNT: usize = 28;
    const THRESHOLD: usize = 10;

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let mut pk = Vec::with_capacity(NODE_COUNT);
    for _ in 0..NODE_COUNT {
        pk.push(G1Affine::from(g1 * Scalar::random(rng)));
    }

    let mut a = Vec::new();
    let mut aa = Vec::new();

    for _ in 0..THRESHOLD {
        let apow = Scalar::random(rng);
        a.push(apow.clone());
        aa.push(G2Affine::from(g2 * apow));
    }

    let r = Scalar::random(rng);
    let rr = G1Affine::from(g1 * &r);

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

    let cc: Vec<_> = pk
        .iter()
        .zip(&s)
        .map(|(yi, si)| G1Projective::mul2(&yi.into(), &r, &g1.into(), si).to_affine())
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
    let mut rng = rand::thread_rng();
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let sharing_proof = prove_sharing(&instance, &witness, &mut rng);
    assert_eq!(
        Ok(()),
        verify_sharing(&instance, &sharing_proof),
        "verify_sharing verifies NIZK proof"
    );
}

#[test]
fn sharing_nizk_is_stable() {
    let mut rng = ChaCha20Rng::from_seed([23; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);

    assert_expected_scalar(
        &r,
        "04c66ff4854bff12d8ce0c2a6aa69791812b5dc2e029040fd3f806936516ece3",
    );

    let instance = SharingInstance::new(pk, aa, rr, cc);

    assert_expected_scalar(
        &instance.hash_to_scalar(),
        "6b0c03602490f5963c08a23f00a06b94640cb57fce6589516a5b9dac74bd45cb",
    );

    let witness = SharingWitness::new(r, s);

    let sharing_proof = prove_sharing(&instance, &witness, &mut rng);

    assert_expected_g2(&sharing_proof.aa,
                       "b4dfde1eb1c9166296d1786f616fa46f1e8e32db76eb804d90b9d522567ee8b734a0c7a04ac53019804bff12aef185d01939da55ff87aefd873b73bf81a5d31c12d5284e5afaa15be4e7f262d17607380adf692c64e7c6cfbde7868f0346c43f");

    assert_expected_g1(&sharing_proof.ff,
                       "868ba5079bba6ad130defd8b287ddbfd9fb9943a85138d0ac8093772efc0227de1d2970911bf6cc7f104952908f6573c");
    assert_expected_g1(&sharing_proof.yy,
                       "b6b0563c9dffa9e3972db09b9b5b06fc4a4e81dfc7fa39212cce0258a555fc25ffb6a9821c11b23a448283ac499af52a");
    assert_expected_scalar(
        &sharing_proof.z_alpha,
        "25628b2e64185161dddea213072df9b27676f59cd95eede58d7ee80afc4ba324",
    );
    assert_expected_scalar(
        &sharing_proof.z_r,
        "54eb80298bc1d250258153e38a85cc4718e69ccc3e4cb9bfc6540117a036db2d",
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
    let mut rng = rand::thread_rng();
    let (pk, _aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);

    let instance = SharingInstance::new(pk, vec![], rr, cc);
    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, &mut rng);
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_invalid_instance() {
    let mut rng = rand::thread_rng();
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);
    pk.push(G1Affine::generator().clone());

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, &mut rng);
}

#[test]
fn sharing_nizk_should_fail_on_invalid_instance() {
    let mut rng = rand::thread_rng();
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);

    let instance = SharingInstance::new(pk.clone(), aa.clone(), rr.clone(), cc.clone());

    pk.push(G1Affine::generator().clone());

    let invalid_instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, &mut rng);

    let sharing_proof = prove_sharing(&instance, &witness, &mut rng);
    assert_eq!(
        Err(ZkProofSharingError::InvalidInstance),
        verify_sharing(&invalid_instance, &sharing_proof),
        "verify_sharing fails on invalid instance"
    );
}

#[test]
fn sharing_nizk_should_fail_on_invalid_proof() {
    let mut rng = rand::thread_rng();
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(&mut rng);

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, &mut rng);

    let sharing_proof = prove_sharing(&instance, &witness, &mut rng);
    let invalid_proof = ProofSharing {
        ff: sharing_proof.ff,
        aa: sharing_proof.aa,
        yy: G1Affine::generator().clone(),
        z_r: sharing_proof.z_r,
        z_alpha: sharing_proof.z_alpha,
    };
    assert_eq!(
        Err(ZkProofSharingError::InvalidProof),
        verify_sharing(&instance, &invalid_proof),
        "verify_sharing fails on invalid proof"
    );
}

fn setup_chunking_instance_and_witness<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (ChunkingInstance, ChunkingWitness) {
    const NODE_COUNT: usize = 28;
    const THRESHOLD: usize = 16;

    let g1 = G1Affine::generator();

    let mut y = Vec::with_capacity(NODE_COUNT);
    for _ in 0..NODE_COUNT {
        y.push(G1Affine::from(g1 * Scalar::random(rng)));
    }

    let mut r = Vec::with_capacity(THRESHOLD);
    let mut rr = Vec::with_capacity(THRESHOLD);
    for _ in 0..THRESHOLD {
        let r_i = Scalar::random(rng);
        rr.push(G1Affine::from(g1 * &r_i));
        r.push(r_i);
    }

    let mut s = Vec::with_capacity(y.len());
    let mut chunk = Vec::new();
    for y_i in &y {
        let mut s_i = Vec::new();
        let mut chunk_i = Vec::new();
        for r_j in &r {
            let s_ij = Scalar::random_within_range(rng, CHUNK_SIZE as u64);
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

#[test]
fn chunking_nizk_should_verify() {
    let mut rng = rand::thread_rng();
    let (instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    let nizk = prove_chunking(&instance, &witness, &mut rng);
    assert_eq!(
        Ok(()),
        verify_chunking(&instance, &nizk),
        "verify_chunking verifies NIZK proof"
    );
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_empty_chunks() {
    let mut rng = rand::thread_rng();
    let (mut instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    // invalidate the instance:
    instance.ciphertext_chunks = vec![];

    let _panic = prove_chunking(&instance, &witness, &mut rng);
}

#[test]
fn chunking_nizk_is_stable() {
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    assert_eq!(
        hex::encode(instance.unique_hash()),
        "6c75186edd23bd24090e76ba0cfcf10f5f01e365810e974590afff6f9cb63623",
    );

    let nizk_cbor =
        serde_cbor::to_vec(&prove_chunking(&instance, &witness, &mut rng).serialize()).unwrap();

    assert_eq!(nizk_cbor.len(), 6942);
    let sha256_nizk_cbor = ic_crypto_sha::Sha256::hash(&nizk_cbor);
    assert_eq!(
        hex::encode(&sha256_nizk_cbor),
        "2fb19b0de6e16fcad55be72669d3d4a6ac26b0c024b059c450aa9ad06502200d",
    );
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_invalid_instance() {
    let mut rng = rand::thread_rng();
    let (mut instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    instance.public_keys.push(G1Affine::generator().clone());

    let _panic = prove_chunking(&instance, &witness, &mut rng);
}

#[test]
fn chunking_nizk_should_fail_on_invalid_instance() {
    let mut rng = rand::thread_rng();
    let (valid_instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    let mut invalid_instance = valid_instance.clone();
    invalid_instance
        .public_keys
        .push(G1Affine::generator().clone());

    let chunking_proof = prove_chunking(&valid_instance, &witness, &mut rng);
    assert_eq!(
        Err(ZkProofChunkingError::InvalidInstance),
        verify_chunking(&invalid_instance, &chunking_proof),
        "verify_chunking fails on invalid instance"
    );
}

#[test]
fn chunking_nizk_should_fail_on_invalid_proof() {
    use ic_crypto_internal_bls12_381_type::G1Affine;

    let mut rng = rand::thread_rng();
    let (instance, witness) = setup_chunking_instance_and_witness(&mut rng);

    let chunking_proof = prove_chunking(&instance, &witness, &mut rng);

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
