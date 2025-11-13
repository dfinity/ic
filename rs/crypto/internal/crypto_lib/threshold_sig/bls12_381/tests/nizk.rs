//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg as dkg;

use dkg::forward_secure::CHUNK_SIZE;
use dkg::nizk_chunking::*;
use dkg::nizk_sharing::{
    ProofSharing, SharingInstance, SharingWitness, ZkProofSharingError, prove_sharing,
    verify_sharing,
};
use dkg::random_oracles::UniqueHash;
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, G2Affine, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::forward_secure::G1Bytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
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

fn assert_expected_scalar(scalar: &Scalar, expected: &'static str) {
    assert_eq!(hex::encode(scalar.serialize()), expected);
}

#[test]
fn sharing_nizk_should_verify() {
    let rng = &mut reproducible_rng();
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let sharing_proof = prove_sharing(&instance, &witness, rng);
    assert_eq!(
        Ok(()),
        verify_sharing(&instance, &sharing_proof),
        "verify_sharing verifies NIZK proof"
    );
}

#[test]
fn sharing_nizk_is_stable() {
    let rng = &mut ChaCha20Rng::from_seed([23; 32]);
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

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

    let sharing_proof = prove_sharing(&instance, &witness, rng);

    assert_eq!(
        Ok(()),
        verify_sharing(&instance, &sharing_proof),
        "verify_sharing verifies NIZK proof"
    );

    let sharing_proof = sharing_proof.serialize();

    assert_eq!(
        hex::encode(sharing_proof.first_move_a),
        "b4dfde1eb1c9166296d1786f616fa46f1e8e32db76eb804d90b9d522567ee8b734a0c7a04ac53019804bff12aef185d01939da55ff87aefd873b73bf81a5d31c12d5284e5afaa15be4e7f262d17607380adf692c64e7c6cfbde7868f0346c43f"
    );

    assert_eq!(
        hex::encode(sharing_proof.first_move_f),
        "868ba5079bba6ad130defd8b287ddbfd9fb9943a85138d0ac8093772efc0227de1d2970911bf6cc7f104952908f6573c"
    );
    assert_eq!(
        hex::encode(sharing_proof.first_move_y),
        "b6b0563c9dffa9e3972db09b9b5b06fc4a4e81dfc7fa39212cce0258a555fc25ffb6a9821c11b23a448283ac499af52a"
    );
    assert_eq!(
        hex::encode(sharing_proof.response_z_a),
        "25628b2e64185161dddea213072df9b27676f59cd95eede58d7ee80afc4ba324"
    );

    assert_eq!(
        hex::encode(sharing_proof.response_z_r),
        "54eb80298bc1d250258153e38a85cc4718e69ccc3e4cb9bfc6540117a036db2d"
    );
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_empty_coefficients() {
    let rng = &mut reproducible_rng();
    let (pk, _aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::new(pk, vec![], rr, cc);
    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
#[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
fn sharing_prover_should_panic_on_invalid_instance() {
    let rng = &mut reproducible_rng();
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);
    pk.push(G1Affine::generator().clone());

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);
}

#[test]
fn sharing_nizk_should_fail_on_invalid_instance() {
    let rng = &mut reproducible_rng();
    let (mut pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::new(pk.clone(), aa.clone(), rr.clone(), cc.clone());

    pk.push(G1Affine::generator().clone());

    let invalid_instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
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
    let rng = &mut reproducible_rng();
    let (pk, aa, rr, cc, r, s) = setup_sharing_instance_and_witness(rng);

    let instance = SharingInstance::new(pk, aa, rr, cc);

    let witness = SharingWitness::new(r, s);
    let _panic_one = prove_sharing(&instance, &witness, rng);

    let sharing_proof = prove_sharing(&instance, &witness, rng).serialize();

    let mut invalid_proof = sharing_proof;
    invalid_proof.first_move_y = G1Bytes(G1Affine::generator().serialize());

    let invalid_proof = ProofSharing::deserialize(&invalid_proof).unwrap();
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
    const NUM_CHUNKS: usize = 16;

    let g1 = G1Affine::generator();

    let mut y = Vec::with_capacity(NODE_COUNT);
    for _ in 0..NODE_COUNT {
        y.push(G1Affine::from(g1 * Scalar::random(rng)));
    }

    let r = Scalar::batch_random_array::<NUM_CHUNKS, R>(rng);
    let rr = g1.batch_mul_array(&r);

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
        s.push(s_i.try_into().expect("Expected size"));
        chunk.push(chunk_i.try_into().expect("Expected size"));
    }

    let instance = ChunkingInstance::new(y, chunk, rr);
    let witness = ChunkingWitness::new(r, s);
    (instance, witness)
}

#[test]
fn chunking_nizk_should_verify() {
    let rng = &mut reproducible_rng();
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
    let rng = &mut reproducible_rng();
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let empty_chunks = vec![];
    let invalid_instance = ChunkingInstance::new(
        instance.public_keys().to_vec(),
        empty_chunks,
        instance.randomizers_r().clone(),
    );

    let _panic = prove_chunking(&invalid_instance, &witness, rng);
}

#[test]
fn chunking_nizk_is_stable() {
    let rng = &mut ChaCha20Rng::from_seed([42; 32]);
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    assert_eq!(
        hex::encode(instance.unique_hash()),
        "6c75186edd23bd24090e76ba0cfcf10f5f01e365810e974590afff6f9cb63623",
    );

    let nizk_cbor =
        serde_cbor::to_vec(&prove_chunking(&instance, &witness, rng).serialize()).unwrap();

    assert_eq!(nizk_cbor.len(), 6942);
    let sha256_nizk_cbor = ic_crypto_sha2::Sha256::hash(&nizk_cbor);
    assert_eq!(
        hex::encode(sha256_nizk_cbor),
        "2fb19b0de6e16fcad55be72669d3d4a6ac26b0c024b059c450aa9ad06502200d",
    );
}

#[test]
#[should_panic(expected = "The chunking proof instance is invalid: InvalidInstance")]
fn chunking_prover_should_panic_on_invalid_instance() {
    let rng = &mut reproducible_rng();
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let mut with_extra_key = instance.public_keys().to_vec();
    with_extra_key.push(G1Affine::generator().clone());

    let invalid_instance = ChunkingInstance::new(
        with_extra_key,
        instance.ciphertext_chunks().to_vec(),
        instance.randomizers_r().clone(),
    );

    let _panic = prove_chunking(&invalid_instance, &witness, rng);
}

#[test]
fn chunking_nizk_should_fail_on_invalid_instance() {
    let rng = &mut reproducible_rng();
    let (instance, witness) = setup_chunking_instance_and_witness(rng);

    let chunking_proof = prove_chunking(&instance, &witness, rng);

    let mut with_extra_key = instance.public_keys().to_vec();
    with_extra_key.push(G1Affine::generator().clone());

    let invalid_instance = ChunkingInstance::new(
        with_extra_key,
        instance.ciphertext_chunks().to_vec(),
        instance.randomizers_r().clone(),
    );

    assert_eq!(
        Err(ZkProofChunkingError::InvalidInstance),
        verify_chunking(&invalid_instance, &chunking_proof),
        "verify_chunking fails on invalid instance"
    );
}

#[test]
fn chunking_nizk_should_fail_on_invalid_proof() {
    use ic_crypto_internal_bls12_381_type::G1Affine;

    let rng = &mut reproducible_rng();
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
