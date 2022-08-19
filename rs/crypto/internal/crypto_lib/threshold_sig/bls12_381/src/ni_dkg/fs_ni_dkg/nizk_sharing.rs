//! Proofs of correct sharing
#![allow(clippy::needless_range_loop)]

use crate::ni_dkg::fs_ni_dkg::random_oracles::*;
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ic_crypto_internal_types::curves::bls12_381::{Fr as FrBytes, G1 as G1Bytes, G2 as G2Bytes};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::ZKProofShare;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::rand::RAND;
use std::vec::Vec;

/// Domain separators for the zk proof of sharing
const DOMAIN_PROOF_OF_SHARING_INSTANCE: &str = "ic-zk-proof-of-sharing-instance";
const DOMAIN_PROOF_OF_SHARING_CHALLENGE: &str = "ic-zk-proof-of-sharing-challenge";

/// Instance for a sharing relation.
///
/// From Section 6.4 of the NIDKG paper:
///   instance = (g_1,g_2,[y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
///   g_1 is the generator of G1
///   g_2 is the generator of G2
pub struct SharingInstance {
    g1_gen: G1Affine,
    g2_gen: G2Affine,
    public_keys: Vec<G1Affine>,
    public_coefficients: Vec<G2Affine>,
    combined_randomizer: G1Affine,
    combined_ciphertexts: Vec<G1Affine>,
}

impl SharingInstance {
    pub fn new(
        public_keys: Vec<G1Affine>,
        public_coefficients: Vec<G2Affine>,
        combined_randomizer: G1Affine,
        combined_ciphertexts: Vec<G1Affine>,
    ) -> Self {
        Self {
            g1_gen: G1Affine::generator(),
            g2_gen: G2Affine::generator(),
            public_keys,
            public_coefficients,
            combined_randomizer,
            combined_ciphertexts,
        }
    }

    pub fn from_miracl(
        public_keys: Vec<ECP>,
        public_coeff: Vec<ECP2>,
        combined_randomizer: ECP,
        combined_ctext: Vec<ECP>,
    ) -> Self {
        Self::new(
            public_keys.iter().map(G1Affine::from_miracl).collect(),
            public_coeff.iter().map(G2Affine::from_miracl).collect(),
            G1Affine::from_miracl(&combined_randomizer),
            combined_ctext.iter().map(G1Affine::from_miracl).collect(),
        )
    }
}

/// Witness for the validity of a sharing instance.
///
///   Witness = (r, s= [s_1..s_n])
pub struct SharingWitness {
    scalar_r: Scalar,
    scalars_s: Vec<Scalar>,
}

impl SharingWitness {
    pub fn new(scalar_r: Scalar, scalars_s: Vec<Scalar>) -> Self {
        Self {
            scalar_r,
            scalars_s,
        }
    }

    pub fn from_miracl(scalar_r: BIG, scalars_s: Vec<BIG>) -> Self {
        Self::new(
            Scalar::from_miracl(&scalar_r),
            scalars_s.iter().map(Scalar::from_miracl).collect(),
        )
    }
}

/// Zero-knowledge proof of sharing.
pub struct ProofSharing {
    pub ff: G1Affine,
    pub aa: G2Affine,
    pub yy: G1Affine,
    pub z_r: Scalar,
    pub z_alpha: Scalar,
}

impl ProofSharing {
    /// Convert the sharing proof into a serializable form
    pub fn serialize(&self) -> ZKProofShare {
        ZKProofShare {
            first_move_f: G1Bytes(self.ff.serialize()),
            first_move_a: G2Bytes(self.aa.serialize()),
            first_move_y: G1Bytes(self.yy.serialize()),
            response_z_r: FrBytes(self.z_r.serialize()),
            response_z_a: FrBytes(self.z_alpha.serialize()),
        }
    }

    pub fn deserialize(proof: &ZKProofShare) -> Option<Self> {
        let ff = G1Affine::deserialize(proof.first_move_f.as_bytes());
        let aa = G2Affine::deserialize(proof.first_move_a.as_bytes());
        let yy = G1Affine::deserialize(proof.first_move_y.as_bytes());
        let z_r = Scalar::deserialize(proof.response_z_r.as_bytes());
        let z_alpha = Scalar::deserialize(proof.response_z_a.as_bytes());

        if let (Ok(ff), Ok(aa), Ok(yy), Ok(z_r), Ok(z_alpha)) = (ff, aa, yy, z_r, z_alpha) {
            Some(Self {
                ff,
                aa,
                yy,
                z_r,
                z_alpha,
            })
        } else {
            None
        }
    }
}

/// First move of the prover in the zero-knowledge proof of sharing
struct FirstMoveSharing {
    blinder_g1: G1Affine,
    blinder_g2: G2Affine,
    blinded_instance: G1Affine,
}

/// Creating or verifying a proof of sharing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofSharingError {
    InvalidProof,
    InvalidInstance,
}

impl UniqueHash for SharingInstance {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("g1-generator", &self.g1_gen);
        map.insert_hashed("g2-enerator", &self.g2_gen);
        map.insert_hashed("public-keys", &self.public_keys);
        map.insert_hashed("public-coefficients", &self.public_coefficients);
        map.insert_hashed("combined-randomizers", &self.combined_randomizer);
        map.insert_hashed("combined-ciphertext", &self.combined_ciphertexts);
        map.unique_hash()
    }
}

impl SharingInstance {
    // Computes the hash of the instance.
    pub fn hash_to_scalar(&self) -> Scalar {
        random_oracle_to_scalar(DOMAIN_PROOF_OF_SHARING_INSTANCE, self)
    }
    pub fn check_instance(&self) -> Result<(), ZkProofSharingError> {
        if self.public_keys.is_empty() || self.public_coefficients.is_empty() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        if self.public_keys.len() != self.combined_ciphertexts.len() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        Ok(())
    }
}
impl From<&ProofSharing> for FirstMoveSharing {
    fn from(proof: &ProofSharing) -> Self {
        Self {
            blinder_g1: proof.ff,
            blinder_g2: proof.aa,
            blinded_instance: proof.yy,
        }
    }
}

impl UniqueHash for FirstMoveSharing {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("blinder-g1", &self.blinder_g1);
        map.insert_hashed("blinder-g2", &self.blinder_g2);
        map.insert_hashed("blinded-instance", &self.blinded_instance);
        map.unique_hash()
    }
}

fn sharing_proof_challenge(hashed_instance: &Scalar, first_move: &FirstMoveSharing) -> Scalar {
    let mut map = HashedMap::new();
    map.insert_hashed("instance-hash", hashed_instance);
    map.insert_hashed("first-move", first_move);
    random_oracle_to_scalar(DOMAIN_PROOF_OF_SHARING_CHALLENGE, &map)
}

/// Create a proof of correct sharing
///
/// See section 6.4 of <https://eprint.iacr.org/2021/339.pdf>
pub fn prove_sharing(
    instance: &SharingInstance,
    witness: &SharingWitness,
    rng: &mut impl RAND,
) -> ProofSharing {
    //   instance = ([y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
    //   witness = (r, [s_1..s_n])
    instance
        .check_instance()
        .expect("The sharing proof instance is invalid");
    assert_eq!(instance.public_keys.len(), witness.scalars_s.len());

    // Hash of instance: x = oracle(instance)
    let x = instance.hash_to_scalar();

    let xpow = Scalar::xpowers(&x, witness.scalars_s.len());

    // First move (prover)
    // alpha, rho <- random Z_p
    let alpha = Scalar::miracl_random_using_miracl_rand(rng);
    let rho = Scalar::miracl_random_using_miracl_rand(rng);
    // F = g_1^rho
    // A = g_2^alpha
    // Y = product [y_i^x^i | i <- [1..n]]^rho * g_1^alpha
    let ff = (instance.g1_gen * rho).to_affine();
    let aa = (instance.g2_gen * alpha).to_affine();

    let pk_mul_xi = G1Projective::muln_affine_vartime(&instance.public_keys, &xpow);
    let yy = G1Projective::mul2(&pk_mul_xi, &rho, &instance.g1_gen.into(), &alpha).to_affine();

    let first_move = FirstMoveSharing {
        blinder_g1: ff,
        blinder_g2: aa,
        blinded_instance: yy,
    };

    // Second move (verifier's challenge)
    // x' = oracle(x, F, A, Y)
    let x_challenge = sharing_proof_challenge(&x, &first_move);

    // Third move (prover)
    // z_r = r * x' + rho mod p
    // z_alpha = x' * sum [s_i*x^i | i <- [1..n]] + alpha mod p
    let z_r = witness.scalar_r * x_challenge + rho;

    let terms = witness
        .scalars_s
        .iter()
        .cloned()
        .zip(xpow)
        .collect::<Vec<_>>();
    let z_alpha = Scalar::muln_vartime(&terms) * x_challenge + alpha;

    ProofSharing {
        ff,
        aa,
        yy,
        z_r,
        z_alpha,
    }
}

/// Verify a proof of correct sharing
///
/// See section 6.4 of <https://eprint.iacr.org/2021/339.pdf>
pub fn verify_sharing(
    instance: &SharingInstance,
    nizk: &ProofSharing,
) -> Result<(), ZkProofSharingError> {
    instance.check_instance()?;
    // Hash of Instance
    // x = oracle(instance)
    let x = instance.hash_to_scalar();

    let first_move = FirstMoveSharing::from(nizk);
    // Verifier's challenge
    // x' = oracle(x, F, A, Y)
    let x_challenge = sharing_proof_challenge(&x, &first_move);

    // First verification equation
    // R^x' * F == g_1^z_r
    let lhs = instance.combined_randomizer * x_challenge + first_move.blinder_g1;
    let rhs = instance.g1_gen * nizk.z_r;
    if lhs != rhs {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Second verification equation
    // Verify: product [A_k ^ sum [i^k * x^i | i <- [1..n]] | k <- [0..t-1]]^x' * A
    // == g_2^z_alpha

    let xpow = Scalar::xpowers(&x, instance.public_keys.len());

    let mut xpow_ik = Vec::with_capacity(instance.public_keys.len());
    for i in 1..=instance.public_keys.len() {
        xpow_ik.push((xpow[i - 1], Scalar::one()));
    }

    let mut terms = Vec::with_capacity(instance.public_coefficients.len());
    for pc in &instance.public_coefficients {
        let acc = Scalar::muln_vartime(&xpow_ik);
        terms.push((pc.into(), acc));

        for i in 0..xpow_ik.len() {
            xpow_ik[i].1 *= Scalar::from_u64((i + 1) as u64);
        }
    }
    let lhs = G2Projective::muln_vartime(&terms) * x_challenge + nizk.aa;

    let rhs = instance.g2_gen * nizk.z_alpha;

    if lhs != rhs {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Third verification equation
    // LHS = product [C_i ^ x^i | i <- [1..n]]^x' * Y
    // RHS = product [y_i ^ x^i | i <- 1..n]^z_r * g_1^z_alpha

    let cc_mul_xi = G1Projective::muln_affine_vartime(&instance.combined_ciphertexts, &xpow);
    let lhs = cc_mul_xi * x_challenge + nizk.yy;

    let pk_mul_xi = G1Projective::muln_affine_vartime(&instance.public_keys, &xpow);
    let rhs = G1Projective::mul2(
        &pk_mul_xi,
        &nizk.z_r,
        &instance.g1_gen.into(),
        &nizk.z_alpha,
    );

    if lhs != rhs {
        return Err(ZkProofSharingError::InvalidProof);
    }
    Ok(())
}
