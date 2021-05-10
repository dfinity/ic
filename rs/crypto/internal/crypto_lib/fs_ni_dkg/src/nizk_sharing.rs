//! Proofs of correct sharing

use crate::random_oracles::*;
use crate::utils::*;
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
    pub g1_gen: ECP,
    pub g2_gen: ECP2,
    pub public_keys: Vec<ECP>,
    pub public_coefficients: Vec<ECP2>,
    pub combined_randomizer: ECP,
    pub combined_ciphertexts: Vec<ECP>,
}

/// Witness for the validity of a sharing instance.
///
///   Witness = (r, s= [s_1..s_n])
pub struct SharingWitness {
    pub scalar_r: BIG,
    pub scalars_s: Vec<BIG>,
}

/// Zero-knowledge proof of sharing.
pub struct ProofSharing {
    pub ff: ECP,
    pub aa: ECP2,
    pub yy: ECP,
    pub z_r: BIG,
    pub z_alpha: BIG,
}

/// First move of the prover in the zero-knowledge proof of sharing
struct FirstMoveSharing {
    pub blinder_g1: ECP,
    pub blinder_g2: ECP2,
    pub blinded_instance: ECP,
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
    pub fn hash_to_scalar(&self) -> BIG {
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
            blinder_g1: proof.ff.to_owned(),
            blinder_g2: proof.aa.to_owned(),
            blinded_instance: proof.yy.to_owned(),
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

fn sharing_proof_challenge(hashed_instance: &BIG, first_move: &FirstMoveSharing) -> BIG {
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
    // Hash of instance: x = oracle(instance)
    let x = instance.hash_to_scalar();

    // First move (prover)
    // alpha, rho <- random Z_p
    let alpha: BIG = BIG::randomnum(&curve_order(), rng);
    let rho: BIG = BIG::randomnum(&curve_order(), rng);
    // F = g_1^rho
    // A = g_2^alpha
    // Y = product [y_i^x^i | i <- [1..n]]^rho * g_1^alpha
    let ff: ECP = instance.g1_gen.mul(&rho);
    let aa: ECP2 = instance.g2_gen.mul(&alpha);
    let mut yy: ECP = instance
        .public_keys
        .iter()
        .rev()
        .fold(ecp_inf(), |mut acc, point| {
            acc.add(&point);
            acc.mul(&x)
        });

    yy = yy.mul2(&rho, &instance.g1_gen, &alpha);

    let first_move = FirstMoveSharing {
        blinder_g1: ff,
        blinder_g2: aa,
        blinded_instance: yy,
    };

    // Second move (verifier's challenge)
    // x' = oracle(x, F, A, Y)
    let x_challenge: BIG = sharing_proof_challenge(&x, &first_move);

    // Third move (prover)
    // z_r = r * x' + rho mod p
    // z_alpha = x' * sum [s_i*x^i | i <- [1..n]] + alpha mod p
    let mut z_r: BIG = field_mul(&witness.scalar_r, &x_challenge);
    z_r = field_add(&z_r, &rho);

    let mut z_alpha: BIG = witness
        .scalars_s
        .iter()
        .rev()
        .fold(big_zero(), |mut acc, scalar| {
            acc = field_add(&acc, &scalar);
            field_mul(&acc, &x)
        });

    z_alpha = field_mul(&z_alpha, &x_challenge);
    z_alpha = field_add(&z_alpha, &alpha);
    ProofSharing {
        ff: first_move.blinder_g1,
        aa: first_move.blinder_g2,
        yy: first_move.blinded_instance,
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
    let x: BIG = instance.hash_to_scalar();

    let first_move = FirstMoveSharing::from(nizk);
    // Verifier's challenge
    // x' = oracle(x, F, A, Y)
    let x_challenge: BIG = sharing_proof_challenge(&x, &first_move);

    // First verification equation
    // R^x' * F == g_1^z_r
    let mut lhs: ECP = instance.combined_randomizer.mul(&x_challenge);
    lhs.add(&first_move.blinder_g1);
    let rhs = instance.g1_gen.mul(&nizk.z_r);
    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Second verification equation
    // Verify: product [A_k ^ sum [i^k * x^i | i <- [1..n]] | k <- [0..t-1]]^x' * A
    // == g_2^z_alpha
    let mut kbig: BIG = big_zero();
    let one: BIG = big_one();
    let mut lhs: ECP2 = ecp2_inf();
    instance.public_coefficients.iter().for_each(|aa_k| {
        let mut acc = big_zero();
        let mut xpow = x;
        let mut ibig = big_one();
        instance.public_keys.iter().for_each(|_| {
            let tmp = field_mul(&ibig.powmod(&kbig, &curve_order()), &xpow);
            acc = field_add(&acc, &tmp);
            xpow = field_mul(&xpow, &x);
            ibig = field_add(&ibig, &one);
        });
        lhs.add(&aa_k.mul(&acc));
        kbig = field_add(&kbig, &one);
    });
    lhs = lhs.mul(&x_challenge);
    lhs.add(&nizk.aa);
    let rhs = instance.g2_gen.mul(&nizk.z_alpha);

    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Third verification equation
    // LHS = product [C_i ^ x^i | i <- [1..n]]^x' * Y
    // RHS = product [y_i ^ x^i | i <- 1..n]^z_r * g_1^z_alpha
    let mut lhs: ECP =
        instance
            .combined_ciphertexts
            .iter()
            .rev()
            .fold(ecp_inf(), |mut acc, point| {
                acc.add(&point);
                acc.mul(&x)
            });
    lhs = lhs.mul(&x_challenge);
    lhs.add(&nizk.yy);

    let mut rhs: ECP = instance
        .public_keys
        .iter()
        .rev()
        .fold(ecp_inf(), |mut acc, point| {
            acc.add(&point);
            acc.mul(&x)
        });
    rhs = rhs.mul2(&nizk.z_r, &instance.g1_gen, &nizk.z_alpha);
    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }
    Ok(())
}
