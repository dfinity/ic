//! Proofs of correct chunking

use crate::forward_secure::CHUNK_SIZE;
use crate::random_oracles::{random_oracle, random_oracle_to_scalar, HashedMap, UniqueHash};
use crate::utils::*;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::rom;
use miracl_core::rand::RAND;
use std::vec::Vec;

/// Domain separators for the zk proof of chunking
const DOMAIN_PROOF_OF_CHUNKING_ORACLE: &str = "ic-zk-proof-of-chunking-chunking";
const DOMAIN_PROOF_OF_CHUNKING_CHALLENGE: &str = "ic-zk-proof-of-chunking-challenge";

const SECURITY_LEVEL: usize = 256;

/// The number of parallel proofs handled by one challenge
///
/// In Section 6.5 of <https://eprint.iacr.org/2021/339.pdf> this
/// value is referred to as `l`
pub const NUM_ZK_REPETITIONS: usize = 32;

/// Defined as ceil(SECURITY_LEVEL/NUM_ZK_REPETITIONS)
pub const CHALLENGE_BITS: usize = (SECURITY_LEVEL + NUM_ZK_REPETITIONS - 1) / NUM_ZK_REPETITIONS;

/// Instance for a chunking relation.
///
/// From Section 6.5 of the NIDKG paper.
///   instance = (y=[y_1..y_n], C=[chunk_{1,1}..chunk_{n,m}], R=[R_1,..R_m])
/// We rename:
///   y -> public_keys.
///   C_{i,j} -> ciphertext_chunks.
///   R -> randomizers_r
pub struct ChunkingInstance {
    pub g1_gen: ECP,
    pub public_keys: Vec<ECP>,
    //This should be Vec<[ECP; NUM_CHUNKS]>
    pub ciphertext_chunks: Vec<Vec<ECP>>,
    //This should have size NUM_CHUNKS
    pub randomizers_r: Vec<ECP>,
}

/// Witness for the validity of a chunking instance.
///
/// From Section 6.5 of the NIDKG paper:
///   Witness = (scalar_r =[r_1..r_m], scalar_s=[s_{1,1}..s_{n,m}])
pub struct ChunkingWitness {
    //This should have size NUM_CHUNKS
    pub scalars_r: Vec<BIG>,
    //This should be Vec<[BIG; NUM_CHUNKS]>
    pub scalars_s: Vec<Vec<BIG>>,
}

/// Creating or verifying a proof of correct chunking failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofChunkingError {
    InvalidProof,
    InvalidInstance,
}

/// Zero-knowledge proof of chunking.
pub struct ProofChunking {
    pub y0: ECP,
    pub bb: Vec<ECP>,
    pub cc: Vec<ECP>,
    pub dd: Vec<ECP>,
    pub yy: ECP,
    pub z_r: Vec<BIG>,
    pub z_s: Vec<BIG>,
    pub z_beta: BIG,
}

/// First move of the prover in the zero-knowledge proof of chunking.
struct FirstMoveChunking {
    pub y0: ECP,
    pub bb: Vec<ECP>,
    pub cc: Vec<ECP>,
}

/// Prover's response to the first challenge of the verifier.
struct SecondMoveChunking {
    pub z_s: Vec<BIG>,
    pub dd: Vec<ECP>,
    pub yy: ECP,
}

impl ChunkingInstance {
    pub fn check_instance(&self) -> Result<(), ZkProofChunkingError> {
        if self.public_keys.is_empty()
            || self.ciphertext_chunks.is_empty()
            || self.randomizers_r.is_empty()
        {
            return Err(ZkProofChunkingError::InvalidInstance);
        };
        if self.public_keys.len() != self.ciphertext_chunks.len() {
            return Err(ZkProofChunkingError::InvalidInstance);
        };
        Ok(())
    }
}

impl FirstMoveChunking {
    fn from(y0: &ECP, bb: &[ECP], cc: &[ECP]) -> Self {
        Self {
            y0: y0.to_owned(),
            bb: bb.to_owned(),
            cc: cc.to_owned(),
        }
    }
}

impl SecondMoveChunking {
    fn from(z_s: &[BIG], dd: &[ECP], yy: &ECP) -> Self {
        Self {
            z_s: z_s.to_owned(),
            dd: dd.to_owned(),
            yy: yy.to_owned(),
        }
    }
}

impl UniqueHash for ChunkingInstance {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("g1-generator", &self.g1_gen);
        map.insert_hashed("public-keys", &self.public_keys);
        map.insert_hashed("ciphertext-chunks", &self.ciphertext_chunks);
        map.insert_hashed("randomizers-r", &self.randomizers_r);
        map.unique_hash()
    }
}

impl UniqueHash for FirstMoveChunking {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("y0", &self.y0);
        map.insert_hashed("bb", &self.bb);
        map.insert_hashed("cc", &self.cc);
        map.unique_hash()
    }
}

impl UniqueHash for SecondMoveChunking {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("z_s", &self.z_s);
        map.insert_hashed("dd", &self.dd);
        map.insert_hashed("yy", &self.yy);
        map.unique_hash()
    }
}

/// Create a proof of correct chunking
pub fn prove_chunking(
    instance: &ChunkingInstance,
    witness: &ChunkingWitness,
    rng: &mut impl RAND,
) -> ProofChunking {
    instance
        .check_instance()
        .expect("The chunking proof instance is invalid");
    let g1 = instance.g1_gen.clone();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    // y0 <- getRandomG1
    let y0 = g1.mul(&BIG::randomnum(&spec_p, rng));
    let spec_m = instance.randomizers_r.len();
    let spec_n = instance.public_keys.len();
    // Rename `B` to `bb_constant` to distinguish it from `B_i`.
    let bb_constant = CHUNK_SIZE as usize;
    let ee = 1 << CHALLENGE_BITS;
    let ss = spec_n * spec_m * (bb_constant - 1) * (ee - 1);
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let range = zz - 1 + ss + 1;
    let range_big = BIG::new_int(range as isize);
    let zz_big = BIG::new_int(zz as isize);
    let mut p_sub_s = BIG::new_int(ss as isize);
    p_sub_s.rsub(&spec_p);
    // sigma = replicateM NUM_ZK_REPETITIONS $ getRandom [-S..Z-1]
    // beta = replicateM NUM_ZK_REPETITIONS $ getRandom [0..p-1]
    // bb = map (g1^) beta
    // cc = zipWith (\x pk -> y0^x * g1^pk) beta sigma
    let beta: Vec<BIG> = (0..NUM_ZK_REPETITIONS)
        .map(|_| BIG::randomnum(&spec_p, rng))
        .collect();
    let bb: Vec<ECP> = beta.iter().map(|beta_i| g1.mul(&beta_i)).collect();
    let (first_move, first_challenge, z_s) = loop {
        let sigma: Vec<BIG> = (0..NUM_ZK_REPETITIONS)
            .map(|_| BIG::modadd(&BIG::randomnum(&range_big, rng), &p_sub_s, &spec_p))
            .collect();
        let cc: Vec<ECP> = beta
            .iter()
            .zip(&sigma)
            .map(|(beta_i, sigma_i)| y0.mul2(&beta_i, &g1, &sigma_i))
            .collect();

        let first_move = FirstMoveChunking::from(&y0, &bb, &cc);
        // Verifier's challenge.
        let first_challenge =
            ChunksOracle::new(&instance, &first_move).get_all_chunks(spec_n, spec_m);

        // z_s = [sum [e_ijk * s_ij | i <- [1..n], j <- [1..m]] + sigma_k | k <- [1..l]]
        let z_s: Result<Vec<BIG>, ()> = (0..NUM_ZK_REPETITIONS)
            .map(|k| {
                let mut acc = BIG::new_int(0);
                first_challenge
                    .iter()
                    .zip(witness.scalars_s.iter())
                    .for_each(|(e_i, s_i)| {
                        e_i.iter().zip(s_i.iter()).for_each(|(e_ij, s_ij)| {
                            acc = BIG::modadd(
                                &acc,
                                &BIG::modmul(&BIG::new_int(e_ij[k] as isize), &s_ij, &spec_p),
                                &spec_p,
                            );
                        });
                    });
                acc = BIG::modadd(&acc, &sigma[k], &spec_p);
                acc.norm();

                if BIG::comp(&acc, &zz_big) >= 0 {
                    Err(())
                } else {
                    Ok(acc)
                }
            })
            .collect();

        if let Ok(z_s) = z_s {
            break (first_move, first_challenge, z_s);
        }
    };

    // delta <- replicate (n + 1) getRandom
    // dd = map (g1^) delta
    // Y = product [y_i^delta_i | i <- [0..n]]
    let mut delta = Vec::new();
    let mut dd = Vec::new();
    let mut yy = ECP::new();
    for i in 0..spec_n + 1 {
        let delta_i = BIG::randomnum(&spec_p, rng);
        dd.push(g1.mul(&delta_i));
        if i == 0 {
            yy = y0.mul(&delta_i);
        } else {
            yy.add(&instance.public_keys[i - 1].mul(&delta_i));
        }
        delta.push(delta_i);
    }

    let second_move = SecondMoveChunking::from(&z_s, &dd, &yy);

    // Second verifier's challege. Forth move in the protocol.
    // x = oracle(e, z_s, dd, yy)
    let second_challenge = chunking_proof_challenge_oracle(&first_challenge, &second_move);

    let mut z_r = Vec::new();
    let mut delta_idx = 1;
    for e_i in first_challenge.iter() {
        let mut z_rk = delta[delta_idx];
        delta_idx += 1;
        e_i.iter()
            .zip(witness.scalars_r.iter())
            .for_each(|(e_ij, r_j)| {
                let mut xpow = second_challenge;
                e_ij.iter().for_each(|e_ijk| {
                    z_rk = BIG::modadd(
                        &z_rk,
                        &BIG::modmul(
                            &BIG::modmul(&BIG::new_int(*e_ijk as isize), &r_j, &spec_p),
                            &xpow,
                            &spec_p,
                        ),
                        &spec_p,
                    );
                    xpow = BIG::modmul(&xpow, &second_challenge, &spec_p);
                })
            });
        z_r.push(z_rk);
    }

    let mut xpow = second_challenge;
    let mut z_beta = delta[0];
    beta.iter().for_each(|beta_k| {
        z_beta = BIG::modadd(&z_beta, &BIG::modmul(&beta_k, &xpow, &spec_p), &spec_p);
        xpow = BIG::modmul(&xpow, &second_challenge, &spec_p);
    });
    ProofChunking {
        y0: first_move.y0,
        bb: first_move.bb,
        cc: first_move.cc,
        dd,
        yy,
        z_r,
        z_s,
        z_beta,
    }
}

/// Verify a proof of correct chunking
pub fn verify_chunking(
    instance: &ChunkingInstance,
    nizk: &ProofChunking,
) -> Result<(), ZkProofChunkingError> {
    instance.check_instance()?;

    let g1 = instance.g1_gen.clone();
    let num_receivers = instance.public_keys.len();
    require_eq("bb", nizk.bb.len(), NUM_ZK_REPETITIONS)?;
    require_eq("cc", nizk.cc.len(), NUM_ZK_REPETITIONS)?;
    require_eq("dd", nizk.dd.len(), num_receivers + 1)?;
    require_eq("z_r", nizk.z_r.len(), num_receivers)?;
    require_eq("z_s", nizk.z_s.len(), NUM_ZK_REPETITIONS)?;

    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    let spec_m = instance.randomizers_r.len();
    let spec_n = instance.public_keys.len();
    let bb_constant = CHUNK_SIZE as usize;
    let ee = 1 << CHALLENGE_BITS;
    let ss = spec_n * spec_m * (bb_constant - 1) * (ee - 1);
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let zz_big = BIG::new_int(zz as isize);

    for z_sk in nizk.z_s.iter() {
        if BIG::comp(&z_sk, &zz_big) >= 0 {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    let first_move = FirstMoveChunking::from(&nizk.y0, &nizk.bb, &nizk.cc);
    let second_move = SecondMoveChunking::from(&nizk.z_s, &nizk.dd, &nizk.yy);
    // e_{m,n,l} = oracle(instance, y_0, bb, cc)
    let e = ChunksOracle::new(&instance, &first_move).get_all_chunks(spec_n, spec_m);

    // x = oracle(e, z_s, dd, yy)
    let x = chunking_proof_challenge_oracle(&e, &second_move);

    let mut xpowers = Vec::new();
    let mut tmp = x;
    for _i in 0..NUM_ZK_REPETITIONS {
        xpowers.push(tmp);
        tmp = BIG::modmul(&tmp, &x, &spec_p);
    }

    // Verify: all [product [R_j ^ sum [e_ijk * x^k | k <- [1..l]] | j <- [1..m]] *
    // dd_i == g1 ^ z_r_i | i <- [1..n]]
    let mut delta_idx = 1;
    let mut verifies = true;
    e.iter().zip(nizk.z_r.iter()).for_each(|(e_i, z_ri)| {
        let mut lhs = nizk.dd[delta_idx].clone();
        delta_idx += 1;
        let e_ijk_polynomials: Vec<BIG> = e_i
            .iter()
            .map(|e_ij| {
                let mut acc = BIG::new_int(0);
                e_ij.iter().enumerate().for_each(|(k, e_ijk)| {
                    acc = BIG::modadd(
                        &acc,
                        &BIG::modmul(&BIG::new_int(*e_ijk as isize), &xpowers[k], &spec_p),
                        &spec_p,
                    );
                });
                acc
            })
            .collect();
        lhs.add(&ECP::muln(
            spec_m,
            &instance.randomizers_r,
            &e_ijk_polynomials,
        ));
        let rhs = g1.mul(&z_ri);
        verifies = verifies && lhs.equals(&rhs);
    });
    if !verifies {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    // Verify: product [bb_k ^ x^k | k <- [1..l]] * dd_0 == g1 ^ z_beta
    let mut lhs = ECP::muln(NUM_ZK_REPETITIONS, &nizk.bb, &xpowers);
    lhs.add(&nizk.dd[0]);

    let rhs = g1.mul(&nizk.z_beta);
    if !lhs.equals(&rhs) {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    // Verify: product [product [chunk_ij ^ e_ijk | i <- [1..n], j <- [1..m]] ^ x^k
    // | k <- [1..l]] * product [cc_k ^ x^k | k <- [1..l]] * Y   = product
    // [y_i^z_ri | i <- [1..n]] * y0^z_beta * g_1 ^ sum [z_sk * x^k | k <- [1..l]]
    let mut lhs = ECP::muln(NUM_ZK_REPETITIONS, &nizk.cc, &xpowers);
    lhs.add(&nizk.yy);

    let cij_to_eijks: Vec<ECP> = (0..NUM_ZK_REPETITIONS)
        .map(|k| {
            let c_ij_s: Vec<ECP> = instance
                .ciphertext_chunks
                .iter()
                .cloned()
                .flatten()
                .collect();
            let e_ijk_s: Vec<BIG> = e
                .iter()
                .flatten()
                .map(|e_ij| BIG::new_int(e_ij[k] as isize))
                .collect();
            if c_ij_s.len() != spec_m * spec_n || e_ijk_s.len() != spec_m * spec_n {
                return Err(ZkProofChunkingError::InvalidProof);
            }
            Ok(ECP::muln(spec_m * spec_n, &c_ij_s, &e_ijk_s))
        })
        .collect::<Result<Vec<ECP>, _>>()?;

    lhs.add(&ECP::muln(NUM_ZK_REPETITIONS, &cij_to_eijks, &xpowers));

    let mut acc = BIG::new_int(0);
    nizk.z_s
        .iter()
        .zip(xpowers.iter())
        .for_each(|(z_sk, xpow)| {
            acc = BIG::modadd(&acc, &BIG::modmul(&z_sk, &xpow, &spec_p), &spec_p);
        });
    let mut rhs = ECP::muln(num_receivers, &instance.public_keys, &nizk.z_r);
    rhs.add(&nizk.y0.mul2(&nizk.z_beta, &g1, &acc));
    if !lhs.equals(&rhs) {
        return Err(ZkProofChunkingError::InvalidProof);
    }
    Ok(())
}

struct ChunksOracle {
    rng: RAND_ChaCha20, // The choice of RNG matters so this is explicit, not a trait.
}

impl ChunksOracle {
    pub fn new(instance: &ChunkingInstance, first_move: &FirstMoveChunking) -> Self {
        let mut map = HashedMap::new();
        map.insert_hashed("instance", instance);
        map.insert_hashed("first-move", first_move);
        map.insert_hashed("number-of-parallel-repetitions", &NUM_ZK_REPETITIONS);

        let hash = random_oracle(DOMAIN_PROOF_OF_CHUNKING_ORACLE, &map);

        let rng = RAND_ChaCha20::new(hash);
        Self { rng }
    }

    /// Get a chunk-sized unit of data.
    fn get_chunk(&mut self) -> usize {
        // The order of the getbyte(..) calls matters so this is intentionally serial.
        let challenge_bytes = (CHALLENGE_BITS + 7) / 8;
        debug_assert!(challenge_bytes < std::mem::size_of::<usize>());
        let (challenge_mask, _) = (1usize << CHALLENGE_BITS).overflowing_sub(1); // == 111...1
        challenge_mask
            & (0..challenge_bytes).fold(0, |state, _| (state << 8) | (self.rng.getbyte() as usize))
    }

    fn get_all_chunks(&mut self, spec_n: usize, spec_m: usize) -> Vec<Vec<Vec<usize>>> {
        (0..spec_n)
            .map(|_| {
                (0..spec_m)
                    .map(|_| (0..NUM_ZK_REPETITIONS).map(|_| self.get_chunk()).collect())
                    .collect()
            })
            .collect()
    }
}

fn chunking_proof_challenge_oracle(
    first_challenge: &[Vec<Vec<usize>>],
    second_move: &SecondMoveChunking,
) -> BIG {
    let mut map = HashedMap::new();
    map.insert_hashed("first-challenge", &first_challenge.to_vec());
    map.insert_hashed("second-move", second_move);

    random_oracle_to_scalar(DOMAIN_PROOF_OF_CHUNKING_CHALLENGE, &map)
}

#[inline]
fn require_eq(
    name: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ZkProofChunkingError> {
    if expected != actual {
        dbg!(name);
        dbg!(actual);
        dbg!(expected);
        Err(ZkProofChunkingError::InvalidProof)
    } else {
        Ok(())
    }
}
