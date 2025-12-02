//! Proofs of correct chunking
#![allow(clippy::needless_range_loop)]

use crate::ni_dkg::fs_ni_dkg::forward_secure::{CHUNK_SIZE, NUM_CHUNKS};
use crate::ni_dkg::fs_ni_dkg::random_oracles::{
    HashedMap, UniqueHash, random_oracle, random_oracle_to_scalar,
};
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, Scalar};
use ic_crypto_internal_types::curves::bls12_381::{FrBytes, G1Bytes};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::ZKProofDec;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

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
pub const CHALLENGE_BITS: usize = SECURITY_LEVEL.div_ceil(NUM_ZK_REPETITIONS);

// The number of bytes needed to represent a challenge (which must fit in a usize)
pub const CHALLENGE_BYTES: usize = CHALLENGE_BITS.div_ceil(8);
const _: () = assert!(CHALLENGE_BYTES < std::mem::size_of::<usize>());

// A bitmask specifying the size of a challenge
pub const CHALLENGE_MASK: usize = (1 << CHALLENGE_BITS) - 1;

/// Instance for a chunking relation.
///
/// From Section 6.5 of the NIDKG paper.
///   instance = (y=[y_1..y_n], C=[chunk_{1,1}..chunk_{n,m}], R=[R_1,..R_m])
/// We rename:
///   y -> public_keys.
///   C_{i,j} -> ciphertext_chunks.
///   R -> randomizers_r
#[derive(Clone, Debug)]
pub struct ChunkingInstance {
    g1_gen: G1Affine,
    public_keys: Vec<G1Affine>,
    ciphertext_chunks: Vec<[G1Affine; NUM_CHUNKS]>,
    randomizers_r: [G1Affine; NUM_CHUNKS],
}

impl ChunkingInstance {
    pub fn public_keys(&self) -> &[G1Affine] {
        &self.public_keys
    }

    pub fn ciphertext_chunks(&self) -> &[[G1Affine; NUM_CHUNKS]] {
        &self.ciphertext_chunks
    }

    pub fn randomizers_r(&self) -> &[G1Affine; NUM_CHUNKS] {
        &self.randomizers_r
    }

    pub fn new(
        public_keys: Vec<G1Affine>,
        ciphertext_chunks: Vec<[G1Affine; NUM_CHUNKS]>,
        randomizers_r: [G1Affine; NUM_CHUNKS],
    ) -> Self {
        Self {
            g1_gen: G1Affine::generator().clone(),
            public_keys,
            ciphertext_chunks,
            randomizers_r,
        }
    }
}

/// Witness for the validity of a chunking instance.
///
/// From Section 6.5 of the NIDKG paper:
///   Witness = (scalar_r =[r_1..r_m], scalar_s=[s_{1,1}..s_{n,m}])
#[derive(Clone, Debug)]
pub struct ChunkingWitness {
    scalars_r: [Scalar; NUM_CHUNKS],
    scalars_s: Vec<[Scalar; NUM_CHUNKS]>,
}

impl ChunkingWitness {
    pub fn new(scalars_r: [Scalar; NUM_CHUNKS], scalars_s: Vec<[Scalar; NUM_CHUNKS]>) -> Self {
        Self {
            scalars_r,
            scalars_s,
        }
    }
}

/// Creating or verifying a proof of correct chunking failed.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ZkProofChunkingError {
    InvalidProof,
    InvalidInstance,
}

/// Zero-knowledge proof of chunking.
pub struct ProofChunking {
    y0: G1Affine,
    bb: [G1Affine; NUM_ZK_REPETITIONS],
    cc: [G1Affine; NUM_ZK_REPETITIONS],
    dd: Vec<G1Affine>,
    yy: G1Affine,
    z_r: Vec<Scalar>,
    z_s: [Scalar; NUM_ZK_REPETITIONS],
    z_beta: Scalar,
}

/// First move of the prover in the zero-knowledge proof of chunking.
struct FirstMoveChunking {
    y0: G1Affine,
    bb: [G1Affine; NUM_ZK_REPETITIONS],
    cc: [G1Affine; NUM_ZK_REPETITIONS],
}

/// Prover's response to the first challenge of the verifier.
struct SecondMoveChunking {
    z_s: Vec<Scalar>,
    dd: Vec<G1Affine>,
    yy: G1Affine,
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
    fn from(
        y0: G1Affine,
        bb: [G1Affine; NUM_ZK_REPETITIONS],
        cc: [G1Affine; NUM_ZK_REPETITIONS],
    ) -> Self {
        Self { y0, bb, cc }
    }
}

impl SecondMoveChunking {
    fn from(z_s: &[Scalar], dd: &[G1Affine], yy: &G1Affine) -> Self {
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
pub fn prove_chunking<R: RngCore + CryptoRng>(
    instance: &ChunkingInstance,
    witness: &ChunkingWitness,
    rng: &mut R,
) -> ProofChunking {
    instance
        .check_instance()
        .expect("The chunking proof instance is invalid");

    let m = instance.randomizers_r.len();
    let n = instance.public_keys.len();

    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let range = zz - 1 + ss + 1;
    let zz_big = Scalar::from_usize(zz);
    let p_sub_s = Scalar::from_usize(ss).neg();

    // y0 <- getRandomG1
    let y0 = G1Affine::hash(
        b"ic-crypto-nizk-chunking-proof-y0",
        &rng.r#gen::<[u8; 32]>(),
    );

    let g1 = &instance.g1_gen;

    let y0_g1_tbl =
        G1Projective::compute_mul2_tbl(&G1Projective::from(&y0), &G1Projective::from(g1));

    let beta = Scalar::batch_random_array::<NUM_ZK_REPETITIONS, R>(rng);
    let bb = g1.batch_mul_array(&beta);

    let (first_move, first_challenge, z_s) = loop {
        let sigma = [(); NUM_ZK_REPETITIONS]
            .map(|_| Scalar::random_within_range(rng, range as u64) + &p_sub_s);

        let cc = G1Projective::batch_normalize_array(&y0_g1_tbl.mul2_array(&beta, &sigma));

        let first_move = FirstMoveChunking::from(y0.clone(), bb.clone(), cc);
        // Verifier's challenge.
        let first_challenge = ChunksOracle::new(instance, &first_move).get_all_chunks(n, m);

        // z_s = [sum [e_ijk * s_ij | i <- [1..n], j <- [1..m]] + sigma_k | k <- [1..l]]

        let iota: [usize; NUM_ZK_REPETITIONS] = std::array::from_fn(|i| i);

        let z_s = iota.map(|k| {
            let mut acc = Scalar::zero();
            first_challenge
                .iter()
                .zip(witness.scalars_s.iter())
                .for_each(|(e_i, s_i)| {
                    e_i.iter().zip(s_i.iter()).for_each(|(e_ij, s_ij)| {
                        acc += Scalar::from_usize(e_ij[k]) * s_ij;
                    });
                });
            acc += &sigma[k];

            acc
        });

        // Now check if our z_s is valid. Our control flow reveals if we retry
        // but in the event of a retry it should ideally not reveal *which* z_s
        // caused us to retry, since that may reveal information about the witness.
        //
        // Perform the check by using ct_compare with zz_big. This function
        // returns 1 if the zz_big is greater than its argument. If for any
        // input it returns 0 or -1 (indicating z was == or > zz_big) then the
        // sum will not match the overall length of z_s.

        let zs_in_range = z_s
            .iter()
            .map(|z| zz_big.ct_compare(z) as isize)
            .sum::<isize>() as usize
            == NUM_ZK_REPETITIONS;

        if zs_in_range {
            break (first_move, first_challenge, z_s);
        }
    };

    // delta <- replicate (n + 1) getRandom
    // dd = map (g1^) delta
    // Y = product [y_i^delta_i | i <- [0..n]]
    let delta = Scalar::batch_random(rng, n + 1);
    let dd = g1.batch_mul(&delta);

    let yy = {
        let y0_and_pk = [y0.clone()]
            .iter()
            .chain(&instance.public_keys)
            .cloned()
            .collect::<Vec<_>>();
        G1Projective::muln_affine_vartime(&y0_and_pk, &delta).to_affine()
    };

    let second_move = SecondMoveChunking::from(&z_s, &dd, &yy);

    // Second verifier's challenge. Forth move in the protocol.
    // x = oracle(e, z_s, dd, yy)
    let second_challenge = chunking_proof_challenge_oracle(&first_challenge, &second_move);

    let xpowers = Scalar::xpowers(&second_challenge, NUM_ZK_REPETITIONS);

    let mut z_r = Vec::with_capacity(first_challenge.len());
    let mut delta_idx = 1;

    for e_i in first_challenge.iter() {
        let mut xpow_e_ij = Vec::with_capacity(e_i.len());
        for j in 0..e_i.len() {
            xpow_e_ij.push(Scalar::muln_usize_vartime(&xpowers, &e_i[j]));
        }

        let z_rk = Scalar::muln_vartime(&witness.scalars_r, &xpow_e_ij) + &delta[delta_idx];

        z_r.push(z_rk);

        delta_idx += 1;
    }

    let z_beta = Scalar::muln_vartime(&beta, &xpowers) + &delta[0];

    ProofChunking {
        y0,
        bb,
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

    let num_receivers = instance.public_keys.len();
    require_eq("bb", nizk.bb.len(), NUM_ZK_REPETITIONS)?;
    require_eq("cc", nizk.cc.len(), NUM_ZK_REPETITIONS)?;
    require_eq("dd", nizk.dd.len(), num_receivers + 1)?;
    require_eq("z_r", nizk.z_r.len(), num_receivers)?;
    require_eq("z_s", nizk.z_s.len(), NUM_ZK_REPETITIONS)?;

    let m = instance.randomizers_r.len();
    let n = instance.public_keys.len();
    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let zz_big = Scalar::from_usize(zz);

    for z_sk in nizk.z_s.iter() {
        if z_sk >= &zz_big {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    let first_move = FirstMoveChunking::from(nizk.y0.clone(), nizk.bb.clone(), nizk.cc.clone());
    let second_move = SecondMoveChunking::from(&nizk.z_s, &nizk.dd, &nizk.yy);
    // e_{m,n,l} = oracle(instance, y_0, bb, cc)
    let e = ChunksOracle::new(instance, &first_move).get_all_chunks(n, m);

    // x = oracle(e, z_s, dd, yy)
    let x = chunking_proof_challenge_oracle(&e, &second_move);

    let xpowers = Scalar::xpowers(&x, NUM_ZK_REPETITIONS);
    let g1 = &instance.g1_gen;

    // TODO(CRP-2550) Verification of chunking proof could run in 3 threads

    // Thread 1
    {
        /*
        Verify lhs == rhs where
        lhs = product [R_j ^ sum [e_ijk * x^k | k <- [1..l]] | j <- [1..m]] * dd_i
        rhs = g1 ^ z_r_i | i <- [1..n]]
         */

        let rhs = g1.batch_mul_vartime(&nizk.z_r);

        let lhs = {
            let mut lhs = Vec::with_capacity(e.len());
            for (i, e_i) in e.iter().enumerate() {
                let e_ijk_polynomials: Vec<_> = e_i
                    .iter()
                    .map(|e_ij| Scalar::muln_usize_vartime(&xpowers, e_ij))
                    .collect();

                let rj_e_ijk =
                    G1Projective::muln_affine_vartime(&instance.randomizers_r, &e_ijk_polynomials);

                lhs.push(rj_e_ijk + &nizk.dd[i + 1]);
            }
            G1Projective::batch_normalize(&lhs)
        };

        if lhs != rhs {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    // Thread 2
    {
        // Verify: product [bb_k ^ x^k | k <- [1..l]] * dd_0 == g1 ^ z_beta
        let lhs = G1Projective::muln_affine_vartime(&nizk.bb, &xpowers) + &nizk.dd[0];

        let rhs = g1.mul_vartime(&nizk.z_beta);
        if lhs != rhs {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    // Thread 3
    {
        // Verify: product [product [chunk_ij ^ e_ijk | i <- [1..n], j <- [1..m]] ^ x^k
        // | k <- [1..l]] * product [cc_k ^ x^k | k <- [1..l]] * Y   = product
        // [y_i^z_ri | i <- [1..n]] * y0^z_beta * g_1 ^ sum [z_sk * x^k | k <- [1..l]]

        let cij_to_eijks: Vec<G1Projective> = (0..NUM_ZK_REPETITIONS)
            .map(|k| {
                let c_ij_s: Vec<_> = instance
                    .ciphertext_chunks
                    .iter()
                    .flatten()
                    .cloned()
                    .collect();
                let e_ijk_s: Vec<_> = e
                    .iter()
                    .flatten()
                    .map(|e_ij| Scalar::from_usize(e_ij[k]))
                    .collect();
                if c_ij_s.len() != m * n || e_ijk_s.len() != m * n {
                    return Err(ZkProofChunkingError::InvalidProof);
                }

                Ok(G1Projective::muln_affine_vartime(&c_ij_s, &e_ijk_s) + &nizk.cc[k])
            })
            .collect::<Result<Vec<_>, _>>()?;

        let lhs = G1Projective::muln_vartime(&cij_to_eijks[..], &xpowers[..]) + &nizk.yy;

        let acc = Scalar::muln_vartime(&nizk.z_s, &xpowers);

        let rhs = G1Projective::muln_affine_vartime(&instance.public_keys, &nizk.z_r)
            + G1Projective::mul2_vartime(
                &G1Projective::from(&nizk.y0),
                &nizk.z_beta,
                &G1Projective::from(g1),
                &acc,
            );

        if lhs != rhs {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    Ok(())
}

struct ChunksOracle {
    rng: ChaCha20Rng, // The choice of RNG matters so this is explicit, not a trait.
}

impl ChunksOracle {
    pub fn new(instance: &ChunkingInstance, first_move: &FirstMoveChunking) -> Self {
        let mut map = HashedMap::new();
        map.insert_hashed("instance", instance);
        map.insert_hashed("first-move", first_move);
        map.insert_hashed("number-of-parallel-repetitions", &NUM_ZK_REPETITIONS);

        let hash = random_oracle(DOMAIN_PROOF_OF_CHUNKING_ORACLE, &map);

        let rng = ChaCha20Rng::from_seed(hash);
        Self { rng }
    }

    fn getbyte(&mut self) -> u8 {
        let mut random_byte: [u8; 1] = [0; 1];
        // `fill_bytes()` with 1-byte buffer consumes 4 bytes of the random stream.
        self.rng.fill_bytes(&mut random_byte);
        random_byte[0]
    }

    /// Get a chunk-sized unit of data.
    fn get_chunk(&mut self) -> usize {
        // The order of the getbyte(..) calls matters so this is intentionally serial.
        CHALLENGE_MASK
            & (0..CHALLENGE_BYTES).fold(0, |state, _| (state << 8) | (self.getbyte() as usize))
    }

    fn get_all_chunks(&mut self, n: usize, m: usize) -> Vec<Vec<Vec<usize>>> {
        (0..n)
            .map(|_| {
                (0..m)
                    .map(|_| (0..NUM_ZK_REPETITIONS).map(|_| self.get_chunk()).collect())
                    .collect()
            })
            .collect()
    }
}

fn chunking_proof_challenge_oracle(
    first_challenge: &[Vec<Vec<usize>>],
    second_move: &SecondMoveChunking,
) -> Scalar {
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

impl ProofChunking {
    /// Serialises a chunking proof from the internal form to the standard form
    pub fn serialize(&self) -> ZKProofDec {
        ZKProofDec {
            first_move_y0: self.y0.serialize_to::<G1Bytes>(),
            first_move_b: G1Affine::serialize_array_to::<G1Bytes, NUM_ZK_REPETITIONS>(&self.bb),
            first_move_c: G1Affine::serialize_array_to::<G1Bytes, NUM_ZK_REPETITIONS>(&self.cc),
            second_move_d: G1Affine::serialize_seq_to::<G1Bytes>(&self.dd),
            second_move_y: self.yy.serialize_to::<G1Bytes>(),
            response_z_r: Scalar::serialize_seq_to::<FrBytes>(&self.z_r),
            response_z_s: Scalar::serialize_array_to::<FrBytes, NUM_ZK_REPETITIONS>(&self.z_s),
            response_z_b: self.z_beta.serialize_to::<FrBytes>(),
        }
    }

    /// Parses a chunking proof from the standard form
    pub fn deserialize(proof: &ZKProofDec) -> Option<Self> {
        let y0 = G1Affine::deserialize(&proof.first_move_y0);
        let bb = G1Affine::batch_deserialize_array(&proof.first_move_b);
        let cc = G1Affine::batch_deserialize_array(&proof.first_move_c);
        let dd = G1Affine::batch_deserialize(&proof.second_move_d[..]);
        let yy = G1Affine::deserialize(proof.second_move_y.as_bytes());
        let z_r = Scalar::batch_deserialize(&proof.response_z_r);
        let z_s = Scalar::batch_deserialize_array(&proof.response_z_s);
        let z_beta = Scalar::deserialize(proof.response_z_b.as_bytes());

        match (y0, bb, cc, dd, yy, z_r, z_s, z_beta) {
            (Ok(y0), Ok(bb), Ok(cc), Ok(dd), Ok(yy), Ok(z_r), Ok(z_s), Ok(z_beta)) => {
                if dd.len() != z_r.len() + 1 {
                    return None;
                }

                Some(Self {
                    y0,
                    bb,
                    cc,
                    dd,
                    yy,
                    z_r,
                    z_s,
                    z_beta,
                })
            }
            _ => None,
        }
    }
}
