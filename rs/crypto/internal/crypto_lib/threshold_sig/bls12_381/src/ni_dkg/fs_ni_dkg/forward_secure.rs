#![allow(clippy::needless_range_loop)]

//! Methods for forward secure encryption

// NOTE: the paper uses multiplicative notation for operations on GT,
// while our BLS12-381 API uses additive naming convention, hence
//    u*v  corresponds to u + v
// and
//    g^x  corresponds to g * x

pub use crate::ni_dkg::fs_ni_dkg::chunking::*;
use crate::ni_dkg::fs_ni_dkg::dlog_recovery::{
    CheatingDealerDlogSolver, HonestDealerDlogLookupTable,
};
use crate::ni_dkg::fs_ni_dkg::encryption_key_pop::{
    prove_pop, verify_pop, EncryptionKeyInstance, EncryptionKeyPop,
};
use crate::ni_dkg::fs_ni_dkg::random_oracles::{random_oracle, HashedMap};

use crate::ni_dkg::groth20_bls12_381::types::{BTENodeBytes, FsEncryptionSecretKey};
use ic_crypto_internal_bls12_381_type::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
pub use ic_crypto_internal_types::curves::bls12_381::{FrBytes, G1Bytes, G2Bytes};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    FsEncryptionCiphertextBytes, FsEncryptionPop, FsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use lazy_static::lazy_static;
use rand::{CryptoRng, RngCore};
use std::collections::LinkedList;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constant which controls the upper limit of epochs
///
/// Specifically 2**LAMBDA_T NI-DKG epochs cann occur
///
/// See Section 7.1 of <https://eprint.iacr.org/2021/339.pdf>
pub const LAMBDA_T: usize = 32;

/// The size of the hash function used during encryption
///
/// See Section 7.1 of <https://eprint.iacr.org/2021/339.pdf>
pub const LAMBDA_H: usize = 256;

/// The maximum epoch is derived from the size of LAMBDA_T
///
/// The maximum epoch is expressed as a u32 because that is the
/// underlying size of the Epoch type in ic-crypto-internal-types
pub const MAXIMUM_EPOCH: u32 = ((1u64 << LAMBDA_T) - 1) as u32;

const DOMAIN_CIPHERTEXT_NODE: &str = "ic-fs-encryption/binary-tree-node";

/// Type for a single bit
#[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
pub(crate) enum Bit {
    Zero = 0,
    One = 1,
}

impl From<u8> for Bit {
    fn from(i: u8) -> Self {
        if i == 0 {
            Bit::Zero
        } else {
            Bit::One
        }
    }
}

impl From<&Bit> for u8 {
    fn from(b: &Bit) -> u8 {
        match &b {
            Bit::Zero => 0,
            Bit::One => 1,
        }
    }
}

impl From<&Bit> for u32 {
    fn from(b: &Bit) -> u32 {
        match &b {
            Bit::Zero => 0,
            Bit::One => 1,
        }
    }
}

/// Represents a prefix of an epoch.
///
/// The bits are the encoding (in big-endian ordering) of an
/// integer which represents a prefix of an epoch.
#[derive(Debug, Clone, Zeroize)]
pub(crate) struct Tau(pub Vec<Bit>);

impl Tau {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn extended_by(&self, bit: Bit) -> Self {
        let mut ext = self.clone();
        ext.push(bit);
        ext
    }

    pub fn push(&mut self, bit: Bit) {
        self.0.push(bit);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn is_prefix_of_epoch(&self, epoch: Epoch) -> bool {
        fn is_prefix(xs: &[Bit], ys: &[Bit]) -> bool {
            if xs.len() > ys.len() {
                return false;
            }
            for i in 0..xs.len() {
                if xs[i] != ys[i] {
                    return false;
                }
            }
            true
        }

        is_prefix(&self.0, &Tau::from(epoch).0)
    }
}

impl std::ops::Index<usize> for Tau {
    type Output = Bit;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl From<Epoch> for Tau {
    /// Gets the leaf node tau for a given epoch
    fn from(epoch: Epoch) -> Tau {
        let epoch = epoch.get();
        let num_bits = std::mem::size_of::<Epoch>() * 8;
        Tau((0..num_bits)
            .rev()
            .map(|shift| Bit::from(((epoch >> shift) & 1) as u8))
            .collect())
    }
}

/// A node of a Binary Tree Encryption scheme.
///
/// Notation from section 7.2.
pub(crate) struct BTENode {
    // Bit-vector, indicating a path in a binary tree.
    pub tau: Tau,

    pub a: G1Affine,
    pub b: G2Affine,

    // We split the d's into two groups.
    // The vector `d_h` always contains the last LAMBDA_H points
    // of d_l,...,d_lambda.
    // The list `d_t` contains the other elements. There are at most LAMBDA_T of them.
    // The longer this list, the higher up we are in the binary tree,
    // and the more leaf node keys we are able to derive.
    pub d_t: LinkedList<G2Affine>,
    pub d_h: Vec<G2Affine>,

    pub e: G2Affine,
}

// must implement explicitly as zeroize does not support LinkedList
impl zeroize::Zeroize for BTENode {
    fn zeroize(&mut self) {
        self.tau.zeroize();
        self.a.zeroize();
        self.b.zeroize();
        self.d_t.iter_mut().for_each(|x| x.zeroize());
        self.d_h.zeroize();
        self.e.zeroize();
    }
}

// ZeroizeOnDrop doesn't work if you don't derive Zeroize
impl Drop for BTENode {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BTENode {
    pub(crate) fn serialize(&self) -> BTENodeBytes {
        BTENodeBytes {
            tau: self.tau.0.iter().map(|i| *i as u8).collect(),
            a: self.a.serialize_to::<G1Bytes>(),
            b: self.b.serialize_to::<G2Bytes>(),
            d_t: self
                .d_t
                .iter()
                .map(|p| p.serialize_to::<G2Bytes>())
                .collect(),
            d_h: self
                .d_h
                .iter()
                .map(|p| p.serialize_to::<G2Bytes>())
                .collect(),
            e: self.e.serialize_to::<G2Bytes>(),
        }
    }

    /// Deserialize a BTENode
    ///
    /// Assumes inputs are trusted points. Panics if deserialization fails.
    pub(crate) fn deserialize_unchecked(node: &BTENodeBytes) -> Self {
        Self {
            tau: Tau(node.tau.iter().copied().map(Bit::from).collect()),
            a: G1Affine::deserialize_unchecked(&node.a).expect("Malformed secret key at BTENode.a"),
            b: G2Affine::deserialize_unchecked(&node.b).expect("Malformed secret key at BTENode.b"),
            d_t: node
                .d_t
                .iter()
                .map(|g2| {
                    G2Affine::deserialize_unchecked(&g2)
                        .expect("Malformed secret key at BTENode.d_t")
                })
                .collect(),
            d_h: node
                .d_h
                .iter()
                .map(|g2| {
                    G2Affine::deserialize_unchecked(&g2)
                        .expect("Malformed secret key at BTENode.d_h")
                })
                .collect(),
            e: G2Affine::deserialize_unchecked(&node.e).expect("Malformed secret key at BTENode.e"),
        }
    }
}

/// A forward-secure secret key is a list of BTE nodes.
///
/// We can derive the keys of any descendant of any node in the list.
/// We obtain forward security by maintaining the list so that we can
/// derive current and future private keys, but none of the past keys.
pub struct SecretKey {
    bte_nodes: LinkedList<BTENode>,
}

/// A public key and its associated proof of possession
#[derive(Clone, Debug)]
pub struct PublicKeyWithPop {
    pub key_value: G1Affine,
    pub proof_data: EncryptionKeyPop,
}

impl PublicKeyWithPop {
    pub fn verify(&self, associated_data: &[u8]) -> bool {
        let instance = EncryptionKeyInstance {
            g1_gen: G1Affine::generator().clone(),
            public_key: self.key_value.clone(),
            associated_data: associated_data.to_vec(),
        };
        verify_pop(&instance, &self.proof_data).is_ok()
    }

    /// Parse a serialized public key and PoP
    pub fn deserialize(pk: &FsEncryptionPublicKey, pop: &FsEncryptionPop) -> Option<Self> {
        let key_value = G1Affine::deserialize(pk.as_bytes());
        let pop_key = G1Affine::deserialize(&pop.pop_key);
        let challenge = Scalar::deserialize(&pop.challenge);
        let response = Scalar::deserialize(&pop.response);

        match (key_value, pop_key, challenge, response) {
            (Ok(key_value), Ok(pop_key), Ok(challenge), Ok(response)) => Some(Self {
                key_value,
                proof_data: EncryptionKeyPop {
                    pop_key,
                    challenge,
                    response,
                },
            }),
            (_, _, _, _) => None,
        }
    }

    /// Serialize the public key and PoP
    pub(crate) fn serialize(&self) -> (FsEncryptionPublicKey, FsEncryptionPop) {
        let public_key = FsEncryptionPublicKey(self.key_value.serialize_to::<G1Bytes>());

        let pop = FsEncryptionPop {
            pop_key: G1Bytes(self.proof_data.pop_key.serialize()),
            challenge: FrBytes(self.proof_data.challenge.serialize()),
            response: FrBytes(self.proof_data.response.serialize()),
        };
        (public_key, pop)
    }
}

/// NI-DKG system parameters
pub struct SysParam {
    pub f0: G2Affine,       // f_0 in the paper.
    pub f: Vec<G2Affine>,   // f_1, ..., f_{lambda_T} in the paper.
    pub f_h: Vec<G2Affine>, // The remaining LAMBDA_H f_i's in the paper.
    pub h: G2Affine,
    h_prep: G2Prepared,
}

/// Generates a (public key, secret key) pair for of forward-secure
/// public-key encryption scheme.
///
/// # Arguments:
/// * `associated_data`: public information for the Proof of Possession of the
///   key.
/// * `sys`: system parameters for the FS Encryption scheme.
/// * `rng`: seeded pseudo random number generator.
pub fn kgen<R: RngCore + CryptoRng>(
    associated_data: &[u8],
    sys: &SysParam,
    rng: &mut R,
) -> (PublicKeyWithPop, SecretKey) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let x = Scalar::random(rng);
    let rho = Scalar::random(rng);
    let a = G1Affine::from(g1 * &rho);
    let b = G2Projective::mul2(
        &G2Projective::from(g2),
        &x,
        &G2Projective::from(&sys.f0),
        &rho,
    )
    .to_affine();
    let mut d_t = LinkedList::new();
    for f in sys.f.iter() {
        d_t.push_back(G2Affine::from(f * &rho));
    }

    let mut d_h = Vec::new();
    for h in sys.f_h.iter() {
        d_h.push(h * &rho);
    }
    let d_h = G2Projective::batch_normalize(&d_h);

    let e = G2Affine::from(&sys.h * &rho);
    let bte_root = BTENode {
        tau: Tau::empty(),
        a,
        b,
        d_t,
        d_h,
        e,
    };
    let sk = SecretKey::new(bte_root);

    let y = G1Affine::from(g1 * &x);

    let pop_instance = EncryptionKeyInstance {
        g1_gen: G1Affine::generator().clone(),
        public_key: y.clone(),
        associated_data: associated_data.to_vec(),
    };

    let pop = prove_pop(&pop_instance, &x, rng).expect("Implementation bug: Pop generation failed");

    (
        PublicKeyWithPop {
            key_value: y,
            proof_data: pop,
        },
        sk,
    )
}

impl SecretKey {
    fn new(bte_root: BTENode) -> SecretKey {
        let mut bte_nodes = LinkedList::new();
        bte_nodes.push_back(bte_root);
        SecretKey { bte_nodes }
    }

    /// Returns this key's  BTE-node that corresponds to the current epoch.
    pub(crate) fn current(&self) -> Option<&BTENode> {
        self.bte_nodes.back()
    }

    /// Gets the current epoch for a secret key.
    ///
    /// Returns None if the key has been exhausted
    pub fn current_epoch(&self) -> Option<Epoch> {
        if let Some(node) = self.current() {
            let mut epoch = 0u32;
            for i in 0..LAMBDA_T {
                let x = if let Some(t) = node.tau.0.get(i) {
                    t.into()
                } else {
                    0
                };

                epoch |= x << (LAMBDA_T - 1 - i);
            }
            Some(Epoch::from(epoch))
        } else {
            None
        }
    }

    /// Updates this key to the next epoch.  After an update,
    /// the decryption keys for previous epochs are not accessible any more.
    /// (KUpd(dk, 1) from Sect. 9.1)
    ///
    /// The current key (the end of list of BTENodes) of a `SecretKey` should
    /// always correspond to an epoch described by LAMBDA_T bits. However this
    /// invariant is broken when we pop the final node. The second call to
    /// update_to modifies the list so the current key corresponds to the
    /// first epoch of the subtree described by the current key.
    ///
    /// For example, if LAMBDA_T = 5, then [..., 011] will change to
    /// [..., 0111, 01101, 01100].
    /// The current key's `tau` now has 5 bits, and the other entries cover the
    /// rest of the 011 subtree after we delete the current key.
    ///
    /// Another example: during the very first epoch the private key is
    /// [1, 01, 001, 0001, 00001, 00000].
    ///
    /// This makes key update easy: pop off the current key, then update again
    ///
    /// An alternative is to only store the root nodes of the subtrees that
    /// cover the remaining valid keys. Thus the first epoch, the private
    /// key would simply be \[0\], and would only change to [1, 01, 001, 0001,
    /// 00001] after the first update. Generally, some computations
    /// happen one epoch later than they would with our current scheme. However,
    /// key update is a bit fiddlier.
    pub fn update<R: RngCore + CryptoRng>(&mut self, sys: &SysParam, rng: &mut R) {
        if let Some(current_epoch) = self.current_epoch() {
            self.update_to(current_epoch, sys, rng);
        }
        match self.bte_nodes.pop_back() {
            None => {}
            Some(mut dk) => {
                dk.zeroize();
                if let Some(current_epoch) = self.current_epoch() {
                    self.update_to(current_epoch, sys, rng);
                }
            }
        }
    }

    /// Updates `self` to the given `epoch`.
    ///
    /// If `epoch` is in the past, with respect to the current key, then nothing happens
    /// If `epoch` is the current epoch of the key, then nothing happens
    ///
    /// A key update can take up to 2*LAMBDA_T*LAMBDA_H G2 multiplications
    pub fn update_to<R: RngCore + CryptoRng>(&mut self, epoch: Epoch, sys: &SysParam, rng: &mut R) {
        if let Some(current_epoch) = self.current_epoch() {
            if current_epoch > epoch {
                return;
            }
        }

        // Drop nodes from the end of bte_nodes until we either run out of nodes
        // (in which case return, with the key disabled) or until we arrive at a
        // node whose tau value is a prefix of the target epoch.
        loop {
            match self.bte_nodes.back() {
                None => return,
                Some(cur) => {
                    if cur.tau.is_prefix_of_epoch(epoch) {
                        break;
                    }
                }
            }
            self.bte_nodes
                .pop_back()
                .expect("bte_nodes unexpectedly empty")
                .zeroize();
        }

        let epoch = Tau::from(epoch);

        // At this point, bte_nodes.back() is a prefix of `epoch`.
        // Replace it with the nodes for `epoch` and later (in the subtree).
        //
        // For example, with a 5-bit epoch, if `node` is 011, and `epoch` is
        // 01101, then we replace [..., 011] with [..., 0111, 01101]:
        //   * The current epoch is now 01101.
        //   * We can still derive the keys for 01110 and 01111 from 0111.
        //   * We can no longer decrypt 01100.
        let mut node = self.bte_nodes.pop_back().expect("self.bte_nodes was empty");
        // Nothing to do if `node.tau` is already `epoch`.
        if node.tau.len() == epoch.len() {
            self.bte_nodes.push_back(node);
            return;
        }
        let mut d_t = node.d_t.clone();
        // Accumulators.
        //   b_acc = b * product [d_i^tau_i | i <- [1..n]]
        //   f_acc = f0 * product [f_i^tau_i | i <- [1..n]]
        let mut b_acc = G2Projective::from(&node.b);
        let mut f_acc = ftau_partial(&node.tau, sys).expect("node.tau not the expected size");
        let mut tau = node.tau.clone();

        for n in node.tau.len()..epoch.len() {
            if epoch[n] == Bit::Zero {
                // Save the root of the right subtree for later.
                let tau_1 = tau.extended_by(Bit::One);
                let delta = Scalar::random(rng);

                let a_blind = (G1Affine::generator() * &delta) + &node.a;
                let mut b_blind =
                    G2Projective::from(d_t.pop_front().expect("d_t not sufficiently large"));
                b_blind += &b_acc;
                b_blind += (&f_acc + &sys.f[n]) * &delta;

                let e_blind = (&sys.h * &delta) + &node.e;
                let mut d_t_blind = LinkedList::new();
                let mut k = n + 1;
                d_t.iter().for_each(|d| {
                    let tmp = (&sys.f[k] * &delta) + d;
                    d_t_blind.push_back(tmp.to_affine());
                    k += 1;
                });

                let mut d_h_blind = Vec::new();
                node.d_h.iter().zip(&sys.f_h).for_each(|(d, f)| {
                    let tmp = (f * &delta) + d;
                    d_h_blind.push(tmp);
                });
                let d_h_blind = G2Projective::batch_normalize(&d_h_blind);

                self.bte_nodes.push_back(BTENode {
                    tau: tau_1,
                    a: a_blind.to_affine(),
                    b: b_blind.to_affine(),
                    d_t: d_t_blind,
                    d_h: d_h_blind,
                    e: e_blind.to_affine(),
                });
            } else {
                // Update accumulators.
                f_acc += &sys.f[n];
                b_acc += d_t.pop_front().expect("d_t not sufficiently large");
            }
            tau.push(epoch[n]);
        }

        let delta = Scalar::random(rng);
        let a = G1Affine::generator() * &delta + &node.a;
        let e = &sys.h * &delta + &node.e;
        b_acc += f_acc * &delta;

        let mut d_t_blind = LinkedList::new();
        // Typically `d_t_blind` remains empty.
        // It is only nontrivial if `epoch` is less than LAMBDA_T bits.
        let mut k = epoch.len();
        d_t.iter().for_each(|d| {
            let tmp = (&sys.f[k] * &delta) + d;
            d_t_blind.push_back(tmp.to_affine());
            k += 1;
        });
        let mut d_h_blind = Vec::new();
        node.d_h.iter().zip(&sys.f_h).for_each(|(d, f)| {
            let tmp = f * &delta + d;
            d_h_blind.push(tmp.to_affine());
        });

        self.bte_nodes.push_back(BTENode {
            tau,
            a: a.to_affine(),
            b: b_acc.to_affine(),
            d_t: d_t_blind,
            d_h: d_h_blind,
            e: e.to_affine(),
        });
        node.zeroize();
    }

    /// Serialises a forward secure secret key into the standard form.
    pub fn serialize(&self) -> FsEncryptionSecretKey {
        FsEncryptionSecretKey {
            bte_nodes: self.bte_nodes.iter().map(|node| node.serialize()).collect(),
        }
    }

    /// Parses a forward secure secret key
    ///
    /// # Security Note
    ///
    /// The provided `secret_key` is assumed to be "trusted",
    /// meaning it was obtained from a known and trusted source.
    /// This is because certain safety checks are NOT performed
    /// on the members of the key.
    ///
    /// # Panics
    /// Panics if the key is malformed.  Given that secret keys are created and
    /// managed within the CSP such a failure is an error in this code or a
    /// corruption of the secret key store.
    pub fn deserialize(secret_key: &FsEncryptionSecretKey) -> Self {
        Self {
            bte_nodes: secret_key
                .bte_nodes
                .iter()
                .map(BTENode::deserialize_unchecked)
                .collect(),
        }
    }
}

/// Forward secure ciphertexts
///
/// This is (C,R,S,Z) tuple of section 5.2, with multiple C values,
/// one for each recipent.
#[derive(Debug)]
pub struct FsEncryptionCiphertext {
    pub cc: Vec<Vec<G1Affine>>,
    pub rr: Vec<G1Affine>,
    pub ss: Vec<G1Affine>,
    pub zz: Vec<G2Affine>,
}

impl FsEncryptionCiphertext {
    /// Serialises a ciphertext from the internal representation into the standard
    /// form.
    ///
    /// # Panics
    /// This will panic if the internal representation is invalid.  Given that the
    /// internal representation is generated internally, this can happen only if there
    /// is an error in our code.
    pub fn serialize(&self) -> FsEncryptionCiphertextBytes {
        assert_eq!(self.rr.len(), NUM_CHUNKS);
        assert_eq!(self.ss.len(), NUM_CHUNKS);
        assert_eq!(self.zz.len(), NUM_CHUNKS);

        let rand_r = {
            let mut rand_r = [G1Bytes([0u8; G1Bytes::SIZE]); NUM_CHUNKS];
            for (dst, src) in rand_r[..].iter_mut().zip(&self.rr) {
                *dst = src.serialize_to::<G1Bytes>();
            }
            rand_r
        };
        let rand_s = {
            let mut rand_s = [G1Bytes([0u8; G1Bytes::SIZE]); NUM_CHUNKS];
            for (dst, src) in rand_s[..].iter_mut().zip(&self.ss) {
                *dst = src.serialize_to::<G1Bytes>();
            }
            rand_s
        };
        let rand_z = {
            let mut rand_z = [G2Bytes([0u8; G2Bytes::SIZE]); NUM_CHUNKS];
            for (dst, src) in rand_z[..].iter_mut().zip(&self.zz) {
                *dst = src.serialize_to::<G2Bytes>();
            }
            rand_z
        };
        let ciphertext_chunks = self
            .cc
            .iter()
            .map(|cj| {
                assert_eq!(cj.len(), NUM_CHUNKS);

                let mut cc = [G1Bytes([0u8; G1Bytes::SIZE]); NUM_CHUNKS];
                for (dst, src) in cc[..].iter_mut().zip(cj) {
                    *dst = src.serialize_to::<G1Bytes>();
                }
                cc
            })
            .collect();

        FsEncryptionCiphertextBytes {
            rand_r,
            rand_s,
            rand_z,
            ciphertext_chunks,
        }
    }

    /// Parses a ciphertext into the internal representation.
    ///
    /// # Errors
    /// This will return an error if any of the constituent group elements is
    /// invalid.
    pub fn deserialize(ciphertext: &FsEncryptionCiphertextBytes) -> Result<Self, &'static str> {
        let rr = G1Affine::batch_deserialize(&ciphertext.rand_r).or(Err("Malformed rand_r"))?;
        let ss = G1Affine::batch_deserialize(&ciphertext.rand_s).or(Err("Malformed rand_s"))?;
        let zz = G2Affine::batch_deserialize(&ciphertext.rand_z).or(Err("Malformed rand_z"))?;

        let cc: Vec<Vec<G1Affine>> = ciphertext
            .ciphertext_chunks
            .iter()
            .map(|cj| G1Affine::batch_deserialize(&cj[..]).or(Err("Malformed ciphertext_chunk")))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { cc, rr, ss, zz })
    }
}

/// Randomness needed for NIZK proofs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionWitness {
    pub r: Vec<Scalar>,
}

/// Encrypt chunks. Returns ciphertext as well as the witness for later use
/// in the NIZK proofs.
pub fn enc_chunks<R: RngCore + CryptoRng>(
    recipient_and_message: &[(G1Affine, PlaintextChunks)],
    epoch: Epoch,
    associated_data: &[u8],
    sys: &SysParam,
    rng: &mut R,
) -> (FsEncryptionCiphertext, EncryptionWitness) {
    let receivers = recipient_and_message.len();

    let g1 = G1Affine::generator();

    let s = Scalar::batch_random(rng, NUM_CHUNKS);
    let ss = g1.batch_mul(&s);

    let r = Scalar::batch_random(rng, NUM_CHUNKS);
    let rr = g1.batch_mul(&r);

    let cc = {
        let mut cc: Vec<Vec<G1Affine>> = Vec::with_capacity(receivers);

        let g1 = G1Projective::from(g1);

        for (pk, ptext) in recipient_and_message {
            let pk = G1Projective::from(pk);
            let pk_g1_tbl = G1Projective::compute_mul2_tbl(&pk, &g1);

            let chunks = ptext.chunks_as_scalars();

            let mut enc_chunks = Vec::with_capacity(NUM_CHUNKS);

            for j in 0..NUM_CHUNKS {
                enc_chunks.push(pk_g1_tbl.mul2(&r[j], &chunks[j]));
            }

            cc.push(G1Projective::batch_normalize(&enc_chunks));
        }

        cc
    };

    let id = ftau_extended(&cc, &rr, &ss, sys, epoch, associated_data);
    let mut zz = Vec::with_capacity(NUM_CHUNKS);

    let id_h_tbl = G2Projective::compute_mul2_tbl(&id, &G2Projective::from(&sys.h));
    for j in 0..NUM_CHUNKS {
        zz.push(id_h_tbl.mul2(&r[j], &s[j]));
    }

    let zz = G2Projective::batch_normalize(&zz);

    let witness = EncryptionWitness { r };
    let crsz = FsEncryptionCiphertext { cc, rr, ss, zz };

    (crsz, witness)
}

fn find_prefix(dks: &SecretKey, epoch: Epoch) -> Option<&BTENode> {
    dks.bte_nodes
        .iter()
        .find(|&node| node.tau.is_prefix_of_epoch(epoch))
}

/// Error while decrypting
#[derive(Debug)]
pub enum DecErr {
    ExpiredKey,
    InvalidChunk,
    InvalidCiphertext,
}

/// Decrypt the i-th group of chunks.
///
/// Decrypting a message for a future epoch hardly costs more than a message for
/// a current epoch: at most LAMBDA_T point additions.
///
/// Upgrading a key is expensive in comparison because we must compute new
/// subtree roots and re-"blind" them (the random deltas of the paper) to hide
/// ciphertexts from future keys. Each re-blinding costs at least LAMBDA_H
/// (which is 256 in our system) point multiplications.
///
/// Caller must ensure i < n, where n = crsz.cc.len().
pub fn dec_chunks(
    dks: &SecretKey,
    i: usize,
    crsz: &FsEncryptionCiphertext,
    epoch: Epoch,
    associated_data: &[u8],
) -> Result<Scalar, DecErr> {
    let n = crsz.cc.len();
    let m = crsz.cc[i].len();

    if crsz.rr.len() != m || crsz.ss.len() != m || crsz.zz.len() != m {
        return Err(DecErr::InvalidCiphertext);
    }

    let dk = find_prefix(dks, epoch).ok_or(DecErr::ExpiredKey)?;

    let bneg = {
        let extended_tau = extend_tau(&crsz.cc, &crsz.rr, &crsz.ss, epoch, associated_data);

        let mut bneg = G2Projective::from(&dk.b);

        for (i, t) in dk.d_t.iter().enumerate() {
            if extended_tau[dk.tau.len() + i] == Bit::One {
                bneg += t;
            }
        }
        for k in 0..LAMBDA_H {
            if extended_tau[LAMBDA_T + k] == Bit::One {
                bneg += &dk.d_h[k];
            }
        }
        bneg.neg()
    };

    let cj = &crsz.cc[i];

    let bneg = G2Prepared::from(&bneg);
    let eneg = G2Prepared::from(&dk.e.neg());

    let mut powers = Vec::with_capacity(m);

    for i in 0..m {
        let x = Gt::multipairing(&[
            (&cj[i], G2Prepared::generator()),
            (&crsz.rr[i], &bneg),
            (&dk.a, &G2Prepared::from(&crsz.zz[i])),
            (&crsz.ss[i], &eneg),
        ]);

        powers.push(x);
    }

    // Find discrete log of the powers
    let linear_search = HonestDealerDlogLookupTable::new();

    let dlogs = {
        let mut dlogs = linear_search.solve_several(&powers);

        if dlogs.iter().any(|x| x.is_none()) {
            // Cheating dealer case
            let cheating_solver = CheatingDealerDlogSolver::new(n, m);

            for i in 0..dlogs.len() {
                if dlogs[i].is_none() {
                    // It may take hours to brute force a cheater's discrete log.
                    dlogs[i] = cheating_solver.solve(&powers[i]);
                }
            }
        }

        let mut solutions = Vec::with_capacity(dlogs.len());

        for dlog in dlogs {
            if let Some(solution) = dlog {
                solutions.push(solution);
            } else {
                return Err(DecErr::InvalidChunk);
            }
        }

        solutions
    };

    Ok(PlaintextChunks::from_dlogs(&dlogs).recombine_to_scalar())
}

// TODO(IDX-1866)
#[allow(clippy::result_unit_err)]
/// Verify ciphertext integrity
///
/// Part of DVfy of Section 7.1 of <https://eprint.iacr.org/2021/339.pdf>
//
/// In addition to verifying the proofs of chunking and sharing,
/// we must also verify ciphertext integrity.
pub fn verify_ciphertext_integrity(
    crsz: &FsEncryptionCiphertext,
    epoch: Epoch,
    associated_data: &[u8],
    sys: &SysParam,
) -> Result<(), ()> {
    let n = if crsz.cc.is_empty() {
        0
    } else {
        crsz.cc[0].len()
    };
    if crsz.rr.len() != n || crsz.ss.len() != n || crsz.zz.len() != n {
        // In theory, this is unreachable fail because deserialization only succeeds
        // when the vectors of a CRSZ have the same length. (In practice, it's
        // surprising how often "unreachable" code is reached!)
        return Err(());
    }

    let id = ftau_extended(&crsz.cc, &crsz.rr, &crsz.ss, sys, epoch, associated_data);

    let g1_neg = G1Affine::generator().neg();
    let precomp_id = G2Prepared::from(&id);

    let checks: Result<(), ()> = crsz
        .rr
        .iter()
        .zip(crsz.ss.iter().zip(crsz.zz.iter()))
        .try_for_each(|(r, (s, z))| {
            let z = G2Prepared::from(z);

            let v = Gt::multipairing(&[(r, &precomp_id), (s, &sys.h_prep), (&g1_neg, &z)]);

            if v.is_identity() {
                Ok(())
            } else {
                Err(())
            }
        });
    checks
}

/// Returns (tau || RO(cc, rr, ss, tau, associated_data)).
///
/// See the description of Deal in Section 7.1.
pub(crate) fn extend_tau(
    cc: &[Vec<G1Affine>],
    rr: &[G1Affine],
    ss: &[G1Affine],
    epoch: Epoch,
    associated_data: &[u8],
) -> Tau {
    let mut map = HashedMap::new();
    map.insert_hashed("ciphertext-chunks", &cc.to_vec());
    map.insert_hashed("randomizers-r", &rr.to_vec());
    map.insert_hashed("randomizers-s", &ss.to_vec());
    map.insert_hashed("epoch", &(epoch.get() as usize));
    map.insert_hashed("associated-data", &associated_data.to_vec());

    let hash = random_oracle(DOMAIN_CIPHERTEXT_NODE, &map);

    let tau = Tau::from(epoch);

    let mut extended_tau: Vec<Bit> = tau.0;
    hash.iter().for_each(|byte| {
        for b in 0..8 {
            extended_tau.push(Bit::from((byte >> b) & 1));
        }
    });
    Tau(extended_tau)
}

/// Extends tau using the random oracle, and computes the function f
///
/// See the description of Deal in Section 7.1.
pub fn ftau_extended(
    cc: &[Vec<G1Affine>],
    rr: &[G1Affine],
    ss: &[G1Affine],
    sys: &SysParam,
    epoch: Epoch,
    associated_data: &[u8],
) -> G2Projective {
    let extended_tau = extend_tau(cc, rr, ss, epoch, associated_data);

    let mut id = G2Projective::from(&sys.f0);

    for i in 0..LAMBDA_T {
        if extended_tau.0[i] == Bit::One {
            id += &sys.f[i];
        }
    }

    for i in 0..LAMBDA_H {
        if extended_tau.0[LAMBDA_T + i] == Bit::One {
            id += &sys.f_h[i];
        }
    }

    id
}

/// Computes f for bit vectors tau <= LAMBDA_T.
pub(crate) fn ftau_partial(tau: &Tau, sys: &SysParam) -> Option<G2Projective> {
    if tau.0.len() > LAMBDA_T {
        return None;
    }
    let mut id = G2Projective::from(&sys.f0);
    tau.0.iter().zip(sys.f.iter()).for_each(|(t, f)| {
        if *t == Bit::One {
            id += f;
        }
    });
    Some(id)
}

lazy_static! {
    static ref SYSTEM_PARAMS: SysParam =
        SysParam::create(b"DFX01-with-BLS12381G2_XMD:SHA-256_SSWU_RO_");
}

impl SysParam {
    /// Create a set of system parameters
    fn create(dst: &[u8]) -> Self {
        let f0 = G2Affine::hash_with_precomputation(dst, b"f0");

        let mut f = Vec::with_capacity(LAMBDA_T);
        for i in 0..LAMBDA_T {
            let s = format!("f{}", i + 1);
            f.push(G2Affine::hash_with_precomputation(dst, s.as_bytes()));
        }
        let mut f_h = Vec::with_capacity(LAMBDA_H);
        for i in 0..LAMBDA_H {
            let s = format!("f_h{}", i);
            f_h.push(G2Affine::hash_with_precomputation(dst, s.as_bytes()));
        }

        let h = G2Affine::hash_with_precomputation(dst, b"h");

        let h_prep = G2Prepared::from(&h);

        SysParam {
            f0,
            f,
            f_h,
            h,
            h_prep,
        }
    }

    /// Return a reference to the global NI-DKG system parameters
    pub fn global() -> &'static Self {
        &SYSTEM_PARAMS
    }
}
