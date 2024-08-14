//! A partial implementation of the server side vetkd API

use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use ic_bls12_381::*;
use rand::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutputReset, Update, XofReader},
    Shake256,
};

pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        /*
        A BLS12-381 scalar is 255 bits long. Generate the scalar using
        rejection sampling by creating a 255 bit random bitstring then
        checking if it is less than the group order.
         */
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        buf[0] &= 0b0111_1111; // clear the 256th bit

        let s = Scalar::from_bytes(&buf);

        if bool::from(s.is_some()) {
            return s.unwrap();
        }
    }
}

/// See draft-irtf-cfrg-bls-signature-01 §4.2.2 for details on BLS augmented signatures
fn augmented_hash_to_g1(pk: &G2Affine, data: &[u8]) -> G1Affine {
    let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

    let mut signature_input = vec![];
    signature_input.extend_from_slice(&pk.to_compressed());
    signature_input.extend_from_slice(data);

    let pt = <ic_bls12_381::G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        signature_input,
        domain_sep,
    );

    G1Affine::from(pt)
}

struct RandomOracle {
    shake: Shake256,
}

impl RandomOracle {
    fn new(domain_separator: &str) -> Self {
        let mut ro = Self {
            shake: Shake256::default(),
        };

        ro.update_str(domain_separator);

        ro
    }

    fn update_str(&mut self, s: &str) {
        self.update_bin(s.as_bytes());
    }

    fn update_bin(&mut self, v: &[u8]) {
        let v_len = v.len() as u64;
        self.shake.update(&v_len.to_be_bytes());
        self.shake.update(v);
    }

    fn finalize(&mut self, output: &mut [u8]) {
        let o_len = output.len() as u64;
        self.shake.update(&o_len.to_be_bytes());

        let mut xof = self.shake.finalize_xof_reset();
        xof.read(output);
    }

    fn finalize_to_scalar(mut self) -> Scalar {
        let mut output = [0u8; 2 * 32];
        self.finalize(&mut output);
        Scalar::from_bytes_wide(&output)
    }
}

pub struct DerivationPath {
    delta: Scalar,
}

impl DerivationPath {
    /// Create a new derivation path
    pub fn new<U: AsRef<[u8]>>(canister_id: &[u8], extra_paths: &[U]) -> Self {
        let mut ro = RandomOracle::new("ic-crypto-vetkd-bls12-381-derivation-path");

        ro.update_bin(canister_id);

        for path in extra_paths {
            ro.update_bin(path.as_ref());
        }

        let delta = ro.finalize_to_scalar();
        Self { delta }
    }

    pub fn delta(&self) -> &Scalar {
        &self.delta
    }
}

pub fn create_encrypted_key<R: CryptoRng + RngCore>(
    rng: &mut R,
    master_pk: &G2Affine,
    master_sk: &Scalar,
    transport_pk: &G1Affine,
    derivation_path: &DerivationPath,
    did: &[u8],
) -> Vec<u8> {
    let delta = derivation_path.delta();

    let dsk = delta + master_sk;
    let dpk = G2Affine::from(G2Affine::generator() * delta + master_pk);

    let r = random_scalar(rng);

    let msg = augmented_hash_to_g1(&dpk, did);

    let c1 = G1Affine::from(G1Affine::generator() * r);
    let c2 = G2Affine::from(G2Affine::generator() * r);
    let c3 = G1Affine::from(transport_pk * r + msg * dsk);

    let mut output = vec![];
    output.extend_from_slice(&c1.to_compressed());
    output.extend_from_slice(&c2.to_compressed());
    output.extend_from_slice(&c3.to_compressed());
    output
}
