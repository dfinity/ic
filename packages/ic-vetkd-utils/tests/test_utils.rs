//! A partial implementation of the server side vetkd API

use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use ic_bls12_381::*;
use rand::{CryptoRng, RngCore};

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

fn hash_to_scalar(input: &[u8], domain_sep: &str) -> ic_bls12_381::Scalar {
    use ic_bls12_381::hash_to_curve::HashToField;

    let mut s = [ic_bls12_381::Scalar::zero()];
    <ic_bls12_381::Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
        input,
        domain_sep.as_bytes(),
        &mut s,
    );
    s[0]
}

pub struct DerivationContext {
    delta: Scalar,
}

impl DerivationContext {
    /// Create a new derivation path
    pub fn new(canister_id: &[u8], context: &[u8]) -> Self {
        let domain_sep = "ic-vetkd-bls12-381-context";
        let mut delta = hash_to_scalar(canister_id, domain_sep);
        delta += hash_to_scalar(context, domain_sep);
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
    context: &DerivationContext,
    input: &[u8],
) -> Vec<u8> {
    let delta = context.delta();

    let dsk = delta + master_sk;
    let dpk = G2Affine::from(G2Affine::generator() * delta + master_pk);

    let r = random_scalar(rng);

    let msg = augmented_hash_to_g1(&dpk, input);

    let c1 = G1Affine::from(G1Affine::generator() * r);
    let c2 = G2Affine::from(G2Affine::generator() * r);
    let c3 = G1Affine::from(transport_pk * r + msg * dsk);

    let mut output = vec![];
    output.extend_from_slice(&c1.to_compressed());
    output.extend_from_slice(&c2.to_compressed());
    output.extend_from_slice(&c3.to_compressed());
    output
}
