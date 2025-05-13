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

const DERIVATION_CANISTER_DST: &[u8; 33] = b"ic-vetkd-bls12-381-g2-canister-id";

const DERIVATION_CONTEXT_DST: &[u8; 29] = b"ic-vetkd-bls12-381-g2-context";

pub struct DerivationContext {
    canister_id: Vec<u8>,
    context: Option<Vec<u8>>,
}

impl DerivationContext {
    /// Create a new derivation context
    pub fn new(canister_id: &[u8], context: &[u8]) -> Self {
        Self {
            canister_id: canister_id.to_vec(),
            context: if context.len() > 0 {
                Some(context.to_vec())
            } else {
                None
            },
        }
    }

    fn hash_to_scalar(input1: &[u8], input2: &[u8], domain_sep: &'static [u8]) -> Scalar {
        let combined_input = {
            let mut c = Vec::with_capacity(2 * 8 + input1.len() + input2.len());
            c.extend_from_slice(&(input1.len() as u64).to_be_bytes());
            c.extend_from_slice(input1);
            c.extend_from_slice(&(input2.len() as u64).to_be_bytes());
            c.extend_from_slice(input2);
            c
        };

        use ic_bls12_381::hash_to_curve::HashToField;

        let mut s = [ic_bls12_381::Scalar::zero()];
        <ic_bls12_381::Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
            &combined_input,
            domain_sep,
            &mut s,
        );
        s[0]
    }

    pub fn derive_key(&self, master_pk: &G2Affine) -> (G2Affine, Scalar) {
        let mut offset = Self::hash_to_scalar(
            &master_pk.to_compressed(),
            &self.canister_id,
            DERIVATION_CANISTER_DST,
        );

        let canister_key = G2Affine::from(G2Affine::generator() * &offset + master_pk);

        if let Some(context) = &self.context {
            let context_offset = Self::hash_to_scalar(
                &canister_key.to_compressed(),
                context,
                DERIVATION_CONTEXT_DST,
            );
            let canister_key_with_context = G2Affine::generator() * &context_offset + canister_key;
            offset += context_offset;
            (G2Affine::from(canister_key_with_context), offset)
        } else {
            (G2Affine::from(canister_key), offset)
        }
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
    let (dpk, delta) = context.derive_key(master_pk);

    let dsk = delta + master_sk;

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
