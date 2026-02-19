use std::{convert::TryInto, ops::Range};

use candid::Principal;
use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use ic_bls12_381::*;
use ic_stable_structures::storable::Blob;
use ic_vetkeys::types::{AccessRights, ByteBuf, KeyName};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::convert::TryFrom;

pub fn reproducible_rng() -> ChaCha20Rng {
    let seed = rand::thread_rng().gen();
    println!("RNG seed: {seed:?}");
    ChaCha20Rng::from_seed(seed)
}

pub fn random_unique_memory_ids<R: Rng + CryptoRng>(rng: &mut R) -> (u8, [u8; 3]) {
    const MAX_MEMORY_ID: u8 = 254;
    let mut set = std::collections::HashSet::<u8>::new();
    let mut unique_memory_ids = [0; 4];
    while set.len() != unique_memory_ids.len() {
        set.insert(rng.gen_range(0..=MAX_MEMORY_ID));
    }
    unique_memory_ids = set.into_iter().collect::<Vec<u8>>().try_into().unwrap();

    let memory_id_encrypted_maps = unique_memory_ids[0];
    let memory_ids_key_manager = [
        unique_memory_ids[1],
        unique_memory_ids[2],
        unique_memory_ids[3],
    ];
    (memory_id_encrypted_maps, memory_ids_key_manager)
}

pub fn random_name<R: Rng + CryptoRng>(rng: &mut R) -> KeyName {
    random_blob(rng)
}

pub fn random_blob<R: Rng + CryptoRng, const N: usize>(rng: &mut R) -> Blob<N> {
    let mut result = [0u8; N];
    rng.fill_bytes(&mut result);
    Blob::try_from(result.as_slice()).unwrap()
}

pub fn random_bytebuf<R: Rng + CryptoRng>(rng: &mut R, range: Range<usize>) -> ByteBuf {
    let length: usize = rng.gen_range(range);
    let mut result: Vec<u8> = vec![0; length];
    rng.fill_bytes(&mut result);
    ByteBuf::from(result)
}

pub fn random_key<R: Rng + CryptoRng>(rng: &mut R) -> Blob<32> {
    random_blob(rng)
}

pub fn random_self_authenticating_principal<R: Rng + CryptoRng>(rng: &mut R) -> Principal {
    let mut fake_public_key = vec![0u8; 32];
    rng.fill_bytes(&mut fake_public_key);
    Principal::self_authenticating::<&[u8]>(fake_public_key.as_ref())
}

pub fn random_access_rights<R: Rng + CryptoRng>(rng: &mut R) -> AccessRights {
    loop {
        if let Some(ar) = AccessRights::from_repr(rng.gen()) {
            return ar;
        }
    }
}

pub fn random_utf8_string<R: Rng + CryptoRng>(rng: &mut R, len: usize) -> String {
    rng.sample_iter::<char, _>(&rand::distributions::Standard)
        .take(len)
        .collect()
}

pub fn git_root_dir() -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("Failed to execute git command");
    assert!(output.status.success());
    let root_dir_with_newline =
        String::from_utf8(output.stdout).expect("Failed to convert stdout to string");
    root_dir_with_newline.trim_end_matches('\n').to_string()
}

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
            context: if context.is_empty() {
                None
            } else {
                Some(context.to_vec())
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

        let canister_key = G2Affine::from(G2Affine::generator() * offset + master_pk);

        if let Some(context) = &self.context {
            let context_offset = Self::hash_to_scalar(
                &canister_key.to_compressed(),
                context,
                DERIVATION_CONTEXT_DST,
            );
            let canister_key_with_context = G2Affine::generator() * context_offset + canister_key;
            offset += context_offset;
            (G2Affine::from(canister_key_with_context), offset)
        } else {
            (canister_key, offset)
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
