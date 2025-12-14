//! Elliptic curve crypt
//! This uses the core elliptic curve operations but expresses them in
//! cryptographic terms.
use crate::types::{
    CombinedPublicKey, CombinedSignature, IndividualSignature, Pop, PublicKey, PublicKeyBytes,
    SecretKey,
};

use ic_crypto_internal_bls12_381_type::{
    G1Affine, G1Projective, G2Affine, Scalar, verify_bls_signature,
};

use ic_crypto_sha2::DomainSeparationContext;
use rand::{CryptoRng, Rng};

/// Domain separator for Hash-to-G1 to be used for signature generation in a
/// scheme supporting proof of possession, as specified for the Proof of
/// Possession ciphersuite in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-4.2.3
const DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG_WITH_POP: &[u8; 43] =
    b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separator for Hash-to-G1 to be used in a proof of possession as
/// as specified for the Proof of Possession ciphersuite in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-4.2.3
const DOMAIN_HASH_PUB_KEY_TO_G1_BLS12381_SIG_WITH_POP: &[u8; 43] =
    b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation string used in the creation of proof of possessions of BLS
/// multi-signature public keys.
pub const DOMAIN_MULTI_SIG_BLS12_381_POP: &str = "ic-multi-sig-bls12381-pop";

pub fn hash_message_to_g1(msg: &[u8]) -> G1Projective {
    G1Projective::hash(DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG_WITH_POP, msg)
}

pub fn hash_public_key_to_g1(public_key: &[u8]) -> G1Projective {
    G1Projective::hash(DOMAIN_HASH_PUB_KEY_TO_G1_BLS12381_SIG_WITH_POP, public_key)
}

// Once upon a time we had placed the `seed` values directly into the output
// `FrRepr` value, but this places a large burden on the caller, who must
// guarantee `seed` represents a number strictly less than the group order, or
// risk generating from a non-uniform distribution. Now, we use `seed` to seed a
// RNG, then use this to generate a uniform random element.
#[cfg(test)]
pub fn keypair_from_seed(seed: [u64; 4]) -> (SecretKey, PublicKey) {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut seed_as_u8: [u8; 32] = [0; 32];
    for i in 0..4 {
        let bs = seed[i].to_be_bytes();
        for j in 0..8 {
            seed_as_u8[i * 8 + j] = bs[j];
        }
    }
    keypair_from_rng(&mut ChaCha20Rng::from_seed(seed_as_u8))
}

pub fn keypair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> (SecretKey, PublicKey) {
    let secret_key = Scalar::random(rng);
    let public_key = (G2Affine::generator() * &secret_key).to_affine();
    (secret_key, public_key)
}

pub fn sign_point(point: &G1Projective, secret_key: &SecretKey) -> IndividualSignature {
    (point * secret_key).to_affine()
}
pub fn sign_message(message: &[u8], secret_key: &SecretKey) -> IndividualSignature {
    sign_point(&hash_message_to_g1(message), secret_key)
}

pub fn create_pop(public_key: &PublicKey, secret_key: &SecretKey) -> Pop {
    let public_key_bytes = PublicKeyBytes::from(public_key);
    let mut domain_separated_public_key: Vec<u8> = vec![];
    domain_separated_public_key
        .extend(DomainSeparationContext::new(DOMAIN_MULTI_SIG_BLS12_381_POP).as_bytes());
    domain_separated_public_key.extend(&public_key_bytes.0[..]);
    sign_point(
        &hash_public_key_to_g1(&domain_separated_public_key),
        secret_key,
    )
}

pub fn combine_signatures(signatures: &[IndividualSignature]) -> CombinedSignature {
    G1Affine::sum(signatures).to_affine()
}
pub fn combine_public_keys(public_keys: &[PublicKey]) -> CombinedPublicKey {
    G2Affine::sum(public_keys).to_affine()
}

pub fn verify_point(hash: &G1Affine, signature: &G1Affine, public_key: &PublicKey) -> bool {
    verify_bls_signature(signature, public_key, hash)
}

pub fn verify_individual_message_signature(
    message: &[u8],
    signature: &IndividualSignature,
    public_key: &PublicKey,
) -> bool {
    let hash = hash_message_to_g1(message);
    verify_point(&hash.to_affine(), signature, public_key)
}
pub fn verify_pop(pop: &Pop, public_key: &PublicKey) -> bool {
    let public_key_bytes = PublicKeyBytes::from(public_key);
    let mut domain_separated_public_key: Vec<u8> = vec![];
    domain_separated_public_key
        .extend(DomainSeparationContext::new(DOMAIN_MULTI_SIG_BLS12_381_POP).as_bytes());
    domain_separated_public_key.extend(&public_key_bytes.0[..]);
    let hash = hash_public_key_to_g1(&domain_separated_public_key);
    verify_point(&hash.to_affine(), pop, public_key)
}

pub fn verify_combined_message_signature(
    message: &[u8],
    signature: &CombinedSignature,
    public_keys: &[PublicKey],
) -> bool {
    let hash = hash_message_to_g1(message);
    let public_key = combine_public_keys(public_keys);
    verify_point(&hash.to_affine(), signature, &public_key)
}
