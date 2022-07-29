//! Generating and verifying Proofs of Possession (PoP)

#[cfg(test)]
mod tests;

use crate::random_oracles::{random_oracle_to_g1, random_oracle_to_scalar, HashedMap, UniqueHash};
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, Scalar};
use miracl_core::rand::RAND;
use zeroize::Zeroize;

const DOMAIN_POP_ENCRYPTION_KEY: &str = "ic-pop-encryption";

/// Proof of Possession (PoP) of the Encryption Key.
#[derive(Clone, Debug)]
pub struct EncryptionKeyPop {
    pub pop_key: G1Affine,
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Instance for the Possession of the Encryption Key.
pub struct EncryptionKeyInstance {
    pub g1_gen: G1Affine,
    pub public_key: G1Affine,
    pub associated_data: Vec<u8>,
}

/// A PoP could not be generated or verified
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionKeyPopError {
    InvalidProof,
    InvalidInstance,
}

impl UniqueHash for EncryptionKeyInstance {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("g1-generator", &self.g1_gen);
        map.insert_hashed("public-key", &self.public_key);
        map.insert_hashed("associated-data", &self.associated_data);
        map.unique_hash()
    }
}

fn generate_pop_challenge(
    public_key: &G1Affine,
    pop_base: &G1Affine,
    pop_key: &G1Affine,
    blinder_public_key: &G1Affine,
    blinder_pop_key: &G1Affine,
) -> Scalar {
    let mut map = HashedMap::new();
    map.insert_hashed("public-key", public_key);
    map.insert_hashed("pop-base", pop_base);
    map.insert_hashed("pop-key", pop_key);
    map.insert_hashed("blinder-public-key", blinder_public_key);
    map.insert_hashed("blinder-pop-key", blinder_pop_key);

    random_oracle_to_scalar(DOMAIN_POP_ENCRYPTION_KEY, &map)
}

/// Prove the Possession of an EncryptionKey.
pub fn prove_pop(
    instance: &EncryptionKeyInstance,
    witness: &Scalar,
    rng: &mut impl RAND,
) -> Result<EncryptionKeyPop, EncryptionKeyPopError> {
    // Check validity of the instance
    if instance.public_key != G1Affine::from(instance.g1_gen * witness) {
        return Err(EncryptionKeyPopError::InvalidInstance);
    }

    // First Move
    let pop_base = random_oracle_to_g1(DOMAIN_POP_ENCRYPTION_KEY, instance);
    let pop_key = G1Affine::from(pop_base * witness);

    // This is not a random oracle and could be changed to using Scalar::random
    // aside from the fact that this would break the stability test.
    let mut random_scalar = Scalar::miracl_random_using_miracl_rand(rng);

    let blinder_public_key = G1Affine::from(instance.g1_gen * random_scalar);
    let blinder_pop_key = G1Affine::from(pop_base * random_scalar);

    // Challenge
    let challenge = generate_pop_challenge(
        &instance.public_key,
        &pop_base,
        &pop_key,
        &blinder_public_key,
        &blinder_pop_key,
    );

    // Response
    let response = challenge * witness + random_scalar;

    random_scalar.zeroize();

    Ok(EncryptionKeyPop {
        pop_key,
        challenge,
        response,
    })
}

/// Verifies the Proof of Possession of an EncryptionKey.
pub fn verify_pop(
    instance: &EncryptionKeyInstance,
    pop: &EncryptionKeyPop,
) -> Result<(), EncryptionKeyPopError> {
    let minus_challenge = pop.challenge.neg();
    let pop_base = random_oracle_to_g1(DOMAIN_POP_ENCRYPTION_KEY, instance);

    let blinder_public_key = G1Projective::mul2(
        &instance.public_key.into(),
        &minus_challenge,
        &instance.g1_gen.into(),
        &pop.response,
    );

    let blinder_pop_key = G1Projective::mul2(
        &pop.pop_key.into(),
        &minus_challenge,
        &pop_base.into(),
        &pop.response,
    );

    let challenge = generate_pop_challenge(
        &instance.public_key,
        &pop_base,
        &pop.pop_key,
        &blinder_public_key.into(),
        &blinder_pop_key.into(),
    );

    if challenge != pop.challenge {
        return Err(EncryptionKeyPopError::InvalidProof);
    }
    Ok(())
}
