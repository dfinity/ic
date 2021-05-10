//! Generating and verifying Proofs of Possession (PoP)

#[cfg(test)]
mod tests;

use crate::forward_secure::ZeroizedBIG;
use crate::random_oracles::{
    random_oracle_to_miracl_g1, random_oracle_to_scalar, HashedMap, UniqueHash,
};
use crate::utils::*;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::rand::RAND;
use zeroize::Zeroize;

const DOMAIN_POP_ENCRYPTION_KEY: &str = "ic-pop-encryption";

/// Proof of Possession (PoP) of the Encryption Key.
#[derive(Clone, Debug)]
pub struct EncryptionKeyPop {
    pub pop_key: ECP,
    pub challenge: BIG,
    pub response: BIG,
}

/// Instance for the Possession of the Encryption Key.
pub struct EncryptionKeyInstance {
    pub g1_gen: ECP,
    pub public_key: ECP,
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

#[allow(dead_code)]
fn pop_challenge(
    public_key: &ECP,
    pop_base: &ECP,
    pop_key: &ECP,
    blinder_public_key: &ECP,
    blinder_pop_key: &ECP,
) -> BIG {
    let mut map = HashedMap::new();
    map.insert_hashed("public-key", public_key);
    map.insert_hashed("pop-base", pop_base);
    map.insert_hashed("pop-key", pop_key);
    map.insert_hashed("blinder-public-key", blinder_public_key);
    map.insert_hashed("blinder-pop-key", blinder_pop_key);

    random_oracle_to_scalar(DOMAIN_POP_ENCRYPTION_KEY, &map)
}

/// Prove the Possession of an EncryptionKey.
#[allow(dead_code)]
pub fn prove_pop(
    instance: &EncryptionKeyInstance,
    witness: &BIG,
    rng: &mut impl RAND,
) -> Result<EncryptionKeyPop, EncryptionKeyPopError> {
    // Check validity of the instance
    if !instance.public_key.equals(&instance.g1_gen.mul(witness)) {
        return Err(EncryptionKeyPopError::InvalidInstance);
    }
    // First Move
    let pop_base = random_oracle_to_miracl_g1(DOMAIN_POP_ENCRYPTION_KEY, instance);
    let pop_key = pop_base.mul(witness);

    let mut random_scalar = ZeroizedBIG {
        big: BIG::randomnum(&curve_order(), rng),
    };
    let blinder_public_key = instance.g1_gen.mul(&random_scalar.big);
    let blinder_pop_key = pop_base.mul(&random_scalar.big);

    // Challenge
    let challenge = pop_challenge(
        &instance.public_key,
        &pop_base,
        &pop_key,
        &blinder_public_key,
        &blinder_pop_key,
    );

    // Response
    let mut response = field_mul(&challenge, witness);
    response = field_add(&response, &random_scalar.big);

    random_scalar.zeroize();

    Ok(EncryptionKeyPop {
        pop_key,
        challenge,
        response,
    })
}

/// Verifies the Proof of Possession of an EncryptionKey.
#[allow(dead_code)]
pub fn verify_pop(
    instance: &EncryptionKeyInstance,
    pop: &EncryptionKeyPop,
) -> Result<(), EncryptionKeyPopError> {
    let pop_base = random_oracle_to_miracl_g1(DOMAIN_POP_ENCRYPTION_KEY, instance);

    let minus_challenge = BIG::modneg(&pop.challenge, &curve_order());
    let blinder_public_key =
        instance
            .public_key
            .mul2(&minus_challenge, &instance.g1_gen, &pop.response);
    let blinder_pop_key = pop.pop_key.mul2(&minus_challenge, &pop_base, &pop.response);
    // Challenge
    let challenge = pop_challenge(
        &instance.public_key,
        &pop_base,
        &pop.pop_key,
        &blinder_public_key,
        &blinder_pop_key,
    );

    if BIG::comp(&challenge, &pop.challenge) != 0 {
        return Err(EncryptionKeyPopError::InvalidProof);
    }
    Ok(())
}
