//! Generating and verifying Proofs of Possession (PoP)

use crate::ni_dkg::fs_ni_dkg::random_oracles::{
    HashedMap, UniqueHash, random_oracle_to_g1, random_oracle_to_scalar,
};
use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, Scalar};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    FrBytes, FsEncryptionPop, G1Bytes,
};
use rand::{CryptoRng, RngCore};

const DOMAIN_POP_ENCRYPTION_KEY: &str = "ic-pop-encryption";

/// Proof of Possession (PoP) of the Encryption Key.
#[derive(Clone, Debug)]
pub struct EncryptionKeyPop {
    pop_key: G1Affine,
    challenge: Scalar,
    response: Scalar,
}

impl EncryptionKeyPop {
    pub fn new(pop_key: G1Affine, challenge: Scalar, response: Scalar) -> Self {
        Self {
            pop_key,
            challenge,
            response,
        }
    }

    pub fn serialize(&self) -> FsEncryptionPop {
        FsEncryptionPop {
            pop_key: G1Bytes(self.pop_key.serialize()),
            challenge: FrBytes(self.challenge.serialize()),
            response: FrBytes(self.response.serialize()),
        }
    }
}

/// Instance for the Possession of the Encryption Key.
pub struct EncryptionKeyInstance {
    g1_gen: G1Affine,
    public_key: G1Affine,
    associated_data: Vec<u8>,
}

impl EncryptionKeyInstance {
    pub fn new(public_key: &G1Affine, associated_data: &[u8]) -> Self {
        Self {
            g1_gen: G1Affine::generator().clone(),
            public_key: public_key.clone(),
            associated_data: associated_data.to_vec(),
        }
    }
}

/// A PoP could not be generated or verified
#[derive(Clone, Eq, PartialEq, Debug)]
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
pub fn prove_pop<R: RngCore + CryptoRng>(
    instance: &EncryptionKeyInstance,
    witness: &Scalar,
    rng: &mut R,
) -> Result<EncryptionKeyPop, EncryptionKeyPopError> {
    // Check validity of the instance
    if instance.public_key != (&instance.g1_gen * witness).to_affine() {
        return Err(EncryptionKeyPopError::InvalidInstance);
    }

    // First Move
    let pop_base = random_oracle_to_g1(DOMAIN_POP_ENCRYPTION_KEY, instance);
    let pop_key = G1Affine::from(&pop_base * witness);

    let random_scalar = Scalar::random(rng);

    let blinder_public_key = G1Affine::from(&instance.g1_gen * &random_scalar);
    let blinder_pop_key = G1Affine::from(&pop_base * &random_scalar);

    // Challenge
    let challenge = generate_pop_challenge(
        &instance.public_key,
        &pop_base,
        &pop_key,
        &blinder_public_key,
        &blinder_pop_key,
    );

    // Response
    let response = &challenge * witness + random_scalar;

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

    let blinder_public_key = G1Projective::mul2_affine_vartime(
        &instance.public_key,
        &minus_challenge,
        &&instance.g1_gen,
        &pop.response,
    );

    let blinder_pop_key =
        G1Projective::mul2_affine_vartime(&pop.pop_key, &minus_challenge, &pop_base, &pop.response);

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
