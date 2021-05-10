//! (deprecated) Ephemeral Key Generation for interactive distributed key
//! generation.

use crate::api::dkg_errors::{DkgVerifyEphemeralError, MalformedPopError};
use crate::dkg::secp256k1::types::{
    EphemeralPop, EphemeralPopBytes, EphemeralPublicKey, EphemeralPublicKeyBytes,
    EphemeralSecretKey, EphemeralSecretKeyBytes, SECP256K1_PUBLIC_KEY_ONE,
};
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_crypto_sha256::Sha256;
use ic_types::{crypto::AlgorithmId, IDkgId, Randomness};
use rand::{CryptoRng, Rng};
use std::convert::TryInto;

#[cfg(test)]
pub mod tests;

const DOMAIN_POP_EPHEMERAL: &str = "pop ephemeral key";
const DOMAIN_POP_EPHEMERAL_NON_REWIND: &str = "pop ephemeral key non-rewind";

/// Generates an ephemeral key pair, with pop.
///
/// # Arguments
/// * `rng` - a cryptographically secure random number generator.
/// * `dkg_id` - the DKG this ephemeral key is to be used for.
/// * `sender` - a name to identify the current node.
/// # Returns
/// * `EphemeralSecretKeyBytes` -  a key that needs to be kept secret by the
///   current node and used for the DKG protocol.  It is not needed once the
///   threshold keys have been derived.
/// * `EphemeralPublicKeyBytes and EphemeralPopBytes` - the corresponding public
///   key and proof of possession.
/// # Panics
/// This method is not expected to panic.
pub fn create_ephemeral<R: Rng + CryptoRng>(
    mut rng: &mut R,
    dkg_id: IDkgId,
    sender: &[u8],
) -> (
    EphemeralSecretKeyBytes,
    EphemeralPublicKeyBytes,
    EphemeralPopBytes,
) {
    let secret_key = EphemeralSecretKey::random(rng);
    let PopData {
        public_key_bytes,
        pop,
        ..
    } = create_pop_data(&mut rng, dkg_id, &secret_key, sender);
    (
        EphemeralSecretKeyBytes::from(secret_key),
        public_key_bytes,
        EphemeralPopBytes::from(pop),
    )
}

/// Creates an ephemeral PoP and significant intermediate values.
fn create_pop_data<'a, R: Rng + CryptoRng>(
    rng: &mut R,
    dkg_id: IDkgId,
    secret_key: &EphemeralSecretKey,
    sender: &'a [u8],
) -> PopData<'a> {
    let public_key = EphemeralPublicKey::from(secret_key);
    let public_key_bytes = EphemeralPublicKeyBytes::from(&public_key);

    // The plain Schnorr pop would require rewinding in the security proof to
    // ensure we can properly simulate dealings with dishonest receivers. The
    // following element allows to implement a "strong DH"-oracle-type
    // computation in the reduction to CDH.

    // spec_h == spec: H is a hash over the inputs, so effectively it captures what
    // the PoP is making a proof about.
    let h_digest = HDigest::<'a> {
        dkg_id,
        public_key_bytes,
        sender,
    };
    let spec_h: EphemeralPublicKey = h_digest.hash_to_secp256k1();
    let spec_ext: EphemeralPublicKey = spec_h.clone() * secret_key;

    // r is a random value, a nonce.
    let r: EphemeralSecretKey = EphemeralSecretKey::random(rng);
    let c_digest = {
        let spec_t = EphemeralPublicKey::from(&r);
        let spec_u: EphemeralPublicKey = spec_h.clone() * &r;
        ChallengeDigest::<'a> {
            dkg_id,
            h_bytes: EphemeralPublicKeyBytes::from(&spec_h),
            public_key_bytes,
            ext_bytes: EphemeralPublicKeyBytes::from(&spec_ext),
            t_bytes: EphemeralPublicKeyBytes::from(&spec_t),
            u_bytes: EphemeralPublicKeyBytes::from(&spec_u),
            sender,
        }
    };
    let spec_c: EphemeralSecretKey = c_digest.hash_to_secret_key();
    let spec_s = spec_c.clone() * secret_key + &r;
    let pop = EphemeralPop {
        spec_ext,
        spec_c,
        spec_s,
    };
    PopData {
        public_key_bytes,
        pop,
        h_digest,
        c_digest,
    }
}

/// Verifies an ephemeral key (e.g. for cases where subgroup checks are
/// necessary)
///
/// # Arguments
/// * `dkg_id` - the DKG this ephemeral key is to be used for.
/// * `sender` - a name for the key holder.
/// * `key` - the public key and pop to be verified.
/// # Error
/// This method SHALL return an error if:
/// * the public key is not a point on the curve.  Note: In this case the public
///   key will fail to parse.
/// * the proof of possession is invalid.
/// # Panics
/// This method is not expected to panic.
pub fn verify_ephemeral(
    dkg_id: IDkgId,
    sender: &[u8],
    key: (EphemeralPublicKeyBytes, EphemeralPopBytes),
) -> Result<(), DkgVerifyEphemeralError> {
    let PopData { pop, c_digest, .. } = verification_pop_data(dkg_id, sender, key)?;

    if EphemeralSecretKeyBytes::from(c_digest.hash_to_secret_key())
        != EphemeralSecretKeyBytes::from(pop.spec_c)
    {
        Err(DkgVerifyEphemeralError::InvalidPopError(
            MalformedPopError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: format!("Pop does not verify for sender: {:?}", sender),
                bytes: Some((key.1).0.to_vec()),
            },
        ))
    } else {
        Ok(())
    }
}

/// Recreates a PoP for verification, keeping intermediate values.
fn verification_pop_data<'a>(
    dkg_id: IDkgId,
    sender: &'a [u8],
    key: (EphemeralPublicKeyBytes, EphemeralPopBytes),
) -> Result<PopData<'_>, DkgVerifyEphemeralError> {
    let (public_key_bytes, pop_bytes) = key;
    let public_key: EphemeralPublicKey = public_key_bytes
        .try_into()
        .map_err(DkgVerifyEphemeralError::MalformedPublicKeyError)?;
    let pop: EphemeralPop = pop_bytes
        .try_into()
        .map_err(DkgVerifyEphemeralError::MalformedPopError)?;
    let h_digest = HDigest::<'a> {
        dkg_id,
        public_key_bytes,
        sender,
    };

    let c_digest = {
        let spec_h: EphemeralPublicKey = h_digest.hash_to_secp256k1();
        let spec_t: EphemeralPublicKey =
            EphemeralPublicKey::from(&pop.spec_s) + public_key * &-pop.spec_c.clone();
        let spec_u: EphemeralPublicKey =
            (spec_h.clone() * &pop.spec_s) + (pop.spec_ext.clone() * &-pop.spec_c.clone());

        ChallengeDigest::<'a> {
            dkg_id,
            h_bytes: EphemeralPublicKeyBytes::from(&spec_h),
            public_key_bytes,
            ext_bytes: EphemeralPublicKeyBytes::from(&pop.spec_ext),
            t_bytes: EphemeralPublicKeyBytes::from(&spec_t),
            u_bytes: EphemeralPublicKeyBytes::from(&spec_u),
            sender,
        }
    };

    Ok(PopData {
        public_key_bytes,
        pop,
        h_digest,
        c_digest,
    })
}

// Values hashed to generate "h" in the spec.
#[derive(Debug, Eq, PartialEq)]
struct HDigest<'a> {
    dkg_id: IDkgId,
    public_key_bytes: EphemeralPublicKeyBytes,
    sender: &'a [u8],
}
impl HDigest<'_> {
    pub fn hash_to_secp256k1(&self) -> EphemeralPublicKey {
        EphemeralPublicKey::from(Randomness::from(self.digest()))
    }
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.write(DomainSeparationContext::new(DOMAIN_POP_EPHEMERAL_NON_REWIND).as_bytes());
        hash.write(&serde_cbor::to_vec(&self.dkg_id).expect("Failed to serialize to CBOR"));
        hash.write(&self.public_key_bytes.0);
        hash.write(self.sender);
        hash.finish()
    }
}

// Values hashed to generate "c" from the spec.
#[derive(Debug, Eq, PartialEq)]
struct ChallengeDigest<'a> {
    dkg_id: IDkgId,
    h_bytes: EphemeralPublicKeyBytes,
    public_key_bytes: EphemeralPublicKeyBytes,
    ext_bytes: EphemeralPublicKeyBytes,
    t_bytes: EphemeralPublicKeyBytes,
    u_bytes: EphemeralPublicKeyBytes,
    sender: &'a [u8],
}
impl ChallengeDigest<'_> {
    pub fn hash_to_secret_key(&self) -> EphemeralSecretKey {
        EphemeralSecretKey::from(Randomness::from(self.digest()))
    }
    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.write(DomainSeparationContext::new(DOMAIN_POP_EPHEMERAL).as_bytes());
        digest.write(&serde_cbor::to_vec(&self.dkg_id).expect("Failed to serialize to CBOR"));
        digest.write(&SECP256K1_PUBLIC_KEY_ONE.0);
        digest.write(&self.h_bytes.0);
        digest.write(&self.public_key_bytes.0);
        digest.write(&self.ext_bytes.0);
        digest.write(&self.t_bytes.0);
        digest.write(&self.u_bytes.0);
        digest.write(self.sender);
        digest.finish()
    }
}

/// Values created when computing or verifying a PoP.
///
/// For valid PoPs, these values match in generation and verification.
#[derive(Debug, Eq, PartialEq)]
struct PopData<'a> {
    public_key_bytes: EphemeralPublicKeyBytes,
    pop: EphemeralPop,
    h_digest: HDigest<'a>,
    c_digest: ChallengeDigest<'a>,
}
