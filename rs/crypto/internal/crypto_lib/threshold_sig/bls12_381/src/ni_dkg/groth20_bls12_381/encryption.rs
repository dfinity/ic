#![allow(clippy::needless_range_loop)]

//! Groth20 forward secure encryption API.
//!
//! This file translates to and from an external library that does the
//! mathematics.

use super::types::FsEncryptionKeySetWithPop;
use super::ALGORITHM_ID;
use crate::api::ni_dkg_errors::{
    CspDkgVerifyDealingError, DecryptError, EncryptAndZKProveError, MalformedPublicKeyError,
    SizeError,
};
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_types::sign::threshold_sig::{
    ni_dkg::ni_dkg_groth20_bls12_381::{
        FsEncryptionCiphertextBytes, FsEncryptionPublicKey, NodeIndex, ZKProofDec, ZKProofShare,
    },
    ni_dkg::Epoch,
    public_coefficients::bls12_381::PublicCoefficientsBytes,
};
use ic_types::{crypto::error::InvalidArgumentError, crypto::AlgorithmId, NumberOfNodes};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::convert::TryFrom;

mod crypto {

    pub use crate::ni_dkg::fs_ni_dkg::forward_secure::{
        dec_chunks, enc_chunks, kgen, verify_ciphertext_integrity, EncryptionWitness,
        FsEncryptionCiphertext, PlaintextChunks, SecretKey, SysParam,
    };
    pub use crate::ni_dkg::fs_ni_dkg::nizk_chunking::{
        prove_chunking, verify_chunking, ChunkingInstance, ChunkingWitness, ProofChunking,
    };
    pub use crate::ni_dkg::fs_ni_dkg::nizk_sharing::{
        prove_sharing, verify_sharing, ProofSharing, SharingInstance, SharingWitness,
    };
}

pub use crypto::SecretKey;

#[cfg(test)]
mod tests;

/// Generates a forward secure key pair.
///
/// # Arguments
/// * `seed` - randomness used to seed the PRNG for generating the keys. It must
///   be treated as a secret.
/// * `associated_data` - public information for the Proof of Possession of the
///   key.
pub fn create_forward_secure_key_pair(
    seed: Seed,
    associated_data: &[u8],
) -> FsEncryptionKeySetWithPop {
    let rng = &mut seed.into_rng();
    let (lib_public_key_with_pop, lib_secret_key) =
        crypto::kgen(associated_data, crypto::SysParam::global(), rng);
    let (public_key, pop) = lib_public_key_with_pop.serialize();
    let secret_key = lib_secret_key.serialize();
    FsEncryptionKeySetWithPop {
        public_key,
        pop,
        secret_key,
    }
}

/// Updates the provided key.
///
/// Note: If the lowest supported epoch of the secret key is greater than or
/// equal to the threshold cutoff epoch, the secret key is unchanged.
///
/// This mutates the key inplace,
/// to avoid copying the sensitive information in memory.
///
/// # Arguments
/// * `secret_key` - The forward-secure encryption key to be updated.
/// * `epoch` - The earliest epoch at which to retain keys.
/// * `seed` - Randomness used in updating the secret key to the given `epoch`.
pub fn update_key_inplace_to_epoch(secret_key: &mut crypto::SecretKey, epoch: Epoch, seed: Seed) {
    let rng = &mut seed.into_rng();
    if let Some(current_epoch) = secret_key.current_epoch() {
        if current_epoch < epoch {
            secret_key.update_to(epoch, crypto::SysParam::global(), rng);
        }
    }
}

/// Encrypts several messages to several recipients
///
/// # Errors
/// This should never return an error if the protocol is followed.  Every error
/// should be prevented by the caller validating the arguments beforehand.
pub fn encrypt_and_prove(
    seed: Seed,
    key_message_pairs: &[(FsEncryptionPublicKey, Scalar)],
    epoch: Epoch,
    public_coefficients: &PublicCoefficientsBytes,
    associated_data: &[u8],
) -> Result<(FsEncryptionCiphertextBytes, ZKProofDec, ZKProofShare), EncryptAndZKProveError> {
    let receivers = key_message_pairs.len();

    let public_keys = {
        let mut public_keys = Vec::with_capacity(receivers);
        for receiver_index in 0..receivers {
            let public_key_bytes = key_message_pairs[receiver_index].0.as_bytes();
            let pk = G1Affine::deserialize(public_key_bytes).map_err(|_| {
                EncryptAndZKProveError::MalformedFsPublicKeyError {
                    receiver_index: receiver_index as u32,
                    error: MalformedPublicKeyError {
                        algorithm: AlgorithmId::NiDkg_Groth20_Bls12_381,
                        key_bytes: Some(public_key_bytes.to_vec()),
                        internal_error: "Could not parse public key.".to_string(),
                    },
                }
            })?;

            public_keys.push(pk);
        }
        public_keys
    };

    let plaintext_chunks = key_message_pairs
        .iter()
        .map(|(_, s)| crypto::PlaintextChunks::from_scalar(s))
        .collect::<Vec<_>>();

    let keys_and_messages = {
        let mut v = Vec::with_capacity(key_message_pairs.len());

        for i in 0..key_message_pairs.len() {
            v.push((public_keys[i].clone(), plaintext_chunks[i].clone()));
        }

        v
    };

    let rng = &mut seed.into_rng();
    let (ciphertext, encryption_witness) = crypto::enc_chunks(
        &keys_and_messages,
        epoch,
        associated_data,
        crypto::SysParam::global(),
        rng,
    );

    let chunking_proof = prove_chunking(
        &public_keys,
        &ciphertext,
        &plaintext_chunks,
        &encryption_witness,
        rng,
    );

    let public_coefficients = G2Affine::batch_deserialize(&public_coefficients.coefficients)
        .map_err(|_| EncryptAndZKProveError::MalformedPublicCoefficients)?;

    let sharing_proof = prove_sharing(
        &public_keys,
        &public_coefficients,
        &ciphertext,
        &plaintext_chunks,
        &encryption_witness,
        rng,
    );

    #[cfg(test)]
    {
        assert_eq!(
            crypto::verify_chunking(
                &crypto::ChunkingInstance::new(
                    public_keys.clone(),
                    ciphertext.ciphertext_chunks().to_vec(),
                    ciphertext.randomizers_r().clone(),
                ),
                &chunking_proof,
            ),
            Ok(()),
            "We just created an invalid chunking proof"
        );
        let combined_ciphertexts: Vec<_> = ciphertext
            .ciphertext_chunks()
            .iter()
            .map(|s| util::g1_from_big_endian_chunks(s))
            .collect();

        assert_eq!(
            crypto::verify_sharing(
                &crypto::SharingInstance::new(
                    public_keys,
                    public_coefficients,
                    util::g1_from_big_endian_chunks(ciphertext.randomizers_r()),
                    combined_ciphertexts,
                ),
                &sharing_proof,
            ),
            Ok(()),
            "We just created an invalid sharing proof"
        );
    }

    Ok((
        ciphertext.serialize(),
        chunking_proof.serialize(),
        sharing_proof.serialize(),
    ))
}

/// Decrypts a single message
///
/// # Returns
/// The plaintext chunks
///
/// # Errors
/// This will return an error if the `epoch` is below the `secret_key` epoch.
pub fn decrypt(
    ciphertext: &FsEncryptionCiphertextBytes,
    secret_key: &crypto::SecretKey,
    node_index: NodeIndex,
    epoch: Epoch,
    associated_data: &[u8],
) -> Result<Scalar, DecryptError> {
    let index = usize::try_from(node_index).map_err(|_| {
        DecryptError::SizeError(SizeError {
            message: format!("Node index is too large for this machine: {}", node_index),
        })
    })?;
    if index >= ciphertext.ciphertext_chunks.len() {
        return Err(DecryptError::InvalidReceiverIndex {
            num_receivers: NumberOfNodes::from(ciphertext.ciphertext_chunks.len() as NodeIndex),
            node_index,
        });
    }
    if let Some(current_epoch) = secret_key.current_epoch() {
        if epoch < current_epoch {
            return Err(DecryptError::EpochTooOld {
                ciphertext_epoch: epoch,
                secret_key_epoch: current_epoch,
            });
        }
    }
    let ciphertext = crypto::FsEncryptionCiphertext::deserialize(ciphertext)
        .map_err(DecryptError::MalformedCiphertext)?;
    crypto::dec_chunks(secret_key, index, &ciphertext, epoch, associated_data)
        .map_err(|_| DecryptError::InvalidChunk)
}

/// Zero knowledge proof of correct chunking
///
/// Note: The crypto::nizk API data types are inconsistent with those used in
/// crypto::forward_secure so we need a thin wrapper to convert.
fn prove_chunking<R: RngCore + CryptoRng>(
    public_keys: &[G1Affine],
    ciphertext: &crypto::FsEncryptionCiphertext,
    plaintext_chunks: &[crypto::PlaintextChunks],
    encryption_witness: &crypto::EncryptionWitness,
    rng: &mut R,
) -> crypto::ProofChunking {
    let big_plaintext_chunks: Vec<_> = plaintext_chunks
        .iter()
        .map(|chunks| chunks.chunks_as_scalars())
        .collect();

    let chunking_instance = crypto::ChunkingInstance::new(
        public_keys.to_vec(),
        ciphertext.ciphertext_chunks().to_vec(),
        ciphertext.randomizers_r().clone(),
    );

    let chunking_witness =
        crypto::ChunkingWitness::new(encryption_witness.witness().clone(), big_plaintext_chunks);

    crypto::prove_chunking(&chunking_instance, &chunking_witness, rng)
}

/// Zero knowledge proof of correct sharing
fn prove_sharing<R: RngCore + CryptoRng>(
    receiver_fs_public_keys: &[G1Affine],
    public_coefficients: &[G2Affine],
    ciphertext: &crypto::FsEncryptionCiphertext,
    plaintext_chunks: &[crypto::PlaintextChunks],
    encryption_witness: &crypto::EncryptionWitness,
    rng: &mut R,
) -> crypto::ProofSharing {
    // Convert fs encryption data:
    let combined_ciphertexts: Vec<_> = ciphertext
        .ciphertext_chunks()
        .iter()
        .map(|s| util::g1_from_big_endian_chunks(s))
        .collect();

    let combined_r = util::g1_from_big_endian_chunks(ciphertext.randomizers_r());

    let combined_r_scalar = util::scalar_from_big_endian_chunks(encryption_witness.witness());

    let combined_plaintexts = plaintext_chunks
        .iter()
        .map(|chunks| chunks.recombine_to_scalar())
        .collect::<Vec<_>>();

    crypto::prove_sharing(
        &crypto::SharingInstance::new(
            receiver_fs_public_keys.to_vec(),
            public_coefficients.to_vec(),
            combined_r,
            combined_ciphertexts,
        ),
        &crypto::SharingWitness::new(combined_r_scalar, combined_plaintexts),
        rng,
    )
}

/// Verifies zero-knowledge proofs associated to forward-secure encryptions.
///
/// # Errors
/// * `CspDkgVerifyDealingError::MalformedFsPublicKeyError` if any of
///   `receiver_fs_public_keys` is malformed or invalid.
/// * `CspDkgVerifyDealingError::MalformedDealingError` if `ciphertexts` is
///   malformed or invalid.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if the integrity of
///   `ciphertexts` doesn't verify.
/// * `CspDkgVerifyDealingError::MalformedDealingError` if `chunking_proof` is
///   malformed or invalid.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if `chunking_proof`
///   doesn't verify.
/// * `CspDkgVerifyDealingError::MalformedDealingError` if `public_coefficients`
///   is malformed or invalid.
/// * `CspDkgVerifyDealingError::MalformedDealingError` if `sharing_proof` is
///   malformed or invalid.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if `sharing_proof` doesn't
///   verify.
pub fn verify_zk_proofs(
    epoch: Epoch,
    receiver_fs_public_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    public_coefficients: &PublicCoefficientsBytes,
    ciphertexts: &FsEncryptionCiphertextBytes,
    chunking_proof: &ZKProofDec,
    sharing_proof: &ZKProofShare,
    associated_data: &[u8],
) -> Result<(), CspDkgVerifyDealingError> {
    // Conversions
    let public_keys: Result<Vec<G1Affine>, CspDkgVerifyDealingError> = receiver_fs_public_keys
        .values()
        .zip(0..)
        .map(|(public_key, receiver_index)| {
            G1Affine::deserialize(public_key.as_bytes()).map_err(|parse_error| {
                let error = MalformedPublicKeyError {
                    algorithm: ALGORITHM_ID,
                    key_bytes: Some(public_key.as_bytes()[..].to_vec()),
                    internal_error: format!("{:?}", parse_error),
                };
                CspDkgVerifyDealingError::MalformedFsPublicKeyError {
                    receiver_index,
                    error,
                }
            })
        })
        .collect();
    let public_keys = public_keys?;

    let ciphertext = crypto::FsEncryptionCiphertext::deserialize(ciphertexts).map_err(|error| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: error.to_string(),
        })
    })?;

    // TODO(CRP-2525) The proofs can be verified independently

    crypto::verify_ciphertext_integrity(
        &ciphertext,
        epoch,
        associated_data,
        crypto::SysParam::global(),
    )
    .map_err(|_| {
        CspDkgVerifyDealingError::InvalidDealingError(InvalidArgumentError {
            message: "Ciphertext integrity check failed".to_string(),
        })
    })?;

    let chunking_proof = crypto::ProofChunking::deserialize(chunking_proof).ok_or_else(|| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: "Could not parse proof of correct encryption".to_string(),
        })
    })?;

    // Verify proof
    crypto::verify_chunking(
        &crypto::ChunkingInstance::new(
            public_keys.clone(),
            ciphertext.ciphertext_chunks().to_vec(),
            ciphertext.randomizers_r().clone(),
        ),
        &chunking_proof,
    )
    .map_err(|_| {
        let error = InvalidArgumentError {
            message: "Invalid chunking proof".to_string(),
        };
        CspDkgVerifyDealingError::InvalidDealingError(error)
    })?;

    // More conversions
    let public_coefficients = public_coefficients
        .coefficients
        .iter()
        .map(G2Affine::deserialize)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
                message: "Could not parse public coefficients".to_string(),
            })
        })?;

    let combined_r = util::g1_from_big_endian_chunks(ciphertext.randomizers_r());
    let combined_ciphertexts: Vec<_> = ciphertext
        .ciphertext_chunks()
        .iter()
        .map(|s| util::g1_from_big_endian_chunks(s))
        .collect();
    let sharing_proof = crypto::ProofSharing::deserialize(sharing_proof).ok_or_else(|| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: "Could not parse proof of correct sharing".to_string(),
        })
    })?;

    crypto::verify_sharing(
        &crypto::SharingInstance::new(
            public_keys,
            public_coefficients,
            combined_r,
            combined_ciphertexts,
        ),
        &sharing_proof,
    )
    .map_err(|_| {
        let error = InvalidArgumentError {
            message: "Invalid sharing proof".to_string(),
        };
        CspDkgVerifyDealingError::InvalidDealingError(error)
    })
}

mod util {
    use ic_crypto_internal_bls12_381_type::{G1Affine, G1Projective, Scalar};

    /// Combine a big endian array of group elements (first chunk is the
    /// most significant) into a single group element.
    pub fn g1_from_big_endian_chunks(terms: &[G1Affine]) -> G1Affine {
        let mut acc = G1Projective::identity();

        for term in terms {
            for _ in 0..16 {
                acc = acc.double();
            }

            acc += term;
        }

        acc.to_affine()
    }

    /// Combine a big endian array of field elements (first chunk is the
    /// most significant) into a single field element.
    pub fn scalar_from_big_endian_chunks(terms: &[Scalar]) -> Scalar {
        let factor = Scalar::from_u64(1 << 16);

        let mut acc = Scalar::zero();
        for term in terms {
            acc *= &factor;
            acc += term;
        }

        acc
    }
}
