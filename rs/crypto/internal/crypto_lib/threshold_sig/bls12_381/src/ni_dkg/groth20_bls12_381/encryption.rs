//! Groth20 forward secure encryption API.
//!
//! This file translates to and from an external library that does the
//! mathematics.

use super::types::{FsEncryptionKeySetWithPop, FsEncryptionSecretKey};
use super::ALGORITHM_ID;
use crate::api::ni_dkg_errors::CspDkgVerifyDealingError;
use crate::api::ni_dkg_errors::{
    DecryptError, EncryptAndZKProveError, MalformedPublicKeyError, SizeError,
};
use conversions::{
    chunking_proof_from_miracl, chunking_proof_into_miracl, ciphertext_from_miracl,
    ciphertext_into_miracl, epoch_from_miracl_secret_key, plaintext_from_bytes, plaintext_to_bytes,
    public_coefficients_to_miracl, public_key_from_miracl, public_key_into_miracl,
    secret_key_from_miracl, secret_key_into_miracl, sharing_proof_from_miracl,
    sharing_proof_into_miracl, Tau,
};
use ic_crypto_internal_bls12381_serde_miracl::miracl_g1_from_bytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    FsEncryptionCiphertext, FsEncryptionPlaintext, FsEncryptionPop, FsEncryptionPublicKey,
    NodeIndex,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    ZKProofDec, ZKProofShare,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_types::crypto::error::InvalidArgumentError;
use ic_types::crypto::AlgorithmId;
use ic_types::{NumberOfNodes, Randomness};
use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::convert::TryFrom;

pub(crate) mod conversions;

mod crypto {
    pub use ic_crypto_internal_fs_ni_dkg::encryption_key_pop::EncryptionKeyPop;
    pub use ic_crypto_internal_fs_ni_dkg::forward_secure::{
        dec_chunks, enc_chunks, epoch_from_tau_vec, kgen, mk_sys_params,
        verify_ciphertext_integrity, BTENode, Bit, PublicKeyWithPop, SecretKey, SysParam,
        ToxicWaste, CRSZ,
    };
    pub use ic_crypto_internal_fs_ni_dkg::nizk_chunking::{
        prove_chunking, verify_chunking, ChunkingInstance, ChunkingWitness, ProofChunking,
    };
    pub use ic_crypto_internal_fs_ni_dkg::nizk_sharing::{
        prove_sharing, verify_sharing, ProofSharing, SharingInstance, SharingWitness,
    };
    pub use ic_crypto_internal_fs_ni_dkg::utils::RAND_ChaCha20;
}
mod miracl {
    pub use miracl_core::bls12381::big::BIG;
    pub use miracl_core::bls12381::ecp::ECP;
    pub use miracl_core::bls12381::ecp2::ECP2;
    pub use miracl_core::bls12381::fp::FP;
    pub use miracl_core::bls12381::fp12::FP12;
    pub use miracl_core::bls12381::rom;
    pub use miracl_core::hmac;
}

#[cfg(test)]
mod tests;

lazy_static! {
    static ref SYS_PARAMS: crypto::SysParam = crypto::mk_sys_params();
}

/// Generates a forward secure key pair.
///
/// # Arguments
/// * `seed` - randomness used to seed the PRNG for generating the keys. It must
///   be treated as a secret.
/// * `associated_data` - public information for the Proof of Possession of the
///   key.
pub fn create_forward_secure_key_pair(
    seed: Randomness,
    associated_data: &[u8],
) -> FsEncryptionKeySetWithPop {
    let mut rng = crypto::RAND_ChaCha20::new(seed.get());
    let (lib_public_key_with_pop, lib_secret_key) =
        crypto::kgen(associated_data, &SYS_PARAMS, &mut rng);
    let (public_key, pop) = public_key_from_miracl(&lib_public_key_with_pop);
    let secret_key = secret_key_from_miracl(&lib_secret_key);
    FsEncryptionKeySetWithPop {
        public_key,
        pop,
        secret_key,
    }
}

/// Verifies that a public key is a point on the curve and that the proof of
/// possession holds.
///
/// # Errors
/// * `Err(())` if
///   - Any of the components of `public_key` is not a correct group element.
///   - The proof of possession doesn't verify.
pub fn verify_forward_secure_key(
    public_key: &FsEncryptionPublicKey,
    pop: &FsEncryptionPop,
    associated_data: &[u8],
) -> Result<(), ()> {
    let crypto_public_key_with_pop = public_key_into_miracl((public_key, pop))?;
    if crypto_public_key_with_pop.verify(associated_data) {
        Ok(())
    } else {
        Err(())
    }
}

/// Forgets keys before the given epoch.
///
/// Note: If the lowest supported epoch of the secret key is greater than or
/// equal to the threshold cutoff epoch, the secret key is unchanged.
///
/// # Arguments
/// * `secret_key` - The forward-secure encryption key to be updated.
/// * `epoch` - The earliest epoch at which to retain keys.
/// * `seed` - Randomness used in updating the secret key to the given `epoch`.
///
/// # Returns
/// A new `FsEncryptionSecretKey`, with keys only at or after the given epoch.
pub fn update_forward_secure_epoch(
    secret_key: &FsEncryptionSecretKey,
    epoch: Epoch,
    seed: Randomness,
) -> FsEncryptionSecretKey {
    let mut rng = crypto::RAND_ChaCha20::new(seed.get());
    let mut secret_key = secret_key_into_miracl(secret_key);
    let tau = Tau::from(epoch);
    if epoch_from_miracl_secret_key(&secret_key) < epoch {
        secret_key.update_to(&tau.0, &SYS_PARAMS, &mut rng);
    }
    secret_key_from_miracl(&secret_key)
}

/// Encrypts several messages to several recipients
///
/// # Errors
/// This should never return an error if the protocol is followed.  Every error
/// should be prevented by the caller validating the arguments beforehand.
///
/// # Panics
/// * If the `enc_chunks` function fails. Though, this truly should never happen
///   (cf. CRP-815).
pub fn encrypt_and_prove(
    seed: Randomness,
    key_message_pairs: &[(FsEncryptionPublicKey, FsEncryptionPlaintext)],
    epoch: Epoch,
    public_coefficients: &PublicCoefficientsBytes,
    associated_data: &[u8],
) -> Result<(FsEncryptionCiphertext, ZKProofDec, ZKProofShare), EncryptAndZKProveError> {
    let public_keys: Result<Vec<miracl::ECP>, EncryptAndZKProveError> = key_message_pairs
        .as_ref()
        .iter()
        .zip(0..)
        .map(|((public_key, _plaintext), receiver_index)| {
            miracl_g1_from_bytes(public_key.as_bytes()).map_err(|_| {
                EncryptAndZKProveError::MalformedFsPublicKeyError {
                    receiver_index,
                    error: MalformedPublicKeyError {
                        algorithm: AlgorithmId::NiDkg_Groth20_Bls12_381,
                        key_bytes: Some(public_key.as_bytes().to_vec()),
                        internal_error: "Could not parse public key.".to_string(),
                    },
                }
            })
        })
        .collect();
    let public_keys = public_keys?;

    let plaintext_chunks: Vec<_> = key_message_pairs
        .as_ref()
        .iter()
        .map(|(_public_key, plaintext)| plaintext_from_bytes(&plaintext.chunks))
        .collect();

    // The API takes a vector of pointers so we need to keep the values but generate
    // another vector with the values.
    let public_key_pointers: Vec<&miracl::ECP> = public_keys.iter().collect();
    let tau = Tau::from(epoch);
    let mut rng = crypto::RAND_ChaCha20::new(seed.get());
    let (ciphertext, toxic_waste) = crypto::enc_chunks(
        &plaintext_chunks,
        public_key_pointers,
        &tau.0[..],
        associated_data,
        &SYS_PARAMS,
        &mut rng,
    )
    .expect(
        "TODO (CRP-815): I think the result should never be None.  Can the return type be changed?",
    );

    let chunking_proof = prove_chunking(
        &public_keys,
        &ciphertext,
        &plaintext_chunks,
        &toxic_waste,
        &mut rng,
    );
    let miracl_public_coefficients = public_coefficients_to_miracl(public_coefficients)
        .map_err(|_| EncryptAndZKProveError::MalformedPublicCoefficients)?;
    let sharing_proof = prove_sharing(
        &public_keys,
        &miracl_public_coefficients,
        &ciphertext,
        &plaintext_chunks,
        &toxic_waste,
        &mut rng,
    );

    #[cfg(test)]
    {
        assert_eq!(
            crypto::verify_chunking(
                &crypto::ChunkingInstance {
                    g1_gen: miracl::ECP::generator(),
                    public_keys: public_keys.clone(),
                    ciphertext_chunks: ciphertext.cc.clone(),
                    randomizers_r: ciphertext.rr.clone(),
                },
                &chunking_proof,
            ),
            Ok(()),
            "We just created an invalid chunking proof"
        );
        let combined_ciphertexts: Vec<miracl::ECP> = ciphertext
            .cc
            .iter()
            .map(util::ecp_from_big_endian_chunks)
            .collect();

        assert_eq!(
            crypto::verify_sharing(
                &crypto::SharingInstance {
                    g1_gen: miracl::ECP::generator(),
                    g2_gen: miracl::ECP2::generator(),
                    public_keys,
                    public_coefficients: miracl_public_coefficients,
                    combined_randomizer: util::ecp_from_big_endian_chunks(&ciphertext.rr),
                    combined_ciphertexts,
                },
                &sharing_proof,
            ),
            Ok(()),
            "We just created an invalid sharing proof"
        );
    }

    Ok((
        ciphertext_from_miracl(&ciphertext),
        chunking_proof_from_miracl(&chunking_proof),
        sharing_proof_from_miracl(&sharing_proof),
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
    ciphertext: &FsEncryptionCiphertext,
    secret_key: &FsEncryptionSecretKey,
    node_index: NodeIndex,
    epoch: Epoch,
    associated_data: &[u8],
) -> Result<FsEncryptionPlaintext, DecryptError> {
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
    let secret_key = secret_key_into_miracl(secret_key);
    if epoch < epoch_from_miracl_secret_key(&secret_key) {
        return Err(DecryptError::EpochTooOld {
            ciphertext_epoch: epoch,
            secret_key_epoch: epoch_from_miracl_secret_key(&secret_key),
        });
    }
    let ciphertext =
        ciphertext_into_miracl(ciphertext).map_err(DecryptError::MalformedCiphertext)?;
    let tau = Tau::from(epoch);
    let decrypt_maybe = crypto::dec_chunks(
        &secret_key,
        index,
        &ciphertext,
        &tau.0[..],
        associated_data,
        &SYS_PARAMS,
    );

    decrypt_maybe
        .map(|decrypt| plaintext_to_bytes(&decrypt))
        .map_err(|_| DecryptError::InvalidChunk)
}

/// Zero knowledge proof of correct chunking
///
/// Note: The crypto::nizk API data types are inconsistent with those used in
/// crypto::forward_secure so we need a thin wrapper to convert.
fn prove_chunking(
    receiver_fs_public_keys: &[miracl::ECP],
    ciphertext: &crypto::CRSZ,
    plaintext_chunks: &[Vec<isize>],
    toxic_waste: &crypto::ToxicWaste,
    rng: &mut crypto::RAND_ChaCha20,
) -> crypto::ProofChunking {
    let big_plaintext_chunks: Vec<Vec<miracl::BIG>> = plaintext_chunks
        .iter()
        .map(|chunks| chunks.iter().copied().map(miracl::BIG::new_int).collect())
        .collect();

    let chunking_instance = crypto::ChunkingInstance {
        g1_gen: miracl::ECP::generator(),
        public_keys: receiver_fs_public_keys.to_vec(),
        ciphertext_chunks: ciphertext.cc.clone(),
        randomizers_r: ciphertext.rr.clone(),
    };

    let chunking_witness = crypto::ChunkingWitness {
        scalars_r: toxic_waste.spec_r.clone(),
        scalars_s: big_plaintext_chunks,
    };

    crypto::prove_chunking(&chunking_instance, &chunking_witness, rng)
}

/// Zero knowledge proof of correct sharing
fn prove_sharing(
    receiver_fs_public_keys: &[miracl::ECP],
    public_coefficients: &[miracl::ECP2],
    ciphertext: &crypto::CRSZ,
    plaintext_chunks: &[Vec<isize>],
    toxic_waste: &crypto::ToxicWaste,
    rng: &mut crypto::RAND_ChaCha20,
) -> crypto::ProofSharing {
    // Convert fs encryption data:
    let combined_ciphertexts: Vec<miracl::ECP> = ciphertext
        .cc
        .iter()
        .map(util::ecp_from_big_endian_chunks)
        .collect();
    let combined_r_scalar: miracl::BIG = util::big_from_big_endian_chunks(&toxic_waste.spec_r);
    let combined_r = util::ecp_from_big_endian_chunks(&ciphertext.rr);
    let combined_plaintexts: Vec<miracl::BIG> = plaintext_chunks
        .iter()
        .map(|receiver_chunks| {
            util::big_from_big_endian_chunks(
                &receiver_chunks
                    .iter()
                    .copied()
                    .map(miracl::BIG::new_int)
                    .collect(),
            )
        })
        .collect();

    crypto::prove_sharing(
        &crypto::SharingInstance {
            g1_gen: miracl::ECP::generator(),
            g2_gen: miracl::ECP2::generator(),
            public_keys: receiver_fs_public_keys.to_vec(),
            public_coefficients: public_coefficients.to_vec(),
            combined_randomizer: combined_r,
            combined_ciphertexts,
        },
        &crypto::SharingWitness {
            scalar_r: combined_r_scalar,
            scalars_s: combined_plaintexts,
        },
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
    ciphertexts: &FsEncryptionCiphertext,
    chunking_proof: &ZKProofDec,
    sharing_proof: &ZKProofShare,
    associated_data: &[u8],
) -> Result<(), CspDkgVerifyDealingError> {
    // Conversions
    let public_keys: Result<Vec<miracl::ECP>, CspDkgVerifyDealingError> = receiver_fs_public_keys
        .values()
        .zip(0..)
        .map(|(public_key, receiver_index)| {
            miracl_g1_from_bytes(public_key.as_bytes()).map_err(|parse_error| {
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

    let ciphertext = ciphertext_into_miracl(&ciphertexts).map_err(|error| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: error.to_string(),
        })
    })?;

    let tau = Tau::from(epoch);
    crypto::verify_ciphertext_integrity(&ciphertext, &tau.0[..], associated_data, &SYS_PARAMS)
        .map_err(|_| {
            CspDkgVerifyDealingError::InvalidDealingError(InvalidArgumentError {
                message: "Ciphertext integrity check failed".to_string(),
            })
        })?;

    let chunking_proof = chunking_proof_into_miracl(&chunking_proof).map_err(|_| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: "Could not parse proof of correct encryption".to_string(),
        })
    })?;

    // Verify proof
    crypto::verify_chunking(
        &crypto::ChunkingInstance {
            g1_gen: miracl::ECP::generator(),
            public_keys: public_keys.clone(),
            ciphertext_chunks: ciphertext.cc.clone(),
            randomizers_r: ciphertext.rr.clone(),
        },
        &chunking_proof,
    )
    .map_err(|_| {
        let error = InvalidArgumentError {
            message: "Invalid chunking proof".to_string(),
        };
        CspDkgVerifyDealingError::InvalidDealingError(error)
    })?;

    // More conversions
    let miracl_public_coefficients =
        public_coefficients_to_miracl(public_coefficients).map_err(|_| {
            CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
                message: "Could not parse public coefficients".to_string(),
            })
        })?;
    let combined_r = util::ecp_from_big_endian_chunks(&ciphertext.rr);
    let combined_ciphertexts: Vec<miracl::ECP> = ciphertext
        .cc
        .iter()
        .map(util::ecp_from_big_endian_chunks)
        .collect();
    let sharing_proof = sharing_proof_into_miracl(sharing_proof).map_err(|_| {
        CspDkgVerifyDealingError::MalformedDealingError(InvalidArgumentError {
            message: "Could not parse proof of correct sharing".to_string(),
        })
    })?;

    crypto::verify_sharing(
        &crypto::SharingInstance {
            g1_gen: miracl::ECP::generator(),
            g2_gen: miracl::ECP2::generator(),
            public_keys,
            public_coefficients: miracl_public_coefficients,
            combined_randomizer: combined_r,
            combined_ciphertexts,
        },
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
    use super::miracl;

    /// Combine a big endian array of group elements (first chunk is the
    /// most significant) into a single group element.
    #[allow(clippy::ptr_arg)] // Vec is the only type we need this for.  Being specific reduces repeated code.
    pub fn ecp_from_big_endian_chunks(data: &Vec<miracl::ECP>) -> miracl::ECP {
        // Note: Relies on miracl::ECP::new() being zero == point at infinity.
        data.iter().fold(miracl::ECP::new(), |acc, term| {
            let mut acc = acc.mul(&miracl::BIG::new_int(1 << 16));
            let mut reduced_term = miracl::ECP::new();
            reduced_term.copy(term);
            reduced_term.affine();
            acc.add(&reduced_term);
            acc.affine(); // Needed to avoid getting an overflow error.
            acc
        })
    }
    /// Combine a big endian array of field elements (first chunk is the
    /// most significant) into a single field element.
    ///     
    /// Note: The field elements stored as Miracl miracl::BIG types, so we
    /// have to do the modular reduction ourselves.  As the array length is
    /// unbounded and miracl::BIG has finite size we cannot do the reduction
    /// safely at the end, so it is done on every iteration.  This is not
    /// cheap.
    #[allow(clippy::ptr_arg)] // Vec is the only type we need this for.  Being specific reduces repeated code.
    pub fn big_from_big_endian_chunks(data: &Vec<miracl::BIG>) -> miracl::BIG {
        // Note: Relies on miracl::BIG::new() being zero.
        let curve_order = miracl::BIG::new_ints(&miracl::rom::CURVE_ORDER);
        data.iter().fold(miracl::BIG::new(), |mut acc, term| {
            acc.shl(16);
            let mut reduced_term = miracl::BIG::new_big(&term);
            reduced_term.rmod(&curve_order);
            acc.add(&reduced_term);
            acc.rmod(&curve_order); // Needed to avoid getting a buffer overflow.
            acc
        })
    }
}
