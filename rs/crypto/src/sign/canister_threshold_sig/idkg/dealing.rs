//! Implementations of IDkgProtocol related to dealings

use crate::sign::basic_sig::{self, BasicSigVerifierInternal};
use crate::sign::canister_threshold_sig::idkg::utils::{
    MegaKeyFromRegistryError, fetch_idkg_dealing_encryption_public_key_from_registry,
    retrieve_mega_public_key_from_registry,
};
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::{
    BasicSignatureCspVault, CspVault, IDkgCreateDealingVaultError, IDkgDealingInternalBytes,
    IDkgTranscriptOperationInternalBytes,
};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    IDkgDealingInternal, IDkgTranscriptOperationInternal, publicly_verify_dealing,
};
use ic_interfaces_registry::RegistryClient;
use ic_types::NodeId;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
    IDkgVerifyInitialDealingsError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgReceivers, IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::signature::BasicSignature;
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub fn create_dealing(
    vault: &dyn CspVault,
    self_node_id: &NodeId,
    registry: &dyn RegistryClient,
    params: &IDkgTranscriptParams,
    metrics: &CryptoMetrics,
) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
    let self_index =
        params
            .dealer_index(*self_node_id)
            .ok_or(IDkgCreateDealingError::NotADealer {
                node_id: *self_node_id,
            })?;

    let key_protos = params
        .receivers()
        .iter()
        .map(|(_index, receiver)| {
            fetch_idkg_dealing_encryption_public_key_from_registry(
                &receiver,
                registry,
                params.registry_version(),
            )
        })
        .collect::<Result<Vec<_>, MegaKeyFromRegistryError>>()?;

    let transcript_operation_internal_bytes =
        IDkgTranscriptOperationInternalBytes::from(params.operation_type());

    let internal_dealing = vault
        .idkg_create_dealing(
            params.algorithm_id(),
            params.context_data(),
            self_index,
            params.reconstruction_threshold(),
            key_protos,
            transcript_operation_internal_bytes,
        )
        .map_err(|e| {
            idkg_create_dealing_vault_error_into_idkg_create_dealing_error(e, params.receivers())
        })?;

    let unsigned_dealing = IDkgDealing {
        transcript_id: params.transcript_id(),
        internal_dealing_raw: internal_dealing.into_vec(),
    };

    sign_dealing(unsigned_dealing, *self_node_id, vault, metrics)
}

fn sign_dealing(
    dealing: IDkgDealing,
    signer: NodeId,
    vault: &dyn BasicSignatureCspVault,
    metrics: &CryptoMetrics,
) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
    basic_sig::sign(&dealing, vault, metrics)
        .map(|signature| SignedIDkgDealing {
            signature: BasicSignature { signature, signer },
            content: dealing,
        })
        .map_err(|crypto_error| IDkgCreateDealingError::SignatureError {
            internal_error: format!("{crypto_error}"),
        })
}

pub fn verify_dealing_private(
    vault: &Arc<dyn CspVault>,
    self_node_id: &NodeId,
    registry: &dyn RegistryClient,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) -> Result<(), IDkgVerifyDealingPrivateError> {
    if signed_dealing.idkg_dealing().transcript_id != params.transcript_id() {
        return Err(IDkgVerifyDealingPrivateError::InvalidArgument(format!(
            "mismatching transcript IDs in dealing ({:?}) and params ({:?})",
            signed_dealing.idkg_dealing().transcript_id,
            params.transcript_id(),
        )));
    }
    let dealer_index = params
        .dealer_index(signed_dealing.dealer_id())
        .ok_or_else(|| {
            IDkgVerifyDealingPrivateError::InvalidArgument(format!(
                "failed to determine dealer index: node {:?} is not a dealer",
                signed_dealing.dealer_id()
            ))
        })?;
    let self_receiver_index = params
        .receiver_index(*self_node_id)
        .ok_or(IDkgVerifyDealingPrivateError::NotAReceiver)?;
    let self_mega_pubkey =
        retrieve_mega_public_key_from_registry(self_node_id, registry, params.registry_version())?;

    vault.idkg_verify_dealing_private(
        params.algorithm_id(),
        IDkgDealingInternalBytes::from(signed_dealing.idkg_dealing().dealing_to_bytes()),
        dealer_index,
        self_receiver_index,
        KeyId::from(&self_mega_pubkey),
        params.context_data(),
    )
}

impl From<MegaKeyFromRegistryError> for IDkgVerifyDealingPrivateError {
    fn from(mega_key_from_registry_error: MegaKeyFromRegistryError) -> Self {
        type Mkfre = MegaKeyFromRegistryError;
        type Ivdpe = IDkgVerifyDealingPrivateError;
        match mega_key_from_registry_error {
            Mkfre::RegistryError(e) => Ivdpe::RegistryError(e),
            Mkfre::PublicKeyNotFound {
                node_id,
                registry_version,
            } => Ivdpe::PublicKeyNotInRegistry {
                node_id,
                registry_version,
            },
            Mkfre::UnsupportedAlgorithm { algorithm_id } => {
                Ivdpe::UnsupportedAlgorithm { algorithm_id }
            }
            Mkfre::MalformedPublicKey { node_id, key_bytes } => {
                Ivdpe::MalformedPublicKey { node_id, key_bytes }
            }
        }
    }
}

#[allow(clippy::result_large_err)]
pub fn verify_dealing_public<C: CspSigner>(
    csp_client: &C,
    registry: &dyn RegistryClient,
    params: &IDkgTranscriptParams,
    signed_dealing: &SignedIDkgDealing,
) -> Result<(), IDkgVerifyDealingPublicError> {
    // Check the dealing is for the correct transcript ID
    if params.transcript_id() != signed_dealing.idkg_dealing().transcript_id {
        return Err(IDkgVerifyDealingPublicError::TranscriptIdMismatch);
    }

    let dealer_id = signed_dealing.dealer_id();
    BasicSigVerifierInternal::verify_basic_sig(
        csp_client,
        registry,
        &signed_dealing.signature.signature,
        signed_dealing.idkg_dealing(),
        dealer_id,
        params.registry_version(),
    )
    .map_err(
        |crypto_error| IDkgVerifyDealingPublicError::InvalidSignature {
            error: format!(
                "Invalid basic signature on signed iDKG dealing \
                 from signer {dealer_id}",
            ),
            crypto_error,
        },
    )?;

    let internal_dealing =
        IDkgDealingInternal::deserialize(&signed_dealing.idkg_dealing().internal_dealing_raw)
            .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
                reason: format!("{e:?}"),
            })?;

    // Compute CSP operation. Same of IDKM operation type, but wrapping the polynomial commitment from the transcripts.

    let internal_operation = IDkgTranscriptOperationInternal::try_from(params.operation_type())
        .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
            reason: format!("{e:?}"),
        })?;

    let dealer_index =
        params
            .dealer_index(dealer_id)
            .ok_or(IDkgVerifyDealingPublicError::InvalidDealing {
                reason: "No such dealer".to_string(),
            })?;

    let number_of_receivers = params.receivers().count();

    publicly_verify_dealing(
        params.algorithm_id(),
        &internal_dealing,
        &internal_operation,
        params.reconstruction_threshold(),
        dealer_index,
        number_of_receivers,
        &params.context_data(),
    )
    .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
        reason: format!("{e:?}"),
    })
}

#[allow(clippy::result_large_err)]
pub fn verify_initial_dealings<C: CspSigner>(
    csp_client: &C,
    registry: &dyn RegistryClient,
    params: &IDkgTranscriptParams,
    initial_dealings: &InitialIDkgDealings,
) -> Result<(), IDkgVerifyInitialDealingsError> {
    if params != initial_dealings.params() {
        return Err(IDkgVerifyInitialDealingsError::MismatchingTranscriptParams);
    };
    for (i, signed_dealing) in initial_dealings.dealings().iter().enumerate() {
        verify_dealing_public(
            csp_client,
            registry,
            initial_dealings.params(),
            signed_dealing,
        )
        .map_err(|verify_dealing_public_error| {
            let signer = signed_dealing.signature.signer;
            IDkgVerifyInitialDealingsError::PublicVerificationFailure {
                error: format!(
                    "Failed to publicly verify signed iDKG dealing with index \
                    {i} from signer {signer}: {verify_dealing_public_error}",
                ),
                verify_dealing_public_error,
            }
        })?;
    }
    Ok(())
}

fn idkg_create_dealing_vault_error_into_idkg_create_dealing_error(
    e: IDkgCreateDealingVaultError,
    receivers: &IDkgReceivers,
) -> IDkgCreateDealingError {
    match e{
        IDkgCreateDealingVaultError::MalformedPublicKey {
            receiver_index,
            key_bytes,
        } => {
            receivers.iter().nth(receiver_index as usize).map_or_else(
                || IDkgCreateDealingError::InternalError {
                internal_error: format!("node index {receiver_index} out of bounds for malformed public key {key_bytes:?}"),
            },
             |(_, node_id)|  {
                IDkgCreateDealingError::MalformedPublicKey {
                    node_id,
                    key_bytes: key_bytes.clone(),
                }}
            )
        }
        IDkgCreateDealingVaultError::UnsupportedAlgorithm(algorithm_id) => {
            IDkgCreateDealingError::UnsupportedAlgorithm {
                algorithm_id,
            }
        }
        IDkgCreateDealingVaultError::TransientInternalError(internal_error) => {
            IDkgCreateDealingError::TransientInternalError {
                internal_error,
            }
        }
        IDkgCreateDealingVaultError::SerializationError(internal_error) => {
            IDkgCreateDealingError::SerializationError {
                internal_error,
            }
        }
        IDkgCreateDealingVaultError::InternalError(internal_error) => {
            IDkgCreateDealingError::InternalError {
                internal_error,
            }
        }
        IDkgCreateDealingVaultError::SecretSharesNotFound {
            commitment_string,
        } => {
            IDkgCreateDealingError::SecretSharesNotFound {
                commitment_string,
            }
        }
    }
}
