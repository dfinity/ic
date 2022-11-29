//! Implementations of IDkgProtocol related to dealings

use crate::sign::basic_sig::{BasicSigVerifierInternal, BasicSignerInternal};
use crate::sign::canister_threshold_sig::idkg::utils::{
    get_mega_pubkey, idkg_encryption_keys_from_registry, MegaKeyFromRegistryError,
};
use ic_base_types::RegistryVersion;
use ic_crypto_internal_csp::api::{CspIDkgProtocol, CspSigner};
use ic_crypto_internal_threshold_sig_ecdsa::{
    IDkgDealingInternal, IDkgTranscriptOperationInternal,
};
use ic_interfaces_registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
    IDkgVerifyInitialDealingsError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::signature::BasicSignature;
use ic_types::NodeId;
use std::convert::TryFrom;
use std::sync::Arc;

pub fn create_dealing<C: CspIDkgProtocol + CspSigner>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    params: &IDkgTranscriptParams,
) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
    let self_index =
        params
            .dealer_index(*self_node_id)
            .ok_or(IDkgCreateDealingError::NotADealer {
                node_id: *self_node_id,
            })?;

    let receiver_keys = idkg_encryption_keys_from_registry(
        params.receivers(),
        registry.as_ref(),
        params.registry_version(),
    )?;
    let receiver_keys_vec = receiver_keys
        .iter()
        .map(|(_, k)| k.clone())
        .collect::<Vec<_>>();

    let csp_operation_type = IDkgTranscriptOperationInternal::try_from(params.operation_type())
        .map_err(|e| IDkgCreateDealingError::SerializationError {
            internal_error: format!("{:?}", e),
        })?;

    let internal_dealing = csp_client.idkg_create_dealing(
        params.algorithm_id(),
        &params.context_data(),
        self_index,
        params.reconstruction_threshold(),
        &receiver_keys_vec,
        &csp_operation_type,
    )?;

    let internal_dealing_raw =
        internal_dealing
            .serialize()
            .map_err(|e| IDkgCreateDealingError::SerializationError {
                internal_error: format!("{:?}", e),
            })?;

    let unsigned_dealing = IDkgDealing {
        transcript_id: params.transcript_id(),
        internal_dealing_raw,
    };

    sign_dealing(
        csp_client,
        registry,
        unsigned_dealing,
        *self_node_id,
        params.registry_version(),
    )
}

fn sign_dealing<S: CspSigner>(
    csp_signer: &S,
    registry: &Arc<dyn RegistryClient>,
    dealing: IDkgDealing,
    signer: NodeId,
    registry_version: RegistryVersion,
) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
    BasicSignerInternal::sign_basic(
        csp_signer,
        registry.clone(),
        &dealing,
        signer,
        registry_version,
    )
    .map(|signature| SignedIDkgDealing {
        signature: BasicSignature { signature, signer },
        content: dealing,
    })
    .map_err(|crypto_error| IDkgCreateDealingError::SignatureError {
        internal_error: format!("{}", crypto_error),
    })
}

pub fn verify_dealing_private<C: CspIDkgProtocol>(
    csp_client: &C,
    self_node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
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
    let internal_dealing =
        IDkgDealingInternal::deserialize(&signed_dealing.idkg_dealing().internal_dealing_raw)
            .map_err(|e| {
                IDkgVerifyDealingPrivateError::InvalidArgument(format!(
                    "failed to deserialize internal dealing: {:?}",
                    e
                ))
            })?;
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
        get_mega_pubkey(self_node_id, registry.as_ref(), params.registry_version())?;

    csp_client.idkg_verify_dealing_private(
        params.algorithm_id(),
        &internal_dealing,
        dealer_index,
        self_receiver_index,
        &self_mega_pubkey,
        &params.context_data(),
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

pub fn verify_dealing_public<C: CspIDkgProtocol + CspSigner>(
    csp_client: &C,
    registry: &Arc<dyn RegistryClient>,
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
        Arc::clone(registry),
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
                reason: format!("{:?}", e),
            })?;

    // Compute CSP operation. Same of IDKM operation type, but wrapping the polynomial commitment from the transcripts.

    let internal_operation = IDkgTranscriptOperationInternal::try_from(params.operation_type())
        .map_err(|e| IDkgVerifyDealingPublicError::InvalidDealing {
            reason: format!("{:?}", e),
        })?;

    let dealer_index =
        params
            .dealer_index(dealer_id)
            .ok_or(IDkgVerifyDealingPublicError::InvalidDealing {
                reason: "No such dealer".to_string(),
            })?;

    let number_of_receivers = params.receivers().count();

    csp_client.idkg_verify_dealing_public(
        params.algorithm_id(),
        &internal_dealing,
        &internal_operation,
        params.reconstruction_threshold(),
        dealer_index,
        number_of_receivers,
        &params.context_data(),
    )
}

pub fn verify_initial_dealings<C: CspIDkgProtocol + CspSigner>(
    csp_client: &C,
    registry: &Arc<dyn RegistryClient>,
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
