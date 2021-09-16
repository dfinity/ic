use super::*;

use crate::sign::basic_sig::BasicSigVerifierInternal;
use crate::sign::basic_sig::{BasicSignVerifierByPublicKeyInternal, BasicSignerInternal};
use crate::sign::multi_sig::MultiSigVerifierInternal;
use crate::sign::multi_sig::MultiSignerInternal;
use crate::sign::threshold_sig::{ThresholdSigVerifierInternal, ThresholdSignerInternal};
use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, BasicSigner, CanisterSigVerifier,
    IDkgTranscriptGenerator, MultiSigVerifier, MultiSigner, Signable, ThresholdSigVerifier,
    ThresholdSigVerifierByPublicKey, ThresholdSigner,
};
use ic_logger::{debug, new_logger};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgComplaintVerificationError, IDkgDealingError, IDkgDealingVerificationError,
    IDkgOpeningVerificationError, IDkgTranscriptCreationError, IDkgTranscriptLoadError,
    IDkgTranscriptOpeningError, IDkgTranscriptVerificationError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptParams, VerifiedIDkgDealing,
};
use ic_types::crypto::threshold_sig::errors::threshold_sign_error::ThresholdSignError;
use ic_types::crypto::threshold_sig::ni_dkg::DkgId;
use ic_types::crypto::KeyPurpose::CommitteeSigning;
use ic_types::crypto::{
    AlgorithmId, BasicSig, BasicSigOf, CanisterSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSigOf, CryptoError, CryptoResult, IndividualMultiSig, IndividualMultiSigOf,
    ThresholdSigShareOf, UserPublicKey,
};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
pub use threshold_sig::ThresholdSigDataStore;
pub use threshold_sig::ThresholdSigDataStoreImpl;

mod basic_sig;
mod canister_sig;
mod canister_threshold_sign;
mod multi_sig;
mod threshold_sig;

#[cfg(test)]
mod tests;
// TODO: Remove this indirection:
pub(crate) use ic_crypto_internal_csp::imported_utilities::sign_utils as utils;

impl<C: CryptoServiceProvider, H: Signable> BasicSigner<H> for CryptoComponentFatClient<C> {
    fn sign_basic(
        &self,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<H>> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "BasicSigner",
            crypto.method_name => "sign_basic",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger; crypto.description => "start",);
        let result = BasicSignerInternal::sign_basic(
            &self.csp,
            self.registry_client.clone(),
            message,
            signer,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> BasicSigVerifier<H> for CryptoComponentFatClient<C> {
    fn verify_basic_sig(
        &self,
        signature: &BasicSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "BasicSigVerifier",
            crypto.method_name => "verify_basic_sig",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger; crypto.description => "start",);
        let result = BasicSigVerifierInternal::verify_basic_sig(
            &self.csp,
            Arc::clone(&self.registry_client),
            signature,
            message,
            signer,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, S: Signable> BasicSigVerifierByPublicKey<S>
    for CryptoComponentFatClient<C>
{
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "BasicSigVerifierByPublicBytes",
            crypto.method_name => "verify_basic_sig_by_public_key",
            crypto.signed_bytes => hex::encode(signed_bytes.as_signed_bytes()),
            crypto.public_key => format!("{}", public_key),
        );
        debug!(logger; crypto.description => "start",);
        let result = BasicSignVerifierByPublicKeyInternal::verify_basic_sig_by_public_key(
            &self.csp,
            signature,
            signed_bytes,
            public_key,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> MultiSigner<H> for CryptoComponentFatClient<C> {
    fn sign_multi(
        &self,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<IndividualMultiSigOf<H>> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "sign_multi",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger; crypto.description => "start",);
        let result = MultiSignerInternal::sign_multi(
            &self.csp,
            Arc::clone(&self.registry_client),
            message,
            signer,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> MultiSigVerifier<H> for CryptoComponentFatClient<C> {
    fn verify_multi_sig_individual(
        &self,
        signature: &IndividualMultiSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "verify_multi_sig_individual",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger; crypto.description => "start",);
        let result = MultiSigVerifierInternal::verify_multi_sig_individual(
            &self.csp,
            Arc::clone(&self.registry_client),
            signature,
            message,
            signer,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    /// Combines a non-empty collection of individual signatures into a combined
    /// signature. Panics if called with zero signatures.
    fn combine_multi_sig_individuals(
        &self,
        signatures: BTreeMap<NodeId, IndividualMultiSigOf<H>>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<CombinedMultiSigOf<H>> {
        let signature_count = signatures.len();
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "combine_multi_sig_individuals",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger;
            crypto.description => format!("start; signature count: {}", signature_count),
        );
        let result = MultiSigVerifierInternal::combine_multi_sig_individuals(
            &self.csp,
            Arc::clone(&self.registry_client),
            signatures,
            registry_version,
        );
        debug!(logger;
            crypto.description => format!("end; signature count: {}", signature_count),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    /// Verifies a combined signature from a non-empty set of signers. Panics if
    /// called with zero signers.
    fn verify_multi_sig_combined(
        &self,
        signature: &CombinedMultiSigOf<H>,
        message: &H,
        signers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "verify_multi_sig_combined",
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger;
            crypto.description => format!("start; signers: {:?}", signers),
        );
        let result = MultiSigVerifierInternal::verify_multi_sig_combined(
            &self.csp,
            Arc::clone(&self.registry_client),
            signature,
            message,
            signers.clone(),
            registry_version,
        );
        debug!(logger;
            crypto.description => format!("end; signers: {:?}", signers),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigner<T> for CryptoComponentFatClient<C> {
    // TODO (CRP-479): switch to Result<ThresholdSigShareOf<T>,
    // ThresholdSigDataNotFoundError>
    fn sign_threshold(&self, message: &T, dkg_id: DkgId) -> CryptoResult<ThresholdSigShareOf<T>> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "ThresholdSigner",
            crypto.method_name => "sign_threshold",
            crypto.dkg_id => format!("{}", dkg_id),
        );
        debug!(logger; crypto.description => "start",);
        let result = ThresholdSignerInternal::sign_threshold(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            message,
            dkg_id,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        Ok(result?)
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigVerifier<T>
    for CryptoComponentFatClient<C>
{
    fn verify_threshold_sig_share(
        &self,
        signature: &ThresholdSigShareOf<T>,
        message: &T,
        dkg_id: DkgId,
        signer: NodeId,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "verify_threshold_sig_share",
            crypto.dkg_id => format!("{}", dkg_id),
        );
        debug!(logger; crypto.description => "start",);
        let result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            signature,
            message,
            dkg_id,
            signer,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn combine_threshold_sig_shares(
        &self,
        shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
        dkg_id: DkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>> {
        let nodes_with_share: BTreeSet<NodeId> = shares.keys().cloned().collect();
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "combine_threshold_sig_shares",
            crypto.dkg_id => format!("{}", dkg_id),
        );
        debug!(logger;
            crypto.description => format!("start; nodes with share: {:?}", nodes_with_share),
        );
        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            shares,
            dkg_id,
        );
        debug!(logger;
            crypto.description => format!("end; nodes with share: {:?}", nodes_with_share),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_threshold_sig_combined(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        dkg_id: DkgId,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "verify_threshold_sig_combined",
            crypto.dkg_id => format!("{}", dkg_id),
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            signature,
            message,
            dkg_id,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigVerifierByPublicKey<T>
    for CryptoComponentFatClient<C>
{
    fn verify_combined_threshold_sig_by_public_key(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "ThresholdSigVerifierByPublicKey",
            crypto.method_name => "verify_combined_threshold_sig_by_public_key",
            crypto.subnet_id => format!("{}", subnet_id),
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &self.csp,
            Arc::clone(&self.registry_client),
            signature,
            message,
            subnet_id,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, S: Signable> CanisterSigVerifier<S> for CryptoComponentFatClient<C> {
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "CanisterSigVerifier",
            crypto.method_name => "verify_canister_sig",
            crypto.signed_bytes => hex::encode(signed_bytes.as_signed_bytes()),
            crypto.public_key => format!("{}", public_key),
            crypto.registry_version => registry_version.get(),
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_sig::verify_canister_sig(
            Arc::clone(&self.registry_client),
            signature,
            signed_bytes,
            public_key,
            registry_version,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

/// Currently, these are implemented with noop stubs,
/// while the true implementation is in progress.
impl<C: CryptoServiceProvider> IDkgTranscriptGenerator for CryptoComponentFatClient<C> {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgDealingError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "create_dealing",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_create_dealing(params);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_dealing_public",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_verify_dealing_public(params, dealing);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_dealing_private",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_verify_dealing_private(params, dealing);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BTreeMap<NodeId, VerifiedIDkgDealing>,
    ) -> Result<IDkgTranscript, IDkgTranscriptCreationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "create_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_create_transcript(params, dealings);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgTranscriptVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_verify_transcript(transcript);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgTranscriptLoadError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "load_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_load_transcript(transcript);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_complaint(
        &self,
        transcript_id: IDkgTranscriptId,
        complainer: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgComplaintVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_complaint",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result =
            canister_threshold_sign::mock_verify_complaint(transcript_id, complainer, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn open_transcript(
        &self,
        transcript_id: IDkgTranscriptId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgTranscriptOpeningError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "open_transcript",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result = canister_threshold_sign::mock_open_transcript(transcript_id, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_opening(
        &self,
        transcript_id: IDkgTranscriptId,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgOpeningVerificationError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "verify_opening",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result =
            canister_threshold_sign::mock_verify_opening(transcript_id, opener, opening, complaint);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript_with_openings(
        &self,
        transcript: IDkgTranscript,
        opening: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgTranscriptLoadError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "load_transcript_with_openings",
        );
        debug!(logger;
            crypto.description => "start",
        );
        let result =
            canister_threshold_sign::mock_load_transcript_with_openings(transcript, opening);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn retain_active_transcripts(&self, active_transcripts: &[IDkgTranscriptId]) {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "IDkgTranscriptGenerator",
            crypto.method_name => "retain_active_transcripts",
        );
        debug!(logger;
            crypto.description => "start",
        );
        canister_threshold_sign::mock_retain_active_transcripts(active_transcripts);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => true,
            crypto.error => "none".to_string(),
        );
    }
}

fn log_err<T: fmt::Display>(error_option: Option<&T>) -> String {
    if let Some(error) = error_option {
        return format!("{}", error);
    }
    "none".to_string()
}

pub fn log_ok_content<T: fmt::Display, E>(result: &Result<T, E>) -> String {
    if let Ok(content) = result {
        return format!("{}", content);
    }
    "none".to_string()
}
