use super::*;

use crate::sign::multi_sig::MultiSigVerifierInternal;
use crate::sign::multi_sig::MultiSignerInternal;
use crate::sign::threshold_sig::{ThresholdSigVerifierInternal, ThresholdSignerInternal};
use ic_crypto_interfaces_sig_verification::{BasicSigVerifierByPublicKey, CanisterSigVerifier};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
use ic_crypto_internal_threshold_sig_bls12381::api::bls_signature_cache_statistics;
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigner, MultiSigVerifier, MultiSigner, ThresholdEcdsaSigVerifier,
    ThresholdEcdsaSigner, ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner,
    ThresholdSigVerifier, ThresholdSigVerifierByPublicKey, ThresholdSigner,
};
use ic_logger::{debug, new_logger};
use ic_types::crypto::KeyPurpose::CommitteeSigning;
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCreateSigShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
    ThresholdSchnorrCombineSigSharesError, ThresholdSchnorrCreateSigShareError,
    ThresholdSchnorrVerifyCombinedSigError, ThresholdSchnorrVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
    ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
};
use ic_types::crypto::threshold_sig::errors::threshold_sign_error::ThresholdSignError;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{
    AlgorithmId, BasicSig, BasicSigOf, CanisterSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSigOf, CryptoError, CryptoResult, IndividualMultiSig, IndividualMultiSigOf,
    Signable, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

pub(crate) use basic_sig::{BasicSigVerifierInternal, BasicSignerInternal};
pub(crate) use threshold_sig::lazily_calculated_public_key_from_store;
pub use threshold_sig::{ThresholdSigDataStore, ThresholdSigDataStoreImpl};

mod basic_sig;
mod canister_threshold_sig;
mod multi_sig;
mod threshold_sig;

pub use canister_threshold_sig::{
    MegaKeyFromRegistryError, get_master_public_key_from_transcript,
    retrieve_mega_public_key_from_registry,
};

#[cfg(test)]
mod tests;
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use ic_types::signature::BasicSignatureBatch;

impl<C: CryptoServiceProvider + Send + Sync, H: Signable> BasicSigner<H>
    for CryptoComponentImpl<C>
{
    fn sign_basic(
        &self,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<H>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "BasicSigner",
            crypto.method_name => "sign_basic",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
            crypto.signer => format!("{:?}", signer),
        );
        let start_time = self.metrics.now();
        let result = BasicSignerInternal::sign_basic(
            &self.csp,
            self.registry_client.as_ref(),
            message,
            signer,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Full,
            "sign_basic",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> BasicSigVerifier<H> for CryptoComponentImpl<C> {
    fn verify_basic_sig(
        &self,
        signature: &BasicSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "BasicSigVerifier",
            crypto.method_name => "verify_basic_sig",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
            crypto.signer => format!("{:?}", signer),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        let result = BasicSigVerifierInternal::verify_basic_sig(
            &self.csp,
            self.registry_client.as_ref(),
            signature,
            message,
            signer,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Full,
            "verify_basic_sig",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn combine_basic_sig(
        &self,
        signatures: BTreeMap<NodeId, &BasicSigOf<H>>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSignatureBatch<H>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "BasicSigVerifier",
            crypto.method_name => "combine_basic_sig",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signature_shares => format!("{:?}", signatures),
        );
        let start_time = self.metrics.now();
        let result = BasicSigVerifierInternal::combine_basic_sig(signatures);
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Full,
            "combine_basic_sig",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_basic_sig_batch(
        &self,
        signature: &BasicSignatureBatch<H>,
        message: &H,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "BasicSigVerifier",
            crypto.method_name => "verify_basic_sig_batch",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signature => format!("{:?}", signature.signatures_map),
        );
        let start_time = self.metrics.now();
        let result = BasicSigVerifierInternal::verify_basic_sig_batch(
            self.vault.as_ref(),
            self.registry_client.as_ref(),
            signature,
            message,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Full,
            "verify_basic_sig_batch",
            MetricsResult::from(&result),
            start_time,
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
    for CryptoComponentImpl<C>
{
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "BasicSigVerifierByPublicBytes",
            crypto.method_name => "verify_basic_sig_by_public_key",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signed_bytes => format!("0x{}", hex::encode(signed_bytes.as_signed_bytes())),
            crypto.public_key => format!("{}", public_key),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        let metrics_label = format!("verify_basic_sig_by_public_key_{}", public_key.algorithm_id);
        let result = ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key(
            public_key.algorithm_id,
            &signed_bytes.as_signed_bytes(),
            &signature.get_ref().0,
            &public_key.key,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::BasicSignature,
            MetricsScope::Full,
            &metrics_label,
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> MultiSigner<H> for CryptoComponentImpl<C> {
    fn sign_multi(
        &self,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<IndividualMultiSigOf<H>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "sign_multi",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signer => format!("{:?}", signer),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
        );
        let start_time = self.metrics.now();
        let result = MultiSignerInternal::sign_multi(
            &self.csp,
            self.registry_client.as_ref(),
            message,
            signer,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Full,
            "sign_multi",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
        );
        result
    }
}

impl<C: CryptoServiceProvider, H: Signable> MultiSigVerifier<H> for CryptoComponentImpl<C> {
    fn verify_multi_sig_individual(
        &self,
        signature: &IndividualMultiSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "verify_multi_sig_individual",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.registry_version => registry_version.get(),
            crypto.signer => format!("{:?}", signer),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        let result = MultiSigVerifierInternal::verify_multi_sig_individual(
            &self.csp,
            self.registry_client.as_ref(),
            signature,
            message,
            signer,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Full,
            "verify_multi_sig_individual",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    /// Combines a non-empty collection of individual signatures into a combined
    /// signature.
    fn combine_multi_sig_individuals(
        &self,
        signatures: BTreeMap<NodeId, IndividualMultiSigOf<H>>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<CombinedMultiSigOf<H>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "combine_multi_sig_individuals",
        );
        debug!(logger;
            crypto.description => format!("start"),
            crypto.registry_version => registry_version.get(),
            crypto.signature_shares => format!("{:?}", signatures),
        );
        let start_time = self.metrics.now();
        let result = MultiSigVerifierInternal::combine_multi_sig_individuals(
            &self.csp,
            self.registry_client.as_ref(),
            signatures,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Full,
            "combine_multi_sig_individuals",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => format!("end"),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
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
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "MultiSigner",
            crypto.method_name => "verify_multi_sig_combined",
        );
        debug!(logger;
            crypto.description => format!("start"),
            crypto.registry_version => registry_version.get(),
            crypto.signature => format!("{:?}", signature),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
            crypto.signer => format!("{:?}", signers),
        );
        let start_time = self.metrics.now();
        let result = MultiSigVerifierInternal::verify_multi_sig_combined(
            &self.csp,
            self.registry_client.as_ref(),
            signature,
            message,
            signers,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::MultiSignature,
            MetricsScope::Full,
            "verify_multi_sig_combined",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => format!("end"),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigner<T> for CryptoComponentImpl<C> {
    // TODO (CRP-479): switch to Result<ThresholdSigShareOf<T>,
    // ThresholdSigDataNotFoundError>
    fn sign_threshold(
        &self,
        message: &T,
        dkg_id: &NiDkgId,
    ) -> CryptoResult<ThresholdSigShareOf<T>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSigner",
            crypto.method_name => "sign_threshold",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_id => format!("{}", dkg_id),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
        );
        let start_time = self.metrics.now();
        let result = ThresholdSignerInternal::sign_threshold(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            message,
            dkg_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Full,
            "sign_threshold",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature_shares => log_ok_content(&result),
        );
        Ok(result?)
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigVerifier<T> for CryptoComponentImpl<C> {
    fn verify_threshold_sig_share(
        &self,
        signature: &ThresholdSigShareOf<T>,
        message: &T,
        dkg_id: &NiDkgId,
        signer: NodeId,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "verify_threshold_sig_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_id => format!("{}", dkg_id),
            crypto.signer => format!("{:?}", signer),
            crypto.signature_shares => format!("{:?}", signature),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
        );
        let start_time = self.metrics.now();
        let result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            signature,
            message,
            dkg_id,
            signer,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Full,
            "verify_threshold_sig_share",
            MetricsResult::from(&result),
            start_time,
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
        dkg_id: &NiDkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "combine_threshold_sig_shares",
        );
        debug!(logger;
            crypto.description => format!("start"),
            crypto.dkg_id => format!("{}", dkg_id),
            crypto.signature_shares => format!("{:?}", shares),
        );
        let start_time = self.metrics.now();
        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            shares,
            dkg_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Full,
            "combine_threshold_sig_shares",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => format!("end"),
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
        );
        result
    }

    fn verify_threshold_sig_combined(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        dkg_id: &NiDkgId,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSigVerifier",
            crypto.method_name => "verify_threshold_sig_combined",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_id => format!("{}", dkg_id),
            crypto.signature => format!("{:?}", signature),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
        );
        let start_time = self.metrics.now();
        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            signature,
            message,
            dkg_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Full,
            "verify_threshold_sig_combined",
            MetricsResult::from(&result),
            start_time,
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
    for CryptoComponentImpl<C>
{
    fn verify_combined_threshold_sig_by_public_key(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSigVerifierByPublicKey",
            crypto.method_name => "verify_combined_threshold_sig_by_public_key",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.subnet_id => format!("{}", subnet_id),
            crypto.registry_version => registry_version.get(),
            crypto.signature => format!("{:?}", signature),
            crypto.signed_bytes => format!("0x{}", hex::encode(message.as_signed_bytes())),
        );
        let start_time = self.metrics.now();
        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &self.csp,
            self.registry_client.as_ref(),
            signature,
            message,
            subnet_id,
            registry_version,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSignature,
            MetricsScope::Full,
            "verify_combined_threshold_sig_by_public_key",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider, S: Signable> CanisterSigVerifier<S> for CryptoComponentImpl<C> {
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<S>,
        signed_bytes: &S,
        public_key: &UserPublicKey,
        root_of_trust: &IcRootOfTrust,
    ) -> CryptoResult<()> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "CanisterSigVerifier",
            crypto.method_name => "verify_canister_sig",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signed_bytes => format!("0x{}", hex::encode(signed_bytes.as_signed_bytes())),
            crypto.public_key => format!("{}", public_key),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        ensure_ic_canister_signature(public_key.algorithm_id)?;
        let result = ic_crypto_standalone_sig_verifier::verify_canister_sig(
            &signed_bytes.as_signed_bytes(),
            &signature.get_ref().0,
            &public_key.key,
            root_of_trust,
        );

        // Processing of the cache statistics for metrics is deliberately
        // part of the canister signature run time metric. It is expected to take
        // very little time, but if something goes wrong, e.g., due to a mutex
        // locking congestion or similar, we should be able to notice that.
        let stats = bls_signature_cache_statistics();
        self.metrics
            .observe_bls12_381_sig_cache_stats(stats.size, stats.hits, stats.misses);

        self.metrics
            .observe_iccsa_verification_duration_seconds(MetricsResult::from(&result), start_time);
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider> ThresholdEcdsaSigner for CryptoComponentImpl<C> {
    fn create_sig_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdEcdsaSigner",
            crypto.method_name => "sign_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
        );
        let start_time = self.metrics.now();
        let result =
            canister_threshold_sig::ecdsa::sign_share(self.vault.as_ref(), &self.node_id, inputs);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdEcdsa,
            MetricsScope::Full,
            "sign_share",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature_shares => log_ok_content(&result),
        );
        result
    }
}

impl<C: CryptoServiceProvider> ThresholdEcdsaSigVerifier for CryptoComponentImpl<C> {
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdEcdsaSigInputs,
        share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdEcdsaSigVerifier",
            crypto.method_name => "verify_sig_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_shares => format!("{:?}", share),
            crypto.signer => format!("{:?}", signer),
            crypto.signature_inputs => format!("{:?}", inputs),
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::ecdsa::verify_sig_share(signer, inputs, share);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdEcdsa,
            MetricsScope::Full,
            "verify_sig_share",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn combine_sig_shares(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdEcdsaSigVerifier",
            crypto.method_name => "combine_sig_shares",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
            crypto.signature_shares => format!{"{:?}", shares},
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::ecdsa::combine_sig_shares(inputs, shares);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdEcdsa,
            MetricsScope::Full,
            "combine_sig_shares",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
        );
        result
    }

    fn verify_combined_sig(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdEcdsaSigVerifier",
            crypto.method_name => "verify_combined_sig",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::ecdsa::verify_combined_signature(inputs, signature);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdEcdsa,
            MetricsScope::Full,
            "verify_combined_sig",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

impl<C: CryptoServiceProvider> ThresholdSchnorrSigner for CryptoComponentImpl<C> {
    fn create_sig_share(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
    ) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSchnorrSigner",
            crypto.method_name => "create_sig_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::schnorr::create_sig_share(
            self.vault.as_ref(),
            &self.node_id,
            inputs,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSchnorr,
            MetricsScope::Full,
            "create_sig_share",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature_shares => log_ok_content(&result),
        );
        result
    }
}

impl<C: CryptoServiceProvider> ThresholdSchnorrSigVerifier for CryptoComponentImpl<C> {
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdSchnorrSigInputs,
        share: &ThresholdSchnorrSigShare,
    ) -> Result<(), ThresholdSchnorrVerifySigShareError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSchnorrSigVerifier",
            crypto.method_name => "verify_sig_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_shares => format!("{:?}", share),
            crypto.signer => format!("{:?}", signer),
            crypto.signature_inputs => format!("{:?}", inputs),
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::schnorr::verify_sig_share(signer, inputs, share);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSchnorr,
            MetricsScope::Full,
            "verify_sig_share",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn combine_sig_shares(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
        shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    ) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSchnorrSigVerifier",
            crypto.method_name => "combine_sig_shares",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
            crypto.signature_shares => format!{"{:?}", shares},
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::schnorr::combine_sig_shares(inputs, shares);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSchnorr,
            MetricsScope::Full,
            "combine_sig_shares",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.signature => log_ok_content(&result),
        );
        result
    }

    fn verify_combined_sig(
        &self,
        inputs: &ThresholdSchnorrSigInputs,
        signature: &ThresholdSchnorrCombinedSignature,
    ) -> Result<(), ThresholdSchnorrVerifyCombinedSigError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "ThresholdSchnorrSigVerifier",
            crypto.method_name => "verify_combined_sig",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signature_inputs => format!("{:?}", inputs),
            crypto.signature => format!("{:?}", signature),
        );
        let start_time = self.metrics.now();
        let result = canister_threshold_sig::schnorr::verify_combined_sig(inputs, signature);
        self.metrics.observe_duration_seconds(
            MetricsDomain::ThresholdSchnorr,
            MetricsScope::Full,
            "verify_combined_sig",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

fn log_err<T: fmt::Display>(error_option: Option<&T>) -> String {
    if let Some(error) = error_option {
        return format!("{error}");
    }
    "none".to_string()
}

fn ensure_ic_canister_signature(algorithm_id: AlgorithmId) -> CryptoResult<()> {
    if algorithm_id != AlgorithmId::IcCanisterSignature {
        return Err(CryptoError::AlgorithmNotSupported {
            algorithm: algorithm_id,
            reason: format!("Expected {:?}", AlgorithmId::IcCanisterSignature),
        });
    }
    Ok(())
}

pub fn log_ok_content<T: fmt::Display, E>(result: &Result<T, E>) -> String {
    if let Ok(content) = result {
        return format!("{content}");
    }
    "none".to_string()
}

pub fn debug_ok_content<T: fmt::Debug, E>(result: &Result<T, E>) -> String {
    if let Ok(content) = result {
        return format!("{content:?}");
    }
    "none".to_string()
}
