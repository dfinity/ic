use super::get_log_id;
use crate::sign::BasicSigVerifierInternal;
use crate::sign::BasicSignerInternal;
use crate::sign::ThresholdSigDataStore;
use crate::sign::lazily_calculated_public_key_from_store;
use crate::{CryptoComponentImpl, LockableThresholdSigDataStore};
use ic_crypto_internal_bls12_381_vetkd::{
    DerivationContext, EncryptedKeyCombinationError, EncryptedKeyShare,
    EncryptedKeyShareDeserializationError, G2Affine, NodeIndex, PairingInvalidPoint,
    TransportPublicKey, TransportPublicKeyDeserializationError,
};
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::api::ThresholdSignatureCspClient;
use ic_crypto_internal_csp::key_id::KeyIdInstantiationError;
use ic_crypto_internal_csp::vault::api::VetKdEncryptedKeyShareCreationVaultError;
use ic_crypto_internal_csp::{CryptoServiceProvider, key_id::KeyId, vault::api::CspVault};
use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::PublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_interfaces::crypto::VetKdProtocol;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, debug, info, new_logger};
use ic_types::NodeId;
use ic_types::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::vetkd::VetKdDerivationContext;
use ic_types::crypto::vetkd::{
    VetKdArgs, VetKdEncryptedKey, VetKdEncryptedKeyShare, VetKdKeyShareCombinationError,
    VetKdKeyShareCreationError, VetKdKeyShareVerificationError, VetKdKeyVerificationError,
};
use ic_types::crypto::{BasicSig, BasicSigOf};
use std::collections::BTreeMap;
use std::fmt;

impl<C: CryptoServiceProvider> VetKdProtocol for CryptoComponentImpl<C> {
    // TODO(CRP-2639): Adapt VetKdKeyShareCreationError so that clippy exception is no longer needed
    #[allow(clippy::result_large_err)]
    fn create_encrypted_key_share(
        &self,
        args: VetKdArgs,
    ) -> Result<VetKdEncryptedKeyShare, VetKdKeyShareCreationError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "VetKdProtocol",
            crypto.method_name => "create_encrypted_key_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.vetkd_args => format!("{}", args),
        );
        let start_time = self.metrics.now();
        let result = create_encrypted_key_share_internal(
            &self.lockable_threshold_sig_data_store,
            self.registry_client.as_ref(),
            self.vault.as_ref(),
            &self.csp,
            args,
            self.node_id,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::VetKd,
            MetricsScope::Full,
            "create_encrypted_key_share",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.vetkd_key_share => log_ok_content(&result),
        );
        result
    }

    fn verify_encrypted_key_share(
        &self,
        signer: NodeId,
        key_share: &VetKdEncryptedKeyShare,
        args: &VetKdArgs,
    ) -> Result<(), VetKdKeyShareVerificationError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "VetKdProtocol",
            crypto.method_name => "verify_encrypted_key_share",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.signer => format!("{}", signer),
            crypto.vetkd_key_share => format!("{}", key_share),
        );
        let start_time = self.metrics.now();
        let result = verify_encrypted_key_share_internal(
            &self.lockable_threshold_sig_data_store,
            self.registry_client.as_ref(),
            &self.csp,
            key_share,
            signer,
            args,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::VetKd,
            MetricsScope::Full,
            "verify_encrypted_key_share",
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

    fn combine_encrypted_key_shares(
        &self,
        shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        args: &VetKdArgs,
    ) -> Result<VetKdEncryptedKey, VetKdKeyShareCombinationError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "VetKdProtocol",
            crypto.method_name => "combine_encrypted_key_shares",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.vetkd_args => format!("{}", args),
            crypto.vetkd_key_shares => format!("{:?}", shares),
        );
        let start_time = self.metrics.now();
        let result = combine_encrypted_key_shares_internal(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            &self.logger,
            shares,
            args,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::VetKd,
            MetricsScope::Full,
            "combine_encrypted_key_shares",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.vetkd_key => log_ok_content(&result),
        );
        result
    }

    fn verify_encrypted_key(
        &self,
        key: &VetKdEncryptedKey,
        args: &VetKdArgs,
    ) -> Result<(), VetKdKeyVerificationError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "VetKdProtocol",
            crypto.method_name => "verify_encrypted_key",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.vetkd_args => format!("{}", args),
            crypto.vetkd_key => format!("{}", key),
        );
        let start_time = self.metrics.now();
        let result =
            verify_encrypted_key_internal(&self.lockable_threshold_sig_data_store, key, args);
        self.metrics.observe_duration_seconds(
            MetricsDomain::VetKd,
            MetricsScope::Full,
            "verify_encrypted_key",
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

// TODO(CRP-2639): Adapt VetKdKeyShareCreationError so that clippy exception is no longer needed
#[allow(clippy::result_large_err)]
fn create_encrypted_key_share_internal<S: CspSigner>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    registry: &dyn RegistryClient,
    vault: &dyn CspVault,
    csp_signer: &S,
    args: VetKdArgs,
    self_node_id: NodeId,
) -> Result<VetKdEncryptedKeyShare, VetKdKeyShareCreationError> {
    let (pub_coeffs_from_store, registry_version_from_store) = lockable_threshold_sig_data_store
        .read()
        .transcript_data(args.ni_dkg_id)
        .map(|transcript_data| {
            let pub_coeffs = transcript_data.public_coefficients().clone();
            let registry_version = transcript_data.registry_version();
            (pub_coeffs, registry_version)
        })
        .ok_or_else(|| {
            VetKdKeyShareCreationError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                    dkg_id: args.ni_dkg_id.clone(),
                },
            )
        })?;
    let key_id = KeyId::try_from(&pub_coeffs_from_store).map_err(|e| match e {
        KeyIdInstantiationError::InvalidArguments(msg) => {
            VetKdKeyShareCreationError::KeyIdInstantiationError(msg)
        }
    })?;
    let master_public_key = match &pub_coeffs_from_store {
        PublicCoefficients::Bls12_381(pub_coeffs) => pub_coeffs
            .coefficients
            .iter()
            .copied()
            .next()
            .ok_or_else(|| {
                VetKdKeyShareCreationError::InternalError(format!(
                    "public coefficients for NI-DKG ID {} are empty",
                    &args.ni_dkg_id
                ))
            })?,
    };

    let encrypted_key_share = vault
        .create_encrypted_vetkd_key_share(
            key_id,
            master_public_key.as_bytes().to_vec(),
            args.transport_public_key.clone(),
            VetKdDerivationContext {
                caller: *args.caller,
                context: args.context.clone(),
            },
            args.input.clone(),
        )
        .map_err(vetkd_key_share_creation_error_from_vault_error)?;

    let signature = BasicSignerInternal::sign_basic(
        csp_signer,
        registry,
        &encrypted_key_share,
        self_node_id,
        // TODO(CRP-2666): Cleanup: Remove registry_version from BasicSigner::sign_basic API
        registry_version_from_store,
    )
    .map_err(VetKdKeyShareCreationError::KeyShareSigningError)?;

    Ok(VetKdEncryptedKeyShare {
        encrypted_key_share,
        node_signature: signature.get().0,
    })
}

fn vetkd_key_share_creation_error_from_vault_error(
    error: VetKdEncryptedKeyShareCreationVaultError,
) -> VetKdKeyShareCreationError {
    match error {
        VetKdEncryptedKeyShareCreationVaultError::SecretKeyMissingOrWrongType(error) => {
            VetKdKeyShareCreationError::InternalError(format!(
                "secret key missing or wrong type: {error}"
            ))
        }
        VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentMasterPublicKey => {
            VetKdKeyShareCreationError::InternalError("invalid master public key".to_string())
        }
        VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentEncryptionPublicKey => {
            VetKdKeyShareCreationError::InvalidArgumentEncryptionPublicKey
        }
        VetKdEncryptedKeyShareCreationVaultError::TransientInternalError(error) => {
            VetKdKeyShareCreationError::TransientInternalError(error)
        }
    }
}

fn verify_encrypted_key_share_internal<S: CspSigner>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    registry: &dyn RegistryClient,
    csp_signer: &S,
    key_share: &VetKdEncryptedKeyShare,
    signer: NodeId,
    args: &VetKdArgs,
) -> Result<(), VetKdKeyShareVerificationError> {
    let registry_version_from_store = lockable_threshold_sig_data_store
        .read()
        .transcript_data(args.ni_dkg_id)
        .map(|transcript_data| transcript_data.registry_version())
        .ok_or_else(|| {
            VetKdKeyShareVerificationError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                    dkg_id: args.ni_dkg_id.clone(),
                },
            )
        })?;

    let signature = BasicSigOf::new(BasicSig(key_share.node_signature.clone()));
    BasicSigVerifierInternal::verify_basic_sig(
        csp_signer,
        registry,
        &signature,
        &key_share.encrypted_key_share,
        signer,
        registry_version_from_store,
    )
    .map_err(VetKdKeyShareVerificationError::VerificationError)
}

fn combine_encrypted_key_shares_internal<C: ThresholdSignatureCspClient>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    threshold_sig_csp_client: &C,
    logger: &ReplicaLogger,
    shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
    args: &VetKdArgs,
) -> Result<VetKdEncryptedKey, VetKdKeyShareCombinationError> {
    ensure_sufficient_shares_to_fail_fast(
        shares,
        lockable_threshold_sig_data_store,
        args.ni_dkg_id,
    )?;

    let transcript_data_from_store = lockable_threshold_sig_data_store
        .read()
        .transcript_data(args.ni_dkg_id)
        .cloned()
        .ok_or_else(|| {
            VetKdKeyShareCombinationError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                    dkg_id: args.ni_dkg_id.clone(),
                },
            )
        })?;
    let pub_coeffs_from_store = match transcript_data_from_store.public_coefficients() {
        PublicCoefficients::Bls12_381(pub_coeffs) => &pub_coeffs.coefficients,
    };
    let reconstruction_threshold = pub_coeffs_from_store.len();
    let master_public_key = master_pubkey_from_coeffs(pub_coeffs_from_store, args.ni_dkg_id)
        .map_err(|error| match error {
            MasterPubkeyFromCoeffsError::InternalError(msg) => {
                VetKdKeyShareCombinationError::InternalError(msg)
            }
            MasterPubkeyFromCoeffsError::InvalidArgumentMasterPublicKey => {
                VetKdKeyShareCombinationError::InvalidArgumentMasterPublicKey
            }
        })?;
    let transport_public_key =
        TransportPublicKey::deserialize(args.transport_public_key).map_err(|e| match e {
            TransportPublicKeyDeserializationError::InvalidPublicKey => {
                VetKdKeyShareCombinationError::InvalidArgumentEncryptionPublicKey
            }
        })?;
    let clib_shares: Vec<(NodeId, NodeIndex, EncryptedKeyShare)> = shares
        .iter()
        .map(|(&node_id, share)| {
            let node_index = transcript_data_from_store.index(node_id).ok_or(
                VetKdKeyShareCombinationError::InternalError(format!(
                    "missing index for node with ID {node_id} in threshold \
                        sig data store for NI-DKG ID {}",
                    args.ni_dkg_id
                )),
            )?;
            let clib_share = EncryptedKeyShare::deserialize(&share.encrypted_key_share.0).map_err(
                |e| match e {
                    EncryptedKeyShareDeserializationError::InvalidEncryptedKeyShare => {
                        VetKdKeyShareCombinationError::InvalidArgumentEncryptedKeyShare
                    }
                },
            )?;
            Ok((node_id, *node_index, clib_share))
        })
        .collect::<Result<_, _>>()?;
    let clib_shares_for_combine_all: BTreeMap<NodeIndex, EncryptedKeyShare> = clib_shares
        .iter()
        .map(|(_node_id, node_index, clib_share)| (*node_index, clib_share.clone()))
        .collect();
    let context = DerivationContext::new(args.caller.as_slice(), args.context);

    match ic_crypto_internal_bls12_381_vetkd::EncryptedKey::combine_all(
        &clib_shares_for_combine_all,
        reconstruction_threshold,
        &master_public_key,
        &transport_public_key,
        &context,
        args.input,
    ) {
        Ok(encrypted_key) => Ok(encrypted_key),
        Err(EncryptedKeyCombinationError::InsufficientShares) => {
            Err(VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold {
                threshold: reconstruction_threshold,
                share_count: clib_shares_for_combine_all.len()
            })
        }
        Err(EncryptedKeyCombinationError::InvalidShares) => {
            info!(logger, "EncryptedKey::combine_all failed with InvalidShares, \
                falling back to EncryptedKey::combine_valid_shares"
            );

            let clib_shares_for_combine_valid: BTreeMap<NodeIndex, (G2Affine, EncryptedKeyShare)> = clib_shares
                .into_iter()
                .map(|(node_id, node_index, clib_share)| {
                    let node_public_key = lazily_calculated_public_key_from_store(
                        lockable_threshold_sig_data_store,
                        threshold_sig_csp_client,
                        args.ni_dkg_id,
                        node_id,
                    )
                    .map_err(|e| {
                        VetKdKeyShareCombinationError::IndividualPublicKeyComputationError(e)
                    })?;
                    let node_public_key_g2affine = match node_public_key {
                        CspThresholdSigPublicKey::ThresBls12_381(public_key_bytes) => {
                            G2Affine::deserialize_cached(&public_key_bytes.0)
                            .map_err(|_: PairingInvalidPoint| VetKdKeyShareCombinationError::InternalError(
                                format!("individual public key of node with ID {node_id} in threshold sig data store")
                            ))
                        }
                    }?;
                    Ok((node_index, (node_public_key_g2affine, clib_share.clone())))
                })
                .collect::<Result<_, _>>()?;

            ic_crypto_internal_bls12_381_vetkd::EncryptedKey::combine_valid_shares(
                &clib_shares_for_combine_valid,
                reconstruction_threshold,
                &master_public_key,
                &transport_public_key,
                &context,
                args.input,
            )
            .map_err(|e| {
                VetKdKeyShareCombinationError::CombinationError(format!(
                    "failed to combine the valid encrypted vetKD key shares: {e:?}"
                ))
            })
        },
        Err(other_error) => {
            Err(VetKdKeyShareCombinationError::CombinationError(format!(
                "failed to combine the valid encrypted vetKD key shares: {other_error:?}"
            )))
        }
    }
    .map(|encrypted_key| VetKdEncryptedKey {
        encrypted_key: encrypted_key.serialize().to_vec(),
    })
}

fn verify_encrypted_key_internal(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    key: &VetKdEncryptedKey,
    args: &VetKdArgs,
) -> Result<(), VetKdKeyVerificationError> {
    let encrypted_key =
        ic_crypto_internal_bls12_381_vetkd::EncryptedKey::deserialize(&key.encrypted_key)
        .map_err(|e| match e {
            ic_crypto_internal_bls12_381_vetkd::EncryptedKeyDeserializationError::InvalidEncryptedKey => VetKdKeyVerificationError::InvalidArgumentEncryptedKey,
        })?;

    let master_public_key = {
        let pub_coeffs_from_store = lockable_threshold_sig_data_store
            .read()
            .transcript_data(args.ni_dkg_id)
            .map(|data| data.public_coefficients().clone())
            .ok_or_else(|| {
                VetKdKeyVerificationError::ThresholdSigDataNotFound(
                    ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                        dkg_id: args.ni_dkg_id.clone(),
                    },
                )
            })?;
        match pub_coeffs_from_store {
            PublicCoefficients::Bls12_381(bls_coeffs_trusted) => {
                master_pubkey_from_coeffs(&bls_coeffs_trusted.coefficients, args.ni_dkg_id)
                    .map_err(|error| match error {
                        MasterPubkeyFromCoeffsError::InternalError(msg) => {
                            VetKdKeyVerificationError::InternalError(msg)
                        }
                        MasterPubkeyFromCoeffsError::InvalidArgumentMasterPublicKey => {
                            VetKdKeyVerificationError::InvalidArgumentMasterPublicKey
                        }
                    })?
            }
        }
    };

    let transport_public_key =
        TransportPublicKey::deserialize(args.transport_public_key).map_err(|e| match e {
            TransportPublicKeyDeserializationError::InvalidPublicKey => {
                VetKdKeyVerificationError::InvalidArgumentEncryptionPublicKey
            }
        })?;

    match encrypted_key.is_valid(
        &master_public_key,
        &DerivationContext::new(args.caller.as_slice(), args.context),
        args.input,
        &transport_public_key,
    ) {
        true => Ok(()),
        false => Err(VetKdKeyVerificationError::VerificationError),
    }
}

fn ensure_sufficient_shares_to_fail_fast(
    shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    ni_dkg_id: &NiDkgId,
) -> Result<(), VetKdKeyShareCombinationError> {
    let reconstruction_threshold = lockable_threshold_sig_data_store
        .read()
        .transcript_data(ni_dkg_id)
        .map(|data| match data.public_coefficients() {
            PublicCoefficients::Bls12_381(bls_pub_coeffs) => bls_pub_coeffs.coefficients.len(),
        })
        .ok_or_else(|| {
            VetKdKeyShareCombinationError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                    dkg_id: ni_dkg_id.clone(),
                },
            )
        })?;
    let share_count = shares.len();
    if share_count < reconstruction_threshold {
        Err(
            VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold {
                threshold: reconstruction_threshold,
                share_count,
            },
        )
    } else {
        Ok(())
    }
}

fn master_pubkey_from_coeffs(
    pub_coeffs: &[bls12_381::PublicKeyBytes],
    ni_dkg_id: &NiDkgId,
) -> Result<G2Affine, MasterPubkeyFromCoeffsError> {
    let first_coeff = pub_coeffs.iter().copied().next().ok_or_else(|| {
        MasterPubkeyFromCoeffsError::InternalError(format!(
            "failed to determine master public key: public coefficients 
            for NI-DKG ID {ni_dkg_id} are empty"
        ))
    })?;
    let first_coeff_g2 =
        G2Affine::deserialize_cached(&first_coeff).map_err(|_: PairingInvalidPoint| {
            MasterPubkeyFromCoeffsError::InvalidArgumentMasterPublicKey
        })?;
    Ok(first_coeff_g2)
}

enum MasterPubkeyFromCoeffsError {
    InternalError(String),
    InvalidArgumentMasterPublicKey,
}

fn log_err<T: fmt::Display>(error_option: Option<&T>) -> String {
    if let Some(error) = error_option {
        return format!("{error}");
    }
    "none".to_string()
}

pub fn log_ok_content<T: fmt::Display, E>(result: &Result<T, E>) -> String {
    if let Ok(content) = result {
        return format!("{content}");
    }
    "none".to_string()
}
