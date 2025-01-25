use ic_interfaces::{
    batch_payload::PastPayload,
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    validation::ValidationError,
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, ReplicaLogger};
use ic_management_canister_types::MasterPublicKeyId;
use ic_protobuf::types::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_types::{
    batch::slice_to_messages, consensus::idkg::VetKdKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShare, messages::CallbackId, registry::RegistryClientError,
    NodeId, RegistryVersion, SubnetId, Time,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};

pub(super) fn validation_failed_err(
    err: VetKdPayloadValidationFailure,
) -> Result<(), PayloadValidationError> {
    Err(validation_failed(err))
}

pub(super) fn invalid_artifact_err(
    reason: InvalidVetKdPayloadReason,
) -> Result<(), PayloadValidationError> {
    Err(invalid_artifact(reason))
}

pub(super) fn validation_failed(err: VetKdPayloadValidationFailure) -> PayloadValidationError {
    ValidationError::ValidationFailed(PayloadValidationFailure::VetKdPayloadValidationFailed(err))
}

pub(super) fn invalid_artifact(reason: InvalidVetKdPayloadReason) -> PayloadValidationError {
    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(reason))
}

/// Return the [`ChainKeyConfig`] for the given subnet and registry version,
/// if it contains any keys that require NiDKG (i.e. VetKD).
pub(super) fn get_nidkg_chain_key_config_if_enabled(
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
) -> Result<Option<ChainKeyConfig>, RegistryClientError> {
    if let Some(chain_key_config) =
        registry_client.get_chain_key_config(subnet_id, registry_version)?
    {
        let num_active_key_ids = chain_key_config
            .key_configs
            .iter()
            // Skip keys that don't need to run NIDKG protocol
            .filter(|key_config| !key_config.key_id.is_idkg_key())
            .count();

        if num_active_key_ids == 0 {
            Ok(None)
        } else {
            Ok(Some(chain_key_config))
        }
    } else {
        Ok(None)
    }
}

/// Return the set of Key IDs requiring NiDKG in the given config,
/// and calculate the request expiry time, if a timeout is configured
pub(super) fn get_valid_keys_and_expiry(
    config: ChainKeyConfig,
    context_time: Time,
) -> (BTreeSet<MasterPublicKeyId>, Option<Time>) {
    let valid_keys: BTreeSet<MasterPublicKeyId> = config
        .key_configs
        .iter()
        .filter(|key_config| !key_config.key_id.is_idkg_key())
        .map(|key_config| key_config.key_id.clone())
        .collect();

    let request_expiry_time = config
        .signature_request_timeout_ns
        .and_then(|timeout| context_time.checked_sub(Duration::from_nanos(timeout)));

    (valid_keys, request_expiry_time)
}

pub(super) fn group_shares_by_callback_id<Shares: Iterator<Item = VetKdKeyShare>>(
    shares: Shares,
) -> BTreeMap<CallbackId, BTreeMap<NodeId, VetKdEncryptedKeyShare>> {
    let mut map: BTreeMap<CallbackId, BTreeMap<NodeId, VetKdEncryptedKeyShare>> = BTreeMap::new();
    for share in shares {
        map.entry(share.request_id.callback_id)
            .or_default()
            .insert(share.signer_id, share.share);
    }
    map
}

pub(super) fn parse_past_payload_ids(
    past_payloads: &[PastPayload],
    log: &ReplicaLogger,
) -> HashSet<CallbackId> {
    past_payloads
        .iter()
        .flat_map(|payload| {
            slice_to_messages::<pb::VetKdAgreement>(payload.payload).unwrap_or_else(|err| {
                error!(
                    log,
                    "Failed to parse VetKD past payload for height {}. Error: {}",
                    payload.height,
                    err
                );
                vec![]
            })
        })
        .map(|msg| CallbackId::new(msg.callback_id))
        .collect()
}
