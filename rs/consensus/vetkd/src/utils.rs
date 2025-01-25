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

#[cfg(test)]
mod tests {
    use core::{convert::From, iter::Iterator};
    use ic_logger::no_op_logger;
    use ic_management_canister_types::{EcdsaKeyId, VetKdKeyId};
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_registry::{setup_registry, SubnetRecordBuilder};
    use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_parse_past_payload_ids() {
        let payloads = vec![
            as_bytes(make_vetkd_agreements([0, 1, 2])),
            as_bytes(make_vetkd_agreements([2, 3, 4])),
            as_bytes(make_vetkd_agreements([4, 4, 5])),
        ];
        let past_payloads = payloads
            .iter()
            .map(|p| as_past_payload(&p))
            .collect::<Vec<_>>();
        let past_payload_ids = parse_past_payload_ids(&past_payloads, &no_op_logger());
        let expected = HashSet::from_iter((0..=5).map(CallbackId::from));
        assert_eq!(past_payload_ids, expected);
    }

    fn set_up_chain_key_config_test(
        config: Option<&ChainKeyConfig>,
    ) -> (SubnetId, Arc<FakeRegistryClient>, RegistryVersion) {
        let subnet_id = subnet_test_id(1);
        let registry_version = RegistryVersion::from(10);

        let subnet_record_builder = SubnetRecordBuilder::from(&[node_test_id(0)]);
        let subnet_record_builder = if let Some(config) = config {
            subnet_record_builder.with_chain_key_config(config.clone())
        } else {
            subnet_record_builder
        };

        let registry = setup_registry(
            subnet_id,
            vec![(registry_version.get(), subnet_record_builder.build())],
        );

        (subnet_id, registry, registry_version)
    }

    #[test]
    fn test_get_nidkg_chain_key_config_if_disabled() {
        let (subnet_id, registry, version) = set_up_chain_key_config_test(None);

        let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
            .expect("Should successfully get the config");

        assert!(config.is_none());
    }

    #[test]
    fn test_get_nidkg_chain_key_config_if_enabled_no_keys() {
        let chain_key_config_with_no_keys = ChainKeyConfig::default();
        let (subnet_id, registry, version) =
            set_up_chain_key_config_test(Some(&chain_key_config_with_no_keys));

        let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
            .expect("Should successfully get the config");

        assert!(config.is_none());
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_one_key() {
        let chain_key_config_with_one_key = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::VetKd(
                    VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap(),
                ),
                pre_signatures_to_create_in_advance: 0,
                max_queue_size: 3,
            }],
            ..ChainKeyConfig::default()
        };

        let (subnet_id, registry, version) =
            set_up_chain_key_config_test(Some(&chain_key_config_with_one_key));

        let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
            .expect("Should successfully get the config");

        assert_eq!(config, Some(chain_key_config_with_one_key));
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_one_idkg_key() {
        let chain_key_config_with_one_key = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::Ecdsa(
                    EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                ),
                pre_signatures_to_create_in_advance: 1,
                max_queue_size: 3,
            }],
            ..ChainKeyConfig::default()
        };

        let (subnet_id, registry, version) =
            set_up_chain_key_config_test(Some(&chain_key_config_with_one_key));

        let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
            .expect("Should successfully get the config");

        assert!(config.is_none());
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_multiple_keys() {
        let chain_key_config_with_multiple_keys = make_chain_key_config();

        let (subnet_id, registry, version) =
            set_up_chain_key_config_test(Some(&chain_key_config_with_multiple_keys));

        let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
            .expect("Should successfully get the config");

        assert_eq!(config, Some(chain_key_config_with_multiple_keys));
    }
}
