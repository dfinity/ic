use ic_interfaces::{
    batch_payload::PastPayload,
    consensus::{InvalidPayloadReason, PayloadValidationError, PayloadValidationFailure},
    validation::ValidationError,
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    batch::slice_to_messages, consensus::idkg::VetKdKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShare, messages::CallbackId, NodeId,
};
use std::collections::{BTreeMap, HashSet};

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

// #[cfg(test)]
// mod tests {
//     use core::{convert::From, iter::Iterator};
//     use ic_logger::no_op_logger;
//     use ic_management_canister_types_private::{EcdsaKeyId, VetKdKeyId};
//     use ic_registry_client_fake::FakeRegistryClient;
//     use ic_registry_subnet_features::KeyConfig;
//     use ic_test_utilities_registry::{setup_registry, SubnetRecordBuilder};
//     use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
//     use std::str::FromStr;
//     use std::sync::Arc;

//     use super::*;
//     use crate::test_utils::*;

//     #[test]
//     fn test_parse_past_payload_ids() {
//         let payloads = vec![
//             as_bytes(make_vetkd_agreements([0, 1, 2])),
//             as_bytes(make_vetkd_agreements([2, 3, 4])),
//             as_bytes(make_vetkd_agreements([4, 4, 5])),
//         ];
//         let past_payloads = payloads
//             .iter()
//             .map(|p| as_past_payload(&p))
//             .collect::<Vec<_>>();
//         let past_payload_ids = parse_past_payload_ids(&past_payloads, &no_op_logger());
//         let expected = HashSet::from_iter((0..=5).map(CallbackId::from));
//         assert_eq!(past_payload_ids, expected);
//     }

// fn set_up_chain_key_config_test(
//     config: Option<&ChainKeyConfig>,
// ) -> (SubnetId, Arc<FakeRegistryClient>, RegistryVersion) {
//     let subnet_id = subnet_test_id(1);
//     let registry_version = RegistryVersion::from(10);

//     let subnet_record_builder = SubnetRecordBuilder::from(&[node_test_id(0)]);
//     let subnet_record_builder = if let Some(config) = config {
//         subnet_record_builder.with_chain_key_config(config.clone())
//     } else {
//         subnet_record_builder
//     };

//     let registry = setup_registry(
//         subnet_id,
//         vec![(registry_version.get(), subnet_record_builder.build())],
//     );
//     (subnet_id, registry, registry_version)
// }

// #[test]
// fn test_get_nidkg_chain_key_config_if_disabled() {
//     let (subnet_id, registry, version) = set_up_chain_key_config_test(None);

//     let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
//         .expect("Should successfully get the config");

//     assert!(config.is_none());
// }

// #[test]
// fn test_get_nidkg_chain_key_config_if_enabled_no_keys() {
//     let chain_key_config_with_no_keys = ChainKeyConfig::default();
//     let (subnet_id, registry, version) =
//         set_up_chain_key_config_test(Some(&chain_key_config_with_no_keys));

//     let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
//         .expect("Should successfully get the config");

//     assert!(config.is_none());
// }

// #[test]
// fn test_get_chain_key_config_if_enabled_one_key() {
//     let chain_key_config_with_one_key = ChainKeyConfig {
//         key_configs: vec![KeyConfig {
//             key_id: MasterPublicKeyId::VetKd(
//                 VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap(),
//             ),
//             pre_signatures_to_create_in_advance: 0,
//             max_queue_size: 3,
//         }],
//         ..ChainKeyConfig::default()
//     };

//     let (subnet_id, registry, version) =
//         set_up_chain_key_config_test(Some(&chain_key_config_with_one_key));

//     let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
//         .expect("Should successfully get the config");

//     assert_eq!(config, Some(chain_key_config_with_one_key));
// }

// #[test]
// fn test_get_chain_key_config_if_enabled_one_idkg_key() {
//     let chain_key_config_with_one_key = ChainKeyConfig {
//         key_configs: vec![KeyConfig {
//             key_id: MasterPublicKeyId::Ecdsa(
//                 EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
//             ),
//             pre_signatures_to_create_in_advance: 1,
//             max_queue_size: 3,
//         }],
//         ..ChainKeyConfig::default()
//     };

//     let (subnet_id, registry, version) =
//         set_up_chain_key_config_test(Some(&chain_key_config_with_one_key));

//     let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
//         .expect("Should successfully get the config");

//     assert!(config.is_none());
// }

// #[test]
// fn test_get_chain_key_config_if_enabled_multiple_keys() {
//     let chain_key_config_with_multiple_keys = make_chain_key_config();

//     let (subnet_id, registry, version) =
//         set_up_chain_key_config_test(Some(&chain_key_config_with_multiple_keys));

//     let config = get_nidkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
//         .expect("Should successfully get the config");

//     assert_eq!(config, Some(chain_key_config_with_multiple_keys));
// }
// }
