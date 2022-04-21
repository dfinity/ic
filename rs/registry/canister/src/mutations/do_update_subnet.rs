use std::convert::TryFrom;

use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
use dfn_core::println;
use ic_nns_common::registry::decode_or_panic;
use serde::Serialize;

use ic_base_types::{subnet_id_into_protobuf, SubnetId};
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::registry::{
    crypto::v1::EcdsaSigningSubnetList,
    subnet::v1::{GossipAdvertConfig, SubnetRecord},
};
use ic_registry_keys::{make_ecdsa_signing_subnet_list_key, make_subnet_record_key};
use ic_registry_subnet_features::{EcdsaConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use ic_types::p2p::build_default_gossip_config;

/// Updates the subnet's configuration in the registry.
///
/// This method is called by the proposals canister, after a proposal
/// for updating a new subnet has been accepted.
impl Registry {
    pub fn do_update_subnet(&mut self, payload: UpdateSubnetPayload) {
        println!("{}do_update_subnet: {:?}", LOG_PREFIX, payload);

        let subnet_id = payload.subnet_id;
        let subnet_record = self.get_subnet_or_panic(subnet_id);

        let new_subnet_record = merge_subnet_record(subnet_record.clone(), payload.clone());
        let subnet_record_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_subnet_record_key(subnet_id).as_bytes().to_vec(),
            value: encode_or_panic(&new_subnet_record),
        };

        let mut mutations = vec![subnet_record_mutation];

        if let Some(ecdsa_key_signing_enable) = payload.ecdsa_key_signing_enable {
            for key_id in &ecdsa_key_signing_enable {
                let ecdsa_signing_subnet_list_key_id = make_ecdsa_signing_subnet_list_key(key_id);
                let mut ecdsa_signing_subnet_list_record = self
                    .get_ecdsa_signing_subnet_list_or_default(&ecdsa_signing_subnet_list_key_id);

                let ecdsa_signing_subnet_list_contains_subnet_id = ecdsa_signing_subnet_list_record
                    .subnets
                    .contains(&subnet_id_into_protobuf(subnet_id));

                // Proposals cannote enable signing for a key unless the key was
                // previously held by the subnet.
                let current_keys = subnet_record
                    .ecdsa_config
                    .as_ref()
                    .map(|ecdsa_config| ecdsa_config.key_ids.clone())
                    .unwrap_or_default();

                if !current_keys.contains(&key_id.into())
                    && !ecdsa_signing_subnet_list_contains_subnet_id
                {
                    panic!("Proposal attempts to enable signing for ECDSA key {} on Subnet {},  but the subnet does not hold the given key. A proposal to add that key to the subnet must first be separately submitted.",
                        key_id, subnet_id
                    );
                }

                if !ecdsa_signing_subnet_list_contains_subnet_id {
                    ecdsa_signing_subnet_list_record
                        .subnets
                        .push(subnet_id_into_protobuf(subnet_id));

                    let ecdsa_signing_subnet_list_mutation = RegistryMutation {
                        mutation_type: registry_mutation::Type::Upsert as i32,
                        key: ecdsa_signing_subnet_list_key_id.as_bytes().to_vec(),
                        value: encode_or_panic(&ecdsa_signing_subnet_list_record),
                    };

                    mutations.push(ecdsa_signing_subnet_list_mutation);
                }
            }
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    fn get_ecdsa_signing_subnet_list_or_default(
        &self,
        ecdsa_signing_subnet_list_key_id: &str,
    ) -> EcdsaSigningSubnetList {
        match self.get(
            ecdsa_signing_subnet_list_key_id.as_bytes(),
            self.latest_version(),
        ) {
            Some(RegistryValue {
                value: ecdsa_signing_subnet_list_record_vec,
                version: _,
                deletion_marker: _,
            }) => decode_or_panic::<EcdsaSigningSubnetList>(
                ecdsa_signing_subnet_list_record_vec.to_vec(),
            ),
            None => EcdsaSigningSubnetList { subnets: vec![] },
        }
    }
}

/// The payload of a proposal to update an existing subnet's configuration.
///
/// See /rs/protobuf/def/registry/subnet/v1/subnet.proto
/// for the explanation of the fields for the SubnetRecord.
///
/// Setting a field to `None` means that its value should not be changed. The
/// rest of the fields will be overwritten in the SubnetRecord.
///
/// Note that `replica_version_id` and `membership`
/// are intentionally left out as they are updated via other proposals and/or
/// handlers because they are subject to invariants, e.g. the replica version
/// must be "blessed".
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateSubnetPayload {
    pub subnet_id: SubnetId,

    pub max_ingress_bytes_per_message: Option<u64>,
    pub max_ingress_messages_per_block: Option<u64>,
    pub max_block_payload_size: Option<u64>,
    pub unit_delay_millis: Option<u64>,
    pub initial_notary_delay_millis: Option<u64>,
    pub dkg_interval_length: Option<u64>,
    pub dkg_dealings_per_block: Option<u64>,

    pub max_artifact_streams_per_peer: Option<u32>,
    pub max_chunk_wait_ms: Option<u32>,
    pub max_duplicity: Option<u32>,
    pub max_chunk_size: Option<u32>,
    pub receive_check_cache_size: Option<u32>,
    pub pfn_evaluation_period_ms: Option<u32>,
    pub registry_poll_period_ms: Option<u32>,
    pub retransmission_request_ms: Option<u32>,
    pub advert_best_effort_percentage: Option<u32>,

    pub set_gossip_config_to_default: bool,

    pub start_as_nns: Option<bool>,

    pub subnet_type: Option<SubnetType>,

    pub is_halted: Option<bool>,

    pub max_instructions_per_message: Option<u64>,
    pub max_instructions_per_round: Option<u64>,
    pub max_instructions_per_install_code: Option<u64>,
    pub features: Option<SubnetFeatures>,

    pub ecdsa_config: Option<EcdsaConfig>,
    pub ecdsa_key_signing_enable: Option<Vec<EcdsaKeyId>>,

    pub max_number_of_canisters: Option<u64>,

    pub ssh_readonly_access: Option<Vec<String>>,
    pub ssh_backup_access: Option<Vec<String>>,
}

// Sets the value of a field in record `a` if the provided value `b` is not
// `None`, otherwise does nothing.
macro_rules! maybe_set {
    ($a:tt, $b:tt) => {
        if let Some(val) = $b {
            $a.$b = val.into();
        }
    };
}

// Sets the value of an optional field in record `a` if the provided value `b`
// is not `None`, otherwise does nothing.
macro_rules! maybe_set_option {
    ($a:tt, $b:tt) => {
        if let Some(val) = $b {
            $a.$b = Some(val.into());
        }
    };
}

// Returns true if any gossip related field is set for an override in the
// provided payload or false otherwise.
fn is_any_gossip_field_set(payload: &UpdateSubnetPayload) -> bool {
    payload.max_artifact_streams_per_peer.is_some()
        || payload.max_chunk_wait_ms.is_some()
        || payload.max_duplicity.is_some()
        || payload.max_chunk_size.is_some()
        || payload.receive_check_cache_size.is_some()
        || payload.pfn_evaluation_period_ms.is_some()
        || payload.registry_poll_period_ms.is_some()
        || payload.retransmission_request_ms.is_some()
        || payload.advert_best_effort_percentage.is_some()
}

// Merges the changes included in the `UpdateSubnetPayload` to the given
// `SubnetRecord`. If any value in the provided payload is None, then it is
// skipped, otherwise it overwrites the corresponding value in the
// `SubnetRecord`.
#[allow(clippy::cognitive_complexity)]
fn merge_subnet_record(
    mut subnet_record: SubnetRecord,
    payload: UpdateSubnetPayload,
) -> SubnetRecord {
    if subnet_record.gossip_config.is_none()
        && !payload.set_gossip_config_to_default
        && is_any_gossip_field_set(&payload)
    {
        panic!(
            "Attempt to update gossip config params when the subnet record does not have any gossip \
            config set and a default one was not requested. Use `set_gossip_config_to_default=true` \
            and try again."
        );
    }

    let UpdateSubnetPayload {
        subnet_id: _subnet_id,
        max_ingress_bytes_per_message,
        max_ingress_messages_per_block,
        max_block_payload_size,
        unit_delay_millis,
        initial_notary_delay_millis,
        dkg_interval_length,
        dkg_dealings_per_block,
        max_artifact_streams_per_peer,
        max_chunk_wait_ms,
        max_duplicity,
        max_chunk_size,
        receive_check_cache_size,
        pfn_evaluation_period_ms,
        registry_poll_period_ms,
        retransmission_request_ms,
        advert_best_effort_percentage,
        set_gossip_config_to_default,
        start_as_nns,
        subnet_type,
        is_halted,
        max_instructions_per_message,
        max_instructions_per_round,
        max_instructions_per_install_code,
        features,
        ecdsa_config,
        ecdsa_key_signing_enable: _,
        max_number_of_canisters,
        ssh_readonly_access,
        ssh_backup_access,
    } = payload;

    maybe_set!(subnet_record, max_ingress_bytes_per_message);
    maybe_set!(subnet_record, max_ingress_messages_per_block);
    maybe_set!(subnet_record, max_block_payload_size);
    maybe_set!(subnet_record, unit_delay_millis);
    maybe_set!(subnet_record, initial_notary_delay_millis);
    maybe_set!(subnet_record, dkg_interval_length);
    maybe_set!(subnet_record, dkg_dealings_per_block);

    // Set a default gossip config if it was requested...
    if set_gossip_config_to_default {
        subnet_record.gossip_config = Some(build_default_gossip_config());
    }

    // and overwrite fields provided by the user as necessary.
    let mut gossip_config = subnet_record.gossip_config.take().unwrap();
    maybe_set!(gossip_config, max_artifact_streams_per_peer);
    maybe_set!(gossip_config, max_chunk_wait_ms);
    maybe_set!(gossip_config, max_duplicity);
    maybe_set!(gossip_config, max_chunk_size);
    maybe_set!(gossip_config, receive_check_cache_size);
    maybe_set!(gossip_config, pfn_evaluation_period_ms);
    maybe_set!(gossip_config, registry_poll_period_ms);
    maybe_set!(gossip_config, retransmission_request_ms);
    let advert_config = advert_best_effort_percentage.map(|val| GossipAdvertConfig {
        best_effort_percentage: val,
    });
    maybe_set!(gossip_config, advert_config);
    subnet_record.gossip_config = Some(gossip_config);

    maybe_set!(subnet_record, start_as_nns);

    // See EXC-408: changing of the subnet type is disabled.
    if let Some(value) = subnet_type {
        assert_eq!(subnet_record.subnet_type, i32::from(value));
    }

    maybe_set!(subnet_record, is_halted);

    maybe_set!(subnet_record, max_instructions_per_message);
    maybe_set!(subnet_record, max_instructions_per_round);
    maybe_set!(subnet_record, max_instructions_per_install_code);

    // TODO(NNS1-1129): Removal of a threshold ECDSA key from a subnet is not supported
    if let Some(new_ecdsa_config) = ecdsa_config.as_ref() {
        if let Some(existing_ecdsa_record) = subnet_record.ecdsa_config.as_ref() {
            assert!(existing_ecdsa_record
                .key_ids
                .iter()
                .all(|x| new_ecdsa_config
                    .key_ids
                    .contains(&EcdsaKeyId::try_from(x.clone()).unwrap())));
        }
    }
    maybe_set_option!(subnet_record, features);
    maybe_set_option!(subnet_record, ecdsa_config);

    maybe_set!(subnet_record, max_number_of_canisters);

    maybe_set!(subnet_record, ssh_readonly_access);
    maybe_set!(subnet_record, ssh_backup_access);

    subnet_record
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_ic00_types::EcdsaCurve;
    use ic_protobuf::registry::subnet::v1::{GossipAdvertConfig, GossipConfig};
    use ic_registry_subnet_type::SubnetType;
    use ic_types::p2p::{
        MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_WAIT_MS, MAX_DUPLICITY, PFN_EVALUATION_PERIOD_MS,
        RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS, RETRANSMISSION_REQUEST_MS,
    };
    use ic_types::{PrincipalId, SubnetId};
    use std::str::FromStr;

    fn make_ecdsa_key(name: &str) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: name.to_string(),
        }
    }

    fn make_default_payload_for_tests() -> UpdateSubnetPayload {
        UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: Some(256),
            max_ingress_messages_per_block: Some(256),
            max_block_payload_size: Some(200),
            unit_delay_millis: Some(300),
            initial_notary_delay_millis: Some(200),
            dkg_interval_length: Some(8),
            dkg_dealings_per_block: Some(1),
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(10),
            max_duplicity: Some(5),
            max_chunk_size: Some(1024),
            receive_check_cache_size: Some(500),
            pfn_evaluation_period_ms: Some(5000),
            registry_poll_period_ms: Some(4000),
            retransmission_request_ms: Some(7000),
            advert_best_effort_percentage: Some(50),
            set_gossip_config_to_default: false,
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: Some(SubnetFeatures {
                ecdsa_signatures: false,
                canister_sandboxing: false,
                http_requests: false,
                bitcoin_testnet_feature: None,
            }),
            ecdsa_config: Some(EcdsaConfig {
                quadruples_to_create_in_advance: 10,
                key_ids: vec![make_ecdsa_key("key_id_1")],
            }),
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_2")]),
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
        }
    }

    #[test]
    fn can_override_all_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfig {
                max_artifact_streams_per_peer: 10,
                max_chunk_wait_ms: 100,
                max_duplicity: 2,
                max_chunk_size: 10,
                receive_check_cache_size: 1024,
                pfn_evaluation_period_ms: 100,
                registry_poll_period_ms: 100,
                retransmission_request_ms: 100,
                advert_config: None,
            }),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: Some(256),
            max_ingress_messages_per_block: Some(256),
            max_block_payload_size: Some(200),
            unit_delay_millis: Some(300),
            initial_notary_delay_millis: Some(200),
            dkg_interval_length: Some(8),
            dkg_dealings_per_block: Some(1),
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(10),
            max_duplicity: Some(5),
            max_chunk_size: Some(1024),
            receive_check_cache_size: Some(500),
            pfn_evaluation_period_ms: Some(5000),
            registry_poll_period_ms: Some(4000),
            retransmission_request_ms: Some(7000),
            advert_best_effort_percentage: Some(50),
            set_gossip_config_to_default: false,
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: Some(SubnetFeatures {
                ecdsa_signatures: false,
                canister_sandboxing: false,
                http_requests: false,
                bitcoin_testnet_feature: None,
            }),
            ecdsa_config: Some(EcdsaConfig {
                quadruples_to_create_in_advance: 10,
                key_ids: vec![make_ecdsa_key("key_id_1")],
            }),
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_2")]),
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 256,
                max_ingress_messages_per_block: 256,
                max_block_payload_size: 200,
                unit_delay_millis: 300,
                initial_notary_delay_millis: 200,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 8,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: 0,
                    max_chunk_wait_ms: 10,
                    max_duplicity: 5,
                    max_chunk_size: 1024,
                    receive_check_cache_size: 500,
                    pfn_evaluation_period_ms: 5000,
                    registry_poll_period_ms: 4000,
                    retransmission_request_ms: 7000,
                    advert_config: Some(GossipAdvertConfig {
                        best_effort_percentage: 50
                    }),
                }),
                start_as_nns: true,
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                max_instructions_per_message: 6_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 300_000_000_000,
                features: Some(
                    SubnetFeatures {
                        ecdsa_signatures: false,
                        canister_sandboxing: false,
                        http_requests: false,
                        bitcoin_testnet_feature: None,
                    }
                    .into()
                ),
                ecdsa_config: Some(
                    EcdsaConfig {
                        quadruples_to_create_in_advance: 10,
                        key_ids: vec![make_ecdsa_key("key_id_1")]
                    }
                    .into()
                ),
                max_number_of_canisters: 10,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
            }
        );
    }

    #[test]
    fn can_override_some_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfig {
                max_artifact_streams_per_peer: 10,
                max_chunk_wait_ms: 100,
                max_duplicity: 2,
                max_chunk_size: 10,
                receive_check_cache_size: 1024,
                pfn_evaluation_period_ms: 100,
                registry_poll_period_ms: 100,
                retransmission_request_ms: 100,
                advert_config: Some(GossipAdvertConfig {
                    best_effort_percentage: 10,
                }),
            }),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: Some(100),
            initial_notary_delay_millis: None,
            dkg_interval_length: Some(2),
            dkg_dealings_per_block: Some(1),
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(10),
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: Some(200),
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: Some(50),
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 100,
                initial_notary_delay_millis: 1500,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: 0,
                    max_chunk_wait_ms: 10,
                    max_duplicity: 2,
                    max_chunk_size: 10,
                    receive_check_cache_size: 200,
                    pfn_evaluation_period_ms: 100,
                    registry_poll_period_ms: 100,
                    retransmission_request_ms: 100,
                    advert_config: Some(GossipAdvertConfig {
                        best_effort_percentage: 10,
                    }),
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 50,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
            }
        );
    }

    #[test]
    #[should_panic]
    fn merging_ecdsa_key_ids_works_correctly() {
        let ecdsa_config = Some(EcdsaConfig {
            key_ids: vec![make_ecdsa_key("key_id_1")],
            quadruples_to_create_in_advance: 0,
        });

        let subnet_record = SubnetRecord {
            ecdsa_config: Some(
                EcdsaConfig {
                    key_ids: vec![make_ecdsa_key("key_id_1")],
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };

        let mut payload_1 = make_default_payload_for_tests();
        payload_1.ecdsa_config = ecdsa_config.clone();

        assert_eq!(
            merge_subnet_record(subnet_record.clone(), payload_1),
            subnet_record
        );

        let mut new_subnet_record = subnet_record.clone();
        new_subnet_record.ecdsa_config = ecdsa_config.map(|c| c.into());

        let mut payload_2 = make_default_payload_for_tests();
        payload_2.ecdsa_config = Some(EcdsaConfig {
            key_ids: vec![make_ecdsa_key("key_id_1"), make_ecdsa_key("key_id_2")],
            ..Default::default()
        });
        assert_eq!(
            &merge_subnet_record(subnet_record, payload_2),
            &new_subnet_record
        );
    }

    #[test]
    #[should_panic]
    fn panic_on_removing_ecdsa_key_ids() {
        let subnet_record = SubnetRecord {
            ecdsa_config: Some(
                EcdsaConfig {
                    key_ids: vec![make_ecdsa_key("key_id_1")],
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };

        let mut payload = make_default_payload_for_tests();
        payload.ecdsa_config = Some(EcdsaConfig {
            key_ids: vec![make_ecdsa_key("key_id_2")],
            ..Default::default()
        });

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    #[should_panic]
    fn panic_on_removing_ecdsa_config_none_value() {
        let subnet_record = SubnetRecord {
            ecdsa_config: Some(
                EcdsaConfig {
                    key_ids: vec![make_ecdsa_key("key_id_1")],
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };

        let mut payload = make_default_payload_for_tests();
        payload.ecdsa_config = None;

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    #[should_panic]
    // This test confirms that if `set_gossip_config_to_default` = false and the
    // existing subnet record does not have a gossip config and some gossip related
    // fields are set to override, `merge_subnet_record` panics as expected.
    fn can_handle_invalid_combination_of_set_gossip_config_to_default() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: None,
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: Some(100),
            initial_notary_delay_millis: None,
            dkg_interval_length: Some(2),
            dkg_dealings_per_block: Some(1),
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(10),
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: Some(200),
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::Application),
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    fn can_set_default_gossip_config_and_override_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
            max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
            max_duplicity: Some(MAX_DUPLICITY),
            max_chunk_size: Some(10),
            receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
            pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
            registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
            retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
            advert_best_effort_percentage: Some(30),
            set_gossip_config_to_default: true,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 500,
                initial_notary_delay_millis: 1500,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 0,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
                    max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
                    max_duplicity: MAX_DUPLICITY,
                    max_chunk_size: 10,
                    receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
                    pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
                    registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
                    retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
                    advert_config: Some(GossipAdvertConfig {
                        best_effort_percentage: 30
                    }),
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 7_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 0,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
            }
        );
    }

    #[test]
    fn update_advert_config() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfig {
                max_artifact_streams_per_peer: 10,
                max_chunk_wait_ms: 100,
                max_duplicity: 2,
                max_chunk_size: 10,
                receive_check_cache_size: 1024,
                pfn_evaluation_period_ms: 100,
                registry_poll_period_ms: 100,
                retransmission_request_ms: 100,
                advert_config: Some(GossipAdvertConfig {
                    best_effort_percentage: 10,
                }),
            }),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 10,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: Some(100),
            initial_notary_delay_millis: None,
            dkg_interval_length: Some(2),
            dkg_dealings_per_block: Some(1),
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(10),
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: Some(200),
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: Some(100),
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 100,
                initial_notary_delay_millis: 1500,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: 0,
                    max_chunk_wait_ms: 10,
                    max_duplicity: 2,
                    max_chunk_size: 10,
                    receive_check_cache_size: 200,
                    pfn_evaluation_period_ms: 100,
                    registry_poll_period_ms: 100,
                    retransmission_request_ms: 100,
                    advert_config: Some(GossipAdvertConfig {
                        best_effort_percentage: 100
                    }),
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 10,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
            }
        );
    }
}
