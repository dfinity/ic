use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
use dfn_core::println;

use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
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

        let new_subnet_record = merge_subnet_record(subnet_record, payload);
        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_subnet_record_key(subnet_id).as_bytes().to_vec(),
            value: encode_or_panic(&new_subnet_record),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
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
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateSubnetPayload {
    pub subnet_id: SubnetId,

    pub ingress_bytes_per_block_soft_cap: Option<u64>,
    pub max_ingress_bytes_per_message: Option<u64>,
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

    pub set_gossip_config_to_default: bool,

    pub start_as_nns: Option<bool>,

    pub subnet_type: Option<SubnetType>,

    pub is_halted: Option<bool>,

    pub max_instructions_per_message: Option<u64>,
    pub max_instructions_per_round: Option<u64>,
    pub max_instructions_per_install_code: Option<u64>,
}

#[macro_use]
// Sets the value of a field in record `a` if the provided value `b` is not
// `None`, otherwise does nothing.
macro_rules! maybe_set {
    ($a:tt, $b:tt) => {
        if let Some(val) = $b {
            $a.$b = val.into();
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
}

// Merges the changes included in the `UpdateSubnetPayload` to the given
// `SubnetRecord`. If any value in the provided payload is None, then it is
// skipped, otherwise it overwrites the corresponding value in the
// `SubnetRecord`.
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
        ingress_bytes_per_block_soft_cap,
        max_ingress_bytes_per_message,
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
        set_gossip_config_to_default,
        start_as_nns,
        subnet_type,
        is_halted,
        max_instructions_per_message,
        max_instructions_per_round,
        max_instructions_per_install_code,
    } = payload;

    maybe_set!(subnet_record, ingress_bytes_per_block_soft_cap);
    maybe_set!(subnet_record, max_ingress_bytes_per_message);
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
    subnet_record.gossip_config = Some(gossip_config);

    maybe_set!(subnet_record, start_as_nns);

    maybe_set!(subnet_record, subnet_type);

    maybe_set!(subnet_record, is_halted);

    maybe_set!(subnet_record, max_instructions_per_message);
    maybe_set!(subnet_record, max_instructions_per_round);
    maybe_set!(subnet_record, max_instructions_per_install_code);
    subnet_record
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::subnet::v1::GossipConfig;
    use ic_registry_subnet_type::SubnetType;
    use ic_types::{PrincipalId, SubnetId};
    use std::str::FromStr;

    #[test]
    fn can_override_all_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
            }),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            ingress_bytes_per_block_soft_cap: Some(100),
            max_ingress_bytes_per_message: Some(256),
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
            set_gossip_config_to_default: false,
            start_as_nns: Some(true),
            subnet_type: Some(SubnetType::System),
            is_halted: Some(true),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                ingress_bytes_per_block_soft_cap: 100,
                max_ingress_bytes_per_message: 256,
                max_ingress_messages_per_block: 1000,
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
                }),
                start_as_nns: true,
                subnet_type: SubnetType::System.into(),
                is_halted: true,
                max_instructions_per_message: 6_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 300_000_000_000,
            }
        );
    }

    #[test]
    fn can_override_some_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
            }),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            ingress_bytes_per_block_soft_cap: None,
            max_ingress_bytes_per_message: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::System),
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_block_payload_size: 4 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
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
                }),
                start_as_nns: false,
                subnet_type: SubnetType::System.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
            }
        );
    }

    #[test]
    #[should_panic]
    // This test confirms that if `set_gossip_config_to_default` = false and the
    // existing subnet record does not have a gossip config and some gossip related
    // fields are set to override, `merge_subnet_record` panics as expected.
    fn can_handle_invalid_combination_of_set_gossip_config_to_default() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            ingress_bytes_per_block_soft_cap: None,
            max_ingress_bytes_per_message: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::System),
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
        };

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    fn can_set_default_gossip_config_and_override_fields() {
        let subnet_record = SubnetRecord {
            membership: vec![],
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
        };

        let payload = UpdateSubnetPayload {
            subnet_id: SubnetId::from(
                PrincipalId::from_str(
                    "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
                )
                .unwrap(),
            ),
            ingress_bytes_per_block_soft_cap: None,
            max_ingress_bytes_per_message: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: Some(0),
            max_chunk_wait_ms: Some(100),
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: Some(100),
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: true,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecord {
                membership: vec![],
                ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_block_payload_size: 4 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                unit_delay_millis: 500,
                initial_notary_delay_millis: 1500,
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 0,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: 0,
                    max_chunk_wait_ms: 100,
                    max_duplicity: 1,
                    max_chunk_size: 4096,
                    receive_check_cache_size: 100,
                    pfn_evaluation_period_ms: 3000,
                    registry_poll_period_ms: 3000,
                    retransmission_request_ms: 60_000,
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 7_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
            }
        );
    }
}
