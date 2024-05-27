use crate::{
    common::LOG_PREFIX,
    mutations::common::{encode_or_panic, has_duplicates},
    registry::Registry,
};
use std::collections::HashSet;

use candid::{CandidType, Deserialize};
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{subnet_id_into_protobuf, SubnetId};
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::registry::subnet::v1::{
    SubnetFeatures as SubnetFeaturesPb, SubnetRecord as SubnetRecordPb,
};
use ic_registry_keys::{
    make_chain_key_signing_subnet_list_key, make_ecdsa_signing_subnet_list_key,
    make_subnet_record_key,
};
use ic_registry_subnet_features::{ChainKeyConfig, EcdsaConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
use ic_types::p2p::build_default_gossip_config;

/// Updates the subnet's configuration in the registry.
///
/// This method is called by the governance canister, after a proposal
/// for updating a new subnet has been accepted.
impl Registry {
    pub fn do_update_subnet(&mut self, payload: UpdateSubnetPayload) {
        println!("{}do_update_subnet: {:?}", LOG_PREFIX, payload);

        self.validate_update_payload_ecdsa_config(&payload);
        self.validate_update_sev_feature(&payload);

        let subnet_id = payload.subnet_id;

        let new_subnet_record =
            merge_subnet_record(self.get_subnet_or_panic(subnet_id), payload.clone());

        let subnet_record_mutation = upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            encode_or_panic(&new_subnet_record),
        );

        let mut mutations = vec![subnet_record_mutation];

        if let Some(ecdsa_key_signing_enable) = payload.ecdsa_key_signing_enable {
            mutations.append(
                &mut self.mutations_to_enable_subnet_signing(subnet_id, &ecdsa_key_signing_enable),
            );
        }

        if let Some(ecdsa_key_signing_disable) = payload.ecdsa_key_signing_disable {
            mutations.append(
                &mut self
                    .mutations_to_disable_subnet_signing(subnet_id, &ecdsa_key_signing_disable),
            )
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    /// Validates that EcdsaKeyId's are globally unique across all subnets
    /// Panics if they are not
    fn validate_update_payload_ecdsa_config(&self, payload: &UpdateSubnetPayload) {
        if payload.ecdsa_config.is_none() {
            return;
        }
        let subnet_id = payload.subnet_id;
        let payload_ecdsa_config = payload.ecdsa_config.as_ref().unwrap();

        if has_duplicates(&payload_ecdsa_config.key_ids) {
            panic!(
                "{}The requested ECDSA key ids {:?} have duplicates",
                LOG_PREFIX, payload_ecdsa_config.key_ids
            );
        }

        // Ensure that if keys are held by the subnet, they cannot be changed.
        let keys_held_currently = self.get_ecdsa_keys_held_by_subnet(subnet_id);
        if !keys_held_currently.is_empty() && payload_ecdsa_config.key_ids != keys_held_currently {
            panic!(
                "{}ECDSA Keys cannot be changed once set for a subnet. Attempted to update ECDSA \
                   keys for subnet: '{}'",
                LOG_PREFIX, subnet_id
            );
        }

        // Validate that any new keys do not exist in another subnet, as that would trigger
        // creating another key with the same EcdsaKeyId, which would break ECDSA signing.
        let new_keys = self
            .get_keys_that_will_be_added_to_subnet(subnet_id, payload_ecdsa_config.key_ids.clone());

        let ecdsa_subnet_map = self.get_ecdsa_keys_to_subnets_map();
        new_keys.iter().for_each(|key_id| {
            if ecdsa_subnet_map.contains_key(key_id) {
                panic!(
                    "{}ECDSA key with id '{}' already exists.  ID must be globally unique.",
                    LOG_PREFIX, key_id
                );
            }
        });

        // Signing cannot be enabled unless the key was previously held by the subnet.
        if let Some(ref ecdsa_key_signing_enable) = payload.ecdsa_key_signing_enable {
            let current_keys = self.get_ecdsa_keys_held_by_subnet(subnet_id);
            for key_id in ecdsa_key_signing_enable {
                if !current_keys.contains(key_id) {
                    panic!(
                        "{}Proposal attempts to enable signing for ECDSA key '{}' on Subnet '{}', \
                        but the subnet does not hold the given key. A proposal to add that key to \
                        the subnet must first be separately submitted.",
                        LOG_PREFIX, key_id, subnet_id
                    );
                }
            }
        }

        // Validate that proposal is not attempting to disable and enable signing for the same key
        // in the same proposal
        if let (Some(ecdsa_signing_enable), Some(ecdsa_signging_disable)) = (
            &payload.ecdsa_key_signing_enable,
            &payload.ecdsa_key_signing_disable,
        ) {
            let enable_set = ecdsa_signing_enable.iter().collect::<HashSet<_>>();
            let disable_set = ecdsa_signging_disable.iter().collect::<HashSet<_>>();
            let intersection = enable_set.intersection(&disable_set).collect::<Vec<_>>();
            if !intersection.is_empty() {
                panic!("{}update_subnet aborted: Proposal attempts to enable and disable signing for same ECDSA keys: {:?}",
                    LOG_PREFIX, intersection
                    )
            }
        }
    }

    /// Validates that the SEV feature is not changed on an existing subnet.
    /// Panics if the SEV feature is attempted to be changed.
    fn validate_update_sev_feature(&self, payload: &UpdateSubnetPayload) {
        if payload.features.is_none() {
            return;
        }
        let subnet_id = payload.subnet_id;
        let subnet_record = self.get_subnet_or_panic(subnet_id);
        if let Some(old_features) = subnet_record.features {
            // Compare as `SubnetFeatures`, to avoid having to worry about
            // `None` vs `Some(false)`.
            let new_features: SubnetFeatures = payload.features.clone().unwrap().into();
            let old_features: SubnetFeatures = old_features.into();
            if new_features.sev_enabled == old_features.sev_enabled {
                return;
            }
        }
        panic!(
            "{}Proposal attempts to change sev_enabled for Subnet '{}', \
                        but sev_enabled can only be set during subnet creation.",
            LOG_PREFIX, subnet_id
        );
    }

    // TODO(NNS1-2986): Migrate the function to work over MasterPublicKeyId without replicating to EcdsaKeyId
    fn mutations_to_enable_subnet_signing(
        &self,
        subnet_id: SubnetId,
        ecdsa_key_signing_enable: &Vec<EcdsaKeyId>,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];
        for ecdsa_key_id in ecdsa_key_signing_enable {
            let ck_key_id = MasterPublicKeyId::Ecdsa(ecdsa_key_id.clone());

            let mut ecdsa_signing_list_for_key = self
                .get_ecdsa_signing_subnet_list(ecdsa_key_id)
                .unwrap_or_default();
            let mut ck_signing_list_for_key = self
                .get_chain_key_signing_subnet_list(&ck_key_id)
                .unwrap_or_default();

            // If this subnet already signs for this key, do nothing.
            if ecdsa_signing_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }
            if ck_signing_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }

            // Preconditions are okay, so we add the subnet to our list of signing subnets.
            ecdsa_signing_list_for_key
                .subnets
                .push(subnet_id_into_protobuf(subnet_id));
            ck_signing_list_for_key
                .subnets
                .push(subnet_id_into_protobuf(subnet_id));

            mutations.push(upsert(
                make_ecdsa_signing_subnet_list_key(ecdsa_key_id).into_bytes(),
                encode_or_panic(&ecdsa_signing_list_for_key),
            ));
            mutations.push(upsert(
                make_chain_key_signing_subnet_list_key(&ck_key_id).into_bytes(),
                encode_or_panic(&ck_signing_list_for_key),
            ));
        }
        mutations
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

    pub set_gossip_config_to_default: bool,

    pub start_as_nns: Option<bool>,

    pub subnet_type: Option<SubnetType>,

    pub is_halted: Option<bool>,
    pub halt_at_cup_height: Option<bool>,

    pub max_instructions_per_message: Option<u64>,
    pub max_instructions_per_round: Option<u64>,
    pub max_instructions_per_install_code: Option<u64>,
    pub features: Option<SubnetFeaturesPb>,

    /// The following three ecdsa_* fields will soon be deprecated and replaced with chain_* fields.
    /// This defines keys held by the subnet,
    pub ecdsa_config: Option<EcdsaConfig>,
    /// This enables signing for keys the subnet holds, which is not held in the SubnetRecord
    pub ecdsa_key_signing_enable: Option<Vec<EcdsaKeyId>>,
    /// This disables signing for keys the subnet holds, which is not held in the SubnetRecord
    pub ecdsa_key_signing_disable: Option<Vec<EcdsaKeyId>>,

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
}

// Merges the changes included in the `UpdateSubnetPayload` to the given
// `SubnetRecord`. If any value in the provided payload is None, then it is
// skipped, otherwise it overwrites the corresponding value in the
// `SubnetRecord`.
#[allow(clippy::cognitive_complexity)]
fn merge_subnet_record(
    mut subnet_record: SubnetRecordPb,
    payload: UpdateSubnetPayload,
) -> SubnetRecordPb {
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
        set_gossip_config_to_default,
        start_as_nns,
        subnet_type,
        is_halted,
        halt_at_cup_height,
        max_instructions_per_message,
        max_instructions_per_round,
        max_instructions_per_install_code,
        features,
        ecdsa_config,
        ecdsa_key_signing_enable: _,
        ecdsa_key_signing_disable: _,
        max_number_of_canisters,
        ssh_readonly_access,
        ssh_backup_access,
    } = payload;

    let features: Option<SubnetFeaturesPb> = features.map(|v| SubnetFeatures::from(v).into());

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
    subnet_record.gossip_config = Some(gossip_config);

    maybe_set!(subnet_record, start_as_nns);

    // See EXC-408: changing of the subnet type is disabled.
    if let Some(value) = subnet_type {
        assert_eq!(subnet_record.subnet_type, i32::from(value));
    }

    maybe_set!(subnet_record, is_halted);
    maybe_set!(subnet_record, halt_at_cup_height);

    maybe_set!(subnet_record, max_instructions_per_message);
    maybe_set!(subnet_record, max_instructions_per_round);
    maybe_set!(subnet_record, max_instructions_per_install_code);

    maybe_set_option!(subnet_record, features);

    // TODO[NNS1-2988]: Take value directly from `UpdateSubnetPayload.chain_key_config`.
    {
        let chain_key_config = ecdsa_config.clone().map(ChainKeyConfig::from);
        maybe_set_option!(subnet_record, chain_key_config);
    }
    // TODO[NNS1-3006]: Stop updating the ecdsa_config field.
    maybe_set_option!(subnet_record, ecdsa_config);

    maybe_set!(subnet_record, max_number_of_canisters);

    maybe_set!(subnet_record, ssh_readonly_access);
    maybe_set!(subnet_record, ssh_backup_access);

    subnet_record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_protobuf::registry::subnet::v1::{
        ChainKeyConfig as ChainKeyConfigPb, EcdsaConfig as EcdsaConfigPb,
        GossipConfig as GossipConfigPb, SubnetRecord as SubnetRecordPb,
    };
    use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        p2p::{
            MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_WAIT_MS, MAX_DUPLICITY,
            PFN_EVALUATION_PERIOD_MS, RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS,
            RETRANSMISSION_REQUEST_MS,
        },
        PrincipalId, ReplicaVersion, SubnetId,
    };
    use maplit::btreemap;
    use std::str::FromStr;

    fn make_ecdsa_key(name: &str) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: name.to_string(),
        }
    }

    fn make_default_update_subnet_payload_for_merge_subnet_tests() -> UpdateSubnetPayload {
        let legacy_ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![make_ecdsa_key("key_id_1")],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
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
            max_chunk_wait_ms: Some(200),
            max_duplicity: Some(5),
            max_chunk_size: Some(1024),
            receive_check_cache_size: Some(500),
            pfn_evaluation_period_ms: Some(5000),
            registry_poll_period_ms: Some(4000),
            retransmission_request_ms: Some(7000),
            set_gossip_config_to_default: false,
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            halt_at_cup_height: Some(false),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: Some(
                SubnetFeatures {
                    canister_sandboxing: false,
                    http_requests: false,
                    sev_enabled: false,
                }
                .into(),
            ),
            ecdsa_config: Some(legacy_ecdsa_config),
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_2")]),
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
        }
    }

    fn make_empty_update_payload(subnet_id: SubnetId) -> UpdateSubnetPayload {
        UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        }
    }

    #[test]
    fn can_override_all_fields() {
        let subnet_record = SubnetRecordPb {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfigPb {
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
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
        };

        let ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![make_ecdsa_key("key_id_1")],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        let ecdsa_config_pb = ecdsa_config.clone().map(EcdsaConfigPb::from);
        let chain_key_config_pb = ecdsa_config_pb.clone().map(ChainKeyConfigPb::from);

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
            set_gossip_config_to_default: false,
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            halt_at_cup_height: Some(false),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: Some(
                SubnetFeatures {
                    canister_sandboxing: false,
                    http_requests: false,
                    sev_enabled: false,
                }
                .into(),
            ),
            ecdsa_config,
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_2")]),
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecordPb {
                membership: vec![],
                max_ingress_bytes_per_message: 256,
                max_ingress_messages_per_block: 256,
                max_block_payload_size: 200,
                unit_delay_millis: 300,
                initial_notary_delay_millis: 200,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 8,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfigPb {
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
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                halt_at_cup_height: false,
                max_instructions_per_message: 6_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 300_000_000_000,
                features: Some(
                    SubnetFeatures {
                        canister_sandboxing: false,
                        http_requests: false,
                        sev_enabled: false,
                    }
                    .into()
                ),
                ecdsa_config: ecdsa_config_pb,
                chain_key_config: chain_key_config_pb,
                max_number_of_canisters: 10,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
            }
        );
    }

    #[test]
    fn can_override_some_fields() {
        let subnet_record = SubnetRecordPb {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfigPb {
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
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: Some(true),
            max_instructions_per_message: None,
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: Some(50),
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecordPb {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 100,
                initial_notary_delay_millis: 1500,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfigPb {
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
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: true,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 50,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
                chain_key_config: None,
            }
        );
    }

    // TODO[NNS1-2988]: Add test `panic_on_removing_chain_key_config`.
    #[test]
    #[should_panic]
    fn panic_on_removing_ecdsa_config() {
        let subnet_record = SubnetRecordPb {
            ecdsa_config: Some(
                EcdsaConfig {
                    key_ids: vec![make_ecdsa_key("key_id_1")],
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };

        let mut payload = make_default_update_subnet_payload_for_merge_subnet_tests();
        payload.ecdsa_config = None;

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    #[should_panic]
    // This test confirms that if `set_gossip_config_to_default` = false and the
    // existing subnet record does not have a gossip config and some gossip related
    // fields are set to override, `merge_subnet_record` panics as expected.
    fn can_handle_invalid_combination_of_set_gossip_config_to_default() {
        let subnet_record = SubnetRecordPb {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: None,
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::Application),
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        merge_subnet_record(subnet_record, payload);
    }

    #[test]
    fn can_set_default_gossip_config_and_override_fields() {
        let subnet_record = SubnetRecordPb {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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
            set_gossip_config_to_default: true,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecordPb {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 500,
                initial_notary_delay_millis: 1500,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 0,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfigPb {
                    max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
                    max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
                    max_duplicity: MAX_DUPLICITY,
                    max_chunk_size: 10,
                    receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
                    pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
                    registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
                    retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 7_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 0,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
                chain_key_config: None,
            }
        );
    }

    #[test]
    fn update_advert_config() {
        let subnet_record = SubnetRecordPb {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfigPb {
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
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 10,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: None,
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
        };

        assert_eq!(
            merge_subnet_record(subnet_record, payload),
            SubnetRecordPb {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 4 * 1024 * 1024,
                unit_delay_millis: 100,
                initial_notary_delay_millis: 1500,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfigPb {
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
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: false,
                max_instructions_per_message: 5_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 200_000_000_000,
                features: None,
                max_number_of_canisters: 10,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
                chain_key_config: None,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "roposal attempts to enable signing for ECDSA key 'Secp256k1:existing_key_id' \
        on Subnet 'ge6io-epiam-aaaaa-aaaap-yai', but the subnet does not hold the given key. \
        A proposal to add that key to the subnet must first be separately submitted."
    )]
    fn test_ecdsa_keys_cannot_be_enabled_unless_already_held() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };

        // Create the subnet we will update that doesn't hold the key
        let mut node_ids_and_dkg_pks_iter = node_ids_and_dkg_pks.iter();
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks_iter
            .next()
            .expect("should contain at least one node ID and key");
        let subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });
        payload.ecdsa_key_signing_enable = Some(vec![key]);

        // Should panic because we are trying to enable a key that hasn't previously held it
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "The requested ECDSA key ids [EcdsaKeyId { curve: Secp256k1, name: \"key_id\" }, \
        EcdsaKeyId { curve: Secp256k1, name: \"key_id\" }] have duplicates"
    )]
    fn test_disallow_duplicate_ecdsa_keys() {
        // Step 1: prepare registry with a subnet record.
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let mut subnet_list_record = registry.get_subnet_list_record();
        let mut node_ids_and_dkg_pks_iter = node_ids_and_dkg_pks.iter();
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks_iter
            .next()
            .expect("should contain at least one node ID and key");
        let subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        // Step 2: try to update the subnet with duplicate ECDSA keys and should panic.
        let key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_id".to_string(),
        };
        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key.clone(), key.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });
        payload.ecdsa_key_signing_enable = Some(vec![key]);
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "ECDSA key with id 'Secp256k1:existing_key_id' already exists.  \
                    ID must be globally unique."
    )]
    fn test_ecdsa_key_ids_must_be_globally_unique() {
        // We create 2 subnets. One has the key already, and the other tries to have that key id added
        // in an update call, which is not allowed.
        let existing_key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };
        let subnet_holding_key_id = SubnetId::from(*TEST_USER1_PRINCIPAL);
        let subnet_to_update_id = SubnetId::from(*TEST_USER2_PRINCIPAL);

        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        // Create first subnet that holds the ECDSA key.
        let mut node_ids_and_dkg_pks_iter = node_ids_and_dkg_pks.iter();
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks_iter
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_holding_key_record =
            get_invariant_compliant_subnet_record(vec![*first_node_id]);
        // This marks the subnet as having the key.
        subnet_holding_key_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![existing_key_id],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_holding_key_id,
            &mut subnet_list_record,
            subnet_holding_key_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        // Create second subnet that does not hold the key.
        let (second_node_id, second_dkg_pkg) = node_ids_and_dkg_pks_iter
            .next()
            .expect("should contain at least one node ID");
        let subnet_to_update = get_invariant_compliant_subnet_record(vec![*second_node_id]);

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_to_update_id,
            &mut subnet_list_record,
            subnet_to_update,
            &btreemap!(*second_node_id => second_dkg_pkg.clone()),
        ));

        // Now that both subnets are added to the Registry, one with the existing_key_id,
        // we try an update call with the same existing_key_id to the other subnet
        // which should fail.
        let mut payload = make_empty_update_payload(subnet_to_update_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "existing_key_id".to_string(),
            }],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "Proposal attempts to change sev_enabled for Subnet 'ge6io-epiam-aaaaa-aaaap-yai', \
                    but sev_enabled can only be set during subnet creation."
    )]
    fn test_sev_enabled_cannot_be_changed() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        // Create the subnet we will update that changes sev_enabled
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);
        payload.features = Some(
            SubnetFeatures {
                canister_sandboxing: false,
                http_requests: false,
                sev_enabled: true,
            }
            .into(),
        );

        // Should panic because we are changing SubnetFeatures
        registry.do_update_subnet(payload);
    }

    #[test]
    fn can_disable_signing_without_removing_keys() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key_held_by_subnet = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };

        // Create first subnet that holds the ECDSA key
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_holding_key_record =
            get_invariant_compliant_subnet_record(vec![*first_node_id]);
        // This marks the subnet as having the key
        subnet_holding_key_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_held_by_subnet.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_holding_key_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_held_by_subnet.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });
        payload.ecdsa_key_signing_enable = Some(vec![key_held_by_subnet.clone()]);

        registry.do_update_subnet(payload);

        // Make sure it's actually in the signing list.
        assert!(registry
            .get_ecdsa_signing_subnet_list(&key_held_by_subnet)
            .unwrap()
            .subnets
            .contains(&subnet_id_into_protobuf(subnet_id)));

        // Make sure config contains the key.
        assert!(registry
            .get_subnet_or_panic(subnet_id)
            .ecdsa_config
            .unwrap()
            .key_ids
            .contains(&(&key_held_by_subnet).into()));

        // The next payload to disable signing with the key.
        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_key_signing_disable = Some(vec![key_held_by_subnet.clone()]);
        registry.do_update_subnet(payload);

        // Ensure it's now removed from signing list.
        assert!(!registry
            .get_ecdsa_signing_subnet_list(&key_held_by_subnet)
            .unwrap()
            .subnets
            .contains(&subnet_id_into_protobuf(subnet_id)));
        // Ensure the config still  has the key.
        assert!(registry
            .get_subnet_or_panic(subnet_id)
            .ecdsa_config
            .unwrap()
            .key_ids
            .contains(&(&key_held_by_subnet).into()));
    }

    #[test]
    #[should_panic(
        expected = "update_subnet aborted: Proposal attempts to enable and disable signing for same \
                    ECDSA keys: [EcdsaKeyId { curve: Secp256k1, name: \"existing_key_id\" }]"
    )]
    fn enable_and_disable_signing_lists_should_not_have_same_keys_in_single_request() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };

        // Create the subnet we will update
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
        // Give it the key.
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });
        payload.ecdsa_key_signing_enable = Some(vec![key.clone()]);
        payload.ecdsa_key_signing_disable = Some(vec![key]);

        // Should panic because we are trying to enable/disable same key
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "ECDSA Keys cannot be changed once set for a subnet. Attempted to update ECDSA \
                   keys for subnet: 'ge6io-epiam-aaaaa-aaaap-yai'"
    )]
    fn test_modify_ecdsa_keys_after_setting_fails() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };

        // Create the subnet we will update
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
        // Give it the key.
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key.clone()],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        registry.do_update_subnet(payload.clone());

        if let Some(ecdsa_config) = payload.ecdsa_config.as_mut() {
            ecdsa_config.key_ids.clear()
        }

        // Should panic because we are trying to modify the config
        registry.do_update_subnet(payload)
    }
}
