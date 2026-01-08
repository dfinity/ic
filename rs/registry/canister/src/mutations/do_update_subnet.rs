use crate::{common::LOG_PREFIX, mutations::common::has_duplicates, registry::Registry};
use candid::{CandidType, Deserialize};
use dfn_core::println;
use ic_base_types::{SubnetId, subnet_id_into_protobuf};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::registry::subnet::v1::{
    SubnetFeatures as SubnetFeaturesPb, SubnetRecord as SubnetRecordPb,
};
use ic_registry_keys::{make_chain_key_enabled_subnet_list_key, make_subnet_record_key};
use ic_registry_subnet_features::{
    ChainKeyConfig as ChainKeyConfigInternal, KeyConfig as KeyConfigInternal, SubnetFeatures,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
use prost::Message;
use serde::Serialize;
use std::collections::HashSet;

/// Updates the subnet's configuration in the registry.
///
/// This method is called by the governance canister, after a proposal
/// for updating a new subnet has been accepted.
impl Registry {
    pub fn do_update_subnet(&mut self, payload: UpdateSubnetPayload) {
        println!("{}do_update_subnet: {:?}", LOG_PREFIX, payload);

        self.validate_update_payload_chain_key_config(&payload);
        self.validate_update_sev_feature(&payload);

        let subnet_id = payload.subnet_id;

        let new_subnet_record =
            merge_subnet_record(self.get_subnet_or_panic(subnet_id), payload.clone());

        let subnet_record_mutation = upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            new_subnet_record.encode_to_vec(),
        );

        let mut mutations = vec![subnet_record_mutation];

        if let Some(chain_key_signing_enable) = payload.chain_key_signing_enable {
            mutations.append(
                &mut self.mutations_to_enable_chain_key(subnet_id, &chain_key_signing_enable),
            );
        }

        let chain_key_signing_disable = payload.chain_key_signing_disable;

        if let Some(chain_key_signing_disable) = chain_key_signing_disable {
            mutations.append(
                &mut self
                    .mutations_to_disable_subnet_chain_key(subnet_id, &chain_key_signing_disable),
            );
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    /// Validates that the chain key IDs are globally unique across all subnets.
    ///
    /// Panics if they are not.
    fn validate_update_payload_chain_key_config(&self, payload: &UpdateSubnetPayload) {
        let subnet_id = payload.subnet_id;

        let payload_chain_key_config = payload.chain_key_config.clone().map(|chain_key_config| {
            ChainKeyConfigInternal::try_from(chain_key_config).unwrap_or_else(|err| {
                panic!("{LOG_PREFIX}Invalid UpdateSubnetPayload.chain_key_config: {err}");
            })
        });

        if let Some(payload_chain_key_config) = payload_chain_key_config {
            let payload_key_ids = payload_chain_key_config.key_ids();

            if has_duplicates(&payload_key_ids) {
                panic!(
                    "{LOG_PREFIX}The requested chain key IDs {payload_key_ids:?} have duplicates."
                );
            }

            // Ensure that the keys held by the subnet cannot be deleted.
            let keys_held_currently: HashSet<MasterPublicKeyId> =
                HashSet::from_iter(self.get_master_public_keys_held_by_subnet(subnet_id));
            let payload_key_ids_set = HashSet::from_iter(payload_key_ids.clone());

            let deleted_keys: HashSet<_> = keys_held_currently
                .difference(&payload_key_ids_set)
                .collect();

            if !deleted_keys.is_empty() {
                panic!(
                    "{LOG_PREFIX}Chain keys cannot be deleted. Attempted to delete chain keys {deleted_keys:?} \
                    for subnet: '{subnet_id}'"
                );
            }

            // Validate that any new keys do not exist in another subnet, as that would trigger
            // creating another key with the same MasterPublicKeyId, which would break chain key signing.
            let new_keys =
                self.get_keys_that_will_be_added_to_subnet(subnet_id, payload_key_ids.clone());

            let keys_to_subnet_map = self.get_master_public_keys_to_subnets_map();
            new_keys.iter().for_each(|key_id| {
                if keys_to_subnet_map.contains_key(key_id) {
                    panic!(
                        "{LOG_PREFIX}Chain key with id '{key_id}' already exists. IDs must be globally unique.",
                    );
                }
            });
        }

        // Signing cannot be enabled unless the key was previously held by the subnet.
        if let Some(ref chain_key_signing_enable) = payload.chain_key_signing_enable {
            let current_keys = self.get_master_public_keys_held_by_subnet(subnet_id);
            for key_id in chain_key_signing_enable {
                if !current_keys.contains(key_id) {
                    panic!(
                        "{LOG_PREFIX}Proposal attempts to enable signing for chain key '{key_id}' on Subnet '{subnet_id}', \
                        but the subnet does not hold the given key. A proposal to add that key to \
                        the subnet must first be separately submitted."
                    );
                }
            }
        }

        // Validate that proposal is not attempting to disable and enable signing for the same key
        // in the same proposal
        if let (Some(chain_key_signing_enable), Some(chain_key_signing_disable)) = (
            &payload.chain_key_signing_enable,
            &payload.chain_key_signing_disable,
        ) {
            let enable_set = chain_key_signing_enable.iter().collect::<HashSet<_>>();
            let disable_set = chain_key_signing_disable.iter().collect::<HashSet<_>>();
            let intersection = enable_set.intersection(&disable_set).collect::<Vec<_>>();
            if !intersection.is_empty() {
                panic!(
                    "{LOG_PREFIX}update_subnet aborted: Proposal attempts to enable and disable signing for \
                    the same chain keys: {intersection:?}",
                )
            }
        }
    }

    /// Validates that the SEV (AMD Secure Encrypted Virtualization) feature is not changed on
    /// an existing subnet.
    ///
    /// Panics if the SEV feature is attempted to be changed.
    fn validate_update_sev_feature(&self, payload: &UpdateSubnetPayload) {
        let subnet_id = payload.subnet_id;

        // Ensure the subnet record exists for this subnet ID.
        let _subnet_record = self.get_subnet_or_panic(subnet_id);

        let Some(features) = payload.features else {
            return;
        };

        if let Some(sev_enabled) = features.sev_enabled {
            panic!(
                "{LOG_PREFIX}Proposal attempts to change sev_enabled for Subnet '{subnet_id}' to {sev_enabled}, \
                 but sev_enabled can only be set during subnet creation.",
            );
        }
    }

    /// Create the mutations that enable a set of chain keys for a single subnet.
    fn mutations_to_enable_chain_key(
        &self,
        subnet_id: SubnetId,
        chain_key_enable: &Vec<MasterPublicKeyId>,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];
        for chain_key_id in chain_key_enable {
            let mut chain_key_enabled_list_for_key = self
                .get_chain_key_enabled_subnet_list(chain_key_id)
                .unwrap_or_default();

            // If this subnet is already enabled for this key, do nothing.
            if chain_key_enabled_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }

            // Preconditions are okay, so we add the subnet to our list of enabled subnets.
            chain_key_enabled_list_for_key
                .subnets
                .push(subnet_id_into_protobuf(subnet_id));

            mutations.push(upsert(
                make_chain_key_enabled_subnet_list_key(chain_key_id).into_bytes(),
                chain_key_enabled_list_for_key.encode_to_vec(),
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateSubnetPayload {
    pub subnet_id: SubnetId,

    pub max_ingress_bytes_per_message: Option<u64>,
    pub max_ingress_messages_per_block: Option<u64>,
    pub max_block_payload_size: Option<u64>,
    pub unit_delay_millis: Option<u64>,
    pub initial_notary_delay_millis: Option<u64>,
    pub dkg_interval_length: Option<u64>,
    pub dkg_dealings_per_block: Option<u64>,

    pub start_as_nns: Option<bool>,

    pub subnet_type: Option<SubnetType>,

    pub is_halted: Option<bool>,
    pub halt_at_cup_height: Option<bool>,

    pub features: Option<SubnetFeaturesPb>,

    pub chain_key_config: Option<ChainKeyConfig>,
    pub chain_key_signing_enable: Option<Vec<MasterPublicKeyId>>,
    pub chain_key_signing_disable: Option<Vec<MasterPublicKeyId>>,

    pub max_number_of_canisters: Option<u64>,

    pub ssh_readonly_access: Option<Vec<String>>,
    pub ssh_backup_access: Option<Vec<String>>,

    // TODO(NNS1-2444): The fields below are deprecated and they are not read anywhere.
    pub max_artifact_streams_per_peer: Option<u32>,
    pub max_chunk_wait_ms: Option<u32>,
    pub max_duplicity: Option<u32>,
    pub max_chunk_size: Option<u32>,
    pub receive_check_cache_size: Option<u32>,
    pub pfn_evaluation_period_ms: Option<u32>,
    pub registry_poll_period_ms: Option<u32>,
    pub retransmission_request_ms: Option<u32>,
    pub set_gossip_config_to_default: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct ChainKeyConfig {
    pub key_configs: Vec<KeyConfig>,
    pub signature_request_timeout_ns: Option<u64>,
    pub idkg_key_rotation_period_ms: Option<u64>,
    pub max_parallel_pre_signature_transcripts_in_creation: Option<u32>,
}

impl From<ChainKeyConfigInternal> for ChainKeyConfig {
    fn from(src: ChainKeyConfigInternal) -> Self {
        let ChainKeyConfigInternal {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        } = src;

        let key_configs = key_configs
            .into_iter()
            .map(
                |KeyConfigInternal {
                     key_id,
                     pre_signatures_to_create_in_advance,
                     max_queue_size,
                 }| KeyConfig {
                    key_id: Some(key_id),
                    pre_signatures_to_create_in_advance,
                    max_queue_size: Some(max_queue_size),
                },
            )
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        }
    }
}

impl TryFrom<ChainKeyConfig> for ChainKeyConfigInternal {
    type Error = String;

    fn try_from(src: ChainKeyConfig) -> Result<Self, Self::Error> {
        let ChainKeyConfig {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        } = src;

        let mut errors = vec![];
        let key_configs = key_configs
            .into_iter()
            .filter_map(|key_config| {
                KeyConfigInternal::try_from(key_config)
                    .map_err(|err| {
                        errors.push(err);
                    })
                    .ok()
            })
            .collect();

        if !errors.is_empty() {
            return Err(format!(
                "Invalid ChainKeyConfig.key_configs: {}",
                errors.join(", ")
            ));
        }

        Ok(Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct KeyConfig {
    pub key_id: Option<MasterPublicKeyId>,
    pub pre_signatures_to_create_in_advance: Option<u32>,
    pub max_queue_size: Option<u32>,
}

impl From<KeyConfigInternal> for KeyConfig {
    fn from(src: KeyConfigInternal) -> Self {
        let KeyConfigInternal {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        Self {
            key_id: Some(key_id),
            pre_signatures_to_create_in_advance,
            max_queue_size: Some(max_queue_size),
        }
    }
}

impl TryFrom<KeyConfig> for KeyConfigInternal {
    type Error = String;

    fn try_from(src: KeyConfig) -> Result<Self, Self::Error> {
        let KeyConfig {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        } = src;

        let Some(key_id) = key_id else {
            return Err("KeyConfig.key_id must be specified.".to_string());
        };

        // Ensure presence of `pre_signatures_to_create_in_advance` for keys that require pre-signatures.
        // Note that an invariant ensures that this field is not zero for keys that require pre-signatures.
        if key_id.requires_pre_signatures() && pre_signatures_to_create_in_advance.is_none() {
            return Err(format!(
                "KeyConfig.pre_signatures_to_create_in_advance must be specified for key {key_id}."
            ));
        };
        // Ensure absence of `pre_signatures_to_create_in_advance` for keys that do not require it.
        if !key_id.requires_pre_signatures() && pre_signatures_to_create_in_advance.is_some() {
            return Err(format!(
                "KeyConfig.pre_signatures_to_create_in_advance must not be specified for key {key_id} because it does not require pre-signatures."
            ));
        };

        let Some(max_queue_size) = max_queue_size else {
            return Err("KeyConfig.max_queue_size must be specified.".to_string());
        };

        Ok(Self {
            key_id,
            pre_signatures_to_create_in_advance,
            max_queue_size,
        })
    }
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

// Merges the changes included in the `UpdateSubnetPayload` to the given
// `SubnetRecord`. If any value in the provided payload is None, then it is
// skipped, otherwise it overwrites the corresponding value in the
// `SubnetRecord`.
#[allow(clippy::cognitive_complexity)]
#[allow(unused_variables)]
fn merge_subnet_record(
    mut subnet_record: SubnetRecordPb,
    payload: UpdateSubnetPayload,
) -> SubnetRecordPb {
    let UpdateSubnetPayload {
        subnet_id: _subnet_id,
        max_ingress_bytes_per_message,
        max_ingress_messages_per_block,
        max_block_payload_size,
        unit_delay_millis,
        initial_notary_delay_millis,
        dkg_interval_length,
        dkg_dealings_per_block,
        start_as_nns,
        subnet_type,
        is_halted,
        halt_at_cup_height,
        features,
        chain_key_config,
        chain_key_signing_enable: _,
        chain_key_signing_disable: _,
        max_number_of_canisters,
        ssh_readonly_access,
        ssh_backup_access,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: _,
        max_chunk_wait_ms: _,
        max_duplicity: _,
        max_chunk_size: _,
        receive_check_cache_size: _,
        pfn_evaluation_period_ms: _,
        registry_poll_period_ms: _,
        retransmission_request_ms: _,
        set_gossip_config_to_default: _,
    } = payload;

    let features: Option<SubnetFeaturesPb> = features.map(|v| SubnetFeatures::from(v).into());

    maybe_set!(subnet_record, max_ingress_bytes_per_message);
    maybe_set!(subnet_record, max_ingress_messages_per_block);
    maybe_set!(subnet_record, max_block_payload_size);
    maybe_set!(subnet_record, unit_delay_millis);
    maybe_set!(subnet_record, initial_notary_delay_millis);
    maybe_set!(subnet_record, dkg_interval_length);
    maybe_set!(subnet_record, dkg_dealings_per_block);

    maybe_set!(subnet_record, start_as_nns);

    // See EXC-408: changing of the subnet type is disabled.
    if let Some(value) = subnet_type {
        assert_eq!(subnet_record.subnet_type, i32::from(value));
    }

    maybe_set!(subnet_record, is_halted);
    maybe_set!(subnet_record, halt_at_cup_height);

    maybe_set_option!(subnet_record, features);

    let chain_key_config = chain_key_config.map(|chain_key_config| {
        ChainKeyConfigInternal::try_from(chain_key_config)
            .expect("Invalid UpdateSubnetPayload.chain_key_config")
    });
    maybe_set_option!(subnet_record, chain_key_config);

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
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
    };
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_protobuf::registry::subnet::v1::{
        CanisterCyclesCostSchedule, ChainKeyConfig as ChainKeyConfigPb, KeyConfig as KeyConfigPb,
        SubnetRecord as SubnetRecordPb,
    };
    use ic_protobuf::types::v1::MasterPublicKeyId as MasterPublicKeyIdPb;
    use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{PrincipalId, ReplicaVersion, SubnetId};
    use maplit::btreemap;
    use std::str::FromStr;

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
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            features: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
            chain_key_config: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
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
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            chain_key_config: None,
            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
        };

        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_id".to_string(),
        };
        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                pre_signatures_to_create_in_advance: Some(111),
                max_queue_size: Some(222),
            }],
            signature_request_timeout_ns: Some(333),
            idkg_key_rotation_period_ms: Some(444),
            max_parallel_pre_signature_transcripts_in_creation: Some(555),
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
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            halt_at_cup_height: Some(false),
            features: Some(
                SubnetFeatures {
                    canister_sandboxing: false,
                    http_requests: false,
                    sev_enabled: false,
                }
                .into(),
            ),
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
            chain_key_config: Some(chain_key_config.clone()),
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
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
                start_as_nns: true,
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                halt_at_cup_height: false,
                features: Some(
                    SubnetFeatures {
                        canister_sandboxing: false,
                        http_requests: false,
                        sev_enabled: false,
                    }
                    .into()
                ),
                chain_key_config: Some(ChainKeyConfigPb::from(
                    ChainKeyConfigInternal::try_from(chain_key_config).unwrap()
                )),
                max_number_of_canisters: 10,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
                canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
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
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            chain_key_config: None,
            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
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
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: Some(true),
            features: None,
            max_number_of_canisters: Some(50),
            ssh_readonly_access: None,
            ssh_backup_access: None,
            chain_key_config: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
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
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: true,
                features: None,
                max_number_of_canisters: 50,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                chain_key_config: None,
                canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "[Registry] Proposal attempts to enable signing for chain key \
        'ecdsa:Secp256k1:existing_key_id' on Subnet 'ge6io-epiam-aaaaa-aaaap-yai', \
        but the subnet does not hold the given key. A proposal to add that key to the subnet \
        must first be separately submitted."
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

        payload.chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(key.clone())),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        payload.chain_key_signing_enable = Some(vec![MasterPublicKeyId::Ecdsa(key)]);

        // Should panic because we are trying to enable a key that hasn't previously held it
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "The requested chain key IDs [Ecdsa(EcdsaKeyId { curve: Secp256k1, \
        name: \"key_id\" }), Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"key_id\" })] \
        have duplicates."
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

        payload.chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![
                KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key.clone())),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                },
                KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key.clone())),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                },
            ],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        payload.chain_key_signing_enable = Some(vec![MasterPublicKeyId::Ecdsa(key)]);

        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "[Registry] Chain key with id 'ecdsa:Secp256k1:existing_key_id' already exists. \
                    IDs must be globally unique."
    )]
    fn test_chain_key_ids_must_be_globally_unique() {
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
        let chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(existing_key_id)),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        subnet_holding_key_record.chain_key_config = chain_key_config.map(|chain_key_config| {
            let chain_key_config = ChainKeyConfigInternal::try_from(chain_key_config).unwrap();
            ChainKeyConfigPb::from(chain_key_config)
        });

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

        payload.chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "existing_key_id".to_string(),
                })),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        registry.do_update_subnet(payload);
    }

    /// Returns an invariant-compliant Registry instance and an ID of a subnet
    /// with an existing subnet record.
    fn make_registry_for_update_subnet_tests() -> (Registry, SubnetId) {
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

        (registry, subnet_id)
    }

    #[test]
    #[should_panic(expected = "Proposal attempts to change sev_enabled for Subnet \
                    'ge6io-epiam-aaaaa-aaaap-yai' to true, but sev_enabled can only be set during \
                    subnet creation.")]
    fn test_sev_enabled_cannot_be_changed_to_true() {
        let (mut registry, subnet_id) = make_registry_for_update_subnet_tests();

        let mut payload = make_empty_update_payload(subnet_id);
        payload.features = Some(SubnetFeaturesPb {
            canister_sandboxing: false,
            http_requests: false,
            sev_enabled: Some(true),
        });

        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(expected = "Proposal attempts to change sev_enabled for Subnet \
                    'ge6io-epiam-aaaaa-aaaap-yai' to false, but sev_enabled can only be set during \
                    subnet creation.")]
    fn test_sev_enabled_cannot_be_changed_to_false() {
        let (mut registry, subnet_id) = make_registry_for_update_subnet_tests();

        let mut payload = make_empty_update_payload(subnet_id);
        payload.features = Some(SubnetFeaturesPb {
            canister_sandboxing: false,
            http_requests: false,
            // The only difference compared to test_sev_enabled_cannot_be_changed_to_true
            sev_enabled: Some(false),
        });

        // Should panic because we are changing SEV-related subnet features.
        registry.do_update_subnet(payload);
    }

    #[test]
    fn test_sev_enabled_validation_does_not_prevent_setting_other_subnet_features() {
        let (mut registry, subnet_id) = make_registry_for_update_subnet_tests();

        let mut payload = make_empty_update_payload(subnet_id);
        payload.features = Some(SubnetFeaturesPb {
            canister_sandboxing: true,
            http_requests: true,
            sev_enabled: None,
        });

        // Should not panic because we are not changing SEV-related subnet features.
        registry.do_update_subnet(payload);
    }

    #[test]
    fn test_initializing_subnet_features_after_subnet_creation() {
        let (mut registry, subnet_id) = make_registry_for_update_subnet_tests();

        // Disable all features by setting subnet_record.features to None.
        {
            let mut payload = make_empty_update_payload(subnet_id);
            payload.features = None;
            registry.do_update_subnet(payload);
        }

        // Enable non-SEV-related features that can be enabled after the subnet was created.
        {
            let mut payload = make_empty_update_payload(subnet_id);
            payload.features = Some(SubnetFeaturesPb {
                canister_sandboxing: true,
                http_requests: true,
                sev_enabled: None,
            });
            registry.do_update_subnet(payload);
        }
    }

    #[test]
    fn can_disable_chain_key_without_removing_keys() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key_held_by_subnet = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };
        let master_public_key_held_by_subnet = MasterPublicKeyId::Ecdsa(key_held_by_subnet);

        // Create first subnet that holds the ECDSA key
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_holding_key_record =
            get_invariant_compliant_subnet_record(vec![*first_node_id]);

        // This marks the subnet as having the key
        let chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(master_public_key_held_by_subnet.clone()),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        subnet_holding_key_record.chain_key_config = chain_key_config.map(|chain_key_config| {
            let chain_key_config = ChainKeyConfigInternal::try_from(chain_key_config).unwrap();
            ChainKeyConfigPb::from(chain_key_config)
        });

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_holding_key_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);

        payload.chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(master_public_key_held_by_subnet.clone()),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        payload.chain_key_signing_enable = Some(vec![master_public_key_held_by_subnet.clone()]);

        registry.do_update_subnet(payload);

        // Make sure it's actually in the list of enabled chain keys.
        assert!(
            registry
                .get_chain_key_enabled_subnet_list(&master_public_key_held_by_subnet)
                .unwrap()
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
        );

        // Make sure config contains the key.
        assert!(
            registry
                .get_subnet_or_panic(subnet_id)
                .chain_key_config
                .unwrap()
                .key_configs
                .iter()
                .map(|key_config| key_config.key_id.clone().unwrap())
                .collect::<Vec<_>>()
                .contains(&(&master_public_key_held_by_subnet).into())
        );

        // The next payload to disable the chain key.
        let mut payload = make_empty_update_payload(subnet_id);

        payload.chain_key_signing_disable = Some(vec![master_public_key_held_by_subnet.clone()]);

        registry.do_update_subnet(payload);

        // Ensure it's now removed from list of enabled subnets.
        assert!(
            !registry
                .get_chain_key_enabled_subnet_list(&master_public_key_held_by_subnet)
                .unwrap()
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
        );
        // Ensure the config still  has the key.
        assert!(
            registry
                .get_subnet_or_panic(subnet_id)
                .chain_key_config
                .unwrap()
                .key_configs
                .iter()
                .map(|key_config| key_config.key_id.clone().unwrap())
                .collect::<Vec<_>>()
                .contains(&(&master_public_key_held_by_subnet).into())
        );
    }

    #[test]
    #[should_panic(
        expected = "Proposal attempts to enable and disable signing for the same chain keys"
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
        subnet_record.chain_key_config = Some(ChainKeyConfigPb {
            key_configs: vec![KeyConfigPb {
                key_id: Some(MasterPublicKeyIdPb::from(&MasterPublicKeyId::Ecdsa(
                    key.clone(),
                ))),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        let subnet_id = subnet_test_id(1000);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let mut payload = make_empty_update_payload(subnet_id);

        payload.chain_key_config = Some(ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(MasterPublicKeyId::Ecdsa(key.clone())),
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

        payload.chain_key_signing_enable = Some(vec![MasterPublicKeyId::Ecdsa(key.clone())]);
        payload.chain_key_signing_disable = Some(vec![MasterPublicKeyId::Ecdsa(key.clone())]);

        // Should panic because we are trying to enable/disable same key
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "Chain keys cannot be deleted. Attempted to delete chain keys \
        {Schnorr(SchnorrKeyId { algorithm: Bip340Secp256k1, name: \"existing_key_id_2\" })} for \
        subnet: 'ge6io-epiam-aaaaa-aaaap-yai'"
    )]
    fn test_deleting_chain_keys_fails() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let existing_key_1 = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        });

        let existing_key_2 = MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "existing_key_id_2".to_string(),
        });

        let new_key = MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "new_key_id_3".to_string(),
        });

        // Create the subnet we will update
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");

        let subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        let fake_key_config = |key_id: &MasterPublicKeyId| KeyConfig {
            key_id: Some(key_id.clone()),
            pre_signatures_to_create_in_advance: Some(1),
            max_queue_size: Some(2),
        };

        // Give it the keys.
        let chain_key_config = ChainKeyConfig {
            key_configs: vec![
                fake_key_config(&existing_key_1),
                fake_key_config(&existing_key_2),
            ],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        };

        let subnet_id = subnet_test_id(1000);

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let payload = UpdateSubnetPayload {
            chain_key_config: Some(chain_key_config.clone()),
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload.clone());

        // Try to update the subnet by adding a new key and removing one of the existing keys
        let payload = UpdateSubnetPayload {
            chain_key_config: Some(ChainKeyConfig {
                key_configs: vec![fake_key_config(&existing_key_1), fake_key_config(&new_key)],
                ..chain_key_config
            }),
            ..payload
        };

        // Should panic because we are trying to delete an existing key
        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "KeyConfig.pre_signatures_to_create_in_advance must be specified for key ecdsa:Secp256k1:some_key_name"
    )]
    fn should_panic_when_key_requiring_pre_signatures_is_missing_pre_signatures_to_create() {
        let key_config = KeyConfig {
            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "some_key_name".to_string(),
            })),
            pre_signatures_to_create_in_advance: None,
            max_queue_size: Some(155),
        };

        let _ = KeyConfigInternal::try_from(key_config).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "KeyConfig.pre_signatures_to_create_in_advance must not be specified for key vetkd:Bls12_381_G2:some_key_name"
    )]
    fn should_panic_when_key_not_requiring_pre_signatures_has_pre_signatures_to_create() {
        let key_config = KeyConfig {
            key_id: Some(MasterPublicKeyId::VetKd(VetKdKeyId {
                curve: VetKdCurve::Bls12_381_G2,
                name: "some_key_name".to_string(),
            })),
            pre_signatures_to_create_in_advance: Some(99),
            max_queue_size: Some(155),
        };

        let _ = KeyConfigInternal::try_from(key_config).unwrap();
    }
}
