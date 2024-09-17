use crate::{common::LOG_PREFIX, mutations::common::has_duplicates, registry::Registry};
use candid::{CandidType, Deserialize};
use dfn_core::println;
use ic_base_types::{subnet_id_into_protobuf, SubnetId};
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::registry::subnet::v1::{
    SubnetFeatures as SubnetFeaturesPb, SubnetRecord as SubnetRecordPb,
};
use ic_registry_keys::{make_chain_key_signing_subnet_list_key, make_subnet_record_key};
use ic_registry_subnet_features::{
    ChainKeyConfig as ChainKeyConfigInternal, EcdsaConfig, KeyConfig as KeyConfigInternal,
    SubnetFeatures,
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

        let chain_key_signing_enable =
            if let Some(chain_key_signing_enable) = payload.chain_key_signing_enable {
                Some(chain_key_signing_enable)
            } else if let Some(ecdsa_key_signing_enable) = payload.ecdsa_key_signing_enable {
                // TODO[NNS1-3022]: Remove ths branch.
                let chain_key_signing_enable = ecdsa_key_signing_enable
                    .iter()
                    .cloned()
                    .map(MasterPublicKeyId::Ecdsa)
                    .collect();
                Some(chain_key_signing_enable)
            } else {
                None
            };
        if let Some(chain_key_signing_enable) = chain_key_signing_enable {
            mutations.append(
                &mut self.mutations_to_enable_subnet_signing(subnet_id, &chain_key_signing_enable),
            );
        }

        let chain_key_signing_disable =
            if let Some(chain_key_signing_disable) = payload.chain_key_signing_disable {
                Some(chain_key_signing_disable)
            } else if let Some(ecdsa_key_signing_disable) = payload.ecdsa_key_signing_disable {
                // TODO[NNS1-3022]: Remove ths branch.
                let chain_key_signing_disable = ecdsa_key_signing_disable
                    .iter()
                    .cloned()
                    .map(MasterPublicKeyId::Ecdsa)
                    .collect();
                Some(chain_key_signing_disable)
            } else {
                None
            };
        if let Some(chain_key_signing_disable) = chain_key_signing_disable {
            mutations.append(
                &mut self
                    .mutations_to_disable_subnet_signing(subnet_id, &chain_key_signing_disable),
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

        let chain_key_config_from_old_source = payload
            .ecdsa_config
            .clone()
            .map(ChainKeyConfigInternal::from);
        let chain_key_config_from_new_source =
            payload.chain_key_config.clone().map(|chain_key_config| {
                ChainKeyConfigInternal::try_from(chain_key_config).unwrap_or_else(|err| {
                    panic!(
                        "{}Invalid UpdateSubnetPayload.chain_key_config: {}",
                        LOG_PREFIX, err
                    );
                })
            });

        let payload_chain_key_config = match (
            chain_key_config_from_old_source,
            chain_key_config_from_new_source,
        ) {
            (Some(_), Some(_)) => {
                panic!(
                    "{}Deprecated field ecdsa_config cannot be specified with chain_key_config.",
                    LOG_PREFIX
                );
            }
            (Some(chain_key_config), None) => {
                // Old API is used; check that nothing weird is being mixed in from the new API.
                assert_eq!(payload.chain_key_signing_enable, None, "{}Deprecated field ecdsa_config cannot be specified with chain_key_signing_enable.", LOG_PREFIX);
                assert_eq!(payload.chain_key_signing_disable, None, "{}Deprecated field ecdsa_config cannot be specified with chain_key_signing_disable.", LOG_PREFIX);
                Some(chain_key_config)
            }
            (None, Some(chain_key_config)) => {
                // New API is used; check that nothing weird is being mixed in from the old API.
                assert_eq!(payload.ecdsa_key_signing_enable, None, "{}Field chain_key_config cannot be specified with deprecated ecdsa_key_signing_enable.", LOG_PREFIX);
                assert_eq!(payload.ecdsa_key_signing_disable, None, "{}Field chain_key_config cannot be specified with deprecated ecdsa_key_signing_disable.", LOG_PREFIX);
                Some(chain_key_config)
            }
            (None, None) => {
                let has_ecdsa_key_signing_fields = payload.ecdsa_key_signing_enable.is_some()
                    || payload.ecdsa_key_signing_disable.is_some();
                let has_chain_key_signing_fields = payload.chain_key_signing_enable.is_some()
                    || payload.chain_key_signing_disable.is_some();
                if has_ecdsa_key_signing_fields && has_chain_key_signing_fields {
                    panic!("Deprecated fields ecdsa_key_signing_{{en,dis}}able should not be used together with chain_key_signing_{{en,dis}}able.");
                }
                None
            }
        };

        if let Some(payload_chain_key_config) = payload_chain_key_config {
            let payload_key_ids = payload_chain_key_config.key_ids();

            if has_duplicates(&payload_key_ids) {
                panic!(
                    "{}The requested chain key IDs {:?} have duplicates.",
                    LOG_PREFIX, payload_key_ids
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
                    "{}Chain keys cannot be deleted. Attempted to delete chain keys {:?} \
                    for subnet: '{}'",
                    LOG_PREFIX, deleted_keys, subnet_id
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
                        "{}Chain key with id '{}' already exists. IDs must be globally unique.",
                        LOG_PREFIX, key_id,
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
                        "{}Proposal attempts to enable signing for chain key '{}' on Subnet '{}', \
                        but the subnet does not hold the given key. A proposal to add that key to \
                        the subnet must first be separately submitted.",
                        LOG_PREFIX, key_id, subnet_id
                    );
                }
            }
        }

        // TODO[NNS1-3022]: Remove this code.
        if let Some(ref ecdsa_key_signing_enable) = payload.ecdsa_key_signing_enable {
            let current_keys = self.get_master_public_keys_held_by_subnet(subnet_id);
            for key_id in ecdsa_key_signing_enable {
                let key_id = MasterPublicKeyId::Ecdsa(key_id.clone());
                if !current_keys.contains(&key_id) {
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
        if let (Some(chain_key_signing_enable), Some(chain_key_signing_disable)) = (
            &payload.chain_key_signing_enable,
            &payload.chain_key_signing_disable,
        ) {
            let enable_set = chain_key_signing_enable.iter().collect::<HashSet<_>>();
            let disable_set = chain_key_signing_disable.iter().collect::<HashSet<_>>();
            let intersection = enable_set.intersection(&disable_set).collect::<Vec<_>>();
            if !intersection.is_empty() {
                panic!(
                    "{}update_subnet aborted: Proposal attempts to enable and disable signing for \
                    the same chain keys: {:?}",
                    LOG_PREFIX, intersection,
                )
            }
        }

        // TODO[NNS1-3022]: Remove this code.
        if let (Some(ecdsa_signing_enable), Some(ecdsa_signging_disable)) = (
            &payload.ecdsa_key_signing_enable,
            &payload.ecdsa_key_signing_disable,
        ) {
            let enable_set = ecdsa_signing_enable.iter().collect::<HashSet<_>>();
            let disable_set = ecdsa_signging_disable.iter().collect::<HashSet<_>>();
            let intersection = enable_set.intersection(&disable_set).collect::<Vec<_>>();
            if !intersection.is_empty() {
                panic!(
                    "{}update_subnet aborted: Proposal attempts to enable and disable signing for \
                    the same ECDSA keys: {:?}",
                    LOG_PREFIX, intersection,
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

    /// Create the mutations that enable subnet signing for a single subnet and set of EcdsaKeyId's.
    fn mutations_to_enable_subnet_signing(
        &self,
        subnet_id: SubnetId,
        chain_key_signing_enable: &Vec<MasterPublicKeyId>,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];
        for master_public_key_id in chain_key_signing_enable {
            let mut chain_key_signing_list_for_key = self
                .get_chain_key_signing_subnet_list(master_public_key_id)
                .unwrap_or_default();

            // If this subnet already signs for this key, do nothing.
            if chain_key_signing_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }

            // Preconditions are okay, so we add the subnet to our list of signing subnets.
            chain_key_signing_list_for_key
                .subnets
                .push(subnet_id_into_protobuf(subnet_id));

            mutations.push(upsert(
                make_chain_key_signing_subnet_list_key(master_public_key_id).into_bytes(),
                chain_key_signing_list_for_key.encode_to_vec(),
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
    pub create_checkpoint: Option<bool>,

    pub features: Option<SubnetFeaturesPb>,

    /// The following three ecdsa_* fields will soon be deprecated and replaced with chain_* fields.
    /// This defines keys held by the subnet,
    pub ecdsa_config: Option<EcdsaConfig>,
    /// This enables signing for keys the subnet holds, which is not held in the SubnetRecord
    pub ecdsa_key_signing_enable: Option<Vec<EcdsaKeyId>>,
    /// This disables signing for keys the subnet holds, which is not held in the SubnetRecord
    pub ecdsa_key_signing_disable: Option<Vec<EcdsaKeyId>>,

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
}

impl From<ChainKeyConfigInternal> for ChainKeyConfig {
    fn from(src: ChainKeyConfigInternal) -> Self {
        let ChainKeyConfigInternal {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
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
                    pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
                    max_queue_size: Some(max_queue_size),
                },
            )
            .collect();

        Self {
            key_configs,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
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
            pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
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
        let Some(pre_signatures_to_create_in_advance) = pre_signatures_to_create_in_advance else {
            return Err(
                "KeyConfig.pre_signatures_to_create_in_advance must be specified.".to_string(),
            );
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
        create_checkpoint,
        features,
        ecdsa_config,
        chain_key_config,
        ecdsa_key_signing_enable: _,
        ecdsa_key_signing_disable: _,
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
    maybe_set!(subnet_record, create_checkpoint);

    maybe_set_option!(subnet_record, features);

    // TODO[NNS1-3022]: Stop reading from `UpdateSubnetPayload.ecdsa_config`.
    {
        let chain_key_config_from_old_source = ecdsa_config.map(ChainKeyConfigInternal::from);
        let chain_key_config_from_new_source = chain_key_config.map(|chain_key_config| {
            ChainKeyConfigInternal::try_from(chain_key_config)
                .expect("Invalid UpdateSubnetPayload.chain_key_config")
        });
        let chain_key_config =
            chain_key_config_from_new_source.or(chain_key_config_from_old_source);
        maybe_set_option!(subnet_record, chain_key_config);
    }

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
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId};
    use ic_nervous_system_common_test_keys::{TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL};
    use ic_protobuf::registry::{
        crypto::v1::MasterPublicKeyId as MasterPublicKeyIdPb,
        subnet::v1::{
            ChainKeyConfig as ChainKeyConfigPb, EcdsaConfig as EcdsaConfigPb,
            KeyConfig as KeyConfigPb, SubnetRecord as SubnetRecordPb,
        },
    };
    use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{PrincipalId, ReplicaVersion, SubnetId};
    use maplit::btreemap;
    use std::str::FromStr;

    fn make_ecdsa_key(name: &str) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: name.to_string(),
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
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            create_checkpoint: None,
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
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
            create_checkpoint: false,
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
            start_as_nns: Some(true),
            subnet_type: None,
            is_halted: Some(true),
            halt_at_cup_height: Some(false),
            create_checkpoint: Some(false),
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
                create_checkpoint: false,
                features: Some(
                    SubnetFeatures {
                        canister_sandboxing: false,
                        http_requests: false,
                        sev_enabled: false,
                    }
                    .into()
                ),
                chain_key_config: chain_key_config_pb,
                ecdsa_config: None, // obsolete (chain_key_config is used instead now)
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
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            create_checkpoint: false,
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
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: Some(true),
            create_checkpoint: Some(true),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
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
                create_checkpoint: true,
                features: None,
                max_number_of_canisters: 50,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
                chain_key_config: None,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "[Registry] Proposal attempts to enable signing for ECDSA key \
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
        expected = "[Registry] Chain key with id 'ecdsa:Secp256k1:existing_key_id' already exists. \
                    IDs must be globally unique."
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
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![existing_key_id],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };

        {
            let chain_key_config = ChainKeyConfigInternal::from(ecdsa_config.clone());
            let chain_key_config_pb = ChainKeyConfigPb::from(chain_key_config);
            subnet_holding_key_record.chain_key_config = Some(chain_key_config_pb);
        }

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
        let master_public_key_held_by_subnet = MasterPublicKeyId::Ecdsa(key_held_by_subnet.clone());

        // Create first subnet that holds the ECDSA key
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let mut subnet_holding_key_record =
            get_invariant_compliant_subnet_record(vec![*first_node_id]);
        // This marks the subnet as having the key
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_held_by_subnet.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
        let chain_key_config = ChainKeyConfigInternal::from(ecdsa_config);
        let chain_key_config_pb = ChainKeyConfigPb::from(chain_key_config);
        subnet_holding_key_record.chain_key_config = Some(chain_key_config_pb);

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
            .get_chain_key_signing_subnet_list(&master_public_key_held_by_subnet)
            .unwrap()
            .subnets
            .contains(&subnet_id_into_protobuf(subnet_id)));

        // Make sure config contains the key.
        assert!(registry
            .get_subnet_or_panic(subnet_id)
            .chain_key_config
            .unwrap()
            .key_configs
            .iter()
            .map(|key_config| key_config.key_id.clone().unwrap())
            .collect::<Vec<_>>()
            .contains(&(&master_public_key_held_by_subnet).into()));

        // The next payload to disable signing with the key.
        let mut payload = make_empty_update_payload(subnet_id);
        payload.ecdsa_key_signing_disable = Some(vec![key_held_by_subnet.clone()]);
        registry.do_update_subnet(payload);

        // Ensure it's now removed from signing list.
        assert!(!registry
            .get_chain_key_signing_subnet_list(&master_public_key_held_by_subnet)
            .unwrap()
            .subnets
            .contains(&subnet_id_into_protobuf(subnet_id)));
        // Ensure the config still  has the key.
        assert!(registry
            .get_subnet_or_panic(subnet_id)
            .chain_key_config
            .unwrap()
            .key_configs
            .iter()
            .map(|key_config| key_config.key_id.clone().unwrap())
            .collect::<Vec<_>>()
            .contains(&(&master_public_key_held_by_subnet).into()));
    }

    #[test]
    #[should_panic(
        expected = "[Registry] Proposal attempts to enable signing for ECDSA key \
        'ecdsa:Secp256k1:existing_key_id' on Subnet 'ge6io-epiam-aaaaa-aaaap-yai', but the subnet \
        does not hold the given key. A proposal to add that key to the subnet must first be \
        separately submitted."
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
        expected = "Chain keys cannot be deleted. Attempted to delete chain keys \
        {Ecdsa(EcdsaKeyId { curve: Secp256k1, name: \"existing_key_id_2\" })} for subnet: \
        'ge6io-epiam-aaaaa-aaaap-yai'"
    )]
    // TODO(NNS1-3022): Delete this once ecdsa_config is obsolete
    fn test_deleting_ecdsa_keys_fails_legacy() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let key_1 = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id".to_string(),
        };

        let key_2 = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "existing_key_id_2".to_string(),
        };

        // Create the subnet we will update
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");

        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        // Give it the keys.
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![key_1.clone(), key_2.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        };
        {
            let chain_key_config = ChainKeyConfigInternal::from(ecdsa_config.clone());
            let chain_key_config_pb = ChainKeyConfigPb::from(chain_key_config);
            subnet_record.chain_key_config = Some(chain_key_config_pb);
        }

        let subnet_id = subnet_test_id(1000);

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        let payload = UpdateSubnetPayload {
            ecdsa_config: Some(ecdsa_config.clone()),
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload.clone());

        let payload = UpdateSubnetPayload {
            ecdsa_config: Some(EcdsaConfig {
                key_ids: vec![key_1.clone()],
                ..ecdsa_config
            }),
            ..payload
        };

        // Should panic because we are trying to modify the config
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

    // TODO[NNS1-3022]: Replace this with a test that checks that `UpdateSubnetPayload.ecdsa_config`
    // TODO[NNS1-3022]: cannot be set.
    #[test]
    #[should_panic(
        expected = "Deprecated field ecdsa_config cannot be specified with chain_key_config."
    )]
    fn test_disallow_legacy_and_chain_key_ecdsa_config_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        // Make a request for the key from a subnet that does not have the key.
        let subnet_id = subnet_test_id(1000);
        let payload = UpdateSubnetPayload {
            ecdsa_config: Some(EcdsaConfig {
                key_ids: vec![key_id.clone()],
                quadruples_to_create_in_advance: 111,
                max_queue_size: Some(222),
                signature_request_timeout_ns: Some(333),
                idkg_key_rotation_period_ms: Some(444),
            }),
            chain_key_config: Some(ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: Some(MasterPublicKeyId::Ecdsa(key_id)),
                    pre_signatures_to_create_in_advance: Some(111),
                    max_queue_size: Some(222),
                }],
                signature_request_timeout_ns: Some(333),
                idkg_key_rotation_period_ms: Some(444),
            }),
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    // TODO[NNS1-3022]: Replace this with a test that checks that
    // TODO[NNS1-3022]: `UpdateSubnetPayload.ecdsa_key_signing_{en,dis}able` cannot be set.
    #[test]
    #[should_panic(
        expected = "Deprecated fields ecdsa_key_signing_{en,dis}able should not be used \
        together with chain_key_signing_{en,dis}able."
    )]
    fn test_disallow_legacy_and_chain_key_ecdsa_signing_enable_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = subnet_test_id(1000);
        let payload = UpdateSubnetPayload {
            ecdsa_key_signing_enable: Some(vec![key_id.clone()]),
            chain_key_signing_enable: Some(vec![MasterPublicKeyId::Ecdsa(key_id)]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    // TODO[NNS1-3022]: Remove this test.
    #[test]
    #[should_panic(
        expected = "Deprecated fields ecdsa_key_signing_{en,dis}able should not be used \
        together with chain_key_signing_{en,dis}able."
    )]
    fn test_disallow_legacy_and_chain_key_ecdsa_signing_disable_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = subnet_test_id(1000);
        let payload = UpdateSubnetPayload {
            ecdsa_key_signing_disable: Some(vec![key_id.clone()]),
            chain_key_signing_disable: Some(vec![MasterPublicKeyId::Ecdsa(key_id)]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    // TODO[NNS1-3022]: Remove this test.
    #[test]
    #[should_panic(
        expected = "Deprecated fields ecdsa_key_signing_{en,dis}able should not be used \
        together with chain_key_signing_{en,dis}able."
    )]
    fn test_disallow_legacy_enable_and_chain_key_ecdsa_signing_disable_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = subnet_test_id(1000);
        let payload = UpdateSubnetPayload {
            ecdsa_key_signing_enable: Some(vec![key_id.clone()]),
            chain_key_signing_disable: Some(vec![MasterPublicKeyId::Ecdsa(key_id)]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    // TODO[NNS1-3022]: Remove this test.
    #[test]
    #[should_panic(
        expected = "Deprecated fields ecdsa_key_signing_{en,dis}able should not be used \
        together with chain_key_signing_{en,dis}able."
    )]
    fn test_disallow_legacy_disable_and_chain_key_ecdsa_signing_enable_specification_together() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let mut registry = invariant_compliant_registry(0);

        let subnet_id = subnet_test_id(1000);
        let payload = UpdateSubnetPayload {
            ecdsa_key_signing_disable: Some(vec![key_id.clone()]),
            chain_key_signing_enable: Some(vec![MasterPublicKeyId::Ecdsa(key_id)]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    // TODO[NNS1-3022]: Remove this test.
    #[test]
    #[should_panic(
        expected = "Proposal attempts to enable and disable signing for the same ECDSA keys"
    )]
    fn test_disallow_ecdsa_key_signing_disable_and_enable_for_same_key_legacy() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        };
        let subnet_id = subnet_test_id(1000);

        let mut registry = invariant_compliant_registry(0);

        // Make sure the registry has the expected subnet record.
        {
            let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
            registry.maybe_apply_mutation_internal(mutate_request.mutations);
            let mut subnet_list_record = registry.get_subnet_list_record();
            let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
                .iter()
                .next()
                .expect("should contain at least one node ID");
            let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
            subnet_record.chain_key_config = Some(ChainKeyConfigPb {
                key_configs: vec![KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb::from(&MasterPublicKeyId::Ecdsa(
                        key_id.clone(),
                    ))),
                    pre_signatures_to_create_in_advance: Some(111),
                    max_queue_size: Some(222),
                }],
                signature_request_timeout_ns: Some(333),
                idkg_key_rotation_period_ms: Some(444),
            });
            registry.maybe_apply_mutation_internal(add_fake_subnet(
                subnet_id,
                &mut subnet_list_record,
                subnet_record,
                &btreemap!(*first_node_id => first_dkg_pk.clone()),
            ));
        }

        let payload = UpdateSubnetPayload {
            ecdsa_key_signing_disable: Some(vec![key_id.clone()]),
            ecdsa_key_signing_enable: Some(vec![key_id]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }

    #[test]
    #[should_panic(
        expected = "Proposal attempts to enable and disable signing for the same chain keys"
    )]
    fn test_disallow_chain_key_signing_disable_and_enable_for_same_key() {
        let key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "fake_key_id".to_string(),
        });
        let subnet_id = subnet_test_id(1000);

        let mut registry = invariant_compliant_registry(0);

        // Make sure the registry has the expected subnet record.
        {
            let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
            registry.maybe_apply_mutation_internal(mutate_request.mutations);
            let mut subnet_list_record = registry.get_subnet_list_record();
            let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
                .iter()
                .next()
                .expect("should contain at least one node ID");
            let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);
            subnet_record.chain_key_config = Some(ChainKeyConfigPb {
                key_configs: vec![KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb::from(&key_id)),
                    pre_signatures_to_create_in_advance: Some(111),
                    max_queue_size: Some(222),
                }],
                signature_request_timeout_ns: Some(333),
                idkg_key_rotation_period_ms: Some(444),
            });
            registry.maybe_apply_mutation_internal(add_fake_subnet(
                subnet_id,
                &mut subnet_list_record,
                subnet_record,
                &btreemap!(*first_node_id => first_dkg_pk.clone()),
            ));
        }

        let payload = UpdateSubnetPayload {
            chain_key_signing_disable: Some(vec![key_id.clone()]),
            chain_key_signing_enable: Some(vec![key_id]),
            ecdsa_config: None,
            chain_key_config: None,
            ..make_empty_update_payload(subnet_id)
        };

        registry.do_update_subnet(payload);
    }
}
