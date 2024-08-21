use crate::helpers::{
    get_proposer_and_sender, get_subnet_record, parse_proposal_url, shortened_subnet_string,
    summary_from_string_or_file,
};
use crate::types::{ProposalMetadata, ProposalPayload, SubnetRecord};
use crate::{ProposalTitle, SubnetDescriptor};
use async_trait::async_trait;
use clap::Parser;
use ic_admin_derive::derive_common_proposal_fields;
use ic_canister_client::{Agent, Sender};
use ic_management_canister_types::MasterPublicKeyId;
use ic_nns_common::types::NeuronId;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_features::SubnetFeatures;
use ic_types::SubnetId;
use registry_canister::mutations::do_update_subnet;
use std::collections::BTreeMap;
use std::{collections::HashSet, path::PathBuf};
use url::Url;

/// Sub-command to submit a proposal to update a subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Parser)]
pub(crate) struct ProposeToUpdateSubnetCmd {
    /// The subnet that should be updated.
    #[clap(long, required = true, alias = "subnet-id")]
    pub subnet: SubnetDescriptor,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub max_ingress_bytes_per_message: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub max_ingress_messages_per_block: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub max_block_payload_size: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub unit_delay_millis: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub initial_notary_delay_millis: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub dkg_interval_length: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub dkg_dealings_per_block: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub start_as_nns: Option<bool>,

    /// If set, the subnet will be halted: it will no longer create or execute
    /// blocks
    #[clap(long)]
    pub is_halted: Option<bool>,

    /// If set, the subnet will be halted at the next CUP height: it will no longer create or execute
    /// blocks
    #[clap(long)]
    pub halt_at_cup_height: Option<bool>,

    #[clap(long)]
    /// Configuration for chain key:
    /// The key configurations to be added to (or edited) for this subnet. If a key configuration
    /// is new for the specified subnet, it must also not already exist on the IC.
    ///
    /// key_id: master public key ID formatted as "Scheme:AlgorithmID:KeyName".
    /// pre_signatures_to_create_in_advance: Non-negative integer value.
    /// max_queue_size: integer value greater than or equal 1.
    ///
    /// Example (note that all values, including integers, are represented as strings):
    ///
    /// ```
    /// --chain-key-configs-to-generate '[
    ///     {
    ///         "key_id": "ecdsa:Secp256k1:some_key_name_1",
    ///         "pre_signatures_to_create_in_advance": "99",
    ///         "max_queue_size": "155"
    ///     },
    ///     {
    ///         "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
    ///         "pre_signatures_to_create_in_advance": "98",
    ///         "max_queue_size": "154"
    ///     }
    /// ]'
    /// ```
    #[clap(long)]
    pub chain_key_configs_to_generate: Option<String>,

    #[clap(long)]
    /// Configuration for chain key:
    /// Enable key signing on this subnet for a particular key_id.
    /// Only one key_id is permitted at a time at the moment.
    ///
    /// Keys must be given in Scheme:AlgorithmID:KeyName format, like `ecdsa:Secp256k1:some_key_name`.
    chain_key_signing_enable: Option<Vec<String>>,

    #[clap(long)]
    /// Configuration for chain key:
    /// Disable key signing on this subnet for a particular key_id.
    /// Cannot have same values as ecdsa_key_signing_enable, or proposal will not execute.
    ///
    /// Keys must be given in Scheme:AlgorithmID:KeyName format, like `ecdsa:Secp256k1:some_key_name`.
    pub chain_key_signing_disable: Option<Vec<String>>,

    /// Configuration for chain key:
    /// The number of nanoseconds that a chain key signature request will time out.
    /// If none is specified, no request will time out.
    #[clap(long)]
    pub signature_request_timeout_ns: Option<u64>,

    /// Configuration for chain key:
    /// idkg key rotation period of a single node in milliseconds.
    /// If none is specified key rotation is disabled.
    #[clap(long)]
    pub idkg_key_rotation_period_ms: Option<u64>,

    /// The features that are enabled and disabled on the subnet.
    #[clap(long)]
    pub features: Option<SubnetFeatures>,

    /// The list of public keys whose owners have "readonly" SSH access to all
    /// replicas on this subnet.
    #[clap(long, multiple_values(true))]
    ssh_readonly_access: Option<Vec<String>>,
    /// The list of public keys whose owners have "backup" SSH access to nodes
    /// on the NNS subnet.
    #[clap(long, multiple_values(true))]
    ssh_backup_access: Option<Vec<String>>,

    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    #[clap(long)]
    pub max_number_of_canisters: Option<u64>,
}

impl ProposalTitle for ProposeToUpdateSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update configuration of subnet: {}",
                shortened_subnet_string(&self.subnet),
            ),
        }
    }
}

fn parse_chain_key_configs_option(
    maybe_value: &Option<String>,
) -> Vec<do_update_subnet::KeyConfig> {
    let Some(value) = maybe_value else {
        return vec![];
    };

    let raw: Vec<BTreeMap<String, String>> = serde_json::from_str(value)
        .unwrap_or_else(|err| panic!("Cannot parse `{}` as JSON: {}", value, err));

    raw.iter()
        .map(|btree| {
            let key_id = Some(btree
                .get("key_id")
                .map(|key| {
                    key.parse::<MasterPublicKeyId>()
                        .unwrap_or_else(|_| panic!("Could not parse key_id: '{}'", key))
                })
                .expect("Each element of the JSON object must specify a 'key_id'."));

            let pre_signatures_to_create_in_advance = Some(btree
                .get("pre_signatures_to_create_in_advance")
                .map(|x| x.parse::<u32>().expect("pre_signatures_to_create_in_advance must be a u32."))
                .expect("Each element of the JSON object must specify a 'pre_signatures_to_create_in_advance'."));

            let max_queue_size = Some(btree
                .get("max_queue_size")
                .map(|x| x.parse::<u32>().expect("max_queue_size must be a u32"))
                .expect("Each element of the JSON object must specify a 'max_queue_size'."));

            do_update_subnet::KeyConfig { key_id, pre_signatures_to_create_in_advance, max_queue_size }
        })
        .collect()
}

fn parse_chain_keys(key_strings: &[String]) -> Vec<MasterPublicKeyId> {
    key_strings
        .iter()
        .map(|key| {
            key.parse::<MasterPublicKeyId>()
                .unwrap_or_else(|_| panic!("Could not parse as MasterPublicKeyId: '{}'", key))
        })
        .collect()
}

impl ProposeToUpdateSubnetCmd {
    fn new_payload_for_subnet(
        &self,
        subnet_id: SubnetId,
        subnet_record: SubnetRecord,
    ) -> do_update_subnet::UpdateSubnetPayload {
        let chain_key_config = if self.chain_key_configs_to_generate.is_none()
            && self.idkg_key_rotation_period_ms.is_none()
            && self.signature_request_timeout_ns.is_none()
        {
            None
        } else {
            let signature_request_timeout_ns = self.signature_request_timeout_ns.or(subnet_record
                .chain_key_config
                .as_ref()
                .and_then(|c| c.signature_request_timeout_ns));

            let idkg_key_rotation_period_ms = self.idkg_key_rotation_period_ms.or(subnet_record
                .chain_key_config
                .as_ref()
                .and_then(|c| c.idkg_key_rotation_period_ms));

            let mut key_ids_to_configs = subnet_record
                .chain_key_config
                .map(|c| c.key_configs)
                .unwrap_or_default()
                .into_iter()
                .map(|key_config| {
                    (
                        key_config.key_id.clone(),
                        do_update_subnet::KeyConfig::from(key_config),
                    )
                })
                .collect::<BTreeMap<_, _>>();

            // Unsert everything from `chain_key_configs_to_generate`.
            {
                let key_configs_to_add =
                    parse_chain_key_configs_option(&self.chain_key_configs_to_generate);
                for key_config in key_configs_to_add {
                    key_ids_to_configs.insert(key_config.key_id.clone().unwrap(), key_config);
                }
            }

            let key_configs = key_ids_to_configs.into_values().collect();

            Some(do_update_subnet::ChainKeyConfig {
                key_configs,
                signature_request_timeout_ns,
                idkg_key_rotation_period_ms,
            })
        };

        let chain_key_signing_enable = self
            .chain_key_signing_enable
            .as_ref()
            .map(|key_strings| parse_chain_keys(key_strings));

        let chain_key_signing_disable = self
            .chain_key_signing_disable
            .as_ref()
            .map(|key_strings| parse_chain_keys(key_strings));

        if let (Some(enable_signing), Some(disable_signing)) =
            (&chain_key_signing_enable, &chain_key_signing_disable)
        {
            let enable_set = enable_signing.iter().collect::<HashSet<_>>();
            let disable_set = disable_signing.iter().collect::<HashSet<_>>();
            let intersection = enable_set.intersection(&disable_set).collect::<Vec<_>>();
            if !intersection.is_empty() {
                panic!(
                    "You are attempting to enable and disable signing for the same chain keys: \
                    {:?}",
                    intersection
                )
            }
        }

        do_update_subnet::UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message,
            max_ingress_messages_per_block: self.max_ingress_messages_per_block,
            max_block_payload_size: self.max_block_payload_size,
            unit_delay_millis: self.unit_delay_millis,
            initial_notary_delay_millis: self.initial_notary_delay_millis,
            dkg_interval_length: self.dkg_interval_length,
            dkg_dealings_per_block: self.dkg_dealings_per_block,

            start_as_nns: self.start_as_nns,

            // See EXC-408: changing the subnet type is disabled.
            subnet_type: None,

            is_halted: self.is_halted,
            halt_at_cup_height: self.halt_at_cup_height,
            features: self.features.map(|v| v.into()),

            ssh_readonly_access: self.ssh_readonly_access.clone(),
            ssh_backup_access: self.ssh_backup_access.clone(),
            max_number_of_canisters: self.max_number_of_canisters,

            chain_key_config,
            chain_key_signing_enable,
            chain_key_signing_disable,

            // Deprecated fields
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: false,
        }
    }
}

#[async_trait]
impl ProposalPayload<do_update_subnet::UpdateSubnetPayload> for ProposeToUpdateSubnetCmd {
    async fn payload(&self, agent: &Agent) -> do_update_subnet::UpdateSubnetPayload {
        let registry_canister = RegistryCanister::new_with_agent(agent.clone());
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        let subnet_record = get_subnet_record(&registry_canister, subnet_id).await;
        self.new_payload_for_subnet(subnet_id, subnet_record)
    }
}

#[cfg(test)]
mod tests {
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId};
    use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
    use ic_types::PrincipalId;

    use super::*;

    fn make_empty_update_payload(subnet_id: SubnetId) -> do_update_subnet::UpdateSubnetPayload {
        do_update_subnet::UpdateSubnetPayload {
            subnet_id,
            set_gossip_config_to_default: false,
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
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
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
        }
    }

    fn empty_propose_to_update_subnet_cmd(subnet_id: SubnetId) -> ProposeToUpdateSubnetCmd {
        ProposeToUpdateSubnetCmd {
            subnet: SubnetDescriptor::Id(subnet_id.get()),
            test_neuron_proposer: false,
            dry_run: true,
            json: true,
            proposer: None,
            proposal_url: None,
            proposal_title: None,
            summary: None,
            summary_file: None,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            start_as_nns: None,
            is_halted: None,
            halt_at_cup_height: None,
            chain_key_configs_to_generate: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            features: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
            max_number_of_canisters: None,
        }
    }

    #[test]
    fn cli_to_payload_conversion_works_for_chain_key_fields_for_signing_subnet() {
        // Boilerplate stuff
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
        let subnet_record = SubnetRecord {
            chain_key_config: Some(ChainKeyConfig {
                key_configs: vec![
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_3".to_string(),
                        }),
                        pre_signatures_to_create_in_advance: 555,
                        max_queue_size: 444,
                    },
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "some_key_name_4".to_string(),
                        }),
                        pre_signatures_to_create_in_advance: 999,
                        max_queue_size: 888,
                    },
                ],
                signature_request_timeout_ns: Some(111_111),
                idkg_key_rotation_period_ms: Some(111),
            }),
            ..Default::default()
        };

        // Fields under test
        let chain_key_configs_to_generate = r#"[{
                "key_id": "ecdsa:Secp256k1:some_key_name_1",
                "pre_signatures_to_create_in_advance": "99",
                "max_queue_size": "155"
            },
            {
                "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
                "pre_signatures_to_create_in_advance": "98",
                "max_queue_size": "154"
            }]"#
        .to_string();
        let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

        let chain_key_signing_enable = Some(vec!["ecdsa:Secp256k1:some_key_name_3".to_string()]);

        let chain_key_signing_disable = Some(vec!["ecdsa:Secp256k1:some_key_name_4".to_string()]);

        let signature_request_timeout_ns = Some(222_222);
        let idkg_key_rotation_period_ms = Some(222);

        // Run code under test
        let cmd = ProposeToUpdateSubnetCmd {
            chain_key_configs_to_generate,
            chain_key_signing_enable,
            chain_key_signing_disable,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            ..empty_propose_to_update_subnet_cmd(subnet_id)
        };

        assert_eq!(
            cmd.new_payload_for_subnet(subnet_id, subnet_record),
            do_update_subnet::UpdateSubnetPayload {
                chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                    // Note the order is not important so long as it is deterministic. As a matter
                    // of fact, the order is lexicographic, as the implementation uses `BTreeSet`.
                    key_configs: vec![
                        // New config, now being added.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_1".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(99),
                            max_queue_size: Some(155),
                        },
                        // Existed before, now being enabled.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_3".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(555),
                            max_queue_size: Some(444),
                        },
                        // Note that `some_key_name_4` is still here, although it is being disabled.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_4".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(999),
                            max_queue_size: Some(888),
                        },
                        // Another new config, now being added.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                                algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                                name: "some_key_name_2".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(98),
                            max_queue_size: Some(154),
                        },
                    ],
                    signature_request_timeout_ns: Some(222_222),
                    idkg_key_rotation_period_ms: Some(222),
                }),
                chain_key_signing_enable: Some(vec![MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "some_key_name_3".to_string(),
                })]),
                chain_key_signing_disable: Some(vec![MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "some_key_name_4".to_string(),
                })]),
                ..make_empty_update_payload(subnet_id)
            },
        );
    }

    #[test]
    fn cli_to_payload_conversion_works_for_chain_key_fields_for_non_signing_subnet() {
        // Boilerplate stuff
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
        let subnet_record = SubnetRecord {
            chain_key_config: None,
            ..Default::default()
        };

        // Fields under test
        let chain_key_configs_to_generate = r#"[{
                "key_id": "ecdsa:Secp256k1:some_key_name_1",
                "pre_signatures_to_create_in_advance": "99",
                "max_queue_size": "155"
            },
            {
                "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
                "pre_signatures_to_create_in_advance": "98",
                "max_queue_size": "154"
            }]"#
        .to_string();
        let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

        let signature_request_timeout_ns = Some(111);
        let idkg_key_rotation_period_ms = Some(222);

        // Run code under test
        let cmd = ProposeToUpdateSubnetCmd {
            chain_key_configs_to_generate,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            ..empty_propose_to_update_subnet_cmd(subnet_id)
        };

        assert_eq!(
            cmd.new_payload_for_subnet(subnet_id, subnet_record),
            do_update_subnet::UpdateSubnetPayload {
                chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                    key_configs: vec![
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_1".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(99),
                            max_queue_size: Some(155),
                        },
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                                algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                                name: "some_key_name_2".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(98),
                            max_queue_size: Some(154),
                        },
                    ],
                    signature_request_timeout_ns: Some(111),
                    idkg_key_rotation_period_ms: Some(222),
                }),
                ..make_empty_update_payload(subnet_id)
            },
        );
    }

    #[test]
    fn cli_to_payload_conversion_works_for_editing_existing_chain_key_fields() {
        // Boilerplate stuff
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(1));
        let subnet_record = SubnetRecord {
            chain_key_config: Some(ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "some_key_name_1".to_string(),
                    }),
                    pre_signatures_to_create_in_advance: 111_111,
                    max_queue_size: 222_222,
                }],
                signature_request_timeout_ns: Some(888_888),
                idkg_key_rotation_period_ms: Some(999_999),
            }),
            ..Default::default()
        };

        // Fields under test
        let chain_key_configs_to_generate = r#"[{
                "key_id": "ecdsa:Secp256k1:some_key_name_1",
                "pre_signatures_to_create_in_advance": "111",
                "max_queue_size": "222"
            },
            {
                "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
                "pre_signatures_to_create_in_advance": "333",
                "max_queue_size": "444"
            }]"#
        .to_string();
        let chain_key_configs_to_generate = Some(chain_key_configs_to_generate);

        let signature_request_timeout_ns = Some(888);
        let idkg_key_rotation_period_ms = Some(999);

        // Run code under test
        let cmd = ProposeToUpdateSubnetCmd {
            chain_key_configs_to_generate,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            ..empty_propose_to_update_subnet_cmd(subnet_id)
        };

        assert_eq!(
            cmd.new_payload_for_subnet(subnet_id, subnet_record),
            do_update_subnet::UpdateSubnetPayload {
                chain_key_config: Some(do_update_subnet::ChainKeyConfig {
                    key_configs: vec![
                        // Existed before, now being updated.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                curve: EcdsaCurve::Secp256k1,
                                name: "some_key_name_1".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(111),
                            max_queue_size: Some(222),
                        },
                        // New config, now being added.
                        do_update_subnet::KeyConfig {
                            key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                                algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                                name: "some_key_name_2".to_string(),
                            })),
                            pre_signatures_to_create_in_advance: Some(333),
                            max_queue_size: Some(444),
                        },
                    ],
                    signature_request_timeout_ns: Some(888),
                    idkg_key_rotation_period_ms: Some(999),
                }),
                ..make_empty_update_payload(subnet_id)
            },
        );
    }
}
