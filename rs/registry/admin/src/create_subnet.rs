use crate::helpers::{
    get_proposer_and_sender, parse_proposal_url, shortened_pids_string, summary_from_string_or_file,
};
use crate::types::{ProposalMetadata, ProposalPayload};
use crate::ProposalTitle;
use async_trait::async_trait;
use clap::Parser;
use ic_admin_derive::derive_common_proposal_fields;
use ic_canister_client::{Agent, Sender};
use ic_management_canister_types::MasterPublicKeyId;
use ic_nns_common::types::NeuronId;
use ic_prep_lib::subnet_configuration::get_default_config_params;
use ic_protobuf::registry::subnet::v1::SubnetFeatures as SubnetFeaturesPb;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::{NodeId, PrincipalId, ReplicaVersion};
use registry_canister::mutations::do_create_subnet;
use std::collections::BTreeMap;
use std::path::PathBuf;
use url::Url;

/// Sub-command to submit a proposal to create a new subnet.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
pub(crate) struct ProposeToCreateSubnetCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing. Exists for compatibility with legacy scripts.
    subnet_handler_id: Option<String>,

    #[clap(name = "NODE_ID", multiple_values(true), required = true)]
    /// The node IDs of the nodes that will be part of the new subnet.
    pub node_ids: Vec<PrincipalId>,

    #[clap(long)]
    // Assigns this subnet ID to the newly created subnet
    pub subnet_id_override: Option<PrincipalId>,

    #[clap(long)]
    /// Maximum amount of bytes per message. This is a hard cap.
    pub max_ingress_bytes_per_message: Option<u64>,

    #[clap(long)]
    /// Maximum number of ingress messages per block. This is a hard cap.
    pub max_ingress_messages_per_block: Option<u64>,

    #[clap(long)]
    /// Maximum size in bytes ingress and xnet messages can occupy in a block.
    pub max_block_payload_size: Option<u64>,

    // the default is from subnet_configuration.rs from ic-prep
    #[clap(long)]
    ///  Unit delay for blockmaker (in milliseconds).
    pub unit_delay_millis: Option<u64>,

    #[clap(long)]
    /// Initial delay for notary (in milliseconds), to give time to rank-0 block
    /// propagation.
    pub initial_notary_delay_millis: Option<u64>,

    #[clap(long, parse(try_from_str = ReplicaVersion::try_from))]
    /// ID of the Replica version to run.
    pub replica_version_id: Option<ReplicaVersion>,

    #[clap(long)]
    /// The length of all DKG intervals. The DKG interval length is the number
    /// of rounds following the DKG summary.
    pub dkg_interval_length: Option<u64>,

    #[clap(long)]
    /// The upper bound for the number of allowed DKG dealings in a block.
    pub dkg_dealings_per_block: Option<u64>,

    #[clap(long)]
    /// if set, the subnet will start as (new) NNS.
    pub start_as_nns: bool,

    #[clap(long)]
    /// The type of the subnet.
    /// Can be either "application" or "system".
    pub subnet_type: SubnetType,

    /// If set, the created subnet will be halted: it will not create or execute
    /// blocks
    #[clap(long)]
    pub is_halted: bool,

    /// Configuration for chain key:
    /// A list of chain key configurations to be requested from other subnets for this subnet,
    /// each with a subnet ID to request this key from.
    ///
    /// key_id: Master public key ID formatted as "Scheme:AlgorithmID:KeyName".
    /// pre_signatures_to_create_in_advance: Non-negative integer value.
    /// max_queue_size: Integer value greater than or equal 1.
    /// subnet_id: Principal ID of a subnet holding the requested key.
    ///
    /// Example (note that all values, including integers, are represented as strings):
    ///
    /// ```
    /// --initial-chain-key-configs-to-request '[
    ///     {
    ///         "key_id": "ecdsa:Secp256k1:some_key_name_1",
    ///         "pre_signatures_to_create_in_advance": "99",
    ///         "max_queue_size": "155",
    ///         "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
    ///     },
    ///     {
    ///         "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
    ///         "pre_signatures_to_create_in_advance": "98",
    ///         "max_queue_size": "154",
    ///         "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
    ///     }
    /// ]'
    /// ```
    #[clap(long)]
    pub initial_chain_key_configs_to_request: Option<String>,

    /// The number of nanoseconds that a chain key signature request will time out.
    /// If none is specified, no request will time out.
    #[clap(long)]
    pub signature_request_timeout_ns: Option<u64>,

    /// Configuration for chain key:
    /// idkg key rotation period of a single node in milliseconds.
    /// If none is specified key rotation is disabled.
    #[clap(long)]
    pub idkg_key_rotation_period_ms: Option<u64>,

    /// The list of public keys whose owners have "readonly" SSH access to all
    /// replicas on this subnet.
    #[clap(long, multiple_values(true))]
    ssh_readonly_access: Vec<String>,
    /// The list of public keys whose owners have "backup" SSH access to nodes
    /// on the NNS subnet.
    #[clap(long, multiple_values(true))]
    ssh_backup_access: Vec<String>,

    /// The maximum number of canisters that are allowed to be created in this
    /// subnet.
    #[clap(long)]
    pub max_number_of_canisters: Option<u64>,

    /// The features that are enabled and disabled on the subnet.
    #[clap(long)]
    pub features: Option<SubnetFeatures>,
}

fn parse_key_config_requests_option(
    maybe_value: &Option<String>,
) -> Vec<do_create_subnet::KeyConfigRequest> {
    let Some(value) = maybe_value else {
        return vec![];
    };

    let raw: Vec<BTreeMap<String, String>> = serde_json::from_str(value)
        .unwrap_or_else(|err| panic!("Cannot parse `{}` as JSON: {}", value, err));

    raw.iter()
        .map(|btree| {
            let subnet_id = Some(btree
                .get("subnet_id")
                .map(|key| {
                    key.parse::<PrincipalId>()
                        .unwrap_or_else(|_| panic!("Could not parse subnet_id: '{}'", key))
                })
                .expect("Each element of the JSON object must specify a 'subnet_id'."));

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

            let key_config = Some(do_create_subnet::KeyConfig {
                key_id,
                pre_signatures_to_create_in_advance,
                max_queue_size
            });

            do_create_subnet::KeyConfigRequest { key_config, subnet_id }
        })
        .collect()
}

impl ProposalTitle for ProposeToCreateSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Create new subnet with nodes: {}",
                shortened_pids_string(&self.node_ids)
            ),
        }
    }
}

impl ProposeToCreateSubnetCmd {
    /// Set fields (that were not provided by the user explicitly) to defaults.
    pub(crate) fn apply_defaults_for_unset_fields(&mut self) {
        // Set default subnet parameters.
        {
            let subnet_config = get_default_config_params(self.subnet_type, self.node_ids.len());
            self.max_ingress_bytes_per_message
                .get_or_insert(subnet_config.max_ingress_bytes_per_message);
            self.max_ingress_messages_per_block
                .get_or_insert(subnet_config.max_ingress_messages_per_block);
            self.max_block_payload_size
                .get_or_insert(subnet_config.max_block_payload_size);
            self.unit_delay_millis
                .get_or_insert(subnet_config.unit_delay.as_millis() as u64);
            self.initial_notary_delay_millis
                .get_or_insert(subnet_config.initial_notary_delay.as_millis() as u64);
            self.dkg_dealings_per_block
                .get_or_insert(subnet_config.dkg_dealings_per_block as u64);
            self.dkg_interval_length
                .get_or_insert(subnet_config.dkg_interval_length.get());
        }
        // Other default parameters.
        {
            self.replica_version_id
                .get_or_insert(ReplicaVersion::default());
            self.max_number_of_canisters.get_or_insert(0);
            self.features.get_or_insert(SubnetFeatures::default());
        }
    }

    fn new_payload(&self) -> do_create_subnet::CreateSubnetPayload {
        let node_ids = self
            .node_ids
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();

        let chain_key_config = if self.signature_request_timeout_ns.is_none()
            && self.idkg_key_rotation_period_ms.is_none()
            && self.initial_chain_key_configs_to_request.is_none()
        {
            None
        } else {
            let key_configs =
                parse_key_config_requests_option(&self.initial_chain_key_configs_to_request);
            Some(do_create_subnet::InitialChainKeyConfig {
                key_configs,
                signature_request_timeout_ns: self.signature_request_timeout_ns,
                idkg_key_rotation_period_ms: self.idkg_key_rotation_period_ms,
            })
        };

        do_create_subnet::CreateSubnetPayload {
            node_ids,
            subnet_id_override: self.subnet_id_override,
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message.unwrap_or_default(),
            max_ingress_messages_per_block: self.max_ingress_messages_per_block.unwrap_or_default(),
            max_block_payload_size: self.max_block_payload_size.unwrap_or_default(),
            replica_version_id: self
                .replica_version_id
                .as_ref()
                .expect("replica_version_id must be specified.")
                .to_string(),
            unit_delay_millis: self.unit_delay_millis.unwrap_or_default(),
            initial_notary_delay_millis: self.initial_notary_delay_millis.unwrap_or_default(),
            dkg_interval_length: self.dkg_interval_length.unwrap_or_default(),
            dkg_dealings_per_block: self.dkg_dealings_per_block.unwrap_or_default(),
            start_as_nns: self.start_as_nns,
            subnet_type: self.subnet_type,
            is_halted: self.is_halted,

            features: SubnetFeaturesPb::from(self.features.expect("features must be specified.")),
            ssh_readonly_access: self.ssh_readonly_access.clone(),
            ssh_backup_access: self.ssh_backup_access.clone(),
            max_number_of_canisters: self.max_number_of_canisters.unwrap_or_default(),
            chain_key_config,

            // Deprecated fields.
            ecdsa_config: None,
            ingress_bytes_per_block_soft_cap: Default::default(),
            gossip_max_artifact_streams_per_peer: Default::default(),
            gossip_max_chunk_wait_ms: Default::default(),
            gossip_max_duplicity: Default::default(),
            gossip_max_chunk_size: Default::default(),
            gossip_receive_check_cache_size: Default::default(),
            gossip_pfn_evaluation_period_ms: Default::default(),
            gossip_registry_poll_period_ms: Default::default(),
            gossip_retransmission_request_ms: Default::default(),
        }
    }
}

#[async_trait]
impl ProposalPayload<do_create_subnet::CreateSubnetPayload> for ProposeToCreateSubnetCmd {
    async fn payload(&self, _: &Agent) -> do_create_subnet::CreateSubnetPayload {
        self.new_payload()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId};
    use ic_types::PrincipalId;

    use super::*;

    fn minimal_create_payload() -> do_create_subnet::CreateSubnetPayload {
        do_create_subnet::CreateSubnetPayload {
            ..Default::default()
        }
    }

    fn empty_propose_to_create_subnet_cmd() -> ProposeToCreateSubnetCmd {
        ProposeToCreateSubnetCmd {
            subnet_type: SubnetType::Application,
            test_neuron_proposer: false,
            dry_run: false,
            json: true,
            start_as_nns: false,
            is_halted: false,
            node_ids: vec![],
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            proposer: None,
            proposal_url: None,
            proposal_title: None,
            summary: None,
            summary_file: None,
            subnet_handler_id: None,
            subnet_id_override: None,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            replica_version_id: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            initial_chain_key_configs_to_request: None,
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_number_of_canisters: None,
            features: None,
        }
    }

    #[test]
    fn cli_to_payload_conversion_works_for_chain_key_fields() {
        // Boilerplate stuff
        let replica_version_id = ReplicaVersion::default();
        let features = SubnetFeatures::default();

        let initial_chain_key_configs_to_request = r#"[{
                "key_id": "ecdsa:Secp256k1:some_key_name_1",
                "pre_signatures_to_create_in_advance": "99",
                "max_queue_size": "155",
                "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
            },
            {
                "key_id": "schnorr:Bip340Secp256k1:some_key_name_2",
                "pre_signatures_to_create_in_advance": "98",
                "max_queue_size": "154",
                "subnet_id": "gxevo-lhkam-aaaaa-aaaap-yai"
            }]"#
        .to_string();
        let initial_chain_key_configs_to_request = Some(initial_chain_key_configs_to_request);
        let signature_request_timeout_ns = Some(111);
        let idkg_key_rotation_period_ms = Some(222);

        // Run code under test
        let cmd = ProposeToCreateSubnetCmd {
            initial_chain_key_configs_to_request,
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,

            replica_version_id: Some(replica_version_id.clone()),
            features: Some(features),
            ..empty_propose_to_create_subnet_cmd()
        };
        assert_eq!(
            cmd.new_payload(),
            do_create_subnet::CreateSubnetPayload {
                chain_key_config: Some(do_create_subnet::InitialChainKeyConfig {
                    key_configs: vec![
                        do_create_subnet::KeyConfigRequest {
                            key_config: Some(do_create_subnet::KeyConfig {
                                key_id: Some(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                                    curve: EcdsaCurve::Secp256k1,
                                    name: "some_key_name_1".to_string(),
                                })),
                                pre_signatures_to_create_in_advance: Some(99),
                                max_queue_size: Some(155),
                            }),
                            subnet_id: Some(
                                PrincipalId::from_str("gxevo-lhkam-aaaaa-aaaap-yai").unwrap()
                            ),
                        },
                        do_create_subnet::KeyConfigRequest {
                            key_config: Some(do_create_subnet::KeyConfig {
                                key_id: Some(MasterPublicKeyId::Schnorr(SchnorrKeyId {
                                    algorithm: SchnorrAlgorithm::Bip340Secp256k1,
                                    name: "some_key_name_2".to_string(),
                                })),
                                pre_signatures_to_create_in_advance: Some(98),
                                max_queue_size: Some(154),
                            }),
                            subnet_id: Some(
                                PrincipalId::from_str("gxevo-lhkam-aaaaa-aaaap-yai").unwrap()
                            ),
                        },
                    ],
                    signature_request_timeout_ns: Some(111),
                    idkg_key_rotation_period_ms: Some(222),
                }),
                replica_version_id: replica_version_id.to_string(),
                features: SubnetFeaturesPb::from(features),
                ..minimal_create_payload()
            },
        );
    }
}
