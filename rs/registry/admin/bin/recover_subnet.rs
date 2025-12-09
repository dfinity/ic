use crate::helpers::{
    get_proposer_and_sender, parse_proposal_url, shortened_subnet_string,
    summary_from_string_or_file,
};
use crate::types::{ProposalMetadata, ProposalPayload};
use crate::{ProposalTitle, SubnetDescriptor};
use async_trait::async_trait;
use clap::Parser;
use ic_admin_derive::derive_common_proposal_fields;
use ic_canister_client::{Agent, Sender};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_common::types::NeuronId;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{NodeId, PrincipalId, SubnetId};
use registry_canister::mutations::do_recover_subnet;
use std::collections::BTreeMap;
use std::path::PathBuf;
use url::Url;

/// Sub-command to submit a proposal to update the recovery CUP of a subnet.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
pub(crate) struct ProposeToUpdateRecoveryCupCmd {
    #[clap(long, required = true, alias = "subnet-index")]
    /// The targeted subnet.
    subnet: SubnetDescriptor,

    #[clap(long, required = true)]
    /// The height of the CUP
    pub height: u64,

    #[clap(long, required = true)]
    /// The block time to start from (nanoseconds from Epoch)
    pub time_ns: u64,

    #[clap(long, required = true)]
    /// The hash of the state
    pub state_hash: String,

    #[clap(long, num_args(1..))]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<PrincipalId>>,

    /// A uri from which data to replace the registry local store should be
    /// downloaded
    #[clap(long)]
    pub registry_store_uri: Option<String>,

    /// The hash of the data that is to be retrieved at the registry store URI
    #[clap(long)]
    pub registry_store_hash: Option<String>,

    /// The registry version that should be used for the recovery cup
    #[clap(long)]
    pub registry_version: Option<u64>,

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

    /// Configuration for chain key:
    /// The number of nanoseconds that a chain key signature request will time out.
    /// If none is specified, no request will time out.
    #[clap(long)]
    pub signature_request_timeout_ns: Option<u64>,

    /// Configuration for chain key:
    /// idkg key rotation period of a single node in milliseconds.
    /// If none is specified, key rotation is disabled.
    #[clap(long)]
    pub idkg_key_rotation_period_ms: Option<u64>,

    /// Configuration for chain key:
    /// Maximum number of pre-signature transcripts that can be worked on in parallel to fill the
    /// pre-signature stash.
    #[clap(long)]
    pub max_parallel_pre_signature_transcripts_in_creation: Option<u32>,
}

impl ProposalTitle for ProposeToUpdateRecoveryCupCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update recovery CatchUp Package of subnet: {} to height: {}",
                shortened_subnet_string(&self.subnet),
                self.height
            ),
        }
    }
}

fn parse_key_config_requests_option(
    maybe_value: &Option<String>,
) -> Vec<do_recover_subnet::KeyConfigRequest> {
    let Some(value) = maybe_value else {
        return vec![];
    };

    let raw: Vec<BTreeMap<String, String>> = serde_json::from_str(value)
        .unwrap_or_else(|err| panic!("Cannot parse `{value}` as JSON: {err}"));

    raw.iter()
        .map(|btree| {
            let subnet_id = Some(btree
                .get("subnet_id")
                .map(|key| {
                    key.parse::<PrincipalId>()
                        .unwrap_or_else(|_| panic!("Could not parse subnet_id: '{key}'"))
                })
                .expect("Each element of the JSON object must specify a 'subnet_id'."));

            let key_id = Some(btree
                .get("key_id")
                .map(|key| {
                    key.parse::<MasterPublicKeyId>()
                        .unwrap_or_else(|_| panic!("Could not parse key_id: '{key}'"))
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

            let key_config = Some(do_recover_subnet::KeyConfig {
                key_id,
                pre_signatures_to_create_in_advance,
                max_queue_size
            });

            do_recover_subnet::KeyConfigRequest { key_config, subnet_id }
        })
        .collect()
}

impl ProposeToUpdateRecoveryCupCmd {
    fn new_payload_for_subnet(
        &self,
        subnet_id: SubnetId,
    ) -> do_recover_subnet::RecoverSubnetPayload {
        let state_hash = hex::decode(self.state_hash.clone())
            .unwrap_or_else(|err| panic!("The provided state hash was invalid: {err}"));

        let replacement_nodes = self
            .replacement_nodes
            .clone()
            .map(|nodes| nodes.into_iter().map(NodeId::from).collect());

        let registry_store_uri = {
            let hash = self.registry_store_hash.clone().unwrap_or_default();
            let registry_version = self.registry_version.unwrap_or(0);
            self.registry_store_uri
                .clone()
                .map(|uri| (uri, hash, registry_version))
        };

        let chain_key_config = if self.signature_request_timeout_ns.is_none()
            && self.idkg_key_rotation_period_ms.is_none()
            && self
                .max_parallel_pre_signature_transcripts_in_creation
                .is_none()
            && self.initial_chain_key_configs_to_request.is_none()
        {
            None
        } else {
            let key_configs =
                parse_key_config_requests_option(&self.initial_chain_key_configs_to_request);
            Some(do_recover_subnet::InitialChainKeyConfig {
                key_configs,
                signature_request_timeout_ns: self.signature_request_timeout_ns,
                idkg_key_rotation_period_ms: self.idkg_key_rotation_period_ms,
                max_parallel_pre_signature_transcripts_in_creation: self
                    .max_parallel_pre_signature_transcripts_in_creation,
            })
        };

        do_recover_subnet::RecoverSubnetPayload {
            height: self.height,
            time_ns: self.time_ns,
            subnet_id: subnet_id.get(),
            state_hash,
            replacement_nodes,
            registry_store_uri,
            chain_key_config,
        }
    }
}

#[async_trait]
impl ProposalPayload<do_recover_subnet::RecoverSubnetPayload> for ProposeToUpdateRecoveryCupCmd {
    async fn payload(&self, agent: &Agent) -> do_recover_subnet::RecoverSubnetPayload {
        let registry_canister = RegistryCanister::new_with_agent(agent.clone());
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        self.new_payload_for_subnet(subnet_id)
    }
}

#[cfg(test)]
#[path = "recover_subnet_tests.rs"]
mod tests;
