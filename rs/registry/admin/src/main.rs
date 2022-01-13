//! Command-line utility to help submitting proposals to modify the IC's NNS.
//!
//! TODO(NNS1-902) Move this utility to `rs/nns`.
mod types;

extern crate chrono;
use async_trait::async_trait;
use candid::{CandidType, Decode, Encode};
use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use clap::Clap;
use cycles_minting_canister::SetAuthorizedSubnetworkListArgs;
use ed25519_dalek::Keypair;
use ic_canister_client::{Agent, Sender};
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_sha::Sha256;
use ic_crypto_utils_basic_sig::conversions::Ed25519SecretKeyConversions;
use ic_http_utils::file_downloader::{check_file_hash, extract_tar_gz_into_dir, FileDownloader};
use ic_prep_lib::subnet_configuration;
use ic_types::p2p;
#[macro_use]
extern crate ic_admin_derive;
use ic_consensus::dkg::make_registry_cup;
use ic_interfaces::registry::RegistryClient;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::{
        TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR,
        TEST_USER2_PRINCIPAL, TEST_USER3_KEYPAIR, TEST_USER3_PRINCIPAL, TEST_USER4_KEYPAIR,
        TEST_USER4_PRINCIPAL,
    },
    GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change, manage_neuron::Command, proposal::Action,
    AddOrRemoveNodeProvider, GovernanceError, ManageNeuron, NodeProvider, Proposal,
    RewardNodeProviders,
};
use ic_nns_governance::{
    pb::v1::NnsFunction,
    proposal_submission::{
        create_external_update_proposal_candid, create_make_proposal_payload,
        decode_make_proposal_response,
    },
};
use ic_nns_handler_root::{
    common::{
        AddNnsCanisterProposalPayload, CanisterStatusResult, ChangeNnsCanisterProposalPayload,
    },
    root_proposals::{GovernanceUpgradeRootProposal, RootProposalBallot},
};
use ic_nns_init::make_hsm_sender;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_protobuf::registry::dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord};
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_protobuf::registry::{
    conversion_rate::v1::IcpXdrConversionRateRecord,
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable,
    subnet::v1::{EcdsaConfig, SubnetListRecord, SubnetRecord as SubnetRecordProto},
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client::helper::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_registry_common::data_provider::NnsDataProvider;
use ic_registry_common::local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::{
    get_node_record_node_id, is_node_record_key, make_blessed_replica_version_key,
    make_crypto_node_key, make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key,
    make_data_center_record_key, make_icp_xdr_conversion_rate_record_key,
    make_node_operator_record_key, make_node_record_key, make_provisional_whitelist_record_key,
    make_replica_version_key, make_routing_table_record_key, make_subnet_list_record_key,
    make_subnet_record_key, make_unassigned_nodes_config_record_key,
    NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY, ROOT_SUBNET_ID_KEY,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::Error;
use ic_types::{
    consensus::{catchup::CUPWithOriginalProtobuf, HasHeight},
    crypto::{threshold_sig::ThresholdSigPublicKey, KeyPurpose},
    ic00::CanisterIdRecord,
    messages::CanisterInstallMode,
    CanisterId, NodeId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId,
};
use prost::Message;
use registry_canister::mutations::common::decode_registry_value;
use registry_canister::mutations::do_set_firewall_config::SetFirewallConfigPayload;
use registry_canister::mutations::do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload;
use registry_canister::mutations::{
    do_add_node_operator::AddNodeOperatorPayload, do_add_nodes_to_subnet::AddNodesToSubnetPayload,
    do_bless_replica_version::BlessReplicaVersionPayload, do_create_subnet::CreateSubnetPayload,
    do_recover_subnet::RecoverSubnetPayload, do_remove_nodes::RemoveNodesPayload,
    do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
    do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
    do_update_subnet::UpdateSubnetPayload,
    do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::io::Write;
use std::sync::Arc;
use std::{
    convert::TryFrom,
    fs::{metadata, read_to_string, File},
    io::Read,
    path::{Path, PathBuf},
    process::exit,
    str::FromStr,
    time::SystemTime,
};
use types::{ProvisionalWhitelistRecord, Registry, RegistryRecord, RegistryValue, SubnetRecord};
use url::Url;

/// Common command-line options for `ic-admin`.
#[derive(Clap)]
#[clap(version = "1.0")]
struct Opts {
    #[clap(short = 'r', long, alias = "registry-url")]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_url: Url,

    #[clap(short = 's', long)]
    /// The pem file containing a secret key to use while authenticating with
    /// the NNS.
    secret_key_pem: Option<PathBuf>,

    #[clap(subcommand)]
    subcmd: SubCommand,

    /// Use an HSM to sign calls.
    #[clap(long)]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    hsm_slot: Option<String>,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    key_id: Option<String>,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    pin: Option<String>,
}

impl ProposeToCreateSubnetCmd {
    /// Set fields (that were not provided by the user explicitly) to defaults.
    fn apply_defaults_for_unset_fields(&mut self) {
        let subnet_config =
            subnet_configuration::get_default_config_params(self.subnet_type, self.node_ids.len());
        let gossip_config = p2p::build_default_gossip_config();
        // set subnet params
        self.ingress_bytes_per_block_soft_cap
            .get_or_insert(subnet_config.ingress_bytes_per_block_soft_cap);
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
        // set gossip params
        self.gossip_max_artifact_streams_per_peer
            .get_or_insert(gossip_config.max_artifact_streams_per_peer);
        self.gossip_max_chunk_wait_ms
            .get_or_insert(gossip_config.max_chunk_wait_ms);
        self.gossip_max_duplicity
            .get_or_insert(gossip_config.max_duplicity);
        self.gossip_max_chunk_size
            .get_or_insert(gossip_config.max_chunk_size);
        self.gossip_receive_check_cache_size
            .get_or_insert(gossip_config.receive_check_cache_size);
        self.gossip_pfn_evaluation_period_ms
            .get_or_insert(gossip_config.pfn_evaluation_period_ms);
        self.gossip_registry_poll_period_ms
            .get_or_insert(gossip_config.registry_poll_period_ms);
        self.gossip_retransmission_request_ms
            .get_or_insert(gossip_config.retransmission_request_ms);
    }
}

/// List of sub-commands accepted by `ic-admin`.
#[derive(Clap)]
#[allow(clippy::large_enum_variant)]
enum SubCommand {
    /// Get the last version of a node's public key from the registry.
    GetPublicKey(GetPublicKeyCmd),
    /// Get the last version of a node's TLS certificate key from the registry.
    GetTlsCertificate(GetTlsCertificateCmd),
    /// Submits a proposal to remove nodes from the subnets they are currently
    /// assigned to.
    ProposeToRemoveNodesFromSubnet(ProposeToRemoveNodesFromSubnetCmd),
    /// Get the last version of a node from the registry.
    GetNode(GetNodeCmd),
    /// Get the nodes added since a given version (exclusive).
    GetNodeListSince(GetNodeListSinceCmd),
    /// Get the topology of the system as described in the registry, in JSON
    /// format.
    GetTopology,
    /// Get the last version of a subnet from the registry.
    GetSubnet(GetSubnetCmd),
    /// Get the last version of the subnet list from the registry.
    GetSubnetList,
    /// Get info about a Replica version
    GetReplicaVersion(GetReplicaVersionCmd),
    /// Get the ICP/XDR conversion rate (the value of 1 ICP measured in XDR).
    GetIcpXdrConversionRate,
    /// Propose updating a subnet's Replica version
    ProposeToUpdateSubnetReplicaVersion(ProposeToUpdateSubnetReplicaVersionCmd),
    /// Get the list of blessed Replica versions.
    GetBlessedReplicaVersions,
    /// Get the latest routing table.
    GetRoutingTable,
    /// Submits a proposal to get a given replica version, to be downloaded from
    /// download.dfinity.systems, blessed.
    ProposeToBlessReplicaVersion(ProposeToBlessReplicaVersionCmd),
    /// Submits a proposal to get the given replica version blessed. This
    /// command gives you maximum flexibility for specifying the download
    /// locations. It is usually preferable to use
    /// --propose-to-bless-replica-version instead, which is less flexible, but
    /// easier to use.
    ProposeToBlessReplicaVersionFlexible(ProposeToBlessReplicaVersionFlexibleCmd),
    /// Submits a proposal to create a new subnet.
    ProposeToCreateSubnet(ProposeToCreateSubnetCmd),
    /// Submits a proposal to update an existing subnet.
    ProposeToAddNodesToSubnet(ProposeToAddNodesToSubnetCmd),
    /// Submits a proposal to update a subnet's recovery CUP
    ProposeToUpdateRecoveryCup(ProposeToUpdateRecoveryCupCmd),
    /// Submits a proposal to update an existing subnet's configuration.
    ProposeToUpdateSubnet(ProposeToUpdateSubnetCmd),
    /// Submits a proposal to change an existing canister on NNS.
    ProposeToChangeNnsCanister(ProposeToChangeNnsCanisterCmd),
    /// Submits a proposal to uninstall code of a canister.
    ProposeToUninstallCode(ProposeToUninstallCodeCmd),
    /// Submits a proposal to set authorized subnetworks that the cycles minting
    /// canister can use.
    ProposeToSetAuthorizedSubnetworks(ProposeToSetAuthorizedSubnetworksCmd),
    /// Submits a proposal to add a new canister on NNS.
    ProposeToAddNnsCanister(ProposeToAddNnsCanisterCmd),
    /// Convert the integer node ID into Principal Id
    ConvertNumericNodeIdToPrincipalId(ConvertNumericNodeIdtoPrincipalIdCmd),
    /// Get whitelist of principals that can access the provisional_* APIs in
    /// the management canister.
    GetProvisionalWhitelist,
    /// Get the public of the subnet.
    GetSubnetPublicKey(SubnetPublicKeyCmd),
    /// Get the recovery CUP fields of a subnet
    GetRecoveryCup(GetRecoveryCupCmd),
    /// Propose to add a new node operator to the registry.
    ProposeToAddNodeOperator(ProposeToAddNodeOperatorCmd),
    /// Get a node operator's record
    GetNodeOperator(GetNodeOperatorCmd),
    /// Get the list of all node operators
    GetNodeOperatorList,
    /// Update local registry store by pulling from remote URL
    UpdateRegistryLocalStore(UpdateRegistryLocalStoreCmd),
    /// Update the whitelist of principals that can access the provisional_*
    /// APIs in the management canister.
    ProposeToClearProvisionalWhitelist(ProposeToClearProvisionalWhitelistCmd),
    /// Update the Node Operator's specified parameters
    ProposeToUpdateNodeOperatorConfig(ProposeToUpdateNodeOperatorConfigCmd),
    /// Propose to set the firewall config
    ProposeToSetFirewallConfig(ProposeToSetFirewallConfigCmd),
    /// Propose to remove a node from the registry via proposal.
    ProposeToRemoveNodes(ProposeToRemoveNodesCmd),
    /// Propose to add or remove a node provider from the governance canister
    ProposeToAddOrRemoveNodeProvider(ProposeToAddOrRemoveNodeProviderCmd),
    // Get latest registry version number
    GetRegistryVersion,
    // Submit a root proposal to the root canister to upgrade the governance canister.
    SubmitRootProposalToUpgradeGovernanceCanister(SubmitRootProposalToUpgradeGovernanceCanisterCmd),
    // Get the pending proposals to upgrade the governance canister.
    GetPendingRootProposalsToUpgradeGovernanceCanister,
    // Vote on a pending root proposal to upgrade the governance canister.
    VoteOnRootProposalToUpgradeGovernanceCanister(VoteOnRootProposalToUpgradeGovernanceCanisterCmd),
    /// Get a DataCenterRecord
    GetDataCenter(GetDataCenterCmd),
    /// Submit a proposal to add data centers and/or remove data centers from
    /// the Registry
    ProposeToAddOrRemoveDataCenters(ProposeToAddOrRemoveDataCentersCmd),
    /// Get the node rewards table
    GetNodeRewardsTable,
    /// Submit a proposal to update the node rewards table
    ProposeToUpdateNodeRewardsTable(ProposeToUpdateNodeRewardsTableCmd),
    /// Submit a proposal to update the unassigned nodes
    ProposeToUpdateUnassignedNodesConfig(ProposeToUpdateUnassignedNodesConfigCmd),
    /// Get the SSH key access lists for unassigned nodes
    GetUnassignedNodes,
    /// Get the monthly Node Provider rewards
    GetMonthlyNodeProviderRewards,
}

/// Indicates whether a value should be added or removed.
#[derive(Clap)]
enum AddOrRemove {
    /// Whether the value should be added
    Add,
    /// Whether the value should be removed
    Remove,
}

impl FromStr for AddOrRemove {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        match string {
            "add" => Ok(AddOrRemove::Add),
            "remove" => Ok(AddOrRemove::Remove),
            &_ => Err(format!("Unknown add or remove value: {:?}", string)),
        }
    }
}

/// Sub-command to fetch the public key of an IC node from the registry.
#[derive(Clap)]
struct GetPublicKeyCmd {
    /// The node id to which the key belongs.
    node_id: PrincipalId,
    /// The purpose of the key. See ic::types::crypto::KeyPurpose.
    key_purpose: KeyPurpose,
}

/// Sub-command to fetch the tls certificate of an IC node from the registry.
#[derive(Clap)]
struct GetTlsCertificateCmd {
    /// The node id to which the TLS certificate belongs.
    node_id: PrincipalId,
}

/// Extracts the summary from either a file or from a string or returns the
/// empty summary.
pub fn summary_from_string_or_file(
    summary: &Option<String>,
    summary_file: &Option<PathBuf>,
) -> String {
    match (summary, summary_file) {
        (None, None) => "".to_string(),
        (Some(_), Some(_)) => panic!("Can't provide both a summary string and a summary file."),
        (Some(s), None) => s.clone(),
        (None, Some(p)) => read_to_string(p).expect("Couldn't read summary from file."),
    }
}

/// Selects a `(NeuronId, Sender)` pair to submit the proposal. If
/// `use_test_neuron` is true, it returns `TEST_NEURON_1_ID` and a `Sender`
/// based on that test neuron's private key, otherwise it validates and returns
/// the `NeuronId` and `Sender` passed as argument.
fn get_proposer_and_sender(
    proposer: Option<NeuronId>,
    sender: Sender,
    use_test_neuron: bool,
) -> (NeuronId, Sender) {
    if use_test_neuron {
        return (
            NeuronId(TEST_NEURON_1_ID),
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        );
    }
    let proposer = proposer.expect("A proposal must have a proposer.");
    assert!(
        sender.get_principal_id() != Sender::Anonymous.get_principal_id(),
        "Must specify a keypair to submit a proposal that corresponds to the owner of a neuron."
    );
    (proposer, sender)
}

/// Trait to extract metadata from a proposal subcommand.
/// This trait is totally implemented in macros and should
/// be used within the derive directive.
pub trait ProposalMetadata {
    fn summary(&self) -> String;
    fn url(&self) -> String;
    fn proposer_and_sender(&self, sender: Sender) -> (NeuronId, Sender);
    fn is_dry_run(&self) -> bool;
    fn is_verbose(&self) -> bool;
}

/// Trait to extract the title and the payload for each proposal type.
/// This trait is async as building some payloads requires async calls.
#[async_trait]
pub trait ProposalTitleAndPayload<T: CandidType> {
    fn title(&self) -> String;
    async fn payload(&self, nns_url: Url) -> T;
}

/// Shortens the provided `PrincipalId` to make it easier to display.
fn shortened_pid_string(pid: &PrincipalId) -> String {
    format!("{}", pid)[..5].to_string()
}

/// Shortens the provided `PrincipalId`s to make them easier to display.
fn shortened_pids_string(pids: &[PrincipalId]) -> String {
    let mut pids_string = "[".to_string();
    pids_string.push_str(
        &pids
            .to_vec()
            .iter()
            .map(PrincipalId::to_string)
            .map(|mut s| {
                s.truncate(5);
                s
            })
            .collect::<Vec<String>>()
            .join(", "),
    );
    pids_string.push(']');
    pids_string
}

/// Sub-command to submit a proposal to remove nodes from a subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToRemoveNodesFromSubnetCmd {
    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs of the nodes that will leave the subnet.
    pub node_ids: Vec<PrincipalId>,
}

#[async_trait]
impl ProposalTitleAndPayload<RemoveNodesFromSubnetPayload> for ProposeToRemoveNodesFromSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Remove nodes: {} from their assigned subnets",
                shortened_pids_string(&self.node_ids)
            ),
        }
    }

    async fn payload(&self, _: Url) -> RemoveNodesFromSubnetPayload {
        let node_ids = self
            .node_ids
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();
        RemoveNodesFromSubnetPayload { node_ids }
    }
}

/// Sub-command to fetch a `NodeRecord` from the registry.
#[derive(Clap)]
struct GetNodeCmd {
    /// The id of the node to get.
    node_id: PrincipalId,
}

/// Sub-command to convert a numeric `NodeId` to a `PrincipalId`.
#[derive(Clap)]
struct ConvertNumericNodeIdtoPrincipalIdCmd {
    /// The integer Id of the node to convert to actual node id.
    node_id: u64,
}

/// Sub-command to fetch a `SubnetRecord` from the registry.
#[derive(Clap)]
struct GetSubnetCmd {
    /// The subnet to get.
    subnet: SubnetDescriptor,
}

/// Sub-command to fetch the most recent `NodeRecord`s since a specific version,
/// from the registry.
#[derive(Clap)]
struct GetNodeListSinceCmd {
    /// Returns the most recent node records added since this given version,
    /// exclusive.
    version: u64,
}

/// Sub-command to fetch a replica version from the registry.
#[derive(Clap)]
struct GetReplicaVersionCmd {
    /// The Replica version to query
    replica_version_id: String,
}

/// Sub-command to submit a proposal to upgrade the replicas running a specific
/// subnet to the given (blessed) version.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateSubnetReplicaVersionCmd {
    /// The subnet to update.
    subnet: SubnetDescriptor,
    /// The new Replica version to use.
    replica_version_id: String,
}

/// Shortens the id of the provided subent to make it easier to display.
fn shortened_subnet_string(subnet: &SubnetDescriptor) -> String {
    match *subnet {
        SubnetDescriptor::Id(pid) => shortened_pid_string(&pid),
        SubnetDescriptor::Index(i) => format!("{}", i),
    }
}

#[async_trait]
impl ProposalTitleAndPayload<UpdateSubnetReplicaVersionPayload>
    for ProposeToUpdateSubnetReplicaVersionCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Upgrade subnet: {} to replica version: {}",
                shortened_subnet_string(&self.subnet),
                self.replica_version_id
            ),
        }
    }

    async fn payload(&self, nns_url: Url) -> UpdateSubnetReplicaVersionPayload {
        let registry_canister = RegistryCanister::new(vec![nns_url.clone()]);
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        UpdateSubnetReplicaVersionPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: self.replica_version_id.clone(),
        }
    }
}

/// Sub-command to  submit a proposal change public keys with "readonly" access
/// privileges or the replica version for the set of all unassigned nodes. There
/// is no easy way to set a privilege to an empty list.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateUnassignedNodesConfigCmd {
    /// The list of public keys whose owners have "readonly" SSH access to all
    /// unassigned nodes.
    #[clap(long)]
    pub ssh_readonly_access: Option<Vec<String>>,

    /// The ID of the replica version that all the unassigned nodes run.
    #[clap(long)]
    pub replica_version_id: Option<String>,
}

#[async_trait]
impl ProposalTitleAndPayload<UpdateUnassignedNodesConfigPayload>
    for ProposeToUpdateUnassignedNodesConfigCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update all unassigned nodes".to_string(),
        }
    }

    async fn payload(&self, _: Url) -> UpdateUnassignedNodesConfigPayload {
        UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: self.ssh_readonly_access.clone(),
            replica_version: self.replica_version_id.clone(),
        }
    }
}

/// Sub-command to submit a proposal to bless a new replica version, by commit
/// hash.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToBlessReplicaVersionCmd {
    /// The hash of the commit to propose
    pub commit_hash: String,
}

#[async_trait]
impl ProposalTitleAndPayload<BlessReplicaVersionPayload> for ProposeToBlessReplicaVersionCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Bless replica version from commit: {}", self.commit_hash),
        }
    }

    async fn payload(&self, _: Url) -> BlessReplicaVersionPayload {
        let file_downloader = FileDownloader::new(None);
        let binary_url = format!(
            "https://download.dfinity.systems/ic/{}/x86_64-linux/ic-replica.tar.gz",
            &self.commit_hash
        );
        let orchestrator_binary_url = format!(
            "https://download.dfinity.systems/ic/{}/x86_64-linux/orchestrator.tar.gz",
            &self.commit_hash
        );

        let dir = tempfile::tempdir().unwrap().into_path();
        file_downloader
            .download_and_extract_tar_gz(&binary_url, &dir, None)
            .await
            .unwrap();

        file_downloader
            .download_and_extract_tar_gz(&orchestrator_binary_url, &dir, None)
            .await
            .unwrap();

        BlessReplicaVersionPayload {
            replica_version_id: self.commit_hash.clone(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        }
    }
}

/// Sub-command to submit a proposal to bless a new replica version, with full
/// detais.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToBlessReplicaVersionFlexibleCmd {
    /// Version ID. This can be anything, it has no semantics. The reason it is
    /// part of the payload is that it will be needed in the subsequent step
    /// of upgrading individual subnets.
    pub replica_version_id: String,

    /// The URL against which a HTTP GET request will return a release
    /// package that corresponds to this version. If set,
    /// {replica, orchestrator}_{url, sha256_hex} will be ignored
    pub release_package_url: Option<String>,

    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_url'. Must be present if release_package_url is
    /// present.
    release_package_sha256_hex: Option<String>,
}

#[async_trait]
impl ProposalTitleAndPayload<BlessReplicaVersionPayload>
    for ProposeToBlessReplicaVersionFlexibleCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Bless replica version: {}", self.replica_version_id,),
        }
    }

    async fn payload(&self, _: Url) -> BlessReplicaVersionPayload {
        BlessReplicaVersionPayload {
            replica_version_id: self.replica_version_id.clone(),
            release_package_url: self
                .release_package_url
                .clone()
                .expect("Release package url is rquired"),
            release_package_sha256_hex: self
                .release_package_sha256_hex
                .clone()
                .expect("Release package sha256 is rquired"),
        }
    }
}

/// Sub-command to submit a proposal to create a new subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToCreateSubnetCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing. Exists for compatibility with legacy scripts.
    subnet_handler_id: Option<String>,

    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs of the nodes that will be part of the new subnet.
    pub node_ids: Vec<PrincipalId>,

    #[clap(long)]
    // Assigns this subnet ID to the newly created subnet
    pub subnet_id_override: Option<PrincipalId>,

    #[clap(long)]
    /// Maximum amount of bytes per block. This is a soft cap.
    pub ingress_bytes_per_block_soft_cap: Option<u64>,

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

    // These are for the GossipConfig sub-struct
    #[clap(long)]
    /// max outstanding request per peer MIN/DEFAULT/MAX.
    pub gossip_max_artifact_streams_per_peer: Option<u32>,

    #[clap(long)]
    /// timeout for a outstanding request.
    pub gossip_max_chunk_wait_ms: Option<u32>,

    #[clap(long)]
    /// max duplicate requests in underutilized networks.
    pub gossip_max_duplicity: Option<u32>,

    #[clap(long)]
    /// maximum chunk size supported on this subnet.
    pub gossip_max_chunk_size: Option<u32>,

    #[clap(long)]
    /// history size for receive check.
    pub gossip_receive_check_cache_size: Option<u32>,

    #[clap(long)]
    /// period for re evaluating the priority function.
    pub gossip_pfn_evaluation_period_ms: Option<u32>,

    #[clap(long)]
    /// period for polling the registry for updates.
    pub gossip_registry_poll_period_ms: Option<u32>,

    #[clap(long)]
    /// period for sending retransmission request.
    pub gossip_retransmission_request_ms: Option<u32>,

    #[clap(long)]
    /// advert best effort percentage (GossipAdvertConfig in
    /// rs/protobuf/def/registry/subnet/v1/subnet.proto)
    pub advert_best_effort_percentage: Option<u32>,

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

    /// The maximum number of instructions a message can execute.
    /// See the comments in `subnet_config.rs` for more details.
    #[clap(long)]
    pub max_instructions_per_message: Option<u64>,

    /// The maximum number of instructions a round can execute.
    /// See the comments in `subnet_config.rs` for more details.
    #[clap(long)]
    pub max_instructions_per_round: Option<u64>,

    /// The maximum number of instructions an `install_code` message can
    /// execute. See the comments in `subnet_config.rs` for more details.
    #[clap(long)]
    pub max_instructions_per_install_code: Option<u64>,

    /// The list of public keys whose owners have "readonly" SSH access to all
    /// replicas on this subnet.
    #[clap(long)]
    ssh_readonly_access: Vec<String>,
    /// The list of public keys whose owners have "backup" SSH access to nodes
    /// on the NNS subnet.
    #[clap(long)]
    ssh_backup_access: Vec<String>,

    /// The maximum number of canisters that are allowed to be created in this
    /// subnet.
    #[clap(long)]
    pub max_number_of_canisters: Option<u64>,
}

#[async_trait]
impl ProposalTitleAndPayload<CreateSubnetPayload> for ProposeToCreateSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Create new subnet with nodes: {}",
                shortened_pids_string(&self.node_ids)
            ),
        }
    }

    async fn payload(&self, _: Url) -> CreateSubnetPayload {
        let node_ids = self
            .node_ids
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();
        let scheduler_config = SchedulerConfig::default_for_subnet_type(self.subnet_type);
        CreateSubnetPayload {
            node_ids,
            subnet_id_override: self.subnet_id_override,
            ingress_bytes_per_block_soft_cap: self.ingress_bytes_per_block_soft_cap.unwrap(),
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message.unwrap(),
            max_ingress_messages_per_block: self.max_ingress_messages_per_block.unwrap(),
            max_block_payload_size: self.max_block_payload_size.unwrap(),
            replica_version_id: self
                .replica_version_id
                .clone()
                .unwrap_or_else(ReplicaVersion::default)
                .to_string(),
            unit_delay_millis: self.unit_delay_millis.unwrap(),
            initial_notary_delay_millis: self.initial_notary_delay_millis.unwrap(),
            dkg_interval_length: self.dkg_interval_length.unwrap(),
            dkg_dealings_per_block: self.dkg_dealings_per_block.unwrap(),
            gossip_max_artifact_streams_per_peer: self
                .gossip_max_artifact_streams_per_peer
                .unwrap(),
            gossip_max_chunk_wait_ms: self.gossip_max_chunk_wait_ms.unwrap(),
            gossip_max_duplicity: self.gossip_max_duplicity.unwrap(),
            gossip_max_chunk_size: self.gossip_max_chunk_size.unwrap(),
            gossip_receive_check_cache_size: self.gossip_receive_check_cache_size.unwrap(),
            gossip_pfn_evaluation_period_ms: self.gossip_pfn_evaluation_period_ms.unwrap(),
            gossip_registry_poll_period_ms: self.gossip_registry_poll_period_ms.unwrap(),
            gossip_retransmission_request_ms: self.gossip_retransmission_request_ms.unwrap(),
            advert_best_effort_percentage: self.advert_best_effort_percentage,
            start_as_nns: self.start_as_nns,
            subnet_type: self.subnet_type,
            is_halted: self.is_halted,
            max_instructions_per_message: self
                .max_instructions_per_message
                .unwrap_or_else(|| scheduler_config.max_instructions_per_message.get()),
            max_instructions_per_round: self
                .max_instructions_per_round
                .unwrap_or_else(|| scheduler_config.max_instructions_per_round.get()),
            max_instructions_per_install_code: self
                .max_instructions_per_install_code
                .unwrap_or_else(|| scheduler_config.max_instructions_per_install_code.get()),
            features: SubnetFeatures::default(),
            ssh_readonly_access: self.ssh_readonly_access.clone(),
            ssh_backup_access: self.ssh_backup_access.clone(),
            max_number_of_canisters: self.max_number_of_canisters.unwrap_or(0),
        }
    }
}

/// Sub-command to submit a prposals to add a nodes to an existing subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToAddNodesToSubnetCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing
    subnet_handler_id: Option<String>,

    #[clap(long, required = true, alias = "subnet-id")]
    /// The subnet to modify
    subnet: SubnetDescriptor,

    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs of the nodes that will be part of the new subnet.
    pub node_ids: Vec<PrincipalId>,
}

#[async_trait]
impl ProposalTitleAndPayload<AddNodesToSubnetPayload> for ProposeToAddNodesToSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Add nodes: {} to subnet: {}",
                shortened_pids_string(&self.node_ids),
                shortened_subnet_string(&self.subnet)
            ),
        }
    }

    async fn payload(&self, nns_url: Url) -> AddNodesToSubnetPayload {
        let registry_canister = RegistryCanister::new(vec![nns_url.clone()]);
        let node_ids = self
            .node_ids
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();
        AddNodesToSubnetPayload {
            subnet_id: self.subnet.get_id(&registry_canister).await.get(),
            node_ids,
        }
    }
}

/// Sub-command to submit a proposal to update the recovery CUP of a subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateRecoveryCupCmd {
    #[clap(long, required = true, alias = "subnet-index")]
    /// The targetted subnet.
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

    #[clap(long)]
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
}

#[async_trait]
impl ProposalTitleAndPayload<RecoverSubnetPayload> for ProposeToUpdateRecoveryCupCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update recovery cup of subnet: {} to height: {}",
                shortened_subnet_string(&self.subnet),
                self.height
            ),
        }
    }

    async fn payload(&self, nns_url: Url) -> RecoverSubnetPayload {
        let registry_canister = RegistryCanister::new(vec![nns_url.clone()]);
        let subnet_id = self.subnet.get_id(&registry_canister).await.get();
        let node_ids = self
            .replacement_nodes
            .clone()
            .map(|nodes| nodes.into_iter().map(NodeId::from).collect());

        let hash = self
            .registry_store_hash
            .clone()
            .unwrap_or_else(|| "".to_string());
        let registry_version = self.registry_version.unwrap_or(0);

        RecoverSubnetPayload {
            subnet_id,
            height: self.height,
            time_ns: self.time_ns,
            state_hash: hex::decode(self.state_hash.clone())
                .expect("The provided state hash was invalid"),
            replacement_nodes: node_ids,
            registry_store_uri: self
                .registry_store_uri
                .clone()
                .map(|uri| (uri, hash, registry_version)),
        }
    }
}

/// Sub-command to submit a proposal to update a subnet.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateSubnetCmd {
    /// The subnet that should be updated.
    #[clap(long, required = true, alias = "subnet-id")]
    subnet: SubnetDescriptor,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub max_ingress_bytes_per_message: Option<u64>,

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
    pub gossip_max_artifact_streams_per_peer: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_chunk_wait_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_duplicity: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_chunk_size: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_receive_check_cache_size: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_pfn_evaluation_period_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_registry_poll_period_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_retransmission_request_ms: Option<u32>,

    #[clap(long)]
    /// advert best effort percentage (GossipAdvertConfig in
    /// rs/protobuf/def/registry/subnet/v1/subnet.proto)
    pub advert_best_effort_percentage: Option<u32>,

    #[clap(long)]
    /// If set, it will set a default value for the entire gossip config. Useful
    /// when you want to only set some fields for the gossip config and there's
    /// currently none set.
    pub set_gossip_config_to_default: bool,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub start_as_nns: Option<bool>,
    /// If set, the subnet will be halted: it will no longer create or execute
    /// blocks
    #[clap(long)]
    pub is_halted: Option<bool>,

    #[clap(long)]
    /// If set, this updates the instruction limit per message.
    /// See the comments in `subnet_config.rs` for more details
    /// on how to choose values.
    max_instructions_per_message: Option<u64>,

    #[clap(long)]
    /// If set, this updates the instruction limit per round.
    /// See the comments in `subnet_config.rs` for more details
    /// on how to choose values.
    max_instructions_per_round: Option<u64>,

    #[clap(long)]
    /// If set, this updates the instruction limit per
    /// `install_code` message. See the comments in `subnet_config.rs`
    /// for more details on how to choose values.
    max_instructions_per_install_code: Option<u64>,

    /// Configuration for ECDSA feature.
    #[clap(long)]
    pub ecdsa_quadruples_to_create_in_advance: Option<u32>,

    /// The features that are enabled and disabled on the subnet.
    #[clap(long)]
    pub features: Option<SubnetFeatures>,

    /// The list of public keys whose owners have "readonly" SSH access to all
    /// replicas on this subnet.
    #[clap(long)]
    ssh_readonly_access: Option<Vec<String>>,
    /// The list of public keys whose owners have "backup" SSH access to nodes
    /// on the NNS subnet.
    #[clap(long)]
    ssh_backup_access: Option<Vec<String>>,

    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    #[clap(long)]
    pub max_number_of_canisters: Option<u64>,
}

#[async_trait]
impl ProposalTitleAndPayload<UpdateSubnetPayload> for ProposeToUpdateSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update configuration of subnet: {}",
                shortened_subnet_string(&self.subnet),
            ),
        }
    }

    async fn payload(&self, nns_url: Url) -> UpdateSubnetPayload {
        let registry_canister = RegistryCanister::new(vec![nns_url.clone()]);
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message,
            max_block_payload_size: self.max_block_payload_size,
            unit_delay_millis: self.unit_delay_millis,
            initial_notary_delay_millis: self.initial_notary_delay_millis,
            dkg_interval_length: self.dkg_interval_length,
            dkg_dealings_per_block: self.dkg_dealings_per_block,
            max_artifact_streams_per_peer: self.gossip_max_artifact_streams_per_peer,
            max_chunk_wait_ms: self.gossip_max_chunk_wait_ms,
            max_duplicity: self.gossip_max_duplicity,
            max_chunk_size: self.gossip_max_chunk_size,
            receive_check_cache_size: self.gossip_receive_check_cache_size,
            pfn_evaluation_period_ms: self.gossip_pfn_evaluation_period_ms,
            registry_poll_period_ms: self.gossip_registry_poll_period_ms,
            retransmission_request_ms: self.gossip_retransmission_request_ms,
            advert_best_effort_percentage: self.advert_best_effort_percentage,
            set_gossip_config_to_default: self.set_gossip_config_to_default,
            start_as_nns: self.start_as_nns,

            // See EXC-408: changing the subnet type is disabled.
            subnet_type: None,

            is_halted: self.is_halted,
            max_instructions_per_message: self.max_instructions_per_message,
            max_instructions_per_round: self.max_instructions_per_round,
            max_instructions_per_install_code: self.max_instructions_per_install_code,
            features: self.features,
            ecdsa_config: self
                .ecdsa_quadruples_to_create_in_advance
                .map(|val| EcdsaConfig {
                    quadruples_to_create_in_advance: val,
                }),
            ssh_readonly_access: self.ssh_readonly_access.clone(),
            ssh_backup_access: self.ssh_backup_access.clone(),
            max_number_of_canisters: self.max_number_of_canisters,
        }
    }
}

/// Sub-command to submit a proposal to upgrade an NNS canister.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToChangeNnsCanisterCmd {
    #[clap(long)]
    /// Whether to skip stopping the canister before installing. Generally,
    /// recommended to stop your canister but you can skip if you are sure there
    /// are no outstanding callbacks that could put it in undefined state after
    /// the upgrade.
    skip_stopping_before_installing: bool,

    #[clap(long, required = true)]
    /// The mode to use when updating the canister.
    mode: CanisterInstallMode,

    #[clap(long, required = true)]
    /// The ID of the canister to modify
    canister_id: CanisterId,

    #[clap(long)]
    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: Option<PathBuf>,

    #[clap(long)]
    /// The URL of the new wasm module to ship.
    wasm_module_url: Option<Url>,

    #[clap(long, required = true)]
    /// The sha256 of the new wasm module to ship.
    wasm_module_sha256: String,

    #[clap(long)]
    /// The path to a binary file containing the initialization args of the
    /// canister.
    arg: Option<PathBuf>,

    #[clap(long)]
    /// If set, it will update the canister's compute allocation to this value.
    /// See `ComputeAllocation` for the semantics of this field.
    compute_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's memory allocation to this value.
    /// See `MemoryAllocation` for the semantics of this field.
    memory_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's query allocation to this value.
    /// See `QueryAllocation` for the semantics of this field.
    query_allocation: Option<u64>,
}

#[async_trait]
impl ProposalTitleAndPayload<UpgradeRootProposalPayload> for ProposeToChangeNnsCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Upgrade Root Canister to wasm with hash: {}",
                &self.wasm_module_sha256
            ),
        }
    }

    async fn payload(&self, _: Url) -> UpgradeRootProposalPayload {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let module_arg = self
            .arg
            .as_ref()
            .map_or(vec![], |path| read_file_fully(path));
        let stop_upgrade_start = !self.skip_stopping_before_installing;
        UpgradeRootProposalPayload {
            wasm_module,
            module_arg,
            stop_upgrade_start,
        }
    }
}

#[async_trait]
impl ProposalTitleAndPayload<ChangeNnsCanisterProposalPayload> for ProposeToChangeNnsCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Upgrade Nns Canister: {} to wasm with hash: {}",
                self.canister_id, &self.wasm_module_sha256
            ),
        }
    }

    async fn payload(&self, _: Url) -> ChangeNnsCanisterProposalPayload {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let arg = self
            .arg
            .as_ref()
            .map_or(vec![], |path| read_file_fully(path));
        ChangeNnsCanisterProposalPayload {
            stop_before_installing: !self.skip_stopping_before_installing,
            mode: self.mode,
            canister_id: self.canister_id,
            wasm_module,
            arg,
            compute_allocation: self.compute_allocation.map(candid::Nat::from),
            memory_allocation: self.memory_allocation.map(candid::Nat::from),
            query_allocation: self.query_allocation.map(candid::Nat::from),
            authz_changes: vec![],
        }
    }
}

/// Sub-command to submit a proposal to uninstall the code of a canister.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUninstallCodeCmd {
    #[clap(long, required = true)]
    /// The ID of the canister to uninstall.
    canister_id: CanisterId,
}

#[async_trait]
impl ProposalTitleAndPayload<CanisterIdRecord> for ProposeToUninstallCodeCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "SECURITY AGENCY ALERT: Uninstall code of canister: {}",
                self.canister_id
            ),
        }
    }

    async fn payload(&self, _: Url) -> CanisterIdRecord {
        CanisterIdRecord::from(self.canister_id)
    }
}

/// Sub-command to submit a proposal to add a new NNS canister.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToAddNnsCanisterCmd {
    #[clap(long, required = true)]
    /// A unique name for the canister.
    name: String,

    #[clap(long)]
    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: Option<PathBuf>,

    #[clap(long)]
    /// The URL of the new wasm module to ship.
    wasm_module_url: Option<Url>,

    #[clap(long, required = true)]
    /// The sha256 of the new wasm module to ship.
    wasm_module_sha256: String,

    #[clap(long)]
    /// The path to a binary file containing the initialization args of the
    /// canister.
    arg: Option<PathBuf>,

    #[clap(long)]
    /// If set, it will update the canister's compute allocation to this value.
    /// See `ComputeAllocation` for the semantics of this field.
    compute_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's memory allocation to this value.
    /// See `MemoryAllocation` for the semantics of this field.
    memory_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's query allocation to this value.
    /// See `QueryAllocation` for the semantics of this field.
    query_allocation: Option<u64>,
}

#[async_trait]
impl ProposalTitleAndPayload<AddNnsCanisterProposalPayload> for ProposeToAddNnsCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Add nns canister: {}", self.name),
        }
    }

    async fn payload(&self, _: Url) -> AddNnsCanisterProposalPayload {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let arg = self
            .arg
            .clone()
            .map_or(vec![], |path| read_file_fully(&path));

        AddNnsCanisterProposalPayload {
            name: self.name.clone(),
            wasm_module,
            arg,
            // Hard code to 1 to satisfy the payload requirement. We don't need more since the
            // canister is running on the NNS where no cycles are charged.
            initial_cycles: 1,
            compute_allocation: self.compute_allocation.map(candid::Nat::from),
            memory_allocation: self.memory_allocation.map(candid::Nat::from),
            query_allocation: self.query_allocation.map(candid::Nat::from),
            authz_changes: vec![],
        }
    }
}

/// Sub-command to submit a proposal to clear the provisional whitelist.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToClearProvisionalWhitelistCmd {}

#[async_trait]
impl ProposalTitleAndPayload<()> for ProposeToClearProvisionalWhitelistCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Clear the provisional whitelist".to_string(),
        }
    }

    async fn payload(&self, _: Url) -> () {}
}

/// Sub-command to submit a proposal set the list of authorized subnets.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToSetAuthorizedSubnetworksCmd {
    /// The principal to be authorized to create canisters using ICPTs.
    /// If who is `None`, then the proposal will set the default list of subnets
    /// onto which everyone is authorized to create canisters to `subnets`
    /// (except those who have a custom list).
    #[clap(long)]
    pub who: Option<PrincipalId>,

    /// The list of subnets that `who` would be authorized to create subnets on.
    /// If `subnets` is `None`, then `who` is removed from the list of
    /// authorized users.
    #[clap(long)]
    pub subnets: Option<Vec<PrincipalId>>,
}

#[async_trait]
impl ProposalTitleAndPayload<SetAuthorizedSubnetworkListArgs>
    for ProposeToSetAuthorizedSubnetworksCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match (&self.who, &self.subnets) {
                (Some(pid), Some(subnets)) => format!(
                    "Authorize principal: {} to install canisters in subnets: {}",
                    shortened_pid_string(pid),
                    shortened_pids_string(subnets)
                ),
                (None, None) => panic!("Must provide 'who' and/or 'subnets"),
                (Some(pid), None) => format!(
                    "Remove principal: {} from the list of principals \
                     that are authorized to install canisters",
                    shortened_pid_string(pid)
                ),
                (None, Some(subnets)) => format!(
                    "Allow all principals to install canisters on subnets: {}",
                    shortened_pids_string(subnets)
                ),
            },
        }
    }

    async fn payload(&self, _: Url) -> SetAuthorizedSubnetworkListArgs {
        let subnets: Vec<SubnetId> = self
            .subnets
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(SubnetId::from)
            .collect();
        SetAuthorizedSubnetworkListArgs {
            who: self.who,
            subnets,
        }
    }
}

/// Sub-command to get the public key of a subnet from the registry.
#[derive(Clap)]
struct SubnetPublicKeyCmd {
    /// The subnet.
    subnet: SubnetDescriptor,

    /// Target path where the PEM is stored.
    target_path: PathBuf,
}

/// Sub-command to get the recovery cup of a subnet from the registry.
#[derive(Clap)]
struct GetRecoveryCupCmd {
    /// The subnet
    subnet: SubnetDescriptor,

    #[clap(long)]
    output_file: Option<PathBuf>,

    /// Read recovery CUP from a local store instead.
    #[clap(long)]
    registry_local_store: Option<PathBuf>,
}

/// Sub-command to submit a proposal to add or remove a node provider.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToAddOrRemoveNodeProviderCmd {
    /// The principal id of the node provider.
    #[clap(long, required = true)]
    pub node_provider_pid: PrincipalId,

    /// A value to indicated whether the provider is to be added or removed.
    pub add_or_remove_provider: AddOrRemove,
}

/// Sub-command to submit a proposal to add a new node operator.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToAddNodeOperatorCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,

    #[clap(long, required = true)]
    /// The remaining number of nodes that could be added by this node operator
    pub node_allowance: u64,

    //// The principal id of this node operator's provider
    pub node_provider_principal_id: PrincipalId,

    /// The data center ID.
    #[clap(long)]
    dc_id: Option<String>,

    /// A JSON map from node type to the number of nodes of that type that the
    /// given Node Operator should be rewarded for.
    ///
    /// Example:
    /// '{ "default": 10, "storage_upgrade": 24 }'
    #[clap(long)]
    rewardable_nodes: Option<String>,
}

#[async_trait]
impl ProposalTitleAndPayload<AddNodeOperatorPayload> for ProposeToAddNodeOperatorCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Add {} as a Node Operator of Node Provider: {}",
                shortened_pid_string(&self.node_operator_principal_id),
                shortened_pid_string(&self.node_provider_principal_id)
            ),
        }
    }

    async fn payload(&self, _: Url) -> AddNodeOperatorPayload {
        let rewardable_nodes = self
            .rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s))
            .unwrap_or_else(BTreeMap::new);

        AddNodeOperatorPayload {
            node_operator_principal_id: Some(self.node_operator_principal_id),
            node_allowance: self.node_allowance,
            node_provider_principal_id: Some(self.node_provider_principal_id),
            dc_id: self.dc_id.clone().unwrap_or_else(|| "".to_string()),
            rewardable_nodes,
        }
    }
}

/// Sub-command to submit a proposal to update the configuration of a node
/// operator.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateNodeOperatorConfigCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_id: PrincipalId,

    /// The remaining number of nodes that could be added by this node operator
    pub node_allowance: Option<u64>,

    /// The data center ID.
    #[clap(long)]
    dc_id: Option<String>,

    /// A JSON map from node type to the number of nodes of that type that the
    /// given Node Operator should be rewarded for.
    ///
    /// Example:
    /// '{ "default": 10, "storage_upgrade": 24 }'
    #[clap(long)]
    rewardable_nodes: Option<String>,
}

#[async_trait]
impl ProposalTitleAndPayload<UpdateNodeOperatorConfigPayload>
    for ProposeToUpdateNodeOperatorConfigCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update config of Node Operator: {}",
                shortened_pid_string(&self.node_operator_id)
            ),
        }
    }

    async fn payload(&self, _: Url) -> UpdateNodeOperatorConfigPayload {
        let rewardable_nodes = self
            .rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s))
            .unwrap_or_else(BTreeMap::new);

        UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(self.node_operator_id),
            node_allowance: self.node_allowance,
            dc_id: self.dc_id.clone(),
            rewardable_nodes,
        }
    }
}

/// Parses a JSON-encoded map from node type (string) to the number of
/// rewardable nodes of that type.
///
/// The supplied node types must be in the node type whitelist
fn parse_rewardable_nodes(json: &str) -> BTreeMap<String, u32> {
    let map: BTreeMap<String, u32> = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("Unable to parse rewardable_nodes: {}", e));

    for node_type in map.keys() {
        if !ic_nns_constants::NODE_TYPES.contains(&node_type.as_str()) {
            panic!(
                "Supplied node type \"{}\" is not a whitelisted node type",
                node_type
            )
        }
    }

    map
}

#[derive(Clap)]
struct GetDataCenterCmd {
    pub dc_id: String,
}

/// Sub-command to submit a proposal to add or remove a data center.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToAddOrRemoveDataCentersCmd {
    /// The JSON-formatted Data Center records to add to the Registry.
    ///
    /// Example:
    /// '{ "id": "AN1", "region": "us-west", "owner": "DC Corp", "gps": {
    /// "latitude": 37.774929,    "longitude": -122.419416 } }'
    #[clap(long)]
    pub data_centers_to_add: Vec<String>,

    /// The IDs of data centers to remove
    #[clap(long)]
    pub data_centers_to_remove: Vec<String>,

    /// If true, skips printing out the `AddOrRemoveDataCentersProposalPayload`
    /// and requiring user confirmation that this payload is correct.
    #[clap(long)]
    pub skip_confirmation: bool,
}

impl ProposeToAddOrRemoveDataCentersCmd {
    fn get_payload(&self) -> AddOrRemoveDataCentersProposalPayload {
        let data_centers_to_add: Vec<DataCenterRecord> = self
            .data_centers_to_add
            .iter()
            .map(|str| {
                let dc: DataCenterRecord = serde_json::from_str(str).unwrap_or_else(|e| {
                    panic!(
                        "Unable to parse JSON DataCenterRecord: {}\nError: {}",
                        str, e
                    );
                });

                dc
            })
            .collect();

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add,
            data_centers_to_remove: self.data_centers_to_remove.clone(),
        };

        payload.validate().unwrap();
        payload
    }
}

#[async_trait]
impl ProposalTitleAndPayload<AddOrRemoveDataCentersProposalPayload>
    for ProposeToAddOrRemoveDataCentersCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => {
                let mut title = String::new();
                let payload = self.get_payload();
                let dc_ids_to_add: Vec<String> = payload
                    .data_centers_to_add
                    .iter()
                    .map(|dc| dc.id.clone())
                    .collect();

                if !dc_ids_to_add.is_empty() {
                    title.push_str("Add data centers: [");
                    title.push_str(&dc_ids_to_add.join(", "));
                    title.push_str("] ");
                }

                if !self.data_centers_to_remove.is_empty() {
                    title.push_str("Remove data centers: [");
                    title.push_str(&self.data_centers_to_remove.clone().join(", "));
                    title.push(']');
                }

                if title.is_empty() {
                    panic!("No data centers to add or remove were specified");
                }

                title
            }
        }
    }

    async fn payload(&self, _: Url) -> AddOrRemoveDataCentersProposalPayload {
        let payload = self.get_payload();

        if !self.skip_confirmation {
            println!("\n{}", &payload);
            println!("Is the above payload correct? [Y/n]");

            let mut buffer = String::new();
            let stdin = std::io::stdin();
            stdin.read_line(&mut buffer).unwrap();

            if &buffer == "Y\n" {
                println!("Submitting proposal...");
            } else {
                panic!("Aborting");
            }
        }

        payload
    }
}

/// Sub-command to submit a proposal to update the node rewards table.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToUpdateNodeRewardsTableCmd {
    /// A JSON-encoded map from region to a map from node type to the
    /// xdr_permyriad_per_node_per_month for that node type in that region
    ///
    /// Example:
    /// '{ "us-west": { "default": 10, "storage_upgrade": 24 }, "france": {
    /// "default": 24 } }'
    #[clap(long)]
    pub updated_node_rewards: String,
}

#[async_trait]
impl ProposalTitleAndPayload<UpdateNodeRewardsTableProposalPayload>
    for ProposeToUpdateNodeRewardsTableCmd
{
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update the Node Rewards Table".into(),
        }
    }

    async fn payload(&self, _: Url) -> UpdateNodeRewardsTableProposalPayload {
        let map: BTreeMap<String, BTreeMap<String, u64>> =
            serde_json::from_str(&self.updated_node_rewards)
                .unwrap_or_else(|e| panic!("Unable to parse updated_node_rewards: {}", e));

        for node_type_to_rewards_map in map.values() {
            for node_type in node_type_to_rewards_map.keys() {
                if !ic_nns_constants::NODE_TYPES.contains(&node_type.as_str()) {
                    panic!(
                        "Supplied node type \"{}\" is not a whitelisted node type",
                        node_type
                    )
                }
            }
        }

        UpdateNodeRewardsTableProposalPayload::from(map)
    }
}

/// Sub-command to fetch a `NodeOperatorRecord` from the registry.
#[derive(Clap)]
struct GetNodeOperatorCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,
}

/// Sub-command to update the registry local store.
#[derive(Clap)]
struct UpdateRegistryLocalStoreCmd {
    /// The path of the directory of registry local store.
    local_store_path: PathBuf,
    #[clap(long)]
    /// Option to disable certificate validation, useful for emergency
    /// recovery.
    disable_certificate_validation: bool,
}

/// Sub-command to submit a proposal to update the firewall configuration.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToSetFirewallConfigCmd {
    /// File with the firewall configuration content
    pub firewall_config_file: PathBuf,
    /// List of allowed IPv4 prefixes, comma separated, or "-" (for empty list)
    pub ipv4_prefixes: String,
    /// List of allowed IPv6 prefixes, comma separated, or "-" (for empty list)
    pub ipv6_prefixes: String,
}

#[async_trait]
impl ProposalTitleAndPayload<SetFirewallConfigPayload> for ProposeToSetFirewallConfigCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update firewall configuration".to_string(),
        }
    }

    async fn payload(&self, _: Url) -> SetFirewallConfigPayload {
        let firewall_config =
            String::from_utf8(read_file_fully(&self.firewall_config_file)).unwrap();
        let ipv4_prefixes: Vec<String> = if self.ipv4_prefixes.eq("-") {
            vec![]
        } else {
            self.ipv4_prefixes
                .split(',')
                .map(|s| s.to_string())
                .collect()
        };
        let ipv6_prefixes: Vec<String> = if self.ipv6_prefixes.eq("-") {
            vec![]
        } else {
            self.ipv6_prefixes
                .split(',')
                .map(|s| s.to_string())
                .collect()
        };
        SetFirewallConfigPayload {
            firewall_config,
            ipv4_prefixes,
            ipv6_prefixes,
        }
    }
}

/// Sub-command to submit a proposal to remove nodes.
#[derive_common_proposal_fields]
#[derive(ProposalMetadata, Clap)]
struct ProposeToRemoveNodesCmd {
    /// The IDs of the nodes to remove.
    #[clap(name = "NODE_ID", required = true)]
    pub node_ids: Vec<PrincipalId>,
}

#[async_trait]
impl ProposalTitleAndPayload<RemoveNodesPayload> for ProposeToRemoveNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Remove nodes: {}", shortened_pids_string(&self.node_ids)),
        }
    }

    async fn payload(&self, _: Url) -> RemoveNodesPayload {
        RemoveNodesPayload {
            node_ids: self
                .node_ids
                .clone()
                .into_iter()
                .map(NodeId::from)
                .collect(),
        }
    }
}

/// Sub-command to submit a root proposal to upgrade the governance canister.
#[derive(Clap)]
struct SubmitRootProposalToUpgradeGovernanceCanisterCmd {
    /// If set, the proposal will be submitted using a known test user key.
    #[clap(long)]
    pub test_user_proposer: Option<u8>,

    #[clap(long)]
    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: Option<PathBuf>,

    #[clap(long)]
    /// The URL of the new wasm module to ship.
    wasm_module_url: Option<Url>,

    #[clap(long, required = true)]
    /// The sha256 of the new wasm module to ship.
    wasm_module_sha256: String,
}

/// Sub-command to vote on a root proposal to upgrade the governance canister.
#[derive(Clap)]
struct VoteOnRootProposalToUpgradeGovernanceCanisterCmd {
    /// If set, the proposal will be voted on using a known test user key.
    #[clap(long)]
    pub test_user_voter: Option<u8>,

    /// If set, the proposal will be expected to have been submitted by
    /// a known test user key.
    #[clap(long)]
    pub test_user_proposer: Option<u8>,

    /// The id of the node operator that is supposed to have submitted
    /// the proposal. Unused if test_user_proposer is set.
    #[clap(long)]
    pub proposer: Option<PrincipalId>,

    /// The hex representation of the sha256 that is expected to have
    /// been proposed.
    #[clap(long)]
    pub expected_proposed_sha256_hex: String,

    /// The ballot that shall be cast.
    #[clap(long)]
    pub ballot: RootProposalBallot,
}

/// A description of a subnet, either by index, or by id.
#[derive(Clone, Copy)]
enum SubnetDescriptor {
    Id(PrincipalId),
    Index(usize),
}

impl FromStr for SubnetDescriptor {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let maybe_index = usize::from_str(s);
        let maybe_principal = PrincipalId::from_str(s);
        match (maybe_index, maybe_principal) {
            (Err(e1), Err(e2)) => Err(format!(
                "Cannot parse argument '{}' as a subnet descriptor. \
                 It is not an index because {}. It is not a principal because {}.",
                s, e1, e2
            )),
            (Ok(i), Err(_)) => Ok(Self::Index(i)),
            (Err(_), Ok(id)) => Ok(Self::Id(id)),
            (Ok(_), Ok(_)) => Err(format!(
                "Well that's embarrassing. {} can be interpreted both as an index and as a \
                 principal. I did not think this was possible!",
                s
            )),
        }
    }
}

impl SubnetDescriptor {
    async fn get_id(&self, registry_canister: &RegistryCanister) -> SubnetId {
        match self {
            Self::Id(p) => SubnetId::new(*p),
            Self::Index(i) => {
                let subnets = get_subnet_ids(registry_canister).await;
                *(subnets.get(*i)
                    .unwrap_or_else(|| panic!("Tried to get subnet of index {}, but there are only {} subnets according to the registry", i, subnets.len())))
            }
        }
    }
}

/// `main()` method for the `ic-admin` utility.
#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();
    let registry_canister = RegistryCanister::new(vec![opts.nns_url.clone()]);

    let sender = if opts.secret_key_pem.is_some() || opts.use_hsm {
        // Make sure to let the user know that we only actually use the sender
        // in methods that go through the NNS handlers and not for other methods.
        //
        // TODO(NNS1-486): Remove ic-admin command whitelist for sender
        match opts.subcmd {
            SubCommand::ProposeToUpdateSubnetReplicaVersion(_) => (),
            SubCommand::ProposeToCreateSubnet(_) => (),
            SubCommand::ProposeToAddNodesToSubnet(_) => (),
            SubCommand::ProposeToRemoveNodes(_) => (),
            SubCommand::ProposeToRemoveNodesFromSubnet(_) => (),
            SubCommand::ProposeToChangeNnsCanister(_) => (),
            SubCommand::ProposeToUninstallCode(_) => (),
            SubCommand::ProposeToAddNnsCanister(_) => (),
            SubCommand::ProposeToBlessReplicaVersion(_) => (),
            SubCommand::ProposeToBlessReplicaVersionFlexible(_) => (),
            SubCommand::ProposeToUpdateSubnet(_) => (),
            SubCommand::ProposeToClearProvisionalWhitelist(_) => (),
            SubCommand::ProposeToUpdateRecoveryCup(_) => (),
            SubCommand::ProposeToUpdateNodeOperatorConfig(_) => (),
            SubCommand::ProposeToSetFirewallConfig(_) => (),
            SubCommand::ProposeToSetAuthorizedSubnetworks(_) => (),
            SubCommand::ProposeToAddOrRemoveNodeProvider(_) => (),
            SubCommand::SubmitRootProposalToUpgradeGovernanceCanister(_) => (),
            SubCommand::VoteOnRootProposalToUpgradeGovernanceCanister(_) => (),
            SubCommand::ProposeToAddOrRemoveDataCenters(_) => (),
            SubCommand::ProposeToUpdateNodeRewardsTable(_) => (),
            SubCommand::ProposeToUpdateUnassignedNodesConfig(_) => (),
            SubCommand::ProposeToAddNodeOperator(_) => (),
            _ => panic!(
                "Specifying a secret key or HSM is only supported for \
                     methods that interact with NNS handlers."
            ),
        }

        if opts.secret_key_pem.is_some() {
            let secret_key_path = opts.secret_key_pem.unwrap();
            use ic_crypto_internal_types::sign::eddsa::ed25519::SecretKey;
            let contents = read_to_string(secret_key_path).expect("Could not read key file.");
            let (secret_key, public_key) =
                SecretKey::from_pem(&contents).expect("Invalid secret key.");
            let mut buf = Vec::new();
            buf.extend(secret_key.as_bytes());
            buf.extend(public_key.as_bytes());
            let keypair = Keypair::from_bytes(&buf).expect("Invalid secret key.");
            Sender::from_keypair(&keypair)
        } else if opts.use_hsm {
            make_hsm_sender(
                &opts.hsm_slot.unwrap(),
                &opts.key_id.unwrap(),
                &opts.pin.unwrap(),
            )
        } else {
            Sender::Anonymous
        }
    } else {
        Sender::Anonymous
    };

    match opts.subcmd {
        SubCommand::GetPublicKey(get_pk_cmd) => {
            let node_id = NodeId::from(get_pk_cmd.node_id);
            print_and_get_last_value::<PublicKey>(
                make_crypto_node_key(node_id, get_pk_cmd.key_purpose)
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetTlsCertificate(get_cert_cmd) => {
            let node_id = NodeId::from(get_cert_cmd.node_id);
            print_and_get_last_value::<X509PublicKeyCert>(
                make_crypto_tls_cert_key(node_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::ProposeToRemoveNodesFromSubnet(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RemoveNodesFromSubnet,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetNode(get_node_cmd) => {
            let node_id = NodeId::from(get_node_cmd.node_id);
            print_and_get_last_value::<NodeRecord>(
                make_node_record_key(node_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetNodeListSince(cmd) => {
            let node_records = get_node_list_since(cmd.version, registry_canister).await;

            let res = serde_json::to_string(&node_records)
                .unwrap_or_else(|_| "Could not serialize node_records".to_string());
            println!("{}", res);
        }
        SubCommand::GetTopology => {
            // Because ic-admin codebase is riddled with bad patterns -- most notably, all
            // get/fetch methods also print out the representation of the
            // data, there is no nice way to print the whole topology.
            // Instead, we print the surrounding structure in a not so nice way
            // and delegate pretty-printing to jq or other consumers.
            // Also, this method is slow, as each fetch needs to happen in sequence (due to
            // printing from it).
            let subnet_ids = get_subnet_ids(&registry_canister).await;
            let subnet_count = subnet_ids.len();
            let mut seen: HashSet<NodeId> = HashSet::new();
            println!("{{ \"topology\": {{");
            println!("\"subnets\": {{");
            for (i, subnet_id) in subnet_ids.iter().enumerate() {
                println!("\"{}\": ", subnet_id);
                let record = print_and_get_last_value::<SubnetRecordProto>(
                    make_subnet_record_key(*subnet_id).as_bytes().to_vec(),
                    &registry_canister,
                )
                .await;
                if i + 1 != subnet_count {
                    println!(",")
                }

                for node in record
                    .membership
                    .iter()
                    .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
                {
                    seen.insert(node);
                }
            }
            println!("}}");
            let node_ids = get_node_list_since(0, registry_canister)
                .await
                .into_iter()
                .filter(|record| {
                    let node_id = NodeId::from(PrincipalId::from_str(&record.node_id).unwrap());
                    !seen.contains(&node_id)
                })
                .collect::<Vec<_>>();
            println!(
                ",\"unassigned_nodes\": {}",
                serde_json::to_string_pretty(&node_ids).unwrap()
            );
            println!("}}}}");
        }
        SubCommand::ConvertNumericNodeIdToPrincipalId(
            convert_numeric_node_id_to_principal_id_cmd,
        ) => {
            let node_id = NodeId::from(PrincipalId::new_node_test_id(
                convert_numeric_node_id_to_principal_id_cmd.node_id,
            ));
            println!("{}", node_id);
        }
        SubCommand::GetSubnet(get_subnet_cmd) => {
            let subnet_id = get_subnet_cmd.subnet.get_id(&registry_canister).await;
            print_and_get_last_value::<SubnetRecordProto>(
                make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetSubnetList => {
            let value: Vec<_> = registry_canister
                .get_value(make_subnet_list_record_key().as_bytes().to_vec(), None)
                .await
                .map(|(bytes, _version)| SubnetListRecord::decode(&bytes[..]).unwrap())
                .unwrap()
                .subnets
                .into_iter()
                .map(|id_vec| format!("{:?}", PrincipalId::try_from(id_vec).unwrap()))
                .collect();
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        SubCommand::GetReplicaVersion(get_replica_version_cmd) => {
            let key = make_replica_version_key(&get_replica_version_cmd.replica_version_id)
                .as_bytes()
                .to_vec();
            let version =
                print_and_get_last_value::<ReplicaVersionRecord>(key, &registry_canister).await;

            let mut success = true;

            eprintln!("Download IC-OS .. ");
            let tmp_dir = tempfile::tempdir().unwrap().into_path();
            let mut tmp_file = tmp_dir.clone();
            tmp_file.push("temp.gz");

            // Download the IC-OS upgrade, do not check sha256 yet, we will do that
            // explicitly later
            let file_downloader = FileDownloader::new(None);
            file_downloader
                .download_file(&version.release_package_url, &tmp_file, None)
                .await
                .expect("Download of release package failed.");

            println!("OK   Download success");

            // Explicitly check sha256 sum again, just to make sure and make the output a
            // bit nicer
            match check_file_hash(&tmp_file, &version.release_package_sha256_hex) {
                Ok(()) => println!("OK   sha256 hash of IC-OS upgrade tar"),
                Err(e) => {
                    println!("FAIL sha256 incorrect: {:?}", e);
                    success = false;
                }
            };

            // Check version number.
            eprintln!("Extracting .. ");
            match extract_tar_gz_into_dir(&tmp_file, &tmp_dir) {
                Ok(()) => {
                    println!("OK   extracting tar gz archive");
                    let mut version_file = tmp_dir.clone();
                    version_file.push("VERSION.TXT");

                    if !version_file.exists() {
                        // Older versions of the IC-OS had version.txt as a file name
                        version_file = tmp_dir.clone();
                        version_file.push("version.txt");
                    }

                    let archive_version = read_to_string(version_file)
                        .expect("Could not read version in extracted verison file");
                    let archive_version = archive_version.trim();

                    if archive_version == get_replica_version_cmd.replica_version_id {
                        println!("OK   correct version number in archived version file");
                    } else {
                        println!(
                            "FAIL incorrect version number in archived version file ({} vs {})",
                            archive_version, get_replica_version_cmd.replica_version_id
                        );
                        success = false;
                    }
                }
                Err(e) => {
                    println!("FAIL extracting tar gz archive: {:?}", e);
                    success = false;
                }
            }

            if !success {
                exit(1);
            }
        }
        SubCommand::GetIcpXdrConversionRate => {
            let key = make_icp_xdr_conversion_rate_record_key()
                .as_bytes()
                .to_vec();
            let value = registry_canister.get_value(key.clone(), None).await;
            if let Ok((bytes, _version)) = value {
                let value = IcpXdrConversionRateRecord::decode(&bytes[..])
                    .expect("Error decoding conversion rate from registry.");
                // Convert the UNIX epoch timestamp to date and (UTC) time:
                let date_time = NaiveDateTime::from_timestamp(value.timestamp_seconds as i64, 0);
                let date_time: DateTime<Utc> = DateTime::from_utc(date_time, Utc);
                println!(
                    "ICP/XDR conversion rate at {}: {}",
                    date_time,
                    value.xdr_permyriad_per_icp as f64 / 10_000.
                );
            }
        }
        SubCommand::ProposeToUpdateSubnetReplicaVersion(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateSubnetReplicaVersion,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetBlessedReplicaVersions => {
            print_and_get_last_value::<BlessedReplicaVersions>(
                make_blessed_replica_version_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetRoutingTable => {
            print_and_get_last_value::<RoutingTable>(
                make_routing_table_record_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::ProposeToBlessReplicaVersion(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::BlessReplicaVersion,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToBlessReplicaVersionFlexible(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::BlessReplicaVersion,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToCreateSubnet(mut cmd) => {
            cmd.apply_defaults_for_unset_fields();
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::CreateSubnet,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToAddNodesToSubnet(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AddNodeToSubnet,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToUpdateRecoveryCup(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RecoverSubnet,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSubnet(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateConfigOfSubnet,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToAddNnsCanister(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::NnsCanisterInstall,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToChangeNnsCanister(cmd) => {
            if cmd.canister_id == ROOT_CANISTER_ID {
                propose_external_proposal_from_command::<
                    UpgradeRootProposalPayload,
                    ProposeToChangeNnsCanisterCmd,
                >(cmd, NnsFunction::NnsRootUpgrade, opts.nns_url, sender)
                .await;
            } else {
                propose_external_proposal_from_command::<
                    ChangeNnsCanisterProposalPayload,
                    ProposeToChangeNnsCanisterCmd,
                >(cmd, NnsFunction::NnsCanisterUpgrade, opts.nns_url, sender)
                .await;
            }
        }
        SubCommand::ProposeToUninstallCode(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UninstallCode,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToClearProvisionalWhitelist(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ClearProvisionalWhitelist,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToSetAuthorizedSubnetworks(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetAuthorizedSubnetworks,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetProvisionalWhitelist => {
            print_and_get_last_value::<ProvisionalWhitelistProto>(
                make_provisional_whitelist_record_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetSubnetPublicKey(cmd) => {
            store_subnet_pk(&registry_canister, cmd.subnet, cmd.target_path.as_path()).await;
        }
        SubCommand::GetRecoveryCup(cmd) => get_recovery_cup(registry_canister, cmd).await,
        SubCommand::ProposeToRemoveNodes(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RemoveNodes,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToAddNodeOperator(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AssignNoid,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetNodeOperator(cmd) => {
            let key = make_node_operator_record_key(cmd.node_operator_principal_id)
                .as_bytes()
                .to_vec();

            print_and_get_last_value::<NodeOperatorRecord>(key, &registry_canister).await;
        }
        SubCommand::GetNodeOperatorList => {
            let registry_client =
                RegistryClientImpl::new(Arc::new(NnsDataProvider::new(registry_canister)), None);

            // maximum number of retries, let the user ctrl+c if necessary
            registry_client
                .try_polling_latest_version(usize::MAX)
                .unwrap();

            let keys = registry_client
                .get_key_family(
                    NODE_OPERATOR_RECORD_KEY_PREFIX,
                    registry_client.get_latest_version(),
                )
                .unwrap();

            println!();
            for key in keys {
                let node_operator_id = key.strip_prefix(NODE_OPERATOR_RECORD_KEY_PREFIX).unwrap();
                println!("{}", node_operator_id);
            }
        }
        SubCommand::UpdateRegistryLocalStore(cmd) => {
            update_registry_local_store(opts.nns_url, cmd).await;
        }
        SubCommand::ProposeToUpdateNodeOperatorConfig(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateNodeOperatorConfig,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToSetFirewallConfig(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetFirewallConfig,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToAddOrRemoveNodeProvider(cmd) => {
            propose_to_add_or_remove_node_provider(cmd, opts.nns_url, sender).await
        }
        SubCommand::GetRegistryVersion => {
            let latest_version = registry_canister.get_latest_version().await.unwrap();
            println!("{}", latest_version)
        }
        SubCommand::SubmitRootProposalToUpgradeGovernanceCanister(cmd) => {
            submit_root_proposal_to_upgrade_governance_canister(cmd, opts.nns_url, sender).await
        }
        SubCommand::GetPendingRootProposalsToUpgradeGovernanceCanister => {
            get_pending_root_proposals_to_upgrade_governance_canister(opts.nns_url, sender).await
        }
        SubCommand::VoteOnRootProposalToUpgradeGovernanceCanister(cmd) => {
            vote_on_root_proposal_to_upgrade_governance_canister(cmd, opts.nns_url, sender).await
        }
        SubCommand::GetDataCenter(cmd) => {
            let (bytes, _) = registry_canister
                .get_value(make_data_center_record_key(&cmd.dc_id).into_bytes(), None)
                .await
                .unwrap();

            let dc = decode_registry_value::<DataCenterRecord>(bytes);
            println!("{}", dc);
        }
        SubCommand::ProposeToAddOrRemoveDataCenters(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AddOrRemoveDataCenters,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetNodeRewardsTable => {
            let (bytes, _) = registry_canister
                .get_value(NODE_REWARDS_TABLE_KEY.as_bytes().to_vec(), None)
                .await
                .unwrap();

            let table = decode_registry_value::<NodeRewardsTable>(bytes);
            println!("{}", table);
        }
        SubCommand::ProposeToUpdateNodeRewardsTable(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateNodeRewardsTable,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::ProposeToUpdateUnassignedNodesConfig(cmd) => {
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateUnassignedNodesConfig,
                opts.nns_url,
                sender,
            )
            .await;
        }
        SubCommand::GetUnassignedNodes => {
            print_and_get_last_value::<UnassignedNodesConfigRecord>(
                make_unassigned_nodes_config_record_key()
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetMonthlyNodeProviderRewards => {
            let canister_client = GovernanceCanisterClient(make_canister_client(
                opts.nns_url.clone(),
                GOVERNANCE_CANISTER_ID,
                sender,
                None,
            ));

            let response = canister_client.get_monthly_node_provider_rewards().await;
            println!("{:?}", response);
        }
    }
}

/// Reads (fully) the file in `path` and returns it's contents as a Vec<u8>.
fn read_file_fully(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|_| panic!("Value file not found at: {:?}", path));
    let metadata = metadata(path).expect("Unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read the content of {:?}", path));
    buffer
}

/// Fetches the last value stored under `key` in the registry and prints it.
async fn print_and_get_last_value<T: Message + Default + serde::Serialize>(
    key: Vec<u8>,
    registry: &RegistryCanister,
) -> T {
    let value = registry.get_value(key.clone(), None).await;
    match value.clone() {
        Ok((bytes, version)) => {
            if key.starts_with(b"subnet_record_") {
                // subnet records are emitted as JSON
                let value = SubnetRecordProto::decode(&bytes[..])
                    .expect("Error decoding value from registry.");
                let subnet_record = SubnetRecord::from(&value);

                let mut registry = Registry {
                    version,
                    ..Default::default()
                };

                let record = RegistryRecord {
                    key: std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    value: RegistryValue::SubnetRecord(subnet_record),
                };

                registry.records.push(record);

                println!("{}", serde_json::to_string_pretty(&registry).unwrap());
            } else if key == b"provisional_whitelist" {
                let value = ProvisionalWhitelistProto::decode(&bytes[..])
                    .expect("Error decoding value from registry.");
                let provisional_whitelist = ProvisionalWhitelistRecord::from(value);

                let mut registry = Registry {
                    version,
                    ..Default::default()
                };
                let record = RegistryRecord {
                    key: std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    value: RegistryValue::ProvisionalWhitelistRecord(provisional_whitelist),
                };

                registry.records.push(record);

                println!("{}", serde_json::to_string_pretty(&registry).unwrap());
            } else {
                // Everything is dumped as debug representation
                println!(
                    "Fetching the most recent value for key: {:?}",
                    std::str::from_utf8(&key).unwrap()
                );
                let value = T::decode(&bytes[..]).expect("Error decoding value from registry.");
                println!("Most recent version is {:?}. Value:\n{:?}", version, value);
            }
        }
        Err(error) => {
            let msg = match error {
                Error::KeyNotPresent(key) => format!(
                    "Key not present: {}",
                    std::str::from_utf8(&key).expect("key is not a str")
                ),
                _ => format!("{:?}", error),
            };
            panic!("Error getting value from registry: {}", msg);
        }
    };

    value
        .map(|(bytes, _version)| T::decode(&bytes[..]).unwrap())
        .unwrap()
}

/// Extracts a proposal payload from the provided command and uses it to submit
/// a proposal to the governance canister.
async fn propose_external_proposal_from_command<
    C: CandidType + Serialize + Debug,
    Command: ProposalMetadata + ProposalTitleAndPayload<C>,
>(
    cmd: Command,
    nns_function: NnsFunction,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) = cmd.proposer_and_sender(sender);
    let canister_client = GovernanceCanisterClient(make_canister_client(
        nns_url.clone(),
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let payload = cmd.payload(nns_url).await;
    print_payload(&payload, &cmd);

    if cmd.is_dry_run() {
        return;
    }

    let response = canister_client
        .submit_external_proposal_candid(
            payload,
            nns_function,
            cmd.url(),
            &cmd.title(),
            &cmd.summary(),
        )
        .await;
    eprintln!(
        "submit_proposal for {} response: {:?}",
        cmd.title(),
        response,
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for {} error: {:?}", cmd.title(), e);
            std::process::exit(1);
        }
    };
}

/// Enpasulates a node/node operator id pair.
#[derive(Serialize)]
struct NodeAndNodeOperatorId {
    node_id: String,
    node_operator_id: String,
}

/// Fetches the list of nodes that were added since `version` to the registry.
async fn get_node_list_since(
    version: u64,
    registry: RegistryCanister,
) -> Vec<NodeAndNodeOperatorId> {
    let (nns_subnet_id_vec, _) = registry
        .get_value(ROOT_SUBNET_ID_KEY.as_bytes().to_vec(), None)
        .await
        .unwrap();
    let nns_subnet_id =
        decode_registry_value::<ic_protobuf::types::v1::SubnetId>(nns_subnet_id_vec);
    let (nns_pub_key_vec, _) = registry
        .get_value(
            make_crypto_threshold_signing_pubkey_key(SubnetId::new(
                PrincipalId::try_from(nns_subnet_id.principal_id.unwrap().raw).unwrap(),
            ))
            .as_bytes()
            .to_vec(),
            None,
        )
        .await
        .unwrap();
    let nns_pub_key =
        ThresholdSigPublicKey::try_from(PublicKey::decode(nns_pub_key_vec.as_slice()).unwrap())
            .unwrap();

    let latest_version = registry.get_latest_version().await.unwrap();

    // Retrieving the nodes added since a given version involves
    // going over all the changes since said version; get_certified_changes_since is
    // used as it caps the number of responses it provides and in doing so enforces
    // pagination. This is why we loop here.
    let mut deltas = vec![];
    let mut current_version = version;
    loop {
        match registry
            .get_certified_changes_since(current_version, &nns_pub_key)
            .await
        {
            Err(err) => panic!("Couldn't fetch registry delta: {:?}", err),
            Ok((mut v, _, _)) => {
                current_version = v[v.len() - 1].version.get();
                deltas.append(&mut v);
                if current_version >= latest_version {
                    break;
                };
            }
        };
    }

    let mut node_map = BTreeMap::new();
    deltas.into_iter().for_each(|versioned_record| {
        // Since RegistryVersionedRecord's are strongly typed; we must filter those
        // with the relevant keys.
        if is_node_record_key(&versioned_record.key) {
            match versioned_record.value {
                Some(v) => {
                    let decoded_v = NodeRecord::decode(v.as_slice()).unwrap();
                    node_map
                        .entry(versioned_record.key)
                        .and_modify(|e: &mut Vec<NodeRecord>| e.push(decoded_v.clone()))
                        .or_insert_with(|| vec![decoded_v]);
                }
                None => {
                    node_map.remove(&versioned_record.key);
                }
            };
        }
    });

    let node_records: Vec<NodeAndNodeOperatorId> = node_map
        .iter()
        .filter_map(|(k, v)| {
            v.last().map(|res| NodeAndNodeOperatorId {
                node_id: format!("{}", get_node_record_node_id(k).unwrap()),
                node_operator_id: format!(
                    "{}",
                    PrincipalId::try_from(res.node_operator_id.clone()).unwrap()
                ),
            })
        })
        .collect();

    node_records
}

/// Parses the URL of a proposal.
fn parse_proposal_url(url: Option<Url>) -> String {
    match url {
        Some(url) => {
            if url.scheme() != "https" {
                panic!("proposal-url must use https");
            }
            url.to_string()
        }
        // By default point to the landing page of `nns-proposals` repository.
        None => "".to_string(),
    }
}

/// Reads the wasm module into memory and validates it against a sha256 checksum
async fn read_wasm_module(
    wasm_module_path: &Option<PathBuf>,
    wasm_module_url: &Option<Url>,
    wasm_resource_sha256: &str,
) -> Vec<u8> {
    let wasm_file_path = match (wasm_module_path, wasm_module_url) {
        (None, None) => {
            panic!("Must provide either --wasm-module-path PATH or --wasm-module-url URL")
        }
        (Some(_), Some(_)) => {
            panic!("Cannot provide both --wasm-module-path PATH and --wasm-module-url URL")
        }
        (Some(path), None) => path.clone(),
        (None, Some(url)) => download_wasm_module(url).await,
    };

    check_file_hash(&wasm_file_path, wasm_resource_sha256)
        .expect("Wasm module's sha256 does not match provided sha256");

    read_file_fully(&wasm_file_path)
}

async fn download_wasm_module(url: &Url) -> PathBuf {
    if url.scheme() != "https" {
        panic!("Wasm module urls must use https");
    }

    let tmp_dir = tempfile::tempdir().unwrap().into_path();
    let mut tmp_file = tmp_dir.clone();
    tmp_file.push("wasm_module.tar.gz");

    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(url.as_str(), &tmp_file, None)
        .await
        .expect("Failed to download wasm module");

    tmp_file
}

/// Extracts the ids from a `SubnetListRecord`.
fn extract_subnet_ids(subnet_list_record: &SubnetListRecord) -> Vec<SubnetId> {
    subnet_list_record
        .subnets
        .iter()
        .map(|x| {
            SubnetId::from(
                PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
            )
        })
        .collect()
}

/// Returns the ids from all the subnets currently in the registry.
async fn get_subnet_ids(registry: &RegistryCanister) -> Vec<SubnetId> {
    let (subnet_list_record, _) = get_subnet_list_record(registry).await;
    extract_subnet_ids(&subnet_list_record)
}

/// Returns the record that lists all the subnets currently in the registry.
async fn get_subnet_list_record(registry: &RegistryCanister) -> (SubnetListRecord, bool) {
    // First we need to get the current subnet list record.

    let subnet_list_record_result = registry
        .get_value(make_subnet_list_record_key().as_bytes().to_vec(), None)
        .await;
    match subnet_list_record_result {
        Ok((bytes, _version)) => match SubnetListRecord::decode(&bytes[..]) {
            Ok(record) => (record, false),
            Err(error) => panic!("Error decoding subnet list record: {:?}", error),
        },
        Err(error) => match error {
            // It might be the first time we store a subnet, so we might
            // have to update the subnet list record.
            Error::KeyNotPresent(_) => (SubnetListRecord::default(), true),
            _ => panic!(
                "Error while fetching current subnet list record: {:?}",
                error
            ),
        },
    }
}

/// Writes the threshold signing public key of the given subnet to the given
/// path.
async fn store_subnet_pk<P: AsRef<Path>>(
    registry: &RegistryCanister,
    subnet: SubnetDescriptor,
    path: P,
) {
    let subnet_id = subnet.get_id(registry).await;
    let pk = get_subnet_pk(registry, subnet_id).await;
    store_threshold_sig_pk(&pk, path);
}

/// Fetch a subnet's public key.
async fn get_subnet_pk(registry: &RegistryCanister, subnet_id: SubnetId) -> PublicKey {
    let k = make_crypto_threshold_signing_pubkey_key(subnet_id)
        .as_bytes()
        .to_vec();
    match registry.get_value(k.clone(), None).await {
        Ok((bytes, _)) => {
            PublicKey::decode(&bytes[..]).expect("Error decoding PublicKey from registry")
        }
        Err(error) => panic!("Error getting value from registry: {:?}", error),
    }
}

/// Fetch a subnet's recovery CUP.
async fn get_recovery_cup(registry_canister: RegistryCanister, cmd: GetRecoveryCupCmd) {
    let subnet_id = cmd.subnet.get_id(&registry_canister).await;
    let registry_client = if let Some(local_store_path) = cmd.registry_local_store {
        let local_store = Arc::new(LocalStoreImpl::new(local_store_path));
        RegistryClientImpl::new(local_store, None)
    } else {
        RegistryClientImpl::new(Arc::new(NnsDataProvider::new(registry_canister)), None)
    };
    // maximum number of retries, let the user ctrl+c if necessary
    registry_client
        .try_polling_latest_version(usize::MAX)
        .expect("Failed to poll client");

    let cup =
        make_registry_cup(&registry_client, subnet_id, None).expect("Failed to make registry CUP");

    // This prints JSON with byte array fields in hex format.
    fn to_json_string<T: Serialize>(msg: &T) -> String {
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);
        let ser = serde_bytes_repr::ByteFmtSerializer::hex(&mut ser);
        msg.serialize(ser).expect("Failed to serialize to JSON");
        String::from_utf8(out).expect("UTF8 conversion error")
    }

    // CUP content is printed to stdout as JSON string.
    println!("{}", to_json_string(&cup));
    // Additional information is printed to stderr in human readable form.
    eprintln!(
        "height: {}, time: {}, state_hash: {:?}",
        cup.height(),
        cup.content.block.as_ref().context.time,
        cup.content.state_hash
    );

    if let Some(output_file) = cmd.output_file {
        let cup_proto = CUPWithOriginalProtobuf::from_cup(cup);
        let mut file =
            std::fs::File::create(output_file).expect("Failed to open output file for write");
        let mut bytes = Vec::<u8>::new();
        cup_proto
            .protobuf
            .encode(&mut bytes)
            .expect("Failed to encode protobuf");
        file.write_all(&bytes)
            .expect("Failed to write to output file");
    }
}

/// The proposal payload to upgrade the root canister.
///
/// The "authoritative" data structure is the one defined in `lifeline.mo` and
/// this should stay in sync with it
#[derive(CandidType, Serialize)]
pub struct UpgradeRootProposalPayload {
    pub wasm_module: Vec<u8>,
    pub module_arg: Vec<u8>,
    pub stop_upgrade_start: bool,
}

impl std::fmt::Debug for UpgradeRootProposalPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.module_arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("UpgradeRootProposalPayload")
            .field("stop_upgrade_start", &self.stop_upgrade_start)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("module_arg_sha256", &format!("{:x?}", arg_sha))
            .finish()
    }
}

/// Writes a threshold signing public key to the given path.
pub fn store_threshold_sig_pk<P: AsRef<Path>>(pk: &PublicKey, path: P) {
    let pk = ThresholdSigPublicKey::try_from(pk.clone())
        .expect("failed to parse threshold signature PK from protobuf");
    let der_bytes = threshold_sig_public_key_to_der(pk)
        .expect("failed to encode threshold signature PK into DER");

    let mut bytes = vec![];
    bytes.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\r\n");
    for chunk in base64::encode(&der_bytes[..]).as_bytes().chunks(64) {
        bytes.extend_from_slice(chunk);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"-----END PUBLIC KEY-----\r\n");

    let path = path.as_ref();
    std::fs::write(path, bytes)
        .unwrap_or_else(|e| panic!("failed to store public key to {}: {}", path.display(), e));
}

/// Submit a proposal to add a new node provider record
async fn propose_to_add_or_remove_node_provider(
    cmd: ProposeToAddOrRemoveNodeProviderCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let canister_client = GovernanceCanisterClient(make_canister_client(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let node_provider = NodeProvider {
        id: Some(cmd.node_provider_pid),
        // TODO(NNS1-771): accept this data from the command line
        reward_account: None,
    };
    let (change, default_summary) = match cmd.add_or_remove_provider {
        AddOrRemove::Add => (
            Some(Change::ToAdd(node_provider)),
            format!("Add node provider {}", cmd.node_provider_pid),
        ),
        AddOrRemove::Remove => (
            Some(Change::ToRemove(node_provider)),
            format!("Remove node provider {}", cmd.node_provider_pid),
        ),
    };
    let payload = AddOrRemoveNodeProvider { change };
    print_payload(&payload, &cmd);

    if cmd.is_dry_run() {
        return;
    }

    let summary = cmd.summary.unwrap_or(default_summary);
    let response = canister_client
        .submit_add_or_remove_node_provider_proposal(
            payload,
            parse_proposal_url(cmd.proposal_url),
            format!("Add node provider: {}", cmd.node_provider_pid),
            summary,
        )
        .await;

    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("propose_to_add_or_remove_node_provider error: {:?}", e);
            std::process::exit(1);
        }
    };
}

/// Returns the threshold signing public key of the roo (NNS) subnet.
fn get_root_subnet_pub_key(
    client: Arc<RegistryClientImpl>,
    version: RegistryVersion,
) -> Result<ThresholdSigPublicKey, String> {
    let root_subnet_id = client
        .get_root_subnet_id(version)
        .map_err(|err| format!("{}", err))?
        .ok_or("Root subnet_id is not found")?;
    client
        .get_threshold_signing_public_key_for_subnet(root_subnet_id, version)
        .map_err(|err| format!("{}", err))?
        .ok_or_else(|| "Root subnet public key is not found".to_string())
}

/// Fetch registry records from the given `nns_url`, and update the local
/// registry store with the new records.
async fn update_registry_local_store(nns_url: Url, cmd: UpdateRegistryLocalStoreCmd) {
    eprintln!("RegistryLocalStore path: {:?}", cmd.local_store_path);
    let local_store = Arc::new(LocalStoreImpl::new(cmd.local_store_path));
    let local_client = Arc::new(RegistryClientImpl::new(local_store.clone(), None));
    // maximum number of retries, let the user ctrl+c if necessary
    local_client
        .try_polling_latest_version(usize::MAX)
        .expect("Local registry client try_polling_latest_version failed");
    let latest_version = local_client.get_latest_version();
    eprintln!("RegistryLocalStore latest version: {}", latest_version);
    let nns_pub_key = match get_root_subnet_pub_key(local_client.clone(), latest_version) {
        Ok(pub_key) => {
            eprintln!("Root subnet public key found: {:?}", pub_key);
            pub_key
        }
        Err(err) => {
            if cmd.disable_certificate_validation {
                eprintln!("Root subnet public key is not found in RegistryLocalStore. Ignore.");
                // Try again with validation disabled
                use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
                PublicKeyBytes([0; PublicKeyBytes::SIZE]).into()
            } else {
                panic!("Error looking up RegistryLocalStore: {}", err)
            }
        }
    };
    let remote_canister = RegistryCanister::new(vec![nns_url.clone()]);
    let response = remote_canister
        .get_certified_changes_since(latest_version.get(), &nns_pub_key)
        .await;
    let records = match response {
        Ok(response) => response.0,
        Err(err) => {
            let throw_err = |err| panic!("Error retrieving registry records: {:?}", err);
            if cmd.disable_certificate_validation {
                remote_canister
                    .get_changes_since_as_transport_records(latest_version.get())
                    .await
                    .unwrap_or_else(throw_err)
            } else {
                throw_err(err)
            }
            .0
        }
    };

    let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
        let rel_version = (r.version - latest_version).get();
        if cl.len() < rel_version as usize {
            cl.push(ChangelogEntry::default());
        }
        cl.last_mut().unwrap().push(KeyMutation {
            key: r.key.clone(),
            value: r.value.clone(),
        });
        cl
    });

    changelog
        .into_iter()
        .enumerate()
        .try_for_each(|(i, cle)| {
            let v = latest_version + RegistryVersion::from(i as u64 + 1);
            eprintln!("Writing data of registry version {}", v);
            local_store.store(v, cle)
        })
        .expect("Writing to the filesystem failed: Stop.");

    eprintln!("Finished update.");
}

/// Returns a sender corresponding to a `test_sender`, or `current_sender` if
/// not set.
fn get_test_sender_if_set(current_sender: Sender, test_sender: Option<u8>) -> Sender {
    match test_sender {
        None => current_sender,
        Some(1) => Sender::from_keypair(&TEST_USER1_KEYPAIR),
        Some(2) => Sender::from_keypair(&TEST_USER2_KEYPAIR),
        Some(3) => Sender::from_keypair(&TEST_USER3_KEYPAIR),
        Some(4) => Sender::from_keypair(&TEST_USER4_KEYPAIR),
        _ => {
            panic!("Invalid test user sender value. Must be [1, 4].");
        }
    }
}

/// Submits a root proposal to upgrade the governance canister.
async fn submit_root_proposal_to_upgrade_governance_canister(
    cmd: SubmitRootProposalToUpgradeGovernanceCanisterCmd,
    nns_url: Url,
    sender: Sender,
) {
    let sender = get_test_sender_if_set(sender, cmd.test_user_proposer);
    let canister_client = RootCanisterClient(make_canister_client(
        nns_url,
        ROOT_CANISTER_ID,
        sender,
        None,
    ));
    let result = canister_client
        .submit_root_proposal_to_upgrade_governance_canister(cmd)
        .await;
    match result {
        Ok(()) => println!("Root proposal to upgrade the governance canister submitted."),
        Err(error) => println!(
            "Error submitting root propoposal to upgrade governance cansister: {}",
            error
        ),
    }
}

/// Returns the current list of pending root proposals to upgrade the governance
/// canister.
async fn get_pending_root_proposals_to_upgrade_governance_canister(nns_url: Url, sender: Sender) {
    let canister_client = RootCanisterClient(make_canister_client(
        nns_url,
        ROOT_CANISTER_ID,
        sender,
        None,
    ));
    let proposals = canister_client
        .get_pending_root_proposals_to_upgrade_governance_canister()
        .await;

    if proposals.is_empty() {
        println!("No currently pending root proposals.")
    } else {
        println!("Currently pending root proposals: ");
        for proposal in proposals {
            println!("{:?}", proposal);
        }
    }
}

/// Votes a root proposal to upgrade the governance canister.
async fn vote_on_root_proposal_to_upgrade_governance_canister(
    cmd: VoteOnRootProposalToUpgradeGovernanceCanisterCmd,
    nns_url: Url,
    sender: Sender,
) {
    let sender = get_test_sender_if_set(sender, cmd.test_user_voter);
    let canister_client = RootCanisterClient(make_canister_client(
        nns_url,
        ROOT_CANISTER_ID,
        sender,
        None,
    ));
    let result = canister_client
        .vote_on_root_proposal_to_upgrade_governance_canister(cmd)
        .await;
    match result {
        Ok(()) => println!("Ballot for root proposal cast."),
        Err(error) => println!("Error submitting root propoposal ballot: {}", error),
    }
}

/// A helper function for the handler code.
fn generate_nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

/// A client view of an NNS canister.
struct NnsCanisterClient {
    /// The agent to talk to the IC.
    agent: Agent,

    /// Canister ID of the handler.
    handler_id: CanisterId,

    /// If this handler will perform an operation on behalf of a neuron,
    /// such as submitting a proposal or voting, this must be set to the
    /// id of that neuron.
    author: Option<NeuronId>,
}

impl NnsCanisterClient {
    fn proposal_author(&self) -> &NeuronId {
        self.author
            .as_ref()
            .expect("No neuron id to be used as an author was set.")
    }
}

/// A client for the governance canister.
struct GovernanceCanisterClient(NnsCanisterClient);
/// A client for the root canister.
struct RootCanisterClient(NnsCanisterClient);

/// Build a new canister client.
fn make_canister_client(
    nns_url: Url,
    handler_id: CanisterId,
    sender: Sender,
    author: Option<NeuronId>,
) -> NnsCanisterClient {
    NnsCanisterClient {
        agent: Agent::new(nns_url, sender),
        handler_id,
        author,
    }
}

impl NnsCanisterClient {
    pub async fn execute_update<S: ToString>(
        &self,
        msg: S,
        arguments: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut ids_to_try = vec![self.handler_id];
        ids_to_try.extend(ic_nns_constants::ALL_NNS_CANISTER_IDS.iter().cloned());

        for canister_id in ids_to_try {
            let result = self
                .agent
                .execute_update(
                    &canister_id,
                    msg.to_string(),
                    arguments.clone(),
                    generate_nonce(),
                )
                .await;

            match result {
                Ok(result) => return Ok(result),
                Err(error_string) => {
                    if error_string.contains("has no update method") {
                        println!("Couldn't reach NNS canister at id: {:?}", canister_id);
                        continue;
                    }
                    return Err(error_string);
                }
            };
        }
        Err(format!(
            "Could not find method: {} in any NNS canister",
            msg.to_string()
        ))
    }
}

impl GovernanceCanisterClient {
    pub async fn submit_add_or_remove_node_provider_proposal(
        &self,
        payload: AddOrRemoveNodeProvider,
        url: String,
        title: String,
        summary: String,
    ) -> Result<ProposalId, String> {
        let serialized = Encode!(&ManageNeuron {
            neuron_id_or_subaccount: None,
            command: Some(Command::MakeProposal(Box::new(Proposal {
                title: Some(title),
                summary,
                url,
                action: Some(Action::AddOrRemoveNodeProvider(payload)),
            }))),
            id: Some((*self.0.proposal_author()).into()),
        })
        .map_err(|e| {
            format!(
                "Cannot candid-serialize the submit_add_or_remove_node_provider_proposal payload: {}",
                e
            )
        })?;
        let response = self
            .0
            .execute_update("manage_neuron", serialized)
            .await?
            .ok_or_else(|| "submit_proposal replied nothing.".to_string())?;

        decode_make_proposal_response(response)
    }

    pub async fn submit_external_proposal_candid<T: CandidType>(
        &self,
        payload: T,
        external_update_type: NnsFunction,
        url: String,
        title: &str,
        summary: &str,
    ) -> Result<ProposalId, String> {
        self.submit_external_proposal(
            &create_make_proposal_payload(
                create_external_update_proposal_candid(
                    &title.to_string(),
                    &summary.to_string(),
                    &url,
                    external_update_type,
                    payload,
                ),
                self.0.proposal_author(),
            ),
            title,
        )
        .await
    }

    async fn submit_external_proposal(
        &self,
        submit_proposal_command: &ManageNeuron,
        title: &str,
    ) -> Result<ProposalId, String> {
        let serialized = Encode!(submit_proposal_command).map_err(|e| {
            format!(
                "Cannot candid-serialize the payload of proposal:'{}'. Payload: {}",
                title, e
            )
        })?;
        let response = self
            .0
            .execute_update("manage_neuron", serialized)
            .await?
            .ok_or_else(|| "submit_proposal replied nothing.".to_string())?;

        decode_make_proposal_response(response)
    }

    pub async fn get_monthly_node_provider_rewards(
        &self,
    ) -> Result<RewardNodeProviders, GovernanceError> {
        let serialized = Encode!(&()).unwrap();

        let response = self
            .0
            .execute_update("get_monthly_node_provider_rewards", serialized)
            .await
            .unwrap()
            .ok_or_else(|| "get_monthly_node_provider_rewards replied nothing.".to_string())
            .unwrap();

        Decode!(&response, Result<RewardNodeProviders, GovernanceError>).unwrap()
    }
}

impl RootCanisterClient {
    pub async fn submit_root_proposal_to_upgrade_governance_canister(
        &self,
        cmd: SubmitRootProposalToUpgradeGovernanceCanisterCmd,
    ) -> Result<(), String> {
        let wasm_module = read_wasm_module(
            &cmd.wasm_module_path,
            &cmd.wasm_module_url,
            &cmd.wasm_module_sha256,
        )
        .await;
        let root_proposal = ChangeNnsCanisterProposalPayload::new(
            true,
            CanisterInstallMode::Upgrade,
            GOVERNANCE_CANISTER_ID,
        )
        .with_wasm(wasm_module);

        let serialized = Encode!(&CanisterIdRecord::from(GOVERNANCE_CANISTER_ID)).unwrap();
        let response = self
            .0
            .execute_update("canister_status", serialized)
            .await?
            .unwrap();

        let status = Decode!(&response, CanisterStatusResult).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from canister_status: {}",
                e
            )
        })?;

        let module_hash = status.module_hash.as_ref().unwrap().clone();

        println!(
            "Current governance canister wasm is: {:?}. \
                  Root proposal will only remain valid as long \
                  as the wasm and the membership of the nns subnet doesn't change.",
            hex::encode(&module_hash)
        );

        let serialized = Encode!(&module_hash, &root_proposal)
            .expect("Error candid-serializing root proposal to upgrade governance canister.");
        let response = self
            .0
            .execute_update(
                "submit_root_proposal_to_upgrade_governance_canister",
                serialized,
            )
            .await?
            .unwrap();

        Decode!(&response, Result<(), String>).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from \
                 submit_root_proposal_to_upgrade_governance_canister: {}",
                e
            )
        })?
    }

    pub async fn get_pending_root_proposals_to_upgrade_governance_canister(
        &self,
    ) -> Vec<GovernanceUpgradeRootProposal> {
        let serialized = Encode!(&()).unwrap();
        let response = self
            .0
            .execute_update(
                "get_pending_root_proposals_to_upgrade_governance_canister",
                serialized,
            )
            .await
            .unwrap()
            .unwrap();
        Decode!(&response, Vec<GovernanceUpgradeRootProposal>)
            .map_err(|e| {
                format!(
                    "Cannot candid-deserialize the response from \
                 get_pending_root_proposals_to_upgrade_governance_canister: {}",
                    e
                )
            })
            .unwrap()
    }

    pub async fn vote_on_root_proposal_to_upgrade_governance_canister(
        &self,
        cmd: VoteOnRootProposalToUpgradeGovernanceCanisterCmd,
    ) -> Result<(), String> {
        let proposer_pid = match cmd.test_user_proposer {
            None => cmd.proposer.expect("Must provide a proposer PrincipalId."),
            Some(1) => *TEST_USER1_PRINCIPAL,
            Some(2) => *TEST_USER2_PRINCIPAL,
            Some(3) => *TEST_USER3_PRINCIPAL,
            Some(4) => *TEST_USER4_PRINCIPAL,
            _ => {
                panic!("Invalid test proposer.");
            }
        };
        let sha256 = hex::decode(&cmd.expected_proposed_sha256_hex).unwrap();
        let serialized = Encode!(&proposer_pid, &sha256, &cmd.ballot).expect(
            "Error candid-serializing argument to \
                     vote_on_root_proposal_to_upgrade_governance_canister",
        );
        let response = self
            .0
            .execute_update(
                "vote_on_root_proposal_to_upgrade_governance_canister",
                serialized,
            )
            .await?
            .unwrap();

        Decode!(&response, Result<(), String>).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from \
                 vote_on_root_proposal_to_upgrade_governance_canister: {}",
                e
            )
        })?
    }
}

fn print_payload<T: Serialize + Debug, C: ProposalMetadata>(payload: &T, cmd: &C) {
    if cmd.is_verbose() {
        let serialized = serde_json::to_string(&payload).unwrap();
        println!("submit_proposal payload: \n{}", serialized);
    } else {
        println!("submit_proposal payload: \n{:#?}", payload);
    }
}
