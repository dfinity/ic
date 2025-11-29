//! Command-line utility to help submitting proposals to modify the IC's NNS.
use crate::helpers::*;
use anyhow::anyhow;
use async_trait::async_trait;
use candid::{CandidType, Decode, Encode, Principal};
use clap::{Args, CommandFactory, FromArgMatches, Parser, ValueEnum};
use create_subnet::ProposeToCreateSubnetCmd;
use cycles_minting_canister::{
    ChangeSubnetTypeAssignmentArgs, SetAuthorizedSubnetworkListArgs, SubnetListWithType,
    UpdateSubnetTypeArgs,
};
use helpers::{
    get_node_record_pb, get_proposer_and_sender, get_subnet_ids, get_subnet_record_with_details,
    parse_proposal_url, shortened_pid_string, shortened_subnet_string,
};
use ic_admin::get_routing_table;
use ic_btc_interface::{Fees, Flag, SetConfigRequest};
use ic_canister_client::{Agent, Sender};
use ic_canister_client_sender::SigKeys;
use ic_crypto_utils_threshold_sig_der::{
    parse_threshold_sig_key, parse_threshold_sig_key_from_der,
};
use ic_http_utils::file_downloader::{FileDownloader, check_file_hash};
use ic_interfaces_registry::{RegistryClient, RegistryDataProvider};
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR, TEST_USER2_PRINCIPAL,
    TEST_USER3_KEYPAIR, TEST_USER3_PRINCIPAL, TEST_USER4_KEYPAIR, TEST_USER4_PRINCIPAL,
};
use ic_nervous_system_humanize::{
    parse_duration, parse_percentage, parse_time_of_day, parse_tokens,
};
use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use ic_nervous_system_root::change_canister::{
    AddCanisterRequest, CanisterAction, ChangeCanisterRequest, StopOrStartCanisterRequest,
};
use ic_nns_common::types::{NeuronId, ProposalId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, CreateServiceNervousSystem, GovernanceError, InstallCodeRequest,
    MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest, NnsFunction,
    NodeProvider, ProposalActionRequest, RewardNodeProviders, StopOrStartCanister,
    UpdateCanisterSettings,
    add_or_remove_node_provider::Change,
    bitcoin::{BitcoinNetwork, BitcoinSetConfigProposal},
    create_service_nervous_system::{
        GovernanceParameters, InitialTokenDistribution, LedgerParameters, SwapParameters,
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            DeveloperDistribution, SwapDistribution, TreasuryDistribution,
            developer_distribution::NeuronDistribution,
        },
        swap_parameters,
    },
    install_code::CanisterInstallMode as GovernanceInstallMode,
    proposal_submission_helpers::{
        create_external_update_proposal_candid, create_make_proposal_payload,
        decode_make_proposal_response,
    },
    stop_or_start_canister::CanisterAction as GovernanceCanisterAction,
    subnet_rental::{RentalConditionId, SubnetRentalRequest},
    update_canister_settings::{
        CanisterSettings, Controllers, LogVisibility as GovernanceLogVisibility,
    },
};
use ic_nns_handler_root::root_proposals::{GovernanceUpgradeRootProposal, RootProposalBallot};
use ic_nns_init::make_hsm_sender;
use ic_nns_test_utils::governance::{HardResetNnsRootToVersionPayload, UpgradeRootProposal};
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord,
    crypto::v1::{PublicKey, X509PublicKeyCert},
    dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord},
    firewall::v1::{FirewallConfig, FirewallRule, FirewallRuleSet},
    node::v1::{NodeRecord, NodeRewardType},
    node_operator::v1::NodeOperatorRecord,
    node_rewards::v2::{NodeRewardRate, UpdateNodeRewardsTableProposalPayload},
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::CanisterMigrations,
    subnet::v1::{SubnetListRecord, SubnetRecord as SubnetRecordProto},
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::{
    chain_keys::ChainKeysRegistry, crypto::CryptoRegistry, deserialize_registry_value,
    ecdsa_keys::EcdsaKeysRegistry, hostos_version::HostosRegistry, subnet::SubnetRegistry,
};
use ic_registry_keys::{
    API_BOUNDARY_NODE_RECORD_KEY_PREFIX, FirewallRulesScope, NODE_OPERATOR_RECORD_KEY_PREFIX,
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY, ROOT_SUBNET_ID_KEY,
    get_node_operator_id_from_record_key, get_node_record_node_id, is_node_operator_record_key,
    is_node_record_key, make_api_boundary_node_record_key, make_blessed_replica_versions_key,
    make_canister_migrations_record_key, make_crypto_node_key,
    make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key,
    make_data_center_record_key, make_firewall_config_record_key, make_firewall_rules_record_key,
    make_node_operator_record_key, make_node_record_key, make_provisional_whitelist_record_key,
    make_replica_version_key, make_subnet_list_record_key, make_subnet_record_key,
    make_unassigned_nodes_config_record_key,
};
use ic_registry_local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_nns_data_provider_wrappers::{CertifiedNnsDataProvider, NnsDataProvider};
use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations as OtherCanisterMigrations};
use ic_registry_transport::Error;
use ic_sns_init::pb::v1::SnsInitPayload; // To validate CreateServiceNervousSystem.
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, InsertUpgradePathEntriesRequest, PrettySnsVersion, SnsCanisterType, SnsUpgrade,
    SnsVersion, SnsWasm, UpdateAllowedPrincipalsRequest, UpdateSnsSubnetListRequest,
};
use ic_types::{
    CanisterId, NodeId, PrincipalId, RegistryVersion, SubnetId,
    crypto::{KeyPurpose, threshold_sig::ThresholdSigPublicKey},
};
use indexmap::IndexMap;
use itertools::izip;
use maplit::hashmap;
use prost::Message;
use recover_subnet::ProposeToUpdateRecoveryCupCmd;
use registry_canister::mutations::{
    complete_canister_migration::CompleteCanisterMigrationPayload,
    do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
    do_add_node_operator::AddNodeOperatorPayload,
    do_change_subnet_membership::ChangeSubnetMembershipPayload,
    do_deploy_guestos_to_all_subnet_nodes::DeployGuestosToAllSubnetNodesPayload,
    do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
    do_remove_api_boundary_nodes::RemoveApiBoundaryNodesPayload,
    do_remove_node_operators::RemoveNodeOperatorsPayload,
    do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
    do_set_firewall_config::SetFirewallConfigPayload,
    do_set_subnet_operational_level::{
        NodeSshAccess, SetSubnetOperationalLevelPayload, operational_level,
    },
    do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload,
    do_update_api_boundary_nodes_version::DeployGuestosToSomeApiBoundaryNodes,
    do_update_elected_hostos_versions::ReviseElectedHostosVersionsPayload,
    do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
    do_update_nodes_hostos_version::DeployHostosToSomeNodes,
    do_update_ssh_readonly_access_for_all_unassigned_nodes::UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
    firewall::{
        AddFirewallRulesPayload, RemoveFirewallRulesPayload, UpdateFirewallRulesPayload,
        add_firewall_rules_compute_entries, compute_firewall_ruleset_hash,
        remove_firewall_rules_compute_entries, update_firewall_rules_compute_entries,
    },
    node_management::do_remove_nodes::RemoveNodesPayload,
    prepare_canister_migration::PrepareCanisterMigrationPayload,
    reroute_canister_ranges::RerouteCanisterRangesPayload,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
    fmt::Debug,
    fs::{File, metadata, read_to_string},
    io::Read,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    process::exit,
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use types::{
    LogVisibility, NodeDetails, ProposalAction, ProposalMetadata, ProposalPayload,
    ProvisionalWhitelistRecord, Registry, RegistryRecord, RegistryValue, SubnetDescriptor,
    SubnetRecord,
};
use update_subnet::ProposeToUpdateSubnetCmd;
use url::Url;

#[macro_use]
extern crate ic_admin_derive;

extern crate chrono;

mod create_subnet;
mod helpers;
mod recover_subnet;
mod types;
mod update_subnet;

#[cfg(test)]
mod main_tests;

const IC_ROOT_PUBLIC_KEY_BASE64: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;
const IC_DOMAINS: &[&str; 3] = &["ic0.app", "icp0.io", "icp-api.io"];

/// Common command-line options for `ic-admin`.
#[derive(Parser)]
struct Opts {
    #[clap(short = 'r', long, aliases = &["registry-url", "nns-url"], value_delimiter = ',', global = true, default_value = "https://ic0.app"
    )]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_urls: Vec<Url>,

    #[clap(short = 's', long, global = true)]
    /// The pem file containing a secret key to use while authenticating with
    /// the NNS.
    secret_key_pem: Option<PathBuf>,

    #[clap(subcommand)]
    subcmd: SubCommand,

    /// Use an HSM to sign calls.
    #[clap(long, global = true, requires_all = &["hsm_slot", "hsm_key_id", "hsm_pin"])]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        help = "Required if use-hsm is set.",
        global = true,
        requires = "use_hsm"
    )]
    hsm_slot: Option<String>,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        help = "Only required if use-hsm is set. Ignored otherwise.",
        global = true,
        requires = "use_hsm",
        visible_alias = "key-id"
    )]
    hsm_key_id: Option<String>,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        help = "Only required if use-hsm is set. Ignored otherwise.",
        global = true,
        requires = "use_hsm",
        visible_alias = "pin"
    )]
    hsm_pin: Option<String>,

    /// Verify NNS responses against NNS public key.
    #[clap(
        long = "verify-nns-responses",
        help = "Verify responses against NNS public key. If --nns-public-key-pem-file is not specified the mainnet NNS public key is used. Requests to ic0.app are always verified with the mainnet NNS public key. "
    )]
    verify_nns_responses: bool,

    /// Overwrite public key used to verify nns responses. By default the mainnet NNS public key is used.
    #[clap(
        long = "nns-public-key-pem-file",
        help = "PEM file to overwrite the mainnet NNS public key. Requires --verify-nns-responses.",
        requires = "verify_nns_responses"
    )]
    nns_public_key_pem_file: Option<PathBuf>,

    /// Return the output in JSON format.
    #[clap(long = "json", global = true)]
    json: bool,

    /// silence notices, can be useful if ic-admin is executed from automation
    #[clap(long = "silence-notices", global = true)]
    silence_notices: bool,
}

////////////////////////////////////////////////////////////////////////////////
// NOTE: Please keep the sub-commands in alphabetical order.
////////////////////////////////////////////////////////////////////////////////
/// List of sub-commands accepted by `ic-admin`.
#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand)]
enum SubCommand {
    /// Convert the integer node ID into Principal Id
    ConvertNumericNodeIdToPrincipalId(ConvertNumericNodeIdtoPrincipalIdCmd),

    /// Sub-command to fetch an API Boundary Node record from the registry.
    /// Retrieve an API Boundary Node record
    GetApiBoundaryNode(GetApiBoundaryNodeCmd),

    /// Retrieve all API Boundary Node Ids
    GetApiBoundaryNodes,

    /// Get the latest canister migrations.
    GetCanisterMigrations,

    /// Get the Master public key ids and their signing subnets
    GetChainKeySigningSubnets,

    /// Get a DataCenterRecord
    GetDataCenter(GetDataCenterCmd),

    /// Get the ECDSA key ids and their signing subnets
    GetEcdsaSigningSubnets,

    /// Get the current list of elected GuestOS/Replica versions.
    #[clap(visible_alias = "get-blessed-replica-versions")]
    GetElectedGuestosVersions,

    /// Get the current list of elected HostOS versions
    GetElectedHostosVersions,

    /// Get the current firewall config
    GetFirewallConfig,

    /// Get the existing firewall rules for a given scope
    GetFirewallRules(GetFirewallRulesCmd),

    /// Get the existing firewall rules that apply to a given node
    GetFirewallRulesForNode(GetFirewallRulesForNodeCmd),

    /// Compute the SHA-256 hash of a given list of firewall rules
    GetFirewallRulesetHash(GetFirewallRulesetHashCmd),

    /// Get the monthly Node Provider rewards
    GetMonthlyNodeProviderRewards,

    /// Get the last version of a node from the registry.
    GetNode(GetNodeCmd),

    /// Get the nodes added since a given version (exclusive).
    GetNodeListSince(GetNodeListSinceCmd),

    /// Get a node operator's record
    GetNodeOperator(GetNodeOperatorCmd),

    /// Get the list of all node operators
    GetNodeOperatorList,

    /// Get the node rewards table
    GetNodeRewardsTable,

    // Get the pending proposals to upgrade the governance canister.
    GetPendingRootProposalsToUpgradeGovernanceCanister,

    /// Get whitelist of principals that can access the provisional_* APIs in
    /// the management canister.
    GetProvisionalWhitelist,

    /// Get the last version of a node's public key from the registry.
    GetPublicKey(GetPublicKeyCmd),

    // Get latest registry version number
    GetRegistryVersion,

    /// Get info about a GuestOS version
    #[clap(visible_alias = "get-guestos-version")]
    GetGuestOSVersion(GetGuestOsVersionCmd),

    /// Get the latest routing table.
    GetRoutingTable,

    /// Get the last version of a subnet from the registry.
    GetSubnet(GetSubnetCmd),

    /// Get the last version of the subnet list from the registry.
    GetSubnetList,

    /// Get the public of the subnet.
    GetSubnetPublicKey(SubnetPublicKeyCmd),

    /// Get the last version of a node's TLS certificate key from the registry.
    GetTlsCertificate(GetTlsCertificateCmd),

    /// Get the topology of the system as described in the registry, in JSON
    /// format.
    GetTopology,

    /// Get the SSH key access lists for unassigned nodes
    GetUnassignedNodes,

    /// Propose to add an API Boundary Node
    ProposeToAddApiBoundaryNodes(ProposeToAddApiBoundaryNodesCmd),

    /// Propose to add firewall rules
    ProposeToAddFirewallRules(ProposeToAddFirewallRulesCmd),

    /// Submits a proposal to add a new canister on NNS.
    ProposeToAddNnsCanister(ProposeToAddNnsCanisterCmd),

    /// Propose to add a new node operator to the registry.
    ProposeToAddNodeOperator(ProposeToAddNodeOperatorCmd),

    /// Submit a proposal to add data centers and/or remove data centers from the Registry
    ProposeToAddOrRemoveDataCenters(ProposeToAddOrRemoveDataCentersCmd),

    /// Propose to add or remove a node provider from the governance canister
    ProposeToAddOrRemoveNodeProvider(ProposeToAddOrRemoveNodeProviderCmd),

    /// Submits a proposal to add an SNS wasm (e.g. Governance, Ledger, etc) to the SNS-WASM NNS
    /// canister.
    ProposeToAddWasmToSnsWasm(ProposeToAddWasmToSnsWasmCmd),

    /// Sets three things:
    ///
    ///     1. In SubnetRecord:
    ///         1. is_halted = false
    ///         2. ssh_readonly_access = vec![]
    ///     2. In NodeRecord:
    ///         1. ssh_node_state_write_access = vec![]
    ///
    /// This is done at the end of subnet recovery. See also
    /// propose-to-take-subnet-offline-for-repairs. This generally rolls back
    /// the changes made by that command.
    ProposeToBringSubnetBackOnlineAfterRepairs(ProposeToBringSubnetBackOnlineAfterRepairsCmd),

    /// Submits a proposal to change an existing canister on NNS.
    ProposeToChangeNnsCanister(ProposeToChangeNnsCanisterCmd),

    /// Submits a proposal to change node membership in a subnet.
    /// Consider using instead the DRE tool to submit this type of proposals.
    /// https://github.com/dfinity/dre
    ProposeToChangeSubnetMembership(ProposeToChangeSubnetMembershipCmd),

    /// Submits a proposal to add or remove subnets from a subnet type in the
    /// cycles minting canister.
    ProposeToChangeSubnetTypeAssignment(ProposeToChangeSubnetTypeAssignmentCmd),

    /// Update the whitelist of principals that can access the provisional_*
    /// APIs in the management canister.
    ProposeToClearProvisionalWhitelist(ProposeToClearProvisionalWhitelistCmd),

    /// Propose to remove entries from `canister_migrations`. Step 3 of canister migration.
    ProposeToCompleteCanisterMigration(ProposeToCompleteCanisterMigrationCmd),

    /// Submits a proposal to create a new service nervous system (usually referred to as SNS).
    ProposeToCreateServiceNervousSystem(ProposeToCreateServiceNervousSystemCmd),

    /// Submits a proposal to create a new subnet.
    ProposeToCreateSubnet(ProposeToCreateSubnetCmd),

    /// Propose to deploy a priorly elected GuestOS version to all subnet nodes.
    ProposeToDeployGuestosToAllSubnetNodes(ProposeToDeployGuestosToAllSubnetNodesCmd),

    /// Propose to deploy the GuestOS version to all unassigned nodes.
    ProposeToDeployGuestosToAllUnassignedNodes(ProposeToDeployGuestosToAllUnassignedNodesCmd),

    /// Propose to upgrade the GuestOS version of a set of API Boundary Nodes.
    ProposeToDeployGuestosToSomeApiBoundaryNodes(ProposeToDeployGuestosToSomeApiBoundaryNodesCmd),

    /// Propose to deploy a HostOS version to some nodes.
    ProposeToDeployHostosToSomeNodes(ProposeToDeployHostosToSomeNodesCmd),

    /// Submits a proposal to uninstall and install root to a particular version
    ProposeToHardResetNnsRootToVersion(ProposeToHardResetNnsRootToVersionCmd),

    // Submits a proposal to add custom upgrade path entries
    ProposeToInsertSnsWasmUpgradePathEntries(ProposeToInsertSnsWasmUpgradePathEntriesCmd),

    /// Propose additions or updates to `canister_migrations`. Step 1 of canister migration.
    ProposeToPrepareCanisterMigration(ProposeToPrepareCanisterMigrationCmd),

    /// Propose to remove a set of API Boundary Nodes
    ProposeToRemoveApiBoundaryNodes(ProposeToRemoveApiBoundaryNodesCmd),

    /// Propose to remove firewall rules
    ProposeToRemoveFirewallRules(ProposeToRemoveFirewallRulesCmd),

    /// Propose to remove a list of node operators from the Registry
    ProposeToRemoveNodeOperators(ProposeToRemoveNodeOperatorsCmd),

    /// Propose to remove a node from the registry via proposal.
    ProposeToRemoveNodes(ProposeToRemoveNodesCmd),

    /// Submits a proposal to express the interest in renting a subnet.
    ProposeToRentSubnet(ProposeToRentSubnetCmd),

    /// Propose to fulfill a subnet rental request
    ProposeToFulfillSubnetRentalRequest(ProposeToFulfillSubnetRentalRequestCmd),

    /// Propose to modify the routing table. Step 2 of canister migration.
    ProposeToRerouteCanisterRanges(ProposeToRerouteCanisterRangesCmd),

    /// Submits a proposal to change the set of currently elected GuestOS versions, by electing
    /// a new version and/or unelecting multiple priorly elected versions.
    ProposeToReviseElectedGuestosVersions(ProposeToReviseElectedGuestsOsVersionsCmd),

    /// Submits a proposal to change the set of currently elected HostOS versions, by electing
    /// a new version and/or unelecting multiple versions.
    ProposeToReviseElectedHostosVersions(ProposeToReviseElectedHostosVersionsCmd),

    /// Submits a proposal to set authorized subnetworks that the cycles minting
    /// canister can use.
    ProposeToSetAuthorizedSubnetworks(ProposeToSetAuthorizedSubnetworksCmd),

    /// Propose to set the Bitcoin configuration
    ProposeToSetBitcoinConfig(ProposeToSetBitcoinConfig),

    /// Propose to set the firewall config
    ProposeToSetFirewallConfig(ProposeToSetFirewallConfigCmd),

    /// Propose to start a canister managed by the governance.
    ProposeToStartCanister(StartCanisterCmd),

    /// Propose to stop a canister managed by the governance.
    ProposeToStopCanister(StopCanisterCmd),

    /// Sets three things:
    ///
    ///     1. is_halted = true
    ///     2. ssh_readonly_access
    ///     3. ssh_node_state_write_access
    ///
    /// This is the first step of subnet recovery. Previously the first step was
    /// done using propose-to-update-subnet. However, that does not support
    /// changing ssn_node_state_write_access, which is needed when a subnet has
    /// SEV enabled everywhere (or the subnet has no DFINITY node).
    ///
    /// At the end of subnet recovery, run propose-to-bring-subnet-back-online.
    ProposeToTakeSubnetOfflineForRepairs(ProposeToTakeSubnetOfflineForRepairsCmd),

    /// Submits a proposal to uninstall code of a canister.
    ProposeToUninstallCode(ProposeToUninstallCodeCmd),

    /// Propose to update the settings of a canister.
    ProposeToUpdateCanisterSettings(ProposeToUpdateCanisterSettingsCmd),

    /// Propose to update firewall rules
    ProposeToUpdateFirewallRules(ProposeToUpdateFirewallRulesCmd),

    /// Update the Node Operator's specified parameters
    ProposeToUpdateNodeOperatorConfig(ProposeToUpdateNodeOperatorConfigCmd),

    /// Submit a proposal to update the node rewards table
    ProposeToUpdateNodeRewardsTable(ProposeToUpdateNodeRewardsTableCmd),

    /// Submits a proposal to update a subnet's recovery CUP
    ProposeToUpdateRecoveryCup(ProposeToUpdateRecoveryCupCmd),

    /// Propose to update the list of Principals that are allowed to deploy SNS instances
    ProposeToUpdateSnsDeployWhitelist(ProposeToUpdateSnsDeployWhitelistCmd),

    /// Propose to update the list of SNS Subnet IDs that SNS-WASM deploys SNS instances to
    ProposeToUpdateSnsSubnetIdsInSnsWasm(ProposeToUpdateSnsSubnetIdsInSnsWasmCmd),

    /// Propose to update the SSH keys that have read-only access to all unassigned nodes.
    ProposeToUpdateSshReadonlyAccessForAllUnassignedNodes(
        ProposeToUpdateSshReadonlyAccessForAllUnassignedNodesCmd,
    ),

    /// Submits a proposal to update an existing subnet's configuration.
    ProposeToUpdateSubnet(ProposeToUpdateSubnetCmd),

    /// Submits a proposal to update the subnet types that are available in the
    /// cycles minting canister.
    ProposeToUpdateSubnetType(ProposeToUpdateSubnetTypeCmd),

    /// Propose Xdr/Icp conversion rate.
    ProposeToUpdateXdrIcpConversionRate(ProposeXdrIcpConversionRateCmd),

    // Submit a root proposal to the root canister to upgrade the governance canister.
    SubmitRootProposalToUpgradeGovernanceCanister(SubmitRootProposalToUpgradeGovernanceCanisterCmd),

    /// Swap nodes in subnet directly, without governance.
    SwapNodeInSubnetDirectly(SwapNodeInSubnetDirectlyCmd),

    /// Update local registry store by pulling from remote URL
    UpdateRegistryLocalStore(UpdateRegistryLocalStoreCmd),

    // Vote on a pending root proposal to upgrade the governance canister.
    VoteOnRootProposalToUpgradeGovernanceCanister(VoteOnRootProposalToUpgradeGovernanceCanisterCmd),
}

/// Indicates whether a value should be added or removed.
#[derive(Clone, ValueEnum)]
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
            &_ => Err(format!("Unknown add or remove value: {string:?}")),
        }
    }
}

/// Sub-command to fetch the public key of an IC node from the registry.
#[derive(Parser)]
struct GetPublicKeyCmd {
    /// The node id to which the key belongs.
    node_id: PrincipalId,
    /// The purpose of the key. See ic::types::crypto::KeyPurpose.
    key_purpose: KeyPurpose,
}

/// Sub-command to fetch the tls certificate of an IC node from the registry.
#[derive(Parser)]
struct GetTlsCertificateCmd {
    /// The node id to which the TLS certificate belongs.
    node_id: PrincipalId,
}

/// Trait to extract the title for proposal type.
pub trait ProposalTitle {
    fn title(&self) -> String;
}

/// Sub-command to submit a proposal to replace in a subnet.
/// Consider using instead the DRE tool to submit this type of proposals.
/// https://github.com/dfinity/dre
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToChangeSubnetMembershipCmd {
    #[clap(long, required = true, alias = "subnet-id")]
    /// The subnet to modify
    subnet: SubnetDescriptor,

    #[clap(long, num_args(1..))]
    /// The node IDs of the nodes that should be added to the subnet.
    pub node_ids_add: Vec<PrincipalId>,

    #[clap(long, num_args(1..))]
    /// The node IDs of the nodes that should be removed from the subnet.
    pub node_ids_remove: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToChangeSubnetMembershipCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Replace nodes {} with {} in subnet {}",
                shortened_pids_string(&self.node_ids_remove),
                shortened_pids_string(&self.node_ids_add),
                shortened_subnet_string(&self.subnet)
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<ChangeSubnetMembershipPayload> for ProposeToChangeSubnetMembershipCmd {
    async fn payload(&self, agent: &Agent) -> ChangeSubnetMembershipPayload {
        let registry_canister = RegistryCanister::new_with_agent(agent.clone());
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        let node_ids_add = self
            .node_ids_add
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();
        let node_ids_remove = self
            .node_ids_remove
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();
        ChangeSubnetMembershipPayload {
            subnet_id: subnet_id.get(),
            node_ids_add,
            node_ids_remove,
        }
    }
}

/// Sub-command to fetch a `NodeRecord` from the registry.
#[derive(Parser)]
struct GetNodeCmd {
    /// The id of the node to get.
    node_id: PrincipalId,
}

/// Sub-command to convert a numeric `NodeId` to a `PrincipalId`.
#[derive(Parser)]
struct ConvertNumericNodeIdtoPrincipalIdCmd {
    /// The integer Id of the node to convert to actual node id.
    node_id: u64,
}

/// Sub-command to fetch a `SubnetRecord` from the registry.
#[derive(Parser)]
struct GetSubnetCmd {
    /// The subnet to get.
    subnet: SubnetDescriptor,
}

/// Sub-command to fetch the most recent `NodeRecord`s since a specific version,
/// from the registry.
#[derive(Parser)]
struct GetNodeListSinceCmd {
    /// Returns the most recent node records added since this given version,
    /// exclusive.
    version: u64,
}

/// Sub-command to fetch a GuestOS version from the registry.
#[derive(Parser)]
#[clap(visible_alias = "get-replica-version")]
struct GetGuestOsVersionCmd {
    /// The GuestOS version to query
    #[clap(visible_alias = "replica-version-id")]
    guestos_version_id: String,
}

/// Sub-command to submit a proposal to upgrade the replicas running a specific
/// subnet to the given (blessed) version.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToDeployGuestosToAllSubnetNodesCmd {
    /// The subnet to update.
    subnet: SubnetDescriptor,
    /// The new GuestOS version to use.
    #[clap(visible_alias = "replica-version-id")]
    guestos_version_id: String,
}

/// Sub-command to submit a proposal to remove node operators.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRemoveNodeOperatorsCmd {
    /// List of principal ids of node operators to remove
    #[clap(num_args(1..))]
    node_operators_to_remove: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToRemoveNodeOperatorsCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Remove node operators with principal ids: {:?}",
                self.node_operators_to_remove
                    .iter()
                    .map(shortened_pid_string)
                    .collect::<Vec<String>>()
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<RemoveNodeOperatorsPayload> for ProposeToRemoveNodeOperatorsCmd {
    async fn payload(&self, _: &Agent) -> RemoveNodeOperatorsPayload {
        RemoveNodeOperatorsPayload::new(self.node_operators_to_remove.clone())
    }
}

impl ProposalTitle for ProposeToDeployGuestosToAllSubnetNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Upgrade subnet: {} to GuestOS version: {}",
                shortened_subnet_string(&self.subnet),
                self.guestos_version_id
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<DeployGuestosToAllSubnetNodesPayload>
    for ProposeToDeployGuestosToAllSubnetNodesCmd
{
    async fn payload(&self, agent: &Agent) -> DeployGuestosToAllSubnetNodesPayload {
        let registry_canister = RegistryCanister::new_with_agent(agent.clone());
        let subnet_id = self.subnet.get_id(&registry_canister).await;
        DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_id.get(),
            replica_version_id: self.guestos_version_id.clone(),
        }
    }
}

/// Deprecated; please use `ProposeToDeployGuestosToAllUnassignedNodes` or
/// `ProposeToUpdateSshReadonlyAccessForAllUnassignedNodes` instead.
#[derive_common_proposal_fields]
#[derive(Clone, Parser, ProposalMetadata)]
struct ProposeToUpdateUnassignedNodesConfigCmd {}

/// Sub-command to submit a proposal to deploy a specific GuestOS version to the set of all
/// unassigned nodes.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToDeployGuestosToAllUnassignedNodesCmd {
    /// The ID of the GuestOS version that all the unassigned nodes should run.
    #[clap(long, visible_alias = "replica-version-id")]
    pub guestos_version_id: String,
}

impl ProposalTitle for ProposeToDeployGuestosToAllUnassignedNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Deploy a guestos version to all unassigned nodes".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<DeployGuestosToAllUnassignedNodesPayload>
    for ProposeToDeployGuestosToAllUnassignedNodesCmd
{
    async fn payload(&self, _: &Agent) -> DeployGuestosToAllUnassignedNodesPayload {
        DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: self.guestos_version_id.clone(),
        }
    }
}

/// Sub-command to submit a proposal to take a subnet offline for repairs.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToTakeSubnetOfflineForRepairsCmd {
    /// Which subnet is being taken offline.
    #[clap(long)]
    pub subnet: PrincipalId,

    /// List of public keys who (will) have ssh "readonly" access to VMs of the
    /// subnet. Note that this overwrites the entire list. Therefore, be aware
    /// of who is currently in the list to make sure you are not clobbering
    /// anything you don't want to clobber.
    ///
    /// This usually isn't a problem, because the list is typically empty when
    /// this proposal is used as part of subnet recovery.
    #[clap(long, num_args(1..))]
    pub ssh_readonly_access: Vec<String>,

    /// Similar to the --ssh-readonly-access flag, but there are some important
    /// differences:
    ///
    ///     1. This gives different privileges to the VM(s). As the name
    ///        suggests, this allows private key holders to (read and) write
    ///        files to where node state (which primarily consists of the memory
    ///        contents of canisters in the subnet) is kept in the VM.
    ///
    ///     2. This only targets ONE node VM at a time. Therefore, you have to
    ///        ALSO specify which node you want to affect. Therefore, the format
    ///        here is similar but different: "${NODE_ID}":"${SSH_PUBLIC_KEY}".
    ///        That is, you must prefix with node ID and a semicolon to
    ///        separate.
    ///
    /// Note that this clobbers the entire ssh_node_state_write_access field of
    /// whatever node is specified, similar to --ssh-readonly-access. Therefore,
    /// similarly be aware of what the field holds prior to this proposal to
    /// make sure that you are not clobbering anything that you do not want to
    /// clobber. However, in practice, it would probably be empty to begin with,
    /// so most likely, this won't be an issue.
    #[clap(long, value_parser, num_args(1..))]
    pub ssh_node_state_write_access: Vec<NodeSshAccessFlagValue>,
}

impl ProposalTitle for ProposeToTakeSubnetOfflineForRepairsCmd {
    fn title(&self) -> String {
        let subnet_id = self.subnet.to_string();
        let subnet_id = subnet_id.split('-').next().unwrap();
        format!("Take Subnet {subnet_id} Offline for Repairs")
    }
}

#[async_trait]
impl ProposalPayload<SetSubnetOperationalLevelPayload> for ProposeToTakeSubnetOfflineForRepairsCmd {
    async fn payload(&self, _agent: &Agent) -> SetSubnetOperationalLevelPayload {
        let ssh_node_state_write_access = self
            .ssh_node_state_write_access
            .clone()
            .into_iter()
            .map(NodeSshAccess::from)
            .collect();

        SetSubnetOperationalLevelPayload {
            subnet_id: Some(SubnetId::from(self.subnet)),
            operational_level: Some(operational_level::DOWN_FOR_REPAIRS),
            ssh_readonly_access: Some(self.ssh_readonly_access.clone()),
            ssh_node_state_write_access: Some(ssh_node_state_write_access),
        }
    }
}

#[derive(Clone)]
struct NodeSshAccessFlagValue {
    pub node_id: NodeId,
    pub public_keys: Vec<String>,
}

impl FromStr for NodeSshAccessFlagValue {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        // Split s into two pieces using ':'.
        let mut parts = s.splitn(2, ':');
        let node_id = parts.next().ok_or("Missing node ID.")?;
        let public_keys = parts
            .next()
            .ok_or("Missing semicolon separating node ID and SSH public key.")?
            .to_string();

        // Parse node_id.
        let node_id = PrincipalId::from_str(node_id).map_err(|err| format!("{err}"))?;
        let node_id = NodeId::from(node_id);

        // Parse public_keys, by simply splitting on ','.<
        let public_keys = public_keys
            .split(',')
            .map(|public_key| public_key.to_string())
            .collect();

        Ok(Self {
            node_id,
            public_keys,
        })
    }
}

impl From<NodeSshAccessFlagValue> for NodeSshAccess {
    fn from(src: NodeSshAccessFlagValue) -> Self {
        let NodeSshAccessFlagValue {
            node_id,
            public_keys,
        } = src;

        Self {
            node_id: Some(node_id),
            public_keys: Some(public_keys),
        }
    }
}

/// Sub-command to submit a proposal to bring a subnet back online after repairs.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToBringSubnetBackOnlineAfterRepairsCmd {
    /// Which subnet is being brought back online.
    #[clap(long)]
    pub subnet: PrincipalId,
}

impl ProposalTitle for ProposeToBringSubnetBackOnlineAfterRepairsCmd {
    fn title(&self) -> String {
        let subnet_id = self.subnet.to_string();
        let subnet_id = subnet_id.split('-').next().unwrap();
        format!("Bring Subnet {subnet_id} Back Online After Repairs")
    }
}

#[async_trait]
impl ProposalPayload<SetSubnetOperationalLevelPayload>
    for ProposeToBringSubnetBackOnlineAfterRepairsCmd
{
    async fn payload(&self, agent: &Agent) -> SetSubnetOperationalLevelPayload {
        let registry_canister = RegistryCanister::new_with_agent(agent.clone());

        let subnet_id = SubnetId::from(self.subnet);
        let subnet_record = get_subnet_record(&registry_canister, subnet_id).await;

        // Clear the ssh_node_state_write_access field in NodeRecords that
        // belong to the subnet (but only on nodes where it is currently
        // actually set).
        let mut ssh_node_state_write_access = vec![];
        for node_id in subnet_record.membership {
            let node_id = NodeId::from(PrincipalId::from_str(&node_id).unwrap());
            let node_record = get_node_record_pb(&registry_canister, node_id).await;
            if !node_record.ssh_node_state_write_access.is_empty() {
                // The current NodeRecord has a non-empty
                // ssh_node_state_write_access, so clear that field for the
                // current node in the set_subnet_operational_level request that
                // we are currently building.
                ssh_node_state_write_access.push(NodeSshAccess {
                    node_id: Some(node_id),
                    public_keys: Some(vec![]),
                });
            }
        }

        SetSubnetOperationalLevelPayload {
            subnet_id: Some(subnet_id),
            operational_level: Some(operational_level::NORMAL),
            ssh_readonly_access: Some(vec![]),
            ssh_node_state_write_access: Some(ssh_node_state_write_access),
        }
    }
}

/// Sub-command to submit a proposal to change the public keys with "readonly"
/// access privileges. There is no easy way to set a privilege to an empty list.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateSshReadonlyAccessForAllUnassignedNodesCmd {
    /// The list of public keys whose owners have "readonly" SSH access to all
    /// unassigned nodes.
    #[clap(long, num_args(1..))]
    pub ssh_readonly_access: Vec<String>,
}

impl ProposalTitle for ProposeToUpdateSshReadonlyAccessForAllUnassignedNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => {
                "Update public keys with SSH readonly access for all unassigned nodes".to_string()
            }
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateSshReadOnlyAccessForAllUnassignedNodesPayload>
    for ProposeToUpdateSshReadonlyAccessForAllUnassignedNodesCmd
{
    async fn payload(&self, _: &Agent) -> UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
        UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
            ssh_readonly_keys: self
                .ssh_readonly_access
                .iter()
                .filter_map(|k| match k.trim() {
                    "" => None,
                    k => Some(k.to_string()),
                })
                .collect::<Vec<_>>(),
        }
    }
}

/// Sub-command to submit a proposal for Xdr/Icp conversion rate.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeXdrIcpConversionRateCmd {
    #[clap(long)]
    pub xdr_permyriad_per_icp: u64,
}

impl ProposalTitle for ProposeXdrIcpConversionRateCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Updating Xdr/Icp conversion rate to {}",
                self.xdr_permyriad_per_icp
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateIcpXdrConversionRatePayload> for ProposeXdrIcpConversionRateCmd {
    async fn payload(&self, _: &Agent) -> UpdateIcpXdrConversionRatePayload {
        UpdateIcpXdrConversionRatePayload {
            data_source: "IC admin".to_string(),
            timestamp_seconds: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            xdr_permyriad_per_icp: self.xdr_permyriad_per_icp,
            reason: None,
        }
    }
}

/// Sub-command to submit a proposal to start a canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct StartCanisterCmd {
    #[clap(long)]
    pub canister_id: CanisterId,
}

impl ProposalTitle for StartCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Start canister {}", self.canister_id),
        }
    }
}

#[async_trait]
impl ProposalPayload<StopOrStartCanisterRequest> for StartCanisterCmd {
    async fn payload(&self, _: &Agent) -> StopOrStartCanisterRequest {
        StopOrStartCanisterRequest {
            canister_id: self.canister_id,
            action: CanisterAction::Start,
        }
    }
}

#[async_trait]
impl ProposalAction for StartCanisterCmd {
    async fn action(&self) -> ProposalActionRequest {
        let canister_id = Some(self.canister_id.get());
        let action = Some(GovernanceCanisterAction::Start as i32);
        let start_canister = StopOrStartCanister {
            canister_id,
            action,
        };
        ProposalActionRequest::StopOrStartCanister(start_canister)
    }
}

/// Sub-command to submit a proposal to start a canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct StopCanisterCmd {
    #[clap(long)]
    pub canister_id: CanisterId,
}

impl ProposalTitle for StopCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Stop canister {}", self.canister_id),
        }
    }
}

#[async_trait]
impl ProposalPayload<StopOrStartCanisterRequest> for StopCanisterCmd {
    async fn payload(&self, _: &Agent) -> StopOrStartCanisterRequest {
        StopOrStartCanisterRequest {
            canister_id: self.canister_id,
            action: CanisterAction::Stop,
        }
    }
}

#[async_trait]
impl ProposalAction for StopCanisterCmd {
    async fn action(&self) -> ProposalActionRequest {
        let canister_id = Some(self.canister_id.get());
        let action = Some(GovernanceCanisterAction::Stop as i32);
        let stop_canister = StopOrStartCanister {
            canister_id,
            action,
        };
        ProposalActionRequest::StopOrStartCanister(stop_canister)
    }
}

/// Sub-command to submit a proposal to update elected GuestOS versions.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToReviseElectedGuestsOsVersionsCmd {
    #[clap(long, visible_alias = "replica-version-to-elect")]
    /// The GuestOS version ID to elect.
    pub guestos_version_to_elect: Option<String>,

    #[clap(long)]
    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_urls'.
    pub release_package_sha256_hex: Option<String>,

    #[clap(long, num_args(1..))]
    /// The URLs against which an HTTP GET request will return a release
    /// package that corresponds to this version.
    pub release_package_urls: Vec<String>,

    #[clap(long, num_args(1..), visible_alias = "replica-versions-to-unelect")]
    /// The GuestOS version ids to remove.
    pub guestos_versions_to_unelect: Vec<String>,

    // TODO: populate this arg in clients and make it required
    #[clap(long)]
    /// Path to the json containing the guest launch measurements
    /// (schema: registry.replica_version.v1.GuestLaunchMeasurements)
    pub guest_launch_measurements_path: Option<PathBuf>,
}

impl ProposeToReviseElectedGuestsOsVersionsCmd {
    /// Reads and returns the SEV-SNP measurements from the input file.
    fn read_guest_launch_measurements(&self) -> Option<GuestLaunchMeasurements> {
        self.guest_launch_measurements_path.as_ref().map(|path| {
            let guest_launch_measurements_json =
                std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path.display()));
            serde_json::from_slice::<GuestLaunchMeasurements>(&guest_launch_measurements_json)
                .expect("Could not decode GuestLaunchMeasurements")
        })
    }
}

impl ProposalTitle for ProposeToReviseElectedGuestsOsVersionsCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match self.guestos_version_to_elect.as_ref() {
                Some(v) => format!("Elect new GuestOS binary revision (commit {v})"),
                None => "Retire IC GuestOS version(s)".to_string(),
            },
        }
    }
}

#[async_trait]
impl ProposalPayload<ReviseElectedGuestosVersionsPayload>
    for ProposeToReviseElectedGuestsOsVersionsCmd
{
    async fn payload(&self, _: &Agent) -> ReviseElectedGuestosVersionsPayload {
        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: self.guestos_version_to_elect.clone(),
            release_package_sha256_hex: self.release_package_sha256_hex.clone(),
            release_package_urls: self.release_package_urls.clone(),
            guest_launch_measurements: self.read_guest_launch_measurements(),
            replica_versions_to_unelect: self.guestos_versions_to_unelect.clone(),
        };
        payload.validate().expect("Failed to validate payload");
        payload
    }
}

/// Sub-command to submit a proposal to upgrade an NNS canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
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

    /// The sha256 of the arg binary file.
    #[clap(long)]
    arg_sha256: Option<String>,
}

#[async_trait]
impl ProposalPayload<UpgradeRootProposal> for ProposeToChangeNnsCanisterCmd {
    async fn payload(&self, _: &Agent) -> UpgradeRootProposal {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let module_arg = read_arg(&self.arg, &self.arg_sha256);
        let stop_upgrade_start = !self.skip_stopping_before_installing;
        UpgradeRootProposal {
            wasm_module,
            module_arg,
            stop_upgrade_start,
        }
    }
}

impl ProposalTitle for ProposeToChangeNnsCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Upgrade NNS Canister: {} to wasm with hash: {}",
                self.canister_id, &self.wasm_module_sha256
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<ChangeCanisterRequest> for ProposeToChangeNnsCanisterCmd {
    async fn payload(&self, _: &Agent) -> ChangeCanisterRequest {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let arg = read_arg(&self.arg, &self.arg_sha256);
        ChangeCanisterRequest {
            stop_before_installing: !self.skip_stopping_before_installing,
            mode: self.mode,
            canister_id: self.canister_id,
            wasm_module,
            arg,
            chunked_canister_wasm: None,
        }
    }
}

#[async_trait]
impl ProposalAction for ProposeToChangeNnsCanisterCmd {
    async fn action(&self) -> ProposalActionRequest {
        let canister_id = Some(self.canister_id.get());
        let wasm_module = Some(
            read_wasm_module(
                &self.wasm_module_path,
                &self.wasm_module_url,
                &self.wasm_module_sha256,
            )
            .await,
        );
        let arg = Some(read_arg(&self.arg, &self.arg_sha256));
        let skip_stopping_before_installing = Some(self.skip_stopping_before_installing);
        let install_mode = match self.mode {
            CanisterInstallMode::Install => Some(GovernanceInstallMode::Install as i32),
            CanisterInstallMode::Reinstall => Some(GovernanceInstallMode::Reinstall as i32),
            CanisterInstallMode::Upgrade => Some(GovernanceInstallMode::Upgrade as i32),
        };

        let install_code = InstallCodeRequest {
            skip_stopping_before_installing,
            install_mode,
            canister_id,
            wasm_module,
            arg,
        };

        ProposalActionRequest::InstallCode(install_code)
    }
}

/// Sub-command to submit a proposal to upgrade an NNS canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToHardResetNnsRootToVersionCmd {
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
    /// The path to a binary file containing the initialization args of the canister.
    init_arg: Option<PathBuf>,
}
impl ProposalTitle for ProposeToHardResetNnsRootToVersionCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Hard reset NNS root to wasm with hash: {}",
                &self.wasm_module_sha256
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<HardResetNnsRootToVersionPayload> for ProposeToHardResetNnsRootToVersionCmd {
    async fn payload(&self, _: &Agent) -> HardResetNnsRootToVersionPayload {
        let wasm_module = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;
        let init_arg = self
            .init_arg
            .as_ref()
            .map_or(vec![], |path| read_file_fully(path));
        HardResetNnsRootToVersionPayload {
            wasm_module,
            init_arg,
        }
    }
}

/// Sub-command to submit a proposal to uninstall the code of a canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUninstallCodeCmd {
    #[clap(long, required = true)]
    /// The ID of the canister to uninstall.
    canister_id: CanisterId,
}

impl ProposalTitle for ProposeToUninstallCodeCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "SECURITY AGENCY ALERT: Uninstall code of canister: {}",
                self.canister_id
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<CanisterIdRecord> for ProposeToUninstallCodeCmd {
    async fn payload(&self, _: &Agent) -> CanisterIdRecord {
        CanisterIdRecord::from(self.canister_id)
    }
}

/// Sub-command to submit a subnet rental request proposal.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRentSubnetCmd {
    #[clap(long, required = true)]
    /// One of the predefined rental conditions of the subnet rental canister.
    rental_condition_id: RentalConditionId,
    /// The user who will be whitelisted for the subnet if the subnet rental request results in a successful subnet rental agreement.
    #[clap(long, required = true)]
    user: PrincipalId,
}

impl ProposalTitle for ProposeToRentSubnetCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Subnet rental request with condition {:?}",
                self.rental_condition_id
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<SubnetRentalRequest> for ProposeToRentSubnetCmd {
    async fn payload(&self, _agent: &Agent) -> SubnetRentalRequest {
        SubnetRentalRequest {
            user: self.user,
            rental_condition_id: self.rental_condition_id,
        }
    }
}
/// Sub-command to submit a subnet rental request proposal.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToFulfillSubnetRentalRequestCmd {
    /// The principal ID of the user whose rental request should be fulfilled
    #[clap(long)]
    user: PrincipalId,

    /// Node IDs that will be members of the subnet
    #[clap(long, num_args(1..))]
    node_ids: Vec<PrincipalId>,

    /// Replica version ID (40 character hexadecimal git commit ID)
    #[clap(long)]
    replica_version_id: String,
}

impl ProposalTitle for ProposeToFulfillSubnetRentalRequestCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Fulfill Subnet Rental Request for {}",
                self.user.to_string().split('-').next().unwrap_or("")
            ),
        }
    }
}

#[async_trait]
impl ProposalAction for ProposeToFulfillSubnetRentalRequestCmd {
    async fn action(&self) -> ProposalActionRequest {
        ProposalActionRequest::FulfillSubnetRentalRequest(
            ic_nns_governance_api::FulfillSubnetRentalRequest {
                user: Some(self.user),
                node_ids: Some(self.node_ids.clone()),
                replica_version_id: Some(self.replica_version_id.clone()),
            },
        )
    }
}

/// Sub-command to submit a proposal to update the settings of a canister. When neigther
/// `--controllers` nor `--remove-all-controllers` is provided, the controllers will not be updated.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateCanisterSettingsCmd {
    #[clap(long, required = true)]
    /// The ID of the target canister.
    canister_id: CanisterId,

    /// If set, it will update the canister's controllers to this value.
    #[clap(long, num_args(1..), group = "update_controllers")]
    controllers: Option<Vec<PrincipalId>>,
    /// If set, it will remove all controllers of the canister.
    #[clap(long, group = "update_controllers")]
    remove_all_controllers: bool,

    #[clap(long)]
    /// If set, it will update the canister's compute allocation to this value.
    compute_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's memory allocation to this value.
    memory_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's freezing threshold to this value.
    freezing_threshold: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's wasm memory limit to this value.
    wasm_memory_limit: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's log visibility to this value.
    log_visibility: Option<LogVisibility>,
    #[clap(long)]
    /// If set, it will update the canister's wasm memory threshold to this value.
    wasm_memory_threshold: Option<u64>,
}

impl ProposalTitle for ProposeToUpdateCanisterSettingsCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Update canister settings: {}", self.canister_id),
        }
    }
}

#[async_trait]
impl ProposalAction for ProposeToUpdateCanisterSettingsCmd {
    async fn action(&self) -> ProposalActionRequest {
        let canister_id = Some(self.canister_id.get());

        let controllers = if self.remove_all_controllers {
            Some(Controllers {
                controllers: vec![],
            })
        } else {
            self.controllers
                .clone()
                .map(|controllers| Controllers { controllers })
        };
        let compute_allocation = self.compute_allocation;
        let memory_allocation = self.memory_allocation;
        let freezing_threshold = self.freezing_threshold;
        let wasm_memory_limit = self.wasm_memory_limit;
        let wasm_memory_threshold = self.wasm_memory_threshold;
        let log_visibility = match self.log_visibility {
            Some(LogVisibility::Controllers) => Some(GovernanceLogVisibility::Controllers as i32),
            Some(LogVisibility::Public) => Some(GovernanceLogVisibility::Public as i32),
            None => None,
        };

        let update_settings = UpdateCanisterSettings {
            canister_id,
            settings: Some(CanisterSettings {
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
                wasm_memory_limit,
                log_visibility,
                wasm_memory_threshold,
            }),
        };

        ProposalActionRequest::UpdateCanisterSettings(update_settings)
    }
}

/// Sub-command to submit a proposal to add a new NNS canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
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
}

impl ProposalTitle for ProposeToAddNnsCanisterCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Add nns canister: {}", self.name),
        }
    }
}

#[async_trait]
impl ProposalPayload<AddCanisterRequest> for ProposeToAddNnsCanisterCmd {
    async fn payload(&self, _: &Agent) -> AddCanisterRequest {
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

        AddCanisterRequest {
            name: self.name.clone(),
            wasm_module,
            arg,
            // Hard code to 1 to satisfy the payload requirement. We don't need more since the
            // canister is running on the NNS where no cycles are charged.
            initial_cycles: 1,
            compute_allocation: self.compute_allocation.map(candid::Nat::from),
            memory_allocation: self.memory_allocation.map(candid::Nat::from),
        }
    }
}

/// A command to propose to add an SNS wasm to the SNS-WASM canister
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddWasmToSnsWasmCmd {
    #[clap(long)]
    /// The file system path to the new wasm module to ship.
    pub wasm_module_path: Option<PathBuf>,

    #[clap(long)]
    /// The URL of the new wasm module to ship.
    wasm_module_url: Option<Url>,

    #[clap(long, required = true)]
    /// The sha256 of the new wasm module to ship.
    wasm_module_sha256: String,

    #[clap(long, required = true)]
    /// The Canister type, one of: Root, Governance, Ledger, Swap, Archive, Index
    canister_type: String,

    #[clap(long)]
    /// If set, it will skip updating the latest version of the SNS-WASM canister.
    skip_update_latest_version: bool,
}

impl ProposalTitle for ProposeToAddWasmToSnsWasmCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Add {} SNS canister wasm to SNS-WASM", self.canister_type),
        }
    }
}

#[async_trait]
impl ProposalPayload<AddWasmRequest> for ProposeToAddWasmToSnsWasmCmd {
    async fn payload(&self, _: &Agent) -> AddWasmRequest {
        let wasm = read_wasm_module(
            &self.wasm_module_path,
            &self.wasm_module_url,
            &self.wasm_module_sha256,
        )
        .await;

        let canister_type = SnsCanisterType::from_str(&self.canister_type).expect(
            "Invalid canister_type, expected one of: \
                        Root, Governance, Ledger, Swap, Archive, Index",
        ) as i32;

        let sns_wasm = SnsWasm {
            wasm,
            canister_type,
            // Will be automatically set by NNS Governance
            proposal_id: None,
        };

        AddWasmRequest {
            wasm: Some(sns_wasm),
            hash: hex::decode(&self.wasm_module_sha256).unwrap(),
            skip_update_latest_version: Some(self.skip_update_latest_version),
        }
    }
}

/// A struct to make command line representations of the version easier, which expects
/// a hex-encoded sha256 sum of wasms.
#[derive(Clone, Deserialize, Serialize)]
struct JsonSnsVersion {
    pub root_wasm_hash: Option<String>,
    pub governance_wasm_hash: Option<String>,
    pub ledger_wasm_hash: Option<String>,
    pub swap_wasm_hash: Option<String>,
    pub archive_wasm_hash: Option<String>,
    pub index_wasm_hash: Option<String>,
}

impl JsonSnsVersion {
    /// Applies all Some fields to create a new JsonSnsVersion (leaving the original fields as they are)
    fn modify_with(&self, other_version: &JsonSnsVersion) -> JsonSnsVersion {
        JsonSnsVersion {
            root_wasm_hash: other_version
                .root_wasm_hash
                .clone()
                .or_else(|| self.root_wasm_hash.clone()),
            governance_wasm_hash: other_version
                .governance_wasm_hash
                .clone()
                .or_else(|| self.governance_wasm_hash.clone()),
            ledger_wasm_hash: other_version
                .ledger_wasm_hash
                .clone()
                .or_else(|| self.ledger_wasm_hash.clone()),
            swap_wasm_hash: other_version
                .swap_wasm_hash
                .clone()
                .or_else(|| self.swap_wasm_hash.clone()),
            archive_wasm_hash: other_version
                .archive_wasm_hash
                .clone()
                .or_else(|| self.archive_wasm_hash.clone()),
            index_wasm_hash: other_version
                .index_wasm_hash
                .clone()
                .or_else(|| self.index_wasm_hash.clone()),
        }
    }
}

impl FromStr for JsonSnsVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("{e}"))
    }
}

impl TryFrom<JsonSnsVersion> for SnsVersion {
    type Error = String;

    fn try_from(json_version: JsonSnsVersion) -> Result<Self, Self::Error> {
        Ok(SnsVersion {
            root_wasm_hash: hex::decode(json_version.root_wasm_hash.ok_or("Missing root")?)
                .map_err(|e| format!("{e}"))?,
            governance_wasm_hash: hex::decode(
                json_version
                    .governance_wasm_hash
                    .ok_or("Missing governance")?,
            )
            .map_err(|e| format!("{e}"))?,
            ledger_wasm_hash: hex::decode(json_version.ledger_wasm_hash.ok_or("Missing ledger")?)
                .map_err(|e| format!("{e}"))?,
            swap_wasm_hash: hex::decode(json_version.swap_wasm_hash.ok_or("Missing swap")?)
                .map_err(|e| format!("{e}"))?,
            archive_wasm_hash: hex::decode(
                json_version.archive_wasm_hash.ok_or("Missing archive")?,
            )
            .map_err(|e| format!("{e}"))?,
            index_wasm_hash: hex::decode(json_version.index_wasm_hash.ok_or("Missing index")?)
                .map_err(|e| format!("{e}"))?,
        })
    }
}

/// Proposal to insert SNS-W Upgrade Path Entries
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToInsertSnsWasmUpgradePathEntriesCmd {
    /// The sns_governance_canister_id that will get a custom response for the entries in the upgrade
    /// path
    #[clap(long)]
    pub sns_governance_canister_id: Option<CanisterId>,
    /// If missing sns_governance_canister_id, this is required to ensure proposer understands
    /// they are modifying the default upgrade path for all SNSes
    #[clap(long)]
    pub force_upgrade_main_upgrade_path: Option<bool>,

    /// Format is a JSON string with all version entries for the first, and at least one entry for each subsequent one.
    /// Subsequent entries are copied over the first entry to create the sequence of upgrades
    /// Example:
    /// propose-to-insert-sns-wasm-upgrade-path entries \
    ///     '{"archive":"archive-A","governance":"gov-A","index":"index-A","ledger":"ledger-A","root":"root-A","swap":"swap-A"}' \
    ///     '{"archive":"archive-B"}' '{"governance": "gov-C"}'
    ///
    /// In this example, there will be three versions like the following, as there was a single initial version and two
    ///  partial versions (treated as deltas):
    ///     '{"archive":"archive-A","governance":"gov-A","index":"index-A","ledger":"ledger-A","root":"root-A","swap":"swap-A"}'
    ///     '{"archive":"archive-B","governance":"gov-A","index":"index-A","ledger":"ledger-A","root":"root-A","swap":"swap-A"}'
    ///     '{"archive":"archive-B","governance":"gov-C","index":"index-A","ledger":"ledger-A","root":"root-A","swap":"swap-A"}'
    ///  and the path will be two step entries from the first to the second, then the second to the third.
    #[clap(required(true), num_args(1..))]
    pub versions: Vec<JsonSnsVersion>,
}

impl ProposalTitle for ProposeToInsertSnsWasmUpgradePathEntriesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Insert custom upgrade paths into SNS-W".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<InsertUpgradePathEntriesRequest>
    for ProposeToInsertSnsWasmUpgradePathEntriesCmd
{
    async fn payload(&self, _: &Agent) -> InsertUpgradePathEntriesRequest {
        let force_upgrade_main_upgrade_path = self.force_upgrade_main_upgrade_path.unwrap_or(false);

        let sns_governance_canister_id = self.sns_governance_canister_id.map(|c| c.into());

        if sns_governance_canister_id.is_none() && !force_upgrade_main_upgrade_path {
            panic!(
                "You must provide --force-upgrade-main-upgrade-path option if not specifying --sns-governance-canister-id option"
            );
        }

        // Note, we are filling in the JsonSnsVersions (b/c they can be optional) so that
        // the usage can be to supply the initial version, and then the deltas one-by-one.
        // This usage makes it easier to avoid errors from copy/pasting.
        let sns_versions: Vec<SnsVersion> = self
            .versions
            .iter()
            .fold(vec![], |list: Vec<JsonSnsVersion>, json_version| {
                let mut list = list;
                let last_version = list.last();
                let version = match last_version {
                    Some(last_version) => last_version.modify_with(json_version),
                    None => json_version.clone(),
                };
                list.push(version);
                list
            })
            .into_iter()
            .map(|j_version| j_version.try_into().unwrap())
            .collect();

        let upgrade_path = sns_versions
            .iter()
            .zip(sns_versions.iter().skip(1))
            .map(|(from, to)| SnsUpgrade {
                current_version: Some(from.clone()),
                next_version: Some(to.clone()),
            })
            .collect();

        InsertUpgradePathEntriesRequest {
            upgrade_path,
            sns_governance_canister_id,
        }
    }
}

fn print_insert_sns_wasm_upgrade_path_entries_payload(payload: InsertUpgradePathEntriesRequest) {
    // TODO how do we format this in a nice way?
    let formatted_upgrade_path = payload
        .upgrade_path
        .into_iter()
        .map(|upgrade| {
            let pretty_to: PrettySnsVersion = upgrade.next_version.unwrap().into();
            let pretty_from: PrettySnsVersion = upgrade.current_version.unwrap().into();
            format!(
                r"SnsUpgrade {{
    current_version:
            {pretty_from:#?},
    next_version:
            {pretty_to:#?}
}}"
            )
        })
        .collect::<Vec<String>>()
        .join(",\n");

    println!(
        r"InsertUpgradePathEntriesRequest {{
    sns_governance_canister_id: {:?},
    upgrade_path: {}
}}",
        payload.sns_governance_canister_id, formatted_upgrade_path
    );
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateSnsSubnetIdsInSnsWasmCmd {
    #[clap(long)]
    /// Add SNS Subnet IDs to the list of subnets that SNS-WASM will deploy SNS instances to
    pub sns_subnet_ids_to_add: Vec<PrincipalId>,

    #[clap(long)]
    /// Remove SNS Subnet IDs from the list of subnets that SNS-WASM will deploy SNS instances to
    pub sns_subnet_ids_to_remove: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToUpdateSnsSubnetIdsInSnsWasmCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Add SNS Subnet IDs to SNS-WASM".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateSnsSubnetListRequest> for ProposeToUpdateSnsSubnetIdsInSnsWasmCmd {
    async fn payload(&self, _: &Agent) -> UpdateSnsSubnetListRequest {
        UpdateSnsSubnetListRequest {
            sns_subnet_ids_to_add: self.sns_subnet_ids_to_add.clone(),
            sns_subnet_ids_to_remove: self.sns_subnet_ids_to_remove.clone(),
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateSnsDeployWhitelistCmd {
    #[clap(long)]
    /// Principals to add to the SNS deploy whitelist
    pub added_principals: Vec<PrincipalId>,

    #[clap(long)]
    /// Principals to remove from the SNS deploy whitelist
    pub removed_principals: Vec<PrincipalId>,
}

/// Deprecated; please use `CreateServiceNervousSystem` instead.
#[derive_common_proposal_fields]
#[derive(Clone, Parser, ProposalMetadata)]
struct ProposeToOpenSnsTokenSwap {}

impl ProposalTitle for ProposeToUpdateSnsDeployWhitelistCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update the list of Principals allowed to deploy an SNS".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateAllowedPrincipalsRequest> for ProposeToUpdateSnsDeployWhitelistCmd {
    async fn payload(&self, _: &Agent) -> UpdateAllowedPrincipalsRequest {
        UpdateAllowedPrincipalsRequest {
            added_principals: self.added_principals.clone(),
            removed_principals: self.removed_principals.clone(),
        }
    }
}

/// Sub-command to submit a proposal to clear the provisional whitelist.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToClearProvisionalWhitelistCmd {}

impl ProposalTitle for ProposeToClearProvisionalWhitelistCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Clear the provisional whitelist".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<()> for ProposeToClearProvisionalWhitelistCmd {
    async fn payload(&self, _: &Agent) -> () {}
}

/// Sub-command to submit a proposal set the list of authorized subnets.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
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
    #[clap(long, num_args(1..))]
    pub subnets: Option<Vec<PrincipalId>>,
}

impl ProposalTitle for ProposeToSetAuthorizedSubnetworksCmd {
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
}

#[async_trait]
impl ProposalPayload<SetAuthorizedSubnetworkListArgs> for ProposeToSetAuthorizedSubnetworksCmd {
    async fn payload(&self, _: &Agent) -> SetAuthorizedSubnetworkListArgs {
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

/// Sub-command to submit a proposal to add or remove subnet types in cycles
/// minting canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateSubnetTypeCmd {
    /// A value to indicate whether the subnet type is to be added or removed.
    #[clap(long, required = true)]
    pub operation: AddOrRemove,

    /// The name of the subnet type to be added or removed.
    #[clap(long, required = true)]
    pub subnet_type: String,
}

impl ProposalTitle for ProposeToUpdateSubnetTypeCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match &self.operation {
                AddOrRemove::Add => {
                    format!("Adding new subnet type: {}", self.subnet_type)
                }
                AddOrRemove::Remove => {
                    format!("Removing subnet type: {}", self.subnet_type)
                }
            },
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateSubnetTypeArgs> for ProposeToUpdateSubnetTypeCmd {
    async fn payload(&self, _: &Agent) -> UpdateSubnetTypeArgs {
        match self.operation {
            AddOrRemove::Add => UpdateSubnetTypeArgs::Add(self.subnet_type.clone()),
            AddOrRemove::Remove => UpdateSubnetTypeArgs::Remove(self.subnet_type.clone()),
        }
    }
}

/// Sub-command to submit a proposal to add or remove subnets to/from a subnet
/// type in cycles minting canister.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToChangeSubnetTypeAssignmentCmd {
    /// A value to indicate whether subnets are going to be added or removed
    /// to/from a subnet type.
    #[clap(long, required = true)]
    pub operation: AddOrRemove,

    /// The list of subnets to be added to or removed from a subnet type.
    #[clap(long, required = true)]
    pub subnets: Vec<PrincipalId>,

    /// The subnet type to add subnets to or remove subnets from.
    #[clap(long, required = true)]
    pub subnet_type: String,
}

impl ProposalTitle for ProposeToChangeSubnetTypeAssignmentCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match &self.operation {
                AddOrRemove::Add => {
                    format!(
                        "Adding subnets: {} to subnet type {}",
                        shortened_pids_string(&self.subnets),
                        self.subnet_type
                    )
                }
                AddOrRemove::Remove => {
                    format!(
                        "Removing subnets: {} from subnet type {}",
                        shortened_pids_string(&self.subnets),
                        self.subnet_type
                    )
                }
            },
        }
    }
}

#[async_trait]
impl ProposalPayload<ChangeSubnetTypeAssignmentArgs> for ProposeToChangeSubnetTypeAssignmentCmd {
    async fn payload(&self, _: &Agent) -> ChangeSubnetTypeAssignmentArgs {
        match self.operation {
            AddOrRemove::Add => ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
                subnets: self.subnets.iter().cloned().map(SubnetId::from).collect(),
                subnet_type: self.subnet_type.clone(),
            }),
            AddOrRemove::Remove => ChangeSubnetTypeAssignmentArgs::Remove(SubnetListWithType {
                subnets: self.subnets.iter().cloned().map(SubnetId::from).collect(),
                subnet_type: self.subnet_type.clone(),
            }),
        }
    }
}

/// Sub-command to get the public key of a subnet from the registry.
#[derive(Parser)]
struct SubnetPublicKeyCmd {
    /// The subnet.
    subnet: SubnetDescriptor,

    /// Target path where the PEM is stored.
    target_path: PathBuf,
}

/// Sub-command to submit a proposal to add or remove a node provider.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddOrRemoveNodeProviderCmd {
    /// The principal id of the node provider.
    #[clap(long, required = true)]
    pub node_provider_pid: PrincipalId,

    /// A value to indicated whether the provider is to be added or removed.
    pub add_or_remove_provider: AddOrRemove,
}

impl ProposalTitle for ProposeToAddOrRemoveNodeProviderCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match self.add_or_remove_provider {
                AddOrRemove::Add => format!(
                    "Add Node Provider: {}",
                    shortened_pid_string(&self.node_provider_pid)
                ),
                AddOrRemove::Remove => format!(
                    "Remove Node Provider: {}",
                    shortened_pid_string(&self.node_provider_pid)
                ),
            },
        }
    }
}

/// Sub-command to submit a proposal to add a new node operator.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddNodeOperatorCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,

    #[clap(long, hide = true)]
    /// Deprecated, will be removed in the future.
    /// The remaining number of nodes that could be added by this node operator
    pub node_allowance: Option<u64>,

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

    /// The ipv6 address.
    #[clap(long)]
    ipv6: Option<String>,

    /// A JSON map from node type to the maximum number of nodes of that type that the
    /// given Node Operator can be rewarded for.
    ///
    /// Example:
    /// '{ "type1.1": 10, "type3.1": 24 }'
    #[clap(long, required = true)]
    max_rewardable_nodes: Option<String>,
}

impl ProposalTitle for ProposeToAddNodeOperatorCmd {
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
}

#[async_trait]
impl ProposalPayload<AddNodeOperatorPayload> for ProposeToAddNodeOperatorCmd {
    async fn payload(&self, _: &Agent) -> AddNodeOperatorPayload {
        let rewardable_nodes = self
            .rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s))
            .unwrap_or_default();

        // TODO(DRE-583): Remove the `--node-allowance` flag after callers of `ic-admin`
        // have migrated to `--max-rewardable-nodes`.
        let node_allowance = self.node_allowance.map(|allowance| {
            if allowance != 0 {
                eprintln!("WARNING: node allowance is deprecated and will be removed in the future. Overriding value to 0");
            }
            0
        }).unwrap_or_default();

        let max_rewardable_nodes = self
            .max_rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s));

        AddNodeOperatorPayload {
            node_operator_principal_id: Some(self.node_operator_principal_id),
            node_allowance,
            node_provider_principal_id: Some(self.node_provider_principal_id),
            dc_id: self
                .dc_id
                .as_ref()
                .map(|dc| dc.to_lowercase())
                .unwrap_or_default(),
            rewardable_nodes,
            ipv6: self.ipv6.clone(),
            max_rewardable_nodes,
        }
    }
}

/// Sub-command to submit a proposal to update the configuration of a node
/// operator.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
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

    #[clap(long)]
    /// The principal id of the node provider
    pub node_provider_id: Option<PrincipalId>,

    /// The ipv6 address of the node operator.
    #[clap(long)]
    ipv6: Option<String>,

    /// Set the field ipv6 in the NodeOperatorRecord to None. If the field ipv6 in this struct is
    /// set to None, the field ipv6 in the NodeOperatorRecord will not be updated.
    /// This field is for the case when we want to update the value to be None.
    #[clap(long)]
    pub set_ipv6_to_none: Option<bool>,

    /// A JSON map from node type to the maximum number of nodes of that type that the
    /// given Node Operator can be rewarded for.
    ///
    /// Example:
    /// '{ "type1.1": 10, "type3.1": 24 }'
    #[clap(long)]
    max_rewardable_nodes: Option<String>,
}

impl ProposalTitle for ProposeToUpdateNodeOperatorConfigCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update config of Node Operator: {}",
                shortened_pid_string(&self.node_operator_id)
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateNodeOperatorConfigPayload> for ProposeToUpdateNodeOperatorConfigCmd {
    async fn payload(&self, _: &Agent) -> UpdateNodeOperatorConfigPayload {
        let rewardable_nodes = self
            .rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s))
            .unwrap_or_default();

        let max_rewardable_nodes = self
            .max_rewardable_nodes
            .as_ref()
            .map(|s| parse_rewardable_nodes(s));

        UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(self.node_operator_id),
            node_allowance: self.node_allowance,
            dc_id: self.dc_id.as_ref().map(|dc| dc.to_lowercase()),
            rewardable_nodes,
            node_provider_id: self.node_provider_id,
            ipv6: self.ipv6.clone(),
            set_ipv6_to_none: self.set_ipv6_to_none,
            max_rewardable_nodes,
        }
    }
}

/// Parses a JSON-encoded map from node type (string) to the number of
/// rewardable nodes of that type.
///
/// The supplied node types must be in the node type whitelist
fn parse_rewardable_nodes(json: &str) -> BTreeMap<String, u32> {
    let map: BTreeMap<String, u32> = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("Unable to parse rewardable_nodes: {e}"));

    map
}

#[derive(Parser)]
struct GetDataCenterCmd {
    pub dc_id: String,
}

/// Sub-command to submit a proposal to add or remove a data center.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddOrRemoveDataCentersCmd {
    /// The JSON-formatted Data Center records to add to the Registry.
    ///
    /// Example:
    /// '{ "id": "AN1", "region": "us-west", "owner": "DC Corp", "gps": {
    /// "latitude": 37.774929,    "longitude": -122.419416 } }'
    #[clap(long, num_args(1..))]
    pub data_centers_to_add: Vec<String>,

    /// The IDs of data centers to remove
    #[clap(long, num_args(1..))]
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
                    panic!("Unable to parse JSON DataCenterRecord: {str}\nError: {e}");
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

impl ProposalTitle for ProposeToAddOrRemoveDataCentersCmd {
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
}

#[async_trait]
impl ProposalPayload<AddOrRemoveDataCentersProposalPayload> for ProposeToAddOrRemoveDataCentersCmd {
    async fn payload(&self, _: &Agent) -> AddOrRemoveDataCentersProposalPayload {
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
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateNodeRewardsTableCmd {
    /// A JSON-encoded map from region to a map from node type to the
    /// xdr_permyriad_per_node_per_month for that node type in that region
    ///
    /// Example:
    /// '{ "North America,US,California": { "type0": 10, "type1": 24 }, "Europe": { "type0": 24 } }'
    #[clap(long)]
    pub updated_node_rewards: String,
}

impl ProposalTitle for ProposeToUpdateNodeRewardsTableCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update the Node Rewards Table".into(),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateNodeRewardsTableProposalPayload> for ProposeToUpdateNodeRewardsTableCmd {
    async fn payload(&self, _: &Agent) -> UpdateNodeRewardsTableProposalPayload {
        let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
            serde_json::from_str(&self.updated_node_rewards)
                .unwrap_or_else(|e| panic!("Unable to parse updated_node_rewards: {e}"));

        UpdateNodeRewardsTableProposalPayload::from(map)
    }
}

/// Sub-command to fetch a `NodeOperatorRecord` from the registry.
#[derive(Parser)]
struct GetNodeOperatorCmd {
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,
}

/// Sub-command to update the registry local store.
#[derive(Parser)]
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
#[derive(Parser, ProposalMetadata)]
struct ProposeToSetFirewallConfigCmd {
    /// File with the firewall configuration content
    pub firewall_config_file: PathBuf,
    /// List of allowed IPv4 prefixes, comma separated, or "-" (for empty list)
    pub ipv4_prefixes: String,
    /// List of allowed IPv6 prefixes, comma separated, or "-" (for empty list)
    pub ipv6_prefixes: String,
}

impl ProposalTitle for ProposeToSetFirewallConfigCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update firewall configuration".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<SetFirewallConfigPayload> for ProposeToSetFirewallConfigCmd {
    async fn payload(&self, _: &Agent) -> SetFirewallConfigPayload {
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

/// Sub-command to submit a proposal to add firewall rules.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddFirewallRulesCmd {
    /// The scope to apply new rules at (can be "global", "replica_nodes", "subnet(id)", or "node(id)")
    pub scope: FirewallRulesScope,
    /// File with the rules in JSON format
    pub rules_file: PathBuf,
    /// Comma separated list of indices to insert the rules at within the existing ruleset (0 means top of the list and highest priority, -1 means bottom of the list and lowest priority)
    pub positions: String,
    /// Expected SHA-256 of the result ruleset
    pub expected_ruleset_hash: String,
    /// Test mode - does not require a hash. Instead of making the proposal, will only return the expected modified ruleset
    #[clap(long)]
    pub test: bool,
}

impl ProposalTitle for ProposeToAddFirewallRulesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Add firewall rules".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<AddFirewallRulesPayload> for ProposeToAddFirewallRulesCmd {
    async fn payload(&self, _: &Agent) -> AddFirewallRulesPayload {
        let rule_file = String::from_utf8(read_file_fully(&self.rules_file)).unwrap();
        let rules: Vec<FirewallRule> = serde_json::from_str(&rule_file)
            .unwrap_or_else(|_| panic!("Failed to parse firewall rules"));
        let positions: Vec<i32> = self
            .positions
            .clone()
            .split(',')
            .map(|pos_str| {
                i32::from_str(pos_str)
                    .unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
            })
            .collect();
        let expected_hash = &self.expected_ruleset_hash;
        AddFirewallRulesPayload {
            scope: self.scope.clone(),
            rules,
            positions,
            expected_hash: expected_hash.to_string(),
        }
    }
}

/// Sub-command to submit a proposal to remove firewall rules.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRemoveFirewallRulesCmd {
    /// The scope to apply new rules at (can be "global", "replica_nodes", "subnet(id)", or "node(id)")
    pub scope: FirewallRulesScope,
    /// Comma separated list of indices to remove from the ruleset
    pub positions: String,
    /// Expected SHA-256 of the result ruleset
    pub expected_ruleset_hash: String,
    /// Test mode - does not require a hash. Instead of making the proposal, will only return the expected modified ruleset
    #[clap(long)]
    pub test: bool,
}

impl ProposalTitle for ProposeToRemoveFirewallRulesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Remove firewall rules".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<RemoveFirewallRulesPayload> for ProposeToRemoveFirewallRulesCmd {
    async fn payload(&self, _: &Agent) -> RemoveFirewallRulesPayload {
        let positions: Vec<i32> = self
            .positions
            .clone()
            .split(',')
            .map(|pos_str| {
                i32::from_str(pos_str)
                    .unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
            })
            .collect();
        let expected_hash = &self.expected_ruleset_hash;
        RemoveFirewallRulesPayload {
            scope: self.scope.clone(),
            positions,
            expected_hash: expected_hash.to_string(),
        }
    }
}

/// Sub-command to submit a proposal to update firewall rules.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateFirewallRulesCmd {
    /// The scope to apply new rules at (can be "global", "replica_nodes", "subnet(id)", or "node(id)")
    pub scope: FirewallRulesScope,
    /// File with the updated rules in JSON format
    pub rules_file: PathBuf,
    /// Comma separated list of indices to update in the ruleset
    pub positions: String,
    /// Expected SHA-256 of the result ruleset
    pub expected_ruleset_hash: String,
    /// Test mode - does not require a hash. Instead of making the proposal, will only return the expected modified ruleset
    #[clap(long)]
    pub test: bool,
}

impl ProposalTitle for ProposeToUpdateFirewallRulesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => "Update firewall rules".to_string(),
        }
    }
}

#[async_trait]
impl ProposalPayload<UpdateFirewallRulesPayload> for ProposeToUpdateFirewallRulesCmd {
    async fn payload(&self, _: &Agent) -> UpdateFirewallRulesPayload {
        let rule_file = String::from_utf8(read_file_fully(&self.rules_file)).unwrap();
        let rules: Vec<FirewallRule> = serde_json::from_str(&rule_file)
            .unwrap_or_else(|_| panic!("Failed to parse firewall rules"));
        let positions: Vec<i32> = self
            .positions
            .clone()
            .split(',')
            .map(|pos_str| {
                i32::from_str(pos_str)
                    .unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
            })
            .collect();
        let expected_hash = &self.expected_ruleset_hash;
        UpdateFirewallRulesPayload {
            scope: self.scope.clone(),
            rules,
            positions,
            expected_hash: expected_hash.to_string(),
        }
    }
}

/// Sub-command to get all firewall rules for a given scope.
#[derive(Parser)]
struct GetFirewallRulesCmd {
    /// The scope to apply new rules at (can be "global", "replica_nodes", "subnet(id)", or "node(id)")
    pub scope: FirewallRulesScope,
}

/// Sub-command to get all firewall rules that apply for a specific node.
#[derive(Parser)]
struct GetFirewallRulesForNodeCmd {
    /// PrincipalID of the node
    pub node_id: PrincipalId,
}

/// Sub-command to compute the SHA-256 hash of a given firewall ruleset.
#[derive(Parser)]
struct GetFirewallRulesetHashCmd {
    /// File with the firewall rules in JSON format
    pub rules_file: PathBuf,
}

/// Sub-command to submit a proposal to remove nodes.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRemoveNodesCmd {
    /// The IDs of the nodes to remove.
    #[clap(name = "NODE_ID", num_args(1..), required = true)]
    pub node_ids: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToRemoveNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!("Remove nodes: {}", shortened_pids_string(&self.node_ids)),
        }
    }
}

#[async_trait]
impl ProposalPayload<RemoveNodesPayload> for ProposeToRemoveNodesCmd {
    async fn payload(&self, _: &Agent) -> RemoveNodesPayload {
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
#[derive(Parser)]
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

#[derive(Parser)]
struct SwapNodeInSubnetDirectlyCmd {
    /// Represents the node principal id of a node which will be removed from a subnet.
    #[clap(long)]
    pub old_node_id: PrincipalId,

    /// Represents the node principal id of a node which will be added to a subnet in
    /// place of the `old_node_id`.
    #[clap(long)]
    pub new_node_id: PrincipalId,
}

/// Sub-command to vote on a root proposal to upgrade the governance canister.
#[derive(Parser)]
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

/// Sub-command to submit a proposal to modify the canister migrations.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToPrepareCanisterMigrationCmd {
    /// The list of canister ID ranges in migration.
    #[clap(long, num_args(1..), required = true)]
    canister_id_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    #[clap(long, required = true)]
    source_subnet: PrincipalId,
    /// The new destination for the canister ID ranges.
    #[clap(long, required = true)]
    destination_subnet: PrincipalId,
}

impl ProposalTitle for ProposeToPrepareCanisterMigrationCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Migrate {} canister ranges from subnet {} to subnet {}",
                self.canister_id_ranges.len(),
                self.source_subnet,
                self.destination_subnet
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<PrepareCanisterMigrationPayload> for ProposeToPrepareCanisterMigrationCmd {
    async fn payload(&self, _: &Agent) -> PrepareCanisterMigrationPayload {
        PrepareCanisterMigrationPayload {
            canister_id_ranges: self.canister_id_ranges.clone(),
            source_subnet: SubnetId::from(self.source_subnet),
            destination_subnet: SubnetId::from(self.destination_subnet),
        }
    }
}

/// Sub-command to propose a change in the routing table.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRerouteCanisterRangesCmd {
    /// The list of canister ID ranges to be rerouted.
    #[clap(long, num_args(1..), required = true)]
    canister_id_ranges: Vec<CanisterIdRange>,
    /// The source of the canister ID ranges.
    #[clap(long, required = true)]
    source_subnet: PrincipalId,
    /// The destination subnet for the specified canister range.
    #[clap(long, required = true)]
    destination_subnet: PrincipalId,
}

impl ProposalTitle for ProposeToRerouteCanisterRangesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Reroute {} canister ranges from subnet {} to subnet {}",
                self.canister_id_ranges.len(),
                self.source_subnet,
                self.destination_subnet
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<RerouteCanisterRangesPayload> for ProposeToRerouteCanisterRangesCmd {
    async fn payload(&self, _: &Agent) -> RerouteCanisterRangesPayload {
        RerouteCanisterRangesPayload {
            reassigned_canister_ranges: self.canister_id_ranges.clone(),
            source_subnet: SubnetId::from(self.source_subnet),
            destination_subnet: SubnetId::from(self.destination_subnet),
        }
    }
}

/// Sub-command to submit a proposal to remove some entries from the canister migrations.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToCompleteCanisterMigrationCmd {
    /// The list of canister ID ranges to be removed from canister migrations.
    #[clap(long, num_args(1..), required = true)]
    canister_id_ranges: Vec<CanisterIdRange>,
    /// The migration trace containing a list of subnet IDs.
    #[clap(long, num_args(1..), required = true)]
    migration_trace: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToCompleteCanisterMigrationCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Remove {} canister ranges from the canister migrations.",
                self.canister_id_ranges.len()
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<CompleteCanisterMigrationPayload> for ProposeToCompleteCanisterMigrationCmd {
    async fn payload(&self, _: &Agent) -> CompleteCanisterMigrationPayload {
        CompleteCanisterMigrationPayload {
            canister_id_ranges: self.canister_id_ranges.clone(),
            migration_trace: self
                .migration_trace
                .iter()
                .cloned()
                .map(SubnetId::from)
                .collect(),
        }
    }
}

/// Sub-command to submit a proposal to set the bitcoin configuration.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToSetBitcoinConfig {
    pub network: BitcoinNetwork,

    #[clap(long, help = "Updates the stability threshold.")]
    pub stability_threshold: Option<u128>,

    #[clap(long, help = "Enables/disables access to the Bitcoin canister's API.")]
    pub api_access: Option<bool>,

    #[clap(long, help = "Sets/clears the watchdog canister principal.")]
    pub watchdog_canister: Option<Option<PrincipalId>>,

    #[clap(
        long,
        help = "Whether or not to disable the API if canister isn't fully synced."
    )]
    pub disable_api_if_not_fully_synced: Option<bool>,

    #[clap(
        long,
        help = "Updates the base fee to charge for all `get_utxos` requests."
    )]
    pub get_utxos_base: u128,

    #[clap(
        long,
        help = "Updates the number of cycles to charge per 10 instructions in a `get_utxos` request."
    )]
    pub get_utxos_cycles_per_ten_instructions: u128,

    #[clap(
        long,
        help = "Updates the maximum amount of cycles that can be charged in a `get_utxos` request."
    )]
    pub get_utxos_maximum: u128,

    #[clap(
        long,
        help = "Updates the flat fee to charge for a `get_balance` request."
    )]
    pub get_balance: u128,

    #[clap(
        long,
        help = "Updates the maximum amount of cycles that can be charged in a `get_balance` request."
    )]
    pub get_balance_maximum: u128,

    #[clap(
        long,
        help = "Updates the flat fee to charge for a `get_current_fee_percentiles` request."
    )]
    pub get_current_fee_percentiles: u128,

    #[clap(
        long,
        help = "Updates the maximum amount of cycles that can be charged in a `get_current_fee_percentiles` request."
    )]
    pub get_current_fee_percentiles_maximum: u128,

    #[clap(
        long,
        help = "Updates the base fee to charge for all `send_transaction` requests."
    )]
    pub send_transaction_base: u128,

    #[clap(
        long,
        help = "Updates the number of cycles to charge for each byte in the transaction."
    )]
    pub send_transaction_per_byte: u128,

    #[clap(
        long,
        help = "Updates the base fee to charge for all `get_block_headers` requests."
    )]
    pub get_block_headers_base: u128,

    #[clap(
        long,
        help = "Updates the number of cycles to charge per 10 instructions in a `get_block_headers` request."
    )]
    pub get_block_headers_cycles_per_ten_instructions: u128,

    #[clap(
        long,
        help = "Updates the maximum amount of cycles that can be charged in a `get_block_headers` request."
    )]
    pub get_block_headers_maximum: u128,
}

impl ProposalTitle for ProposeToSetBitcoinConfig {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Bitcoin: set config of the {} canister",
                match self.network {
                    BitcoinNetwork::Mainnet => "mainnet",
                    BitcoinNetwork::Testnet => "testnet",
                }
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<BitcoinSetConfigProposal> for ProposeToSetBitcoinConfig {
    async fn payload(&self, _: &Agent) -> BitcoinSetConfigProposal {
        let request: SetConfigRequest = SetConfigRequest {
            stability_threshold: self.stability_threshold,
            api_access: self
                .api_access
                .map(|flag| if flag { Flag::Enabled } else { Flag::Disabled }),
            watchdog_canister: self
                .watchdog_canister
                .map(|principal_id| principal_id.map(Principal::from)),
            disable_api_if_not_fully_synced: self
                .disable_api_if_not_fully_synced
                .map(|flag| if flag { Flag::Enabled } else { Flag::Disabled }),
            fees: Some(Fees {
                get_utxos_base: self.get_utxos_base,
                get_utxos_cycles_per_ten_instructions: self.get_utxos_cycles_per_ten_instructions,
                get_utxos_maximum: self.get_utxos_maximum,
                get_balance: self.get_balance,
                get_balance_maximum: self.get_balance_maximum,
                get_current_fee_percentiles: self.get_current_fee_percentiles,
                get_current_fee_percentiles_maximum: self.get_current_fee_percentiles_maximum,
                send_transaction_base: self.send_transaction_base,
                send_transaction_per_byte: self.send_transaction_per_byte,
                get_block_headers_base: self.get_block_headers_base,
                get_block_headers_cycles_per_ten_instructions: self
                    .get_block_headers_cycles_per_ten_instructions,
                get_block_headers_maximum: self.get_block_headers_maximum,
            }),
            ..Default::default()
        };

        BitcoinSetConfigProposal {
            network: self.network,
            payload: Encode!(&request).unwrap(),
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Clone, Debug, Parser, ProposalMetadata)]
struct ProposeToCreateServiceNervousSystemCmd {
    #[clap(long)]
    name: String,

    #[clap(long)]
    description: String,

    #[clap(long)]
    url: String,

    #[clap(long)]
    logo: String,

    // Canister Control
    // ----------------
    #[clap(long)]
    fallback_controller_principal_id: Vec<PrincipalId>,

    #[clap(long)]
    dapp_canister: Vec<PrincipalId>,

    // Initial SNS Tokens and Neurons
    // ------------------------------
    #[clap(long)]
    developer_neuron_controller: Vec<PrincipalId>,

    #[clap(long, value_parser=parse_duration)]
    developer_neuron_dissolve_delay: Vec<nervous_system_pb::Duration>,

    #[clap(long)]
    developer_neuron_memo: Vec<u64>,

    #[clap(long, value_parser=parse_tokens)]
    developer_neuron_stake: Vec<nervous_system_pb::Tokens>,

    #[clap(long, value_parser=parse_duration)]
    developer_neuron_vesting_period: Vec<nervous_system_pb::Duration>,

    #[clap(long, value_parser=parse_tokens)]
    treasury_amount: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_tokens)]
    swap_amount: nervous_system_pb::Tokens,

    // Swap
    // ----
    #[clap(long)]
    swap_minimum_participants: u64,

    #[clap(long, value_parser=parse_tokens)]
    swap_minimum_direct_participation_icp: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_tokens)]
    swap_maximum_direct_participation_icp: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_tokens)]
    swap_minimum_participant_icp: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_tokens)]
    swap_maximum_participant_icp: nervous_system_pb::Tokens,

    #[clap(long)]
    confirmation_text: Option<String>,

    #[clap(long)]
    restrict_swap_in_country: Option<Vec<String>>,

    #[clap(long)]
    swap_neuron_count: u64,

    #[clap(long, value_parser=parse_duration)]
    swap_neuron_dissolve_delay: nervous_system_pb::Duration,

    #[clap(long, value_parser=parse_time_of_day)]
    swap_start_time: Option<nervous_system_pb::GlobalTimeOfDay>,

    #[clap(long, value_parser=parse_duration)]
    swap_duration: nervous_system_pb::Duration,

    #[clap(long, action)]
    neurons_fund_participation: bool, // defaults to false if unset (due to `action`)

    // Ledger
    // ------
    #[clap(long, value_parser=parse_tokens)]
    transaction_fee: nervous_system_pb::Tokens,

    #[clap(long)]
    token_name: String,

    #[clap(long)]
    token_symbol: String,

    #[clap(long)]
    token_logo_url: String,

    // Proposals
    // ---------
    #[clap(long, value_parser=parse_tokens)]
    proposal_rejection_fee: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_duration)]
    proposal_initial_voting_period: nervous_system_pb::Duration,

    #[clap(long, value_parser=parse_duration)]
    proposal_wait_for_quiet_deadline_increase: nervous_system_pb::Duration,

    // Neurons
    // -------
    #[clap(long, value_parser=parse_tokens)]
    neuron_minimum_stake: nervous_system_pb::Tokens,

    #[clap(long, value_parser=parse_duration)]
    neuron_minimum_dissolve_delay_to_vote: nervous_system_pb::Duration,

    #[clap(long, value_parser=parse_duration)]
    neuron_maximum_dissolve_delay: nervous_system_pb::Duration,

    #[clap(long, value_parser=parse_percentage)]
    neuron_maximum_dissolve_delay_bonus: nervous_system_pb::Percentage,

    #[clap(long, value_parser=parse_duration)]
    neuron_maximum_age_for_age_bonus: nervous_system_pb::Duration,

    #[clap(long, value_parser=parse_percentage)]
    neuron_maximum_age_bonus: nervous_system_pb::Percentage,

    // Voting Reward(s)
    // ----------------
    #[clap(long, value_parser=parse_percentage)]
    initial_voting_reward_rate: nervous_system_pb::Percentage,

    #[clap(long, value_parser=parse_percentage)]
    final_voting_reward_rate: nervous_system_pb::Percentage,

    #[clap(long, value_parser=parse_duration)]
    voting_reward_rate_transition_duration: nervous_system_pb::Duration,
}

impl TryFrom<ProposeToCreateServiceNervousSystemCmd> for CreateServiceNervousSystem {
    type Error = String;
    fn try_from(cmd: ProposeToCreateServiceNervousSystemCmd) -> Result<Self, String> {
        let ProposeToCreateServiceNervousSystemCmd {
            name,
            description,
            url,
            logo,
            // Deconstruct to a more indicative name
            fallback_controller_principal_id: fallback_controller_principal_ids,
            // Deconstruct to a more indicative name
            dapp_canister: dapp_canisters,

            developer_neuron_controller,
            developer_neuron_dissolve_delay,
            developer_neuron_memo,
            developer_neuron_stake,
            developer_neuron_vesting_period,

            treasury_amount,
            swap_amount,

            swap_minimum_participants,
            swap_minimum_direct_participation_icp,
            swap_maximum_direct_participation_icp,
            swap_minimum_participant_icp,
            swap_maximum_participant_icp,
            swap_neuron_count,
            swap_neuron_dissolve_delay,
            confirmation_text,
            // Deconstruct to a more indicative name
            restrict_swap_in_country: restricted_countries,
            swap_start_time,
            swap_duration,
            neurons_fund_participation,

            transaction_fee,
            token_name,
            token_symbol,
            token_logo_url,

            proposal_rejection_fee,
            proposal_initial_voting_period,
            proposal_wait_for_quiet_deadline_increase,

            neuron_minimum_stake,
            neuron_minimum_dissolve_delay_to_vote,
            neuron_maximum_dissolve_delay,
            neuron_maximum_dissolve_delay_bonus,
            neuron_maximum_age_for_age_bonus,
            neuron_maximum_age_bonus,

            initial_voting_reward_rate,
            final_voting_reward_rate,
            voting_reward_rate_transition_duration,

            // Not used.
            proposer: _,
            test_neuron_proposer: _,
            proposal_url: _,
            proposal_title: _,
            summary: _,
            summary_file: _,
            dry_run: _,
            json: _,
        } = cmd;

        let name = Some(name);
        let description = Some(description);
        let url = Some(url);
        let logo = Some(nervous_system_pb::Image {
            base64_encoding: Some(logo),
        });

        let dapp_canisters = dapp_canisters
            .into_iter()
            .map(|id| nervous_system_pb::Canister { id: Some(id) })
            .collect();

        let initial_token_distribution = {
            let developer_distribution = {
                // Require that all the --developer_neuron_* receive the same
                // number of values.
                let lengths = hashmap! {
                    "controller" => developer_neuron_controller.len(),
                    "dissolve_delay" => developer_neuron_dissolve_delay.len(),
                    "memo" => developer_neuron_memo.len(),
                    "stake" => developer_neuron_stake.len(),
                    "vesting_period" => developer_neuron_vesting_period.len(),
                };
                let distinct_lengths = lengths.values().copied().collect::<HashSet<_>>();
                if distinct_lengths.len() != 1 {
                    return Err(format!(
                        "--developer_neuron_* flags must receive the same number \
                         of values. lengths: {lengths:#?}",
                    ));
                }

                let developer_neurons = izip!(
                    developer_neuron_controller,
                    developer_neuron_dissolve_delay,
                    developer_neuron_memo,
                    developer_neuron_stake,
                    developer_neuron_vesting_period,
                )
                .map(
                    |(controller, dissolve_delay, memo, stake, vesting_period)| {
                        let controller = Some(controller);
                        let dissolve_delay = Some(dissolve_delay);
                        let memo = Some(memo);
                        let stake = Some(stake);
                        let vesting_period = Some(vesting_period);

                        NeuronDistribution {
                            controller,
                            dissolve_delay,
                            memo,
                            stake,
                            vesting_period,
                        }
                    },
                )
                .collect();

                Some(DeveloperDistribution { developer_neurons })
            };

            let treasury_distribution = Some(TreasuryDistribution {
                total: Some(treasury_amount),
            });

            let swap_distribution = Some(SwapDistribution {
                total: Some(swap_amount),
            });

            Some(InitialTokenDistribution {
                developer_distribution,
                treasury_distribution,
                swap_distribution,
            })
        };

        let swap_parameters = {
            let minimum_participants = Some(swap_minimum_participants);
            let minimum_direct_participation_icp = Some(swap_minimum_direct_participation_icp);
            let maximum_direct_participation_icp = Some(swap_maximum_direct_participation_icp);
            let neurons_fund_participation = Some(neurons_fund_participation);

            let minimum_participant_icp = Some(swap_minimum_participant_icp);
            let maximum_participant_icp = Some(swap_maximum_participant_icp);
            let start_time = swap_start_time;
            let duration = Some(swap_duration);

            let neuron_basket_construction_parameters = {
                let count = Some(swap_neuron_count);
                let dissolve_delay_interval = Some(swap_neuron_dissolve_delay);

                Some(swap_parameters::NeuronBasketConstructionParameters {
                    count,
                    dissolve_delay_interval,
                })
            };

            let restricted_countries =
                restricted_countries.map(|iso_codes| nervous_system_pb::Countries { iso_codes });

            // Deprecated fields
            let minimum_icp = None;
            let maximum_icp = None;
            let neurons_fund_investment_icp = None;

            Some(SwapParameters {
                minimum_participants,
                minimum_icp,
                maximum_icp,
                minimum_direct_participation_icp,
                maximum_direct_participation_icp,
                minimum_participant_icp,
                maximum_participant_icp,
                confirmation_text,
                restricted_countries,
                neuron_basket_construction_parameters,
                start_time,
                duration,
                neurons_fund_investment_icp,
                neurons_fund_participation,
            })
        };

        let ledger_parameters = {
            let transaction_fee = Some(transaction_fee);
            let token_name = Some(token_name);
            let token_symbol = Some(token_symbol);
            let token_logo = Some(nervous_system_pb::Image {
                base64_encoding: Some(token_logo_url),
            });

            Some(LedgerParameters {
                transaction_fee,
                token_name,
                token_symbol,
                token_logo,
            })
        };

        let governance_parameters = {
            let proposal_rejection_fee = Some(proposal_rejection_fee);
            let proposal_initial_voting_period = Some(proposal_initial_voting_period);
            let proposal_wait_for_quiet_deadline_increase =
                Some(proposal_wait_for_quiet_deadline_increase);

            let neuron_minimum_stake = Some(neuron_minimum_stake);
            let neuron_minimum_dissolve_delay_to_vote = Some(neuron_minimum_dissolve_delay_to_vote);
            let neuron_maximum_dissolve_delay = Some(neuron_maximum_dissolve_delay);
            let neuron_maximum_dissolve_delay_bonus = Some(neuron_maximum_dissolve_delay_bonus);
            let neuron_maximum_age_for_age_bonus = Some(neuron_maximum_age_for_age_bonus);
            let neuron_maximum_age_bonus = Some(neuron_maximum_age_bonus);

            let voting_reward_parameters = {
                let initial_reward_rate = Some(initial_voting_reward_rate);
                let final_reward_rate = Some(final_voting_reward_rate);
                let reward_rate_transition_duration = Some(voting_reward_rate_transition_duration);

                Some(VotingRewardParameters {
                    initial_reward_rate,
                    final_reward_rate,
                    reward_rate_transition_duration,
                })
            };

            Some(GovernanceParameters {
                proposal_rejection_fee,
                proposal_initial_voting_period,
                proposal_wait_for_quiet_deadline_increase,

                neuron_minimum_stake,
                neuron_minimum_dissolve_delay_to_vote,
                neuron_maximum_dissolve_delay,
                neuron_maximum_dissolve_delay_bonus,
                neuron_maximum_age_for_age_bonus,
                neuron_maximum_age_bonus,

                voting_reward_parameters,
            })
        };

        let result = CreateServiceNervousSystem {
            name,
            description,
            url,
            logo,

            fallback_controller_principal_ids,
            dapp_canisters,

            initial_token_distribution,

            swap_parameters,
            ledger_parameters,
            governance_parameters,
        };

        // TODO migrate validation out of SnsInitPayload so we no longer have to support ic_nns_gov types
        SnsInitPayload::try_from(result.clone())?;

        Ok(result)
    }
}

impl ProposalTitle for ProposeToCreateServiceNervousSystemCmd {
    fn title(&self) -> String {
        format!("Create a New Service Nervous System: {}", self.name)
    }
}

async fn propose_to_create_service_nervous_system(
    cmd: ProposeToCreateServiceNervousSystemCmd,
    agent: Agent,
    proposer: NeuronId,
) {
    let is_dry_run = cmd.is_dry_run();

    let action = Some(ProposalActionRequest::CreateServiceNervousSystem(
        CreateServiceNervousSystem::try_from(cmd.clone()).unwrap(),
    ));
    let title = cmd.title();
    let summary = cmd.summary.clone().unwrap();
    let url = parse_proposal_url(&cmd.proposal_url);
    let proposal = MakeProposalRequest {
        title: Some(title.clone()),
        summary,
        url,
        action,
    };
    print_proposal(&proposal, &cmd);

    if is_dry_run {
        return;
    }

    let canister_client = GovernanceCanisterClient(NnsCanisterClient::new(
        agent,
        GOVERNANCE_CANISTER_ID,
        Some(proposer),
    ));
    let response = canister_client
        .submit_external_proposal(&create_make_proposal_payload(proposal, &proposer), &title)
        .await;

    match response {
        Ok(ok) => {
            println!("{ok:#?}");
        }
        Err(err) => {
            eprintln!("propose_to_create_service_nervous_system error: {err:?}");
            std::process::exit(1);
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToUpdateElectedHostosVersionsCmd {}

/// Sub-command to change the set of currently elected HostOS versions.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToReviseElectedHostosVersionsCmd {
    #[clap(long)]
    /// The HostOS version ID to elect.
    pub hostos_version_to_elect: Option<String>,

    #[clap(long)]
    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_urls'.
    pub release_package_sha256_hex: Option<String>,

    #[clap(long, num_args(1..))]
    /// The URLs against which an HTTP GET request will return a release
    /// package that corresponds to this version.
    pub release_package_urls: Vec<String>,

    #[clap(long, num_args(1..))]
    /// The HostOS version ids to remove.
    pub hostos_versions_to_unelect: Vec<String>,
}

impl ProposalTitle for ProposeToReviseElectedHostosVersionsCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match self.hostos_version_to_elect.as_ref() {
                Some(v) => format!("Elect new HostOS binary revision (commit {v})"),
                None => "Retire IC HostOS version(s)".to_string(),
            },
        }
    }
}

#[async_trait]
impl ProposalPayload<ReviseElectedHostosVersionsPayload>
    for ProposeToReviseElectedHostosVersionsCmd
{
    async fn payload(&self, _: &Agent) -> ReviseElectedHostosVersionsPayload {
        let payload = ReviseElectedHostosVersionsPayload {
            hostos_version_to_elect: self.hostos_version_to_elect.clone(),
            release_package_sha256_hex: self.release_package_sha256_hex.clone(),
            release_package_urls: self.release_package_urls.clone(),
            hostos_versions_to_unelect: self.hostos_versions_to_unelect.clone(),
        };
        payload.validate().expect("Failed to validate payload");
        payload
    }
}

/// Sub-command to deploy a HostOS version to a set of nodes.
#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToDeployHostosToSomeNodesCmd {
    /// The list of nodes on which to set the given HostosVersion
    #[clap(name = "NODE_ID", num_args(1..), required = true)]
    pub node_ids: Vec<PrincipalId>,

    #[clap(flatten)]
    pub hostos_version_flag: HostosVersionFlag,
}

#[derive(Args)]
struct HostosVersionFlag {
    /// Version ID. This should correspond to a HostOS version previously added
    /// to the registry.
    #[clap(long)]
    pub hostos_version_id: Option<String>,
    /// When this flag is passed, remove the HostOS version from this set of
    /// Nodes. This will take the same action as excluding the version id flag.
    #[clap(long)]
    pub clear_hostos_version: bool,
}

impl HostosVersionFlag {
    // TODO: If we upgrade clap, this can be replaced with `group` attributes.
    fn simplify(&self) -> &Option<String> {
        if self.hostos_version_id.is_some() && self.clear_hostos_version {
            panic!(
                "Only one of --hostos-version-id or --clear-hostos-version can be specified at once."
            );
        }

        // When `--clear-hostos-version` is set, `--hostos-version-id` must be
        // unset and `None`, so we can always return it directly.
        &self.hostos_version_id
    }
}

impl ProposalTitle for ProposeToDeployHostosToSomeNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => match &self.hostos_version_flag.simplify() {
                Some(hostos_version_id) => format!(
                    "Set HostOS version: '{}' on nodes: '{}'",
                    hostos_version_id,
                    shortened_pids_string(&self.node_ids)
                ),
                None => format!(
                    "Unsetting HostOS version on nodes: '{}'",
                    shortened_pids_string(&self.node_ids)
                ),
            },
        }
    }
}

#[async_trait]
impl ProposalPayload<DeployHostosToSomeNodes> for ProposeToDeployHostosToSomeNodesCmd {
    async fn payload(&self, _: &Agent) -> DeployHostosToSomeNodes {
        let node_ids = self
            .node_ids
            .clone()
            .into_iter()
            .map(NodeId::from)
            .collect();

        DeployHostosToSomeNodes {
            node_ids,
            hostos_version_id: self.hostos_version_flag.simplify().clone(),
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToAddApiBoundaryNodesCmd {
    #[clap(long, required = true, num_args(1..), alias = "node-ids")]
    /// The nodes to assign as an API Boundary Node
    nodes: Vec<PrincipalId>,

    #[clap(long, required = true, alias = "version-id")]
    /// The version the API Boundary Node will use
    version: String,
}

impl ProposalTitle for ProposeToAddApiBoundaryNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Add API Boundary Nodes {}",
                self.nodes
                    .iter()
                    .map(|id| format!("{id}"))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<AddApiBoundaryNodesPayload> for ProposeToAddApiBoundaryNodesCmd {
    async fn payload(&self, _: &Agent) -> AddApiBoundaryNodesPayload {
        AddApiBoundaryNodesPayload {
            node_ids: self.nodes.iter().cloned().map(NodeId::from).collect(),
            version: self.version.clone(),
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToRemoveApiBoundaryNodesCmd {
    #[clap(long, required = true, num_args(1..), alias = "node-ids")]
    /// The set of API Boundary Nodes that should be returned to an unassigned state
    nodes: Vec<PrincipalId>,
}

impl ProposalTitle for ProposeToRemoveApiBoundaryNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Remove API Boundary Nodes {}",
                self.nodes
                    .iter()
                    .map(|id| format!("{id}"))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<RemoveApiBoundaryNodesPayload> for ProposeToRemoveApiBoundaryNodesCmd {
    async fn payload(&self, _: &Agent) -> RemoveApiBoundaryNodesPayload {
        RemoveApiBoundaryNodesPayload {
            node_ids: self.nodes.iter().cloned().map(NodeId::from).collect(),
        }
    }
}

#[derive_common_proposal_fields]
#[derive(Parser, ProposalMetadata)]
struct ProposeToDeployGuestosToSomeApiBoundaryNodesCmd {
    #[clap(long, required = true, num_args(1..), alias = "node-ids")]
    /// The set of API Boundary Nodes that should have their version updated
    nodes: Vec<PrincipalId>,

    #[clap(long, required = true, alias = "version-id")]
    /// The version that the set of API Boundary Node will use
    version: String,
}

impl ProposalTitle for ProposeToDeployGuestosToSomeApiBoundaryNodesCmd {
    fn title(&self) -> String {
        match &self.proposal_title {
            Some(title) => title.clone(),
            None => format!(
                "Update API Boundary Nodes Version {}",
                self.nodes
                    .iter()
                    .map(|id| format!("{id}"))
                    .collect::<Vec<String>>()
                    .join(", "),
            ),
        }
    }
}

#[async_trait]
impl ProposalPayload<DeployGuestosToSomeApiBoundaryNodes>
    for ProposeToDeployGuestosToSomeApiBoundaryNodesCmd
{
    async fn payload(&self, _: &Agent) -> DeployGuestosToSomeApiBoundaryNodes {
        DeployGuestosToSomeApiBoundaryNodes {
            node_ids: self.nodes.iter().cloned().map(NodeId::from).collect(),
            version: self.version.clone(),
        }
    }
}

/// Sub-command to fetch an API Boundary Node record from the registry.
#[derive(Parser)]
struct GetApiBoundaryNodeCmd {
    /// The node id
    node_id: PrincipalId,
}

async fn get_firewall_rules_from_registry(
    registry_canister: &RegistryCanister,
    scope: &FirewallRulesScope,
) -> Vec<FirewallRule> {
    let registry_answer = registry_canister
        .get_value_with_update(make_firewall_rules_record_key(scope).into_bytes(), None)
        .await;

    if let Ok((bytes, _)) = registry_answer {
        let ruleset = deserialize_registry_value::<FirewallRuleSet>(Ok(Some(bytes)))
            .unwrap()
            .unwrap();
        ruleset.entries
    } else {
        vec![]
    }
}

/// Utility function to convert a Url to a host:port string.
fn url_to_host_with_port(url: Url) -> String {
    let host = url.host_str().unwrap_or("");
    let host = if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        // Likely an IPv6 address, enclose in brackets
        format!("[{host}]")
    } else {
        // IPv4 or hostname
        host.to_string()
    };
    let port = url.port_or_known_default().unwrap_or(8080);

    format!("{host}:{port}")
}

/// Utility function to find NNS URLs that the local machine can connect to.
async fn find_reachable_nns_urls(nns_urls: Vec<Url>) -> Vec<Url> {
    // Early return, otherwise `futures::future::select_all` will panic without a good error
    // message.
    if nns_urls.is_empty() {
        return Vec::new();
    }

    let retries_max = 3;
    let timeout_duration = tokio::time::Duration::from_secs(10);

    for i in 1..=retries_max {
        let tasks: Vec<_> = nns_urls
            .iter()
            .map(|url| {
                Box::pin(async move {
                    let host_with_port = url_to_host_with_port(url.clone());

                    match tokio::net::lookup_host(host_with_port.clone()).await {
                        Ok(ips) => {
                            for ip in ips {
                                match tokio::time::timeout(
                                    timeout_duration,
                                    tokio::net::TcpStream::connect(ip),
                                )
                                .await
                                {
                                    Ok(connection) => match connection {
                                        Ok(_) => return Some(url.clone()),
                                        Err(err) => {
                                            eprintln!(
                                                "WARNING: Failed to connect to {ip}: {err:?}"
                                            );
                                        }
                                    },
                                    Err(err) => {
                                        eprintln!("WARNING: Failed to connect to {ip}: {err:?}");
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("WARNING: Failed to lookup {host_with_port}: {err:?}");
                        }
                    }
                    None
                })
            })
            .collect();

        // Wait for the first task to complete ==> until we have a reachable NNS URL.
        // select_all returns the completed future at position 0, and the remaining futures at position 2.
        let (completed_task, _, remaining_tasks) = futures::future::select_all(tasks).await;
        match completed_task {
            Some(url) => return vec![url],
            None => {
                for task in remaining_tasks {
                    if let Some(url) = task.await {
                        return vec![url];
                    }
                }
                eprintln!(
                    "WARNING: None of the provided NNS urls are reachable. Retrying in 5 seconds... ({i}/{retries_max})"
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }

    Vec::new()
}

/// `main()` method for the `ic-admin` utility.
#[tokio::main]
async fn main() {
    let matches = Opts::command().version(env!("VERSION")).get_matches();
    let opts = Opts::from_arg_matches(&matches).unwrap();

    let reachable_nns_urls = find_reachable_nns_urls(opts.nns_urls.clone()).await;

    if reachable_nns_urls.is_empty() {
        panic!("None of the provided NNS urls are reachable");
    } else {
        eprintln!(
            "Using NNS URLs: {:?}",
            reachable_nns_urls
                .iter()
                .map(|url| url.as_str())
                .collect::<Vec<_>>()
        );
    }

    let sender = if opts.secret_key_pem.is_some() || opts.use_hsm {
        // Make sure to let the user know that we only actually use the sender
        // in methods that go through the NNS handlers and not for other methods.
        //
        // TODO(NNS1-486): Remove ic-admin command whitelist for sender
        match opts.subcmd {
            SubCommand::ProposeToAddApiBoundaryNodes(_) => (),
            SubCommand::ProposeToAddFirewallRules(_) => (),
            SubCommand::ProposeToAddNnsCanister(_) => (),
            SubCommand::ProposeToAddNodeOperator(_) => (),
            SubCommand::ProposeToAddOrRemoveDataCenters(_) => (),
            SubCommand::ProposeToAddOrRemoveNodeProvider(_) => (),
            SubCommand::ProposeToAddWasmToSnsWasm(_) => (),
            SubCommand::ProposeToChangeNnsCanister(_) => (),
            SubCommand::ProposeToChangeSubnetMembership(_) => (),
            SubCommand::ProposeToChangeSubnetTypeAssignment(_) => (),
            SubCommand::ProposeToClearProvisionalWhitelist(_) => (),
            SubCommand::ProposeToCompleteCanisterMigration(_) => (),
            SubCommand::ProposeToCreateServiceNervousSystem(_) => (),
            SubCommand::ProposeToCreateSubnet(_) => (),
            SubCommand::ProposeToDeployGuestosToAllSubnetNodes(_) => (),
            SubCommand::ProposeToDeployGuestosToAllUnassignedNodes(_) => (),
            SubCommand::ProposeToDeployGuestosToSomeApiBoundaryNodes(_) => (),
            SubCommand::ProposeToDeployHostosToSomeNodes(_) => (),
            SubCommand::ProposeToHardResetNnsRootToVersion(_) => (),
            SubCommand::ProposeToInsertSnsWasmUpgradePathEntries(_) => (),
            SubCommand::ProposeToPrepareCanisterMigration(_) => (),
            SubCommand::ProposeToRemoveApiBoundaryNodes(_) => (),
            SubCommand::ProposeToRemoveFirewallRules(_) => (),
            SubCommand::ProposeToRemoveNodeOperators(_) => (),
            SubCommand::ProposeToRemoveNodes(_) => (),
            SubCommand::ProposeToRentSubnet(_) => (),
            SubCommand::ProposeToFulfillSubnetRentalRequest(_) => (),
            SubCommand::ProposeToRerouteCanisterRanges(_) => (),
            SubCommand::ProposeToReviseElectedGuestosVersions(_) => (),
            SubCommand::ProposeToReviseElectedHostosVersions(_) => (),
            SubCommand::ProposeToSetAuthorizedSubnetworks(_) => (),
            SubCommand::ProposeToSetBitcoinConfig(_) => (),
            SubCommand::ProposeToSetFirewallConfig(_) => (),
            SubCommand::ProposeToStartCanister(_) => (),
            SubCommand::ProposeToStopCanister(_) => (),
            SubCommand::ProposeToTakeSubnetOfflineForRepairs(_) => (),
            SubCommand::ProposeToUninstallCode(_) => (),
            SubCommand::ProposeToUpdateCanisterSettings(_) => (),
            SubCommand::ProposeToUpdateFirewallRules(_) => (),
            SubCommand::ProposeToUpdateNodeOperatorConfig(_) => (),
            SubCommand::ProposeToUpdateNodeRewardsTable(_) => (),
            SubCommand::ProposeToUpdateRecoveryCup(_) => (),
            SubCommand::ProposeToUpdateSnsDeployWhitelist(_) => (),
            SubCommand::ProposeToUpdateSnsSubnetIdsInSnsWasm(_) => (),
            SubCommand::ProposeToUpdateSshReadonlyAccessForAllUnassignedNodes(_) => (),
            SubCommand::ProposeToUpdateSubnet(_) => (),
            SubCommand::ProposeToUpdateSubnetType(_) => (),
            SubCommand::ProposeToUpdateXdrIcpConversionRate(_) => (),
            SubCommand::SubmitRootProposalToUpgradeGovernanceCanister(_) => (),
            SubCommand::SwapNodeInSubnetDirectly(_) => (),
            SubCommand::VoteOnRootProposalToUpgradeGovernanceCanister(_) => (),
            _ => panic!(
                "Specifying a secret key or HSM is only supported for \
                     methods that interact with NNS handlers."
            ),
        }

        if opts.secret_key_pem.is_some() {
            let secret_key_path = opts.secret_key_pem.unwrap();
            let contents = read_to_string(secret_key_path).expect("Could not read key file");
            let sig_keys = SigKeys::from_pem(&contents).expect("Failed to parse pem file");
            Sender::SigKeys(sig_keys)
        } else if opts.use_hsm {
            make_hsm_sender(
                &opts.hsm_slot.expect(
                    "HSM slot must also be provided for --use-hsm; use --hsm-slot or see --help.",
                ),
                &opts.hsm_key_id.expect(
                    "HSM key ID must also be provided for --use-hsm; use --key-id or see --help.",
                ),
                &opts.hsm_pin.expect(
                    "HSM pin must also be provided for --use-hsm; use --pin or see --help.",
                ),
            )
        } else {
            Sender::Anonymous
        }
    } else {
        Sender::Anonymous
    };

    let registry_canister = RegistryCanister::new_with_agent(make_canister_client(
        reachable_nns_urls.clone(),
        opts.verify_nns_responses,
        opts.nns_public_key_pem_file.clone(),
        sender.clone(),
    ));

    match opts.subcmd {
        SubCommand::GetPublicKey(get_pk_cmd) => {
            let node_id = NodeId::from(get_pk_cmd.node_id);
            print_and_get_last_value::<PublicKey>(
                make_crypto_node_key(node_id, get_pk_cmd.key_purpose)
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetTlsCertificate(get_cert_cmd) => {
            let node_id = NodeId::from(get_cert_cmd.node_id);
            print_and_get_last_value::<X509PublicKeyCert>(
                make_crypto_tls_cert_key(node_id).as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetNode(get_node_cmd) => {
            let node_id = NodeId::from(get_node_cmd.node_id);
            print_and_get_last_value::<NodeRecord>(
                make_node_record_key(node_id).as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetNodeListSince(cmd) => {
            let node_records = get_node_list_since(cmd.version, &registry_canister).await;

            let res = serde_json::to_string(&node_records)
                .unwrap_or_else(|_| "Could not serialize node_records".to_string());
            println!("{res}");
        }

        SubCommand::GetTopology => {
            // Because ic-admin codebase is riddled with bad patterns -- most notably, all
            // get/fetch methods also print out the representation of the
            // data, there is no nice way to print the whole topology.
            // Instead, we print the surrounding structure in a not so nice way
            // and delegate pretty-printing to jq or other consumers.
            // This method is slow, as each fetch needs to happen in sequence (due to
            // printing from it).
            //
            // Fetch a list of all nodes, with IP addresses and other details
            let all_nodes_with_details = get_node_list_since(0, &registry_canister).await;
            let mut seen: HashSet<NodeId> = HashSet::new();

            #[derive(Serialize)]
            struct Topology {
                // IndexMap preserves the insertion order
                subnets: IndexMap<SubnetId, SubnetRecord>,
                api_boundary_nodes: Vec<NodeId>,
                unassigned_nodes: IndexMap<NodeId, NodeDetails>,
            }
            let mut topology = Topology {
                subnets: IndexMap::new(),
                api_boundary_nodes: Vec::new(),
                unassigned_nodes: IndexMap::new(),
            };
            eprintln!("INFO: Fetching subnets...");
            let subnet_ids = get_subnet_ids(&registry_canister).await;
            for subnet_id in subnet_ids.into_iter() {
                let subnet_record = get_subnet_record_with_details(
                    subnet_id,
                    &registry_canister,
                    &all_nodes_with_details,
                )
                .await;
                topology.subnets.insert(subnet_id, subnet_record.clone());

                for node in subnet_record
                    .membership
                    .iter()
                    .map(|n| NodeId::from(PrincipalId::from_str(n).unwrap()))
                {
                    seen.insert(node);
                }
            }
            eprintln!("INFO: Fetching API Boundary nodes...");
            // list all API Boundary Nodes
            let api_bn_node_ids = get_api_boundary_node_ids(reachable_nns_urls.clone())
                .iter()
                .map(|n| NodeId::from(PrincipalId::from_str(n).unwrap()))
                .collect();
            seen.extend(&api_bn_node_ids);
            topology.api_boundary_nodes = api_bn_node_ids;

            // all remaining nodes are unassigned nodes
            topology.unassigned_nodes = all_nodes_with_details
                .into_iter()
                .filter_map(|(node_id, node_details)| {
                    let node_id = NodeId::from(node_id);
                    if seen.contains(&node_id) {
                        None
                    } else {
                        Some((node_id, node_details))
                    }
                })
                .collect::<IndexMap<_, _>>();
            println!("{}", serde_json::to_string_pretty(&topology).unwrap());
        }
        SubCommand::ConvertNumericNodeIdToPrincipalId(
            convert_numeric_node_id_to_principal_id_cmd,
        ) => {
            let node_id = NodeId::from(PrincipalId::new_node_test_id(
                convert_numeric_node_id_to_principal_id_cmd.node_id,
            ));
            println!("{node_id}");
        }
        SubCommand::GetSubnet(get_subnet_cmd) => {
            let subnet_id = get_subnet_cmd.subnet.get_id(&registry_canister).await;
            print_and_get_last_value::<SubnetRecordProto>(
                make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetSubnetList => {
            let value: Vec<_> = registry_canister
                .get_value_with_update(make_subnet_list_record_key().as_bytes().to_vec(), None)
                .await
                .map(|(bytes, _version)| SubnetListRecord::decode(&bytes[..]).unwrap())
                .unwrap()
                .subnets
                .into_iter()
                .map(|id_vec| format!("{:?}", PrincipalId::try_from(id_vec).unwrap()))
                .collect();
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        SubCommand::GetGuestOSVersion(get_guestos_version_cmd) => {
            let key = make_replica_version_key(&get_guestos_version_cmd.guestos_version_id)
                .as_bytes()
                .to_vec();
            let version = print_and_get_last_value::<ReplicaVersionRecord>(
                key,
                &registry_canister,
                opts.json,
            )
            .await;

            let mut success = true;

            eprintln!("Download IC-OS .. ");
            let tmp_dir = tempfile::tempdir().unwrap().keep();
            let mut tmp_file = tmp_dir.clone();
            tmp_file.push("temp-image");

            // Download the IC-OS upgrade, do not check sha256 yet, we will do that
            // explicitly later
            let file_downloader = FileDownloader::new(None);

            let mut result = Err(anyhow!("Download of release package failed."));
            for url in version.release_package_urls.iter() {
                result = file_downloader
                    .download_file(url, &tmp_file, None)
                    .await
                    .map_err(|v| v.into());

                if result.is_ok() {
                    break;
                }
            }
            result.unwrap();

            println!("OK   Download success");

            // Explicitly check sha256 sum again, just to make sure and make the output a
            // bit nicer
            match check_file_hash(&tmp_file, &version.release_package_sha256_hex) {
                Ok(()) => println!("OK   sha256 hash of IC-OS upgrade tar"),
                Err(e) => {
                    println!("FAIL sha256 incorrect: {e:?}");
                    success = false;
                }
            };

            if !success {
                exit(1);
            }
        }
        SubCommand::ProposeToDeployGuestosToAllSubnetNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::DeployGuestosToAllSubnetNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetElectedGuestosVersions => {
            print_and_get_last_value::<BlessedReplicaVersions>(
                make_blessed_replica_versions_key().as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetRoutingTable => {
            let (routing_table, version) = get_routing_table(reachable_nns_urls);
            if opts.json {
                let routing_table_json = serde_json::to_string_pretty(&routing_table).unwrap();
                println!("{}", routing_table_json);
            } else {
                print_routing_table(&routing_table, version);
            }
        }
        SubCommand::GetEcdsaSigningSubnets => {
            let registry_client = make_registry_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
            );

            // maximum number of retries, let the user ctrl+c if necessary
            registry_client
                .try_polling_latest_version(usize::MAX)
                .unwrap();

            let signing_subnets = registry_client
                .get_ecdsa_signing_subnets(registry_client.get_latest_version())
                .unwrap()
                .unwrap();
            for (key_id, subnets) in signing_subnets.iter() {
                println!("KeyId {key_id:?}: {subnets:?}");
            }
        }
        SubCommand::GetChainKeySigningSubnets => {
            let registry_client = make_registry_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
            );

            // maximum number of retries, let the user ctrl+c if necessary
            registry_client
                .try_polling_latest_version(usize::MAX)
                .unwrap();

            let chain_key_enabled_subnets = registry_client
                .get_chain_key_enabled_subnets(registry_client.get_latest_version())
                .unwrap()
                .unwrap();
            for (key_id, subnets) in chain_key_enabled_subnets.iter() {
                println!("KeyId {key_id:?}: {subnets:?}");
            }
        }
        SubCommand::ProposeToReviseElectedGuestosVersions(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ReviseElectedGuestosVersions,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToCreateSubnet(mut cmd) => {
            cmd.apply_defaults_for_unset_fields();
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::CreateSubnet,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToCreateServiceNervousSystem(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_to_create_service_nervous_system(
                cmd,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToChangeSubnetMembership(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            if !opts.silence_notices {
                println!(
                    "Notice: invoking this command can undesirably worsen the decentralization."
                );
                println!(
                    "Notice: Consider using instead the DRE tool https://dfinity.github.io/dre/ to submit this proposal"
                )
            }
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ChangeSubnetMembership,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateRecoveryCup(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RecoverSubnet,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSubnet(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateConfigOfSubnet,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToAddNnsCanister(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::NnsCanisterInstall,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToChangeNnsCanister(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            let canister_client = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            propose_action_from_command(cmd, canister_client, proposer).await;
        }
        SubCommand::ProposeToHardResetNnsRootToVersion(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command::<
                HardResetNnsRootToVersionPayload,
                ProposeToHardResetNnsRootToVersionCmd,
            >(
                cmd,
                NnsFunction::HardResetNnsRootToVersion,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUninstallCode(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UninstallCode,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateXdrIcpConversionRate(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::IcpXdrConversionRate,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToStartCanister(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            let canister_client = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            propose_action_from_command(cmd, canister_client, proposer).await;
        }
        SubCommand::ProposeToStopCanister(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            let canister_client = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            propose_action_from_command(cmd, canister_client, proposer).await;
        }
        SubCommand::ProposeToClearProvisionalWhitelist(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ClearProvisionalWhitelist,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToSetAuthorizedSubnetworks(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetAuthorizedSubnetworks,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSubnetType(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateSubnetType,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToChangeSubnetTypeAssignment(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ChangeSubnetTypeAssignment,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetProvisionalWhitelist => {
            print_and_get_last_value::<ProvisionalWhitelistProto>(
                make_provisional_whitelist_record_key().as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetSubnetPublicKey(cmd) => {
            store_subnet_pk(&registry_canister, cmd.subnet, cmd.target_path.as_path()).await;
        }
        SubCommand::ProposeToRemoveNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RemoveNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToAddNodeOperator(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AssignNoid,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetNodeOperator(cmd) => {
            let key = make_node_operator_record_key(cmd.node_operator_principal_id)
                .as_bytes()
                .to_vec();

            print_and_get_last_value::<NodeOperatorRecord>(key, &registry_canister, opts.json)
                .await;
        }
        SubCommand::GetNodeOperatorList => {
            let registry_client = RegistryClientImpl::new(
                Arc::new(NnsDataProvider::new(
                    tokio::runtime::Handle::current(),
                    reachable_nns_urls.clone(),
                )),
                None,
            );

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

            let records = keys
                .iter()
                .map(|k| k.strip_prefix(NODE_OPERATOR_RECORD_KEY_PREFIX).unwrap())
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&records)
                    .expect("Failed to serialize the records to JSON")
            );
        }
        SubCommand::UpdateRegistryLocalStore(cmd) => {
            update_registry_local_store(reachable_nns_urls, cmd).await;
        }
        SubCommand::ProposeToUpdateNodeOperatorConfig(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateNodeOperatorConfig,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetFirewallConfig => {
            let key = make_firewall_config_record_key();
            let (bytes, _) = registry_canister
                .get_value_with_update(key.into(), None)
                .await
                .unwrap();

            let firewall_config = FirewallConfig::decode(bytes.as_slice()).unwrap();
            println!("{firewall_config:#?}");
        }
        SubCommand::ProposeToSetFirewallConfig(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetFirewallConfig,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToAddFirewallRules(cmd) => {
            if cmd.test {
                test_add_firewall_rules(cmd, &registry_canister).await;
            } else {
                let (proposer, sender) = cmd.proposer_and_sender(sender);
                propose_external_proposal_from_command(
                    cmd,
                    NnsFunction::AddFirewallRules,
                    make_canister_client(
                        reachable_nns_urls,
                        opts.verify_nns_responses,
                        opts.nns_public_key_pem_file,
                        sender,
                    ),
                    proposer,
                )
                .await;
            }
        }
        SubCommand::ProposeToRemoveFirewallRules(cmd) => {
            if cmd.test {
                test_remove_firewall_rules(cmd, &registry_canister).await;
            } else {
                let (proposer, sender) = cmd.proposer_and_sender(sender);
                propose_external_proposal_from_command(
                    cmd,
                    NnsFunction::RemoveFirewallRules,
                    make_canister_client(
                        reachable_nns_urls,
                        opts.verify_nns_responses,
                        opts.nns_public_key_pem_file,
                        sender,
                    ),
                    proposer,
                )
                .await;
            }
        }
        SubCommand::ProposeToUpdateFirewallRules(cmd) => {
            if cmd.test {
                test_update_firewall_rules(cmd, &registry_canister).await;
            } else {
                let (proposer, sender) = cmd.proposer_and_sender(sender);
                propose_external_proposal_from_command(
                    cmd,
                    NnsFunction::UpdateFirewallRules,
                    make_canister_client(
                        reachable_nns_urls,
                        opts.verify_nns_responses,
                        opts.nns_public_key_pem_file,
                        sender,
                    ),
                    proposer,
                )
                .await;
            }
        }
        SubCommand::GetFirewallRules(cmd) => {
            get_firewall_rules(cmd, &registry_canister).await;
        }
        SubCommand::GetFirewallRulesForNode(cmd) => {
            get_firewall_rules_for_node(cmd, &registry_canister, reachable_nns_urls).await;
        }
        SubCommand::GetFirewallRulesetHash(cmd) => {
            get_firewall_ruleset_hash(cmd);
        }
        SubCommand::ProposeToAddOrRemoveNodeProvider(cmd) => {
            let (proposer, sender) =
                get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
            propose_to_add_or_remove_node_provider(
                cmd,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await
        }
        SubCommand::GetRegistryVersion => {
            let latest_version = registry_canister.get_latest_version().await.unwrap();
            println!("{latest_version}")
        }
        SubCommand::SubmitRootProposalToUpgradeGovernanceCanister(cmd) => {
            let sender = get_test_sender_if_set(sender, cmd.test_user_proposer);
            submit_root_proposal_to_upgrade_governance_canister(
                cmd,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
            )
            .await
        }
        SubCommand::SwapNodeInSubnetDirectly(cmd) => {
            swap_node_in_subnet_directly(registry_canister, cmd).await;
        }
        SubCommand::GetPendingRootProposalsToUpgradeGovernanceCanister => {
            get_pending_root_proposals_to_upgrade_governance_canister(make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            ))
            .await
        }
        SubCommand::VoteOnRootProposalToUpgradeGovernanceCanister(cmd) => {
            let sender = get_test_sender_if_set(sender, cmd.test_user_voter);
            vote_on_root_proposal_to_upgrade_governance_canister(
                cmd,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
            )
            .await
        }
        SubCommand::GetDataCenter(cmd) => {
            print_and_get_last_value::<DataCenterRecord>(
                make_data_center_record_key(&cmd.dc_id)
                    .into_bytes()
                    .to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::ProposeToAddOrRemoveDataCenters(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AddOrRemoveDataCenters,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetNodeRewardsTable => {
            let (bytes, _) = registry_canister
                .get_value_with_update(NODE_REWARDS_TABLE_KEY.as_bytes().to_vec(), None)
                .await
                .unwrap();

            // We re-create the rewards structs here in order to convert the output of get-rewards-table into the format
            // that can also be parsed by propose-to-update-node-rewards-table.
            // This is a bit of a hack, but it's the easiest way to get the desired output.
            // A more proper way would be to adjust the upstream structs to flatten the "rates" and "table" fields
            // directly, but this breaks some of the candid encoding and decoding and also some of the tests.
            // Make sure to keep these structs in sync with the upstream ones.
            #[derive(PartialEq, ::prost::Message, serde::Serialize)]
            pub struct NodeRewardRateFlattened {
                #[prost(uint64, tag = "1")]
                pub xdr_permyriad_per_node_per_month: u64,
                #[prost(int32, optional, tag = "2")]
                #[serde(skip_serializing_if = "Option::is_none")]
                pub reward_coefficient_percent: Option<i32>,
            }

            #[derive(PartialEq, ::prost::Message, serde::Serialize)]
            pub struct NodeRewardRatesFlattened {
                #[prost(btree_map = "string, message", tag = "1")]
                #[serde(flatten)]
                pub rates: BTreeMap<String, NodeRewardRateFlattened>,
            }

            #[derive(PartialEq, ::prost::Message, serde::Serialize)]
            pub struct NodeRewardsTableFlattened {
                #[prost(btree_map = "string, message", tag = "1")]
                #[serde(flatten)]
                pub table: BTreeMap<String, NodeRewardRatesFlattened>,
            }

            let table = NodeRewardsTableFlattened::decode(bytes.as_slice()).unwrap();
            println!(
                "{}",
                serde_json::to_string_pretty(&table)
                    .expect("Failed to serialize the rewards table to JSON")
            );
        }
        SubCommand::ProposeToUpdateNodeRewardsTable(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateNodeRewardsTable,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToDeployGuestosToAllUnassignedNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::DeployGuestosToAllUnassignedNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSshReadonlyAccessForAllUnassignedNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetUnassignedNodes => {
            print_and_get_last_value::<UnassignedNodesConfigRecord>(
                make_unassigned_nodes_config_record_key()
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetMonthlyNodeProviderRewards => {
            let canister_client = GovernanceCanisterClient(NnsCanisterClient::new(
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                GOVERNANCE_CANISTER_ID,
                None,
            ));

            let response = canister_client.get_monthly_node_provider_rewards().await;
            println!("{response:?}");
        }
        SubCommand::ProposeToRemoveNodeOperators(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RemoveNodeOperators,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToRerouteCanisterRanges(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RerouteCanisterRanges,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToPrepareCanisterMigration(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::PrepareCanisterMigration,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToCompleteCanisterMigration(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::CompleteCanisterMigration,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetCanisterMigrations => {
            print_and_get_last_value::<CanisterMigrations>(
                make_canister_migrations_record_key().as_bytes().to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::ProposeToAddWasmToSnsWasm(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AddSnsWasm,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSnsSubnetIdsInSnsWasm(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateSnsWasmSnsSubnetIds,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToUpdateSnsDeployWhitelist(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::UpdateAllowedPrincipals,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToInsertSnsWasmUpgradePathEntries(cmd) => {
            let (proposer, sender) =
                get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);

            let agent = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            // Custom rendering to make it easier to debug your command
            if cmd.is_dry_run() {
                let payload = cmd.payload(&agent).await;
                print_insert_sns_wasm_upgrade_path_entries_payload(payload);
                return;
            }

            propose_external_proposal_from_command(
                cmd,
                NnsFunction::InsertSnsWasmUpgradePathEntries,
                agent,
                proposer,
            )
            .await
        }
        SubCommand::ProposeToSetBitcoinConfig(cmd) => {
            let (proposer, sender) =
                get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
            propose_external_proposal_from_command::<
                BitcoinSetConfigProposal,
                ProposeToSetBitcoinConfig,
            >(
                cmd,
                NnsFunction::BitcoinSetConfig,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToReviseElectedHostosVersions(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::ReviseElectedHostosVersions,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToDeployHostosToSomeNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::DeployHostosToSomeNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetElectedHostosVersions => {
            let registry_client = RegistryClientImpl::new(
                Arc::new(NnsDataProvider::new(
                    tokio::runtime::Handle::current(),
                    reachable_nns_urls.clone(),
                )),
                None,
            );

            // maximum number of retries, let the user ctrl+c if necessary
            registry_client
                .try_polling_latest_version(usize::MAX)
                .unwrap();

            let hostos_versions = registry_client
                .get_hostos_versions(registry_client.get_latest_version())
                .unwrap();

            if let Some(hostos_versions) = hostos_versions {
                for version in hostos_versions {
                    println!("{}", version.hostos_version_id);
                }
            }
        }
        SubCommand::ProposeToAddApiBoundaryNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::AddApiBoundaryNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToRemoveApiBoundaryNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::RemoveApiBoundaryNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToDeployGuestosToSomeApiBoundaryNodes(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::DeployGuestosToSomeApiBoundaryNodes,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::GetApiBoundaryNode(cmd) => {
            print_and_get_last_value::<ApiBoundaryNodeRecord>(
                make_api_boundary_node_record_key(cmd.node_id.into())
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
                opts.json,
            )
            .await;
        }
        SubCommand::GetApiBoundaryNodes => {
            let records = get_api_boundary_node_ids(reachable_nns_urls.clone());
            println!(
                "{}",
                serde_json::to_string_pretty(&records)
                    .expect("Failed to serialize the records to JSON")
            );
        }
        SubCommand::ProposeToRentSubnet(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SubnetRentalRequest,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToFulfillSubnetRentalRequest(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            let canister_client = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            propose_action_from_command(cmd, canister_client, proposer).await;
        }
        SubCommand::ProposeToUpdateCanisterSettings(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            let canister_client = make_canister_client(
                reachable_nns_urls,
                opts.verify_nns_responses,
                opts.nns_public_key_pem_file,
                sender,
            );
            propose_action_from_command(cmd, canister_client, proposer).await;
        }
        SubCommand::ProposeToTakeSubnetOfflineForRepairs(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetSubnetOperationalLevel,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
        SubCommand::ProposeToBringSubnetBackOnlineAfterRepairs(cmd) => {
            let (proposer, sender) = cmd.proposer_and_sender(sender);
            propose_external_proposal_from_command(
                cmd,
                NnsFunction::SetSubnetOperationalLevel,
                make_canister_client(
                    reachable_nns_urls,
                    opts.verify_nns_responses,
                    opts.nns_public_key_pem_file,
                    sender,
                ),
                proposer,
            )
            .await;
        }
    }
}

/// Reads (fully) the file in `path` and returns it's contents as a Vec<u8>.
fn read_file_fully(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|_| panic!("Value file not found at: {path:?}"));
    let metadata = metadata(path).expect("Unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read the content of {path:?}"));
    buffer
}

fn print_value<T: Debug + serde::Serialize>(key: &String, version: u64, value: T, as_json: bool) {
    if as_json {
        #[derive(Serialize)]
        struct Entry<T> {
            key: String,
            version: u64,
            value: T,
        }

        let data = Entry {
            key: key.clone(),
            version,
            value,
        };
        println!("{}", serde_json::to_string_pretty(&data).unwrap());
    } else {
        // Dump as debug representation
        println!("Fetching the most recent value for key: {key}");
        println!("Most recent version is {version:?}. Value:\n{value:?}");
    }
}

/// Fetches the last value stored under `key` in the registry and prints it.
async fn print_and_get_last_value<T: Message + Default + serde::Serialize>(
    key: Vec<u8>,
    registry: &RegistryCanister,
    as_json: bool,
) -> T {
    let value = registry.get_value_with_update(key.clone(), None).await;
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
            } else if key == b"canister_migrations" {
                let value = OtherCanisterMigrations::try_from(
                    CanisterMigrations::decode(&bytes[..])
                        .expect("Error decoding value from registry."),
                )
                .unwrap();
                println!("Canister migrations. Most recent version is {version:?}.\n");
                for (range, trace) in value.iter() {
                    println!(
                        "Trace: {}",
                        trace
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    );
                    println!(
                        "    Range start: {} (0x{})",
                        range.start,
                        hex::encode(range.start.get_ref().as_slice())
                    );
                    println!(
                        "    Range end:   {} (0x{})",
                        range.end,
                        hex::encode(range.end.get_ref().as_slice())
                    );
                }
            } else if key.starts_with(NODE_OPERATOR_RECORD_KEY_PREFIX.as_bytes()) {
                #[derive(Debug, Serialize)]
                pub struct NodeOperator {
                    pub node_operator_principal_id: PrincipalId,
                    pub node_allowance: u64,
                    pub node_provider_principal_id: PrincipalId,
                    pub dc_id: String,
                    pub rewardable_nodes: std::collections::BTreeMap<String, u32>,
                    pub ipv6: Option<String>,
                    pub max_rewardable_nodes: std::collections::BTreeMap<String, u32>,
                }
                let record = NodeOperatorRecord::decode(&bytes[..])
                    .expect("Error decoding value from registry.");
                let record = NodeOperator {
                    node_operator_principal_id: PrincipalId::try_from(
                        record.node_operator_principal_id,
                    )
                    .expect("Error decoding principal"),
                    node_allowance: record.node_allowance,
                    node_provider_principal_id: PrincipalId::try_from(
                        record.node_provider_principal_id,
                    )
                    .expect("Error decoding principal"),
                    dc_id: record.dc_id,
                    rewardable_nodes: record.rewardable_nodes,
                    ipv6: record.ipv6,
                    max_rewardable_nodes: record.max_rewardable_nodes,
                };
                print_value(
                    &std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    record,
                    as_json,
                );
            } else if key.starts_with(NODE_RECORD_KEY_PREFIX.as_bytes()) {
                #[derive(Debug, Serialize)]
                pub struct Node {
                    pub xnet: Option<String>,
                    pub http: Option<String>,
                    pub node_operator_id: PrincipalId,
                    pub chip_id: Option<String>,
                    pub hostos_version_id: Option<String>,
                    pub public_ipv4_config: Option<String>,
                    pub domain: Option<String>,
                    pub node_reward_type: Option<String>,
                }
                let record =
                    NodeRecord::decode(&bytes[..]).expect("Error decoding value from registry.");
                let record = Node {
                    xnet: record.xnet.map(|v| format!("[{}]:{}", v.ip_addr, v.port)),
                    http: record.http.map(|v| format!("[{}]:{}", v.ip_addr, v.port)),
                    node_operator_id: PrincipalId::try_from(record.node_operator_id)
                        .expect("Error decoding principal"),
                    chip_id: record.chip_id.map(hex::encode),
                    hostos_version_id: record.hostos_version_id,
                    public_ipv4_config: record.public_ipv4_config.map(|v| {
                        format!(
                            "ip_addr {} gw {:#?} prefix_length {}",
                            v.ip_addr, v.gateway_ip_addr, v.prefix_length
                        )
                    }),
                    domain: record.domain,
                    node_reward_type: record.node_reward_type.map(|t: i32| {
                        NodeRewardType::try_from(t)
                            .expect("Invalid node_reward_type value")
                            .to_string()
                    }),
                };
                print_value(
                    &std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    record,
                    as_json,
                );
            } else {
                let value = T::decode(&bytes[..]).expect("Error decoding value from registry.");
                print_value(
                    &std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    value,
                    as_json,
                );
            }
        }
        Err(error) => {
            let msg = match error {
                Error::KeyNotPresent(key) => format!(
                    "Key not present: {}",
                    std::str::from_utf8(&key).expect("key is not a str")
                ),
                _ => format!("{error:?}"),
            };
            panic!("Error getting value from registry: {msg}");
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
    Command: ProposalMetadata + ProposalTitle + ProposalPayload<C>,
>(
    cmd: Command,
    nns_function: NnsFunction,
    agent: Agent,
    proposer: NeuronId,
) {
    let payload = cmd.payload(&agent).await;
    let canister_client = GovernanceCanisterClient(NnsCanisterClient::new(
        agent,
        GOVERNANCE_CANISTER_ID,
        Some(proposer),
    ));

    print_proposal(&payload, &cmd);

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
            println!("{proposal_id}");
        }
        Err(e) => {
            eprintln!("submit_proposal for {} error: {:?}", cmd.title(), e);
            std::process::exit(1);
        }
    };
}

async fn propose_action_from_command<Command>(cmd: Command, agent: Agent, proposer: NeuronId)
where
    Command: ProposalMetadata + ProposalTitle + ProposalAction,
{
    let canister_client = GovernanceCanisterClient(NnsCanisterClient::new(
        agent,
        GOVERNANCE_CANISTER_ID,
        Some(proposer),
    ));

    let action = cmd.action().await;

    print_proposal(&action, &cmd);

    if cmd.is_dry_run() {
        return;
    }

    let proposal_id = canister_client
        .submit_proposal_action(action, cmd.url(), cmd.title(), cmd.summary())
        .await
        .unwrap_or_else(|e| {
            eprintln!("propose_action_from_command error: {e:?}");
            std::process::exit(1);
        });

    println!("proposal {proposal_id}");
}

#[derive(Serialize)]
struct FirewallCommandResult {
    entries: Vec<FirewallRule>,
    hash: String,
}

async fn test_add_firewall_rules(
    cmd: ProposeToAddFirewallRulesCmd,
    registry_canister: &RegistryCanister,
) {
    // Fetch existing rules for given scope, add new ones, and return
    let mut entries = get_firewall_rules_from_registry(registry_canister, &cmd.scope).await;

    let rule_file = String::from_utf8(read_file_fully(&cmd.rules_file)).unwrap();
    let new_rules: Vec<FirewallRule> = serde_json::from_str(&rule_file)
        .unwrap_or_else(|_| panic!("Failed to parse firewall rules"));

    let positions: Vec<i32> = cmd
        .positions
        .clone()
        .split(',')
        .map(|pos_str| {
            i32::from_str(pos_str).unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
        })
        .collect();

    if positions.len() != new_rules.len() {
        panic!(
            "Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
            positions.len(),
            new_rules.len()
        );
    }

    let payload = AddFirewallRulesPayload {
        scope: cmd.scope,
        rules: new_rules,
        positions,
        expected_hash: cmd.expected_ruleset_hash,
    };

    add_firewall_rules_compute_entries(&mut entries, &payload);

    let result = FirewallCommandResult {
        entries: entries.clone(),
        hash: compute_firewall_ruleset_hash(&entries),
    };

    println!(
        "{}",
        serde_json::to_string(&result).expect("Failed to serialize rules")
    );
}

async fn test_remove_firewall_rules(
    cmd: ProposeToRemoveFirewallRulesCmd,
    registry_canister: &RegistryCanister,
) {
    // Fetch existing rules for given scope, remove the given ones, and return
    let mut entries = get_firewall_rules_from_registry(registry_canister, &cmd.scope).await;

    let positions: Vec<i32> = cmd
        .positions
        .clone()
        .split(',')
        .map(|pos_str| {
            i32::from_str(pos_str).unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
        })
        .collect();

    let payload = RemoveFirewallRulesPayload {
        scope: cmd.scope,
        positions,
        expected_hash: cmd.expected_ruleset_hash,
    };

    remove_firewall_rules_compute_entries(&mut entries, &payload);

    let result = FirewallCommandResult {
        entries: entries.clone(),
        hash: compute_firewall_ruleset_hash(&entries),
    };

    println!(
        "{}",
        serde_json::to_string(&result).expect("Failed to serialize rules")
    );
}

async fn test_update_firewall_rules(
    cmd: ProposeToUpdateFirewallRulesCmd,
    registry_canister: &RegistryCanister,
) {
    // Fetch existing rules for given scope, update the given ones, and return
    let mut entries = get_firewall_rules_from_registry(registry_canister, &cmd.scope).await;

    let rule_file = String::from_utf8(read_file_fully(&cmd.rules_file)).unwrap();
    let new_rules: Vec<FirewallRule> = serde_json::from_str(&rule_file)
        .unwrap_or_else(|_| panic!("Failed to parse firewall rules"));

    let positions: Vec<i32> = cmd
        .positions
        .clone()
        .split(',')
        .map(|pos_str| {
            i32::from_str(pos_str).unwrap_or_else(|_| panic!("Invalid input position: {pos_str}"))
        })
        .collect();

    if positions.len() != new_rules.len() {
        panic!(
            "Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
            positions.len(),
            new_rules.len()
        );
    }

    let payload = UpdateFirewallRulesPayload {
        scope: cmd.scope,
        rules: new_rules,
        positions,
        expected_hash: cmd.expected_ruleset_hash,
    };

    update_firewall_rules_compute_entries(&mut entries, &payload);

    let result = FirewallCommandResult {
        entries: entries.clone(),
        hash: compute_firewall_ruleset_hash(&entries),
    };

    println!(
        "{}",
        serde_json::to_string(&result).expect("Failed to serialize rules")
    );
}

async fn get_firewall_rules(cmd: GetFirewallRulesCmd, registry_canister: &RegistryCanister) {
    let rules = get_firewall_rules_from_registry(registry_canister, &cmd.scope).await;
    println!(
        "{}",
        serde_json::to_string(&rules).expect("Failed to serialize rules")
    );
}

async fn get_firewall_rules_for_node(
    cmd: GetFirewallRulesForNodeCmd,
    registry_canister: &RegistryCanister,
    nns_urls: Vec<Url>,
) {
    let registry_client = RegistryClientImpl::new(
        Arc::new(NnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
        )),
        None,
    );
    let subnet_id_result = registry_client.get_listed_subnet_for_node_id(
        NodeId::from(cmd.node_id),
        registry_client.get_latest_version(),
    );

    // Get the node rules
    let mut rules = get_firewall_rules_from_registry(
        registry_canister,
        &FirewallRulesScope::Node(NodeId::from(cmd.node_id)),
    )
    .await;

    if let Ok(Some((subnet_id, _))) = subnet_id_result {
        // Get the subnet rules
        rules.append(
            &mut get_firewall_rules_from_registry(
                registry_canister,
                &FirewallRulesScope::Subnet(subnet_id),
            )
            .await,
        );
    }

    // Get the rules for all replica nodes
    rules.append(
        &mut get_firewall_rules_from_registry(registry_canister, &FirewallRulesScope::ReplicaNodes)
            .await,
    );

    // Get the global rules
    rules.append(
        &mut get_firewall_rules_from_registry(registry_canister, &FirewallRulesScope::Global).await,
    );

    println!(
        "{}",
        serde_json::to_string(&rules).expect("Failed to serialize rules")
    );
}

fn get_firewall_ruleset_hash(cmd: GetFirewallRulesetHashCmd) {
    let rule_file = String::from_utf8(read_file_fully(&cmd.rules_file)).unwrap();
    let rules: Vec<FirewallRule> = serde_json::from_str(&rule_file)
        .unwrap_or_else(|_| panic!("Failed to parse firewall rules"));

    println!("{}", compute_firewall_ruleset_hash(&rules));
}

/// Fetches the list of nodes that were added since `version` to the registry.
async fn get_node_list_since(
    version: u64,
    registry: &RegistryCanister,
) -> IndexMap<PrincipalId, NodeDetails> {
    eprintln!("INFO: Fetching a list of all nodes from the registry...");
    let (nns_subnet_id_vec, _) = registry
        .get_value_with_update(ROOT_SUBNET_ID_KEY.as_bytes().to_vec(), None)
        .await
        .unwrap();
    let nns_subnet_id =
        ic_protobuf::types::v1::SubnetId::decode(nns_subnet_id_vec.as_slice()).unwrap();
    let (nns_pub_key_vec, _) = registry
        .get_value_with_update(
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
    let mut errs = 0;
    loop {
        match registry
            .get_certified_changes_since(current_version, &nns_pub_key)
            .await
        {
            Err(err) => {
                errs += 1;
                if errs > 10 {
                    panic!("Couldn't fetch registry delta: {err:?}")
                }
            }
            Ok((mut v, _, _)) => {
                errs = 0;
                current_version = v[v.len() - 1].version.get();
                deltas.append(&mut v);
                if current_version >= latest_version {
                    break;
                };
            }
        };
    }

    let mut node_map: IndexMap<PrincipalId, NodeRecord> = IndexMap::new();
    let mut node_operator_map: IndexMap<PrincipalId, NodeOperatorRecord> = IndexMap::new();
    deltas.into_iter().for_each(|versioned_record| {
        // Since RegistryVersionedRecord's are strongly typed; we must filter those
        // with the relevant keys.
        if is_node_record_key(&versioned_record.key) {
            let node_id = get_node_record_node_id(&versioned_record.key).unwrap();
            match versioned_record.value {
                Some(v) => {
                    let record = NodeRecord::decode(v.as_slice()).unwrap();
                    *node_map.entry(node_id).or_default() = record;
                }
                None => {
                    node_map.shift_remove(&node_id);
                }
            };
        } else if is_node_operator_record_key(&versioned_record.key) {
            let node_operator_id =
                get_node_operator_id_from_record_key(&versioned_record.key).unwrap();
            match versioned_record.value {
                Some(v) => {
                    let record = NodeOperatorRecord::decode(v.as_slice()).unwrap();
                    *node_operator_map.entry(node_operator_id).or_default() = record;
                }
                None => {
                    node_operator_map.shift_remove(&node_operator_id);
                }
            };
        }
    });

    let result: IndexMap<PrincipalId, NodeDetails> = node_map
        .into_iter()
        .map(|(node_id, node_record): (PrincipalId, NodeRecord)| {
            let node_reward_type = node_record.node_reward_type();
            let node_operator_id =
                PrincipalId::try_from(node_record.node_operator_id).unwrap_or_default();
            let (node_provider_id, dc_id) = match node_operator_map.get(&node_operator_id) {
                Some(node_operator_record) => (
                    PrincipalId::try_from(&node_operator_record.node_provider_principal_id)
                        .unwrap_or_default(),
                    node_operator_record.dc_id.clone(),
                ),
                None => (PrincipalId::default(), "".to_string()),
            };
            (
                node_id,
                NodeDetails {
                    node_operator_id,
                    ipv4: node_record.public_ipv4_config.map(|r| r.into()),
                    ipv6: node_record
                        .http
                        .as_ref()
                        .map(|conn| {
                            Ipv6Addr::from_str(&conn.ip_addr)
                                .unwrap_or_else(|_| Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
                        })
                        .unwrap_or_else(|| Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                    node_provider_id,
                    dc_id,
                    hostos_version_id: node_record.hostos_version_id,
                    domain: node_record.domain,
                    node_reward_type,
                },
            )
        })
        .collect();

    result
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

fn read_arg(arg_path: &Option<PathBuf>, arg_sha256: &Option<String>) -> Vec<u8> {
    match (arg_path, arg_sha256) {
        // No arguments, which is fine and we default to empty blob.
        (None, None) => vec![],
        (Some(arg_path), Some(arg_sha256)) => {
            check_file_hash(arg_path, arg_sha256)
                .expect("Upgrade arg's sha256 does not match provided sha256");
            read_file_fully(arg_path)
        }
        (Some(_), None) => panic!("Must provide a sha256 checksum for the upgrade arg",),
        (None, Some(_)) => {
            panic!("--arg-sha256 provided without --arg-path");
        }
    }
}

async fn download_wasm_module(url: &Url) -> PathBuf {
    if url.scheme() != "https" {
        panic!("Wasm module urls must use https");
    }

    let tmp_dir = tempfile::tempdir().unwrap().keep();
    let mut tmp_file = tmp_dir.clone();
    tmp_file.push("wasm_module.tar.gz");

    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(url.as_str(), &tmp_file, None)
        .await
        .expect("Failed to download wasm module");

    tmp_file
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
    match registry.get_value_with_update(k.clone(), None).await {
        Ok((bytes, _)) => {
            PublicKey::decode(&bytes[..]).expect("Error decoding PublicKey from registry")
        }
        Err(error) => panic!("Error getting value from registry: {error:?}"),
    }
}

fn get_api_boundary_node_ids(nns_url: Vec<Url>) -> Vec<String> {
    let registry_client = RegistryClientImpl::new(
        Arc::new(NnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_url,
        )),
        None,
    );
    // maximum number of retries, let the user ctrl+c if necessary
    registry_client
        .try_polling_latest_version(usize::MAX)
        .unwrap();
    let keys = registry_client
        .get_key_family(
            API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
            registry_client.get_latest_version(),
        )
        .unwrap();

    keys.iter()
        .map(|k| {
            k.strip_prefix(API_BOUNDARY_NODE_RECORD_KEY_PREFIX)
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>()
}

fn print_routing_table(routing_table: &Vec<(CanisterIdRange, SubnetId)>, version: RegistryVersion) {
    println!("Routing table. Most recent version is {version}");

    for (range, subnet_id) in routing_table {
        println!("Subnet: {subnet_id}");
        println!(
            "    Range start: {} (0x{})",
            range.start,
            hex::encode(range.start.get_ref().as_slice())
        );
        println!(
            "    Range end:   {} (0x{})",
            range.end,
            hex::encode(range.end.get_ref().as_slice())
        );
    }
}

/// Writes a threshold signing public key to the given path.
pub fn store_threshold_sig_pk<P: AsRef<Path>>(pk: &PublicKey, path: P) {
    let pk = ThresholdSigPublicKey::try_from(pk.clone())
        .expect("failed to parse threshold signature PK from protobuf");
    let der_bytes = ic_crypto_utils_threshold_sig_der::public_key_to_der(&pk.into_bytes())
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
    agent: Agent,
    proposer: NeuronId,
) {
    let canister_client = GovernanceCanisterClient(NnsCanisterClient::new(
        agent,
        GOVERNANCE_CANISTER_ID,
        Some(proposer),
    ));
    let node_provider = NodeProvider {
        id: Some(cmd.node_provider_pid),
        // TODO(NNS1-771): accept this data from the command line
        reward_account: None,
    };
    let (change, default_summary, title) = match cmd.add_or_remove_provider {
        AddOrRemove::Add => {
            let msg = format!("Add node provider: {}", cmd.node_provider_pid);
            (Some(Change::ToAdd(node_provider)), msg.clone(), msg)
        }
        AddOrRemove::Remove => {
            let msg = format!("Remove node provider: {}", cmd.node_provider_pid);
            (Some(Change::ToRemove(node_provider)), msg.clone(), msg)
        }
    };
    let payload = AddOrRemoveNodeProvider { change };
    print_proposal(&payload, &cmd);

    if cmd.is_dry_run() {
        return;
    }

    let summary = cmd.summary.unwrap_or(default_summary);
    let response = canister_client
        .submit_add_or_remove_node_provider_proposal(
            payload,
            parse_proposal_url(&cmd.proposal_url),
            title,
            summary,
        )
        .await;

    match response {
        Ok(proposal_id) => {
            println!("{proposal_id}");
        }
        Err(e) => {
            eprintln!("propose_to_add_or_remove_node_provider error: {e:?}");
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
        .map_err(|err| format!("{err}"))?
        .ok_or("Root subnet_id is not found")?;
    client
        .get_threshold_signing_public_key_for_subnet(root_subnet_id, version)
        .map_err(|err| format!("{err}"))?
        .ok_or_else(|| "Root subnet public key is not found".to_string())
}

/// Fetch registry records from the given `nns_urls`, and update the local
/// registry store with the new records.
async fn update_registry_local_store(nns_urls: Vec<Url>, cmd: UpdateRegistryLocalStoreCmd) {
    eprintln!("RegistryLocalStore path: {:?}", cmd.local_store_path);
    let local_store = Arc::new(LocalStoreImpl::new(cmd.local_store_path));
    let local_client = Arc::new(RegistryClientImpl::new(local_store.clone(), None));
    // maximum number of retries, let the user ctrl+c if necessary
    local_client
        .try_polling_latest_version(usize::MAX)
        .expect("Local registry client try_polling_latest_version failed");
    let latest_version = local_client.get_latest_version();
    eprintln!("RegistryLocalStore latest version: {latest_version}");
    let nns_pub_key = match get_root_subnet_pub_key(local_client.clone(), latest_version) {
        Ok(pub_key) => {
            eprintln!("Root subnet public key found: {pub_key:?}");
            pub_key
        }
        Err(err) => {
            if cmd.disable_certificate_validation {
                eprintln!("Root subnet public key is not found in RegistryLocalStore. Ignore.");
                // Try again with validation disabled
                use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
                PublicKeyBytes([0; PublicKeyBytes::SIZE]).into()
            } else {
                panic!("Error looking up RegistryLocalStore: {err}")
            }
        }
    };
    let remote_canister = RegistryCanister::new(nns_urls);
    let response = remote_canister
        .get_certified_changes_since(latest_version.get(), &nns_pub_key)
        .await;
    let records = match response {
        Ok(response) => response.0,
        Err(err) => {
            let throw_err = |err| panic!("Error retrieving registry records: {err:?}");
            if cmd.disable_certificate_validation {
                remote_canister
                    .get_changes_since_as_registry_records(latest_version.get())
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
            eprintln!("Writing data of registry version {v}");
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
    agent: Agent,
) {
    let canister_client = RootCanisterClient(NnsCanisterClient::new(agent, ROOT_CANISTER_ID, None));
    let result = canister_client
        .submit_root_proposal_to_upgrade_governance_canister(cmd)
        .await;
    match result {
        Ok(()) => println!("Root proposal to upgrade the governance canister submitted."),
        Err(error) => {
            println!("Error submitting root proposal to upgrade governance canister: {error}")
        }
    }
}

/// Returns the current list of pending root proposals to upgrade the governance
/// canister.
async fn get_pending_root_proposals_to_upgrade_governance_canister(agent: Agent) {
    let canister_client = RootCanisterClient(NnsCanisterClient::new(agent, ROOT_CANISTER_ID, None));
    let proposals = canister_client
        .get_pending_root_proposals_to_upgrade_governance_canister()
        .await;

    if proposals.is_empty() {
        println!("No currently pending root proposals.")
    } else {
        println!("Currently pending root proposals: ");
        for proposal in proposals {
            println!("{proposal:?}");
        }
    }
}

/// Votes a root proposal to upgrade the governance canister.
async fn vote_on_root_proposal_to_upgrade_governance_canister(
    cmd: VoteOnRootProposalToUpgradeGovernanceCanisterCmd,
    agent: Agent,
) {
    let canister_client = RootCanisterClient(NnsCanisterClient::new(agent, ROOT_CANISTER_ID, None));
    let result = canister_client
        .vote_on_root_proposal_to_upgrade_governance_canister(cmd)
        .await;
    match result {
        Ok(()) => println!("Ballot for root proposal cast."),
        Err(error) => println!("Error submitting root proposal ballot: {error}"),
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

async fn swap_node_in_subnet_directly(
    registry_canister: RegistryCanister,
    cmd: SwapNodeInSubnetDirectlyCmd,
) {
    let nonce = generate_nonce();
    let request = SwapNodeInSubnetDirectlyPayload {
        new_node_id: Some(cmd.new_node_id),
        old_node_id: Some(cmd.old_node_id),
    };

    let payload = Encode!(&request).expect("Failed to serialize swap node request.");

    let agent = registry_canister.choose_random_agent();

    match agent
        .execute_update(
            &REGISTRY_CANISTER_ID,
            &REGISTRY_CANISTER_ID,
            "swap_node_in_subnet_directly",
            payload,
            nonce,
        )
        .await
        .unwrap()
    {
        Some(_) => println!("Nodes swapped successfully."),
        None => panic!("No response was received from swap_node_in_subnet_directly"),
    }
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
    pub fn new(agent: Agent, handler_id: CanisterId, author: Option<NeuronId>) -> Self {
        Self {
            agent,
            handler_id,
            author,
        }
    }
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

fn is_mainnet(url: &Url) -> bool {
    url.domain().is_some_and(|domain| {
        IC_DOMAINS
            .iter()
            .any(|&ic_domain| domain.contains(ic_domain))
    })
}

fn parse_nns_public_key(
    nns_url: Url,
    verify_nns_responses: bool,
    nns_public_key_pem_file: Option<PathBuf>,
) -> Option<ThresholdSigPublicKey> {
    // If we talk to `ic0.app` we verify against mainnet root key by default.
    if verify_nns_responses || is_mainnet(&nns_url) {
        let nns_key = if let Some(path) = nns_public_key_pem_file {
            parse_threshold_sig_key(&path).expect("Failed to parse PEM file.")
        } else {
            let decoded_nns_mainnet_key = base64::decode(IC_ROOT_PUBLIC_KEY_BASE64)
                .expect("Failed to decode mainnet public key from base64.");
            parse_threshold_sig_key_from_der(&decoded_nns_mainnet_key)
                .expect("Failed to decode mainnet public key.")
        };
        Some(nns_key)
    } else {
        None
    }
}

/// Build a new canister client.
/// `nns_public_key_pem` is the key used for response verification. If None mainnet public key is used.
fn make_canister_client(
    nns_urls: Vec<Url>,
    verify_nns_responses: bool,
    nns_public_key_pem_file: Option<PathBuf>,
    sender: Sender,
) -> Agent {
    let nns_url = &nns_urls[0];
    let agent = Agent::new(nns_url.clone(), sender);

    if let Some(nns_public_key) = parse_nns_public_key(
        nns_url.clone(),
        verify_nns_responses,
        nns_public_key_pem_file,
    ) {
        agent.with_nns_public_key(nns_public_key)
    } else {
        agent
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
                        println!("Couldn't reach NNS canister at id: {canister_id:?}");
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
        let serialized = Encode!(&ManageNeuronRequest {
            neuron_id_or_subaccount: None,
            command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(MakeProposalRequest {
                title: Some(title),
                summary,
                url,
                action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(payload)),
            }))),
            id: Some((*self.0.proposal_author()).into()),
        })
            .map_err(|e| {
                format!(
                    "Cannot candid-serialize the submit_add_or_remove_node_provider_proposal payload: {e}"
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
                    title,
                    summary,
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

    async fn submit_proposal_action(
        &self,
        action: ProposalActionRequest,
        url: String,
        title: String,
        summary: String,
    ) -> Result<ProposalId, String> {
        let serialized = Encode!(&ManageNeuronRequest {
            neuron_id_or_subaccount: None,
            command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                MakeProposalRequest {
                    title: Some(title),
                    summary,
                    url,
                    action: Some(action),
                }
            ))),
            id: Some((*self.0.proposal_author()).into()),
        })
        .map_err(|e| format!("Cannot candid-serialize the submit_proposal_action payload: {e}"))?;
        let response = self
            .0
            .execute_update("manage_neuron", serialized)
            .await?
            .ok_or_else(|| "submit_proposal replied nothing.".to_string())?;

        decode_make_proposal_response(response)
    }

    async fn submit_external_proposal(
        &self,
        submit_proposal_command: &ManageNeuronRequest,
        title: &str,
    ) -> Result<ProposalId, String> {
        let serialized = Encode!(submit_proposal_command).map_err(|e| {
            format!("Cannot candid-serialize the payload of proposal:'{title}'. Payload: {e}")
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
        let change_canister_request =
            ChangeCanisterRequest::new(true, CanisterInstallMode::Upgrade, GOVERNANCE_CANISTER_ID)
                .with_wasm(wasm_module);

        let serialized = Encode!(&CanisterIdRecord::from(GOVERNANCE_CANISTER_ID)).unwrap();
        let response = self
            .0
            .execute_update("canister_status", serialized)
            .await?
            .unwrap();

        let status = Decode!(&response, CanisterStatusResult).map_err(|e| {
            format!("Cannot candid-deserialize the response from canister_status: {e}")
        })?;

        let module_hash = status.module_hash.as_ref().unwrap().clone();

        println!(
            "Current governance canister wasm is: {:?}. \
                  Root proposal will only remain valid as long \
                  as the wasm and the membership of the nns subnet doesn't change.",
            hex::encode(&module_hash)
        );

        let serialized = Encode!(&module_hash, &change_canister_request)
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
                 submit_root_proposal_to_upgrade_governance_canister: {e}"
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
                 get_pending_root_proposals_to_upgrade_governance_canister: {e}"
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
                 vote_on_root_proposal_to_upgrade_governance_canister: {e}"
            )
        })?
    }
}

fn make_registry_client(
    nns_urls: Vec<Url>,
    verify_nns_responses: bool,
    nns_public_key_pem_file: Option<PathBuf>,
) -> RegistryClientImpl {
    let nns_public_key = parse_nns_public_key(
        nns_urls[0].clone(),
        verify_nns_responses,
        nns_public_key_pem_file,
    );
    let data_provider: Arc<dyn RegistryDataProvider> = match nns_public_key {
        Some(nns_public_key) => Arc::new(CertifiedNnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
            nns_public_key,
        )),
        None => Arc::new(NnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
        )),
    };
    RegistryClientImpl::new(data_provider, None)
}

fn print_proposal<T: Serialize + Debug, Command: ProposalMetadata + ProposalTitle>(
    payload: &T,
    cmd: &Command,
) {
    if cmd.is_json() {
        #[derive(Serialize)]
        struct Proposal<T> {
            title: String,
            summary: String,
            url: String,
            payload: T,
        }

        let serialized = serde_json::to_string_pretty(&Proposal {
            title: cmd.title(),
            summary: cmd.summary(),
            url: cmd.url(),
            payload,
        })
        .expect("Serialization for the cmd to JSON failed.");
        println!("{serialized}");
    } else {
        println!("Title: {}\n", cmd.title());
        println!("Summary: {}\n", cmd.summary());
        println!("URL: {}\n", cmd.url());
        println!("Payload: {payload:#?}");
    }
}
