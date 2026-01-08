use crate::{
    decoder_config,
    governance::Environment,
    pb::v1::{
        ExecuteNnsFunction, GovernanceError, NnsFunction, SelfDescribingProposalAction,
        SelfDescribingValue, Topic, governance_error::ErrorType,
    },
    proposals::decode_candid_args_to_self_describing_value::decode_candid_args_to_self_describing_value,
};

use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_management_canister_types_private::{CanisterMetadataRequest, CanisterMetadataResponse};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use std::sync::Arc;

/// A partial Candid interface for the management canister (ic_00) that contains the necessary
/// methods for all the ExecuteNnsFunction proposals. Currently, only the uninstall_code method is
/// supported.
const PARTIAL_IC_00_CANDID: &str = r#"type uninstall_code_args = record {
    canister_id : principal;
    sender_canister_version : opt nat64;
};
service ic : {
    uninstall_code : (uninstall_code_args) -> ();
}"#;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidExecuteNnsFunction {
    pub nns_function: ValidNnsFunction,
    pub payload: Vec<u8>,
}

impl ValidExecuteNnsFunction {
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        self.nns_function.allowed_when_resources_are_low()
    }

    pub(crate) fn can_have_large_payload(&self) -> bool {
        self.nns_function.can_have_large_payload()
    }

    pub(crate) fn topic(&self) -> Topic {
        self.nns_function.topic()
    }

    /// Converts the ExecuteNnsFunction to a self-describing value using the candid file fetched
    /// from the management canister (as canister metadata).
    async fn convert_payload_to_self_describing_value(
        &self,
        env: Arc<dyn Environment>,
    ) -> Result<SelfDescribingValue, String> {
        let candid_source = self.get_candid_source(env).await?;
        let (_, method_name) = self.nns_function.canister_and_function();
        decode_candid_args_to_self_describing_value(&candid_source, method_name, &self.payload)
    }

    pub async fn to_self_describing_action(
        &self,
        env: Arc<dyn Environment>,
    ) -> Result<SelfDescribingProposalAction, GovernanceError> {
        let value = self
            .convert_payload_to_self_describing_value(env)
            .await
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "Failed to convert ExecuteNnsFunction to self-describing value: {}",
                        e
                    ),
                )
            })?;
        Ok(SelfDescribingProposalAction {
            type_name: self.nns_function.type_name().to_string(),
            type_description: self.nns_function.type_description().to_string(),
            value: Some(value),
        })
    }

    async fn get_candid_source(&self, env: Arc<dyn Environment>) -> Result<String, String> {
        let (canister_id, _method_name) = self.nns_function.canister_and_function();

        // The management canister (ic_00) doesn't expose candid:service metadata, so we return a
        // hard-coded DID file for it.
        if canister_id == CanisterId::ic_00() {
            return Ok(PARTIAL_IC_00_CANDID.to_string());
        }

        let request = CanisterMetadataRequest::new(canister_id, "candid:service".to_string());
        let encoded_request = Encode!(&request).expect("Failed to encode payload");
        let response = env
            .call_canister_method(CanisterId::ic_00(), "canister_metadata", encoded_request)
            .await
            .map_err(|(code, msg)| {
                format!(
                    "Failed to call canister_metadata. Error code: {:?}, message: {}",
                    code, msg
                )
            })?;
        let decoded_response = Decode!([decoder_config()]; &response, CanisterMetadataResponse)
            .map_err(|e| format!("Failed to decode response: {}", e))?;
        String::from_utf8(decoded_response.value().to_vec())
            .map_err(|e| format!("Failed to convert metadata to UTF-8: {}", e))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidNnsFunction {
    CreateSubnet,
    AddNodeToSubnet,
    NnsCanisterInstall,
    RecoverSubnet,
    UpdateConfigOfSubnet,
    AssignNoid,
    DeployGuestosToAllSubnetNodes,
    ClearProvisionalWhitelist,
    RemoveNodesFromSubnet,
    SetAuthorizedSubnetworks,
    SetFirewallConfig,
    UpdateNodeOperatorConfig,
    RemoveNodes,
    UninstallCode,
    UpdateNodeRewardsTable,
    AddOrRemoveDataCenters,
    RemoveNodeOperators,
    RerouteCanisterRanges,
    AddFirewallRules,
    RemoveFirewallRules,
    UpdateFirewallRules,
    PrepareCanisterMigration,
    CompleteCanisterMigration,
    AddSnsWasm,
    ChangeSubnetMembership,
    UpdateSubnetType,
    ChangeSubnetTypeAssignment,
    UpdateSnsWasmSnsSubnetIds,
    InsertSnsWasmUpgradePathEntries,
    ReviseElectedGuestosVersions,
    BitcoinSetConfig,
    HardResetNnsRootToVersion,
    AddApiBoundaryNodes,
    RemoveApiBoundaryNodes,
    DeployGuestosToSomeApiBoundaryNodes,
    DeployGuestosToAllUnassignedNodes,
    UpdateSshReadonlyAccessForAllUnassignedNodes,
    ReviseElectedHostosVersions,
    DeployHostosToSomeNodes,
    SubnetRentalRequest,
    PauseCanisterMigrations,
    UnpauseCanisterMigrations,
    SetSubnetOperationalLevel,
    TakeCanisterSnapshot,
    LoadCanisterSnapshot,
}

impl ValidNnsFunction {
    fn allowed_when_resources_are_low(&self) -> bool {
        matches!(
            self,
            ValidNnsFunction::HardResetNnsRootToVersion
                | ValidNnsFunction::ReviseElectedGuestosVersions
                | ValidNnsFunction::DeployGuestosToAllSubnetNodes
        )
    }

    fn can_have_large_payload(&self) -> bool {
        matches!(
            self,
            ValidNnsFunction::NnsCanisterInstall
                | ValidNnsFunction::HardResetNnsRootToVersion
                | ValidNnsFunction::AddSnsWasm
        )
    }

    pub(crate) fn canister_and_function(&self) -> (CanisterId, &'static str) {
        match self {
            ValidNnsFunction::AssignNoid => (REGISTRY_CANISTER_ID, "add_node_operator"),

            ValidNnsFunction::CreateSubnet => (REGISTRY_CANISTER_ID, "create_subnet"),
            ValidNnsFunction::AddNodeToSubnet => (REGISTRY_CANISTER_ID, "add_nodes_to_subnet"),
            ValidNnsFunction::RemoveNodesFromSubnet => {
                (REGISTRY_CANISTER_ID, "remove_nodes_from_subnet")
            }
            ValidNnsFunction::ChangeSubnetMembership => {
                (REGISTRY_CANISTER_ID, "change_subnet_membership")
            }
            ValidNnsFunction::NnsCanisterInstall => (ROOT_CANISTER_ID, "add_nns_canister"),
            ValidNnsFunction::HardResetNnsRootToVersion => {
                (LIFELINE_CANISTER_ID, "hard_reset_root_to_version")
            }
            ValidNnsFunction::RecoverSubnet => (REGISTRY_CANISTER_ID, "recover_subnet"),
            ValidNnsFunction::ReviseElectedGuestosVersions => {
                (REGISTRY_CANISTER_ID, "revise_elected_guestos_versions")
            }
            ValidNnsFunction::UpdateNodeOperatorConfig => {
                (REGISTRY_CANISTER_ID, "update_node_operator_config")
            }
            ValidNnsFunction::DeployGuestosToAllSubnetNodes => {
                (REGISTRY_CANISTER_ID, "deploy_guestos_to_all_subnet_nodes")
            }
            ValidNnsFunction::ReviseElectedHostosVersions => {
                (REGISTRY_CANISTER_ID, "revise_elected_hostos_versions")
            }
            ValidNnsFunction::DeployHostosToSomeNodes => {
                (REGISTRY_CANISTER_ID, "deploy_hostos_to_some_nodes")
            }
            ValidNnsFunction::UpdateConfigOfSubnet => (REGISTRY_CANISTER_ID, "update_subnet"),
            ValidNnsFunction::ClearProvisionalWhitelist => {
                (REGISTRY_CANISTER_ID, "clear_provisional_whitelist")
            }
            ValidNnsFunction::SetAuthorizedSubnetworks => {
                (CYCLES_MINTING_CANISTER_ID, "set_authorized_subnetwork_list")
            }
            ValidNnsFunction::SetFirewallConfig => (REGISTRY_CANISTER_ID, "set_firewall_config"),
            ValidNnsFunction::AddFirewallRules => (REGISTRY_CANISTER_ID, "add_firewall_rules"),
            ValidNnsFunction::RemoveFirewallRules => {
                (REGISTRY_CANISTER_ID, "remove_firewall_rules")
            }
            ValidNnsFunction::UpdateFirewallRules => {
                (REGISTRY_CANISTER_ID, "update_firewall_rules")
            }
            ValidNnsFunction::RemoveNodes => (REGISTRY_CANISTER_ID, "remove_nodes"),
            ValidNnsFunction::UninstallCode => (CanisterId::ic_00(), "uninstall_code"),
            ValidNnsFunction::UpdateNodeRewardsTable => {
                (REGISTRY_CANISTER_ID, "update_node_rewards_table")
            }
            ValidNnsFunction::AddOrRemoveDataCenters => {
                (REGISTRY_CANISTER_ID, "add_or_remove_data_centers")
            }
            ValidNnsFunction::RemoveNodeOperators => {
                (REGISTRY_CANISTER_ID, "remove_node_operators")
            }
            ValidNnsFunction::RerouteCanisterRanges => {
                (REGISTRY_CANISTER_ID, "reroute_canister_ranges")
            }
            ValidNnsFunction::PrepareCanisterMigration => {
                (REGISTRY_CANISTER_ID, "prepare_canister_migration")
            }
            ValidNnsFunction::CompleteCanisterMigration => {
                (REGISTRY_CANISTER_ID, "complete_canister_migration")
            }
            ValidNnsFunction::AddSnsWasm => (SNS_WASM_CANISTER_ID, "add_wasm"),
            ValidNnsFunction::UpdateSubnetType => {
                (CYCLES_MINTING_CANISTER_ID, "update_subnet_type")
            }
            ValidNnsFunction::ChangeSubnetTypeAssignment => {
                (CYCLES_MINTING_CANISTER_ID, "change_subnet_type_assignment")
            }
            ValidNnsFunction::UpdateSnsWasmSnsSubnetIds => {
                (SNS_WASM_CANISTER_ID, "update_sns_subnet_list")
            }
            ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                (SNS_WASM_CANISTER_ID, "insert_upgrade_path_entries")
            }
            ValidNnsFunction::BitcoinSetConfig => (ROOT_CANISTER_ID, "call_canister"),
            ValidNnsFunction::AddApiBoundaryNodes => {
                (REGISTRY_CANISTER_ID, "add_api_boundary_nodes")
            }
            ValidNnsFunction::RemoveApiBoundaryNodes => {
                (REGISTRY_CANISTER_ID, "remove_api_boundary_nodes")
            }
            ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes => (
                REGISTRY_CANISTER_ID,
                "deploy_guestos_to_some_api_boundary_nodes",
            ),
            ValidNnsFunction::DeployGuestosToAllUnassignedNodes => (
                REGISTRY_CANISTER_ID,
                "deploy_guestos_to_all_unassigned_nodes",
            ),
            ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => (
                REGISTRY_CANISTER_ID,
                "update_ssh_readonly_access_for_all_unassigned_nodes",
            ),
            ValidNnsFunction::SubnetRentalRequest => {
                (SUBNET_RENTAL_CANISTER_ID, "execute_rental_request_proposal")
            }
            ValidNnsFunction::PauseCanisterMigrations => (MIGRATION_CANISTER_ID, "disable_api"),
            ValidNnsFunction::UnpauseCanisterMigrations => (MIGRATION_CANISTER_ID, "enable_api"),
            ValidNnsFunction::SetSubnetOperationalLevel => {
                (REGISTRY_CANISTER_ID, "set_subnet_operational_level")
            }
            ValidNnsFunction::TakeCanisterSnapshot => (ROOT_CANISTER_ID, "take_canister_snapshot"),
            ValidNnsFunction::LoadCanisterSnapshot => (ROOT_CANISTER_ID, "load_canister_snapshot"),
        }
    }

    fn topic(&self) -> Topic {
        match self {
            ValidNnsFunction::AssignNoid
            | ValidNnsFunction::UpdateNodeOperatorConfig
            | ValidNnsFunction::RemoveNodeOperators
            | ValidNnsFunction::RemoveNodes
            | ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => Topic::NodeAdmin,

            ValidNnsFunction::CreateSubnet
            | ValidNnsFunction::AddNodeToSubnet
            | ValidNnsFunction::RecoverSubnet
            | ValidNnsFunction::RemoveNodesFromSubnet
            | ValidNnsFunction::ChangeSubnetMembership
            | ValidNnsFunction::UpdateConfigOfSubnet
            | ValidNnsFunction::SetAuthorizedSubnetworks
            | ValidNnsFunction::SetFirewallConfig
            | ValidNnsFunction::AddFirewallRules
            | ValidNnsFunction::RemoveFirewallRules
            | ValidNnsFunction::UpdateFirewallRules
            | ValidNnsFunction::RerouteCanisterRanges
            | ValidNnsFunction::PrepareCanisterMigration
            | ValidNnsFunction::CompleteCanisterMigration
            | ValidNnsFunction::UpdateSubnetType
            | ValidNnsFunction::ChangeSubnetTypeAssignment
            | ValidNnsFunction::UpdateSnsWasmSnsSubnetIds
            | ValidNnsFunction::SetSubnetOperationalLevel => Topic::SubnetManagement,

            ValidNnsFunction::ReviseElectedGuestosVersions
            | ValidNnsFunction::ReviseElectedHostosVersions => Topic::IcOsVersionElection,

            ValidNnsFunction::DeployHostosToSomeNodes
            | ValidNnsFunction::DeployGuestosToAllSubnetNodes
            | ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes
            | ValidNnsFunction::DeployGuestosToAllUnassignedNodes => Topic::IcOsVersionDeployment,

            ValidNnsFunction::ClearProvisionalWhitelist
            | ValidNnsFunction::UpdateNodeRewardsTable => Topic::NetworkEconomics,

            ValidNnsFunction::UninstallCode => Topic::Governance,

            ValidNnsFunction::AddOrRemoveDataCenters => Topic::ParticipantManagement,

            ValidNnsFunction::AddApiBoundaryNodes | ValidNnsFunction::RemoveApiBoundaryNodes => {
                Topic::ApiBoundaryNodeManagement
            }

            ValidNnsFunction::SubnetRentalRequest => Topic::SubnetRental,

            ValidNnsFunction::NnsCanisterInstall
            | ValidNnsFunction::HardResetNnsRootToVersion
            | ValidNnsFunction::BitcoinSetConfig
            | ValidNnsFunction::PauseCanisterMigrations
            | ValidNnsFunction::UnpauseCanisterMigrations
            | ValidNnsFunction::TakeCanisterSnapshot
            | ValidNnsFunction::LoadCanisterSnapshot => Topic::ProtocolCanisterManagement,

            ValidNnsFunction::AddSnsWasm | ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                Topic::ServiceNervousSystemManagement
            }
        }
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            ValidNnsFunction::CreateSubnet => "Create Subnet",
            ValidNnsFunction::AddNodeToSubnet => "Add Node to Subnet",
            ValidNnsFunction::NnsCanisterInstall => "NNS Canister Install",
            ValidNnsFunction::RecoverSubnet => "Recover Subnet",
            ValidNnsFunction::UpdateConfigOfSubnet => "Update Subnet Config",
            ValidNnsFunction::AssignNoid => "Assign Node Operator ID (NOID)",
            ValidNnsFunction::DeployGuestosToAllSubnetNodes => "Deploy GuestOS To All Subnet Nodes",
            ValidNnsFunction::ClearProvisionalWhitelist => "Clear Provisional Whitelist",
            ValidNnsFunction::RemoveNodesFromSubnet => "Remove Node from Subnet",
            ValidNnsFunction::SetAuthorizedSubnetworks => "Set Authorized Subnets",
            ValidNnsFunction::SetFirewallConfig => "Set Firewall Config",
            ValidNnsFunction::UpdateNodeOperatorConfig => "Update Node Operator Config",
            ValidNnsFunction::RemoveNodes => "Remove Nodes from Registry",
            ValidNnsFunction::UninstallCode => "Uninstall Code",
            ValidNnsFunction::UpdateNodeRewardsTable => "Update Node Rewards Table",
            ValidNnsFunction::AddOrRemoveDataCenters => "Add or Remove Data Centers",
            ValidNnsFunction::RemoveNodeOperators => "Remove Node Operators",
            ValidNnsFunction::RerouteCanisterRanges => "Reroute Canister Ranges",
            ValidNnsFunction::AddFirewallRules => "Add Firewall Rules",
            ValidNnsFunction::RemoveFirewallRules => "Remove Firewall Rules",
            ValidNnsFunction::UpdateFirewallRules => "Update Firewall Rules",
            ValidNnsFunction::PrepareCanisterMigration => "Prepare Canister Migration",
            ValidNnsFunction::CompleteCanisterMigration => "Complete Canister Migration",
            ValidNnsFunction::AddSnsWasm => "Bless New SNS Deployment",
            ValidNnsFunction::ChangeSubnetMembership => "Change Subnet Membership",
            ValidNnsFunction::UpdateSubnetType => "Update Subnet Type",
            ValidNnsFunction::ChangeSubnetTypeAssignment => "Change Subnet Type Assignment",
            ValidNnsFunction::UpdateSnsWasmSnsSubnetIds => "Update SNS-W Subnet Ids",
            ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                "Insert SNS-W Upgrade Path Entries"
            }
            ValidNnsFunction::ReviseElectedGuestosVersions => "Revise Elected GuestOS Versions",
            ValidNnsFunction::BitcoinSetConfig => "Set Bitcoin Config",
            ValidNnsFunction::HardResetNnsRootToVersion => "Hard Reset NNS Root To Version",
            ValidNnsFunction::AddApiBoundaryNodes => "Add API Boundary Nodes",
            ValidNnsFunction::RemoveApiBoundaryNodes => "Remove API Boundary Nodes",
            ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                "Deploy GuestOS To Some API Boundary Nodes"
            }
            ValidNnsFunction::DeployGuestosToAllUnassignedNodes => {
                "Deploy GuestOS To All Unassigned Nodes"
            }
            ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                "Update SSH Read Only Access For All Unassigned Nodes"
            }
            ValidNnsFunction::ReviseElectedHostosVersions => "Revise Elected HostOS Versions",
            ValidNnsFunction::DeployHostosToSomeNodes => "Deploy HostOS To Some Nodes",
            ValidNnsFunction::SubnetRentalRequest => "Subnet Rental Request",
            ValidNnsFunction::PauseCanisterMigrations => "Pause Canister Migrations",
            ValidNnsFunction::UnpauseCanisterMigrations => "Unpause Canister Migrations",
            ValidNnsFunction::SetSubnetOperationalLevel => "Set Subnet Operational Level",
            ValidNnsFunction::TakeCanisterSnapshot => "Take Canister Snapshot",
            ValidNnsFunction::LoadCanisterSnapshot => "Load Canister Snapshot",
        }
    }

    pub(crate) fn type_description(&self) -> &'static str {
        match self {
            ValidNnsFunction::CreateSubnet => {
                "Combine a specified set of nodes, typically drawn from data centers \
                and operators in such a way as to guarantee their independence, into \
                a new decentralized subnet. The execution of this external update \
                first initiates a new instance of the distributed key generation \
                protocol. The transcript of that protocol is written to a new subnet \
                record in the registry, together with initial configuration \
                information for the subnet, from where the nodes comprising the \
                subnet pick it up."
            }
            ValidNnsFunction::AddNodeToSubnet => {
                "Add a new node to a subnet. The node cannot be currently assigned to \
                a subnet. The execution of this proposal changes an existing subnet \
                record to add a node. From the perspective of the NNS, this update is \
                a simple update of the subnet record in the registry."
            }
            ValidNnsFunction::NnsCanisterInstall => {
                "A proposal to add a new canister to be installed and executed in the \
                NNS subnetwork. The root canister, which controls all Canisters on \
                the NNS except for itself, handles this proposal type. The call also \
                expects the Wasm module that shall be installed."
            }
            ValidNnsFunction::RecoverSubnet => {
                "Update a subnet's recovery CUP (used to recover subnets that have \
                stalled). Nodes that find a recovery CUP for their subnet will load \
                that CUP from the registry and restart the replica from that CUP."
            }
            ValidNnsFunction::UpdateConfigOfSubnet => {
                "Update a subnet's configuration. This proposal updates the subnet \
                record in the registry, with the changes being picked up by the nodes \
                on the subnet when they reference the respective registry version. \
                Subnet configuration comprises protocol parameters that must be \
                consistent across the subnet (e.g., message sizes)."
            }
            ValidNnsFunction::AssignNoid => {
                "Assign an identity to a node operator associating key information \
                regarding its ownership, the jurisdiction in which it is located, and \
                other information. The node operator is stored as a record in the \
                registry. It contains the remaining node allowance for that node \
                operator, that is the number of nodes the node operator can still add \
                to the IC. When an additional node is added by the node operator, the \
                remaining allowance is decreased."
            }
            ValidNnsFunction::DeployGuestosToAllSubnetNodes => {
                "Deploy a GuestOS version to a given subnet. The proposal changes the \
                GuestOS version that is used on the specified subnet.<br/><br/>The \
                version must be contained in the list of elected GuestOS versions.\
                <br/><br/>The upgrade is completed when the subnet creates the next \
                regular CUP."
            }
            ValidNnsFunction::ClearProvisionalWhitelist => {
                "Clears the provisional whitelist, which allows the listed principals \
                to create Canisters with cycles. The mechanism is only needed for \
                bootstrap and testing and must be deactivated afterward."
            }
            ValidNnsFunction::RemoveNodesFromSubnet => {
                "Remove a node from a subnet. It then becomes available for \
                reassignment. The execution of this proposal changes an existing \
                subnet record to remove a node. From the perspective of the NNS, this \
                update is a simple update of the subnet record in the registry."
            }
            ValidNnsFunction::SetAuthorizedSubnetworks => {
                "Informs the cycles minting canister that a certain principal is \
                authorized to use certain subnetworks (from a list). Can also be used \
                to set the \"default\" list of subnetworks that principals without \
                special authorization are allowed to use."
            }
            ValidNnsFunction::SetFirewallConfig => {
                "Change the Firewall configuration in the registry (configures which \
                boundary nodes subnet blockchain replicas will communicate with)."
            }
            ValidNnsFunction::UpdateNodeOperatorConfig => {
                "Change a Node Operator's allowance in the registry."
            }
            ValidNnsFunction::RemoveNodes => "Remove unassigned nodes from the registry.",
            ValidNnsFunction::UninstallCode => "Uninstall code of a canister.",
            ValidNnsFunction::UpdateNodeRewardsTable => "Update the node rewards table.",
            ValidNnsFunction::AddOrRemoveDataCenters => "Add or remove Data Center records.",
            ValidNnsFunction::RemoveNodeOperators => {
                "Remove node operator records from the registry."
            }
            ValidNnsFunction::RerouteCanisterRanges => {
                "In the routing table in the registry, remap canister ID ranges from \
                one subnet to a different subnet.<br/><br/>The steps of canister \
                migration are:<ol><li>Prepare Canister Migration</li><li>Reroute \
                Canister Ranges</li><li>Complete Canister Migration</li></ol>"
            }
            ValidNnsFunction::AddFirewallRules => {
                "Add firewall rules in the registry. Nodes use a firewall to protect \
                themselves from network attacks."
            }
            ValidNnsFunction::RemoveFirewallRules => {
                "Remove firewall rules in the registry. Nodes use a firewall to \
                protect themselves from network attacks."
            }
            ValidNnsFunction::UpdateFirewallRules => {
                "Update firewall rules in the registry. Nodes use a firewall to \
                protect themselves from network attacks."
            }
            ValidNnsFunction::PrepareCanisterMigration => {
                "Insert or update canister migrations entries. Such entries specify \
                that a migration of canister ID ranges is currently ongoing.\
                <br/><br/>The steps of canister migration are:<ol><li>Prepare \
                Canister Migration</li><li>Reroute Canister Ranges</li>\
                <li>Complete Canister Migration</li></ol>"
            }
            ValidNnsFunction::CompleteCanisterMigration => {
                "Remove canister migrations entries. Such entries specify that a \
                migration of canister ID ranges is currently ongoing.<br/><br/>The \
                steps of canister migration are:<ol><li>Prepare Canister Migration\
                </li><li>Reroute Canister Ranges</li><li>Complete Canister Migration\
                </li></ol>"
            }
            ValidNnsFunction::AddSnsWasm => "Add a new SNS canister WASM.",
            ValidNnsFunction::ChangeSubnetMembership => {
                "Change the membership (list) of nodes in a subnet by adding and/or \
                removing nodes from the subnet. At the time the proposal is executed, \
                the added nodes (if provided in the proposal) need to be unassigned \
                and the removed nodes (if provided in the proposal) need to be \
                assigned to the subnet. After the proposal is executed, the removed \
                nodes become unassigned, and can be reassigned to other subnets via \
                future proposals or completely removed from the network."
            }
            ValidNnsFunction::UpdateSubnetType => {
                "Add or remove a subnet type. A new subnet type can be added if it \
                doesn't already exist. An existing subnet type can be removed if no \
                subnets are assigned to it. Subnet types can be used to choose the \
                kind of subnet a canister should be created on."
            }
            ValidNnsFunction::ChangeSubnetTypeAssignment => {
                "Change the assignment of subnets to subnet types by either adding \
                subnets to or removing subnets from a subnet type. A subnet can be \
                assigned to a subnet type if the subnet is not already assigned to a \
                different subnet type and is not already in the authorized subnets \
                list (i.e., subnets authorized for certain principals) or the default \
                subnets list (i.e., default subnets that new canisters are randomly \
                created on). Once a subnet is assigned to a subnet type, it becomes \
                available to users who can specify that they want their canisters to \
                be created on subnets of that type."
            }
            ValidNnsFunction::UpdateSnsWasmSnsSubnetIds => {
                "Update the list of SNS subnet IDs that SNS-W will deploy SNS \
                instances to."
            }
            ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                "Insert custom upgrade path entries into SNS-W for all SNSs, or for \
                an SNS specified by its governance canister ID."
            }
            ValidNnsFunction::ReviseElectedGuestosVersions => {
                "A proposal to change the set of elected GuestOS versions.<br/><br/>\
                The version to elect (identified by the hash of the installation \
                image) is added to the registry. Besides creating a record for that \
                version, the proposal also appends that version to the list of \
                elected versions that can be installed on nodes of a subnet.\
                <br/><br/>Only elected GuestOS versions can be deployed."
            }
            ValidNnsFunction::BitcoinSetConfig => {
                "A proposal to set the configuration of the underlying Bitcoin \
                Canister that powers the Bitcoin API. The configuration includes \
                whether or not the Bitcoin Canister should sync new blocks from the \
                network, whether the API is enabled, the fees to charge, etc."
            }
            ValidNnsFunction::HardResetNnsRootToVersion => {
                "A proposal to hard reset the NNS root canister to a specific \
                version. This is an emergency recovery mechanism that should only be \
                used when the NNS root canister is in an unrecoverable state."
            }
            ValidNnsFunction::AddApiBoundaryNodes => {
                "A proposal to add a set of new API Boundary Nodes using unassigned \
                nodes."
            }
            ValidNnsFunction::RemoveApiBoundaryNodes => {
                "A proposal to remove a set of API Boundary Nodes, which will \
                designate them as unassigned nodes."
            }
            ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                "A proposal to update the version of a set of API Boundary Nodes."
            }
            ValidNnsFunction::DeployGuestosToAllUnassignedNodes => {
                "A proposal to update the version of all unassigned nodes."
            }
            ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                "A proposal to update SSH readonly access for all unassigned nodes."
            }
            ValidNnsFunction::ReviseElectedHostosVersions => {
                "A proposal to change the set of currently elected HostOS versions, \
                by electing a new version, and/or unelecting some priorly elected \
                versions.<br/><br/>HostOS versions are identified by the hash of the \
                installation image.<br/><br/>The version to elect is added to the \
                Registry, and the versions to unelect are removed from the Registry, \
                ensuring that HostOS cannot upgrade to these versions anymore.\
                <br/><br/>This proposal does not actually perform the upgrade; for \
                deployment of an elected version, please refer to \"Deploy HostOS To \
                Some Nodes\"."
            }
            ValidNnsFunction::DeployHostosToSomeNodes => {
                "Deploy a HostOS version to a given set of nodes. The proposal \
                changes the HostOS version that is used on the specified nodes."
            }
            ValidNnsFunction::SubnetRentalRequest => {
                "A proposal to rent a subnet on the Internet Computer.<br/><br/>The \
                Subnet Rental Canister is called when this proposal is executed, and \
                the rental request is stored there. The user specified in the \
                proposal needs to make a sufficient upfront payment in ICP in order \
                for the proposal to be valid, and the subnet must be available for \
                rent. The available rental conditions can be checked by calling the \
                Subnet Rental Canister."
            }
            ValidNnsFunction::PauseCanisterMigrations => {
                "A proposal to instruct the migration canister to not accept any more \
                migration requests."
            }
            ValidNnsFunction::UnpauseCanisterMigrations => {
                "A proposal to instruct the migration canister to accept migration \
                requests again."
            }
            ValidNnsFunction::SetSubnetOperationalLevel => {
                "A proposal to set the operational level of a subnet, which can be \
                used to take a subnet offline or bring it back online as part of \
                subnet recovery."
            }
            ValidNnsFunction::TakeCanisterSnapshot => {
                "A proposal to take a snapshot of a canister controlled the NNS. \
                 For an introduction to canister snapshots in general, see \
                 https://docs.internetcomputer.org/building-apps/canister-management/snapshots ."
            }
            ValidNnsFunction::LoadCanisterSnapshot => {
                "A proposal to load a canister snapshot into a canister controlled the NNS. \
                 In other words, to restore the canister to an earlier recorded state, \
                 which including the code and memory (including stable memory). \
                 For an introduction to canister snapshots in general, see \
                 https://docs.internetcomputer.org/building-apps/canister-management/snapshots ."
            }
        }
    }
}

impl TryFrom<NnsFunction> for ValidNnsFunction {
    type Error = String;

    fn try_from(value: NnsFunction) -> Result<Self, Self::Error> {
        let format_obsolete_message = |nns_function: &NnsFunction, replacement: &str| -> String {
            format!(
                "{} is obsolete. Use {} instead.",
                nns_function.as_str_name(),
                replacement,
            )
        };

        match value {
            NnsFunction::CreateSubnet => Ok(ValidNnsFunction::CreateSubnet),
            NnsFunction::AddNodeToSubnet => Ok(ValidNnsFunction::AddNodeToSubnet),
            NnsFunction::NnsCanisterInstall => Ok(ValidNnsFunction::NnsCanisterInstall),
            NnsFunction::RecoverSubnet => Ok(ValidNnsFunction::RecoverSubnet),
            NnsFunction::UpdateConfigOfSubnet => Ok(ValidNnsFunction::UpdateConfigOfSubnet),
            NnsFunction::AssignNoid => Ok(ValidNnsFunction::AssignNoid),
            NnsFunction::DeployGuestosToAllSubnetNodes => {
                Ok(ValidNnsFunction::DeployGuestosToAllSubnetNodes)
            }
            NnsFunction::ClearProvisionalWhitelist => {
                Ok(ValidNnsFunction::ClearProvisionalWhitelist)
            }
            NnsFunction::RemoveNodesFromSubnet => Ok(ValidNnsFunction::RemoveNodesFromSubnet),
            NnsFunction::SetAuthorizedSubnetworks => Ok(ValidNnsFunction::SetAuthorizedSubnetworks),
            NnsFunction::SetFirewallConfig => Ok(ValidNnsFunction::SetFirewallConfig),
            NnsFunction::UpdateNodeOperatorConfig => Ok(ValidNnsFunction::UpdateNodeOperatorConfig),
            NnsFunction::RemoveNodes => Ok(ValidNnsFunction::RemoveNodes),
            NnsFunction::UninstallCode => Ok(ValidNnsFunction::UninstallCode),
            NnsFunction::UpdateNodeRewardsTable => Ok(ValidNnsFunction::UpdateNodeRewardsTable),
            NnsFunction::AddOrRemoveDataCenters => Ok(ValidNnsFunction::AddOrRemoveDataCenters),
            NnsFunction::RemoveNodeOperators => Ok(ValidNnsFunction::RemoveNodeOperators),
            NnsFunction::RerouteCanisterRanges => Ok(ValidNnsFunction::RerouteCanisterRanges),
            NnsFunction::AddFirewallRules => Ok(ValidNnsFunction::AddFirewallRules),
            NnsFunction::RemoveFirewallRules => Ok(ValidNnsFunction::RemoveFirewallRules),
            NnsFunction::UpdateFirewallRules => Ok(ValidNnsFunction::UpdateFirewallRules),
            NnsFunction::PrepareCanisterMigration => Ok(ValidNnsFunction::PrepareCanisterMigration),
            NnsFunction::CompleteCanisterMigration => {
                Ok(ValidNnsFunction::CompleteCanisterMigration)
            }
            NnsFunction::AddSnsWasm => Ok(ValidNnsFunction::AddSnsWasm),
            NnsFunction::ChangeSubnetMembership => Ok(ValidNnsFunction::ChangeSubnetMembership),
            NnsFunction::UpdateSubnetType => Ok(ValidNnsFunction::UpdateSubnetType),
            NnsFunction::ChangeSubnetTypeAssignment => {
                Ok(ValidNnsFunction::ChangeSubnetTypeAssignment)
            }
            NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                Ok(ValidNnsFunction::UpdateSnsWasmSnsSubnetIds)
            }
            NnsFunction::InsertSnsWasmUpgradePathEntries => {
                Ok(ValidNnsFunction::InsertSnsWasmUpgradePathEntries)
            }
            NnsFunction::ReviseElectedGuestosVersions => {
                Ok(ValidNnsFunction::ReviseElectedGuestosVersions)
            }
            NnsFunction::BitcoinSetConfig => Ok(ValidNnsFunction::BitcoinSetConfig),
            NnsFunction::HardResetNnsRootToVersion => {
                Ok(ValidNnsFunction::HardResetNnsRootToVersion)
            }
            NnsFunction::AddApiBoundaryNodes => Ok(ValidNnsFunction::AddApiBoundaryNodes),
            NnsFunction::RemoveApiBoundaryNodes => Ok(ValidNnsFunction::RemoveApiBoundaryNodes),
            NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                Ok(ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes)
            }
            NnsFunction::DeployGuestosToAllUnassignedNodes => {
                Ok(ValidNnsFunction::DeployGuestosToAllUnassignedNodes)
            }
            NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                Ok(ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes)
            }
            NnsFunction::ReviseElectedHostosVersions => {
                Ok(ValidNnsFunction::ReviseElectedHostosVersions)
            }
            NnsFunction::DeployHostosToSomeNodes => Ok(ValidNnsFunction::DeployHostosToSomeNodes),
            NnsFunction::SubnetRentalRequest => Ok(ValidNnsFunction::SubnetRentalRequest),
            NnsFunction::PauseCanisterMigrations => Ok(ValidNnsFunction::PauseCanisterMigrations),
            NnsFunction::UnpauseCanisterMigrations => {
                Ok(ValidNnsFunction::UnpauseCanisterMigrations)
            }
            NnsFunction::SetSubnetOperationalLevel => {
                Ok(ValidNnsFunction::SetSubnetOperationalLevel)
            }
            NnsFunction::TakeCanisterSnapshot => Ok(ValidNnsFunction::TakeCanisterSnapshot),
            NnsFunction::LoadCanisterSnapshot => Ok(ValidNnsFunction::LoadCanisterSnapshot),

            // Obsolete functions - based on check_obsolete
            NnsFunction::BlessReplicaVersion | NnsFunction::RetireReplicaVersion => {
                Err(format_obsolete_message(
                    &value,
                    NnsFunction::ReviseElectedHostosVersions.as_str_name(),
                ))
            }
            NnsFunction::UpdateElectedHostosVersions => Err(format_obsolete_message(
                &value,
                NnsFunction::ReviseElectedHostosVersions.as_str_name(),
            )),
            NnsFunction::UpdateApiBoundaryNodesVersion => Err(format_obsolete_message(
                &value,
                NnsFunction::DeployGuestosToSomeApiBoundaryNodes.as_str_name(),
            )),
            NnsFunction::UpdateNodesHostosVersion => Err(format_obsolete_message(
                &value,
                NnsFunction::DeployHostosToSomeNodes.as_str_name(),
            )),
            NnsFunction::UpdateUnassignedNodesConfig => Err(format_obsolete_message(
                &value,
                &format!(
                    "{}/{}",
                    NnsFunction::DeployGuestosToAllUnassignedNodes.as_str_name(),
                    NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes.as_str_name()
                ),
            )),
            NnsFunction::NnsCanisterUpgrade | NnsFunction::NnsRootUpgrade => {
                Err(format_obsolete_message(&value, "InstallCode"))
            }
            NnsFunction::StopOrStartNnsCanister => Err(format_obsolete_message(
                &value,
                "Action::StopOrStartCanister",
            )),
            NnsFunction::UpdateAllowedPrincipals => Err(
                "NNS_FUNCTION_UPDATE_ALLOWED_PRINCIPALS is only used for the old SNS \
                initialization mechanism, which is now obsolete. Use \
                CREATE_SERVICE_NERVOUS_SYSTEM instead."
                    .to_string(),
            ),
            NnsFunction::IcpXdrConversionRate => Err(
                "NNS_FUNCTION_ICP_XDR_CONVERSION_RATE is obsolete as conversion rates \
                are now provided by the exchange rate canister automatically."
                    .to_string(),
            ),
            NnsFunction::Unspecified => {
                Err("NNS_FUNCTION_UNSPECIFIED is not a valid function".to_string())
            }
        }
    }
}

impl TryFrom<ExecuteNnsFunction> for ValidExecuteNnsFunction {
    type Error = GovernanceError;

    fn try_from(value: ExecuteNnsFunction) -> Result<Self, Self::Error> {
        // First convert i32 to NnsFunction
        let nns_function_enum = NnsFunction::try_from(value.nns_function).map_err(|_| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Invalid NnsFunction id: {}", value.nns_function),
            )
        })?;

        // Then convert NnsFunction to ValidNnsFunction
        let nns_function = ValidNnsFunction::try_from(nns_function_enum)
            .map_err(|e| GovernanceError::new_with_message(ErrorType::InvalidProposal, e))?;

        Ok(ValidExecuteNnsFunction {
            nns_function,
            payload: value.payload,
        })
    }
}

#[cfg(test)]
#[path = "execute_nns_function_tests.rs"]
pub mod tests;
