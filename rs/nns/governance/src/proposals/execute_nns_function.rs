use crate::{
    governance::Environment,
    pb::v1::{
        ExecuteNnsFunction, GenericProposalRepresentation, GenericValue as PbGenericValue,
        NnsFunction, Topic,
    },
};

use candid::{
    IDLArgs, IDLValue, Int, Nat,
    types::value::{IDLField, VariantValue},
};
use candid_parser::{IDLProg, TypeEnv, check_prog};
use ic_base_types::CanisterId;
use ic_crypto_sha2::Sha256;

#[cfg(not(feature = "test"))]
use crate::decoder_config;

#[cfg(not(feature = "test"))]
use candid::{Decode, Encode};

#[cfg(not(feature = "test"))]
use ic_management_canister_types_private::{CanisterMetadataRequest, CanisterMetadataResponse};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_governance_api::GenericValue;
use std::{str::FromStr, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub struct ValidExecuteNnsFunction {
    pub nns_function: ValidNnsFunction,
    pub payload: Vec<u8>,
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
}

impl ValidNnsFunction {
    pub fn allowed_when_resources_are_low(&self) -> bool {
        matches!(
            self,
            ValidNnsFunction::HardResetNnsRootToVersion
                | ValidNnsFunction::ReviseElectedGuestosVersions
                | ValidNnsFunction::DeployGuestosToAllSubnetNodes
        )
    }

    pub fn can_have_large_payload(&self) -> bool {
        matches!(
            self,
            ValidNnsFunction::NnsCanisterInstall
                | ValidNnsFunction::HardResetNnsRootToVersion
                | ValidNnsFunction::AddSnsWasm
        )
    }

    pub fn canister_and_function(&self) -> (CanisterId, &str) {
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
        }
    }

    pub fn compute_topic_at_creation(&self) -> Topic {
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
            | ValidNnsFunction::SetSubnetOperationalLevel => Topic::SubnetManagement,
            ValidNnsFunction::ReviseElectedGuestosVersions
            | ValidNnsFunction::ReviseElectedHostosVersions => Topic::IcOsVersionElection,
            ValidNnsFunction::DeployHostosToSomeNodes
            | ValidNnsFunction::DeployGuestosToAllSubnetNodes
            | ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes
            | ValidNnsFunction::DeployGuestosToAllUnassignedNodes => Topic::IcOsVersionDeployment,
            ValidNnsFunction::ClearProvisionalWhitelist => Topic::NetworkEconomics,
            ValidNnsFunction::SetAuthorizedSubnetworks => Topic::SubnetManagement,
            ValidNnsFunction::SetFirewallConfig => Topic::SubnetManagement,
            ValidNnsFunction::AddFirewallRules => Topic::SubnetManagement,
            ValidNnsFunction::RemoveFirewallRules => Topic::SubnetManagement,
            ValidNnsFunction::UpdateFirewallRules => Topic::SubnetManagement,
            ValidNnsFunction::UninstallCode => Topic::Governance,
            ValidNnsFunction::UpdateNodeRewardsTable => Topic::NetworkEconomics,
            ValidNnsFunction::AddOrRemoveDataCenters => Topic::ParticipantManagement,
            ValidNnsFunction::RerouteCanisterRanges => Topic::SubnetManagement,
            ValidNnsFunction::PrepareCanisterMigration => Topic::SubnetManagement,
            ValidNnsFunction::CompleteCanisterMigration => Topic::SubnetManagement,
            ValidNnsFunction::UpdateSubnetType => Topic::SubnetManagement,
            ValidNnsFunction::ChangeSubnetTypeAssignment => Topic::SubnetManagement,
            ValidNnsFunction::UpdateSnsWasmSnsSubnetIds => Topic::SubnetManagement,
            ValidNnsFunction::AddApiBoundaryNodes | ValidNnsFunction::RemoveApiBoundaryNodes => {
                Topic::ApiBoundaryNodeManagement
            }
            ValidNnsFunction::SubnetRentalRequest => Topic::SubnetRental,
            ValidNnsFunction::NnsCanisterInstall
            | ValidNnsFunction::HardResetNnsRootToVersion
            | ValidNnsFunction::BitcoinSetConfig => Topic::ProtocolCanisterManagement,
            ValidNnsFunction::AddSnsWasm | ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                Topic::ServiceNervousSystemManagement
            }
            ValidNnsFunction::PauseCanisterMigrations
            | ValidNnsFunction::UnpauseCanisterMigrations => Topic::ProtocolCanisterManagement,
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
    type Error = String;

    fn try_from(value: ExecuteNnsFunction) -> Result<Self, Self::Error> {
        // First convert i32 to NnsFunction
        let nns_function_enum = NnsFunction::try_from(value.nns_function)
            .map_err(|_| format!("Invalid NnsFunction id: {}", value.nns_function))?;

        // Then convert NnsFunction to ValidNnsFunction
        let nns_function = ValidNnsFunction::try_from(nns_function_enum)?;

        Ok(ValidExecuteNnsFunction {
            nns_function,
            payload: value.payload,
        })
    }
}

impl ValidExecuteNnsFunction {
    pub fn allowed_when_resources_are_low(&self) -> bool {
        self.nns_function.allowed_when_resources_are_low()
    }

    pub fn can_have_large_payload(&self) -> bool {
        self.nns_function.can_have_large_payload()
    }

    pub fn compute_topic_at_creation(&self) -> Topic {
        self.nns_function.compute_topic_at_creation()
    }

    pub async fn to_generic_representation(
        &self,
        env: Arc<dyn Environment>,
    ) -> Result<GenericProposalRepresentation, String> {
        let candid_source = self.get_candid_source(env).await?;
        let (_, method_name) = self.nns_function.canister_and_function();
        let generic_value = candid_to_generic(&candid_source, method_name, &self.payload)?;

        Ok(GenericProposalRepresentation {
            type_name: self.type_name(),
            type_description: self.type_description(),
            value: Some(PbGenericValue::from(generic_value)),
        })
    }

    pub fn type_name(&self) -> String {
        match &self.nns_function {
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
        }
        .to_string()
    }

    pub fn type_description(&self) -> String {
        match &self.nns_function {
            ValidNnsFunction::CreateSubnet => "Combine a specified set of nodes, typically drawn from data centers and operators in such a way as to guarantee their independence, into a new decentralized subnet. The execution of this external update first initiates a new instance of the distributed key generation protocol. The transcript of that protocol is written to a new subnet record in the registry, together with initial configuration information for the subnet, from where the nodes comprising the subnet pick it up.",
            ValidNnsFunction::AddNodeToSubnet => "Add a new node to a subnet. The node cannot be currently assigned to a subnet. The execution of this proposal changes an existing subnet record to add a node. From the perspective of the NNS, this update is a simple update of the subnet record in the registry.",
            ValidNnsFunction::NnsCanisterInstall => "A proposal to add a new canister to be installed and executed in the NNS subnetwork. The root canister, which controls all Canisters on the NNS except for itself, handles this proposal type. The call also expects the Wasm module that shall be installed.",
            ValidNnsFunction::RecoverSubnet => "Update a subnet's recovery CUP (used to recover subnets that have stalled). Nodes that find a recovery CUP for their subnet will load that CUP from the registry and restart the replica from that CUP.",
            ValidNnsFunction::UpdateConfigOfSubnet => "Update a subnet's configuration. This proposal updates the subnet record in the registry, with the changes being picked up by the nodes on the subnet when they reference the respective registry version. Subnet configuration comprises protocol parameters that must be consistent across the subnet (e.g., message sizes).",
            ValidNnsFunction::AssignNoid => "Assign an identity to a node operator associating key information regarding its ownership, the jurisdiction in which it is located, and other information. The node operator is stored as a record in the registry. It contains the remaining node allowance for that node operator, that is the number of nodes the node operator can still add to the IC. When an additional node is added by the node operator, the remaining allowance is decreased.",
            ValidNnsFunction::DeployGuestosToAllSubnetNodes => "Deploy a GuestOS version to a given subnet. The proposal changes the GuestOS version that is used on the specified subnet.<br/><br/>The version must be contained in the list of elected GuestOS versions.<br/><br/>The upgrade is completed when the subnet creates the next regular CUP.",
            ValidNnsFunction::ClearProvisionalWhitelist => "Clears the provisional whitelist, which allows the listed principals to create Canisters with cycles. The mechanism is only needed for bootstrap and testing and must be deactivated afterward.",
            ValidNnsFunction::RemoveNodesFromSubnet => "Remove a node from a subnet. It then becomes available for reassignment. The execution of this proposal changes an existing subnet record to remove a node. From the perspective of the NNS, this update is a simple update of the subnet record in the registry.",
            ValidNnsFunction::SetAuthorizedSubnetworks => "Informs the cycles minting canister that a certain principal is authorized to use certain subnetworks (from a list). Can also be used to set the \"default\" list of subnetworks that principals without special authorization are allowed to use.",
            ValidNnsFunction::SetFirewallConfig => "Change the Firewall configuration in the registry (configures which boundary nodes subnet blockchain replicas will communicate with).",
            ValidNnsFunction::UpdateNodeOperatorConfig => "Change a Node Operator's allowance in the registry.",
            ValidNnsFunction::RemoveNodes => "Remove unassigned nodes from the registry.",
            ValidNnsFunction::UninstallCode => "Uninstall code of a canister.",
            ValidNnsFunction::UpdateNodeRewardsTable => "Update the node rewards table.",
            ValidNnsFunction::AddOrRemoveDataCenters => "Add or remove Data Center records.",
            ValidNnsFunction::RemoveNodeOperators => "Remove node operator records from the registry.",
            ValidNnsFunction::RerouteCanisterRanges => "In the routing table in the registry, remap canister ID ranges from one subnet to a different subnet.<br/><br/>The steps of canister migration are:<ol><li>Prepare Canister Migration</li><li>Reroute Canister Ranges</li><li>Complete Canister Migration</li></ol>",
            ValidNnsFunction::AddFirewallRules => "Add firewall rules in the registry. Nodes use a firewall to protect themselves from network attacks.",
            ValidNnsFunction::RemoveFirewallRules => "Remove firewall rules in the registry. Nodes use a firewall to protect themselves from network attacks.",
            ValidNnsFunction::UpdateFirewallRules => "Update firewall rules in the registry. Nodes use a firewall to protect themselves from network attacks.",
            ValidNnsFunction::PrepareCanisterMigration => "Insert or update canister migrations entries. Such entries specify that a migration of canister ID ranges is currently ongoing.<br/><br/>The steps of canister migration are:<ol><li>Prepare Canister Migration</li><li>Reroute Canister Ranges</li><li>Complete Canister Migration</li></ol>",
            ValidNnsFunction::CompleteCanisterMigration => "Remove canister migrations entries. Such entries specify that a migration of canister ID ranges is currently ongoing.<br/><br/>The steps of canister migration are:<ol><li>Prepare Canister Migration</li><li>Reroute Canister Ranges</li><li>Complete Canister Migration</li></ol>",
            ValidNnsFunction::AddSnsWasm => "Add a new SNS canister WASM.",
            ValidNnsFunction::ChangeSubnetMembership => "Change the membership (list) of nodes in a subnet by adding and/or removing nodes from the subnet. At the time the proposal is executed, the added nodes (if provided in the proposal) need to be unassigned and the removed nodes (if provided in the proposal) need to be assigned to the subnet. After the proposal is executed, the removed nodes become unassigned, and can be reassigned to other subnets via future proposals or completely removed from the network.",
            ValidNnsFunction::UpdateSubnetType => "Add or remove a subnet type. A new subnet type can be added if it doesn't already exist. An existing subnet type can be removed if no subnets are assigned to it. Subnet types can be used to choose the kind of subnet a canister should be created on.",
            ValidNnsFunction::ChangeSubnetTypeAssignment => "Change the assignment of subnets to subnet types by either adding subnets to or removing subnets from a subnet type. A subnet can be assigned to a subnet type if the subnet is not already assigned to a different subnet type and is not already in the authorized subnets list (i.e., subnets authorized for certain principals) or the default subnets list (i.e., default subnets that new canisters are randomly created on). Once a subnet is assigned to a subnet type, it becomes available to users who can specify that they want their canisters to be created on subnets of that type.",
            ValidNnsFunction::UpdateSnsWasmSnsSubnetIds => "Update the list of SNS subnet IDs that SNS-W will deploy SNS instances to.",
            ValidNnsFunction::InsertSnsWasmUpgradePathEntries => "Insert custom upgrade path entries into SNS-W for all SNSs, or for an SNS specified by its governance canister ID.",
            ValidNnsFunction::ReviseElectedGuestosVersions => "A proposal to change the set of elected GuestOS versions.<br/><br/>The version to elect (identified by the hash of the installation image) is added to the registry. Besides creating a record for that version, the proposal also appends that version to the list of elected versions that can be installed on nodes of a subnet.<br/><br/>Only elected GuestOS versions can be deployed.",
            ValidNnsFunction::BitcoinSetConfig => "A proposal to set the configuration of the underlying Bitcoin Canister that powers the Bitcoin API. The configuration includes whether or not the Bitcoin Canister should sync new blocks from the network, whether the API is enabled, the fees to charge, etc.",
            ValidNnsFunction::HardResetNnsRootToVersion => "A proposal to hard reset the NNS root canister to a specific version. This is an emergency recovery mechanism that should only be used when the NNS root canister is in an unrecoverable state.",
            ValidNnsFunction::AddApiBoundaryNodes => "A proposal to add a set of new API Boundary Nodes using unassigned nodes.",
            ValidNnsFunction::RemoveApiBoundaryNodes => "A proposal to remove a set of API Boundary Nodes, which will designate them as unassigned nodes.",
            ValidNnsFunction::DeployGuestosToSomeApiBoundaryNodes => "A proposal to update the version of a set of API Boundary Nodes.",
            ValidNnsFunction::DeployGuestosToAllUnassignedNodes => "A proposal to update the version of all unassigned nodes.",
            ValidNnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => "A proposal to update SSH readonly access for all unassigned nodes.",
            ValidNnsFunction::ReviseElectedHostosVersions => "A proposal to change the set of currently elected HostOS versions, by electing a new version, and/or unelecting some priorly elected versions.<br/><br/>HostOS versions are identified by the hash of the installation image.<br/><br/>The version to elect is added to the Registry, and the versions to unelect are removed from the Registry, ensuring that HostOS cannot upgrade to these versions anymore.<br/><br/>This proposal does not actually perform the upgrade; for deployment of an elected version, please refer to \"Deploy HostOS To Some Nodes\".",
            ValidNnsFunction::DeployHostosToSomeNodes => "Deploy a HostOS version to a given set of nodes. The proposal changes the HostOS version that is used on the specified nodes.",
            ValidNnsFunction::SubnetRentalRequest => "A proposal to rent a subnet on the Internet Computer.<br/><br/>The Subnet Rental Canister is called when this proposal is executed, and the rental request is stored there. The user specified in the proposal needs to make a sufficient upfront payment in ICP in order for the proposal to be valid, and the subnet must be available for rent. The available rental conditions can be checked by calling the Subnet Rental Canister.",
            ValidNnsFunction::PauseCanisterMigrations => "A proposal to instruct the migration canister to not accept any more migration requests.",
            ValidNnsFunction::UnpauseCanisterMigrations => "A proposal to instruct the migration canister to accept migration requests again.",
            ValidNnsFunction::SetSubnetOperationalLevel => "A proposal to set the operational level of a subnet, which can be used to take a subnet offline or bring it back online as part of subnet recovery.",
        }.to_string()
    }

    #[cfg(not(feature = "test"))]
    async fn get_candid_source(&self, env: Arc<dyn Environment>) -> Result<String, String> {
        let (canister_id, _method_name) = self.nns_function.canister_and_function();
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
            .expect("Failed to decode response");
        Ok(String::from_utf8(decoded_response.value().to_vec()).unwrap())
    }

    #[cfg(feature = "test")]
    async fn get_candid_source(&self, _env: Arc<dyn Environment>) -> Result<String, String> {
        let (canister_id, _) = self.nns_function.canister_and_function();
        let candid_source = if canister_id == ROOT_CANISTER_ID {
            r#"type AddCanisterRequest = record {
  arg : blob;
  initial_cycles : nat64;
  wasm_module : blob;
  name : text;
  memory_allocation : opt nat;
  compute_allocation : opt nat;
};

type CanisterAction = variant {
  Start;
  Stop;
};

type CanisterIdRecord = record {
  canister_id : principal;
};

type CanisterInstallMode = variant {
  reinstall;
  upgrade;
  install;
};

type CanisterSettings = record {
  freezing_threshold : opt nat;
  controllers : opt vec principal;
  reserved_cycles_limit : opt nat;
  log_visibility : opt LogVisibility;
  wasm_memory_limit : opt nat;
  memory_allocation : opt nat;
  compute_allocation : opt nat;
  wasm_memory_threshold : opt nat;
};

type MemoryMetrics = record {
  wasm_memory_size : opt nat;
  stable_memory_size : opt nat;
  global_memory_size : opt nat;
  wasm_binary_size : opt nat;
  custom_sections_size : opt nat;
  canister_history_size : opt nat;
  wasm_chunk_store_size : opt nat;
  snapshots_size : opt nat;
};

type CanisterStatusResult = record {
  status : CanisterStatusType;
  memory_size : nat;
  cycles : nat;
  settings : DefiniteCanisterSettings;
  idle_cycles_burned_per_day : opt nat;
  module_hash : opt blob;
  reserved_cycles : opt nat;
  query_stats : opt QueryStats;
  memory_metrics : opt MemoryMetrics;
};

type CanisterStatusType = variant {
  stopped;
  stopping;
  running;
};

type ChangeCanisterControllersError = record {
  code : opt int32;
  description : text;
};

type ChangeCanisterControllersRequest = record {
  target_canister_id : principal;
  new_controllers : vec principal;
};

type ChangeCanisterControllersResponse = record {
  change_canister_controllers_result : ChangeCanisterControllersResult;
};

type ChangeCanisterControllersResult = variant {
  Ok;
  Err : ChangeCanisterControllersError;
};

type ChunkedCanisterWasm = record {
  wasm_module_hash : blob;
  store_canister_id : principal;
  chunk_hashes_list : vec blob;
};

type ChangeCanisterRequest = record {
  arg : blob;
  wasm_module : blob;
  chunked_canister_wasm : opt ChunkedCanisterWasm;
  stop_before_installing : bool;
  mode : CanisterInstallMode;
  canister_id : principal;
};

type DefiniteCanisterSettings = record {
  freezing_threshold : opt nat;
  controllers : vec principal;
  reserved_cycles_limit : opt nat;
  log_visibility : opt CanisterStatusLogVisibility;
  wasm_memory_limit : opt nat;
  memory_allocation : opt nat;
  compute_allocation : opt nat;
  wasm_memory_threshold : opt nat;
};

type LogVisibility = variant {
  controllers;
  public;
};

type CanisterStatusLogVisibility = variant {
  controllers;
  public;
  allowed_viewers : vec principal;
};

type QueryStats = record {
  num_calls_total : opt nat;
  num_instructions_total : opt nat;
  request_payload_bytes_total : opt nat;
  response_payload_bytes_total : opt nat;
};

type StopOrStartCanisterRequest = record {
  action : CanisterAction;
  canister_id : principal;
};

type UpdateCanisterSettingsError = record {
  code : opt int32;
  description : text;
};

type UpdateCanisterSettingsRequest = record {
  canister_id : principal;
  settings : CanisterSettings;
};

type UpdateCanisterSettingsResponse = variant {
  Ok;
  Err : UpdateCanisterSettingsError;
};

service : () -> {
  add_nns_canister : (AddCanisterRequest) -> ();
  canister_status : (CanisterIdRecord) -> (CanisterStatusResult);
  change_canister_controllers : (ChangeCanisterControllersRequest) -> (
      ChangeCanisterControllersResponse,
    );
  change_nns_canister : (ChangeCanisterRequest) -> ();
  get_build_metadata : () -> (text) query;
  stop_or_start_nns_canister : (StopOrStartCanisterRequest) -> ();
  update_canister_settings : (UpdateCanisterSettingsRequest) -> (
      UpdateCanisterSettingsResponse,
    );
}
"#
            .to_string()
        } else if canister_id == CYCLES_MINTING_CANISTER_ID {
            r#"type Cycles = nat;
type BlockIndex = nat64;
type log_visibility = variant {
  controllers;
  public;
};
type environment_variable = record { 
  name: text; 
  value: text;
};
type CanisterSettings = record {
  controllers : opt vec principal;
  compute_allocation : opt nat;
  memory_allocation : opt nat;
  freezing_threshold : opt nat;
  reserved_cycles_limit : opt nat;
  log_visibility : opt log_visibility;
  wasm_memory_limit : opt nat;
  wasm_memory_threshold : opt nat;
  environment_variables : opt vec environment_variable;
};
type Subaccount = opt blob;
type Memo = opt blob;

// The argument of the [notify_top_up] method.
type NotifyTopUpArg = record {
  // Index of the block on the ICP ledger that contains the payment.
  block_index : BlockIndex;

  // The canister to top up.
  canister_id : principal;
};

type SubnetSelection = variant {
  /// Choose a specific subnet
  Subnet : record {
    subnet : principal;
  };
  /// Choose a random subnet that fulfills the specified properties
  Filter : SubnetFilter;
};

type SubnetFilter = record {
  subnet_type : opt text;
};

// The argument of the [create_canister] method.
type CreateCanisterArg = record {
  // Optional canister settings that, if set, are applied to the newly created canister.
  // If not specified, the caller is the controller of the canister and the other settings are set to default values.
  settings : opt CanisterSettings;

  // An optional subnet type that, if set, determines what type of subnet
  // the new canister will be created on.
  // Deprecated. Use subnet_selection instead.
  subnet_type : opt text;

  // Optional instructions to select on which subnet the new canister will be created on.
  subnet_selection : opt SubnetSelection;
};

// The argument of the [notify_create_canister] method.
type NotifyCreateCanisterArg = record {
  // Index of the block on the ICP ledger that contains the payment.
  block_index : BlockIndex;

  // The controller of canister to create.
  controller : principal;

  // An optional subnet type that, if set, determines what type of subnet
  // the new canister will be created on.
  // Deprecated. Use subnet_selection instead.
  subnet_type : opt text;

  // Optional instructions to select on which subnet the new canister will be created on.
  // vec may contain no more than one element.
  subnet_selection : opt SubnetSelection;

  // Optional canister settings that, if set, are applied to the newly created canister.
  // If not specified, the caller is the controller of the canister and the other settings are set to default values.
  settings : opt CanisterSettings;
};

// Canister creation failed and the cycles attached to the call were returned to the calling canister.
// A small fee may be charged.
type CreateCanisterError = variant {
  Refunded : record {
    // The amount of cycles returned to the calling canister
    refund_amount : nat;

    // The reason why creating a canister failed.
    create_error : text;
  };
};

type NotifyError = variant {
  // The payment processing failed and the payment was returned the caller.
  // This is a non-retriable error.
  Refunded : record {
    // The reason for the refund.
    reason : text;
    // The index of the block containing the refund.
    block_index : opt BlockIndex;
  };

  // The same payment is already being processed by a concurrent request.
  // This is a retriable error.
  Processing;

  // The payment was too old to be processed.
  // The value of the variant is the oldest block index that can still be processed.
  // This a non-retriable error.
  TransactionTooOld : BlockIndex;

  // The transaction does not satisfy the cycle minting canister payment protocol.
  // The text contains the description of the problem.
  // This is a non-retriable error.
  InvalidTransaction : text;

  // Other error.
  Other : record { error_code : nat64; error_message : text };
};

type NotifyTopUpResult = variant {
  // The amount of cycles sent to the specified canister.
  Ok : Cycles;
  Err : NotifyError;
};

type CreateCanisterResult = variant {
  // The principal of the newly created canister.
  Ok : principal;
  Err : CreateCanisterError;
};

type NotifyCreateCanisterResult = variant {
  // The principal of the newly created canister.
  Ok : principal;
  Err : NotifyError;
};

type IcpXdrConversionRate = record {
  // The time for which the market data was queried, expressed in UNIX epoch
  // time in seconds.
  timestamp_seconds : nat64;

  // The number of 10,000ths of IMF SDR (currency code XDR) that corresponds
  // to 1 ICP. This value reflects the current market price of one ICP token.
  xdr_permyriad_per_icp : nat64;
};

type IcpXdrConversionRateResponse = record {
  // The latest ICP/XDR conversion rate.
  data : IcpXdrConversionRate;

  // CBOR-serialized hash tree as specified in
  // https://internetcomputer.org/docs/interface-spec/index.html#certification-encoding
  // The hash tree is used for certification and hash the following structure:
  // ```
  // *
  // |
  // +-- ICP_XDR_CONVERSION_RATE -- [ Candid encoded IcpXdrConversionRate ]
  // |
  // `-- AVERAGE_ICP_XDR_CONVERSION_RATE -- [ Candid encoded IcpXdrConversionRate ]
  // ```
  hash_tree : blob;

  // System certificate as specified in
  // https://internetcomputer.org/docs/interface-spec/index.html#certification-encoding
  certificate : blob;
};

type SubnetTypesToSubnetsResponse = record {
  data : vec record { text; vec principal };
};

type PrincipalsAuthorizedToCreateCanistersToSubnetsResponse = record {
  data : vec record { principal; vec principal };
};

type AccountIdentifier = text;

type ExchangeRateCanister = variant {
  /// Enables the exchange rate canister with the given canister ID.
  Set : principal;
  /// Disable the exchange rate canister.
  Unset;
};

type CyclesCanisterInitPayload = record {
  ledger_canister_id : opt principal;
  governance_canister_id : opt principal;
  minting_account_id : opt AccountIdentifier;
  last_purged_notification : opt nat64;
  exchange_rate_canister : opt ExchangeRateCanister;
  cycles_ledger_canister_id : opt principal;
};

type NotifyMintCyclesArg = record {
  block_index : BlockIndex;
  to_subaccount : Subaccount;
  deposit_memo : Memo;
};

type NotifyMintCyclesResult = variant {
  Ok : NotifyMintCyclesSuccess;
  Err : NotifyError;
};

type NotifyMintCyclesSuccess = record {
  // Cycles ledger block index of deposit
  block_index : nat;
  // Amount of cycles that were minted and deposited to the cycles ledger
  minted : nat;
  // New balance of the cycles ledger account
  balance : nat;
};

service : (opt CyclesCanisterInitPayload) -> {
  // Prompts the cycles minting canister to process a payment by converting ICP
  // into cycles and sending the cycles the specified canister.
  notify_top_up : (NotifyTopUpArg) -> (NotifyTopUpResult);

  // Creates a canister using the cycles attached to the function call.
  create_canister : (CreateCanisterArg) -> (CreateCanisterResult);

  // Prompts the cycles minting canister to process a payment for canister creation.
  notify_create_canister : (NotifyCreateCanisterArg) -> (NotifyCreateCanisterResult);

  // Mints cycles and deposits them to the cycles ledger
  notify_mint_cycles : (NotifyMintCyclesArg) -> (NotifyMintCyclesResult);

  // Returns the ICP/XDR conversion rate.
  get_icp_xdr_conversion_rate : () -> (IcpXdrConversionRateResponse) query;

  // Returns the current mapping of subnet types to subnets.
  get_subnet_types_to_subnets : () -> (SubnetTypesToSubnetsResponse) query;

  // Returns the mapping from principals to subnets in which they are authorized
  // to create canisters.
  get_principals_authorized_to_create_canisters_to_subnets : () -> (PrincipalsAuthorizedToCreateCanistersToSubnetsResponse) query;

  get_default_subnets: () -> (vec principal) query;

  get_build_metadata : () -> (text) query;
};
"#.to_string()
        } else if canister_id == LIFELINE_CANISTER_ID {
            r#"type UpgradeRootProposalPayload = record {
  module_arg: blob;
  stop_upgrade_start: bool;
  wasm_module: blob;
};
type HardResetRootToVersionPayload = record {
  wasm_module: blob;
  init_arg: blob;
};
type CanisterSettings = record {
  controllers: opt vec principal;
  compute_allocation: opt nat;
  memory_allocation: opt nat;
  freezing_threshold: opt nat;
  reserved_cycles_limit: opt nat;
  wasm_memory_limit: opt nat;
  log_visibility: opt LogVisibility;
  wasm_memory_threshold: opt nat;
};
type LogVisibility = variant { controllers; public };

service : {
  upgrade_root: (UpgradeRootProposalPayload) -> ();
  hard_reset_root_to_version: (HardResetRootToVersionPayload) -> ();
  upgrade_root_settings: (CanisterSettings) -> ();
}
"#
            .to_string()
        } else if canister_id == SUBNET_RENTAL_CANISTER_ID {
            r#"type Event = record { event : EventType; time_nanos : nat64 };
type EventPage = record { events : vec Event; continuation : nat64 };
type EventType = variant {
  RentalRequestCancelled : record { rental_request : RentalRequest };
  PaymentSuccess : record {
    covered_until_nanos : nat64;
    cycles : nat;
    amount : Tokens;
  };
  Undegraded;
  LockingSuccess : record { user : principal; cycles : nat; amount : Tokens };
  RentalAgreementTerminated : record {
    initial_proposal_id : nat64;
    user : principal;
    rental_condition_id : RentalConditionId;
    subnet_creation_proposal_id : opt nat64;
  };
  PaymentFailure : record { reason : text };
  RentalRequestCreated : record { rental_request : RentalRequest };
  Degraded;
  RentalConditionsChanged : record {
    rental_condition_id : RentalConditionId;
    rental_conditions : opt RentalConditions;
  };
  LockingFailure : record { user : principal; reason : text };
  Other : record { message : text };
  RentalAgreementCreated : record {
    initial_proposal_id : nat64;
    user : principal;
    rental_condition_id : RentalConditionId;
    subnet_creation_proposal_id : opt nat64;
  };
  RentalRequestFailed : record {
    user : principal;
    proposal_id : nat64;
    reason : text;
  };
  TransferSuccess : record { block_index : nat64; amount : Tokens };
};
type RentalConditionId = variant { App13CH };
type RentalConditions = record {
  daily_cost_cycles : nat;
  subnet_id : opt principal;
  description : text;
  initial_rental_period_days : nat64;
  billing_period_days : nat64;
};
type RentalRequest = record {
  locked_amount_icp : Tokens;
  initial_proposal_id : nat64;
  user : principal;
  rental_condition_id : RentalConditionId;
  last_locking_time_nanos : nat64;
  initial_cost_icp : Tokens;
  creation_time_nanos : nat64;
  locked_amount_cycles : nat;
};
type Result = variant { Ok : Tokens; Err : text };
type Result_1 = variant { Ok : nat64; Err : text };
type SubnetRentalProposalPayload = record {
  user : principal;
  rental_condition_id : RentalConditionId;
  proposal_creation_time_seconds : nat64;
  proposal_id : nat64;
};
type Tokens = record { e8s : nat64 };
service : {
  execute_rental_request_proposal : (SubnetRentalProposalPayload) -> ();
  get_history_page : (principal, opt nat64) -> (EventPage) query;
  get_payment_account : (principal) -> (text) query;
  get_rental_conditions_history_page : (opt nat64) -> (EventPage) query;
  get_todays_price : (RentalConditionId) -> (Result);
  list_rental_conditions : () -> (
      vec record { RentalConditionId; RentalConditions },
    ) query;
  list_rental_requests : () -> (vec RentalRequest) query;
  refund : () -> (Result_1);
}
"#
            .to_string()
        } else if canister_id == MIGRATION_CANISTER_ID {
            r#"type MigrationCanisterInitPayload = record {};

service : (opt MigrationCanisterInitPayload) -> {

};
"#
            .to_string()
        } else if canister_id == REGISTRY_CANISTER_ID {
            r#"// A brief note about the history of this file: This file used to be
// automatically generated, but now, it is hand-crafted, because the
// auto-generator has some some pretty degenerate behaviors. The worst of those
// behaviors are 1. type conflation 2. (unstable) numeric suffixes. These
// behaviors made it impractical for clients to do the right thing: program
// against registry.did (by using `didc bind`).
//
// test_implementated_interface_matches_declared_interface_exactly (defined in
// ./tests.rs) ensures that the implementation stays in sync with this file.

type AddApiBoundaryNodesPayload = record {
  version : text;
  node_ids : vec principal;
};

type AddFirewallRulesPayload = record {
  expected_hash : text;
  scope : FirewallRulesScope;
  positions : vec int32;
  rules : vec FirewallRule;
};

type AddNodeOperatorPayload = record {
  ipv6 : opt text;
  node_operator_principal_id : opt principal;
  node_allowance : nat64;
  rewardable_nodes : vec record { text; nat32 };
  node_provider_principal_id : opt principal;
  dc_id : text;
  max_rewardable_nodes : opt vec record { text; nat32 };
};

type AddNodePayload = record {
  prometheus_metrics_endpoint : text;
  http_endpoint : text;
  idkg_dealing_encryption_pk : opt blob;
  domain : opt text;
  public_ipv4_config : opt IPv4Config;
  xnet_endpoint : text;
  chip_id : opt blob;
  committee_signing_pk : blob;
  node_signing_pk : blob;
  transport_tls_cert : blob;
  ni_dkg_dealing_encryption_pk : blob;
  p2p_flow_endpoints : vec text;
  node_reward_type : opt text;
};

type AddNodesToSubnetPayload = record {
  subnet_id : principal;
  node_ids : vec principal;
};

type AddOrRemoveDataCentersProposalPayload = record {
  data_centers_to_add : vec DataCenterRecord;
  data_centers_to_remove : vec text;
};

type CanisterIdRange = record { end : principal; start : principal };

type ChangeSubnetMembershipPayload = record {
  node_ids_add : vec principal;
  subnet_id : principal;
  node_ids_remove : vec principal;
};

type CompleteCanisterMigrationPayload = record {
  canister_id_ranges : vec CanisterIdRange;
  migration_trace : vec principal;
};

type CreateSubnetPayload = record {
  unit_delay_millis : nat64;
  features : SubnetFeatures;
  max_ingress_bytes_per_message : nat64;
  dkg_dealings_per_block : nat64;
  max_block_payload_size : nat64;
  start_as_nns : bool;
  is_halted : bool;
  max_ingress_messages_per_block : nat64;
  max_number_of_canisters : nat64;
  chain_key_config : opt InitialChainKeyConfig;
  replica_version_id : text;
  dkg_interval_length : nat64;
  subnet_id_override : opt principal;
  ssh_backup_access : vec text;
  initial_notary_delay_millis : nat64;
  subnet_type : SubnetType;
  ssh_readonly_access : vec text;
  node_ids : vec principal;

  canister_cycles_cost_schedule: opt CanisterCyclesCostSchedule;

  // TODO(NNS1-2444): The fields below are deprecated and they are not read anywhere.
  ingress_bytes_per_block_soft_cap : nat64;
  gossip_max_artifact_streams_per_peer : nat32;
  gossip_max_chunk_size : nat32;
  gossip_max_chunk_wait_ms : nat32;
  gossip_max_duplicity : nat32;
  gossip_pfn_evaluation_period_ms : nat32;
  gossip_receive_check_cache_size : nat32;
  gossip_registry_poll_period_ms : nat32;
  gossip_retransmission_request_ms : nat32;
};

type CreateSubnetResponse = variant {
  Ok : record {
    new_subnet_id : opt principal;
  };

  Err: text;
};

type CanisterCyclesCostSchedule = variant {
  Normal;
  Free;
};

type DataCenterRecord = record {
  id : text;
  gps : opt Gps;
  region : text;
  owner : text;
};

type DeployGuestosToAllSubnetNodesPayload = record {
  subnet_id : principal;
  replica_version_id : text;
};

type DeployGuestosToAllUnassignedNodesPayload = record {
  elected_replica_version : text;
};

type InitialChainKeyConfig = record {
  key_configs : vec KeyConfigRequest;
  signature_request_timeout_ns : opt nat64;
  idkg_key_rotation_period_ms : opt nat64;
  max_parallel_pre_signature_transcripts_in_creation : opt nat32;
};

type KeyConfigRequest = record {
  key_config : opt KeyConfig;
  subnet_id : opt principal;
};

type KeyConfig = record {
  key_id : opt MasterPublicKeyId;
  pre_signatures_to_create_in_advance : opt nat32;
  max_queue_size : opt nat32;
};

type MasterPublicKeyId = variant { Schnorr : SchnorrKeyId; Ecdsa : EcdsaKeyId; VetKd : VetKdKeyId };

type SchnorrKeyId = record { algorithm : SchnorrAlgorithm; name : text };

type SchnorrAlgorithm = variant { ed25519; bip340secp256k1 };

type VetKdKeyId = record { curve: VetKdCurve; name: text };

type VetKdCurve = variant { bls12_381_g2 };

type EcdsaCurve = variant { secp256k1 };

type EcdsaKeyId = record { name : text; curve : EcdsaCurve };

type FirewallRule = record {
  ipv4_prefixes : vec text;
  direction : opt int32;
  action : int32;
  user : opt text;
  comment : text;
  ipv6_prefixes : vec text;
  ports : vec nat32;
};

type FirewallRulesScope = variant {
  Node : principal;
  ReplicaNodes;
  ApiBoundaryNodes;
  Subnet : principal;
  Global;
};

type GetApiBoundaryNodeIdsRequest = record {

};

type GetApiBoundaryNodeIdsResponse = variant {
    Ok : vec ApiBoundaryNodeIdRecord;
    Err : text;
};

type ApiBoundaryNodeIdRecord = record {
  id : opt principal;
};

type GetChunkRequest = record {
  content_sha256 : opt blob;
};

type GetChunkResponse = variant {
  Ok : Chunk;
  Err : text;
};

type Chunk = record {
  content : opt blob;
};

type GetNodeOperatorsAndDcsOfNodeProviderResponse = variant {
  Ok : vec record { DataCenterRecord; NodeOperatorRecord };
  Err : text;
};

type GetNodeProvidersMonthlyXdrRewardsResponse = variant {
  Ok : NodeProvidersMonthlyXdrRewards;
  Err : text;
};

type GetSubnetForCanisterRequest = record { "principal" : opt principal };

type GetSubnetForCanisterResponse = variant {
  Ok : record { subnet_id : opt principal };
  Err : text;
};

type GetNodeProvidersMonthlyXdrRewardsRequest = record {
    registry_version: opt nat64;
};

type Gps = record { latitude : float32; longitude : float32 };

type IPv4Config = record {
  prefix_length : nat32;
  gateway_ip_addr : text;
  ip_addr : text;
};

type MigrateCanistersPayload = record {
  canister_ids : vec principal;
  target_subnet_id : principal;
};

type MigrateCanistersResponse = record {
  registry_version: nat64;
};

type NodeOperatorRecord = record {
  ipv6 : opt text;
  max_rewardable_nodes : vec record { text; nat32 };
  node_operator_principal_id : blob;
  node_allowance : nat64;
  rewardable_nodes : vec record { text; nat32 };
  node_provider_principal_id : blob;
  dc_id : text;
};

type NodeProvidersMonthlyXdrRewards = record {
  rewards : vec record { text; nat64 };
  registry_version : opt nat64;
};

type NodeRewardRate = record {
  xdr_permyriad_per_node_per_month : nat64;
  reward_coefficient_percent : opt int32;
};

type NodeRewardRates = record { rates : vec record { text; NodeRewardRate } };

type PrepareCanisterMigrationPayload = record {
  canister_id_ranges : vec CanisterIdRange;
  source_subnet : principal;
  destination_subnet : principal;
};

type RecoverSubnetPayload = record {
  height : nat64;
  replacement_nodes : opt vec principal;
  subnet_id : principal;
  registry_store_uri : opt record { text; text; nat64 };
  chain_key_config : opt InitialChainKeyConfig;
  state_hash : blob;
  time_ns : nat64;
};

type RemoveApiBoundaryNodesPayload = record { node_ids : vec principal };

type RemoveFirewallRulesPayload = record {
  expected_hash : text;
  scope : FirewallRulesScope;
  positions : vec int32;
};

type RemoveNodeDirectlyPayload = record { node_id : principal };

type RemoveNodeOperatorsPayload = record {
  node_operators_to_remove : vec blob;
  node_operator_principals_to_remove : opt NodeOperatorPrincipals;
};

type NodeOperatorPrincipals = record {
  principals : vec principal;
};

type RemoveNodesPayload = record { node_ids : vec principal };

type RemoveNodesFromSubnetPayload = record { node_ids : vec principal };

type RerouteCanisterRangesPayload = record {
  source_subnet : principal;
  reassigned_canister_ranges : vec CanisterIdRange;
  destination_subnet : principal;
};

type ReviseElectedGuestosVersionsPayload = record {
  release_package_urls : vec text;
  replica_versions_to_unelect : vec text;
  replica_version_to_elect : opt text;
  guest_launch_measurements : opt GuestLaunchMeasurements;
  release_package_sha256_hex : opt text;
};

type GuestLaunchMeasurements = record {
 guest_launch_measurements : vec record {
   metadata : opt record { kernel_cmdline : text };
   measurement : blob;
 };
};

type SetFirewallConfigPayload = record {
  ipv4_prefixes : vec text;
  firewall_config : text;
  ipv6_prefixes : vec text;
};

type SubnetFeatures = record {
  canister_sandboxing : bool;
  http_requests : bool;
  sev_enabled : opt bool;
};

type SubnetType = variant { application; verified_application; system };

type UpdateApiBoundaryNodesVersionPayload = record {
  version : text;
  node_ids : vec principal;
};

type DeployGuestosToSomeApiBoundaryNodes = record {
  version : text;
  node_ids : vec principal;
};

type UpdateElectedHostosVersionsPayload = record {
  release_package_urls : vec text;
  hostos_version_to_elect : opt text;
  hostos_versions_to_unelect : vec text;
  release_package_sha256_hex : opt text;
};

type ReviseElectedHostosVersionsPayload = record {
  release_package_urls : vec text;
  hostos_version_to_elect : opt text;
  hostos_versions_to_unelect : vec text;
  release_package_sha256_hex : opt text;
};

type UpdateFirewallRulesPayload = record {
  expected_hash : text;
  scope : FirewallRulesScope;
  positions : vec int32;
  rules : vec FirewallRule;
};

type UpdateNodeDirectlyPayload = record {
  idkg_dealing_encryption_pk : opt blob;
};

type UpdateNodeDomainDirectlyPayload = record {
  node_id : principal;
  domain : opt text;
};

type UpdateNodeDomainDirectlyResponse = variant { Ok; Err : text };

type UpdateNodeIPv4ConfigDirectlyPayload = record {
  ipv4_config : opt IPv4Config;
  node_id : principal;
};

type UpdateNodeIpv4ConfigDirectlyResponse = variant { Ok; Err : text };

type UpdateNodeOperatorConfigDirectlyPayload = record {
  node_operator_id : opt principal;
  node_provider_id : opt principal;
};

type UpdateNodeOperatorConfigPayload = record {
  node_operator_id : opt principal;
  set_ipv6_to_none : opt bool;
  ipv6 : opt text;
  node_provider_id : opt principal;
  node_allowance : opt nat64;
  rewardable_nodes : vec record { text; nat32 };
  dc_id : opt text;
  max_rewardable_nodes : opt vec record { text; nat32 };
};

type UpdateNodeRewardsTableProposalPayload = record {
  new_entries : vec record { text; NodeRewardRates };
};

type UpdateNodesHostosVersionPayload = record {
  hostos_version_id : opt text;
  node_ids : vec principal;
};

type DeployHostosToSomeNodes = record {
  hostos_version_id : opt text;
  node_ids : vec principal;
};

type UpdateSshReadOnlyAccessForAllUnassignedNodesPayload = record {
  ssh_readonly_keys : vec text;
};

type UpdateSubnetPayload = record {
  unit_delay_millis : opt nat64;
  max_duplicity : opt nat32;
  features : opt SubnetFeatures;
  set_gossip_config_to_default : bool;
  halt_at_cup_height : opt bool;
  pfn_evaluation_period_ms : opt nat32;
  subnet_id : principal;
  max_ingress_bytes_per_message : opt nat64;
  dkg_dealings_per_block : opt nat64;
  max_block_payload_size : opt nat64;
  start_as_nns : opt bool;
  is_halted : opt bool;
  max_ingress_messages_per_block : opt nat64;
  max_number_of_canisters : opt nat64;
  retransmission_request_ms : opt nat32;
  dkg_interval_length : opt nat64;
  registry_poll_period_ms : opt nat32;
  max_chunk_wait_ms : opt nat32;
  receive_check_cache_size : opt nat32;
  ssh_backup_access : opt vec text;
  max_chunk_size : opt nat32;
  initial_notary_delay_millis : opt nat64;
  max_artifact_streams_per_peer : opt nat32;
  subnet_type : opt SubnetType;
  ssh_readonly_access : opt vec text;
  chain_key_config : opt ChainKeyConfig;
  chain_key_signing_enable : opt vec MasterPublicKeyId;
  chain_key_signing_disable : opt vec MasterPublicKeyId;
};

type ChainKeyConfig = record {
  key_configs : vec KeyConfig;
  signature_request_timeout_ns : opt nat64;
  idkg_key_rotation_period_ms : opt nat64;
  max_parallel_pre_signature_transcripts_in_creation : opt nat32;
};

type UpdateUnassignedNodesConfigPayload = record {
  replica_version : opt text;
  ssh_readonly_access : opt vec text;
};

type SwapNodeInSubnetDirectlyPayload = record {
  new_node_id : opt principal;
  old_node_id : opt principal;
};

// Used to perform the first and last steps of subnet recovery.
type SetSubnetOperationalLevelPayload = record {
  // Which subnet not modify (if any).
  subnet_id : opt principal;

  // 1 = Normal. This results in setting is_halted in SubnetRecord to false.
  // 2 = DownForRepairs. This results in setting is_halted in SubnetRecord to true.
  operational_level : opt int32;

  // SSH public keys that are allowed to ssh into nodes of the subnet with
  // read-only access.
  ssh_readonly_access : opt vec text;

  // Similar to ssh_read_only_access, except that this targets one node at a
  // time, not all the nodes in the subnet.
  ssh_node_state_write_access : opt vec NodeSshAccess;
};

type NodeSshAccess = record {
  // Doesn't make sense without this. (opt for future compatibility.)
  node_id : opt principal;

  // Doesn't make sense without this. (opt for future compatibility.)
  public_keys : opt vec text;
};

service : {
  add_api_boundary_nodes : (AddApiBoundaryNodesPayload) -> ();
  add_firewall_rules : (AddFirewallRulesPayload) -> ();
  add_node : (AddNodePayload) -> (principal);
  add_node_operator : (AddNodeOperatorPayload) -> ();
  add_nodes_to_subnet : (AddNodesToSubnetPayload) -> ();
  add_or_remove_data_centers : (AddOrRemoveDataCentersProposalPayload) -> ();
  change_subnet_membership : (ChangeSubnetMembershipPayload) -> ();
  clear_provisional_whitelist : () -> ();
  complete_canister_migration : (CompleteCanisterMigrationPayload) -> ();
  create_subnet : (CreateSubnetPayload) -> (CreateSubnetResponse);
  deploy_guestos_to_all_subnet_nodes : (
    DeployGuestosToAllSubnetNodesPayload
  ) -> ();
  deploy_guestos_to_all_unassigned_nodes : (
    DeployGuestosToAllUnassignedNodesPayload
  ) -> ();
  deploy_guestos_to_some_api_boundary_nodes : (DeployGuestosToSomeApiBoundaryNodes) -> ();
  deploy_hostos_to_some_nodes : (DeployHostosToSomeNodes) -> ();
  get_api_boundary_node_ids : (GetApiBoundaryNodeIdsRequest) -> (GetApiBoundaryNodeIdsResponse) query;
  get_build_metadata : () -> (text) query;
  get_chunk : (GetChunkRequest) -> (GetChunkResponse) query;
  get_node_operators_and_dcs_of_node_provider : (principal) -> (GetNodeOperatorsAndDcsOfNodeProviderResponse) query;
  get_node_providers_monthly_xdr_rewards : (opt GetNodeProvidersMonthlyXdrRewardsRequest) -> (GetNodeProvidersMonthlyXdrRewardsResponse) query;
  get_subnet_for_canister : (GetSubnetForCanisterRequest) -> (GetSubnetForCanisterResponse) query;
  migrate_canisters: (MigrateCanistersPayload) -> (MigrateCanistersResponse);
  prepare_canister_migration : (PrepareCanisterMigrationPayload) -> ();
  recover_subnet : (RecoverSubnetPayload) -> ();
  remove_api_boundary_nodes : (RemoveApiBoundaryNodesPayload) -> ();
  remove_firewall_rules : (RemoveFirewallRulesPayload) -> ();
  remove_node_directly : (RemoveNodeDirectlyPayload) -> ();
  remove_node_operators : (RemoveNodeOperatorsPayload) -> ();
  remove_nodes : (RemoveNodesPayload) -> ();
  remove_nodes_from_subnet : (RemoveNodesPayload) -> ();
  reroute_canister_ranges : (RerouteCanisterRangesPayload) -> ();
  revise_elected_guestos_versions : (ReviseElectedGuestosVersionsPayload) -> ();
  revise_elected_replica_versions : (ReviseElectedGuestosVersionsPayload) -> ();
  set_firewall_config : (SetFirewallConfigPayload) -> ();
  set_subnet_operational_level : (SetSubnetOperationalLevelPayload) -> ();
  update_api_boundary_nodes_version : (UpdateApiBoundaryNodesVersionPayload) -> ();
  update_elected_hostos_versions : (UpdateElectedHostosVersionsPayload) -> ();
  revise_elected_hostos_versions : (ReviseElectedHostosVersionsPayload) -> ();
  update_firewall_rules : (UpdateFirewallRulesPayload) -> ();
  update_node_directly : (UpdateNodeDirectlyPayload) -> ();
  update_node_domain_directly : (UpdateNodeDomainDirectlyPayload) -> (UpdateNodeDomainDirectlyResponse);
  update_node_ipv4_config_directly : (UpdateNodeIPv4ConfigDirectlyPayload) -> (
    UpdateNodeIpv4ConfigDirectlyResponse
  );
  update_node_operator_config : (UpdateNodeOperatorConfigPayload) -> ();
  update_node_operator_config_directly : (
    UpdateNodeOperatorConfigDirectlyPayload
  ) -> ();
  update_node_rewards_table : (UpdateNodeRewardsTableProposalPayload) -> ();
  update_nodes_hostos_version : (UpdateNodesHostosVersionPayload) -> ();
  update_ssh_readonly_access_for_all_unassigned_nodes : (
    UpdateSshReadOnlyAccessForAllUnassignedNodesPayload
  ) -> ();
  update_subnet : (UpdateSubnetPayload) -> ();
  update_unassigned_nodes_config : (UpdateUnassignedNodesConfigPayload) -> ();
  swap_node_in_subnet_directly : (SwapNodeInSubnetDirectlyPayload) -> ();
};
"#.to_string()
        } else if canister_id == SNS_WASM_CANISTER_ID {
            r#"type AddWasmRequest = record {
  hash : blob;
  wasm : opt SnsWasm;
  skip_update_latest_version : opt bool;
};

type AddWasmResponse = record {
  result : opt Result;
};

type Canister = record {
  id : opt principal;
};

type Countries = record {
  iso_codes : vec text;
};

type DappCanisters = record {
  canisters : vec Canister;
};

type DappCanistersTransferResult = record {
  restored_dapp_canisters : vec Canister;
  nns_controlled_dapp_canisters : vec Canister;
  sns_controlled_dapp_canisters : vec Canister;
};

type DeployNewSnsRequest = record {
  sns_init_payload : opt SnsInitPayload;
};

type DeployNewSnsResponse = record {
  dapp_canisters_transfer_result : opt DappCanistersTransferResult;
  subnet_id : opt principal;
  error : opt SnsWasmError;
  canisters : opt SnsCanisterIds;
};

type DeployedSns = record {
  root_canister_id : opt principal;
  governance_canister_id : opt principal;
  index_canister_id : opt principal;
  swap_canister_id : opt principal;
  ledger_canister_id : opt principal;
};

type DeveloperDistribution = record {
  developer_neurons : vec NeuronDistribution;
};

type FractionalDeveloperVotingPower = record {
  treasury_distribution : opt TreasuryDistribution;
  developer_distribution : opt DeveloperDistribution;
  swap_distribution : opt SwapDistribution;
};

type GetAllowedPrincipalsResponse = record {
  allowed_principals : vec principal;
};

type GetDeployedSnsByProposalIdRequest = record {
  proposal_id : nat64;
};

type GetDeployedSnsByProposalIdResponse = record {
  get_deployed_sns_by_proposal_id_result : opt GetDeployedSnsByProposalIdResult;
};

type GetDeployedSnsByProposalIdResult = variant {
  Error : SnsWasmError;
  DeployedSns : DeployedSns;
};

type GetNextSnsVersionRequest = record {
  governance_canister_id : opt principal;
  current_version : opt SnsVersion;
};

type GetNextSnsVersionResponse = record {
  next_version : opt SnsVersion;
};

type GetProposalIdThatAddedWasmRequest = record {
  hash : blob;
};

type GetProposalIdThatAddedWasmResponse = record {
  proposal_id : opt nat64;
};

type GetSnsSubnetIdsResponse = record {
  sns_subnet_ids : vec principal;
};

type GetWasmMetadataRequest = record {
  hash : opt blob;
};

type GetWasmMetadataResponse = record {
  result : opt Result_1;
};

type GetWasmRequest = record {
  hash : blob;
};

type GetWasmResponse = record {
  wasm : opt SnsWasm;
};

type IdealMatchedParticipationFunction = record {
  serialized_representation : opt text;
};

type InitialTokenDistribution = variant {
  FractionalDeveloperVotingPower : FractionalDeveloperVotingPower;
};

type InsertUpgradePathEntriesRequest = record {
  upgrade_path : vec SnsUpgrade;
  sns_governance_canister_id : opt principal;
};

type InsertUpgradePathEntriesResponse = record {
  error : opt SnsWasmError;
};

type LinearScalingCoefficient = record {
  slope_numerator : opt nat64;
  intercept_icp_e8s : opt nat64;
  from_direct_participation_icp_e8s : opt nat64;
  slope_denominator : opt nat64;
  to_direct_participation_icp_e8s : opt nat64;
};

type ListDeployedSnsesResponse = record {
  instances : vec DeployedSns;
};

type ListUpgradeStep = record {
  pretty_version : opt PrettySnsVersion;
  version : opt SnsVersion;
};

type ListUpgradeStepsRequest = record {
  limit : nat32;
  starting_at : opt SnsVersion;
  sns_governance_canister_id : opt principal;
};

type ListUpgradeStepsResponse = record {
  steps : vec ListUpgradeStep;
};

type MetadataSection = record {
  contents : opt blob;
  name : opt text;
  visibility : opt text;
};

type NeuronBasketConstructionParameters = record {
  dissolve_delay_interval_seconds : nat64;
  count : nat64;
};

type NeuronDistribution = record {
  controller : opt principal;
  dissolve_delay_seconds : nat64;
  memo : nat64;
  stake_e8s : nat64;
  vesting_period_seconds : opt nat64;
};

type NeuronsFundParticipationConstraints = record {
  coefficient_intervals : vec LinearScalingCoefficient;
  max_neurons_fund_participation_icp_e8s : opt nat64;
  min_direct_participation_threshold_icp_e8s : opt nat64;
  ideal_matched_participation_function : opt IdealMatchedParticipationFunction;
};

type Ok = record {
  sections : vec MetadataSection;
};

type PrettySnsVersion = record {
  archive_wasm_hash : text;
  root_wasm_hash : text;
  swap_wasm_hash : text;
  ledger_wasm_hash : text;
  governance_wasm_hash : text;
  index_wasm_hash : text;
};

type Result = variant {
  Error : SnsWasmError;
  Hash : blob;
};

type Result_1 = variant {
  Ok : Ok;
  Error : SnsWasmError;
};

type SnsCanisterIds = record {
  root : opt principal;
  swap : opt principal;
  ledger : opt principal;
  index : opt principal;
  governance : opt principal;
};

type SnsInitPayload = record {
  url : opt text;
  max_dissolve_delay_seconds : opt nat64;
  max_dissolve_delay_bonus_percentage : opt nat64;
  nns_proposal_id : opt nat64;
  neurons_fund_participation : opt bool;
  min_participant_icp_e8s : opt nat64;
  neuron_basket_construction_parameters : opt NeuronBasketConstructionParameters;
  fallback_controller_principal_ids : vec text;
  token_symbol : opt text;
  final_reward_rate_basis_points : opt nat64;
  max_icp_e8s : opt nat64;
  neuron_minimum_stake_e8s : opt nat64;
  confirmation_text : opt text;
  logo : opt text;
  name : opt text;
  swap_start_timestamp_seconds : opt nat64;
  swap_due_timestamp_seconds : opt nat64;
  initial_voting_period_seconds : opt nat64;
  neuron_minimum_dissolve_delay_to_vote_seconds : opt nat64;
  description : opt text;
  max_neuron_age_seconds_for_age_bonus : opt nat64;
  min_participants : opt nat64;
  initial_reward_rate_basis_points : opt nat64;
  wait_for_quiet_deadline_increase_seconds : opt nat64;
  transaction_fee_e8s : opt nat64;
  dapp_canisters : opt DappCanisters;
  neurons_fund_participation_constraints : opt NeuronsFundParticipationConstraints;
  max_age_bonus_percentage : opt nat64;
  initial_token_distribution : opt InitialTokenDistribution;
  reward_rate_transition_duration_seconds : opt nat64;
  token_logo : opt text;
  token_name : opt text;
  max_participant_icp_e8s : opt nat64;
  min_direct_participation_icp_e8s : opt nat64;
  proposal_reject_cost_e8s : opt nat64;
  restricted_countries : opt Countries;
  min_icp_e8s : opt nat64;
  max_direct_participation_icp_e8s : opt nat64;
};

type SnsUpgrade = record {
  next_version : opt SnsVersion;
  current_version : opt SnsVersion;
};

type SnsVersion = record {
  archive_wasm_hash : blob;
  root_wasm_hash : blob;
  swap_wasm_hash : blob;
  ledger_wasm_hash : blob;
  governance_wasm_hash : blob;
  index_wasm_hash : blob;
};

type SnsWasm = record {
  wasm : blob;
  proposal_id : opt nat64;
  canister_type : int32;
};

type SnsWasmCanisterInitPayload = record {
  allowed_principals : vec principal;
  access_controls_enabled : bool;
  sns_subnet_ids : vec principal;
};

type SnsWasmError = record {
  message : text;
};

type SwapDistribution = record {
  total_e8s : nat64;
  initial_swap_amount_e8s : nat64;
};

type TreasuryDistribution = record {
  total_e8s : nat64;
};

type UpdateAllowedPrincipalsRequest = record {
  added_principals : vec principal;
  removed_principals : vec principal;
};

type UpdateAllowedPrincipalsResponse = record {
  update_allowed_principals_result : opt UpdateAllowedPrincipalsResult;
};

type UpdateAllowedPrincipalsResult = variant {
  Error : SnsWasmError;
  AllowedPrincipals : GetAllowedPrincipalsResponse;
};

type UpdateSnsSubnetListRequest = record {
  sns_subnet_ids_to_add : vec principal;
  sns_subnet_ids_to_remove : vec principal;
};

type UpdateSnsSubnetListResponse = record {
  error : opt SnsWasmError;
};

service : (SnsWasmCanisterInitPayload) -> {
  add_wasm : (AddWasmRequest) -> (AddWasmResponse);
  deploy_new_sns : (DeployNewSnsRequest) -> (DeployNewSnsResponse);
  get_allowed_principals : (record {}) -> (GetAllowedPrincipalsResponse) query;
  get_deployed_sns_by_proposal_id : (GetDeployedSnsByProposalIdRequest) -> (
      GetDeployedSnsByProposalIdResponse,
    ) query;
  get_latest_sns_version_pretty : (null) -> (vec record { text; text }) query;
  get_next_sns_version : (GetNextSnsVersionRequest) -> (
      GetNextSnsVersionResponse,
    ) query;
  get_proposal_id_that_added_wasm : (GetProposalIdThatAddedWasmRequest) -> (
      GetProposalIdThatAddedWasmResponse,
    ) query;
  get_sns_subnet_ids : (record {}) -> (GetSnsSubnetIdsResponse) query;
  get_wasm : (GetWasmRequest) -> (GetWasmResponse) query;
  get_wasm_metadata : (GetWasmMetadataRequest) -> (
      GetWasmMetadataResponse,
    ) query;
  insert_upgrade_path_entries : (InsertUpgradePathEntriesRequest) -> (
      InsertUpgradePathEntriesResponse,
    );
  list_deployed_snses : (record {}) -> (ListDeployedSnsesResponse) query;
  list_upgrade_steps : (ListUpgradeStepsRequest) -> (
      ListUpgradeStepsResponse,
    ) query;
  update_allowed_principals : (UpdateAllowedPrincipalsRequest) -> (
      UpdateAllowedPrincipalsResponse,
    );
  update_sns_subnet_list : (UpdateSnsSubnetListRequest) -> (
      UpdateSnsSubnetListResponse,
    );
}
"#
            .to_string()
        } else {
            "".to_string()
        };
        Ok(candid_source)
    }
}

pub fn candid_to_generic(
    candid_source: &str,
    method_name: &str,
    args: &[u8],
) -> Result<GenericValue, String> {
    let arg = candid_to_idl(candid_source, method_name, args)?;
    Ok(idl2generic(arg))
}

fn candid_to_idl(candid_source: &str, method_name: &str, args: &[u8]) -> Result<IDLValue, String> {
    // Parse the Candid source
    let candid_prog = IDLProg::from_str(candid_source)
        .map_err(|e| format!("Failed to parse candid source: {:?}", e))?;

    let mut type_env = TypeEnv::new();
    let service = check_prog(&mut type_env, &candid_prog)
        .map_err(|e| format!("Failed to check candid program: {:?}", e))?
        .ok_or_else(|| "Failed to parse candid: no service found".to_string())?;

    // Get the method signature
    let method = type_env
        .get_method(&service, method_name)
        .map_err(|e| format!("Failed to get method '{}': {:?}", method_name, e))?;

    // Parse the arguments using the method signature
    let idl_args = IDLArgs::from_bytes_with_types(args, &type_env, &method.args)
        .map_err(|e| format!("Failed to parse args: {:?}", e))?;

    if idl_args.args.is_empty() {
        return Ok(IDLValue::Null);
    }

    // Check if we have exactly one argument (as expected for NNS functions)
    if idl_args.args.len() > 1 {
        return Err(format!(
            "Expected at most one argument, got {}",
            idl_args.args.len()
        ));
    }

    let arg = idl_args.args.into_iter().next().unwrap();
    Ok(arg)
}

pub fn idl2generic(idl: IDLValue) -> GenericValue {
    match idl {
        IDLValue::Blob(bytes) => GenericValue::Text(convert_bytes(bytes)),
        IDLValue::Bool(bool) => {
            GenericValue::Nat(if bool { Nat::from(1u8) } else { Nat::from(0u8) })
        }
        IDLValue::Null => GenericValue::Array(vec![]),
        IDLValue::Text(s) => GenericValue::Text(s),
        IDLValue::Number(s) => GenericValue::Text(s),
        IDLValue::Opt(value) => GenericValue::Array(vec![idl2generic(*value)]),
        IDLValue::Vec(value) => convert_array_to_generic(value),
        IDLValue::Record(value) => GenericValue::Map(
            value
                .into_iter()
                .map(|field| (format!("{}", field.id), idl2generic(field.val)))
                .collect(),
        ),
        IDLValue::Variant(value) => convert_variant_to_generic(value),
        IDLValue::Principal(p) => GenericValue::Text(format!("{}", p)),
        IDLValue::None => GenericValue::Array(vec![]),
        IDLValue::Int(i) => GenericValue::Int(i),
        IDLValue::Nat(i) => GenericValue::Nat(i),
        IDLValue::Nat8(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat16(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat32(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat64(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Int8(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int16(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int32(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int64(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Float32(f) => GenericValue::Text(format!("{}", f)),
        IDLValue::Float64(f) => GenericValue::Text(format!("{}", f)),
        IDLValue::Reserved => GenericValue::Text(idl.to_string()),
        IDLValue::Service(_) | IDLValue::Func(..) => panic!("Unexpected IDLValue: {:?}", idl),
    }
}

fn convert_array_to_generic(value: Vec<IDLValue>) -> GenericValue {
    match try_extract_bytes(value) {
        Ok(bytes) => GenericValue::Text(convert_bytes(bytes)),
        Err(value) => GenericValue::Array(value.into_iter().map(idl2generic).collect()),
    }
}

fn convert_variant_to_generic(variant_value: VariantValue) -> GenericValue {
    let IDLField { id, val } = *variant_value.0;
    let label = format!("{}", id);
    let generic_val = idl2generic(val);
    if generic_val == GenericValue::Array(vec![]) {
        GenericValue::Text(label)
    } else {
        GenericValue::Map(vec![(label, generic_val)].into_iter().collect())
    }
}

fn try_extract_bytes(value: Vec<IDLValue>) -> Result<Vec<u8>, Vec<IDLValue>> {
    let mut bytes = Vec::new();
    let mut is_bytes = true;
    for value in value.iter() {
        if let IDLValue::Nat8(byte) = value {
            bytes.push(*byte);
        } else {
            is_bytes = false;
        }
    }
    if is_bytes { Ok(bytes) } else { Err(value) }
}

fn convert_bytes(bytes: Vec<u8>) -> String {
    if bytes.len() > 100 {
        let first_4_hex = hex::encode(&bytes[..4]);
        let last_4_hex = hex::encode(&bytes[bytes.len() - 4..]);
        format!(
            "[{}...{}](len:{};sha256:{})",
            first_4_hex,
            last_4_hex,
            bytes.len(),
            sha256_hex(&bytes)
        )
    } else {
        hex::encode(&bytes)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.write(bytes);
    hex::encode(hasher.finish())
}
