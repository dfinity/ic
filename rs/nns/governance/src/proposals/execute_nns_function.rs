use crate::pb::v1::{
    ExecuteNnsFunction, GovernanceError, NnsFunction, Topic, governance_error::ErrorType,
};

use ic_base_types::CanisterId;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};

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
            | ValidNnsFunction::UnpauseCanisterMigrations => Topic::ProtocolCanisterManagement,

            ValidNnsFunction::AddSnsWasm | ValidNnsFunction::InsertSnsWasmUpgradePathEntries => {
                Topic::ServiceNervousSystemManagement
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
