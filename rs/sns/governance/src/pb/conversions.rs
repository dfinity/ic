use crate::pb::v1 as pb;
use ic_sns_governance_api::pb::v1 as pb_api;

impl From<pb::NeuronPermission> for pb_api::NeuronPermission {
    fn from(item: pb::NeuronPermission) -> Self {
        Self {
            principal: item.principal,
            permission_type: item.permission_type,
        }
    }
}
impl From<pb_api::NeuronPermission> for pb::NeuronPermission {
    fn from(item: pb_api::NeuronPermission) -> Self {
        Self {
            principal: item.principal,
            permission_type: item.permission_type,
        }
    }
}

impl From<pb::NeuronId> for pb_api::NeuronId {
    fn from(item: pb::NeuronId) -> Self {
        Self { id: item.id }
    }
}
impl From<pb_api::NeuronId> for pb::NeuronId {
    fn from(item: pb_api::NeuronId) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::NeuronIds> for pb_api::NeuronIds {
    fn from(item: pb::NeuronIds) -> Self {
        Self {
            neuron_ids: item.neuron_ids.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::NeuronIds> for pb::NeuronIds {
    fn from(item: pb_api::NeuronIds) -> Self {
        Self {
            neuron_ids: item.neuron_ids.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ProposalId> for pb_api::ProposalId {
    fn from(item: pb::ProposalId) -> Self {
        Self { id: item.id }
    }
}
impl From<pb_api::ProposalId> for pb::ProposalId {
    fn from(item: pb_api::ProposalId) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::DisburseMaturityInProgress> for pb_api::DisburseMaturityInProgress {
    fn from(item: pb::DisburseMaturityInProgress) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            timestamp_of_disbursement_seconds: item.timestamp_of_disbursement_seconds,
            account_to_disburse_to: item.account_to_disburse_to.map(|x| x.into()),
            finalize_disbursement_timestamp_seconds: item.finalize_disbursement_timestamp_seconds,
        }
    }
}
impl From<pb_api::DisburseMaturityInProgress> for pb::DisburseMaturityInProgress {
    fn from(item: pb_api::DisburseMaturityInProgress) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            timestamp_of_disbursement_seconds: item.timestamp_of_disbursement_seconds,
            account_to_disburse_to: item.account_to_disburse_to.map(|x| x.into()),
            finalize_disbursement_timestamp_seconds: item.finalize_disbursement_timestamp_seconds,
        }
    }
}

impl From<pb::Neuron> for pb_api::Neuron {
    fn from(item: pb::Neuron) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            permissions: item.permissions.into_iter().map(|x| x.into()).collect(),
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            voting_power_percentage_multiplier: item.voting_power_percentage_multiplier,
            source_nns_neuron_id: item.source_nns_neuron_id,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            vesting_period_seconds: item.vesting_period_seconds,
            disburse_maturity_in_progress: item
                .disburse_maturity_in_progress
                .into_iter()
                .map(|x| x.into())
                .collect(),
            dissolve_state: item.dissolve_state.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Neuron> for pb::Neuron {
    fn from(item: pb_api::Neuron) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            permissions: item.permissions.into_iter().map(|x| x.into()).collect(),
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            voting_power_percentage_multiplier: item.voting_power_percentage_multiplier,
            source_nns_neuron_id: item.source_nns_neuron_id,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            vesting_period_seconds: item.vesting_period_seconds,
            disburse_maturity_in_progress: item
                .disburse_maturity_in_progress
                .into_iter()
                .map(|x| x.into())
                .collect(),
            dissolve_state: item.dissolve_state.map(|x| x.into()),
        }
    }
}

impl From<pb::neuron::Followees> for pb_api::neuron::Followees {
    fn from(item: pb::neuron::Followees) -> Self {
        Self {
            followees: item.followees.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::neuron::Followees> for pb::neuron::Followees {
    fn from(item: pb_api::neuron::Followees) -> Self {
        Self {
            followees: item.followees.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::neuron::DissolveState> for pb_api::neuron::DissolveState {
    fn from(item: pb::neuron::DissolveState) -> Self {
        match item {
            pb::neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb_api::neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb::neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb_api::neuron::DissolveState::DissolveDelaySeconds(v)
            }
        }
    }
}
impl From<pb_api::neuron::DissolveState> for pb::neuron::DissolveState {
    fn from(item: pb_api::neuron::DissolveState) -> Self {
        match item {
            pb_api::neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb::neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb_api::neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb::neuron::DissolveState::DissolveDelaySeconds(v)
            }
        }
    }
}

impl From<pb::NervousSystemFunction> for pb_api::NervousSystemFunction {
    fn from(item: pb::NervousSystemFunction) -> Self {
        Self {
            id: item.id,
            name: item.name,
            description: item.description,
            function_type: item.function_type.map(|x| x.into()),
        }
    }
}
impl From<pb_api::NervousSystemFunction> for pb::NervousSystemFunction {
    fn from(item: pb_api::NervousSystemFunction) -> Self {
        Self {
            id: item.id,
            name: item.name,
            description: item.description,
            function_type: item.function_type.map(|x| x.into()),
        }
    }
}

impl From<pb::nervous_system_function::GenericNervousSystemFunction>
    for pb_api::nervous_system_function::GenericNervousSystemFunction
{
    fn from(item: pb::nervous_system_function::GenericNervousSystemFunction) -> Self {
        Self {
            target_canister_id: item.target_canister_id,
            target_method_name: item.target_method_name,
            validator_canister_id: item.validator_canister_id,
            validator_method_name: item.validator_method_name,
        }
    }
}
impl From<pb_api::nervous_system_function::GenericNervousSystemFunction>
    for pb::nervous_system_function::GenericNervousSystemFunction
{
    fn from(item: pb_api::nervous_system_function::GenericNervousSystemFunction) -> Self {
        Self {
            target_canister_id: item.target_canister_id,
            target_method_name: item.target_method_name,
            validator_canister_id: item.validator_canister_id,
            validator_method_name: item.validator_method_name,
        }
    }
}

impl From<pb::nervous_system_function::FunctionType>
    for pb_api::nervous_system_function::FunctionType
{
    fn from(item: pb::nervous_system_function::FunctionType) -> Self {
        match item {
            pb::nervous_system_function::FunctionType::NativeNervousSystemFunction(v) => {
                pb_api::nervous_system_function::FunctionType::NativeNervousSystemFunction(v.into())
            }
            pb::nervous_system_function::FunctionType::GenericNervousSystemFunction(v) => {
                pb_api::nervous_system_function::FunctionType::GenericNervousSystemFunction(
                    v.into(),
                )
            }
        }
    }
}
impl From<pb_api::nervous_system_function::FunctionType>
    for pb::nervous_system_function::FunctionType
{
    fn from(item: pb_api::nervous_system_function::FunctionType) -> Self {
        match item {
            pb_api::nervous_system_function::FunctionType::NativeNervousSystemFunction(v) => {
                pb::nervous_system_function::FunctionType::NativeNervousSystemFunction(v.into())
            }
            pb_api::nervous_system_function::FunctionType::GenericNervousSystemFunction(v) => {
                pb::nervous_system_function::FunctionType::GenericNervousSystemFunction(v.into())
            }
        }
    }
}

impl From<pb::ExecuteGenericNervousSystemFunction> for pb_api::ExecuteGenericNervousSystemFunction {
    fn from(item: pb::ExecuteGenericNervousSystemFunction) -> Self {
        Self {
            function_id: item.function_id,
            payload: item.payload,
        }
    }
}
impl From<pb_api::ExecuteGenericNervousSystemFunction> for pb::ExecuteGenericNervousSystemFunction {
    fn from(item: pb_api::ExecuteGenericNervousSystemFunction) -> Self {
        Self {
            function_id: item.function_id,
            payload: item.payload,
        }
    }
}

impl From<pb::Motion> for pb_api::Motion {
    fn from(item: pb::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}
impl From<pb_api::Motion> for pb::Motion {
    fn from(item: pb_api::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}

impl From<pb::UpgradeSnsControlledCanister> for pb_api::UpgradeSnsControlledCanister {
    fn from(item: pb::UpgradeSnsControlledCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            new_canister_wasm: item.new_canister_wasm,
            canister_upgrade_arg: item.canister_upgrade_arg,
            mode: item.mode,
        }
    }
}
impl From<pb_api::UpgradeSnsControlledCanister> for pb::UpgradeSnsControlledCanister {
    fn from(item: pb_api::UpgradeSnsControlledCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            new_canister_wasm: item.new_canister_wasm,
            canister_upgrade_arg: item.canister_upgrade_arg,
            mode: item.mode,
        }
    }
}

impl From<pb::TransferSnsTreasuryFunds> for pb_api::TransferSnsTreasuryFunds {
    fn from(item: pb::TransferSnsTreasuryFunds) -> Self {
        Self {
            from_treasury: item.from_treasury,
            amount_e8s: item.amount_e8s,
            memo: item.memo,
            to_principal: item.to_principal,
            to_subaccount: item.to_subaccount.map(|x| x.into()),
        }
    }
}
impl From<pb_api::TransferSnsTreasuryFunds> for pb::TransferSnsTreasuryFunds {
    fn from(item: pb_api::TransferSnsTreasuryFunds) -> Self {
        Self {
            from_treasury: item.from_treasury,
            amount_e8s: item.amount_e8s,
            memo: item.memo,
            to_principal: item.to_principal,
            to_subaccount: item.to_subaccount.map(|x| x.into()),
        }
    }
}

impl From<pb::transfer_sns_treasury_funds::TransferFrom>
    for pb_api::transfer_sns_treasury_funds::TransferFrom
{
    fn from(item: pb::transfer_sns_treasury_funds::TransferFrom) -> Self {
        match item {
            pb::transfer_sns_treasury_funds::TransferFrom::Unspecified => {
                pb_api::transfer_sns_treasury_funds::TransferFrom::Unspecified
            }
            pb::transfer_sns_treasury_funds::TransferFrom::IcpTreasury => {
                pb_api::transfer_sns_treasury_funds::TransferFrom::IcpTreasury
            }
            pb::transfer_sns_treasury_funds::TransferFrom::SnsTokenTreasury => {
                pb_api::transfer_sns_treasury_funds::TransferFrom::SnsTokenTreasury
            }
        }
    }
}
impl From<pb_api::transfer_sns_treasury_funds::TransferFrom>
    for pb::transfer_sns_treasury_funds::TransferFrom
{
    fn from(item: pb_api::transfer_sns_treasury_funds::TransferFrom) -> Self {
        match item {
            pb_api::transfer_sns_treasury_funds::TransferFrom::Unspecified => {
                pb::transfer_sns_treasury_funds::TransferFrom::Unspecified
            }
            pb_api::transfer_sns_treasury_funds::TransferFrom::IcpTreasury => {
                pb::transfer_sns_treasury_funds::TransferFrom::IcpTreasury
            }
            pb_api::transfer_sns_treasury_funds::TransferFrom::SnsTokenTreasury => {
                pb::transfer_sns_treasury_funds::TransferFrom::SnsTokenTreasury
            }
        }
    }
}

impl From<pb::ManageLedgerParameters> for pb_api::ManageLedgerParameters {
    fn from(item: pb::ManageLedgerParameters) -> Self {
        Self {
            transfer_fee: item.transfer_fee,
            token_name: item.token_name,
            token_symbol: item.token_symbol,
            token_logo: item.token_logo,
        }
    }
}
impl From<pb_api::ManageLedgerParameters> for pb::ManageLedgerParameters {
    fn from(item: pb_api::ManageLedgerParameters) -> Self {
        Self {
            transfer_fee: item.transfer_fee,
            token_name: item.token_name,
            token_symbol: item.token_symbol,
            token_logo: item.token_logo,
        }
    }
}

impl From<pb::MintSnsTokens> for pb_api::MintSnsTokens {
    fn from(item: pb::MintSnsTokens) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
            to_principal: item.to_principal,
            to_subaccount: item.to_subaccount.map(|x| x.into()),
        }
    }
}
impl From<pb_api::MintSnsTokens> for pb::MintSnsTokens {
    fn from(item: pb_api::MintSnsTokens) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
            to_principal: item.to_principal,
            to_subaccount: item.to_subaccount.map(|x| x.into()),
        }
    }
}

impl From<pb::ManageSnsMetadata> for pb_api::ManageSnsMetadata {
    fn from(item: pb::ManageSnsMetadata) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}
impl From<pb_api::ManageSnsMetadata> for pb::ManageSnsMetadata {
    fn from(item: pb_api::ManageSnsMetadata) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}

impl From<pb::UpgradeSnsToNextVersion> for pb_api::UpgradeSnsToNextVersion {
    fn from(_: pb::UpgradeSnsToNextVersion) -> Self {
        Self {}
    }
}
impl From<pb_api::UpgradeSnsToNextVersion> for pb::UpgradeSnsToNextVersion {
    fn from(_: pb_api::UpgradeSnsToNextVersion) -> Self {
        Self {}
    }
}

impl From<pb::RegisterDappCanisters> for pb_api::RegisterDappCanisters {
    fn from(item: pb::RegisterDappCanisters) -> Self {
        Self {
            canister_ids: item.canister_ids,
        }
    }
}
impl From<pb_api::RegisterDappCanisters> for pb::RegisterDappCanisters {
    fn from(item: pb_api::RegisterDappCanisters) -> Self {
        Self {
            canister_ids: item.canister_ids,
        }
    }
}

impl From<pb::DeregisterDappCanisters> for pb_api::DeregisterDappCanisters {
    fn from(item: pb::DeregisterDappCanisters) -> Self {
        Self {
            canister_ids: item.canister_ids,
            new_controllers: item.new_controllers,
        }
    }
}
impl From<pb_api::DeregisterDappCanisters> for pb::DeregisterDappCanisters {
    fn from(item: pb_api::DeregisterDappCanisters) -> Self {
        Self {
            canister_ids: item.canister_ids,
            new_controllers: item.new_controllers,
        }
    }
}

impl From<pb::ManageDappCanisterSettings> for pb_api::ManageDappCanisterSettings {
    fn from(item: pb::ManageDappCanisterSettings) -> Self {
        Self {
            canister_ids: item.canister_ids,
            compute_allocation: item.compute_allocation,
            memory_allocation: item.memory_allocation,
            freezing_threshold: item.freezing_threshold,
            reserved_cycles_limit: item.reserved_cycles_limit,
            log_visibility: item.log_visibility,
            wasm_memory_limit: item.wasm_memory_limit,
        }
    }
}
impl From<pb_api::ManageDappCanisterSettings> for pb::ManageDappCanisterSettings {
    fn from(item: pb_api::ManageDappCanisterSettings) -> Self {
        Self {
            canister_ids: item.canister_ids,
            compute_allocation: item.compute_allocation,
            memory_allocation: item.memory_allocation,
            freezing_threshold: item.freezing_threshold,
            reserved_cycles_limit: item.reserved_cycles_limit,
            log_visibility: item.log_visibility,
            wasm_memory_limit: item.wasm_memory_limit,
        }
    }
}

impl From<pb_api::SnsVersion> for pb::SnsVersion {
    fn from(item: pb_api::SnsVersion) -> Self {
        Self {
            governance_wasm_hash: item.governance_wasm_hash,
            swap_wasm_hash: item.swap_wasm_hash,
            root_wasm_hash: item.root_wasm_hash,
            index_wasm_hash: item.index_wasm_hash,
            ledger_wasm_hash: item.ledger_wasm_hash,
            archive_wasm_hash: item.archive_wasm_hash,
        }
    }
}
impl From<pb::SnsVersion> for pb_api::SnsVersion {
    fn from(item: pb::SnsVersion) -> Self {
        Self {
            governance_wasm_hash: item.governance_wasm_hash,
            swap_wasm_hash: item.swap_wasm_hash,
            root_wasm_hash: item.root_wasm_hash,
            index_wasm_hash: item.index_wasm_hash,
            ledger_wasm_hash: item.ledger_wasm_hash,
            archive_wasm_hash: item.archive_wasm_hash,
        }
    }
}

impl From<pb_api::AdvanceSnsTargetVersion> for pb::AdvanceSnsTargetVersion {
    fn from(item: pb_api::AdvanceSnsTargetVersion) -> Self {
        Self {
            new_target: item.new_target.map(pb::SnsVersion::from),
        }
    }
}
impl From<pb::AdvanceSnsTargetVersion> for pb_api::AdvanceSnsTargetVersion {
    fn from(item: pb::AdvanceSnsTargetVersion) -> Self {
        Self {
            new_target: item.new_target.map(pb_api::SnsVersion::from),
        }
    }
}

impl From<pb::Proposal> for pb_api::Proposal {
    fn from(item: pb::Proposal) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Proposal> for pb::Proposal {
    fn from(item: pb_api::Proposal) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
        }
    }
}

impl From<pb::proposal::Action> for pb_api::proposal::Action {
    fn from(item: pb::proposal::Action) -> Self {
        match item {
            pb::proposal::Action::Unspecified(v) => pb_api::proposal::Action::Unspecified(v.into()),
            pb::proposal::Action::Motion(v) => pb_api::proposal::Action::Motion(v.into()),
            pb::proposal::Action::ManageNervousSystemParameters(v) => {
                pb_api::proposal::Action::ManageNervousSystemParameters(v.into())
            }
            pb::proposal::Action::UpgradeSnsControlledCanister(v) => {
                pb_api::proposal::Action::UpgradeSnsControlledCanister(v.into())
            }
            pb::proposal::Action::AddGenericNervousSystemFunction(v) => {
                pb_api::proposal::Action::AddGenericNervousSystemFunction(v.into())
            }
            pb::proposal::Action::RemoveGenericNervousSystemFunction(v) => {
                pb_api::proposal::Action::RemoveGenericNervousSystemFunction(v)
            }
            pb::proposal::Action::ExecuteGenericNervousSystemFunction(v) => {
                pb_api::proposal::Action::ExecuteGenericNervousSystemFunction(v.into())
            }
            pb::proposal::Action::UpgradeSnsToNextVersion(v) => {
                pb_api::proposal::Action::UpgradeSnsToNextVersion(v.into())
            }
            pb::proposal::Action::ManageSnsMetadata(v) => {
                pb_api::proposal::Action::ManageSnsMetadata(v.into())
            }
            pb::proposal::Action::TransferSnsTreasuryFunds(v) => {
                pb_api::proposal::Action::TransferSnsTreasuryFunds(v.into())
            }
            pb::proposal::Action::RegisterDappCanisters(v) => {
                pb_api::proposal::Action::RegisterDappCanisters(v.into())
            }
            pb::proposal::Action::DeregisterDappCanisters(v) => {
                pb_api::proposal::Action::DeregisterDappCanisters(v.into())
            }
            pb::proposal::Action::MintSnsTokens(v) => {
                pb_api::proposal::Action::MintSnsTokens(v.into())
            }
            pb::proposal::Action::ManageLedgerParameters(v) => {
                pb_api::proposal::Action::ManageLedgerParameters(v.into())
            }
            pb::proposal::Action::ManageDappCanisterSettings(v) => {
                pb_api::proposal::Action::ManageDappCanisterSettings(v.into())
            }
            pb::proposal::Action::AdvanceSnsTargetVersion(v) => {
                pb_api::proposal::Action::AdvanceSnsTargetVersion(v.into())
            }
        }
    }
}
impl From<pb_api::proposal::Action> for pb::proposal::Action {
    fn from(item: pb_api::proposal::Action) -> Self {
        match item {
            pb_api::proposal::Action::Unspecified(v) => pb::proposal::Action::Unspecified(v.into()),
            pb_api::proposal::Action::Motion(v) => pb::proposal::Action::Motion(v.into()),
            pb_api::proposal::Action::ManageNervousSystemParameters(v) => {
                pb::proposal::Action::ManageNervousSystemParameters(v.into())
            }
            pb_api::proposal::Action::UpgradeSnsControlledCanister(v) => {
                pb::proposal::Action::UpgradeSnsControlledCanister(v.into())
            }
            pb_api::proposal::Action::AddGenericNervousSystemFunction(v) => {
                pb::proposal::Action::AddGenericNervousSystemFunction(v.into())
            }
            pb_api::proposal::Action::RemoveGenericNervousSystemFunction(v) => {
                pb::proposal::Action::RemoveGenericNervousSystemFunction(v)
            }
            pb_api::proposal::Action::ExecuteGenericNervousSystemFunction(v) => {
                pb::proposal::Action::ExecuteGenericNervousSystemFunction(v.into())
            }
            pb_api::proposal::Action::UpgradeSnsToNextVersion(v) => {
                pb::proposal::Action::UpgradeSnsToNextVersion(v.into())
            }
            pb_api::proposal::Action::ManageSnsMetadata(v) => {
                pb::proposal::Action::ManageSnsMetadata(v.into())
            }
            pb_api::proposal::Action::TransferSnsTreasuryFunds(v) => {
                pb::proposal::Action::TransferSnsTreasuryFunds(v.into())
            }
            pb_api::proposal::Action::RegisterDappCanisters(v) => {
                pb::proposal::Action::RegisterDappCanisters(v.into())
            }
            pb_api::proposal::Action::DeregisterDappCanisters(v) => {
                pb::proposal::Action::DeregisterDappCanisters(v.into())
            }
            pb_api::proposal::Action::MintSnsTokens(v) => {
                pb::proposal::Action::MintSnsTokens(v.into())
            }
            pb_api::proposal::Action::ManageLedgerParameters(v) => {
                pb::proposal::Action::ManageLedgerParameters(v.into())
            }
            pb_api::proposal::Action::ManageDappCanisterSettings(v) => {
                pb::proposal::Action::ManageDappCanisterSettings(v.into())
            }
            pb_api::proposal::Action::AdvanceSnsTargetVersion(v) => {
                pb::proposal::Action::AdvanceSnsTargetVersion(v.into())
            }
        }
    }
}

impl From<pb::GovernanceError> for pb_api::GovernanceError {
    fn from(item: pb::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}
impl From<pb_api::GovernanceError> for pb::GovernanceError {
    fn from(item: pb_api::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}

impl From<pb::governance_error::ErrorType> for pb_api::governance_error::ErrorType {
    fn from(item: pb::governance_error::ErrorType) -> Self {
        match item {
            pb::governance_error::ErrorType::Unspecified => {
                pb_api::governance_error::ErrorType::Unspecified
            }
            pb::governance_error::ErrorType::Unavailable => {
                pb_api::governance_error::ErrorType::Unavailable
            }
            pb::governance_error::ErrorType::NotAuthorized => {
                pb_api::governance_error::ErrorType::NotAuthorized
            }
            pb::governance_error::ErrorType::NotFound => {
                pb_api::governance_error::ErrorType::NotFound
            }
            pb::governance_error::ErrorType::InvalidCommand => {
                pb_api::governance_error::ErrorType::InvalidCommand
            }
            pb::governance_error::ErrorType::RequiresNotDissolving => {
                pb_api::governance_error::ErrorType::RequiresNotDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolving => {
                pb_api::governance_error::ErrorType::RequiresDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolved => {
                pb_api::governance_error::ErrorType::RequiresDissolved
            }
            pb::governance_error::ErrorType::AccessControlList => {
                pb_api::governance_error::ErrorType::AccessControlList
            }
            pb::governance_error::ErrorType::ResourceExhausted => {
                pb_api::governance_error::ErrorType::ResourceExhausted
            }
            pb::governance_error::ErrorType::PreconditionFailed => {
                pb_api::governance_error::ErrorType::PreconditionFailed
            }
            pb::governance_error::ErrorType::External => {
                pb_api::governance_error::ErrorType::External
            }
            pb::governance_error::ErrorType::NeuronLocked => {
                pb_api::governance_error::ErrorType::NeuronLocked
            }
            pb::governance_error::ErrorType::InsufficientFunds => {
                pb_api::governance_error::ErrorType::InsufficientFunds
            }
            pb::governance_error::ErrorType::InvalidPrincipal => {
                pb_api::governance_error::ErrorType::InvalidPrincipal
            }
            pb::governance_error::ErrorType::InvalidProposal => {
                pb_api::governance_error::ErrorType::InvalidProposal
            }
            pb::governance_error::ErrorType::InvalidNeuronId => {
                pb_api::governance_error::ErrorType::InvalidNeuronId
            }
            pb::governance_error::ErrorType::InconsistentInternalData => {
                pb_api::governance_error::ErrorType::InconsistentInternalData
            }
            pb::governance_error::ErrorType::UnreachableCode => {
                pb_api::governance_error::ErrorType::UnreachableCode
            }
        }
    }
}
impl From<pb_api::governance_error::ErrorType> for pb::governance_error::ErrorType {
    fn from(item: pb_api::governance_error::ErrorType) -> Self {
        match item {
            pb_api::governance_error::ErrorType::Unspecified => {
                pb::governance_error::ErrorType::Unspecified
            }
            pb_api::governance_error::ErrorType::Unavailable => {
                pb::governance_error::ErrorType::Unavailable
            }
            pb_api::governance_error::ErrorType::NotAuthorized => {
                pb::governance_error::ErrorType::NotAuthorized
            }
            pb_api::governance_error::ErrorType::NotFound => {
                pb::governance_error::ErrorType::NotFound
            }
            pb_api::governance_error::ErrorType::InvalidCommand => {
                pb::governance_error::ErrorType::InvalidCommand
            }
            pb_api::governance_error::ErrorType::RequiresNotDissolving => {
                pb::governance_error::ErrorType::RequiresNotDissolving
            }
            pb_api::governance_error::ErrorType::RequiresDissolving => {
                pb::governance_error::ErrorType::RequiresDissolving
            }
            pb_api::governance_error::ErrorType::RequiresDissolved => {
                pb::governance_error::ErrorType::RequiresDissolved
            }
            pb_api::governance_error::ErrorType::AccessControlList => {
                pb::governance_error::ErrorType::AccessControlList
            }
            pb_api::governance_error::ErrorType::ResourceExhausted => {
                pb::governance_error::ErrorType::ResourceExhausted
            }
            pb_api::governance_error::ErrorType::PreconditionFailed => {
                pb::governance_error::ErrorType::PreconditionFailed
            }
            pb_api::governance_error::ErrorType::External => {
                pb::governance_error::ErrorType::External
            }
            pb_api::governance_error::ErrorType::NeuronLocked => {
                pb::governance_error::ErrorType::NeuronLocked
            }
            pb_api::governance_error::ErrorType::InsufficientFunds => {
                pb::governance_error::ErrorType::InsufficientFunds
            }
            pb_api::governance_error::ErrorType::InvalidPrincipal => {
                pb::governance_error::ErrorType::InvalidPrincipal
            }
            pb_api::governance_error::ErrorType::InvalidProposal => {
                pb::governance_error::ErrorType::InvalidProposal
            }
            pb_api::governance_error::ErrorType::InvalidNeuronId => {
                pb::governance_error::ErrorType::InvalidNeuronId
            }
            pb_api::governance_error::ErrorType::InconsistentInternalData => {
                pb::governance_error::ErrorType::InconsistentInternalData
            }
            pb_api::governance_error::ErrorType::UnreachableCode => {
                pb::governance_error::ErrorType::UnreachableCode
            }
        }
    }
}

impl From<pb::Ballot> for pb_api::Ballot {
    fn from(item: pb::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
            cast_timestamp_seconds: item.cast_timestamp_seconds,
        }
    }
}
impl From<pb_api::Ballot> for pb::Ballot {
    fn from(item: pb_api::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
            cast_timestamp_seconds: item.cast_timestamp_seconds,
        }
    }
}

impl From<pb::Tally> for pb_api::Tally {
    fn from(item: pb::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}
impl From<pb_api::Tally> for pb::Tally {
    fn from(item: pb_api::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}

impl From<pb::WaitForQuietState> for pb_api::WaitForQuietState {
    fn from(item: pb::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}
impl From<pb_api::WaitForQuietState> for pb::WaitForQuietState {
    fn from(item: pb_api::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}

impl From<pb::ProposalData> for pb_api::ProposalData {
    fn from(item: pb::ProposalData) -> Self {
        Self {
            action: item.action,
            id: item.id.map(|x| x.into()),
            proposer: item.proposer.map(|x| x.into()),
            reject_cost_e8s: item.reject_cost_e8s,
            proposal: item.proposal.map(|x| x.into()),
            proposal_creation_timestamp_seconds: item.proposal_creation_timestamp_seconds,
            ballots: item
                .ballots
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            latest_tally: item.latest_tally.map(|x| x.into()),
            decided_timestamp_seconds: item.decided_timestamp_seconds,
            executed_timestamp_seconds: item.executed_timestamp_seconds,
            failed_timestamp_seconds: item.failed_timestamp_seconds,
            failure_reason: item.failure_reason.map(|x| x.into()),
            reward_event_round: item.reward_event_round,
            wait_for_quiet_state: item.wait_for_quiet_state.map(|x| x.into()),
            payload_text_rendering: item.payload_text_rendering,
            is_eligible_for_rewards: item.is_eligible_for_rewards,
            initial_voting_period_seconds: item.initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: item.wait_for_quiet_deadline_increase_seconds,
            reward_event_end_timestamp_seconds: item.reward_event_end_timestamp_seconds,
            minimum_yes_proportion_of_total: item.minimum_yes_proportion_of_total,
            minimum_yes_proportion_of_exercised: item.minimum_yes_proportion_of_exercised,
            action_auxiliary: item.action_auxiliary.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ProposalData> for pb::ProposalData {
    fn from(item: pb_api::ProposalData) -> Self {
        Self {
            action: item.action,
            id: item.id.map(|x| x.into()),
            proposer: item.proposer.map(|x| x.into()),
            reject_cost_e8s: item.reject_cost_e8s,
            proposal: item.proposal.map(|x| x.into()),
            proposal_creation_timestamp_seconds: item.proposal_creation_timestamp_seconds,
            ballots: item
                .ballots
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            latest_tally: item.latest_tally.map(|x| x.into()),
            decided_timestamp_seconds: item.decided_timestamp_seconds,
            executed_timestamp_seconds: item.executed_timestamp_seconds,
            failed_timestamp_seconds: item.failed_timestamp_seconds,
            failure_reason: item.failure_reason.map(|x| x.into()),
            reward_event_round: item.reward_event_round,
            wait_for_quiet_state: item.wait_for_quiet_state.map(|x| x.into()),
            payload_text_rendering: item.payload_text_rendering,
            is_eligible_for_rewards: item.is_eligible_for_rewards,
            initial_voting_period_seconds: item.initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: item.wait_for_quiet_deadline_increase_seconds,
            reward_event_end_timestamp_seconds: item.reward_event_end_timestamp_seconds,
            minimum_yes_proportion_of_total: item.minimum_yes_proportion_of_total,
            minimum_yes_proportion_of_exercised: item.minimum_yes_proportion_of_exercised,
            action_auxiliary: item.action_auxiliary.map(|x| x.into()),
        }
    }
}

impl From<pb::proposal_data::TransferSnsTreasuryFundsActionAuxiliary>
    for pb_api::proposal_data::TransferSnsTreasuryFundsActionAuxiliary
{
    fn from(item: pb::proposal_data::TransferSnsTreasuryFundsActionAuxiliary) -> Self {
        Self {
            valuation: item.valuation.map(|x| x.into()),
        }
    }
}
impl From<pb_api::proposal_data::TransferSnsTreasuryFundsActionAuxiliary>
    for pb::proposal_data::TransferSnsTreasuryFundsActionAuxiliary
{
    fn from(item: pb_api::proposal_data::TransferSnsTreasuryFundsActionAuxiliary) -> Self {
        Self {
            valuation: item.valuation.map(|x| x.into()),
        }
    }
}

impl From<pb::proposal_data::MintSnsTokensActionAuxiliary>
    for pb_api::proposal_data::MintSnsTokensActionAuxiliary
{
    fn from(item: pb::proposal_data::MintSnsTokensActionAuxiliary) -> Self {
        Self {
            valuation: item.valuation.map(|x| x.into()),
        }
    }
}
impl From<pb_api::proposal_data::MintSnsTokensActionAuxiliary>
    for pb::proposal_data::MintSnsTokensActionAuxiliary
{
    fn from(item: pb_api::proposal_data::MintSnsTokensActionAuxiliary) -> Self {
        Self {
            valuation: item.valuation.map(|x| x.into()),
        }
    }
}

impl From<pb::proposal_data::AdvanceSnsTargetVersionActionAuxiliary>
    for pb_api::proposal_data::AdvanceSnsTargetVersionActionAuxiliary
{
    fn from(item: pb::proposal_data::AdvanceSnsTargetVersionActionAuxiliary) -> Self {
        Self {
            target_version: item.target_version.map(pb_api::SnsVersion::from),
        }
    }
}
impl From<pb_api::proposal_data::AdvanceSnsTargetVersionActionAuxiliary>
    for pb::proposal_data::AdvanceSnsTargetVersionActionAuxiliary
{
    fn from(item: pb_api::proposal_data::AdvanceSnsTargetVersionActionAuxiliary) -> Self {
        Self {
            target_version: item.target_version.map(pb::SnsVersion::from),
        }
    }
}

impl From<pb::proposal_data::ActionAuxiliary> for pb_api::proposal_data::ActionAuxiliary {
    fn from(item: pb::proposal_data::ActionAuxiliary) -> Self {
        match item {
            pb::proposal_data::ActionAuxiliary::TransferSnsTreasuryFunds(v) => {
                pb_api::proposal_data::ActionAuxiliary::TransferSnsTreasuryFunds(v.into())
            }
            pb::proposal_data::ActionAuxiliary::MintSnsTokens(v) => {
                pb_api::proposal_data::ActionAuxiliary::MintSnsTokens(v.into())
            }
            pb::proposal_data::ActionAuxiliary::AdvanceSnsTargetVersion(v) => {
                pb_api::proposal_data::ActionAuxiliary::AdvanceSnsTargetVersion(v.into())
            }
        }
    }
}

impl From<pb_api::proposal_data::ActionAuxiliary> for pb::proposal_data::ActionAuxiliary {
    fn from(item: pb_api::proposal_data::ActionAuxiliary) -> Self {
        match item {
            pb_api::proposal_data::ActionAuxiliary::TransferSnsTreasuryFunds(v) => {
                pb::proposal_data::ActionAuxiliary::TransferSnsTreasuryFunds(v.into())
            }
            pb_api::proposal_data::ActionAuxiliary::MintSnsTokens(v) => {
                pb::proposal_data::ActionAuxiliary::MintSnsTokens(v.into())
            }
            pb_api::proposal_data::ActionAuxiliary::AdvanceSnsTargetVersion(v) => {
                pb::proposal_data::ActionAuxiliary::AdvanceSnsTargetVersion(v.into())
            }
        }
    }
}

impl From<pb::Valuation> for pb_api::Valuation {
    fn from(item: pb::Valuation) -> Self {
        Self {
            token: item.token,
            account: item.account.map(|x| x.into()),
            timestamp_seconds: item.timestamp_seconds,
            valuation_factors: item.valuation_factors.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Valuation> for pb::Valuation {
    fn from(item: pb_api::Valuation) -> Self {
        Self {
            token: item.token,
            account: item.account.map(|x| x.into()),
            timestamp_seconds: item.timestamp_seconds,
            valuation_factors: item.valuation_factors.map(|x| x.into()),
        }
    }
}

impl From<pb::valuation::ValuationFactors> for pb_api::valuation::ValuationFactors {
    fn from(item: pb::valuation::ValuationFactors) -> Self {
        Self {
            tokens: item.tokens,
            icps_per_token: item.icps_per_token,
            xdrs_per_icp: item.xdrs_per_icp,
        }
    }
}
impl From<pb_api::valuation::ValuationFactors> for pb::valuation::ValuationFactors {
    fn from(item: pb_api::valuation::ValuationFactors) -> Self {
        Self {
            tokens: item.tokens,
            icps_per_token: item.icps_per_token,
            xdrs_per_icp: item.xdrs_per_icp,
        }
    }
}

impl From<pb::valuation::Token> for pb_api::valuation::Token {
    fn from(item: pb::valuation::Token) -> Self {
        match item {
            pb::valuation::Token::Unspecified => pb_api::valuation::Token::Unspecified,
            pb::valuation::Token::Icp => pb_api::valuation::Token::Icp,
            pb::valuation::Token::SnsToken => pb_api::valuation::Token::SnsToken,
        }
    }
}
impl From<pb_api::valuation::Token> for pb::valuation::Token {
    fn from(item: pb_api::valuation::Token) -> Self {
        match item {
            pb_api::valuation::Token::Unspecified => pb::valuation::Token::Unspecified,
            pb_api::valuation::Token::Icp => pb::valuation::Token::Icp,
            pb_api::valuation::Token::SnsToken => pb::valuation::Token::SnsToken,
        }
    }
}

impl From<pb::NervousSystemParameters> for pb_api::NervousSystemParameters {
    fn from(item: pb::NervousSystemParameters) -> Self {
        Self {
            reject_cost_e8s: item.reject_cost_e8s,
            neuron_minimum_stake_e8s: item.neuron_minimum_stake_e8s,
            transaction_fee_e8s: item.transaction_fee_e8s,
            max_proposals_to_keep_per_action: item.max_proposals_to_keep_per_action,
            initial_voting_period_seconds: item.initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: item.wait_for_quiet_deadline_increase_seconds,
            default_followees: item.default_followees.map(|x| x.into()),
            max_number_of_neurons: item.max_number_of_neurons,
            neuron_minimum_dissolve_delay_to_vote_seconds: item
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            max_followees_per_function: item.max_followees_per_function,
            max_dissolve_delay_seconds: item.max_dissolve_delay_seconds,
            max_neuron_age_for_age_bonus: item.max_neuron_age_for_age_bonus,
            max_number_of_proposals_with_ballots: item.max_number_of_proposals_with_ballots,
            neuron_claimer_permissions: item.neuron_claimer_permissions.map(|x| x.into()),
            neuron_grantable_permissions: item.neuron_grantable_permissions.map(|x| x.into()),
            max_number_of_principals_per_neuron: item.max_number_of_principals_per_neuron,
            voting_rewards_parameters: item.voting_rewards_parameters.map(|x| x.into()),
            max_dissolve_delay_bonus_percentage: item.max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage: item.max_age_bonus_percentage,
            maturity_modulation_disabled: item.maturity_modulation_disabled,
        }
    }
}
impl From<pb_api::NervousSystemParameters> for pb::NervousSystemParameters {
    fn from(item: pb_api::NervousSystemParameters) -> Self {
        Self {
            reject_cost_e8s: item.reject_cost_e8s,
            neuron_minimum_stake_e8s: item.neuron_minimum_stake_e8s,
            transaction_fee_e8s: item.transaction_fee_e8s,
            max_proposals_to_keep_per_action: item.max_proposals_to_keep_per_action,
            initial_voting_period_seconds: item.initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: item.wait_for_quiet_deadline_increase_seconds,
            default_followees: item.default_followees.map(|x| x.into()),
            max_number_of_neurons: item.max_number_of_neurons,
            neuron_minimum_dissolve_delay_to_vote_seconds: item
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            max_followees_per_function: item.max_followees_per_function,
            max_dissolve_delay_seconds: item.max_dissolve_delay_seconds,
            max_neuron_age_for_age_bonus: item.max_neuron_age_for_age_bonus,
            max_number_of_proposals_with_ballots: item.max_number_of_proposals_with_ballots,
            neuron_claimer_permissions: item.neuron_claimer_permissions.map(|x| x.into()),
            neuron_grantable_permissions: item.neuron_grantable_permissions.map(|x| x.into()),
            max_number_of_principals_per_neuron: item.max_number_of_principals_per_neuron,
            voting_rewards_parameters: item.voting_rewards_parameters.map(|x| x.into()),
            max_dissolve_delay_bonus_percentage: item.max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage: item.max_age_bonus_percentage,
            maturity_modulation_disabled: item.maturity_modulation_disabled,
        }
    }
}

impl From<pb::VotingRewardsParameters> for pb_api::VotingRewardsParameters {
    fn from(item: pb::VotingRewardsParameters) -> Self {
        Self {
            round_duration_seconds: item.round_duration_seconds,
            reward_rate_transition_duration_seconds: item.reward_rate_transition_duration_seconds,
            initial_reward_rate_basis_points: item.initial_reward_rate_basis_points,
            final_reward_rate_basis_points: item.final_reward_rate_basis_points,
        }
    }
}
impl From<pb_api::VotingRewardsParameters> for pb::VotingRewardsParameters {
    fn from(item: pb_api::VotingRewardsParameters) -> Self {
        Self {
            round_duration_seconds: item.round_duration_seconds,
            reward_rate_transition_duration_seconds: item.reward_rate_transition_duration_seconds,
            initial_reward_rate_basis_points: item.initial_reward_rate_basis_points,
            final_reward_rate_basis_points: item.final_reward_rate_basis_points,
        }
    }
}

impl From<pb::DefaultFollowees> for pb_api::DefaultFollowees {
    fn from(item: pb::DefaultFollowees) -> Self {
        Self {
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}
impl From<pb_api::DefaultFollowees> for pb::DefaultFollowees {
    fn from(item: pb_api::DefaultFollowees) -> Self {
        Self {
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<pb::NeuronPermissionList> for pb_api::NeuronPermissionList {
    fn from(item: pb::NeuronPermissionList) -> Self {
        Self {
            permissions: item.permissions,
        }
    }
}
impl From<pb_api::NeuronPermissionList> for pb::NeuronPermissionList {
    fn from(item: pb_api::NeuronPermissionList) -> Self {
        Self {
            permissions: item.permissions,
        }
    }
}

impl From<pb::RewardEvent> for pb_api::RewardEvent {
    fn from(item: pb::RewardEvent) -> Self {
        Self {
            round: item.round,
            actual_timestamp_seconds: item.actual_timestamp_seconds,
            settled_proposals: item
                .settled_proposals
                .into_iter()
                .map(|x| x.into())
                .collect(),
            distributed_e8s_equivalent: item.distributed_e8s_equivalent,
            end_timestamp_seconds: item.end_timestamp_seconds,
            rounds_since_last_distribution: item.rounds_since_last_distribution,
            total_available_e8s_equivalent: item.total_available_e8s_equivalent,
        }
    }
}
impl From<pb_api::RewardEvent> for pb::RewardEvent {
    fn from(item: pb_api::RewardEvent) -> Self {
        Self {
            round: item.round,
            actual_timestamp_seconds: item.actual_timestamp_seconds,
            settled_proposals: item
                .settled_proposals
                .into_iter()
                .map(|x| x.into())
                .collect(),
            distributed_e8s_equivalent: item.distributed_e8s_equivalent,
            end_timestamp_seconds: item.end_timestamp_seconds,
            rounds_since_last_distribution: item.rounds_since_last_distribution,
            total_available_e8s_equivalent: item.total_available_e8s_equivalent,
        }
    }
}

impl From<pb::Governance> for pb_api::Governance {
    fn from(item: pb::Governance) -> Self {
        Self {
            neurons: item
                .neurons
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            proposals: item
                .proposals
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            parameters: item.parameters.map(|x| x.into()),
            latest_reward_event: item.latest_reward_event.map(|x| x.into()),
            in_flight_commands: item
                .in_flight_commands
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            genesis_timestamp_seconds: item.genesis_timestamp_seconds,
            metrics: item.metrics.map(|x| x.into()),
            ledger_canister_id: item.ledger_canister_id,
            root_canister_id: item.root_canister_id,
            id_to_nervous_system_functions: item
                .id_to_nervous_system_functions
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            mode: item.mode,
            swap_canister_id: item.swap_canister_id,
            sns_metadata: item.sns_metadata.map(|x| x.into()),
            sns_initialization_parameters: item.sns_initialization_parameters,
            deployed_version: item.deployed_version.map(|x| x.into()),
            pending_version: item.pending_version.map(|x| x.into()),
            target_version: item.target_version.map(|x| x.into()),
            is_finalizing_disburse_maturity: item.is_finalizing_disburse_maturity,
            maturity_modulation: item.maturity_modulation.map(|x| x.into()),
            cached_upgrade_steps: item.cached_upgrade_steps.map(|x| x.into()),
            timers: item.timers,
            upgrade_journal: item.upgrade_journal.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Governance> for pb::Governance {
    fn from(item: pb_api::Governance) -> Self {
        Self {
            neurons: item
                .neurons
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            proposals: item
                .proposals
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            parameters: item.parameters.map(|x| x.into()),
            latest_reward_event: item.latest_reward_event.map(|x| x.into()),
            in_flight_commands: item
                .in_flight_commands
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            genesis_timestamp_seconds: item.genesis_timestamp_seconds,
            metrics: item.metrics.map(|x| x.into()),
            ledger_canister_id: item.ledger_canister_id,
            root_canister_id: item.root_canister_id,
            id_to_nervous_system_functions: item
                .id_to_nervous_system_functions
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            mode: item.mode,
            swap_canister_id: item.swap_canister_id,
            sns_metadata: item.sns_metadata.map(|x| x.into()),
            sns_initialization_parameters: item.sns_initialization_parameters,
            deployed_version: item.deployed_version.map(|x| x.into()),
            pending_version: item.pending_version.map(|x| x.into()),
            target_version: item.target_version.map(|x| x.into()),
            is_finalizing_disburse_maturity: item.is_finalizing_disburse_maturity,
            maturity_modulation: item.maturity_modulation.map(|x| x.into()),
            cached_upgrade_steps: item.cached_upgrade_steps.map(|x| x.into()),
            timers: item.timers,
            upgrade_journal: item.upgrade_journal.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::NeuronInFlightCommand> for pb_api::governance::NeuronInFlightCommand {
    fn from(item: pb::governance::NeuronInFlightCommand) -> Self {
        Self {
            timestamp: item.timestamp,
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::governance::NeuronInFlightCommand> for pb::governance::NeuronInFlightCommand {
    fn from(item: pb_api::governance::NeuronInFlightCommand) -> Self {
        Self {
            timestamp: item.timestamp,
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::neuron_in_flight_command::SyncCommand>
    for pb_api::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: pb::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}
impl From<pb_api::governance::neuron_in_flight_command::SyncCommand>
    for pb::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: pb_api::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}

impl From<pb::governance::neuron_in_flight_command::Command>
    for pb_api::governance::neuron_in_flight_command::Command
{
    fn from(item: pb::governance::neuron_in_flight_command::Command) -> Self {
        match item {
            pb::governance::neuron_in_flight_command::Command::Disburse(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Disburse(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::Split(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Split(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::MergeMaturity(v) => {
                pb_api::governance::neuron_in_flight_command::Command::MergeMaturity(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::DisburseMaturity(v) => {
                pb_api::governance::neuron_in_flight_command::Command::DisburseMaturity(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v) => {
                pb_api::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(
                    v.into(),
                )
            }
            pb::governance::neuron_in_flight_command::Command::AddNeuronPermissions(v) => {
                pb_api::governance::neuron_in_flight_command::Command::AddNeuronPermissions(
                    v.into(),
                )
            }
            pb::governance::neuron_in_flight_command::Command::RemoveNeuronPermissions(v) => {
                pb_api::governance::neuron_in_flight_command::Command::RemoveNeuronPermissions(
                    v.into(),
                )
            }
            pb::governance::neuron_in_flight_command::Command::Configure(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Configure(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::Follow(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Follow(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::MakeProposal(v) => {
                pb_api::governance::neuron_in_flight_command::Command::MakeProposal(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::RegisterVote(v) => {
                pb_api::governance::neuron_in_flight_command::Command::RegisterVote(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::FinalizeDisburseMaturity(v) => {
                pb_api::governance::neuron_in_flight_command::Command::FinalizeDisburseMaturity(
                    v.into(),
                )
            }
            pb::governance::neuron_in_flight_command::Command::SyncCommand(v) => {
                pb_api::governance::neuron_in_flight_command::Command::SyncCommand(v.into())
            }
        }
    }
}
impl From<pb_api::governance::neuron_in_flight_command::Command>
    for pb::governance::neuron_in_flight_command::Command
{
    fn from(item: pb_api::governance::neuron_in_flight_command::Command) -> Self {
        match item {
            pb_api::governance::neuron_in_flight_command::Command::Disburse(v) => {
                pb::governance::neuron_in_flight_command::Command::Disburse(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Split(v) => {
                pb::governance::neuron_in_flight_command::Command::Split(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::MergeMaturity(v) => {
                pb::governance::neuron_in_flight_command::Command::MergeMaturity(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::DisburseMaturity(v) => {
                pb::governance::neuron_in_flight_command::Command::DisburseMaturity(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v) => {
                pb::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::AddNeuronPermissions(v) => {
                pb::governance::neuron_in_flight_command::Command::AddNeuronPermissions(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::RemoveNeuronPermissions(v) => {
                pb::governance::neuron_in_flight_command::Command::RemoveNeuronPermissions(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Configure(v) => {
                pb::governance::neuron_in_flight_command::Command::Configure(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Follow(v) => {
                pb::governance::neuron_in_flight_command::Command::Follow(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::MakeProposal(v) => {
                pb::governance::neuron_in_flight_command::Command::MakeProposal(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::RegisterVote(v) => {
                pb::governance::neuron_in_flight_command::Command::RegisterVote(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::FinalizeDisburseMaturity(v) => {
                pb::governance::neuron_in_flight_command::Command::FinalizeDisburseMaturity(
                    v.into(),
                )
            }
            pb_api::governance::neuron_in_flight_command::Command::SyncCommand(v) => {
                pb::governance::neuron_in_flight_command::Command::SyncCommand(v.into())
            }
        }
    }
}

impl From<pb::governance::GovernanceCachedMetrics> for pb_api::governance::GovernanceCachedMetrics {
    fn from(item: pb::governance::GovernanceCachedMetrics) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            total_supply_governance_tokens: item.total_supply_governance_tokens,
            dissolving_neurons_count: item.dissolving_neurons_count,
            dissolving_neurons_e8s_buckets: item.dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets: item.dissolving_neurons_count_buckets,
            not_dissolving_neurons_count: item.not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets: item.not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets: item.not_dissolving_neurons_count_buckets,
            dissolved_neurons_count: item.dissolved_neurons_count,
            dissolved_neurons_e8s: item.dissolved_neurons_e8s,
            garbage_collectable_neurons_count: item.garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count: item.neurons_with_invalid_stake_count,
            total_staked_e8s: item.total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count: item
                .neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s: item
                .neurons_with_less_than_6_months_dissolve_delay_e8s,
        }
    }
}
impl From<pb_api::governance::GovernanceCachedMetrics> for pb::governance::GovernanceCachedMetrics {
    fn from(item: pb_api::governance::GovernanceCachedMetrics) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            total_supply_governance_tokens: item.total_supply_governance_tokens,
            dissolving_neurons_count: item.dissolving_neurons_count,
            dissolving_neurons_e8s_buckets: item.dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets: item.dissolving_neurons_count_buckets,
            not_dissolving_neurons_count: item.not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets: item.not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets: item.not_dissolving_neurons_count_buckets,
            dissolved_neurons_count: item.dissolved_neurons_count,
            dissolved_neurons_e8s: item.dissolved_neurons_e8s,
            garbage_collectable_neurons_count: item.garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count: item.neurons_with_invalid_stake_count,
            total_staked_e8s: item.total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count: item
                .neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s: item
                .neurons_with_less_than_6_months_dissolve_delay_e8s,
        }
    }
}

impl From<pb::governance::SnsMetadata> for pb_api::governance::SnsMetadata {
    fn from(item: pb::governance::SnsMetadata) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}
impl From<pb_api::governance::SnsMetadata> for pb::governance::SnsMetadata {
    fn from(item: pb_api::governance::SnsMetadata) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}

impl From<pb::governance::Version> for pb_api::governance::Version {
    fn from(item: pb::governance::Version) -> Self {
        Self {
            root_wasm_hash: item.root_wasm_hash,
            governance_wasm_hash: item.governance_wasm_hash,
            ledger_wasm_hash: item.ledger_wasm_hash,
            swap_wasm_hash: item.swap_wasm_hash,
            archive_wasm_hash: item.archive_wasm_hash,
            index_wasm_hash: item.index_wasm_hash,
        }
    }
}
impl From<pb_api::governance::Version> for pb::governance::Version {
    fn from(item: pb_api::governance::Version) -> Self {
        Self {
            root_wasm_hash: item.root_wasm_hash,
            governance_wasm_hash: item.governance_wasm_hash,
            ledger_wasm_hash: item.ledger_wasm_hash,
            swap_wasm_hash: item.swap_wasm_hash,
            archive_wasm_hash: item.archive_wasm_hash,
            index_wasm_hash: item.index_wasm_hash,
        }
    }
}

impl From<pb::governance::Versions> for pb_api::governance::Versions {
    fn from(item: pb::governance::Versions) -> Self {
        Self {
            versions: item.versions.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::governance::Versions> for pb::governance::Versions {
    fn from(item: pb_api::governance::Versions) -> Self {
        Self {
            versions: item.versions.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::governance::PendingVersion> for pb_api::governance::PendingVersion {
    fn from(item: pb::governance::PendingVersion) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
            mark_failed_at_seconds: item.mark_failed_at_seconds,
            checking_upgrade_lock: item.checking_upgrade_lock,
            proposal_id: item.proposal_id,
        }
    }
}
impl From<pb_api::governance::PendingVersion> for pb::governance::PendingVersion {
    fn from(item: pb_api::governance::PendingVersion) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
            mark_failed_at_seconds: item.mark_failed_at_seconds,
            checking_upgrade_lock: item.checking_upgrade_lock,
            proposal_id: item.proposal_id,
        }
    }
}

impl From<pb::governance::MaturityModulation> for pb_api::governance::MaturityModulation {
    fn from(item: pb::governance::MaturityModulation) -> Self {
        Self {
            current_basis_points: item.current_basis_points,
            updated_at_timestamp_seconds: item.updated_at_timestamp_seconds,
        }
    }
}
impl From<pb_api::governance::MaturityModulation> for pb::governance::MaturityModulation {
    fn from(item: pb_api::governance::MaturityModulation) -> Self {
        Self {
            current_basis_points: item.current_basis_points,
            updated_at_timestamp_seconds: item.updated_at_timestamp_seconds,
        }
    }
}

impl From<pb::governance::CachedUpgradeSteps> for pb_api::governance::CachedUpgradeSteps {
    fn from(item: pb::governance::CachedUpgradeSteps) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
            requested_timestamp_seconds: item.requested_timestamp_seconds,
            response_timestamp_seconds: item.response_timestamp_seconds,
        }
    }
}
impl From<pb_api::governance::CachedUpgradeSteps> for pb::governance::CachedUpgradeSteps {
    fn from(item: pb_api::governance::CachedUpgradeSteps) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
            requested_timestamp_seconds: item.requested_timestamp_seconds,
            response_timestamp_seconds: item.response_timestamp_seconds,
        }
    }
}

impl From<pb::governance::Mode> for pb_api::governance::Mode {
    fn from(item: pb::governance::Mode) -> Self {
        match item {
            pb::governance::Mode::Unspecified => pb_api::governance::Mode::Unspecified,
            pb::governance::Mode::Normal => pb_api::governance::Mode::Normal,
            pb::governance::Mode::PreInitializationSwap => {
                pb_api::governance::Mode::PreInitializationSwap
            }
        }
    }
}
impl From<pb_api::governance::Mode> for pb::governance::Mode {
    fn from(item: pb_api::governance::Mode) -> Self {
        match item {
            pb_api::governance::Mode::Unspecified => pb::governance::Mode::Unspecified,
            pb_api::governance::Mode::Normal => pb::governance::Mode::Normal,
            pb_api::governance::Mode::PreInitializationSwap => {
                pb::governance::Mode::PreInitializationSwap
            }
        }
    }
}

impl From<pb::GetMetadataRequest> for pb_api::GetMetadataRequest {
    fn from(_: pb::GetMetadataRequest) -> Self {
        Self {}
    }
}
impl From<pb_api::GetMetadataRequest> for pb::GetMetadataRequest {
    fn from(_: pb_api::GetMetadataRequest) -> Self {
        Self {}
    }
}

impl From<pb::GetMetadataResponse> for pb_api::GetMetadataResponse {
    fn from(item: pb::GetMetadataResponse) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}
impl From<pb_api::GetMetadataResponse> for pb::GetMetadataResponse {
    fn from(item: pb_api::GetMetadataResponse) -> Self {
        Self {
            logo: item.logo,
            url: item.url,
            name: item.name,
            description: item.description,
        }
    }
}

impl From<pb::GetSnsInitializationParametersRequest>
    for pb_api::GetSnsInitializationParametersRequest
{
    fn from(_: pb::GetSnsInitializationParametersRequest) -> Self {
        Self {}
    }
}
impl From<pb_api::GetSnsInitializationParametersRequest>
    for pb::GetSnsInitializationParametersRequest
{
    fn from(_: pb_api::GetSnsInitializationParametersRequest) -> Self {
        Self {}
    }
}

impl From<pb::GetSnsInitializationParametersResponse>
    for pb_api::GetSnsInitializationParametersResponse
{
    fn from(item: pb::GetSnsInitializationParametersResponse) -> Self {
        Self {
            sns_initialization_parameters: item.sns_initialization_parameters,
        }
    }
}
impl From<pb_api::GetSnsInitializationParametersResponse>
    for pb::GetSnsInitializationParametersResponse
{
    fn from(item: pb_api::GetSnsInitializationParametersResponse) -> Self {
        Self {
            sns_initialization_parameters: item.sns_initialization_parameters,
        }
    }
}

impl From<pb::GetRunningSnsVersionRequest> for pb_api::GetRunningSnsVersionRequest {
    fn from(_: pb::GetRunningSnsVersionRequest) -> Self {
        Self {}
    }
}
impl From<pb_api::GetRunningSnsVersionRequest> for pb::GetRunningSnsVersionRequest {
    fn from(_: pb_api::GetRunningSnsVersionRequest) -> Self {
        Self {}
    }
}

impl From<pb::GetRunningSnsVersionResponse> for pb_api::GetRunningSnsVersionResponse {
    fn from(item: pb::GetRunningSnsVersionResponse) -> Self {
        Self {
            deployed_version: item.deployed_version.map(|x| x.into()),
            pending_version: item.pending_version.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetRunningSnsVersionResponse> for pb::GetRunningSnsVersionResponse {
    fn from(item: pb_api::GetRunningSnsVersionResponse) -> Self {
        Self {
            deployed_version: item.deployed_version.map(|x| x.into()),
            pending_version: item.pending_version.map(|x| x.into()),
        }
    }
}

impl From<pb::get_running_sns_version_response::UpgradeInProgress>
    for pb_api::get_running_sns_version_response::UpgradeInProgress
{
    fn from(item: pb::get_running_sns_version_response::UpgradeInProgress) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
            mark_failed_at_seconds: item.mark_failed_at_seconds,
            checking_upgrade_lock: item.checking_upgrade_lock,
            proposal_id: item.proposal_id,
        }
    }
}
impl From<pb_api::get_running_sns_version_response::UpgradeInProgress>
    for pb::get_running_sns_version_response::UpgradeInProgress
{
    fn from(item: pb_api::get_running_sns_version_response::UpgradeInProgress) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
            mark_failed_at_seconds: item.mark_failed_at_seconds,
            checking_upgrade_lock: item.checking_upgrade_lock,
            proposal_id: item.proposal_id,
        }
    }
}

impl From<pb::FailStuckUpgradeInProgressRequest> for pb_api::FailStuckUpgradeInProgressRequest {
    fn from(_: pb::FailStuckUpgradeInProgressRequest) -> Self {
        Self {}
    }
}
impl From<pb_api::FailStuckUpgradeInProgressRequest> for pb::FailStuckUpgradeInProgressRequest {
    fn from(_: pb_api::FailStuckUpgradeInProgressRequest) -> Self {
        Self {}
    }
}

impl From<pb::FailStuckUpgradeInProgressResponse> for pb_api::FailStuckUpgradeInProgressResponse {
    fn from(_: pb::FailStuckUpgradeInProgressResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::FailStuckUpgradeInProgressResponse> for pb::FailStuckUpgradeInProgressResponse {
    fn from(_: pb_api::FailStuckUpgradeInProgressResponse) -> Self {
        Self {}
    }
}

impl From<pb::Empty> for pb_api::Empty {
    fn from(_: pb::Empty) -> Self {
        Self {}
    }
}
impl From<pb_api::Empty> for pb::Empty {
    fn from(_: pb_api::Empty) -> Self {
        Self {}
    }
}

impl From<pb::ManageNeuron> for pb_api::ManageNeuron {
    fn from(item: pb::ManageNeuron) -> Self {
        Self {
            subaccount: item.subaccount,
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuron> for pb::ManageNeuron {
    fn from(item: pb_api::ManageNeuron) -> Self {
        Self {
            subaccount: item.subaccount,
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::IncreaseDissolveDelay>
    for pb_api::manage_neuron::IncreaseDissolveDelay
{
    fn from(item: pb::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}
impl From<pb_api::manage_neuron::IncreaseDissolveDelay>
    for pb::manage_neuron::IncreaseDissolveDelay
{
    fn from(item: pb_api::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}

impl From<pb::manage_neuron::StartDissolving> for pb_api::manage_neuron::StartDissolving {
    fn from(_: pb::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::StartDissolving> for pb::manage_neuron::StartDissolving {
    fn from(_: pb_api::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::StopDissolving> for pb_api::manage_neuron::StopDissolving {
    fn from(_: pb::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::StopDissolving> for pb::manage_neuron::StopDissolving {
    fn from(_: pb_api::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::SetDissolveTimestamp> for pb_api::manage_neuron::SetDissolveTimestamp {
    fn from(item: pb::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}
impl From<pb_api::manage_neuron::SetDissolveTimestamp> for pb::manage_neuron::SetDissolveTimestamp {
    fn from(item: pb_api::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}

impl From<pb::manage_neuron::ChangeAutoStakeMaturity>
    for pb_api::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: pb::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}
impl From<pb_api::manage_neuron::ChangeAutoStakeMaturity>
    for pb::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: pb_api::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}

impl From<pb::manage_neuron::Configure> for pb_api::manage_neuron::Configure {
    fn from(item: pb::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::Configure> for pb::manage_neuron::Configure {
    fn from(item: pb_api::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::configure::Operation> for pb_api::manage_neuron::configure::Operation {
    fn from(item: pb::manage_neuron::configure::Operation) -> Self {
        match item {
            pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                pb_api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            pb::manage_neuron::configure::Operation::StartDissolving(v) => {
                pb_api::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::StopDissolving(v) => {
                pb_api::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                pb_api::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                pb_api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::configure::Operation> for pb::manage_neuron::configure::Operation {
    fn from(item: pb_api::manage_neuron::configure::Operation) -> Self {
        match item {
            pb_api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            pb_api::manage_neuron::configure::Operation::StartDissolving(v) => {
                pb::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            pb_api::manage_neuron::configure::Operation::StopDissolving(v) => {
                pb::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            pb_api::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            pb_api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::Disburse> for pb_api::manage_neuron::Disburse {
    fn from(item: pb::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::Disburse> for pb::manage_neuron::Disburse {
    fn from(item: pb_api::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::disburse::Amount> for pb_api::manage_neuron::disburse::Amount {
    fn from(item: pb::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}
impl From<pb_api::manage_neuron::disburse::Amount> for pb::manage_neuron::disburse::Amount {
    fn from(item: pb_api::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}

impl From<pb::manage_neuron::Split> for pb_api::manage_neuron::Split {
    fn from(item: pb::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}
impl From<pb_api::manage_neuron::Split> for pb::manage_neuron::Split {
    fn from(item: pb_api::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}

impl From<pb::manage_neuron::MergeMaturity> for pb_api::manage_neuron::MergeMaturity {
    fn from(item: pb::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}
impl From<pb_api::manage_neuron::MergeMaturity> for pb::manage_neuron::MergeMaturity {
    fn from(item: pb_api::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}

impl From<pb::manage_neuron::StakeMaturity> for pb_api::manage_neuron::StakeMaturity {
    fn from(item: pb::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}
impl From<pb_api::manage_neuron::StakeMaturity> for pb::manage_neuron::StakeMaturity {
    fn from(item: pb_api::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}

impl From<pb::manage_neuron::DisburseMaturity> for pb_api::manage_neuron::DisburseMaturity {
    fn from(item: pb::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::DisburseMaturity> for pb::manage_neuron::DisburseMaturity {
    fn from(item: pb_api::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::FinalizeDisburseMaturity>
    for pb_api::manage_neuron::FinalizeDisburseMaturity
{
    fn from(item: pb::manage_neuron::FinalizeDisburseMaturity) -> Self {
        Self {
            amount_to_be_disbursed_e8s: item.amount_to_be_disbursed_e8s,
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::FinalizeDisburseMaturity>
    for pb::manage_neuron::FinalizeDisburseMaturity
{
    fn from(item: pb_api::manage_neuron::FinalizeDisburseMaturity) -> Self {
        Self {
            amount_to_be_disbursed_e8s: item.amount_to_be_disbursed_e8s,
            to_account: item.to_account.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::Follow> for pb_api::manage_neuron::Follow {
    fn from(item: pb::manage_neuron::Follow) -> Self {
        Self {
            function_id: item.function_id,
            followees: item.followees.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::manage_neuron::Follow> for pb::manage_neuron::Follow {
    fn from(item: pb_api::manage_neuron::Follow) -> Self {
        Self {
            function_id: item.function_id,
            followees: item.followees.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::manage_neuron::RegisterVote> for pb_api::manage_neuron::RegisterVote {
    fn from(item: pb::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal.map(|x| x.into()),
            vote: item.vote,
        }
    }
}
impl From<pb_api::manage_neuron::RegisterVote> for pb::manage_neuron::RegisterVote {
    fn from(item: pb_api::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal.map(|x| x.into()),
            vote: item.vote,
        }
    }
}

impl From<pb::manage_neuron::ClaimOrRefresh> for pb_api::manage_neuron::ClaimOrRefresh {
    fn from(item: pb::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::ClaimOrRefresh> for pb::manage_neuron::ClaimOrRefresh {
    fn from(item: pb_api::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::MemoAndController>
    for pb_api::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: pb::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}
impl From<pb_api::manage_neuron::claim_or_refresh::MemoAndController>
    for pb::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: pb_api::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::By> for pb_api::manage_neuron::claim_or_refresh::By {
    fn from(item: pb::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            pb::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                pb_api::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            pb::manage_neuron::claim_or_refresh::By::NeuronId(v) => {
                pb_api::manage_neuron::claim_or_refresh::By::NeuronId(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::claim_or_refresh::By> for pb::manage_neuron::claim_or_refresh::By {
    fn from(item: pb_api::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            pb_api::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                pb::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            pb_api::manage_neuron::claim_or_refresh::By::NeuronId(v) => {
                pb::manage_neuron::claim_or_refresh::By::NeuronId(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::AddNeuronPermissions> for pb_api::manage_neuron::AddNeuronPermissions {
    fn from(item: pb::manage_neuron::AddNeuronPermissions) -> Self {
        Self {
            principal_id: item.principal_id,
            permissions_to_add: item.permissions_to_add.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::AddNeuronPermissions> for pb::manage_neuron::AddNeuronPermissions {
    fn from(item: pb_api::manage_neuron::AddNeuronPermissions) -> Self {
        Self {
            principal_id: item.principal_id,
            permissions_to_add: item.permissions_to_add.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::RemoveNeuronPermissions>
    for pb_api::manage_neuron::RemoveNeuronPermissions
{
    fn from(item: pb::manage_neuron::RemoveNeuronPermissions) -> Self {
        Self {
            principal_id: item.principal_id,
            permissions_to_remove: item.permissions_to_remove.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::RemoveNeuronPermissions>
    for pb::manage_neuron::RemoveNeuronPermissions
{
    fn from(item: pb_api::manage_neuron::RemoveNeuronPermissions) -> Self {
        Self {
            principal_id: item.principal_id,
            permissions_to_remove: item.permissions_to_remove.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::Command> for pb_api::manage_neuron::Command {
    fn from(item: pb::manage_neuron::Command) -> Self {
        match item {
            pb::manage_neuron::Command::Configure(v) => {
                pb_api::manage_neuron::Command::Configure(v.into())
            }
            pb::manage_neuron::Command::Disburse(v) => {
                pb_api::manage_neuron::Command::Disburse(v.into())
            }
            pb::manage_neuron::Command::Follow(v) => {
                pb_api::manage_neuron::Command::Follow(v.into())
            }
            pb::manage_neuron::Command::MakeProposal(v) => {
                pb_api::manage_neuron::Command::MakeProposal(v.into())
            }
            pb::manage_neuron::Command::RegisterVote(v) => {
                pb_api::manage_neuron::Command::RegisterVote(v.into())
            }
            pb::manage_neuron::Command::Split(v) => pb_api::manage_neuron::Command::Split(v.into()),
            pb::manage_neuron::Command::ClaimOrRefresh(v) => {
                pb_api::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron::Command::MergeMaturity(v) => {
                pb_api::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb::manage_neuron::Command::DisburseMaturity(v) => {
                pb_api::manage_neuron::Command::DisburseMaturity(v.into())
            }
            pb::manage_neuron::Command::AddNeuronPermissions(v) => {
                pb_api::manage_neuron::Command::AddNeuronPermissions(v.into())
            }
            pb::manage_neuron::Command::RemoveNeuronPermissions(v) => {
                pb_api::manage_neuron::Command::RemoveNeuronPermissions(v.into())
            }
            pb::manage_neuron::Command::StakeMaturity(v) => {
                pb_api::manage_neuron::Command::StakeMaturity(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::Command> for pb::manage_neuron::Command {
    fn from(item: pb_api::manage_neuron::Command) -> Self {
        match item {
            pb_api::manage_neuron::Command::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            pb_api::manage_neuron::Command::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            pb_api::manage_neuron::Command::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            pb_api::manage_neuron::Command::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(v.into())
            }
            pb_api::manage_neuron::Command::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            pb_api::manage_neuron::Command::Split(v) => pb::manage_neuron::Command::Split(v.into()),
            pb_api::manage_neuron::Command::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb_api::manage_neuron::Command::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb_api::manage_neuron::Command::DisburseMaturity(v) => {
                pb::manage_neuron::Command::DisburseMaturity(v.into())
            }
            pb_api::manage_neuron::Command::AddNeuronPermissions(v) => {
                pb::manage_neuron::Command::AddNeuronPermissions(v.into())
            }
            pb_api::manage_neuron::Command::RemoveNeuronPermissions(v) => {
                pb::manage_neuron::Command::RemoveNeuronPermissions(v.into())
            }
            pb_api::manage_neuron::Command::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
            }
        }
    }
}

impl From<pb::ManageNeuronResponse> for pb_api::ManageNeuronResponse {
    fn from(item: pb::ManageNeuronResponse) -> Self {
        Self {
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuronResponse> for pb::ManageNeuronResponse {
    fn from(item: pb_api::ManageNeuronResponse) -> Self {
        Self {
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::ConfigureResponse>
    for pb_api::manage_neuron_response::ConfigureResponse
{
    fn from(_: pb::manage_neuron_response::ConfigureResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::ConfigureResponse>
    for pb::manage_neuron_response::ConfigureResponse
{
    fn from(_: pb_api::manage_neuron_response::ConfigureResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::DisburseResponse>
    for pb_api::manage_neuron_response::DisburseResponse
{
    fn from(item: pb::manage_neuron_response::DisburseResponse) -> Self {
        Self {
            transfer_block_height: item.transfer_block_height,
        }
    }
}
impl From<pb_api::manage_neuron_response::DisburseResponse>
    for pb::manage_neuron_response::DisburseResponse
{
    fn from(item: pb_api::manage_neuron_response::DisburseResponse) -> Self {
        Self {
            transfer_block_height: item.transfer_block_height,
        }
    }
}

impl From<pb::manage_neuron_response::MergeMaturityResponse>
    for pb_api::manage_neuron_response::MergeMaturityResponse
{
    fn from(item: pb::manage_neuron_response::MergeMaturityResponse) -> Self {
        Self {
            merged_maturity_e8s: item.merged_maturity_e8s,
            new_stake_e8s: item.new_stake_e8s,
        }
    }
}
impl From<pb_api::manage_neuron_response::MergeMaturityResponse>
    for pb::manage_neuron_response::MergeMaturityResponse
{
    fn from(item: pb_api::manage_neuron_response::MergeMaturityResponse) -> Self {
        Self {
            merged_maturity_e8s: item.merged_maturity_e8s,
            new_stake_e8s: item.new_stake_e8s,
        }
    }
}

impl From<pb::manage_neuron_response::DisburseMaturityResponse>
    for pb_api::manage_neuron_response::DisburseMaturityResponse
{
    fn from(item: pb::manage_neuron_response::DisburseMaturityResponse) -> Self {
        Self {
            amount_disbursed_e8s: item.amount_disbursed_e8s,
            amount_deducted_e8s: item.amount_deducted_e8s,
        }
    }
}
impl From<pb_api::manage_neuron_response::DisburseMaturityResponse>
    for pb::manage_neuron_response::DisburseMaturityResponse
{
    fn from(item: pb_api::manage_neuron_response::DisburseMaturityResponse) -> Self {
        Self {
            amount_disbursed_e8s: item.amount_disbursed_e8s,
            amount_deducted_e8s: item.amount_deducted_e8s,
        }
    }
}

impl From<pb::manage_neuron_response::StakeMaturityResponse>
    for pb_api::manage_neuron_response::StakeMaturityResponse
{
    fn from(item: pb::manage_neuron_response::StakeMaturityResponse) -> Self {
        Self {
            maturity_e8s: item.maturity_e8s,
            staked_maturity_e8s: item.staked_maturity_e8s,
        }
    }
}
impl From<pb_api::manage_neuron_response::StakeMaturityResponse>
    for pb::manage_neuron_response::StakeMaturityResponse
{
    fn from(item: pb_api::manage_neuron_response::StakeMaturityResponse) -> Self {
        Self {
            maturity_e8s: item.maturity_e8s,
            staked_maturity_e8s: item.staked_maturity_e8s,
        }
    }
}

impl From<pb::manage_neuron_response::FollowResponse>
    for pb_api::manage_neuron_response::FollowResponse
{
    fn from(_: pb::manage_neuron_response::FollowResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::FollowResponse>
    for pb::manage_neuron_response::FollowResponse
{
    fn from(_: pb_api::manage_neuron_response::FollowResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::MakeProposalResponse>
    for pb_api::manage_neuron_response::MakeProposalResponse
{
    fn from(item: pb::manage_neuron_response::MakeProposalResponse) -> Self {
        Self {
            proposal_id: item.proposal_id.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron_response::MakeProposalResponse>
    for pb::manage_neuron_response::MakeProposalResponse
{
    fn from(item: pb_api::manage_neuron_response::MakeProposalResponse) -> Self {
        Self {
            proposal_id: item.proposal_id.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::RegisterVoteResponse>
    for pb_api::manage_neuron_response::RegisterVoteResponse
{
    fn from(_: pb::manage_neuron_response::RegisterVoteResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::RegisterVoteResponse>
    for pb::manage_neuron_response::RegisterVoteResponse
{
    fn from(_: pb_api::manage_neuron_response::RegisterVoteResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::SplitResponse>
    for pb_api::manage_neuron_response::SplitResponse
{
    fn from(item: pb::manage_neuron_response::SplitResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron_response::SplitResponse>
    for pb::manage_neuron_response::SplitResponse
{
    fn from(item: pb_api::manage_neuron_response::SplitResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::ClaimOrRefreshResponse>
    for pb_api::manage_neuron_response::ClaimOrRefreshResponse
{
    fn from(item: pb::manage_neuron_response::ClaimOrRefreshResponse) -> Self {
        Self {
            refreshed_neuron_id: item.refreshed_neuron_id.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron_response::ClaimOrRefreshResponse>
    for pb::manage_neuron_response::ClaimOrRefreshResponse
{
    fn from(item: pb_api::manage_neuron_response::ClaimOrRefreshResponse) -> Self {
        Self {
            refreshed_neuron_id: item.refreshed_neuron_id.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::AddNeuronPermissionsResponse>
    for pb_api::manage_neuron_response::AddNeuronPermissionsResponse
{
    fn from(_: pb::manage_neuron_response::AddNeuronPermissionsResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::AddNeuronPermissionsResponse>
    for pb::manage_neuron_response::AddNeuronPermissionsResponse
{
    fn from(_: pb_api::manage_neuron_response::AddNeuronPermissionsResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::RemoveNeuronPermissionsResponse>
    for pb_api::manage_neuron_response::RemoveNeuronPermissionsResponse
{
    fn from(_: pb::manage_neuron_response::RemoveNeuronPermissionsResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::RemoveNeuronPermissionsResponse>
    for pb::manage_neuron_response::RemoveNeuronPermissionsResponse
{
    fn from(_: pb_api::manage_neuron_response::RemoveNeuronPermissionsResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::Command> for pb_api::manage_neuron_response::Command {
    fn from(item: pb::manage_neuron_response::Command) -> Self {
        match item {
            pb::manage_neuron_response::Command::Error(v) => {
                pb_api::manage_neuron_response::Command::Error(v.into())
            }
            pb::manage_neuron_response::Command::Configure(v) => {
                pb_api::manage_neuron_response::Command::Configure(v.into())
            }
            pb::manage_neuron_response::Command::Disburse(v) => {
                pb_api::manage_neuron_response::Command::Disburse(v.into())
            }
            pb::manage_neuron_response::Command::Follow(v) => {
                pb_api::manage_neuron_response::Command::Follow(v.into())
            }
            pb::manage_neuron_response::Command::MakeProposal(v) => {
                pb_api::manage_neuron_response::Command::MakeProposal(v.into())
            }
            pb::manage_neuron_response::Command::RegisterVote(v) => {
                pb_api::manage_neuron_response::Command::RegisterVote(v.into())
            }
            pb::manage_neuron_response::Command::Split(v) => {
                pb_api::manage_neuron_response::Command::Split(v.into())
            }
            pb::manage_neuron_response::Command::ClaimOrRefresh(v) => {
                pb_api::manage_neuron_response::Command::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron_response::Command::MergeMaturity(v) => {
                pb_api::manage_neuron_response::Command::MergeMaturity(v.into())
            }
            pb::manage_neuron_response::Command::DisburseMaturity(v) => {
                pb_api::manage_neuron_response::Command::DisburseMaturity(v.into())
            }
            pb::manage_neuron_response::Command::AddNeuronPermission(v) => {
                pb_api::manage_neuron_response::Command::AddNeuronPermission(v.into())
            }
            pb::manage_neuron_response::Command::RemoveNeuronPermission(v) => {
                pb_api::manage_neuron_response::Command::RemoveNeuronPermission(v.into())
            }
            pb::manage_neuron_response::Command::StakeMaturity(v) => {
                pb_api::manage_neuron_response::Command::StakeMaturity(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron_response::Command> for pb::manage_neuron_response::Command {
    fn from(item: pb_api::manage_neuron_response::Command) -> Self {
        match item {
            pb_api::manage_neuron_response::Command::Error(v) => {
                pb::manage_neuron_response::Command::Error(v.into())
            }
            pb_api::manage_neuron_response::Command::Configure(v) => {
                pb::manage_neuron_response::Command::Configure(v.into())
            }
            pb_api::manage_neuron_response::Command::Disburse(v) => {
                pb::manage_neuron_response::Command::Disburse(v.into())
            }
            pb_api::manage_neuron_response::Command::Follow(v) => {
                pb::manage_neuron_response::Command::Follow(v.into())
            }
            pb_api::manage_neuron_response::Command::MakeProposal(v) => {
                pb::manage_neuron_response::Command::MakeProposal(v.into())
            }
            pb_api::manage_neuron_response::Command::RegisterVote(v) => {
                pb::manage_neuron_response::Command::RegisterVote(v.into())
            }
            pb_api::manage_neuron_response::Command::Split(v) => {
                pb::manage_neuron_response::Command::Split(v.into())
            }
            pb_api::manage_neuron_response::Command::ClaimOrRefresh(v) => {
                pb::manage_neuron_response::Command::ClaimOrRefresh(v.into())
            }
            pb_api::manage_neuron_response::Command::MergeMaturity(v) => {
                pb::manage_neuron_response::Command::MergeMaturity(v.into())
            }
            pb_api::manage_neuron_response::Command::DisburseMaturity(v) => {
                pb::manage_neuron_response::Command::DisburseMaturity(v.into())
            }
            pb_api::manage_neuron_response::Command::AddNeuronPermission(v) => {
                pb::manage_neuron_response::Command::AddNeuronPermission(v.into())
            }
            pb_api::manage_neuron_response::Command::RemoveNeuronPermission(v) => {
                pb::manage_neuron_response::Command::RemoveNeuronPermission(v.into())
            }
            pb_api::manage_neuron_response::Command::StakeMaturity(v) => {
                pb::manage_neuron_response::Command::StakeMaturity(v.into())
            }
        }
    }
}

impl From<pb::GetNeuron> for pb_api::GetNeuron {
    fn from(item: pb::GetNeuron) -> Self {
        Self {
            neuron_id: item.neuron_id.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetNeuron> for pb::GetNeuron {
    fn from(item: pb_api::GetNeuron) -> Self {
        Self {
            neuron_id: item.neuron_id.map(|x| x.into()),
        }
    }
}

impl From<pb::GetNeuronResponse> for pb_api::GetNeuronResponse {
    fn from(item: pb::GetNeuronResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetNeuronResponse> for pb::GetNeuronResponse {
    fn from(item: pb_api::GetNeuronResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::get_neuron_response::Result> for pb_api::get_neuron_response::Result {
    fn from(item: pb::get_neuron_response::Result) -> Self {
        match item {
            pb::get_neuron_response::Result::Error(v) => {
                pb_api::get_neuron_response::Result::Error(v.into())
            }
            pb::get_neuron_response::Result::Neuron(v) => {
                pb_api::get_neuron_response::Result::Neuron(v.into())
            }
        }
    }
}
impl From<pb_api::get_neuron_response::Result> for pb::get_neuron_response::Result {
    fn from(item: pb_api::get_neuron_response::Result) -> Self {
        match item {
            pb_api::get_neuron_response::Result::Error(v) => {
                pb::get_neuron_response::Result::Error(v.into())
            }
            pb_api::get_neuron_response::Result::Neuron(v) => {
                pb::get_neuron_response::Result::Neuron(v.into())
            }
        }
    }
}

impl From<pb::GetProposal> for pb_api::GetProposal {
    fn from(item: pb::GetProposal) -> Self {
        Self {
            proposal_id: item.proposal_id.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetProposal> for pb::GetProposal {
    fn from(item: pb_api::GetProposal) -> Self {
        Self {
            proposal_id: item.proposal_id.map(|x| x.into()),
        }
    }
}

impl From<pb::GetProposalResponse> for pb_api::GetProposalResponse {
    fn from(item: pb::GetProposalResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetProposalResponse> for pb::GetProposalResponse {
    fn from(item: pb_api::GetProposalResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::get_proposal_response::Result> for pb_api::get_proposal_response::Result {
    fn from(item: pb::get_proposal_response::Result) -> Self {
        match item {
            pb::get_proposal_response::Result::Error(v) => {
                pb_api::get_proposal_response::Result::Error(v.into())
            }
            pb::get_proposal_response::Result::Proposal(v) => {
                pb_api::get_proposal_response::Result::Proposal(v.into())
            }
        }
    }
}
impl From<pb_api::get_proposal_response::Result> for pb::get_proposal_response::Result {
    fn from(item: pb_api::get_proposal_response::Result) -> Self {
        match item {
            pb_api::get_proposal_response::Result::Error(v) => {
                pb::get_proposal_response::Result::Error(v.into())
            }
            pb_api::get_proposal_response::Result::Proposal(v) => {
                pb::get_proposal_response::Result::Proposal(v.into())
            }
        }
    }
}

impl From<pb::ListProposals> for pb_api::ListProposals {
    fn from(item: pb::ListProposals) -> Self {
        Self {
            limit: item.limit,
            before_proposal: item.before_proposal.map(|x| x.into()),
            exclude_type: item.exclude_type,
            include_reward_status: item.include_reward_status,
            include_status: item.include_status,
        }
    }
}
impl From<pb_api::ListProposals> for pb::ListProposals {
    fn from(item: pb_api::ListProposals) -> Self {
        Self {
            limit: item.limit,
            before_proposal: item.before_proposal.map(|x| x.into()),
            exclude_type: item.exclude_type,
            include_reward_status: item.include_reward_status,
            include_status: item.include_status,
        }
    }
}

impl From<pb::ListProposalsResponse> for pb_api::ListProposalsResponse {
    fn from(item: pb::ListProposalsResponse) -> Self {
        Self {
            proposals: item.proposals.into_iter().map(|x| x.into()).collect(),
            include_ballots_by_caller: item.include_ballots_by_caller,
        }
    }
}
impl From<pb_api::ListProposalsResponse> for pb::ListProposalsResponse {
    fn from(item: pb_api::ListProposalsResponse) -> Self {
        Self {
            proposals: item.proposals.into_iter().map(|x| x.into()).collect(),
            include_ballots_by_caller: item.include_ballots_by_caller,
        }
    }
}

impl From<pb::ListNeurons> for pb_api::ListNeurons {
    fn from(item: pb::ListNeurons) -> Self {
        Self {
            limit: item.limit,
            start_page_at: item.start_page_at.map(|x| x.into()),
            of_principal: item.of_principal,
        }
    }
}
impl From<pb_api::ListNeurons> for pb::ListNeurons {
    fn from(item: pb_api::ListNeurons) -> Self {
        Self {
            limit: item.limit,
            start_page_at: item.start_page_at.map(|x| x.into()),
            of_principal: item.of_principal,
        }
    }
}

impl From<pb::ListNeuronsResponse> for pb_api::ListNeuronsResponse {
    fn from(item: pb::ListNeuronsResponse) -> Self {
        Self {
            neurons: item.neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::ListNeuronsResponse> for pb::ListNeuronsResponse {
    fn from(item: pb_api::ListNeuronsResponse) -> Self {
        Self {
            neurons: item.neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ListNervousSystemFunctionsResponse> for pb_api::ListNervousSystemFunctionsResponse {
    fn from(item: pb::ListNervousSystemFunctionsResponse) -> Self {
        Self {
            functions: item.functions.into_iter().map(|x| x.into()).collect(),
            reserved_ids: item.reserved_ids,
        }
    }
}
impl From<pb_api::ListNervousSystemFunctionsResponse> for pb::ListNervousSystemFunctionsResponse {
    fn from(item: pb_api::ListNervousSystemFunctionsResponse) -> Self {
        Self {
            functions: item.functions.into_iter().map(|x| x.into()).collect(),
            reserved_ids: item.reserved_ids,
        }
    }
}

impl From<pb::SetMode> for pb_api::SetMode {
    fn from(item: pb::SetMode) -> Self {
        Self { mode: item.mode }
    }
}
impl From<pb_api::SetMode> for pb::SetMode {
    fn from(item: pb_api::SetMode) -> Self {
        Self { mode: item.mode }
    }
}

impl From<pb::SetModeResponse> for pb_api::SetModeResponse {
    fn from(_: pb::SetModeResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::SetModeResponse> for pb::SetModeResponse {
    fn from(_: pb_api::SetModeResponse) -> Self {
        Self {}
    }
}

impl From<pb::GetMode> for pb_api::GetMode {
    fn from(_: pb::GetMode) -> Self {
        Self {}
    }
}
impl From<pb_api::GetMode> for pb::GetMode {
    fn from(_: pb_api::GetMode) -> Self {
        Self {}
    }
}

impl From<pb::GetModeResponse> for pb_api::GetModeResponse {
    fn from(item: pb::GetModeResponse) -> Self {
        Self { mode: item.mode }
    }
}
impl From<pb_api::GetModeResponse> for pb::GetModeResponse {
    fn from(item: pb_api::GetModeResponse) -> Self {
        Self { mode: item.mode }
    }
}

impl From<pb::ClaimSwapNeuronsRequest> for pb_api::ClaimSwapNeuronsRequest {
    fn from(item: pb::ClaimSwapNeuronsRequest) -> Self {
        Self {
            neuron_recipes: item.neuron_recipes.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ClaimSwapNeuronsRequest> for pb::ClaimSwapNeuronsRequest {
    fn from(item: pb_api::ClaimSwapNeuronsRequest) -> Self {
        Self {
            neuron_recipes: item.neuron_recipes.map(|x| x.into()),
        }
    }
}

impl From<pb::claim_swap_neurons_request::NeuronRecipe>
    for pb_api::claim_swap_neurons_request::NeuronRecipe
{
    fn from(item: pb::claim_swap_neurons_request::NeuronRecipe) -> Self {
        Self {
            controller: item.controller,
            neuron_id: item.neuron_id.map(|x| x.into()),
            stake_e8s: item.stake_e8s,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            followees: item.followees.map(|x| x.into()),
            participant: item.participant.map(|x| x.into()),
        }
    }
}
impl From<pb_api::claim_swap_neurons_request::NeuronRecipe>
    for pb::claim_swap_neurons_request::NeuronRecipe
{
    fn from(item: pb_api::claim_swap_neurons_request::NeuronRecipe) -> Self {
        Self {
            controller: item.controller,
            neuron_id: item.neuron_id.map(|x| x.into()),
            stake_e8s: item.stake_e8s,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            followees: item.followees.map(|x| x.into()),
            participant: item.participant.map(|x| x.into()),
        }
    }
}

impl From<pb::claim_swap_neurons_request::neuron_recipe::NeuronsFund>
    for pb_api::claim_swap_neurons_request::neuron_recipe::NeuronsFund
{
    fn from(item: pb::claim_swap_neurons_request::neuron_recipe::NeuronsFund) -> Self {
        Self {
            nns_neuron_id: item.nns_neuron_id,
            nns_neuron_controller: item.nns_neuron_controller,
            nns_neuron_hotkeys: item.nns_neuron_hotkeys,
        }
    }
}
impl From<pb_api::claim_swap_neurons_request::neuron_recipe::NeuronsFund>
    for pb::claim_swap_neurons_request::neuron_recipe::NeuronsFund
{
    fn from(item: pb_api::claim_swap_neurons_request::neuron_recipe::NeuronsFund) -> Self {
        Self {
            nns_neuron_id: item.nns_neuron_id,
            nns_neuron_controller: item.nns_neuron_controller,
            nns_neuron_hotkeys: item.nns_neuron_hotkeys,
        }
    }
}

impl From<pb::claim_swap_neurons_request::neuron_recipe::Direct>
    for pb_api::claim_swap_neurons_request::neuron_recipe::Direct
{
    fn from(_: pb::claim_swap_neurons_request::neuron_recipe::Direct) -> Self {
        Self {}
    }
}
impl From<pb_api::claim_swap_neurons_request::neuron_recipe::Direct>
    for pb::claim_swap_neurons_request::neuron_recipe::Direct
{
    fn from(_: pb_api::claim_swap_neurons_request::neuron_recipe::Direct) -> Self {
        Self {}
    }
}

impl From<pb::claim_swap_neurons_request::neuron_recipe::Participant>
    for pb_api::claim_swap_neurons_request::neuron_recipe::Participant
{
    fn from(item: pb::claim_swap_neurons_request::neuron_recipe::Participant) -> Self {
        match item {
            pb::claim_swap_neurons_request::neuron_recipe::Participant::Direct(v) => {
                pb_api::claim_swap_neurons_request::neuron_recipe::Participant::Direct(v.into())
            }
            pb::claim_swap_neurons_request::neuron_recipe::Participant::NeuronsFund(v) => {
                pb_api::claim_swap_neurons_request::neuron_recipe::Participant::NeuronsFund(
                    v.into(),
                )
            }
        }
    }
}
impl From<pb_api::claim_swap_neurons_request::neuron_recipe::Participant>
    for pb::claim_swap_neurons_request::neuron_recipe::Participant
{
    fn from(item: pb_api::claim_swap_neurons_request::neuron_recipe::Participant) -> Self {
        match item {
            pb_api::claim_swap_neurons_request::neuron_recipe::Participant::Direct(v) => {
                pb::claim_swap_neurons_request::neuron_recipe::Participant::Direct(v.into())
            }
            pb_api::claim_swap_neurons_request::neuron_recipe::Participant::NeuronsFund(v) => {
                pb::claim_swap_neurons_request::neuron_recipe::Participant::NeuronsFund(v.into())
            }
        }
    }
}

impl From<pb::claim_swap_neurons_request::NeuronRecipes>
    for pb_api::claim_swap_neurons_request::NeuronRecipes
{
    fn from(item: pb::claim_swap_neurons_request::NeuronRecipes) -> Self {
        Self {
            neuron_recipes: item.neuron_recipes.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::claim_swap_neurons_request::NeuronRecipes>
    for pb::claim_swap_neurons_request::NeuronRecipes
{
    fn from(item: pb_api::claim_swap_neurons_request::NeuronRecipes) -> Self {
        Self {
            neuron_recipes: item.neuron_recipes.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ClaimSwapNeuronsResponse> for pb_api::ClaimSwapNeuronsResponse {
    fn from(item: pb::ClaimSwapNeuronsResponse) -> Self {
        Self {
            claim_swap_neurons_result: item.claim_swap_neurons_result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ClaimSwapNeuronsResponse> for pb::ClaimSwapNeuronsResponse {
    fn from(item: pb_api::ClaimSwapNeuronsResponse) -> Self {
        Self {
            claim_swap_neurons_result: item.claim_swap_neurons_result.map(|x| x.into()),
        }
    }
}

impl From<pb::claim_swap_neurons_response::ClaimedSwapNeurons>
    for pb_api::claim_swap_neurons_response::ClaimedSwapNeurons
{
    fn from(item: pb::claim_swap_neurons_response::ClaimedSwapNeurons) -> Self {
        Self {
            swap_neurons: item.swap_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::claim_swap_neurons_response::ClaimedSwapNeurons>
    for pb::claim_swap_neurons_response::ClaimedSwapNeurons
{
    fn from(item: pb_api::claim_swap_neurons_response::ClaimedSwapNeurons) -> Self {
        Self {
            swap_neurons: item.swap_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::claim_swap_neurons_response::SwapNeuron>
    for pb_api::claim_swap_neurons_response::SwapNeuron
{
    fn from(item: pb::claim_swap_neurons_response::SwapNeuron) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            status: item.status,
        }
    }
}
impl From<pb_api::claim_swap_neurons_response::SwapNeuron>
    for pb::claim_swap_neurons_response::SwapNeuron
{
    fn from(item: pb_api::claim_swap_neurons_response::SwapNeuron) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            status: item.status,
        }
    }
}

impl From<pb::claim_swap_neurons_response::ClaimSwapNeuronsResult>
    for pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult
{
    fn from(item: pb::claim_swap_neurons_response::ClaimSwapNeuronsResult) -> Self {
        match item {
            pb::claim_swap_neurons_response::ClaimSwapNeuronsResult::Ok(v) => {
                pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult::Ok(v.into())
            }
            pb::claim_swap_neurons_response::ClaimSwapNeuronsResult::Err(v) => {
                pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult::Err(v)
            }
        }
    }
}
impl From<pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult>
    for pb::claim_swap_neurons_response::ClaimSwapNeuronsResult
{
    fn from(item: pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult) -> Self {
        match item {
            pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult::Ok(v) => {
                pb::claim_swap_neurons_response::ClaimSwapNeuronsResult::Ok(v.into())
            }
            pb_api::claim_swap_neurons_response::ClaimSwapNeuronsResult::Err(v) => {
                pb::claim_swap_neurons_response::ClaimSwapNeuronsResult::Err(v)
            }
        }
    }
}

impl From<pb::GetMaturityModulationRequest> for pb_api::GetMaturityModulationRequest {
    fn from(_: pb::GetMaturityModulationRequest) -> Self {
        Self {}
    }
}
impl From<pb_api::GetMaturityModulationRequest> for pb::GetMaturityModulationRequest {
    fn from(_: pb_api::GetMaturityModulationRequest) -> Self {
        Self {}
    }
}

impl From<pb::GetMaturityModulationResponse> for pb_api::GetMaturityModulationResponse {
    fn from(item: pb::GetMaturityModulationResponse) -> Self {
        Self {
            maturity_modulation: item.maturity_modulation.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetMaturityModulationResponse> for pb::GetMaturityModulationResponse {
    fn from(item: pb_api::GetMaturityModulationResponse) -> Self {
        Self {
            maturity_modulation: item.maturity_modulation.map(|x| x.into()),
        }
    }
}

impl From<pb::AddMaturityRequest> for pb_api::AddMaturityRequest {
    fn from(item: pb::AddMaturityRequest) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
        }
    }
}
impl From<pb_api::AddMaturityRequest> for pb::AddMaturityRequest {
    fn from(item: pb_api::AddMaturityRequest) -> Self {
        Self {
            id: item.id.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
        }
    }
}

impl From<pb::AddMaturityResponse> for pb_api::AddMaturityResponse {
    fn from(item: pb::AddMaturityResponse) -> Self {
        Self {
            new_maturity_e8s: item.new_maturity_e8s,
        }
    }
}
impl From<pb_api::AddMaturityResponse> for pb::AddMaturityResponse {
    fn from(item: pb_api::AddMaturityResponse) -> Self {
        Self {
            new_maturity_e8s: item.new_maturity_e8s,
        }
    }
}

impl From<pb::AdvanceTargetVersionRequest> for pb_api::AdvanceTargetVersionRequest {
    fn from(item: pb::AdvanceTargetVersionRequest) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
        }
    }
}
impl From<pb_api::AdvanceTargetVersionRequest> for pb::AdvanceTargetVersionRequest {
    fn from(item: pb_api::AdvanceTargetVersionRequest) -> Self {
        Self {
            target_version: item.target_version.map(|x| x.into()),
        }
    }
}

impl From<pb::AdvanceTargetVersionResponse> for pb_api::AdvanceTargetVersionResponse {
    fn from(_: pb::AdvanceTargetVersionResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::AdvanceTargetVersionResponse> for pb::AdvanceTargetVersionResponse {
    fn from(_: pb_api::AdvanceTargetVersionResponse) -> Self {
        Self {}
    }
}

impl From<pb::UpgradeJournalEntry> for pb_api::UpgradeJournalEntry {
    fn from(item: pb::UpgradeJournalEntry) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            event: item.event.map(|x| x.into()),
        }
    }
}
impl From<pb_api::UpgradeJournalEntry> for pb::UpgradeJournalEntry {
    fn from(item: pb_api::UpgradeJournalEntry) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            event: item.event.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::UpgradeStepsRefreshed>
    for pb_api::upgrade_journal_entry::UpgradeStepsRefreshed
{
    fn from(item: pb::upgrade_journal_entry::UpgradeStepsRefreshed) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::UpgradeStepsRefreshed>
    for pb::upgrade_journal_entry::UpgradeStepsRefreshed
{
    fn from(item: pb_api::upgrade_journal_entry::UpgradeStepsRefreshed) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::UpgradeStepsReset>
    for pb_api::upgrade_journal_entry::UpgradeStepsReset
{
    fn from(item: pb::upgrade_journal_entry::UpgradeStepsReset) -> Self {
        Self {
            human_readable: item.human_readable,
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::UpgradeStepsReset>
    for pb::upgrade_journal_entry::UpgradeStepsReset
{
    fn from(item: pb_api::upgrade_journal_entry::UpgradeStepsReset) -> Self {
        Self {
            human_readable: item.human_readable,
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::TargetVersionSet>
    for pb_api::upgrade_journal_entry::TargetVersionSet
{
    fn from(item: pb::upgrade_journal_entry::TargetVersionSet) -> Self {
        Self {
            old_target_version: item.old_target_version.map(|x| x.into()),
            new_target_version: item.new_target_version.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::TargetVersionSet>
    for pb::upgrade_journal_entry::TargetVersionSet
{
    fn from(item: pb_api::upgrade_journal_entry::TargetVersionSet) -> Self {
        Self {
            old_target_version: item.old_target_version.map(|x| x.into()),
            new_target_version: item.new_target_version.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::TargetVersionReset>
    for pb_api::upgrade_journal_entry::TargetVersionReset
{
    fn from(item: pb::upgrade_journal_entry::TargetVersionReset) -> Self {
        Self {
            old_target_version: item.old_target_version.map(|x| x.into()),
            new_target_version: item.new_target_version.map(|x| x.into()),
            human_readable: item.human_readable,
        }
    }
}
impl From<pb_api::upgrade_journal_entry::TargetVersionReset>
    for pb::upgrade_journal_entry::TargetVersionReset
{
    fn from(item: pb_api::upgrade_journal_entry::TargetVersionReset) -> Self {
        Self {
            old_target_version: item.old_target_version.map(|x| x.into()),
            new_target_version: item.new_target_version.map(|x| x.into()),
            human_readable: item.human_readable,
        }
    }
}

impl From<pb::upgrade_journal_entry::UpgradeStarted>
    for pb_api::upgrade_journal_entry::UpgradeStarted
{
    fn from(item: pb::upgrade_journal_entry::UpgradeStarted) -> Self {
        Self {
            current_version: item.current_version.map(|x| x.into()),
            expected_version: item.expected_version.map(|x| x.into()),
            reason: item.reason.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::UpgradeStarted>
    for pb::upgrade_journal_entry::UpgradeStarted
{
    fn from(item: pb_api::upgrade_journal_entry::UpgradeStarted) -> Self {
        Self {
            current_version: item.current_version.map(|x| x.into()),
            expected_version: item.expected_version.map(|x| x.into()),
            reason: item.reason.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::upgrade_started::Reason>
    for pb_api::upgrade_journal_entry::upgrade_started::Reason
{
    fn from(item: pb::upgrade_journal_entry::upgrade_started::Reason) -> Self {
        match item {
            pb::upgrade_journal_entry::upgrade_started::Reason::UpgradeSnsToNextVersionProposal(v) => pb_api::upgrade_journal_entry::upgrade_started::Reason::UpgradeSnsToNextVersionProposal(v.into()),
            pb::upgrade_journal_entry::upgrade_started::Reason::BehindTargetVersion(v) => pb_api::upgrade_journal_entry::upgrade_started::Reason::BehindTargetVersion(v.into())
        }
    }
}
impl From<pb_api::upgrade_journal_entry::upgrade_started::Reason>
    for pb::upgrade_journal_entry::upgrade_started::Reason
{
    fn from(item: pb_api::upgrade_journal_entry::upgrade_started::Reason) -> Self {
        match item {
            pb_api::upgrade_journal_entry::upgrade_started::Reason::UpgradeSnsToNextVersionProposal(v) => pb::upgrade_journal_entry::upgrade_started::Reason::UpgradeSnsToNextVersionProposal(v.into()),
            pb_api::upgrade_journal_entry::upgrade_started::Reason::BehindTargetVersion(v) => pb::upgrade_journal_entry::upgrade_started::Reason::BehindTargetVersion(v.into())
        }
    }
}

impl From<pb::upgrade_journal_entry::UpgradeOutcome>
    for pb_api::upgrade_journal_entry::UpgradeOutcome
{
    fn from(item: pb::upgrade_journal_entry::UpgradeOutcome) -> Self {
        Self {
            human_readable: item.human_readable,
            status: item.status.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::UpgradeOutcome>
    for pb::upgrade_journal_entry::UpgradeOutcome
{
    fn from(item: pb_api::upgrade_journal_entry::UpgradeOutcome) -> Self {
        Self {
            human_readable: item.human_readable,
            status: item.status.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::upgrade_outcome::InvalidState>
    for pb_api::upgrade_journal_entry::upgrade_outcome::InvalidState
{
    fn from(item: pb::upgrade_journal_entry::upgrade_outcome::InvalidState) -> Self {
        Self {
            version: item.version.map(|x| x.into()),
        }
    }
}
impl From<pb_api::upgrade_journal_entry::upgrade_outcome::InvalidState>
    for pb::upgrade_journal_entry::upgrade_outcome::InvalidState
{
    fn from(item: pb_api::upgrade_journal_entry::upgrade_outcome::InvalidState) -> Self {
        Self {
            version: item.version.map(|x| x.into()),
        }
    }
}

impl From<pb::upgrade_journal_entry::upgrade_outcome::Status>
    for pb_api::upgrade_journal_entry::upgrade_outcome::Status
{
    fn from(item: pb::upgrade_journal_entry::upgrade_outcome::Status) -> Self {
        match item {
            pb::upgrade_journal_entry::upgrade_outcome::Status::Success(v) => {
                pb_api::upgrade_journal_entry::upgrade_outcome::Status::Success(v.into())
            }
            pb::upgrade_journal_entry::upgrade_outcome::Status::Timeout(v) => {
                pb_api::upgrade_journal_entry::upgrade_outcome::Status::Timeout(v.into())
            }
            pb::upgrade_journal_entry::upgrade_outcome::Status::InvalidState(v) => {
                pb_api::upgrade_journal_entry::upgrade_outcome::Status::InvalidState(v.into())
            }
            pb::upgrade_journal_entry::upgrade_outcome::Status::ExternalFailure(v) => {
                pb_api::upgrade_journal_entry::upgrade_outcome::Status::ExternalFailure(v.into())
            }
        }
    }
}
impl From<pb_api::upgrade_journal_entry::upgrade_outcome::Status>
    for pb::upgrade_journal_entry::upgrade_outcome::Status
{
    fn from(item: pb_api::upgrade_journal_entry::upgrade_outcome::Status) -> Self {
        match item {
            pb_api::upgrade_journal_entry::upgrade_outcome::Status::Success(v) => {
                pb::upgrade_journal_entry::upgrade_outcome::Status::Success(v.into())
            }
            pb_api::upgrade_journal_entry::upgrade_outcome::Status::Timeout(v) => {
                pb::upgrade_journal_entry::upgrade_outcome::Status::Timeout(v.into())
            }
            pb_api::upgrade_journal_entry::upgrade_outcome::Status::InvalidState(v) => {
                pb::upgrade_journal_entry::upgrade_outcome::Status::InvalidState(v.into())
            }
            pb_api::upgrade_journal_entry::upgrade_outcome::Status::ExternalFailure(v) => {
                pb::upgrade_journal_entry::upgrade_outcome::Status::ExternalFailure(v.into())
            }
        }
    }
}

impl From<pb::upgrade_journal_entry::Event> for pb_api::upgrade_journal_entry::Event {
    fn from(item: pb::upgrade_journal_entry::Event) -> Self {
        match item {
            pb::upgrade_journal_entry::Event::UpgradeStepsRefreshed(v) => {
                pb_api::upgrade_journal_entry::Event::UpgradeStepsRefreshed(v.into())
            }
            pb::upgrade_journal_entry::Event::UpgradeStepsReset(v) => {
                pb_api::upgrade_journal_entry::Event::UpgradeStepsReset(v.into())
            }
            pb::upgrade_journal_entry::Event::TargetVersionSet(v) => {
                pb_api::upgrade_journal_entry::Event::TargetVersionSet(v.into())
            }
            pb::upgrade_journal_entry::Event::TargetVersionReset(v) => {
                pb_api::upgrade_journal_entry::Event::TargetVersionReset(v.into())
            }
            pb::upgrade_journal_entry::Event::UpgradeStarted(v) => {
                pb_api::upgrade_journal_entry::Event::UpgradeStarted(v.into())
            }
            pb::upgrade_journal_entry::Event::UpgradeOutcome(v) => {
                pb_api::upgrade_journal_entry::Event::UpgradeOutcome(v.into())
            }
        }
    }
}
impl From<pb_api::upgrade_journal_entry::Event> for pb::upgrade_journal_entry::Event {
    fn from(item: pb_api::upgrade_journal_entry::Event) -> Self {
        match item {
            pb_api::upgrade_journal_entry::Event::UpgradeStepsRefreshed(v) => {
                pb::upgrade_journal_entry::Event::UpgradeStepsRefreshed(v.into())
            }
            pb_api::upgrade_journal_entry::Event::UpgradeStepsReset(v) => {
                pb::upgrade_journal_entry::Event::UpgradeStepsReset(v.into())
            }
            pb_api::upgrade_journal_entry::Event::TargetVersionSet(v) => {
                pb::upgrade_journal_entry::Event::TargetVersionSet(v.into())
            }
            pb_api::upgrade_journal_entry::Event::TargetVersionReset(v) => {
                pb::upgrade_journal_entry::Event::TargetVersionReset(v.into())
            }
            pb_api::upgrade_journal_entry::Event::UpgradeStarted(v) => {
                pb::upgrade_journal_entry::Event::UpgradeStarted(v.into())
            }
            pb_api::upgrade_journal_entry::Event::UpgradeOutcome(v) => {
                pb::upgrade_journal_entry::Event::UpgradeOutcome(v.into())
            }
        }
    }
}

impl From<pb::UpgradeJournal> for pb_api::UpgradeJournal {
    fn from(item: pb::UpgradeJournal) -> Self {
        Self {
            entries: item.entries.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::UpgradeJournal> for pb::UpgradeJournal {
    fn from(item: pb_api::UpgradeJournal) -> Self {
        Self {
            entries: item.entries.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::GetUpgradeJournalRequest> for pb_api::GetUpgradeJournalRequest {
    fn from(request: pb::GetUpgradeJournalRequest) -> Self {
        let pb::GetUpgradeJournalRequest {
            max_entries,
            start_index,
        } = request;
        Self {
            max_entries,
            start_index,
        }
    }
}
impl From<pb_api::GetUpgradeJournalRequest> for pb::GetUpgradeJournalRequest {
    fn from(request: pb_api::GetUpgradeJournalRequest) -> Self {
        let pb_api::GetUpgradeJournalRequest {
            max_entries,
            start_index,
        } = request;
        Self {
            max_entries,
            start_index,
        }
    }
}

impl From<pb::GetUpgradeJournalResponse> for pb_api::GetUpgradeJournalResponse {
    fn from(item: pb::GetUpgradeJournalResponse) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
            response_timestamp_seconds: item.response_timestamp_seconds,
            target_version: item.target_version.map(|x| x.into()),
            deployed_version: item.deployed_version.map(|x| x.into()),
            upgrade_journal: item.upgrade_journal.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetUpgradeJournalResponse> for pb::GetUpgradeJournalResponse {
    fn from(item: pb_api::GetUpgradeJournalResponse) -> Self {
        Self {
            upgrade_steps: item.upgrade_steps.map(|x| x.into()),
            response_timestamp_seconds: item.response_timestamp_seconds,
            target_version: item.target_version.map(|x| x.into()),
            deployed_version: item.deployed_version.map(|x| x.into()),
            upgrade_journal: item.upgrade_journal.map(|x| x.into()),
        }
    }
}

impl From<pb::MintTokensRequest> for pb_api::MintTokensRequest {
    fn from(item: pb::MintTokensRequest) -> Self {
        Self {
            recipient: item.recipient.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
        }
    }
}
impl From<pb_api::MintTokensRequest> for pb::MintTokensRequest {
    fn from(item: pb_api::MintTokensRequest) -> Self {
        Self {
            recipient: item.recipient.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
        }
    }
}

impl From<pb::MintTokensResponse> for pb_api::MintTokensResponse {
    fn from(_: pb::MintTokensResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::MintTokensResponse> for pb::MintTokensResponse {
    fn from(_: pb_api::MintTokensResponse) -> Self {
        Self {}
    }
}

impl From<pb::Subaccount> for pb_api::Subaccount {
    fn from(item: pb::Subaccount) -> Self {
        Self {
            subaccount: item.subaccount,
        }
    }
}
impl From<pb_api::Subaccount> for pb::Subaccount {
    fn from(item: pb_api::Subaccount) -> Self {
        Self {
            subaccount: item.subaccount,
        }
    }
}

impl From<pb::Account> for pb_api::Account {
    fn from(item: pb::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Account> for pb::Account {
    fn from(item: pb_api::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| x.into()),
        }
    }
}

impl From<pb::NeuronPermissionType> for pb_api::NeuronPermissionType {
    fn from(item: pb::NeuronPermissionType) -> Self {
        match item {
            pb::NeuronPermissionType::Unspecified => pb_api::NeuronPermissionType::Unspecified,
            pb::NeuronPermissionType::ConfigureDissolveState => {
                pb_api::NeuronPermissionType::ConfigureDissolveState
            }
            pb::NeuronPermissionType::ManagePrincipals => {
                pb_api::NeuronPermissionType::ManagePrincipals
            }
            pb::NeuronPermissionType::SubmitProposal => {
                pb_api::NeuronPermissionType::SubmitProposal
            }
            pb::NeuronPermissionType::Vote => pb_api::NeuronPermissionType::Vote,
            pb::NeuronPermissionType::Disburse => pb_api::NeuronPermissionType::Disburse,
            pb::NeuronPermissionType::Split => pb_api::NeuronPermissionType::Split,
            pb::NeuronPermissionType::MergeMaturity => pb_api::NeuronPermissionType::MergeMaturity,
            pb::NeuronPermissionType::DisburseMaturity => {
                pb_api::NeuronPermissionType::DisburseMaturity
            }
            pb::NeuronPermissionType::StakeMaturity => pb_api::NeuronPermissionType::StakeMaturity,
            pb::NeuronPermissionType::ManageVotingPermission => {
                pb_api::NeuronPermissionType::ManageVotingPermission
            }
        }
    }
}
impl From<pb_api::NeuronPermissionType> for pb::NeuronPermissionType {
    fn from(item: pb_api::NeuronPermissionType) -> Self {
        match item {
            pb_api::NeuronPermissionType::Unspecified => pb::NeuronPermissionType::Unspecified,
            pb_api::NeuronPermissionType::ConfigureDissolveState => {
                pb::NeuronPermissionType::ConfigureDissolveState
            }
            pb_api::NeuronPermissionType::ManagePrincipals => {
                pb::NeuronPermissionType::ManagePrincipals
            }
            pb_api::NeuronPermissionType::SubmitProposal => {
                pb::NeuronPermissionType::SubmitProposal
            }
            pb_api::NeuronPermissionType::Vote => pb::NeuronPermissionType::Vote,
            pb_api::NeuronPermissionType::Disburse => pb::NeuronPermissionType::Disburse,
            pb_api::NeuronPermissionType::Split => pb::NeuronPermissionType::Split,
            pb_api::NeuronPermissionType::MergeMaturity => pb::NeuronPermissionType::MergeMaturity,
            pb_api::NeuronPermissionType::DisburseMaturity => {
                pb::NeuronPermissionType::DisburseMaturity
            }
            pb_api::NeuronPermissionType::StakeMaturity => pb::NeuronPermissionType::StakeMaturity,
            pb_api::NeuronPermissionType::ManageVotingPermission => {
                pb::NeuronPermissionType::ManageVotingPermission
            }
        }
    }
}

impl From<pb::Vote> for pb_api::Vote {
    fn from(item: pb::Vote) -> Self {
        match item {
            pb::Vote::Unspecified => pb_api::Vote::Unspecified,
            pb::Vote::Yes => pb_api::Vote::Yes,
            pb::Vote::No => pb_api::Vote::No,
        }
    }
}
impl From<pb_api::Vote> for pb::Vote {
    fn from(item: pb_api::Vote) -> Self {
        match item {
            pb_api::Vote::Unspecified => pb::Vote::Unspecified,
            pb_api::Vote::Yes => pb::Vote::Yes,
            pb_api::Vote::No => pb::Vote::No,
        }
    }
}

impl From<pb::LogVisibility> for pb_api::LogVisibility {
    fn from(item: pb::LogVisibility) -> Self {
        match item {
            pb::LogVisibility::Unspecified => pb_api::LogVisibility::Unspecified,
            pb::LogVisibility::Controllers => pb_api::LogVisibility::Controllers,
            pb::LogVisibility::Public => pb_api::LogVisibility::Public,
        }
    }
}
impl From<pb_api::LogVisibility> for pb::LogVisibility {
    fn from(item: pb_api::LogVisibility) -> Self {
        match item {
            pb_api::LogVisibility::Unspecified => pb::LogVisibility::Unspecified,
            pb_api::LogVisibility::Controllers => pb::LogVisibility::Controllers,
            pb_api::LogVisibility::Public => pb::LogVisibility::Public,
        }
    }
}

impl From<pb::ProposalDecisionStatus> for pb_api::ProposalDecisionStatus {
    fn from(item: pb::ProposalDecisionStatus) -> Self {
        match item {
            pb::ProposalDecisionStatus::Unspecified => pb_api::ProposalDecisionStatus::Unspecified,
            pb::ProposalDecisionStatus::Open => pb_api::ProposalDecisionStatus::Open,
            pb::ProposalDecisionStatus::Rejected => pb_api::ProposalDecisionStatus::Rejected,
            pb::ProposalDecisionStatus::Adopted => pb_api::ProposalDecisionStatus::Adopted,
            pb::ProposalDecisionStatus::Executed => pb_api::ProposalDecisionStatus::Executed,
            pb::ProposalDecisionStatus::Failed => pb_api::ProposalDecisionStatus::Failed,
        }
    }
}
impl From<pb_api::ProposalDecisionStatus> for pb::ProposalDecisionStatus {
    fn from(item: pb_api::ProposalDecisionStatus) -> Self {
        match item {
            pb_api::ProposalDecisionStatus::Unspecified => pb::ProposalDecisionStatus::Unspecified,
            pb_api::ProposalDecisionStatus::Open => pb::ProposalDecisionStatus::Open,
            pb_api::ProposalDecisionStatus::Rejected => pb::ProposalDecisionStatus::Rejected,
            pb_api::ProposalDecisionStatus::Adopted => pb::ProposalDecisionStatus::Adopted,
            pb_api::ProposalDecisionStatus::Executed => pb::ProposalDecisionStatus::Executed,
            pb_api::ProposalDecisionStatus::Failed => pb::ProposalDecisionStatus::Failed,
        }
    }
}

impl From<pb::ProposalRewardStatus> for pb_api::ProposalRewardStatus {
    fn from(item: pb::ProposalRewardStatus) -> Self {
        match item {
            pb::ProposalRewardStatus::Unspecified => pb_api::ProposalRewardStatus::Unspecified,
            pb::ProposalRewardStatus::AcceptVotes => pb_api::ProposalRewardStatus::AcceptVotes,
            pb::ProposalRewardStatus::ReadyToSettle => pb_api::ProposalRewardStatus::ReadyToSettle,
            pb::ProposalRewardStatus::Settled => pb_api::ProposalRewardStatus::Settled,
        }
    }
}
impl From<pb_api::ProposalRewardStatus> for pb::ProposalRewardStatus {
    fn from(item: pb_api::ProposalRewardStatus) -> Self {
        match item {
            pb_api::ProposalRewardStatus::Unspecified => pb::ProposalRewardStatus::Unspecified,
            pb_api::ProposalRewardStatus::AcceptVotes => pb::ProposalRewardStatus::AcceptVotes,
            pb_api::ProposalRewardStatus::ReadyToSettle => pb::ProposalRewardStatus::ReadyToSettle,
            pb_api::ProposalRewardStatus::Settled => pb::ProposalRewardStatus::Settled,
        }
    }
}

impl From<pb::ClaimedSwapNeuronStatus> for pb_api::ClaimedSwapNeuronStatus {
    fn from(item: pb::ClaimedSwapNeuronStatus) -> Self {
        match item {
            pb::ClaimedSwapNeuronStatus::Unspecified => {
                pb_api::ClaimedSwapNeuronStatus::Unspecified
            }
            pb::ClaimedSwapNeuronStatus::Success => pb_api::ClaimedSwapNeuronStatus::Success,
            pb::ClaimedSwapNeuronStatus::Invalid => pb_api::ClaimedSwapNeuronStatus::Invalid,
            pb::ClaimedSwapNeuronStatus::AlreadyExists => {
                pb_api::ClaimedSwapNeuronStatus::AlreadyExists
            }
            pb::ClaimedSwapNeuronStatus::MemoryExhausted => {
                pb_api::ClaimedSwapNeuronStatus::MemoryExhausted
            }
        }
    }
}
impl From<pb_api::ClaimedSwapNeuronStatus> for pb::ClaimedSwapNeuronStatus {
    fn from(item: pb_api::ClaimedSwapNeuronStatus) -> Self {
        match item {
            pb_api::ClaimedSwapNeuronStatus::Unspecified => {
                pb::ClaimedSwapNeuronStatus::Unspecified
            }
            pb_api::ClaimedSwapNeuronStatus::Success => pb::ClaimedSwapNeuronStatus::Success,
            pb_api::ClaimedSwapNeuronStatus::Invalid => pb::ClaimedSwapNeuronStatus::Invalid,
            pb_api::ClaimedSwapNeuronStatus::AlreadyExists => {
                pb::ClaimedSwapNeuronStatus::AlreadyExists
            }
            pb_api::ClaimedSwapNeuronStatus::MemoryExhausted => {
                pb::ClaimedSwapNeuronStatus::MemoryExhausted
            }
        }
    }
}

impl From<pb::ClaimSwapNeuronsError> for pb_api::ClaimSwapNeuronsError {
    fn from(item: pb::ClaimSwapNeuronsError) -> Self {
        match item {
            pb::ClaimSwapNeuronsError::Unspecified => pb_api::ClaimSwapNeuronsError::Unspecified,
            pb::ClaimSwapNeuronsError::Unauthorized => pb_api::ClaimSwapNeuronsError::Unauthorized,
            pb::ClaimSwapNeuronsError::Internal => pb_api::ClaimSwapNeuronsError::Internal,
        }
    }
}
impl From<pb_api::ClaimSwapNeuronsError> for pb::ClaimSwapNeuronsError {
    fn from(item: pb_api::ClaimSwapNeuronsError) -> Self {
        match item {
            pb_api::ClaimSwapNeuronsError::Unspecified => pb::ClaimSwapNeuronsError::Unspecified,
            pb_api::ClaimSwapNeuronsError::Unauthorized => pb::ClaimSwapNeuronsError::Unauthorized,
            pb_api::ClaimSwapNeuronsError::Internal => pb::ClaimSwapNeuronsError::Internal,
        }
    }
}
