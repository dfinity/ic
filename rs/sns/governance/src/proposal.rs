use crate::sns_upgrade::get_proposal_id_that_added_wasm;
use crate::{
    canister_control::perform_execute_generic_nervous_system_function_validate_and_render_call,
    governance::{
        bytes_to_subaccount, log_prefix, NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER,
        TREASURY_SUBACCOUNT_NONCE,
    },
    logs::{ERROR, INFO},
    pb::v1::{
        governance::{SnsMetadata, Version},
        governance_error::ErrorType,
        nervous_system_function::{FunctionType, GenericNervousSystemFunction},
        proposal,
        proposal::Action,
        proposal_data::{
            self, ActionAuxiliary as ActionAuxiliaryPb, MintSnsTokensActionAuxiliary,
            TransferSnsTreasuryFundsActionAuxiliary,
        },
        transfer_sns_treasury_funds::TransferFrom,
        DeregisterDappCanisters, ExecuteGenericNervousSystemFunction, Governance, GovernanceError,
        LogVisibility, ManageDappCanisterSettings, ManageLedgerParameters, ManageSnsMetadata,
        MintSnsTokens, Motion, NervousSystemFunction, NervousSystemParameters, Proposal,
        ProposalData, ProposalDecisionStatus, ProposalId, ProposalRewardStatus,
        RegisterDappCanisters, Tally, TransferSnsTreasuryFunds, UpgradeSnsControlledCanister,
        UpgradeSnsToNextVersion, Valuation as ValuationPb, Vote,
    },
    sns_upgrade::{get_upgrade_params, UpgradeSnsParams},
    types::Environment,
    validate_chars_count, validate_len, validate_required_field,
};
use candid::Principal;
use dfn_core::api::CanisterId;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common::{
    denominations_to_tokens, i2d, ledger::compute_distribution_subaccount_bytes, ledger_validation,
    DEFAULT_TRANSFER_FEE, E8, ONE_DAY_SECONDS,
};
use ic_nervous_system_proto::pb::v1::Percentage;
use ic_protobuf::types::v1::CanisterInstallMode;
use ic_sns_governance_proposals_amount_total_limit::{
    // TODO(NNS1-2982): Uncomment. mint_sns_tokens_7_day_total_upper_bound_tokens,
    transfer_sns_treasury_funds_7_day_total_upper_bound_tokens,
};
use ic_sns_governance_token_valuation::{Token, Valuation};
use icp_ledger::DEFAULT_TRANSFER_FEE as NNS_DEFAULT_TRANSFER_FEE;
use icrc_ledger_types::icrc1::account::Account;
use rust_decimal::Decimal;
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
    fmt::Write,
};

/// The maximum number of bytes in an SNS proposal's title.
pub const PROPOSAL_TITLE_BYTES_MAX: usize = 256;
/// The maximum number of bytes in an SNS proposal's summary.
pub const PROPOSAL_SUMMARY_BYTES_MAX: usize = 30000;
/// The maximum number of bytes in an SNS proposal's URL.
pub const PROPOSAL_URL_CHAR_MAX: usize = 2048;
/// The maximum number of bytes in an SNS motion proposal's motion_text.
pub const PROPOSAL_MOTION_TEXT_BYTES_MAX: usize = 10000;

/// The maximum number of proposals returned by one call to the method `list_proposals`,
/// which can be used to list all proposals in a paginated fashion.
pub const MAX_LIST_PROPOSAL_RESULTS: u32 = 100;

/// The maximum number of unsettled proposals (proposals for which ballots are still stored).
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 700;

/// The maximum number of GenericNervousSystemFunctions the system allows.
pub const MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS: usize = 200_000;

/// The maximum number of dapps that can be managed in a single
/// proposal (RegisterDappCanisters, DeregisterDappCanisters,
/// or ManageDappCanisterSettings).
pub const MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL: usize = 1_000;

// The maximum number of ballots for a proposal that can be returned as part of list_proposals
// response.
pub const MAX_NUMBER_OF_BALLOTS_IN_LIST_PROPOSALS_RESPONSE: usize = 100;

/// What the name says: how long to hang onto TreasurySnsTreasuryTransfer proposals that were
/// successfully executed. (This is used by can_be_purged, and is generally used when calling
/// total_treasury_transfer_amount_tokens to construct the min_executed_timestamp_seconds argument).
pub const EXECUTED_TRANSFER_SNS_TREASURY_FUNDS_PROPOSAL_RETENTION_DURATION_SECONDS: u64 =
    7 * ONE_DAY_SECONDS;

/// Analogous to the previous constant; this one is for MintSnsTokens proposals. The value here is
/// the same, but we keep separate constants, because we consider this to be a coincidence.
pub const EXECUTED_MINT_SNS_TOKENS_PROPOSAL_RETENTION_DURATION_SECONDS: u64 = 7 * ONE_DAY_SECONDS;

/// The maximum message size for inter-canister calls to a different subnet
/// is 2MiB and thus we restrict the maximum joint size of the canister WASM
/// and argument to 2MB (2,000,000B) to leave some slack for Candid overhead
/// and a few constant-size fields (e.g., compute and memory allocation).
pub const MAX_INSTALL_CODE_WASM_AND_ARG_SIZE: usize = 2_000_000; // 2MB

impl Proposal {
    /// Returns whether a proposal is allowed to be submitted when
    /// the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        self.action
            .as_ref()
            .map_or(false, |a| a.allowed_when_resources_are_low())
    }

    /// Returns a clone of self, except that "large blob fields" are replaced
    /// with a (UTF-8 encoded) textual summary of their contents. See
    /// summarize_blob_field.
    pub(crate) fn limited_for_get_proposal(&self) -> Self {
        Self {
            title: self.title.clone(),
            summary: self.summary.clone(),
            url: self.url.clone(),
            action: self
                .action
                .as_ref()
                .map(|action| action.limited_for_get_proposal()),
        }
    }

    /// Returns a clone of self, except that "large blob fields" are cleared.
    pub(crate) fn limited_for_list_proposals(&self) -> Self {
        Self {
            title: self.title.clone(),
            summary: self.summary.clone(),
            url: self.url.clone(),
            action: self
                .action
                .as_ref()
                .map(|action| action.limited_for_list_proposals()),
        }
    }
}

pub(crate) fn get_action_auxiliary(
    proposals: &BTreeMap<u64, ProposalData>,
    proposal_id: ProposalId,
) -> Result<ActionAuxiliary, GovernanceError> {
    let proposal = proposals.get(&proposal_id.id);

    let proposal = match proposal {
        Some(ok) => ok,

        None => {
            return Err(GovernanceError::new_with_message(
                ErrorType::InconsistentInternalData,
                format!(
                    "Unable to find action_auxiliary for proposal {:?}, \
                     because proposal not found.",
                    proposal_id,
                ),
            ))
        }
    };

    let action_auxiliary = &proposal.action_auxiliary;

    ActionAuxiliary::try_from(action_auxiliary)
        // This is really not expected to happen.
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InconsistentInternalData,
                format!(
                    "Invalid action_auxiliary {:?} in ProposalData (id={:?}): {}",
                    action_auxiliary, proposal_id, err,
                ),
            )
        })
}

#[derive(Debug)]
pub(crate) enum ActionAuxiliary {
    TransferSnsTreasuryFunds(Valuation),
    MintSnsTokens(Valuation),
    None,
}

impl ActionAuxiliary {
    pub fn unwrap_transfer_sns_treasury_funds_or_err(self) -> Result<Valuation, GovernanceError> {
        match self {
            Self::TransferSnsTreasuryFunds(valuation) => Ok(valuation),

            wrong => Err(GovernanceError::new_with_message(
                ErrorType::InconsistentInternalData,
                format!(
                    "Missing supporting information. Specifically, \
                     no treasury valuation factors: {:#?}",
                    wrong,
                ),
            )),
        }
    }
}

/// Most proposal actions have no auxiliary data. In those cases, we would have
/// ActionAuxiliary::None, which corresponds to Option<ActionAuxiliaryPb>::None.
impl TryFrom<ActionAuxiliary> for Option<ActionAuxiliaryPb> {
    type Error = String;

    fn try_from(src: ActionAuxiliary) -> Result<Self, String> {
        let result = match src {
            ActionAuxiliary::None => None,

            ActionAuxiliary::TransferSnsTreasuryFunds(valuation) => {
                Some(ActionAuxiliaryPb::TransferSnsTreasuryFunds(
                    proposal_data::TransferSnsTreasuryFundsActionAuxiliary {
                        valuation: Some(ValuationPb::try_from(valuation)?),
                    },
                ))
            }

            ActionAuxiliary::MintSnsTokens(valuation) => Some(ActionAuxiliaryPb::MintSnsTokens(
                proposal_data::MintSnsTokensActionAuxiliary {
                    valuation: Some(ValuationPb::try_from(valuation)?),
                },
            )),
        };

        Ok(result)
    }
}

/// See the docstring of impl TryFrom<ActionAuxiliary> for Option<ActionAuxiliaryPb> (conversion in
/// the opposite direction).
impl TryFrom<&Option<ActionAuxiliaryPb>> for ActionAuxiliary {
    type Error = String;

    fn try_from(src: &Option<ActionAuxiliaryPb>) -> Result<ActionAuxiliary, String> {
        let result = match src {
            None => ActionAuxiliary::None,
            Some(ActionAuxiliaryPb::TransferSnsTreasuryFunds(action_auxiliary)) => {
                let TransferSnsTreasuryFundsActionAuxiliary { valuation } = action_auxiliary;

                let valuation = Valuation::try_from(valuation.as_ref().unwrap_or_default())
                    .map_err(|err| format!("Invalid ActionAuxiliaryPb {:?}: {}", src, err))?;

                ActionAuxiliary::TransferSnsTreasuryFunds(valuation)
            }
            Some(ActionAuxiliaryPb::MintSnsTokens(action_auxiliary)) => {
                let MintSnsTokensActionAuxiliary { valuation } = action_auxiliary;

                let valuation = Valuation::try_from(valuation.as_ref().unwrap_or_default())
                    .map_err(|err| format!("Invalid ActionAuxiliaryPb {:?}: {}", src, err))?;

                ActionAuxiliary::MintSnsTokens(valuation)
            }
        };

        Ok(result)
    }
}

/// Validates a proposal and returns a displayable text rendering of the payload
/// if the proposal is valid.
///
/// Takes in the GovernanceProto as to be able to validate against the current
/// state of governance.
pub(crate) async fn validate_and_render_proposal(
    proposal: &Proposal,
    env: &dyn Environment,
    governance_proto: &Governance,
    reserved_canister_targets: Vec<CanisterId>,
) -> Result<(String, Option<ActionAuxiliaryPb>), String> {
    let mut defects = Vec::new();

    let mut defects_push = |r| {
        if let Err(err) = r {
            defects.push(err);
        }
    };

    const NO_MIN: usize = 0;

    // Inspect (the length of) string fields.
    defects_push(validate_len(
        "title",
        &proposal.title,
        NO_MIN,
        PROPOSAL_TITLE_BYTES_MAX,
    ));
    defects_push(validate_len(
        "summary",
        &proposal.summary,
        NO_MIN,
        PROPOSAL_SUMMARY_BYTES_MAX,
    ));
    defects_push(validate_chars_count(
        "url",
        &proposal.url,
        NO_MIN,
        PROPOSAL_URL_CHAR_MAX,
    ));

    // Even if we already found defects, still validate as to return all the errors found.
    match validate_and_render_action(
        &proposal.action,
        env,
        governance_proto,
        reserved_canister_targets,
    )
    .await
    {
        Err(err) => {
            defects.push(err);
            Err(format!(
                "{} defects in Proposal:\n{}",
                defects.len(),
                defects.join("\n"),
            ))
        }
        Ok((rendering, action_auxiliary)) => {
            if !defects.is_empty() {
                Err(format!(
                    "{} defects in Proposal:\n{}",
                    defects.len(),
                    defects.join("\n"),
                ))
            } else {
                Ok((
                    rendering,
                    Option::<ActionAuxiliaryPb>::try_from(action_auxiliary)?,
                ))
            }
        }
    }
}

/// Validates and renders a proposal by calling the method that implements this logic for a given
/// proposal action.
pub(crate) async fn validate_and_render_action(
    action: &Option<proposal::Action>,
    env: &dyn Environment,
    governance_proto: &Governance,
    reserved_canister_targets: Vec<CanisterId>,
) -> Result<(String, ActionAuxiliary), String> {
    let current_parameters = governance_proto
        .parameters
        .as_ref()
        .expect("Governance must have NervousSystemParameters.");
    let existing_functions = &governance_proto.id_to_nervous_system_functions;
    let root_canister_id = governance_proto.root_canister_id_or_panic();

    let action = match action.as_ref() {
        None => return Err("No action was specified.".into()),
        Some(action) => action,
    };

    // Supporting auxiliary data. Not all of these are used in every case. This makes it very
    // transparent which parts of governance_proto are used by each of the action-specific
    // validators.
    let disallowed_target_canister_ids: HashSet<CanisterId> =
        reserved_canister_targets.clone().drain(..).collect();
    let sns_transfer_fee_e8s = governance_proto
        .parameters
        .as_ref()
        .and_then(|params| params.transaction_fee_e8s)
        .unwrap_or(DEFAULT_TRANSFER_FEE.get_e8s());
    let swap_canister_id = governance_proto.swap_canister_id_or_panic();
    let sns_ledger_canister_id = governance_proto.ledger_canister_id_or_panic();
    let proposals = governance_proto.proposals.values();

    match action {
        proposal::Action::Unspecified(_unspecified) => {
            Err("`unspecified` was used, but is not a valid Proposal action.".into())
        }
        proposal::Action::Motion(motion) => validate_and_render_motion(motion),
        proposal::Action::ManageNervousSystemParameters(manage) => {
            validate_and_render_manage_nervous_system_parameters(manage, current_parameters)
        }
        proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
            validate_and_render_upgrade_sns_controlled_canister(upgrade)
        }
        Action::UpgradeSnsToNextVersion(upgrade_sns) => {
            let current_version = governance_proto.deployed_version_or_panic();

            validate_and_render_upgrade_sns_to_next_version(
                upgrade_sns,
                env,
                root_canister_id,
                current_version,
            )
            .await
        }
        proposal::Action::AddGenericNervousSystemFunction(function_to_add) => {
            validate_and_render_add_generic_nervous_system_function(
                &disallowed_target_canister_ids,
                function_to_add,
                existing_functions,
            )
        }
        proposal::Action::RemoveGenericNervousSystemFunction(id_to_remove) => {
            validate_and_render_remove_nervous_generic_system_function(
                *id_to_remove,
                existing_functions,
            )
        }
        proposal::Action::ExecuteGenericNervousSystemFunction(execute) => {
            validate_and_render_execute_nervous_system_function(env, execute, existing_functions)
                .await
        }
        proposal::Action::RegisterDappCanisters(register_dapp_canisters) => {
            validate_and_render_register_dapp_canisters(
                register_dapp_canisters,
                &disallowed_target_canister_ids,
            )
        }
        proposal::Action::DeregisterDappCanisters(deregister_dapp_canisters) => {
            validate_and_render_deregister_dapp_canisters(
                deregister_dapp_canisters,
                &disallowed_target_canister_ids,
            )
        }
        proposal::Action::ManageSnsMetadata(manage_sns_metadata) => {
            validate_and_render_manage_sns_metadata(manage_sns_metadata)
        }
        proposal::Action::TransferSnsTreasuryFunds(transfer) => {
            return validate_and_render_transfer_sns_treasury_funds(
                transfer,
                sns_transfer_fee_e8s,
                env,
                swap_canister_id,
                sns_ledger_canister_id,
                proposals,
            )
            .await;
        }
        proposal::Action::MintSnsTokens(mint_sns_tokens) => {
            return validate_and_render_mint_sns_tokens(
                mint_sns_tokens,
                sns_transfer_fee_e8s,
                env,
                swap_canister_id,
                sns_ledger_canister_id,
                proposals,
            )
            .await;
        }
        proposal::Action::ManageLedgerParameters(manage_ledger_parameters) => {
            validate_and_render_manage_ledger_parameters(manage_ledger_parameters)
        }
        proposal::Action::ManageDappCanisterSettings(manage_dapp_canister_settings) => {
            validate_and_render_manage_dapp_canister_settings(manage_dapp_canister_settings)
        }
    }
    .map(|rendering| (rendering, ActionAuxiliary::None))
}

/// Validates and renders a proposal with action Motion.
fn validate_and_render_motion(motion: &Motion) -> Result<String, String> {
    validate_len(
        "motion.motion_text",
        &motion.motion_text,
        0, // min
        PROPOSAL_MOTION_TEXT_BYTES_MAX,
    )?;

    Ok(format!(
        r"# Motion Proposal:
## Motion Text:

{}",
        &motion.motion_text
    ))
}

/// Validates and renders a proposal with action ManageNervousSystemParameters.
fn validate_and_render_manage_nervous_system_parameters(
    new_parameters: &NervousSystemParameters,
    current_parameters: &NervousSystemParameters,
) -> Result<String, String> {
    new_parameters.inherit_from(current_parameters).validate()?;

    Ok(format!(
        r"# Proposal to change nervous system parameters:
## Current nervous system parameters:

{:#?}

## New nervous system parameters:

{:#?}",
        &current_parameters, new_parameters
    ))
}

/// Validates and render TransferSnsTreasuryFunds proposal
///
/// Returns ActionAuxiliary::TransferSnsTreasuryFunds.
async fn validate_and_render_transfer_sns_treasury_funds(
    transfer: &TransferSnsTreasuryFunds,
    sns_transfer_fee_e8s: u64,
    env: &dyn Environment,
    swap_canister_id: CanisterId,
    sns_ledger_canister_id: CanisterId,
    proposals: impl Iterator<Item = &ProposalData>,
) -> Result<
    (
        String, // Rendering.
        ActionAuxiliary,
    ),
    String,
> {
    let mut defects = vec![];

    // Validate amount. This requires calling CMC and the swap canister; hence, await.
    let valuation = treasury_valuation_if_proposal_amount_is_small_enough_or_err(
        env,
        sns_ledger_canister_id,
        swap_canister_id,
        proposals,
        transfer,
    )
    .await;
    let valuation = match valuation {
        Ok(ok) => Some(ok),
        Err(err) => {
            defects.push(err);
            None
        }
    };

    // Validate all other aspects of the proposal action.
    locally_validate_and_render_transfer_sns_treasury_funds(transfer, sns_transfer_fee_e8s, defects)
        .and_then(|rendering| {
            match valuation {
                Some(valuation) => Ok((
                    rendering,
                    ActionAuxiliary::TransferSnsTreasuryFunds(valuation),
                )),

                // Proof that this never happens:
                //
                //   1. valuation = None means that amount_result was Err.
                //
                //   2. In that case, nonempty defects was passed to
                //      locally_validate_and_render_transfer_sns_treasury_funds.
                //
                //   3. In that case, the function always returns Err.
                //
                //   4. Then, this closure doesn't get called.
                None => Err(
                    "There seems to be a bug in the amount validator. Somehow, no valuation, \
                     even though a rendering was generated."
                        .to_string(),
                ),
            }
        })
}

/// Performs all the validation on a TransferSnsTreasuryFunds that does not require fetching
/// information from other canisters.
fn locally_validate_and_render_transfer_sns_treasury_funds(
    transfer: &TransferSnsTreasuryFunds,
    sns_transfer_fee_e8s: u64,
    mut defects: Vec<String>,
) -> Result<String, String> {
    // Two things are happening here:
    //
    //     1. make sure that from_treasury is not Unspecified.
    //
    //     2. Humanize from_treasury.
    let (from, unit) = match transfer.from_treasury() {
        TransferFrom::IcpTreasury => ("ICP Treasury (ICP Ledger)", "ICP"),
        TransferFrom::SnsTokenTreasury => ("SNS Token Treasury (SNS Ledger)", "SNS Tokens"),
        TransferFrom::Unspecified => {
            defects.push(
                "Must specify a treasury from which to transfer the funds (ICP/SNS Token)."
                    .to_string(),
            );
            ("", "")
        }
    };

    // Make sure amount is not too small.
    let minimum_transaction = match transfer.from_treasury() {
        TransferFrom::IcpTreasury => NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
        TransferFrom::SnsTokenTreasury => sns_transfer_fee_e8s,
        TransferFrom::Unspecified => 0,
    };
    if transfer.amount_e8s < minimum_transaction {
        defects.push(format!(
            "For transactions from {}, the fee and minimum transaction is {} e8s",
            from, minimum_transaction
        ))
    }

    // Inspect to_principal, which must be Some(non_anonymous).
    let to_principal = if let Some(to_principal) = transfer.to_principal {
        if to_principal == PrincipalId::new_anonymous() {
            defects.push("to_principal must not be anonymous.".to_string());
        }
        to_principal
    } else {
        defects.push("Must specify a principal to make the transfer to.".to_string());
        PrincipalId::new_anonymous()
    };

    let to_account = match &transfer.to_subaccount {
        None => Account {
            owner: to_principal.0,
            subaccount: None,
        }
        .to_string(),
        Some(s) => match bytes_to_subaccount(&s.subaccount[..]) {
            Ok(s) => Account {
                owner: to_principal.0,
                subaccount: Some(s),
            }
            .to_string(),
            Err(e) => {
                defects.push(e.error_message);
                "".to_string()
            }
        },
    };

    // Generate final report.
    if !defects.is_empty() {
        return Err(format!(
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\n{}",
            defects.join("\n"),
        ));
    }

    let display_amount_tokens = i2d(transfer.amount_e8s) / i2d(E8);
    Ok(format!(
        r"# Proposal to transfer SNS Treasury funds:
## Source treasury: {from}
## Amount: {display_amount_tokens:.8} {unit}
## Amount (e8s): {amount_e8s}
## Target principal: {to_principal}
## Target account: {to_account}
## Memo: {memo}",
        amount_e8s = transfer.amount_e8s,
        memo = transfer.memo.unwrap_or(0)
    ))
}

/// The only thing that implements this is Token.
// treasury_account could be moved to impl Token if TREASURY_SUBACCOUNT_NONCE where defined in
// another crate instead of this one.
trait TreasuryAccount {
    fn treasury_account(self, sns_governance_canister_id: CanisterId) -> Result<Account, String>;
}

impl TreasuryAccount for Token {
    fn treasury_account(self, sns_governance_canister_id: CanisterId) -> Result<Account, String> {
        let sns_governance_canister_id = PrincipalId::from(sns_governance_canister_id);
        let owner = Principal::from(sns_governance_canister_id);

        match self {
            Self::Icp => Ok(Account {
                owner,
                subaccount: None,
            }),

            Self::SnsToken => Ok(Account {
                owner,
                subaccount: Some(compute_distribution_subaccount_bytes(
                    sns_governance_canister_id,
                    TREASURY_SUBACCOUNT_NONCE,
                )),
            }),
        }
    }
}

/// Currently, two Actions implement this: TransferSnsTreasuryFunds, and MintSnsTokens.
///
/// The thing that they have in common here is that we want to limit the 7-day amount total of these
/// proposals.
trait TokenProposalAction {
    /// Err can only happen if self is invalid. Otherwise, it is generally determined from the
    /// (badly named) from_treasury field.
    fn token(&self) -> Result<Token, String>;

    /// Err is not returned.
    fn proposal_amount_tokens(&self) -> Result<Decimal, String>;

    /// First, this filters proposals for those like self that have been executed in the "recent"
    /// past (where "recent" is defined by Self). Then, this adds up the amounts in those
    /// proposals.
    fn recent_amount_total_tokens<'a>(
        &self,
        proposals: impl Iterator<Item = &'a ProposalData>,
        now_timestamp_seconds: u64,
    ) -> Result<Decimal, String>;

    /// The greatest that recent_amount_total_tokens is allowed to be. This is based on the value of
    /// the token is in the treasury.
    fn recent_amount_total_upper_bound_tokens(valuation: &Valuation) -> Result<Decimal, String>;
}

// Ideally, I'd like to make this a "direct" method of TokenProposalAction. That is, there should be
// just one implementation of this within TokenProposalAction, not a different implementation for
// each type that implements TokenProposalAction. In general, it seems you can do that, but trying
// to do that here causes a baffling circular dependency. The general way looks like this:
//
// ```
// impl dyn Trait {
//     fn f(&self) {
//         println!("Hello, Trait!");
//     }
// }
// ```
async fn treasury_valuation_if_proposal_amount_is_small_enough_or_err<MyTokenProposalAction>(
    env: &dyn Environment,
    sns_ledger_canister_id: CanisterId,
    swap_canister_id: CanisterId,
    proposals: impl Iterator<Item = &ProposalData>,
    action: &MyTokenProposalAction,
) -> Result<Valuation, String>
where
    MyTokenProposalAction: TokenProposalAction,
{
    let spent_tokens = action.recent_amount_total_tokens(proposals, env.now())?;

    // Get valuation of the tokens in the treasury.
    let token = action.token()?;
    let treasury_account = token.treasury_account(env.canister_id())?;
    let valuation = token
        .assess_balance(sns_ledger_canister_id, swap_canister_id, treasury_account)
        .await
        .map_err(|valuation_error| format!("Unable to validate amount: {:?}", valuation_error))?;

    // From valuation, determine limit on the total from the past 7 days.
    let max_tokens = MyTokenProposalAction::recent_amount_total_upper_bound_tokens(&valuation)
        // Err is most likely a bug.
        .map_err(|treasury_limit_error| {
            format!("Unable to validate amount: {:?}", treasury_limit_error,)
        })?;

    // Finally, inspect the proposal's amount: it must not exceed max - spent (remainder). Or if
    // you prefer, equivalently, amount + spent must be <= max.
    let allowance_remainder_tokens = max_tokens.checked_sub(spent_tokens).ok_or_else(|| {
        format!(
            "Arithmetic error while performing {} - {}",
            max_tokens, spent_tokens,
        )
    })?;
    let proposal_amount_tokens = action.proposal_amount_tokens()?;
    if proposal_amount_tokens > allowance_remainder_tokens {
        // Although it might not be obvious to the user, their proposal is invalid, and we
        // consider it to be "their fault".
        return Err(format!(
            "Amount is too large. Within the past 7 days, a total of {} tokens has already \
             been executed in like proposals. Whereas, at most {} is allowed. An additional \
             {} tokens from this proposal would cause that upper bound to be exceeded. \
             Maybe, try again in a few days?",
            spent_tokens, max_tokens, proposal_amount_tokens
        ));
    }

    Ok(valuation)
}

impl TokenProposalAction for TransferSnsTreasuryFunds {
    fn token(&self) -> Result<Token, String> {
        let transfer_from = TransferFrom::try_from(self.from_treasury).map_err(|err| {
            format!(
                "Invalid TransferSnsTreasuryFunds: \
                     The `from_treasury` field holds an unrecognized value ({:?}): {:?}",
                self.from_treasury, err,
            )
        })?;

        match transfer_from {
            TransferFrom::IcpTreasury => Ok(Token::Icp),
            TransferFrom::SnsTokenTreasury => Ok(Token::SnsToken),
            TransferFrom::Unspecified => Err(format!(
                "Invalid TransferSnsTreasuryFunds: \
                 The `from_treasury` field holds the Unspecified value: {:#?}",
                self,
            )),
        }
    }

    fn proposal_amount_tokens(&self) -> Result<Decimal, String> {
        denominations_to_tokens(self.amount_e8s, E8)
            // This Err will not be generated, because we are dividing a u64 (amount_e8s) by a
            // positive number (E8).
            .ok_or_else(|| {
                format!(
                    "Unable to convert proposal amount {} e8s to tokens.",
                    self.amount_e8s,
                )
            })
    }

    fn recent_amount_total_tokens<'a>(
        &self,
        proposals: impl Iterator<Item = &'a ProposalData>,
        now_timestamp_seconds: u64,
    ) -> Result<Decimal, String> {
        total_treasury_transfer_amount_tokens(
            proposals,
            self.from_treasury(),
            now_timestamp_seconds - 7 * ONE_DAY_SECONDS,
        )
    }

    fn recent_amount_total_upper_bound_tokens(valuation: &Valuation) -> Result<Decimal, String> {
        transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(*valuation)
            // Err is most likely a bug.
            .map_err(|treasury_limit_error| {
                format!("Unable to validate amount: {:?}", treasury_limit_error,)
            })
    }
}

/// Validates and render MintSnsTokens proposal.
///
/// Returns ActionAuxiliary::MintSnsTokens.
async fn validate_and_render_mint_sns_tokens(
    mint_sns_tokens: &MintSnsTokens,
    sns_transfer_fee_e8s: u64,
    env: &dyn Environment,
    swap_canister_id: CanisterId,
    sns_ledger_canister_id: CanisterId,
    proposals: impl Iterator<Item = &ProposalData>,
) -> Result<
    (
        String, // Rendering.
        ActionAuxiliary,
    ),
    String,
> {
    let mut defects = vec![];

    // Validate amount. (This requires calling CMC and the swap canister; hence, await.)
    let valuation = treasury_valuation_if_proposal_amount_is_small_enough_or_err(
        env,
        sns_ledger_canister_id,
        swap_canister_id,
        proposals,
        mint_sns_tokens,
    )
    .await;
    let valuation = match valuation {
        Ok(ok) => Some(ok),
        Err(err) => {
            defects.push(err);
            None
        }
    };

    locally_validate_and_render_mint_sns_tokens(mint_sns_tokens, sns_transfer_fee_e8s, defects)
        .and_then(|rendering| {
            match valuation {
                Some(valuation) => Ok((rendering, ActionAuxiliary::MintSnsTokens(valuation))),

                // Proof that this never happens:
                //
                //   1. valuation = None means that amount_result was Err.
                //
                //   2. In that case, nonempty defects was passed to
                //      locally_validate_and_render_mint_sns_tokens.
                //
                //   3. In that case, the function always returns Err.
                //
                //   4. Then, this closure doesn't get called.
                None => Err(
                    "There is a bug in the amount validator. Somehow, no valuation, \
                     even though a rendering was generated."
                        .to_string(),
                ),
            }
        })
}

/// Performs all the validation on a TransferSnsTreasuryFunds that does not require fetching
/// information from other canisters.
fn locally_validate_and_render_mint_sns_tokens(
    mint: &MintSnsTokens,
    sns_transfer_fee_e8s: u64,
    mut defects: Vec<String>,
) -> Result<String, String> {
    let minimum_transaction_e8s = sns_transfer_fee_e8s;

    if mint.amount_e8s.is_none() {
        defects.push("Must specify an amount_e8s to mint.".to_string());
    } else if mint.amount_e8s() < minimum_transaction_e8s {
        defects.push(format!("The minimum mint is {minimum_transaction_e8s} e8s",))
    }

    let to_principal = if let Some(to_principal) = mint.to_principal {
        if to_principal == PrincipalId::new_anonymous() {
            defects.push("to_principal must not be anonymous.".to_string());
        }
        to_principal
    } else {
        defects.push("Must specify a to_principal to make the mint to.".to_string());
        PrincipalId::new_anonymous()
    };

    let to_account = match &mint.to_subaccount {
        None => Account {
            owner: to_principal.0,
            subaccount: None,
        }
        .to_string(),
        Some(s) => match bytes_to_subaccount(&s.subaccount[..]) {
            Ok(s) => Account {
                owner: to_principal.0,
                subaccount: Some(s),
            }
            .to_string(),
            Err(e) => {
                defects.push(e.error_message);
                "".to_string()
            }
        },
    };

    // Generate final report.
    if !defects.is_empty() {
        return Err(format!(
            "MintSnsTokens proposal was invalid for the following reason(s):\n{}",
            defects.join("\n"),
        ));
    }

    let display_amount_tokens = i2d(mint.amount_e8s()) / i2d(E8);

    Ok(format!(
        r"# Proposal to mint SNS Tokens:
## Amount: {display_amount_tokens:.8} SNS Tokens
## Amount (e8s): {amount_e8s}
## Target principal: {to_principal}
## Target account: {to_account}
## Memo: {memo}",
        amount_e8s = mint.amount_e8s(),
        memo = mint.memo()
    ))
}

impl TokenProposalAction for MintSnsTokens {
    fn token(&self) -> Result<Token, String> {
        Ok(Token::SnsToken)
    }

    fn proposal_amount_tokens(&self) -> Result<Decimal, String> {
        let amount_e8s = self
            .amount_e8s
            // This Err only occurs when self is invalid.
            .ok_or_else(|| "The `amount_e8s` field is not populated.".to_string())?;

        denominations_to_tokens(amount_e8s, E8)
            // This Err will not be generated, because we are dividing a u64 (amount_e8s) by a
            // positive number (E8).
            .ok_or_else(|| {
                format!(
                    "Unable to convert proposal amount {} e8s to tokens.",
                    amount_e8s,
                )
            })
    }

    fn recent_amount_total_tokens<'a>(
        &self,
        proposals: impl Iterator<Item = &'a ProposalData>,
        now_timestamp_seconds: u64,
    ) -> Result<Decimal, String> {
        total_minting_amount_tokens(proposals, now_timestamp_seconds - 7 * ONE_DAY_SECONDS)
    }

    /* TODO(NNS1-2982): Uncomment.
    fn recent_amount_total_upper_bound_tokens(valuation: &Valuation) -> Result<Decimal, String> {
        mint_sns_tokens_7_day_total_upper_bound_tokens(*valuation)
            // Err is most likely a bug.
            .map_err(|treasury_limit_error| {
                format!("Unable to validate amount: {:?}", treasury_limit_error,)
            })
    }
    */

    // TODO(NNS1-2982): Delete.
    fn recent_amount_total_upper_bound_tokens(_valuation: &Valuation) -> Result<Decimal, String> {
        // Ideally, we'd return infinity, but Decimal does not have that. This is the next best
        // thing, and should be good enough, because we have already planned the obselences of this
        // code (see tickets NNS1-298(1|2)).
        Ok(Decimal::MAX)
    }
}

/// Validates and renders a proposal with action UpgradeSnsControlledCanister.
fn validate_and_render_upgrade_sns_controlled_canister(
    upgrade: &UpgradeSnsControlledCanister,
) -> Result<String, String> {
    let mut defects = vec![];

    let UpgradeSnsControlledCanister {
        canister_id: _,
        new_canister_wasm,
        canister_upgrade_arg,
        mode,
    } = upgrade;
    // Make sure `mode` is not None, and not an invalid/unknown value.
    if let Some(mode) = mode {
        if let Err(err) = CanisterInstallMode::try_from(*mode) {
            defects.push(format!("Invalid mode: {}", err));
        }
    }
    // Assume mode is the default if it is not set
    let mode = upgrade.mode_or_upgrade();

    // Inspect canister_id.
    let mut canister_id = PrincipalId::new_user_test_id(0xDEADBEEF); // Initialize to garbage. This won't get used later.
    match validate_required_field("canister_id", &upgrade.canister_id) {
        Err(err) => {
            defects.push(err);
        }
        Ok(id) => {
            canister_id = *id;
        }
    }

    // Inspect wasm.
    const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
    // see https://ic-interface-spec.netlify.app/#canister-module-format
    const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];
    // Minimum length of raw WASM is 8 bytes (4 magic bytes and 4 bytes encoding version).
    // Minimum length of gzipped WASM is 10 bytes (2 magic bytes, 1 byte encoding compression method, and 7 additional gzip header bytes).
    const MIN_WASM_LEN: usize = 8;
    if let Err(err) = validate_len(
        "new_canister_wasm",
        new_canister_wasm,
        MIN_WASM_LEN,
        usize::MAX,
    ) {
        defects.push(err);
    } else if new_canister_wasm[..4] != RAW_WASM_HEADER[..]
        && new_canister_wasm[..3] != GZIPPED_WASM_HEADER[..]
    {
        defects.push("new_canister_wasm lacks the magic value in its header.".into());
    }

    if new_canister_wasm.len()
        + canister_upgrade_arg
            .as_ref()
            .map(|arg| arg.len())
            .unwrap_or_default()
        >= MAX_INSTALL_CODE_WASM_AND_ARG_SIZE
    {
        defects.push(format!("the maximum canister WASM and argument size for UpgradeSnsControlledCanister is {} bytes.", MAX_INSTALL_CODE_WASM_AND_ARG_SIZE));
    }

    // Generate final report.
    if !defects.is_empty() {
        return Err(format!(
            "UpgradeSnsControlledCanister was invalid for the following reason(s):\n{}",
            defects.join("\n"),
        ));
    }

    let canister_wasm_sha256 = {
        let mut state = Sha256::new();
        state.write(new_canister_wasm);
        let sha = state.finish();
        hex::encode(sha)
    };

    let upgrade_args_sha_256 = canister_upgrade_arg
        .as_ref()
        .map(|arg| {
            let mut state = Sha256::new();
            state.write(arg);
            let sha = state.finish();
            format!("Upgrade arg sha256: {}", hex::encode(sha))
        })
        .unwrap_or_else(|| "No upgrade arg".to_string());

    Ok(format!(
        r"# Proposal to upgrade SNS controlled canister:

## Canister id: {canister_id:?}

## Canister wasm sha256: {canister_wasm_sha256}

## Mode: {mode:?}

## {upgrade_args_sha_256}",
    ))
}

pub(crate) fn render_version(version: &Version) -> String {
    format!(
        r"Version {{
    root: {},
    governance: {},
    ledger: {},
    swap: {},
    archive: {},
    index: {},
}}",
        hex::encode(&version.root_wasm_hash),
        hex::encode(&version.governance_wasm_hash),
        hex::encode(&version.ledger_wasm_hash),
        hex::encode(&version.swap_wasm_hash),
        hex::encode(&version.archive_wasm_hash),
        hex::encode(&version.index_wasm_hash),
    )
}
/// Validates and renders a proposal with action UpgradeSnsToNextVersion.
async fn validate_and_render_upgrade_sns_to_next_version(
    _upgrade_sns: &UpgradeSnsToNextVersion,
    env: &dyn Environment,
    root_canister_id: CanisterId,
    current_version: Version,
) -> Result<String, String> {
    let UpgradeSnsParams {
        next_version,
        canister_type_to_upgrade,
        new_wasm_hash,
        canister_ids_to_upgrade,
    } = get_upgrade_params(env, root_canister_id, &current_version)
        .await
        .map_err(|e| {
            format!(
                "UpgradeSnsToNextVersion was invalid for the following reason: {}\n",
                e
            )
        })?;

    let proposal_id_message = get_proposal_id_that_added_wasm(env, new_wasm_hash.to_vec())
        .await
        .ok()
        // TODO(NNS1-3152): If there was an error, surface it in some way so the
        // community can talk about it.
        .flatten()
        .map(|id| {
            format!(
                "## Proposal ID of the NNS proposal that blessed this WASM version: NNS Proposal {}",
                id
            )
        })
        .unwrap_or_default();

    // TODO display the hashes for current version and new version
    Ok(format!(
        r"# Proposal to upgrade SNS {canister_type_to_upgrade:?} to next version:

## SNS Current Version:
{}

## SNS New Version:
{}

## Canisters to be upgraded: {}
## Upgrade Version: {}
{proposal_id_message}
",
        render_version(&current_version),
        render_version(&next_version),
        canister_ids_to_upgrade
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        hex::encode(new_wasm_hash),
    ))
}

#[derive(Debug)]
pub(crate) struct ValidGenericNervousSystemFunction {
    pub id: u64,
    pub target_canister_id: CanisterId,
    pub target_method: String,
    pub validator_canister_id: CanisterId,
    pub validator_method: String,
}

/// Validates a given canister id and adds a defect to a given list of defects if the there was no
/// canister id given or if it was invalid.
fn validate_canister_id(
    field_name: &str,
    canister_id: &Option<PrincipalId>,
    defects: &mut Vec<String>,
) -> Option<CanisterId> {
    match canister_id {
        None => {
            defects.push(format!("{} field was not populated.", field_name));
            None
        }
        Some(canister_id) => Some(CanisterId::unchecked_from_principal(*canister_id)),
    }
}

impl ValidGenericNervousSystemFunction {
    pub const MIN_ID: u64 = 1000;
}

impl TryFrom<&NervousSystemFunction> for ValidGenericNervousSystemFunction {
    type Error = String;

    fn try_from(value: &NervousSystemFunction) -> Result<Self, Self::Error> {
        if value == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
            return Err(
                "NervousSystemFunction is a deletion marker and not an actual function."
                    .to_string(),
            );
        }

        if value.is_native() {
            return Err("NervousSystemFunction is not generic.".to_string());
        }

        let NervousSystemFunction {
            id,
            name,
            description,
            function_type,
        } = value;

        let mut defects = vec![];

        if *id < Self::MIN_ID {
            defects.push(format!(
                "NervousSystemFunction's must have ids starting at {}",
                Self::MIN_ID,
            ));
        }

        if name.is_empty() || name.len() > 256 {
            defects.push(
                "NervousSystemFunction's must have set name with a max of 255 bytes".to_string(),
            );
        }

        if description.is_some() && description.as_ref().unwrap().len() > 10000 {
            defects.push(
                "NervousSystemFunction's description must be at most 10000 bytes".to_string(),
            );
        }

        match function_type {
            Some(FunctionType::GenericNervousSystemFunction(GenericNervousSystemFunction {
                target_canister_id,
                target_method_name,
                validator_canister_id,
                validator_method_name,
            })) => {
                // Validate the target_canister_id field.
                let target_canister_id =
                    validate_canister_id("target_canister_id", target_canister_id, &mut defects);

                // Validate the validator_canister_id field.
                let validator_canister_id = validate_canister_id(
                    "validator_canister_id",
                    validator_canister_id,
                    &mut defects,
                );

                // Validate the target_method_name field.
                if target_method_name.is_none() || target_method_name.as_ref().unwrap().is_empty() {
                    defects.push("target_method_name was empty.".to_string());
                }

                if validator_method_name.is_none()
                    || validator_method_name.as_ref().unwrap().is_empty()
                {
                    defects.push("validator_method_name was empty.".to_string());
                }

                if !defects.is_empty() {
                    return Err(format!(
                        "ExecuteNervousSystemFunction was invalid for the following reason(s):\n{}",
                        defects.join("\n")
                    ));
                }

                Ok(ValidGenericNervousSystemFunction {
                    id: *id,
                    target_canister_id: target_canister_id.unwrap(),
                    target_method: target_method_name.as_ref().unwrap().clone(),
                    validator_canister_id: validator_canister_id.unwrap(),
                    validator_method: validator_method_name.as_ref().unwrap().clone(),
                })
            }
            _ => {
                defects.push("NervousSystemFunction must have a function_type set to GenericNervousSystemFunction".to_string());
                Err(format!(
                    "ExecuteNervousSystemFunction was invalid for the following reason(s):\n{}",
                    defects.join("\n")
                ))
            }
        }
    }
}

/// Validates and renders a proposal with action AddNervousSystemFunction.
pub fn validate_and_render_add_generic_nervous_system_function(
    disallowed_target_canister_ids: &HashSet<CanisterId>,
    add: &NervousSystemFunction,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let validated_function = ValidGenericNervousSystemFunction::try_from(add)?;
    if existing_functions.contains_key(&validated_function.id) {
        return Err(format!(
            "There is already a NervousSystemFunction with id: {}",
            validated_function.id
        ));
    }

    let target_canister_id = validated_function.target_canister_id;
    let validator_canister_id = validated_function.validator_canister_id;

    if disallowed_target_canister_ids.contains(&target_canister_id)
        || disallowed_target_canister_ids.contains(&validator_canister_id)
    {
        return Err("Function targets a reserved canister.".to_string());
    }

    if existing_functions.len() >= MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS {
        return Err("Reached maximum number of allowed GenericNervousSystemFunctions".to_string());
    }

    Ok(format!(
        r"Proposal to add new NervousSystemFunction:

## Function:

{:#?}",
        add
    ))
}

/// Validates and renders a proposal with action RemoveNervousSystemFunction.
pub fn validate_and_render_remove_nervous_generic_system_function(
    remove: u64,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    match existing_functions.get(&remove) {
        None => Err(format!("NervousSystemFunction: {} doesn't exist", remove)),
        Some(function) => Ok(format!(
            r"# Proposal to remove existing NervousSystemFunction:

## Function:

{:#?}",
            function
        )),
    }
}

/// Validates and renders a proposal with action ExecuteNervousSystemFunction.
/// This retrieves the nervous system function's validator method and calls it.
pub async fn validate_and_render_execute_nervous_system_function(
    env: &dyn Environment,
    execute: &ExecuteGenericNervousSystemFunction,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let id = execute.function_id;
    match existing_functions.get(&execute.function_id) {
        None => Err(format!("There is no NervousSystemFunction with id: {}", id)),
        Some(function) => {
            // Make sure this isn't a NervousSystemFunction which has been deleted.
            if function == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
                Err(format!("There is no NervousSystemFunction with id: {}", id))
            } else {
                // To validate the proposal we try and call the validation method,
                // which should produce a payload rendering if the proposal is valid
                // or an error if it isn't.
                let rendering =
                    perform_execute_generic_nervous_system_function_validate_and_render_call(
                        env,
                        function.clone(),
                        execute.clone(),
                    )
                    .await?;

                let payload_hash = {
                    let mut state = Sha256::new();
                    state.write(execute.payload.as_slice());
                    let sha = state.finish();
                    hex::encode(sha)
                };

                Ok(format!(
                    r"# Proposal to execute nervous system function:

## Nervous system function:

{function:#?}

## Payload sha256: 

{payload_hash}

## Payload:

{rendering}"
                ))
            }
        }
    }
}

fn validate_and_render_register_dapp_canisters(
    register_dapp_canisters: &RegisterDappCanisters,
    disallowed_canister_ids: &HashSet<CanisterId>,
) -> Result<String, String> {
    if register_dapp_canisters.canister_ids.is_empty() {
        return Err("RegisterDappCanisters must specify at least one canister id".to_string());
    }

    let num_canisters_to_register = register_dapp_canisters.canister_ids.len();
    if num_canisters_to_register > MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL {
        return Err(format!("RegisterDappCanisters cannot specify more than {MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL} canister ids"));
    }

    let canisters_to_register = register_dapp_canisters
        .canister_ids
        .iter()
        .map(|id| CanisterId::unchecked_from_principal(*id))
        .collect::<HashSet<CanisterId>>();

    let error_canister_ids: HashSet<&CanisterId> = disallowed_canister_ids
        .intersection(&canisters_to_register)
        .collect();

    if error_canister_ids.is_empty() {
        let canister_list = register_dapp_canisters.canister_ids.iter().fold(
            String::new(),
            |mut out, canister_id| {
                let _ = write!(out, "\n- {}", canister_id);
                out
            },
        );

        let render = format!(
            "# Proposal to register {num_canisters_to_register} dapp canisters: \n\
             ## Canister ids: {canister_list}"
        );
        Ok(render)
    } else {
        let error_canister_list =
            error_canister_ids
                .iter()
                .fold(String::new(), |mut out, canister_id| {
                    let _ = write!(out, "\n- {}", canister_id);
                    out
                });

        let err_msg: String = format!(
            "Invalid RegisterDappCanisters Proposal: \n\
             The requested canister is an SNS canister. {error_canister_list}"
        );
        Err(err_msg)
    }
}

fn validate_and_render_deregister_dapp_canisters(
    deregister_dapp_canisters: &DeregisterDappCanisters,
    disallowed_canister_ids: &HashSet<CanisterId>,
) -> Result<String, String> {
    if deregister_dapp_canisters.canister_ids.is_empty() {
        return Err("DeregisterDappCanisters must specify at least one canister id".to_string());
    }

    if deregister_dapp_canisters.canister_ids.len() > MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL {
        return Err(format!("DeregisterDappCanisters cannot specify more than {MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL} canister ids"));
    }

    if deregister_dapp_canisters.new_controllers.is_empty() {
        return Err("DeregisterDappControllers must specify the new controllers".to_string());
    }

    let canisters_to_deregister = deregister_dapp_canisters
        .canister_ids
        .iter()
        .map(|id| CanisterId::unchecked_from_principal(*id))
        .collect::<HashSet<CanisterId>>();

    let error_canister_ids: HashSet<&CanisterId> = disallowed_canister_ids
        .intersection(&canisters_to_deregister)
        .collect();

    if error_canister_ids.is_empty() {
        let rendered = format!(
            r"# Proposal to set the listed principals as controllers of the listed canisters:
(This will result in the canisters being deregistered from this SNS.)

## Principals:
- {}

## Canisters:
- {}",
            deregister_dapp_canisters
                .new_controllers
                .iter()
                .map(|c| format!("{}", c))
                .collect::<Vec<_>>()
                .join("\n- "),
            deregister_dapp_canisters
                .canister_ids
                .iter()
                .map(|c| format!("{}", c))
                .collect::<Vec<_>>()
                .join("\n- ")
        );

        Ok(rendered)
    } else {
        let error_canister_list =
            error_canister_ids
                .iter()
                .fold(String::new(), |mut out, canister_id| {
                    let _ = write!(out, "\n- {}", canister_id);
                    out
                });

        let err_msg: String = format!(
            "Invalid DeregisterDappCanisters Proposal: \n\
             The requested canister is an SNS canister. {error_canister_list}"
        );
        Err(err_msg)
    }
}

// Validates and renders a proposal with action ManageSnsMetadata.
pub fn validate_and_render_manage_sns_metadata(
    manage_sns_metadata: &ManageSnsMetadata,
) -> Result<String, String> {
    let mut no_change = true;
    let mut render = "# Proposal to upgrade sns metadata:\n".to_string();
    if let Some(new_url) = &manage_sns_metadata.url {
        SnsMetadata::validate_url(new_url)?;
        render += &format!("# New url: {} \n", new_url);
        no_change = false;
    }
    if let Some(new_name) = &manage_sns_metadata.name {
        SnsMetadata::validate_name(new_name)?;
        render += &format!("# New name: {} \n", new_name);
        no_change = false;
    }
    if let Some(new_description) = &manage_sns_metadata.description {
        SnsMetadata::validate_description(new_description)?;
        render += &format!("# New description: {} \n", new_description);
        no_change = false;
    }
    if let Some(new_logo) = &manage_sns_metadata.logo {
        SnsMetadata::validate_logo(new_logo)?;
        render += &format!("# New logo (base64 encoding): \n {}", new_logo);
        no_change = false;
    }
    if no_change {
        Err(
            "Error: ManageSnsMetadata must change at least one value, all values are None"
                .to_string(),
        )
    } else {
        Ok(render)
    }
}

fn validate_and_render_manage_ledger_parameters(
    manage_ledger_parameters: &ManageLedgerParameters,
) -> Result<String, String> {
    let mut change = false;
    let mut render = "# Proposal to change ledger parameters:\n".to_string();
    let ManageLedgerParameters {
        transfer_fee,
        token_name,
        token_symbol,
        token_logo,
    } = manage_ledger_parameters;

    if let Some(transfer_fee) = transfer_fee {
        render += &format!("# Set token transfer fee: {transfer_fee} token-quantums. \n",);
        change = true;
    }
    if let Some(token_name) = token_name {
        ledger_validation::validate_token_name(token_name)?;
        render += &format!("# Set token name: {token_name}. \n",);
        change = true;
    }
    if let Some(token_symbol) = token_symbol {
        ledger_validation::validate_token_symbol(token_symbol)?;
        render += &format!("# Set token symbol: {token_symbol}. \n",);
        change = true;
    }
    if let Some(token_logo) = token_logo {
        ledger_validation::validate_token_logo(token_logo)?;
        render += &format!("# Set token logo: {token_logo}. \n",);
        change = true;
    }
    if !change {
        Err(String::from(
            "ManageLedgerParameters must change at least one value, all values are None",
        ))
    } else {
        Ok(render)
    }
}

fn validate_and_render_manage_dapp_canister_settings(
    manage_dapp_canister_settings: &ManageDappCanisterSettings,
) -> Result<String, String> {
    if manage_dapp_canister_settings.canister_ids.is_empty() {
        return Err("ManageDappCanisterSettings must specify at least one canister".to_string());
    }

    if manage_dapp_canister_settings.canister_ids.len() > MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL
    {
        return Err(format!(
            "ManageDappCanisterSettings cannot specify more than \
             {MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL} canister ids"
        ));
    }

    let num_canisters = manage_dapp_canister_settings.canister_ids.len();
    let canister_list = manage_dapp_canister_settings
        .canister_ids
        .iter()
        .map(|id| format!("  - {id}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut render = format!(
        "# Proposal to manage settings for {num_canisters} dapp canister{plural}: \n\
        ## Canister ids: \n\
        {canister_list}\n",
        plural = if num_canisters > 1 { "s" } else { "" },
    );

    let mut no_change = true;
    if let Some(compute_allocation) = &manage_dapp_canister_settings.compute_allocation {
        render += &format!("# Set compute allocation to: {}%\n", compute_allocation);
        no_change = false;
    }
    if let Some(memory_allocation) = &manage_dapp_canister_settings.memory_allocation {
        render += &format!("# Set memory allocation to: {} bytes\n", memory_allocation);
        no_change = false;
    }
    if let Some(freezing_threshold) = &manage_dapp_canister_settings.freezing_threshold {
        render += &format!(
            "# Set freezing threshold to: {} seconds\n",
            freezing_threshold
        );
        no_change = false;
    }
    if let Some(reserved_cycles_limit) = &manage_dapp_canister_settings.reserved_cycles_limit {
        render += &format!(
            "# Set reserved cycles limit to: {} \n",
            reserved_cycles_limit
        );
        no_change = false;
    }
    if let Some(log_visibility) = &manage_dapp_canister_settings.log_visibility {
        render += &format!(
            "# Set log visibility to: {:?} \n",
            LogVisibility::try_from(*log_visibility).unwrap_or_default()
        );
        no_change = false;
    }
    if let Some(wasm_memory_limit) = &manage_dapp_canister_settings.wasm_memory_limit {
        render += &format!("# Set Wasm memory limit to: {}\n", wasm_memory_limit);
        no_change = false;
    }

    if no_change {
        Err(String::from(
            "ManageDappCanisterSettings must change at least one value, all values are None",
        ))
    } else {
        Ok(render)
    }
}

impl ProposalData {
    /// Returns the proposal's decision status. See [ProposalDecisionStatus] in the SNS's
    /// proto for more information.
    pub fn status(&self) -> ProposalDecisionStatus {
        if self.decided_timestamp_seconds == 0 {
            ProposalDecisionStatus::Open
        } else if self.is_accepted() {
            if self.executed_timestamp_seconds > 0 {
                ProposalDecisionStatus::Executed
            } else if self.failed_timestamp_seconds > 0 {
                ProposalDecisionStatus::Failed
            } else {
                ProposalDecisionStatus::Adopted
            }
        } else {
            ProposalDecisionStatus::Rejected
        }
    }

    /// Returns the proposal's reward status. See [ProposalRewardStatus] in the SNS's
    /// proto for more information.
    pub fn reward_status(&self, now_seconds: u64) -> ProposalRewardStatus {
        if self.has_been_rewarded() {
            return ProposalRewardStatus::Settled;
        }

        if self.accepts_vote(now_seconds) {
            return ProposalRewardStatus::AcceptVotes;
        }

        // TODO(NNS1-2731): Replace this with just ReadyToSettle.
        if self.is_eligible_for_rewards {
            ProposalRewardStatus::ReadyToSettle
        } else {
            ProposalRewardStatus::Settled
        }
    }

    /// Returns true if this proposal has been rewarded.
    ///
    /// This is deduced based on two fields:
    ///
    ///   1. The old field: reward_event_round.
    ///   2. The new field: reward_event_end_timestamp_seconds.
    ///
    /// The second field was added later to support being able to change round duration. We still
    /// need to consult the old field though, because there are some old proposals that used it
    /// before we came up with the new field.
    ///
    /// It is feasible that we backfill old data (that is, populate the new field in old proposals).
    /// Then, we could remove the old field. Whether backfilling is worthwhile is debatable.
    pub fn has_been_rewarded(&self) -> bool {
        self.reward_event_end_timestamp_seconds.is_some() || self.reward_event_round > 0
    }

    /// Returns the proposal's current voting period deadline in seconds from the Unix epoch.
    /// This may change as the wait_for_quiet_state is updated.
    pub fn get_deadline_timestamp_seconds(&self) -> u64 {
        self.wait_for_quiet_state
            .as_ref()
            .map(|wfq| wfq.current_deadline_timestamp_seconds)
            .unwrap_or(
                // Assumes there is no delay between when the proposal is
                // created and when the voting period "countdown clock" starts.
                self.proposal_creation_timestamp_seconds + self.initial_voting_period_seconds,
            )
    }

    /// Returns true if votes are still accepted for the proposal and
    /// false otherwise.
    ///
    /// For voting reward purposes, votes may be accepted even after a
    /// proposal has been decided. Thus, this method may return true
    /// even if the proposal is already decided.
    /// (As soon as a majority is reached, the result cannot turn anymore,
    /// thus the proposal is decided. We still give time to other voters
    /// to cast their votes until the voting period ends so that they can
    /// collect voting rewards).
    pub fn accepts_vote(&self, now_seconds: u64) -> bool {
        // Checks if the proposal's deadline is still in the future.
        now_seconds < self.get_deadline_timestamp_seconds()
    }

    /// Possibly extends a proposal's voting period. The underlying idea is
    /// that if a proposal has a clear result, then there is no need to have
    /// a long voting period. However, if a proposal is controversial and the
    /// result keeps flipping, we should give voters more time to contribute
    /// to the decision.
    /// To this end, this method applies the so called wait-for-quiet algorithm
    /// to the given proposal: It evaluates whether the proposal's voting result
    /// has turned (a yes-result turned into a no-result or vice versa) and, if
    /// this is the case, extends the proposal's deadline.
    /// The initial voting period is extended by at most
    /// 2 * wait_for_quiet_deadline_increase_seconds.
    pub fn evaluate_wait_for_quiet(
        &mut self,
        now_seconds: u64,
        old_tally: &Tally,
        new_tally: &Tally,
    ) {
        let wait_for_quiet_state = self
            .wait_for_quiet_state
            .as_mut()
            .expect("Proposal must have a wait_for_quiet_state.");

        // Do not evaluate wait-for-quiet if there is already a decision, or the
        // proposal's voting deadline has been reached. The deciding amount for yes
        // and no are slightly different, because yes needs a majority to succeed, while
        // no only needs a tie.
        let current_deadline = wait_for_quiet_state.current_deadline_timestamp_seconds;
        let deciding_amount_yes = new_tally.total / 2 + 1;
        let deciding_amount_no = (new_tally.total + 1) / 2;
        if new_tally.yes >= deciding_amount_yes
            || new_tally.no >= deciding_amount_no
            || now_seconds > current_deadline
        {
            return;
        }

        // Returns whether the tally result has turned, i.e. if the result now
        // favors yes, but it used to favor no or vice versa.
        fn vote_has_turned(old_tally: &Tally, new_tally: &Tally) -> bool {
            (old_tally.yes > old_tally.no && new_tally.yes <= new_tally.no)
                || (old_tally.yes <= old_tally.no && new_tally.yes > new_tally.no)
        }
        if !vote_has_turned(old_tally, new_tally) {
            return;
        }

        // Let W be short for wait_for_quiet_deadline_increase_seconds. A proposal's voting
        // period starts with an initial_voting_period_seconds and can be extended
        // to at most initial_voting_period_seconds + 2 * W.
        // The required_margin reflects the proposed deadline extension to be
        // made beyond the current moment, so long as that extends beyond the
        // current wait-for-quiet deadline. We calculate the required_margin a
        // bit indirectly here so as to keep with unsigned integers, but the
        // idea is:
        //
        //     W + (initial_voting_period_seconds - elapsed) / 2
        //
        // Thus, while we are still within the initial voting period, we add
        // to W, but once we are beyond that window, we subtract from W until
        // reaching the limit where required_margin remains at zero. This
        // occurs when:
        //
        //     elapsed = initial_voting_period_seconds + 2 * W
        //
        // As an example, given that W = 12h, if the initial_voting_period_seconds is
        // 24h then the maximum deadline will be 24h + 2 * 12h = 48h.
        //
        // The required_margin ends up being a linearly decreasing value,
        // starting at W + initial_voting_period_seconds / 2 and reducing to zero at the
        // furthest possible deadline. When the vote does not flip, we do not
        // update the deadline, and so there is a chance of ending prior to
        // the extreme limit. But each time the vote flips, we "re-enter" the
        // linear progression according to the elapsed time.
        //
        // This means that whenever there is a flip, the deadline is always
        // set to the current time plus the required_margin, which places us
        // along the linear path that was determined by the starting
        // variables.
        let elapsed_seconds = now_seconds.saturating_sub(self.proposal_creation_timestamp_seconds);
        let required_margin = self
            .wait_for_quiet_deadline_increase_seconds
            .saturating_add(self.initial_voting_period_seconds / 2)
            .saturating_sub(elapsed_seconds / 2);
        let new_deadline = std::cmp::max(
            current_deadline,
            now_seconds.saturating_add(required_margin),
        );

        if new_deadline != current_deadline {
            log!(
                INFO,
                "{}Updating WFQ deadline for proposal: {:?}. Old: {}, New: {}, Ext: {}",
                log_prefix(),
                self.id.as_ref().unwrap(),
                current_deadline,
                new_deadline,
                new_deadline - current_deadline
            );

            wait_for_quiet_state.current_deadline_timestamp_seconds = new_deadline;
        }
    }

    /// Recomputes the proposal's tally.
    /// This is an expensive operation.
    pub fn recompute_tally(&mut self, now_seconds: u64) {
        // Tally proposal
        let mut yes = 0;
        let mut no = 0;
        let mut undecided = 0;
        for ballot in self.ballots.values() {
            let lhs: &mut u64 = if let Ok(vote) = Vote::try_from(ballot.vote) {
                match vote {
                    Vote::Unspecified => &mut undecided,
                    Vote::Yes => &mut yes,
                    Vote::No => &mut no,
                }
            } else {
                &mut undecided
            };
            *lhs = (*lhs).saturating_add(ballot.voting_power)
        }

        // It is validated in `make_proposal` that the total does not
        // exceed u64::MAX: the `saturating_add` is just a precaution.
        let total = yes.saturating_add(no).saturating_add(undecided);

        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes,
            no,
            total,
        };

        // Every time the tally changes, (possibly) update the wait-for-quiet
        // dynamic deadline.
        if let Some(old_tally) = self.latest_tally.clone() {
            if new_tally.yes == old_tally.yes
                && new_tally.no == old_tally.no
                && new_tally.total == old_tally.total
            {
                return;
            }

            self.evaluate_wait_for_quiet(now_seconds, &old_tally, &new_tally);
        }

        self.latest_tally = Some(new_tally);
    }

    /// Returns true if the proposal meets the conditions to be accepted, also called "adopted".
    /// The result is only meaningful if a decision on the proposal's result can be made, i.e.,
    /// either there is a majority of yes-votes or the proposal's deadline has passed.
    ///
    /// If this function changes, the GIX team should be notified, since they maintain a
    /// TypeScript version of it
    pub fn is_accepted(&self) -> bool {
        let minimum_yes_proportion_of_exercised = self.minimum_yes_proportion_of_exercised();
        let minimum_yes_proportion_of_total = self.minimum_yes_proportion_of_total();

        debug_assert!(
            minimum_yes_proportion_of_exercised < Percentage::from_basis_points(10_000),
            "minimum_yes_proportion_of_exercised ({minimum_yes_proportion_of_exercised}) should be < 100%"
        );
        debug_assert!(
            minimum_yes_proportion_of_exercised >= Percentage::from_basis_points(5_000),
            "minimum_yes_proportion_of_exercised ({minimum_yes_proportion_of_exercised}) should be >= 50%"
        );

        debug_assert!(
            minimum_yes_proportion_of_total <= minimum_yes_proportion_of_exercised,
            "minimum_yes_proportion_of_total ({minimum_yes_proportion_of_total}) should be <= minimum_yes_proportion_of_exercised ({minimum_yes_proportion_of_exercised})"
        );

        let Some(tally) = &self.latest_tally else {
            return false;
        };

        debug_assert!(
            tally.total >= tally.yes.saturating_add(tally.no),
            "The total number of votes ({}) should be greater than or equal to the number of yes votes ({}) plus the number of no votes ({})",
            tally.total,
            tally.yes,
            tally.no
        );

        let majority_met = Self::majority_decision(
            tally.yes,
            tally.no,
            tally.yes + tally.no,
            minimum_yes_proportion_of_exercised,
        ) == Vote::Yes;

        // We'll convert the values to u128 to prevent overflow.
        let yes = tally.yes as u128;
        let total = tally.total as u128;
        // The unwrap cannot fail because of how minimum_yes_proportion_of_total is computed earlier in this function
        let minimum_yes_proportion_of_total_basis_points =
            minimum_yes_proportion_of_total.basis_points.unwrap() as u128;

        let quorum_met = yes * 10_000 >= total * minimum_yes_proportion_of_total_basis_points;

        quorum_met && majority_met
    }

    /// Returns true if a decision can be made right now to adopt or reject the proposal.
    /// The proposal must be tallied prior to calling this method.
    pub fn can_make_decision(&self, now_seconds: u64) -> bool {
        debug_assert!(self.latest_tally.is_some());
        let Some(tally) = &self.latest_tally else {
            return false;
        };
        // Even when a proposal's deadline has not passed, a proposal is
        // adopted if strictly more than half of the votes are 'yes' and
        // rejected if at least half of the votes are 'no'. The conditions
        // are described as below to avoid overflow. In the absence of overflow,
        // the below is equivalent to (2 * yes > total) || (2 * no >= total).
        let absolute_majority = self.early_decision() != Vote::Unspecified;
        let expired = !self.accepts_vote(now_seconds);
        let decision_reason = match (absolute_majority, expired) {
            (true, true) => "majority and expiration",
            (true, false) => "majority",
            (false, true) => "expiration",
            (false, false) => return false,
        };
        log!(
            INFO,
            "{}Proposal {} decided, thanks to {}. Tally at decision time: {:?}",
            log_prefix(),
            self.id
                .as_ref()
                .map_or("unknown".to_string(), |i| format!("{}", i.id)),
            decision_reason,
            tally
        );
        true
    }

    /// In some cases, a proposal can be decided before the voting period ends,
    /// if enough voting has happened that further votes cannot change the result.
    /// If the proposal has been decided, this function returns the decision.
    /// Otherwise, it returns `Vote::Unspecified`.
    ///
    /// Preconditions:
    /// - `latest_tally` must be `Some`.
    pub fn early_decision(&self) -> Vote {
        let tally = &self
            .latest_tally
            .as_ref()
            .expect("expected latest_tally to not be None");

        let minimum_yes_proportion_of_exercised = self.minimum_yes_proportion_of_exercised();

        Self::majority_decision(
            tally.yes,
            tally.no,
            tally.total,
            minimum_yes_proportion_of_exercised,
        )
    }

    pub fn minimum_yes_proportion_of_total(&self) -> Percentage {
        let minimum_yes_proportion_of_total = self.minimum_yes_proportion_of_total.unwrap_or(
            NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER,
        );
        // make sure minimum_yes_proportion_of_total.basis_points isn't None
        if minimum_yes_proportion_of_total.basis_points.is_some() {
            minimum_yes_proportion_of_total
        } else {
            NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER
        }
    }

    pub fn minimum_yes_proportion_of_exercised(&self) -> Percentage {
        let minimum_yes_proportion_of_exercised =
            self.minimum_yes_proportion_of_exercised.unwrap_or(
                NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER,
            );
        // make sure minimum_yes_proportion_of_exercised.basis_points isn't None
        if minimum_yes_proportion_of_exercised.basis_points.is_some() {
            minimum_yes_proportion_of_exercised
        } else {
            NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER
        }
    }

    /// Considers the amount of 'yes' and 'no' voting power in relation to the total voting power,
    /// based on a percentage threshold that must be met or exceeded for a decision.
    /// - 'yes': Amount of voting power voting 'yes'.
    /// - 'no': Amount of voting power voting 'no'.
    /// - 'total': Total voting power.
    /// - 'percentage_of_total_required': The minimum percentage of the total voting power required for a decision.
    ///
    /// The function returns a `Vote`:
    /// - `Vote::Yes` if the amount of voting power voting 'yes' votes exceeds `percentage_of_total_required` of the total.
    /// - `Vote::No` if the amount of voting power voting 'no' votes is equal to or exceeds `1-percentage_of_total_required` of the total.
    /// - `Vote::Unspecified` if neither the amount of voting power voting 'yes' nor 'no' meet their respective thresholds.
    ///
    /// Preconditions:
    /// - `yes + no <= total`
    /// - `percentage_of_total_required <= 100%`
    /// - `percentage_of_total_required.basis_points` is not `None`
    pub fn majority_decision(
        yes: u64,
        no: u64,
        total: u64,
        percentage_of_total_required: Percentage,
    ) -> Vote {
        let yes = yes as u128;
        let no = no as u128;
        let total = total as u128;
        debug_assert!(total >= yes + no);

        // "permyriad" being a somewhat-obscure term for "per 10,000", analogous to how "percentage" means "per 100"
        let required_yes_of_total_basis_points =
            u128::from(percentage_of_total_required.basis_points.unwrap());
        let required_no_of_total_basis_points =
            10_000u128.saturating_sub(required_yes_of_total_basis_points);

        debug_assert!(required_yes_of_total_basis_points <= 10_000);

        if yes * 10_000 > total * required_yes_of_total_basis_points {
            Vote::Yes
        } else if no * 10_000 >= total * required_no_of_total_basis_points {
            Vote::No
        } else {
            Vote::Unspecified
        }
    }

    /// Return whether the proposal can be purged from storage, e.g.,
    /// if it is allowed to be garbage collected.
    pub(crate) fn can_be_purged(&self, now_seconds: u64) -> bool {
        // Retain proposals that have not gone through the full lifecycle.
        if !self.status().is_final() {
            return false;
        }
        if !self.reward_status(now_seconds).is_final() {
            return false;
        }

        // At this point, we can let go of most proposals. The only special case is
        // TransferSnsTreasuryFunds and MintSnsTokens (the common thread between these is that these
        // affect the value of the treasury). We want to hang onto those for at least 7 days after
        // they have been successfully executed. This is because they are still needed for the
        // purposes of limiting amounts.
        let Some(proposal) = &self.proposal else {
            log!(ERROR, "Proposal {:?} missing `proposal` field", self.id);
            return true;
        };
        let retention_duration_seconds = match &proposal.action {
            Some(Action::TransferSnsTreasuryFunds(_)) => {
                EXECUTED_TRANSFER_SNS_TREASURY_FUNDS_PROPOSAL_RETENTION_DURATION_SECONDS
            }
            Some(Action::MintSnsTokens(_)) => {
                EXECUTED_MINT_SNS_TOKENS_PROPOSAL_RETENTION_DURATION_SECONDS
            }
            _ => return true,
        };

        // Only hang onto proposals that were executed recently enough. In other words, let older
        // proposals age out.
        let earliest_unpurgeable_executed_timestamp_seconds =
            now_seconds - retention_duration_seconds;
        self.executed_timestamp_seconds < earliest_unpurgeable_executed_timestamp_seconds
    }

    /// Returns a clone of self, except that "large blob fields" are replaced
    /// with a (UTF-8 encoded) textual summary of their contents. See
    /// summarize_blob_field.
    pub(crate) fn limited_for_get_proposal(&self) -> Self {
        Self {
            proposal: self
                .proposal
                .as_ref()
                .map(|proposal| proposal.limited_for_get_proposal()),
            ..self.clone()
        }
    }

    /// Creates a limited version of the proposal data, suitable for listing proposals.
    ///
    /// Specifically, remove the ballots in the proposal data and possibly the proposal's payload.
    /// The payload is removed if the proposal is an ExecuteNervousSystemFunction or if it's
    /// a UpgradeSnsControlledCanister. The text rendering should include displayable information about
    /// the payload contents already.
    pub fn limited_for_list_proposals(&self, caller_neurons_set: &HashSet<String>) -> Self {
        let ProposalData {
            action,
            id,
            proposer,
            reject_cost_e8s,
            proposal,
            proposal_creation_timestamp_seconds,
            ballots,
            latest_tally,
            decided_timestamp_seconds,
            executed_timestamp_seconds,
            failed_timestamp_seconds,
            failure_reason,
            reward_event_round,
            wait_for_quiet_state,
            payload_text_rendering: _,
            is_eligible_for_rewards,
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            reward_event_end_timestamp_seconds,
            minimum_yes_proportion_of_total,
            minimum_yes_proportion_of_exercised,
            action_auxiliary,
        } = self;

        let limited_ballots: BTreeMap<_, _> = ballots
            .iter()
            .filter(|(neuron_id, _)| caller_neurons_set.contains(*neuron_id))
            .map(|(neuron_id, ballot)| (neuron_id.clone(), ballot.clone()))
            .take(MAX_NUMBER_OF_BALLOTS_IN_LIST_PROPOSALS_RESPONSE)
            .collect();

        ProposalData {
            action: *action,
            id: *id,
            proposer: proposer.clone(),
            reject_cost_e8s: *reject_cost_e8s,
            proposal_creation_timestamp_seconds: *proposal_creation_timestamp_seconds,
            latest_tally: latest_tally.clone(),
            decided_timestamp_seconds: *decided_timestamp_seconds,
            executed_timestamp_seconds: *executed_timestamp_seconds,
            failed_timestamp_seconds: *failed_timestamp_seconds,
            failure_reason: failure_reason.clone(),
            reward_event_round: *reward_event_round,
            wait_for_quiet_state: wait_for_quiet_state.clone(),
            is_eligible_for_rewards: *is_eligible_for_rewards,
            initial_voting_period_seconds: *initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: *wait_for_quiet_deadline_increase_seconds,
            reward_event_end_timestamp_seconds: *reward_event_end_timestamp_seconds,
            minimum_yes_proportion_of_total: *minimum_yes_proportion_of_total,
            minimum_yes_proportion_of_exercised: *minimum_yes_proportion_of_exercised,
            action_auxiliary: action_auxiliary.clone(),

            // The following fields are truncated:
            payload_text_rendering: None,
            proposal: proposal.as_ref().map(Proposal::limited_for_list_proposals),
            ballots: limited_ballots,
        }
    }
}

impl ProposalDecisionStatus {
    /// Return true if the proposal decision status is 'final', i.e., the proposal
    /// decision status is one that cannot be changed anymore.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            ProposalDecisionStatus::Rejected
                | ProposalDecisionStatus::Executed
                | ProposalDecisionStatus::Failed
        )
    }
}

impl ProposalRewardStatus {
    /// Return true if this reward status is 'final', i.e., the proposal
    /// reward status is one that cannot be changed anymore.
    pub fn is_final(&self) -> bool {
        matches!(self, ProposalRewardStatus::Settled)
    }
}

pub(crate) fn transfer_sns_treasury_funds_amount_is_small_enough_at_execution_time_or_err<'a>(
    transfer: &TransferSnsTreasuryFunds,
    valuation: Valuation,
    proposals: impl Iterator<Item = &'a ProposalData>,
    now_timestamp_seconds: u64,
) -> Result<(), GovernanceError> {
    let allowance_tokens = transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(valuation)
        .map_err(|err| {
            // This should not be possible, because valuation was already used the same way during
            // proposal submission/creation/validation.
            GovernanceError::new_with_message(
                ErrorType::InconsistentInternalData,
                format!(
                    "Unable to determined upper bound on the amount of \
                     TransferSnsTreasuryFunds proposals: {:?}\nvaluation:{:?}",
                    err, valuation,
                ),
            )
        })?;

    // The total calculated here _could_ be different from what was calculated at proposal
    // submission/creation time. A difference would result from the execution of (another)
    // TransferSnsTreasuryFunds proposal between now and then.
    let spent_tokens = total_treasury_transfer_amount_tokens(
        proposals,
        transfer.from_treasury(),
        now_timestamp_seconds - 7 * ONE_DAY_SECONDS,
    )
    .map_err(|message| {
        GovernanceError::new_with_message(ErrorType::InconsistentInternalData, message)
    })?;

    let remainder_tokens = allowance_tokens - spent_tokens;
    let transfer_amount_tokens = denominations_to_tokens(transfer.amount_e8s, E8)
        // This Err cannot be provoked, because we are dividing a u64 (amount_e8s) by a positive
        // integer (E8).
        .ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::UnreachableCode,
                format!(
                    "Unable to convert proposals amount {} e8s to tokens.",
                    transfer.amount_e8s,
                ),
            )
        })?;
    if transfer_amount_tokens > remainder_tokens {
        return Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!(
                "Executing this proposal is not allowed at this time, because doing \
                 so would cause the 7 day upper bound of {} tokens to be exceeded. \
                 Maybe, try again later? The total amount transferred in the past \
                 7 days stands at {} tokens, and the amount in this proposal is {} \
                 tokens. The upper bound is based on treasury valuation factors at \
                 the time of proposal submission: {:?}",
                allowance_tokens, spent_tokens, transfer_amount_tokens, valuation,
            ),
        ));
    }

    Ok(())
}

/// Returns the total amount (in e8s) that was transfered from the treasury via
/// TransferSnsTreasuryFunds proposals, or None if there was an overflow.
///
/// Arguments:
/// * `proposals` - Self-explanatory.
/// * `filter_from_treasury` - Specify the token type (ICP or SNS). The name of this parameter is
///   based on TransferSnsTreasuryFunds.from_treasury, which specifies which token the proposal is
///   concerned about. Furthermore, that field is compared against this parameter.
/// * `min_executed_timestamp_seconds` - Older proposals are not considered.
///
/// Currently, the only known way for this to return Err is if proposals is not valid. Specifically,
/// we require that the `proposal` (singular) field in each element of `proposals` (plural) is
/// Some(...).
fn total_treasury_transfer_amount_tokens<'a>(
    proposals: impl Iterator<Item = &'a ProposalData>,
    filter_from_treasury: TransferFrom,
    min_executed_timestamp_seconds: u64,
) -> Result<Decimal, String> {
    let filter_proposal_action_amount_e8s = |action: &Action| {
        let transfer = match action {
            Action::TransferSnsTreasuryFunds(ok) => ok,
            // Skip other types of proposals.
            _ => return None,
        };

        let is_proposal_token_relevant =
            // Very confusingly, the from_treasury field specifies which token
            // the proposal is about.
            TransferFrom::try_from(transfer.from_treasury) == Ok(filter_from_treasury);
        if !is_proposal_token_relevant {
            return None;
        }

        Some(transfer.amount_e8s)
    };

    total_proposal_amounts_tokens(
        proposals,
        &format!("{:?} transfer", filter_from_treasury),
        filter_proposal_action_amount_e8s,
        min_executed_timestamp_seconds,
    )
}

/// Analogous to total_treasury_transfer_amount_tokens. Of course, this considers MintSnsTokens
/// proposals instead of TransferSnsTreasuryFunds proposals.
#[allow(unused)] // TODO(NNS1-2910): Delete this.
fn total_minting_amount_tokens<'a>(
    proposals: impl Iterator<Item = &'a ProposalData>,
    min_executed_timestamp_seconds: u64,
) -> Result<Decimal, String> {
    let filter_proposal_action_amount_e8s = |action: &Action| {
        let mint = match action {
            Action::MintSnsTokens(ok) => ok,
            // Skip other types of proposals.
            _ => return None,
        };

        mint.amount_e8s
    };

    total_proposal_amounts_tokens(
        proposals,
        "MintSnsTokens",
        filter_proposal_action_amount_e8s,
        min_executed_timestamp_seconds,
    )
}

/// Where most of the implementation for other total_*_amount_tokens functions lives. The only
/// difference among those functions is which actions are relevant.
fn total_proposal_amounts_tokens<'a>(
    proposals: impl Iterator<Item = &'a ProposalData>,
    proposal_type_description: &str,
    filter_proposal_action_amount_e8s: impl Fn(&Action) -> Option<u64>,
    min_executed_timestamp_seconds: u64,
) -> Result<Decimal, String> {
    let mut total_tokens = Decimal::from(0);

    for proposal in proposals {
        // Skip proposals that were not executed recently enough. (This also skips proposals that
        // were rejected, or execution failed).
        if proposal.executed_timestamp_seconds < min_executed_timestamp_seconds {
            continue;
        }

        let proposal_id = proposal.id;

        // Filter based on action.
        let Some(proposal) = &proposal.proposal else {
            return Err(format!(
                "ProposalData {:?} is invalid, because its `proposal` field is empty!",
                proposal_id,
            ));
        };
        let Some(proposal_amount_e8s) = proposal
            .action
            .as_ref()
            .and_then(&filter_proposal_action_amount_e8s)
        else {
            continue;
        };

        // Convert from e8s (u64) to tokens (Decimal).
        let proposal_amount_tokens = denominations_to_tokens(proposal_amount_e8s, E8)
            // This Err is impossible, because we are dividing a u64 by a positive number.
            .ok_or_else(|| {
                format!(
                    "Failed to total amount in recent {} proposals: \
                     Unable to convert amount {} e8s to whole tokens in proposal {:?}.",
                    proposal_type_description, proposal_amount_e8s, proposal_id,
                )
            })?;

        total_tokens = total_tokens
            .checked_add(proposal_amount_tokens)
            // Provoking this Err is infeasible: there would have to be > u32::MAX executed
            // TransferSnsTreasuryFunds proposals that have amount = u64::MAX e8s. In that case,
            // something much worse than causing this to quietly overflow is probably possible.
            .ok_or_else(|| {
                format!(
                    "Failed to total amount in recent TransferSnsTreasuryFunds proposals: \
                     overflow while performing {} + {}.",
                    total_tokens, proposal_amount_tokens,
                )
            })?;
    }

    Ok(total_tokens)
}

#[cfg(test)]
mod treasury_tests;

#[cfg(test)]
mod minting_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pb::v1::{
            governance::{self, Version},
            Ballot, Empty, Governance as GovernanceProto, NeuronId, Proposal, ProposalId,
            Subaccount, WaitForQuietState,
        },
        sns_upgrade::{
            CanisterSummary, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
            GetProposalIdThatAddedWasmRequest, GetProposalIdThatAddedWasmResponse,
            GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse, SnsVersion,
        },
        tests::{assert_is_err, assert_is_ok},
        types::test_helpers::NativeEnvironment,
    };
    use candid::Encode;
    use futures::FutureExt;
    use ic_base_types::{NumBytes, PrincipalId};
    use ic_crypto_sha2::Sha256;
    use ic_nervous_system_clients::canister_status::{CanisterStatusResultV2, CanisterStatusType};
    use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
    use ic_nns_constants::SNS_WASM_CANISTER_ID;
    use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
    use ic_test_utilities_types::ids::canister_test_id;
    use lazy_static::lazy_static;
    use maplit::{btreemap, hashset};
    use std::convert::TryFrom;

    pub const FORBIDDEN_CANISTER: CanisterId = CanisterId::ic_00();

    lazy_static! {
        static ref DEFAULT_PARAMS: NervousSystemParameters =
            NervousSystemParameters::with_default_values();
        static ref EMPTY_FUNCTIONS: BTreeMap<u64, NervousSystemFunction> = BTreeMap::new();
        static ref SNS_ROOT_CANISTER_ID: CanisterId = canister_test_id(500);
        static ref SNS_GOVERNANCE_CANISTER_ID: CanisterId = canister_test_id(501);
        static ref SNS_LEDGER_CANISTER_ID: CanisterId = canister_test_id(502);
        static ref SNS_SWAP_CANISTER_ID: CanisterId = canister_test_id(503);
        static ref FAKE_ENV: Box<dyn Environment> =
            Box::new(NativeEnvironment::new(Some(*SNS_GOVERNANCE_CANISTER_ID)));
    }

    fn governance_proto_for_proposal_tests(deployed_version: Option<Version>) -> GovernanceProto {
        GovernanceProto {
            root_canister_id: Some(PrincipalId::from(*SNS_ROOT_CANISTER_ID)),
            ledger_canister_id: Some(PrincipalId::from(*SNS_LEDGER_CANISTER_ID)),
            swap_canister_id: Some(PrincipalId::from(*SNS_SWAP_CANISTER_ID)),

            sns_metadata: None,
            sns_initialization_parameters: "".to_string(),
            parameters: Some(DEFAULT_PARAMS.clone()),
            id_to_nervous_system_functions: EMPTY_FUNCTIONS.clone(),

            neurons: Default::default(),
            proposals: Default::default(),

            latest_reward_event: None,
            in_flight_commands: Default::default(),
            genesis_timestamp_seconds: 0,
            metrics: None,
            mode: governance::Mode::Normal.into(),
            deployed_version,
            pending_version: None,
            is_finalizing_disburse_maturity: None,
            maturity_modulation: None,
        }
    }

    fn validate_default_proposal(proposal: &Proposal) -> Result<String, String> {
        let governance_proto = governance_proto_for_proposal_tests(None);
        validate_and_render_proposal(
            proposal,
            &**FAKE_ENV,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .map(|(rendering, _action_auxiliary)| rendering)
    }

    fn validate_default_action(action: &Option<proposal::Action>) -> Result<String, String> {
        let governance_proto = governance_proto_for_proposal_tests(None);
        validate_and_render_action(
            action,
            &**FAKE_ENV,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .map(|(rendering, _action_auxiliary)| rendering)
    }

    fn basic_principal_id() -> PrincipalId {
        PrincipalId::try_from(vec![42_u8]).unwrap()
    }

    fn basic_motion_proposal() -> Proposal {
        let result = Proposal {
            title: "title".into(),
            summary: "summary".into(),
            url: "http://www.example.com".into(),
            action: Some(proposal::Action::Motion(Motion::default())),
        };
        assert_is_ok(validate_default_proposal(&result));
        result
    }

    fn subaccount_1() -> Subaccount {
        let mut subaccount = vec![0; 32];
        subaccount[31] = 1;
        Subaccount { subaccount }
    }

    #[test]
    fn proposal_title_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.title = "".into();

        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_TITLE_BYTES_MAX {
            proposal.title.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.title.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_summary_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.summary = "".into();
        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_SUMMARY_BYTES_MAX {
            proposal.summary.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.summary.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_url_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.url = "".into();
        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_URL_CHAR_MAX {
            proposal.url.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.url.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_action_is_required() {
        assert_is_err(validate_default_action(&None));
    }

    #[test]
    fn unspecified_action_is_invalid() {
        assert_is_err(validate_default_action(&Some(
            proposal::Action::Unspecified(Empty {}),
        )));
    }

    #[test]
    fn motion_text_not_too_long() {
        let mut proposal = basic_motion_proposal();

        fn validate_is_ok(proposal: &Proposal) {
            assert_is_ok(validate_default_proposal(proposal));
            assert_is_ok(validate_default_action(&proposal.action));
            match proposal.action.as_ref().unwrap() {
                proposal::Action::Motion(motion) => {
                    assert_is_ok(validate_and_render_motion(motion))
                }
                _ => panic!("proposal.action is not Motion."),
            }
        }

        validate_is_ok(&proposal);
        for _ in 0..PROPOSAL_MOTION_TEXT_BYTES_MAX {
            // Push a character to motion_text.
            match proposal.action.as_mut().unwrap() {
                proposal::Action::Motion(motion) => motion.motion_text.push('a'),
                _ => panic!("proposal.action is not Motion."),
            }

            validate_is_ok(&proposal);
        }

        // The straw that breaks the camel's back: push one more character to motion_text.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::Motion(motion) => motion.motion_text.push('a'),
            _ => panic!("proposal.action is not Motion."),
        }

        // Assert that proposal is no longer ok.
        assert_is_err(validate_default_proposal(&proposal));
        assert_is_err(validate_default_action(&proposal.action));
        match proposal.action.as_ref().unwrap() {
            proposal::Action::Motion(motion) => assert_is_err(validate_and_render_motion(motion)),
            _ => panic!("proposal.action is not Motion."),
        }
    }

    #[test]
    fn render_upgrade_sns_controlled_canister_proposal() {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_upgrade_arg: None,
            mode: Some(CanisterInstallModeProto::Upgrade.into()),
        };
        let text = validate_and_render_upgrade_sns_controlled_canister(&upgrade).unwrap();

        assert_eq!(
            text,
            r#"# Proposal to upgrade SNS controlled canister:

## Canister id: bg4sm-wzk

## Canister wasm sha256: 93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476

## Mode: Upgrade

## No upgrade arg"#
                .to_string()
        );
    }

    #[test]
    fn render_upgrade_sns_controlled_canister_proposal_with_upgrade_args() {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_upgrade_arg: Some(vec![10, 20, 30, 40, 50, 60, 70, 80]),
            mode: Some(CanisterInstallModeProto::Upgrade.into()),
        };
        let text = validate_and_render_upgrade_sns_controlled_canister(&upgrade).unwrap();

        assert_eq!(
            text,
            r#"# Proposal to upgrade SNS controlled canister:

## Canister id: bg4sm-wzk

## Canister wasm sha256: 93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476

## Mode: Upgrade

## Upgrade arg sha256: 73f1171adc7e49b09423da2515a1077e3cc63e3fabcb9846cac437d044ac57ec"#
                .to_string()
        );
    }

    #[test]
    fn render_upgrade_sns_controlled_canister_proposal_validates_mode() {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_upgrade_arg: None,
            mode: Some(100), // 100 is not a valid mode
        };
        let text = validate_and_render_upgrade_sns_controlled_canister(&upgrade).unwrap_err();
        assert!(text.contains("Invalid mode"));
    }

    fn basic_upgrade_sns_controlled_canister_proposal() -> Proposal {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_upgrade_arg: None,
            mode: Some(CanisterInstallModeProto::Upgrade.into()),
        };
        assert_is_ok(validate_and_render_upgrade_sns_controlled_canister(
            &upgrade,
        ));

        let mut result = basic_motion_proposal();
        result.action = Some(proposal::Action::UpgradeSnsControlledCanister(upgrade));

        assert_is_ok(validate_default_action(&result.action));
        assert_is_ok(validate_default_proposal(&result));

        result
    }

    fn assert_validate_upgrade_sns_controlled_canister_is_err(proposal: &Proposal) {
        assert_is_err(validate_default_proposal(proposal));
        assert_is_err(validate_default_action(&proposal.action));

        match proposal.action.as_ref().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade))
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }
    }

    #[test]
    fn upgrade_must_have_canister_id() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.canister_id = None;
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    /// The minimum WASM is 8 bytes long. Therefore, we must not allow the
    /// new_canister_wasm field to be empty.
    #[test]
    fn upgrade_wasm_must_be_non_empty() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.new_canister_wasm = vec![];
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    #[test]
    fn upgrade_wasm_must_not_be_dead_beef() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                // This is invalid, because it does not have the magical first
                // four bytes that a WASM is supposed to have. (Instead, the
                // first four bytes of this Vec are 0xDeadBeef.)
                upgrade.new_canister_wasm = vec![0xde, 0xad, 0xbe, 0xef, 1, 0, 0, 0];
                assert!(upgrade.new_canister_wasm.len() == 8); // The minimum wasm len.
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    #[test]
    fn upgrade_wasm_can_be_gzipped() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.new_canister_wasm =
                    vec![0x1f, 0x8b, 0x08, 0x08, 0xa3, 0x8e, 0xcf, 0x63, 0, 0x03];
                assert!(upgrade.new_canister_wasm.len() >= 8); // The minimum wasm len.
                assert_is_ok(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_is_ok(validate_default_proposal(&proposal));
        assert_is_ok(validate_default_action(&proposal.action));
    }

    fn basic_add_nervous_system_function_proposal() -> Proposal {
        let nervous_system_function = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from_u64(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        let rendered = validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function,
            &EMPTY_FUNCTIONS,
        )
        .unwrap();

        // Assert that the output is pretty-printed by checking for at least one
        // newline.
        assert!(rendered.contains("NervousSystemFunction {\n"));

        let mut result = basic_motion_proposal();
        result.action = Some(proposal::Action::AddGenericNervousSystemFunction(
            nervous_system_function,
        ));

        assert_is_ok(validate_default_action(&result.action));
        assert_is_ok(validate_default_proposal(&result));

        result
    }

    #[test]
    fn add_nervous_system_function_function_must_have_fields_set() {
        let mut proposal = basic_add_nervous_system_function_proposal();

        // Make sure function type is invalid
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.function_type = None;
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure invalid/unset ids are invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.id = 100;
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure name is set
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.name = "".to_string();
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure name is not too big
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.name = "X".repeat(257);
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure description is not too big
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.description = Some("X".repeat(10010));
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the target canister is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            target_canister_id, ..
                        },
                    )) => {
                        *target_canister_id = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the target method name is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            target_method_name, ..
                        },
                    )) => {
                        *target_method_name = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the validator canister id is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            validator_canister_id,
                            ..
                        },
                    )) => {
                        *validator_canister_id = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the validator method name is invalid.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            validator_method_name,
                            ..
                        },
                    )) => {
                        *validator_method_name = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    &hashset![FORBIDDEN_CANISTER],
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }
    }

    #[test]
    fn add_nervous_system_function_cant_reuse_ids() {
        let nervous_system_function = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from_u64(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        let mut functions_map = BTreeMap::new();
        assert_is_ok(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function,
            &functions_map,
        ));

        functions_map.insert(1000, nervous_system_function.clone());

        let rendered =
            validate_and_render_remove_nervous_generic_system_function(1000, &functions_map)
                .unwrap();

        // Assert that the output is pretty-printed by checking for at least one
        // newline.
        assert!(rendered.contains("NervousSystemFunction {\n"));

        functions_map.insert(1000, (*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER).clone());

        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function,
            &functions_map,
        ));
    }

    #[test]
    fn add_nervous_system_function_cant_exceed_maximum() {
        let mut functions_map = BTreeMap::new();

        // Fill up the functions_map with the allowed number of functions
        for i in 0..MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS {
            let nervous_system_function = NervousSystemFunction {
                id: i as u64 + 1000, // Valid ids for GenericNervousSystemFunction start at 1000
                name: "a".to_string(),
                description: None,
                function_type: Some(FunctionType::GenericNervousSystemFunction(
                    GenericNervousSystemFunction {
                        target_canister_id: Some(CanisterId::from_u64(i as u64).get()),
                        target_method_name: Some("test_method".to_string()),
                        validator_canister_id: Some(CanisterId::from_u64(i as u64).get()),
                        validator_method_name: Some("test_validator_method".to_string()),
                    },
                )),
            };
            functions_map.insert(i as u64, nervous_system_function);
        }

        let nervous_system_function = NervousSystemFunction {
            id: u64::MAX, // id that is not taken
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(u64::MAX).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(u64::MAX).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        // Attempting to insert another GenericNervousSystemFunction should fail validation
        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function,
            &functions_map,
        ));
    }

    // Create a dummy status with module hash and CanisterStatusType
    fn canister_status_for_test(
        module_hash: Vec<u8>,
        status: CanisterStatusType,
    ) -> CanisterStatusResultV2 {
        CanisterStatusResultV2::new(
            status,
            Some(module_hash),
            vec![],
            NumBytes::new(0),
            0,
            0,
            Some(0),
            0,
            0,
            0,
        )
    }

    /// This assumes that the current_version is:
    /// SnsVersion {
    ///     root_wasm_hash: Sha256::hash(&[1]),
    ///     governance_wasm_hash:  Sha256::hash(&[2]),
    ///     ledger_wasm_hash:  Sha256::hash(&[3]),
    ///     swap_wasm_hash:  Sha256::hash(&[4]),
    ///     archive_wasm_hash: Sha256::hash(&[5])
    /// }
    ///
    /// It also is set to only upgrade root.
    fn setup_for_upgrade_sns_to_next_version_validation_tests(
    ) -> (NativeEnvironment, GovernanceProto) {
        let expected_wasm_hash_requested = Sha256::hash(&[6]).to_vec();
        let root_canister_id = *SNS_ROOT_CANISTER_ID;

        let governance_canister_id = *SNS_GOVERNANCE_CANISTER_ID;
        let ledger_canister_id = *SNS_LEDGER_CANISTER_ID;
        let swap_canister_id = canister_test_id(503);
        let ledger_archive_ids = [canister_test_id(504)];
        let index_canister_id = canister_test_id(505);

        let root_hash = Sha256::hash(&[1]).to_vec();
        let governance_hash = Sha256::hash(&[2]).to_vec();
        let ledger_hash = Sha256::hash(&[3]).to_vec();
        let swap_hash = Sha256::hash(&[4]).to_vec();
        let archive_hash = Sha256::hash(&[5]).to_vec();
        let index_hash = Sha256::hash(&[7]).to_vec();

        let next_sns_version = SnsVersion {
            root_wasm_hash: Sha256::hash(&[6]).to_vec(),
            governance_wasm_hash: governance_hash.clone(),
            ledger_wasm_hash: ledger_hash.clone(),
            swap_wasm_hash: swap_hash.clone(),
            archive_wasm_hash: archive_hash.clone(),
            index_wasm_hash: index_hash.clone(),
        };

        let current_governance_proto_version = Version {
            root_wasm_hash: root_hash.clone(),
            governance_wasm_hash: governance_hash.clone(),
            ledger_wasm_hash: ledger_hash.clone(),
            swap_wasm_hash: swap_hash.clone(),
            archive_wasm_hash: archive_hash.clone(),
            index_wasm_hash: index_hash.clone(),
        };

        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        env.default_canister_call_response =
            Err((Some(1), "Oh no something was not covered!".to_string()));
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&GetSnsCanistersSummaryResponse {
                root: Some(CanisterSummary {
                    status: Some(canister_status_for_test(
                        root_hash,
                        CanisterStatusType::Running
                    )),
                    canister_id: Some(root_canister_id.get())
                }),
                governance: Some(CanisterSummary {
                    status: Some(canister_status_for_test(
                        governance_hash,
                        CanisterStatusType::Running
                    )),
                    canister_id: Some(governance_canister_id.get())
                }),
                ledger: Some(CanisterSummary {
                    status: Some(canister_status_for_test(
                        ledger_hash,
                        CanisterStatusType::Running
                    )),
                    canister_id: Some(ledger_canister_id.get())
                }),
                swap: Some(CanisterSummary {
                    status: Some(canister_status_for_test(
                        swap_hash,
                        CanisterStatusType::Running
                    )),
                    canister_id: Some(swap_canister_id.get())
                }),
                dapps: vec![],
                archives: ledger_archive_ids
                    .iter()
                    .map(|canister_id| CanisterSummary {
                        status: Some(canister_status_for_test(
                            archive_hash.clone(),
                            CanisterStatusType::Running
                        )),
                        canister_id: Some(canister_id.get())
                    })
                    .collect(),
                index: Some(CanisterSummary {
                    status: Some(canister_status_for_test(
                        index_hash,
                        CanisterStatusType::Running
                    )),
                    canister_id: Some(index_canister_id.get())
                }),
            })
            .unwrap()),
        );
        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_next_sns_version",
            Encode!(&GetNextSnsVersionRequest {
                current_version: Some(current_governance_proto_version.clone().into())
            })
            .unwrap(),
            Ok(Encode!(&GetNextSnsVersionResponse {
                next_version: Some(next_sns_version)
            })
            .unwrap()),
        );
        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_proposal_id_that_added_wasm",
            Encode!(&GetProposalIdThatAddedWasmRequest {
                hash: expected_wasm_hash_requested
            })
            .unwrap(),
            Ok(Encode!(&GetProposalIdThatAddedWasmResponse {
                proposal_id: Some(2),
            })
            .unwrap()),
        );

        let mut governance_proto =
            governance_proto_for_proposal_tests(Some(current_governance_proto_version));
        governance_proto.root_canister_id = Some(root_canister_id.get());

        (env, governance_proto)
    }

    #[test]
    fn upgrade_sns_to_next_version_renders_correctly() {
        let (env, governance_proto) = setup_for_upgrade_sns_to_next_version_validation_tests();
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        // Same id as setup_env_for_upgrade_sns_proposals
        let (actual_text, _) = validate_and_render_action(
            &Some(action),
            &env,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .unwrap();

        let expected_text = r"# Proposal to upgrade SNS Root to next version:

## SNS Current Version:
Version {
    root: 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a,
    governance: dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986,
    ledger: 084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5,
    swap: e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71,
    archive: e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db,
    index: ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879,
}

## SNS New Version:
Version {
    root: 67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6,
    governance: dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986,
    ledger: 084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5,
    swap: e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71,
    archive: e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db,
    index: ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879,
}

## Canisters to be upgraded: q7t5l-saaaa-aaaaa-aah2a-cai
## Upgrade Version: 67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6
## Proposal ID of the NNS proposal that blessed this WASM version: NNS Proposal 2
";
        assert_eq!(actual_text, expected_text);
    }

    #[test]
    fn fail_validation_for_upgrade_sns_to_next_version_when_no_next_version() {
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let (mut env, governance_proto) = setup_for_upgrade_sns_to_next_version_validation_tests();

        let root_hash = Sha256::hash(&[1]).to_vec();
        let governance_hash = Sha256::hash(&[2]).to_vec();
        let ledger_hash = Sha256::hash(&[3]).to_vec();
        let swap_hash = Sha256::hash(&[4]).to_vec();
        let archive_hash = Sha256::hash(&[5]).to_vec();
        let index_hash = Sha256::hash(&[7]).to_vec();

        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_next_sns_version",
            Encode!(&GetNextSnsVersionRequest {
                current_version: Some(SnsVersion {
                    root_wasm_hash: root_hash,
                    governance_wasm_hash: governance_hash,
                    ledger_wasm_hash: ledger_hash,
                    swap_wasm_hash: swap_hash,
                    archive_wasm_hash: archive_hash,
                    index_wasm_hash: index_hash,
                })
            })
            .unwrap(),
            Ok(Encode!(&GetNextSnsVersionResponse { next_version: None }).unwrap()),
        );
        let err = validate_and_render_action(
            &Some(action),
            &env,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .unwrap_err();

        let target_string = "There is no next version found for the current SNS version: Version {";
        assert!(
            err.contains(target_string),
            "Test did not contain '{}'.  Actual: {}",
            target_string,
            err
        );
    }

    #[test]
    fn fail_validation_for_upgrade_sns_to_next_version_when_more_than_one_canister_change_in_version(
    ) {
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let (mut env, governance_proto) = setup_for_upgrade_sns_to_next_version_validation_tests();

        let root_hash = Sha256::hash(&[1]).to_vec();
        let governance_hash = Sha256::hash(&[2]).to_vec();
        let ledger_hash = Sha256::hash(&[3]).to_vec();
        let swap_hash = Sha256::hash(&[4]).to_vec();
        let archive_hash = Sha256::hash(&[5]).to_vec();
        let index_hash = Sha256::hash(&[7]).to_vec();

        let current_version = SnsVersion {
            root_wasm_hash: root_hash.clone(),
            governance_wasm_hash: governance_hash.clone(),
            ledger_wasm_hash: ledger_hash,
            swap_wasm_hash: swap_hash,
            archive_wasm_hash: archive_hash.clone(),
            index_wasm_hash: index_hash.clone(),
        };
        let next_version = SnsVersion {
            root_wasm_hash: root_hash,
            governance_wasm_hash: governance_hash,
            ledger_wasm_hash: Sha256::hash(&[5]).to_vec(),
            swap_wasm_hash: Sha256::hash(&[6]).to_vec(),
            archive_wasm_hash: archive_hash,
            index_wasm_hash: index_hash,
        };

        env.set_call_canister_response(
            SNS_WASM_CANISTER_ID,
            "get_next_sns_version",
            Encode!(&GetNextSnsVersionRequest {
                current_version: Some(current_version)
            })
            .unwrap(),
            Ok(Encode!(&GetNextSnsVersionResponse {
                next_version: Some(next_version)
            })
            .unwrap()),
        );
        let err = validate_and_render_action(
            &Some(action),
            &env,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .unwrap_err();

        assert!(err.contains(
            "There is more than one upgrade possible for UpgradeSnsToNextVersion Action.  \
            This is not currently supported."
        ))
    }

    #[test]
    fn fail_validation_for_upgrade_sns_to_next_version_with_empty_list_sns_canisters_response() {
        let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
        let (mut env, governance_proto) = setup_for_upgrade_sns_to_next_version_validation_tests();
        let root_canister_id = *SNS_ROOT_CANISTER_ID;

        let canisters_summary_response = GetSnsCanistersSummaryResponse {
            root: None,
            governance: None,
            ledger: None,
            swap: None,
            dapps: vec![],
            archives: vec![],
            index: None,
        };

        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&canisters_summary_response).unwrap()),
        );
        let err = validate_and_render_action(
            &Some(action),
            &env,
            &governance_proto,
            vec![FORBIDDEN_CANISTER],
        )
        .now_or_never()
        .unwrap()
        .unwrap_err();

        assert!(err.contains("Did not receive Root CanisterId from list_sns_canisters call"))
    }

    #[test]
    fn fail_validate_manage_sns_metadata() {
        let manage_sns_metadata = ManageSnsMetadata {
            url: None,
            name: None,
            description: None,
            logo: None,
        };

        let err = validate_and_render_manage_sns_metadata(&manage_sns_metadata).unwrap_err();

        assert!(err.contains(
            "Error: ManageSnsMetadata must change at least one value, all values are None"
        ));

        let manage_sns_metadata = ManageSnsMetadata {
            url: Some("X".repeat(SnsMetadata::MAX_URL_LENGTH + 1)),
            name: None,
            description: None,
            logo: None,
        };

        let err = validate_and_render_manage_sns_metadata(&manage_sns_metadata).unwrap_err();

        assert!(err.contains("SnsMetadata.url must be less than"));
    }

    #[test]
    fn add_nervous_system_function_cant_target_disallowed_canisters() {
        // Ensure that no other reason for failure exists before testing error cases
        let nervous_system_function_valid = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(2).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        let functions_map = BTreeMap::new();
        assert_is_ok(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function_valid,
            &functions_map,
        ));

        let nervous_system_function_invalid_target = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::ic_00().get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function_invalid_target,
            &functions_map,
        ));

        let nervous_system_function_invalid_validator = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::ic_00().get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &hashset![FORBIDDEN_CANISTER],
            &nervous_system_function_invalid_validator,
            &functions_map,
        ));
    }

    #[test]
    fn validate_and_render_transfer_sns_treasury_funds_renders_for_valid_inputs() {
        // Valid case
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 1000000,
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to transfer SNS Treasury funds:
## Source treasury: ICP Treasury (ICP Ledger)
## Amount: 0.01000000 ICP
## Amount (e8s): 1000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk
## Memo: 1000"
        );

        // Valid case with default sub-account
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 10000000,
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![0; 32]
                    })
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to transfer SNS Treasury funds:
## Source treasury: ICP Treasury (ICP Ledger)
## Amount: 0.10000000 ICP
## Amount (e8s): 10000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk
## Memo: 0"
        );

        // Valid case with non-default sub-account
        // The textual representation of ICRC-1 Accounts can be
        // found at https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/TextualEncoding.md
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: E8,
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(subaccount_1())
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to transfer SNS Treasury funds:
## Source treasury: ICP Treasury (ICP Ledger)
## Amount: 1.00000000 ICP
## Amount (e8s): 100000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk-msokwai.1
## Memo: 0"
        );

        // Valid transfer from SNS treasury
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::SnsTokenTreasury.into(),
                    amount_e8s: 1000000,
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to transfer SNS Treasury funds:
## Source treasury: SNS Token Treasury (SNS Ledger)
## Amount: 0.01000000 SNS Tokens
## Amount (e8s): 1000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk
## Memo: 1000"
        );
    }

    #[test]
    fn validate_and_render_transfer_sns_treasury_funds_no_principal() {
        // invalid case no principal
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 1000000,
                    memo: None,
                    to_principal: None,
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![0; 32]
                    })
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\nMust specify a principal to make the transfer to.".to_string()
        );
    }

    #[test]
    fn validate_and_render_transfer_sns_treasury_funds_anonymous_principal() {
        // invalid case anonymous principal
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 1000000,
                    memo: None,
                    to_principal: Some(PrincipalId::new_anonymous()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\nto_principal must not be anonymous.".to_string()
        );
    }

    #[test]
    fn validate_and_render_transfer_sns_treasury_funds_bad_subaccount() {
        // invalid case bad subaccount
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 1000000,
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![1, 2]
                    })
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\nInvalid subaccount".to_string()
        );
    }

    #[test]
    fn validate_and_render_transfer_sns_treasury_funds_amount_less_than_fee() {
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury.into(),
                    amount_e8s: 1000,
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\nFor transactions from ICP Treasury (ICP Ledger), the fee and minimum transaction is 10000 e8s"
        );
        assert_eq!(
            locally_validate_and_render_transfer_sns_treasury_funds(
                &TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::SnsTokenTreasury.into(),
                    amount_e8s: 999,
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                1000,
                vec![],
            )
            .unwrap_err(),
            "TransferSnsTreasuryFunds proposal was invalid for the following reason(s):\nFor transactions from SNS Token Treasury (SNS Ledger), the fee and minimum transaction is 1000 e8s"
        );
    }

    #[test]
    fn validate_and_render_mint_sns_tokens_renders_for_valid_inputs() {
        // Valid case
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(1000000),
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to mint SNS Tokens:
## Amount: 0.01000000 SNS Tokens
## Amount (e8s): 1000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk
## Memo: 1000"
        );

        // Valid case with default sub-account
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(10000000),
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![0; 32]
                    })
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to mint SNS Tokens:
## Amount: 0.10000000 SNS Tokens
## Amount (e8s): 10000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk
## Memo: 0"
        );

        // Valid case with non-default sub-account
        // The textual representation of ICRC-1 Accounts can be
        // found at https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/TextualEncoding.md
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(E8),
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(subaccount_1())
                },
                0,
                vec![],
            )
            .unwrap(),
            r"# Proposal to mint SNS Tokens:
## Amount: 1.00000000 SNS Tokens
## Amount (e8s): 100000000
## Target principal: bg4sm-wzk
## Target account: bg4sm-wzk-msokwai.1
## Memo: 0"
        );
    }

    #[test]
    fn validate_and_render_mint_sns_tokens_no_principal() {
        // invalid case no principal
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(1000000),
                    memo: None,
                    to_principal: None,
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![0; 32]
                    })
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "MintSnsTokens proposal was invalid for the following reason(s):\nMust specify a to_principal to make the mint to.".to_string()
        );
    }

    #[test]
    fn validate_and_render_mint_sns_tokens_anonymous_principal() {
        // invalid case anonymous principal
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(1000000),
                    memo: None,
                    to_principal: Some(PrincipalId::new_anonymous()),
                    to_subaccount: None
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "MintSnsTokens proposal was invalid for the following reason(s):\nto_principal must not be anonymous.".to_string()
        );
    }

    #[test]
    fn validate_and_render_mint_sns_tokens_bad_subaccount() {
        // invalid case bad subaccount
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(1000000),
                    memo: None,
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: Some(Subaccount {
                        subaccount: vec![1, 2]
                    })
                },
                0,
                vec![],
            )
            .unwrap_err(),
            "MintSnsTokens proposal was invalid for the following reason(s):\nInvalid subaccount"
                .to_string()
        );
    }

    #[test]
    fn validate_and_render_mint_sns_tokens_amount_less_than_fee() {
        assert_eq!(
            locally_validate_and_render_mint_sns_tokens(
                &MintSnsTokens {
                    amount_e8s: Some(999),
                    memo: Some(1000),
                    to_principal: Some(basic_principal_id()),
                    to_subaccount: None
                },
                1000,
                vec![],
            )
            .unwrap_err(),
            "MintSnsTokens proposal was invalid for the following reason(s):\nThe minimum mint is 1000 e8s"
        );
    }

    #[test]
    fn validate_and_render_register_dapp_canisters_lists_canisters() {
        let canister_ids = (0..10_u8)
            .map(|i| PrincipalId::try_from(vec![i]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let register_dapp_canisters = RegisterDappCanisters { canister_ids };
        let rendered_proposal = validate_and_render_register_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap();

        for canister_id in register_dapp_canisters.canister_ids {
            assert!(rendered_proposal.contains(&format!("\n- {canister_id}")), "rendered proposal \"{rendered_proposal}\" does not contain canister id \"- {canister_id}\"");
        }

        for line in rendered_proposal.lines() {
            assert!(!line.starts_with(char::is_whitespace), "rendered proposal \"{rendered_proposal}\" contains a line that starts with whitespace");
        }
    }

    #[test]
    fn validate_and_render_register_dapp_canisters_allows_max_canisters() {
        let canister_ids = (0..MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL)
            .map(|i| PrincipalId::new_user_test_id(i as u64))
            .collect::<Vec<_>>();
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let register_dapp_canisters = RegisterDappCanisters { canister_ids };
        let rendered_proposal = validate_and_render_register_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap();

        for canister_id in register_dapp_canisters.canister_ids {
            assert!(rendered_proposal.contains(&format!("\n- {canister_id}")), "rendered proposal \"{rendered_proposal}\" does not contain canister id \"- {canister_id}\"");
        }

        rendered_proposal.contains(&format!("{MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL}"));

        for line in rendered_proposal.lines() {
            assert!(!line.starts_with(char::is_whitespace), "rendered proposal \"{rendered_proposal}\" contains a line that starts with whitespace");
        }
    }

    #[test]
    fn validate_and_render_register_dapp_canisters_doesnt_allow_more_than_max_canisters() {
        let canister_ids = (0..(MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL + 1))
            .map(|i| PrincipalId::new_user_test_id(i as u64))
            .collect::<Vec<_>>();
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let register_dapp_canisters = RegisterDappCanisters { canister_ids };
        let rendered_error = validate_and_render_register_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap_err();

        rendered_error.contains(&format!("{MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL}"));
    }

    #[test]
    fn validate_and_render_register_dapp_canisters_doesnt_allow_invalid_canisters() {
        let canister_ids = (0..10_u8)
            .map(|i| PrincipalId::try_from(vec![i]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let disallowed_canister_ids = canister_ids
            .iter()
            // pick an arbitrary principalID
            .skip(4)
            .take(1)
            // convert to CanisterId
            .cloned()
            .map(CanisterId::unchecked_from_principal)
            .collect::<HashSet<_>>();

        let register_dapp_canisters = RegisterDappCanisters { canister_ids };
        let rendered_err = validate_and_render_register_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap_err();

        for canister_id in disallowed_canister_ids {
            assert!(
                rendered_err.contains(&format!("\n- {canister_id}")),
                "error message \"{rendered_err}\" does not contain canister id \"- {canister_id}\""
            );
        }

        for line in rendered_err.lines() {
            assert!(
                !line.starts_with(char::is_whitespace),
                "error message \"{rendered_err}\" contains a line that starts with whitespace"
            );
        }
    }

    #[test]
    fn validate_and_render_register_dapp_canisters_doesnt_allow_empty_id_list() {
        let canister_ids = vec![];
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let register_dapp_canisters = RegisterDappCanisters { canister_ids };
        let rendered_err = validate_and_render_register_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap_err();

        for line in rendered_err.lines() {
            assert!(
                !line.starts_with(char::is_whitespace),
                "error message \"{rendered_err}\" contains a line that starts with whitespace"
            );
        }
    }

    #[test]
    fn validate_and_render_deregister_dapp_canisters_lists_canisters() {
        let canister_ids = (0..10_u8)
            .map(|i| PrincipalId::try_from(vec![i]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let deregister_dapp_canisters = DeregisterDappCanisters {
            canister_ids,
            new_controllers: vec![*TEST_USER1_PRINCIPAL],
        };
        let rendered_proposal = validate_and_render_deregister_dapp_canisters(
            &deregister_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap();

        for canister_id in deregister_dapp_canisters.canister_ids {
            assert!(rendered_proposal.contains(&format!("\n- {canister_id}")), "rendered proposal \"{rendered_proposal}\" does not contain canister id {canister_id}");
        }

        for line in rendered_proposal.lines() {
            assert!(!line.starts_with(char::is_whitespace), "rendered proposal \"{rendered_proposal}\" contains a line that starts with whitespace");
        }
    }

    #[test]
    fn validate_and_render_deregister_dapp_canisters_doesnt_allow_invalid_canisters() {
        let canister_ids = (0..10_u8)
            .map(|i| PrincipalId::try_from(vec![i]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let disallowed_canister_ids = canister_ids
            .iter()
            // pick an arbitrary principalID
            .skip(4)
            .take(1)
            // convert to CanisterId
            .cloned()
            .map(CanisterId::unchecked_from_principal)
            .collect::<HashSet<_>>();

        let deregister_dapp_canisters = DeregisterDappCanisters {
            canister_ids,
            new_controllers: vec![*TEST_USER1_PRINCIPAL],
        };
        let rendered_err = validate_and_render_deregister_dapp_canisters(
            &deregister_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap_err();

        for canister_id in disallowed_canister_ids {
            assert!(
                rendered_err.contains(&format!("\n- {canister_id}")),
                "error message \"{rendered_err}\" does not contain canister id {canister_id}"
            );
        }

        for line in rendered_err.lines() {
            assert!(
                !line.starts_with(char::is_whitespace),
                "error message \"{rendered_err}\" contains a line that starts with whitespace"
            );
        }
    }

    #[test]
    fn validate_and_render_deregister_dapp_canisters_doesnt_allow_empty_id_list() {
        let canister_ids = vec![];
        let disallowed_canister_ids: HashSet<CanisterId> = HashSet::new();

        let register_dapp_canisters = DeregisterDappCanisters {
            canister_ids,
            new_controllers: vec![*TEST_USER1_PRINCIPAL],
        };
        let rendered_err = validate_and_render_deregister_dapp_canisters(
            &register_dapp_canisters,
            &disallowed_canister_ids,
        )
        .unwrap_err();

        for line in rendered_err.lines() {
            assert!(
                !line.starts_with(char::is_whitespace),
                "error message \"{rendered_err}\" contains a line that starts with whitespace"
            );
        }
    }

    lazy_static! {
        // This test data is transcribed from a list_proposals response from the SNS governance
        // canister of Dragginz (previously known as SNS-1) where the request specified that only
        // ReadyToSettle proposals should be returned, and this (with the bug) was mistakenly
        // returned. I have confirmed that without the bug fix, this is considered ReadyToSettle
        // instead of Settled.
        static ref SNS_1_PROPOSAL_5: ProposalData = ProposalData {
            // These are the relevant fields. Both should be considered. The bug is that only the
            // first one is considered.
            reward_event_end_timestamp_seconds: None,
            reward_event_round: 21,

            // The remaining fields should have no impact on this test, but are included for
            // realism.
            id: Some(ProposalId { id: 5 }),
            payload_text_rendering: Some(
                "# Motion Proposal: ## Motion Text: hold token SNS be the main key to \
                 enter the next project"
                .to_string()
            ),
            action: 1,
            failure_reason: None,
            ballots: btreemap!{},
            minimum_yes_proportion_of_total: None,
            minimum_yes_proportion_of_exercised: None,
            failed_timestamp_seconds: 0,
            proposal_creation_timestamp_seconds: 1670488610, // 2022-12-08T08:36:50Z (Thu)
            initial_voting_period_seconds: 345_600, // 4 days
            reject_cost_e8s: 10_000_000,
            latest_tally: Some(Tally {
                no: 37561606004,
                yes: 2999861572,
                total: 266762154361,
                timestamp_seconds: 1670822893, // 2022-12-12T05:28:13Z (Mon)
            }),
            wait_for_quiet_deadline_increase_seconds: 86_400, // 1 day
            decided_timestamp_seconds: 1670834210, // 2022-12-12T08:36:50Z (Mon)
            proposal: Some(Proposal {
                url: "".to_string(),
                title: "SNS Token".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "hold token SNS be the main key to enter the next project".to_string(),
                })),
                summary: "".to_string()
            }),
            proposer: Some(NeuronId {
                // This was derived the hex representation using the Python interpretter:
                // >>> s = "e9e50b664c7d97fcf5811df56cf53cc09066190a247519063b6ab09e159c7691"
                // >>> [int(s[i:i+2], 16) for i in range(0, len(s), 2)]
                id: vec![
                    233, 229, 11, 102, 76, 125, 151, 252, 245, 129, 29, 245, 108, 245, 60, 192,
                    144, 102, 25, 10, 36, 117, 25, 6, 59, 106, 176, 158, 21, 156, 118, 145,
                ],
            }),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: 1670834210, // 2022-12-12T08:36:50Z (Mon)
            }),
            // Rewards were considered "enabled" at the time of proposal creation.
            is_eligible_for_rewards: true,
            // This is because the proposal was rejected (see the latest_tally field).
            executed_timestamp_seconds: 0,
            action_auxiliary: None,
        };
    }

    // This is a regression test. I have confirmed that without the fix (see has_been_rewarded),
    // this fails, and with the fix, it passes.
    #[test]
    fn test_old_proposal_has_reward_status_settled() {
        let now = 1699645996; // 2023-11-10T19:53:16Z (Fri)
        assert_eq!(
            SNS_1_PROPOSAL_5.reward_status(now),
            ProposalRewardStatus::Settled
        );
    }

    #[test]
    fn majority_decision_yes_vote_at_threshold() {
        // Assuming a threshold of 60%, with total votes = 100
        let threshold = Percentage::from_basis_points(6000);
        let total = 100;
        let yes = 60; // Exactly at threshold
        assert_eq!(
            ProposalData::majority_decision(yes, total - yes - 1, total, threshold),
            Vote::Unspecified
        );
        assert_eq!(
            ProposalData::majority_decision(yes + 1, total - yes - 1, total, threshold),
            Vote::Yes
        );
    }

    #[test]
    fn test_new_proposal_has_reward_status_settled() {
        let now = 1699645996; // 2023-11-10T19:53:16Z (Fri)
        let proposal = ProposalData {
            reward_event_end_timestamp_seconds: Some(now),
            reward_event_round: 0,

            ..SNS_1_PROPOSAL_5.clone()
        };

        assert_eq!(proposal.reward_status(now), ProposalRewardStatus::Settled);
    }

    #[test]
    fn test_new_proposal_has_reward_status_ready_to_be_settled() {
        let now = 1699645996; // 2023-11-10T19:53:16Z (Fri)
        let proposal = ProposalData {
            reward_event_end_timestamp_seconds: None,
            reward_event_round: 0,

            ..SNS_1_PROPOSAL_5.clone()
        };

        assert_eq!(
            proposal.reward_status(now),
            ProposalRewardStatus::ReadyToSettle
        );
    }

    #[test]
    fn majority_decision_no_vote_at_threshold() {
        let threshold = Percentage::from_basis_points(6000);
        let total = 100;
        let no = 40; // Exactly at threshold for 'No'
        assert_eq!(
            ProposalData::majority_decision(total - no, no, total, threshold),
            Vote::No
        );
        assert_eq!(
            ProposalData::majority_decision(total - no, no - 1, total, threshold),
            Vote::Unspecified
        );
    }

    #[test]
    fn majority_decision_equal_yes_no_votes_near_threshold() {
        let threshold = Percentage::from_basis_points(5000);
        let total_votes = 100;
        let votes = 50; // If the vote is split 50/50, and the threshold is 50%, `no` should win
        assert_eq!(
            ProposalData::majority_decision(votes, votes, total_votes, threshold),
            Vote::No
        );
        // But if there's one person who hasn't voted, they should determine the result
        assert_eq!(
            ProposalData::majority_decision(votes, votes, total_votes + 1, threshold),
            Vote::Unspecified
        );
        // But then one additional person votes yes, and the result becomes yes
        assert_eq!(
            ProposalData::majority_decision(votes + 1, votes, total_votes + 1, threshold),
            Vote::Yes
        );
        // Of course, if the additional person votes no, the result is still no
        assert_eq!(
            ProposalData::majority_decision(votes, votes + 1, total_votes + 1, threshold),
            Vote::No
        );
    }

    #[test]
    fn majority_decision_no_votes() {
        let threshold = Percentage::from_basis_points(5000);
        let total_votes = 0;
        let votes = 0;
        assert_eq!(
            ProposalData::majority_decision(votes, votes, total_votes, threshold),
            Vote::No
        );
    }

    #[test]
    fn majority_decision_doesnt_overflow_yes() {
        let threshold = Percentage::from_basis_points(5000);
        let total_votes = u64::MAX;
        let yes_votes = u64::MAX;
        assert_eq!(
            ProposalData::majority_decision(yes_votes, 0, total_votes, threshold),
            Vote::Yes
        );
    }

    #[test]
    fn majority_decision_doesnt_overflow_no() {
        let threshold = Percentage::from_basis_points(5000);
        let total_votes = u64::MAX;
        let no_votes = u64::MAX;
        assert_eq!(
            ProposalData::majority_decision(0, no_votes, total_votes, threshold),
            Vote::No
        );
    }
    #[test]
    fn majority_decision_doesnt_overflow_split() {
        let threshold = Percentage::from_basis_points(5000);
        let total_votes = u64::MAX;
        let yes_votes = u64::MAX / 2; // u64::MAX is an odd number, so there is one person who hasn't voted yet
        let no_votes = u64::MAX / 2;
        assert_eq!(
            ProposalData::majority_decision(yes_votes, no_votes, total_votes, threshold),
            Vote::Unspecified
        );
        assert_eq!(
            ProposalData::majority_decision(yes_votes + 1, no_votes, total_votes, threshold),
            Vote::Yes
        );
        assert_eq!(
            ProposalData::majority_decision(yes_votes, no_votes + 1, total_votes, threshold),
            Vote::No
        );
    }

    #[test]
    fn validate_and_render_manage_ledger_parameters_must_be_changes() {
        let rendered_error =
            validate_and_render_manage_ledger_parameters(&ManageLedgerParameters::default())
                .unwrap_err();
        assert!(rendered_error.contains("must change at least one value"));
    }

    #[test]
    fn test_validate_and_render_manage_ledger_parameters_token_transfer_fee() {
        let new_fee = 751;
        let render = validate_and_render_manage_ledger_parameters(&ManageLedgerParameters {
            transfer_fee: Some(new_fee),
            ..ManageLedgerParameters::default()
        })
        .unwrap();
        assert_eq!(
            render,
            format!("# Proposal to change ledger parameters:\n# Set token transfer fee: {new_fee} token-quantums. \n")
        );
    }

    #[test]
    fn test_validate_and_render_manage_ledger_parameters_token_symbol() {
        let new_symbol = "COOL".to_string();
        let render = validate_and_render_manage_ledger_parameters(&ManageLedgerParameters {
            token_symbol: Some(new_symbol.clone()),
            ..ManageLedgerParameters::default()
        })
        .unwrap();
        assert_eq!(
            render,
            format!(
                "# Proposal to change ledger parameters:\n# Set token symbol: {new_symbol}. \n"
            )
        );
    }

    #[test]
    fn test_validate_and_render_manage_ledger_parameters_token_name() {
        let new_name = "coolcoin".to_string();
        let render = validate_and_render_manage_ledger_parameters(&ManageLedgerParameters {
            token_name: Some(new_name.clone()),
            ..ManageLedgerParameters::default()
        })
        .unwrap();
        assert_eq!(
            render,
            format!("# Proposal to change ledger parameters:\n# Set token name: {new_name}. \n")
        );
    }

    #[test]
    fn test_validate_and_render_manage_ledger_parameters_token_logo() {
        let new_logo = "data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string();
        let render = validate_and_render_manage_ledger_parameters(&ManageLedgerParameters {
            token_logo: Some(new_logo.clone()),
            ..ManageLedgerParameters::default()
        })
        .unwrap();
        assert_eq!(
            render,
            format!("# Proposal to change ledger parameters:\n# Set token logo: {new_logo}. \n")
        );
    }

    #[test]
    fn test_validate_and_render_manage_ledger_paramaters() {
        let new_fee = 751;
        let new_symbol = "COOL".to_string();
        let new_name = "coolcoin".to_string();
        let new_logo = "data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string();
        let render = validate_and_render_manage_ledger_parameters(&ManageLedgerParameters {
            transfer_fee: Some(new_fee),
            token_symbol: Some(new_symbol.clone()),
            token_name: Some(new_name.clone()),
            token_logo: Some(new_logo.clone()),
        })
        .unwrap();
        assert_eq!(
            render,
            format!(
                r#"# Proposal to change ledger parameters:
# Set token transfer fee: {new_fee} token-quantums. 
# Set token name: {new_name}. 
# Set token symbol: {new_symbol}. 
# Set token logo: {new_logo}. 
"#
            )
        );
    }

    #[test]
    fn validate_and_render_manage_dapp_canister_settings_no_canisters() {
        let rendered_error = validate_and_render_manage_dapp_canister_settings(
            &ManageDappCanisterSettings::default(),
        )
        .unwrap_err();
        assert!(rendered_error.contains("must specify at least one canister"));
    }

    #[test]
    fn validate_and_render_manage_dapp_canister_settings_max_canisters() {
        let canister_ids = (0..(MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL))
            .map(|i| PrincipalId::new_user_test_id(i as u64))
            .collect::<Vec<_>>();

        validate_and_render_manage_dapp_canister_settings(&ManageDappCanisterSettings {
            canister_ids,
            compute_allocation: Some(50),
            memory_allocation: Some(1 << 30),
            freezing_threshold: Some(1_000),
            reserved_cycles_limit: Some(1_000_000_000_000),
            log_visibility: Some(LogVisibility::Public as i32),
            wasm_memory_limit: Some(1_000_000_000),
        })
        .unwrap();
    }

    #[test]
    fn validate_and_render_manage_dapp_canister_settings_too_many_canisters() {
        let canister_ids = (0..(MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL + 1))
            .map(|i| PrincipalId::new_user_test_id(i as u64))
            .collect::<Vec<_>>();

        let rendered_error =
            validate_and_render_manage_dapp_canister_settings(&ManageDappCanisterSettings {
                canister_ids,
                ..ManageDappCanisterSettings::default()
            })
            .unwrap_err();
        assert!(rendered_error.contains("cannot specify more than"));
    }

    #[test]
    fn validate_and_render_manage_dapp_canister_settings_no_changes() {
        let rendered_error =
            validate_and_render_manage_dapp_canister_settings(&ManageDappCanisterSettings {
                canister_ids: vec![PrincipalId::new_user_test_id(1)],
                ..Default::default()
            })
            .unwrap_err();
        assert!(rendered_error.contains("must change at least one value"));
    }

    #[tokio::test]
    async fn validate_and_render_execute_nervous_system_function_success() {
        let function_id = 1000;
        let canister_id = CanisterId::from_u64(1);
        let payload = vec![1, 2, 3];
        let function = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(canister_id.get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(canister_id.get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        // set up environment
        let governance_canister_id = *SNS_GOVERNANCE_CANISTER_ID;
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        env.default_canister_call_response =
            Err((Some(1), "Oh no something was not covered!".to_string()));
        env.set_call_canister_response(
            canister_id,
            "test_validator_method",
            payload.clone(),
            Ok(Encode!(&Ok::<String, String>("Payload rendering here".to_string())).unwrap()),
        );

        let render = validate_and_render_execute_nervous_system_function(
            &env,
            &ExecuteGenericNervousSystemFunction {
                function_id,
                payload,
            },
            &btreemap! {function_id => function},
        )
        .await
        .unwrap();

        assert_eq!(
            render,
            r#"# Proposal to execute nervous system function:

## Nervous system function:

NervousSystemFunction {
    id: 1000,
    name: "a",
    description: None,
    function_type: Some(
        GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                target_canister_id: Some(
                    rrkah-fqaaa-aaaaa-aaaaq-cai,
                ),
                target_method_name: Some(
                    "test_method",
                ),
                validator_canister_id: Some(
                    rrkah-fqaaa-aaaaa-aaaaq-cai,
                ),
                validator_method_name: Some(
                    "test_validator_method",
                ),
            },
        ),
    ),
}

## Payload sha256: 

039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81

## Payload:

Payload rendering here"#
        );
    }

    #[test]
    fn validate_and_render_manage_dapp_canister_settings_no_changes_multiple_canisters() {
        let render =
            validate_and_render_manage_dapp_canister_settings(&ManageDappCanisterSettings {
                canister_ids: vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
                compute_allocation: Some(50),
                memory_allocation: Some(1 << 30),
                freezing_threshold: Some(1_000),
                reserved_cycles_limit: Some(1_000_000_000_000),
                log_visibility: Some(LogVisibility::Public as i32),
                wasm_memory_limit: Some(1_000_000_000),
            })
            .unwrap();
        assert_eq!(
            render,
            "# Proposal to manage settings for 2 dapp canisters: \n\
             ## Canister ids: \n  \
             - 6fyp7-3ibaa-aaaaa-aaaap-4ai\n  \
             - djduj-3qcaa-aaaaa-aaaap-4ai\n\
             # Set compute allocation to: 50%\n\
             # Set memory allocation to: 1073741824 bytes\n\
             # Set freezing threshold to: 1000 seconds\n\
             # Set reserved cycles limit to: 1000000000000 \n\
             # Set log visibility to: Public \n\
             # Set Wasm memory limit to: 1000000000\n"
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_retain_ballots_by_caller() {
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::Motion(Motion {
                    motion_text: "Some motion text".to_string(),
                })),
                ..Default::default()
            }),
            ballots: btreemap! {
                "1".to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    ..Default::default()
                },
                "2".to_string() => Ballot {
                    vote: Vote::No as i32,
                    ..Default::default()
                },
                "3".to_string() => Ballot {
                    vote: Vote::Unspecified as i32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        let caller_neurons = hashset! { "1".to_string(), "2".to_string() };

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&caller_neurons);

        assert_eq!(
            limited_proposal_data,
            ProposalData {
                ballots: btreemap! {
                    "1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        ..Default::default()
                    },
                    "2".to_string() => Ballot {
                        vote: Vote::No as i32,
                        ..Default::default()
                    },
                },
                ..original_proposal_data
            }
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_truncate_ballots_and_text_rendering() {
        let ballots = (100..300)
            .map(|i| {
                (
                    i.to_string(),
                    Ballot {
                        vote: Vote::Yes as i32,
                        ..Default::default()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::Motion(Motion {
                    motion_text: "Some motion text".to_string(),
                })),
                ..Default::default()
            }),
            ballots,
            payload_text_rendering: Some(
                "# Motion Proposal: ## Motion Text: some motion text".to_string(),
            ),
            ..Default::default()
        };
        let caller_neurons = (0..1000).map(|i| i.to_string()).collect::<HashSet<_>>();

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&caller_neurons);

        let expected_ballots = (100..100 + MAX_NUMBER_OF_BALLOTS_IN_LIST_PROPOSALS_RESPONSE)
            .map(|i| {
                (
                    i.to_string(),
                    Ballot {
                        vote: Vote::Yes as i32,
                        ..Default::default()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            limited_proposal_data,
            ProposalData {
                ballots: expected_ballots,
                payload_text_rendering: None,
                ..original_proposal_data
            }
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_limited_execute_generic_nervous_system_function() {
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::ExecuteGenericNervousSystemFunction(
                    ExecuteGenericNervousSystemFunction {
                        function_id: 1,
                        payload: vec![0, 1, 2, 3],
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        };

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&HashSet::new());

        assert_eq!(
            limited_proposal_data,
            ProposalData {
                proposal: Some(Proposal {
                    action: Some(Action::ExecuteGenericNervousSystemFunction(
                        ExecuteGenericNervousSystemFunction {
                            function_id: 1,
                            payload: vec![],
                        },
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_limited_upgrade_sns_controlled_canister() {
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        canister_id: Some(PrincipalId::new_user_test_id(1)),
                        new_canister_wasm: vec![0, 1, 2, 3],
                        canister_upgrade_arg: Some(vec![4, 5, 6, 7]),
                        mode: Some(1),
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        };

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&HashSet::new());

        assert_eq!(
            limited_proposal_data,
            ProposalData {
                proposal: Some(Proposal {
                    action: Some(Action::UpgradeSnsControlledCanister(
                        UpgradeSnsControlledCanister {
                            canister_id: Some(PrincipalId::new_user_test_id(1)),
                            new_canister_wasm: vec![],
                            canister_upgrade_arg: Some(vec![4, 5, 6, 7]),
                            mode: Some(1),
                        },
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_limited_manage_sns_metadata() {
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::ManageSnsMetadata(ManageSnsMetadata {
                    logo: Some("some logo".to_string()),
                    url: Some("some url".to_string()),
                    name: Some("some name".to_string()),
                    description: Some("some description".to_string()),
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&HashSet::new());

        assert_eq!(
            limited_proposal_data,
            ProposalData {
                proposal: Some(Proposal {
                    action: Some(Action::ManageSnsMetadata(ManageSnsMetadata {
                        logo: None,
                        url: Some("some url".to_string()),
                        name: Some("some name".to_string()),
                        description: Some("some description".to_string()),
                    },)),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn limited_proposal_data_for_list_proposals_limited_manage_ledger_parameters() {
        let original_proposal_data = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                    transfer_fee: Some(100),
                    token_name: Some("some name".to_string()),
                    token_symbol: Some("some symbol".to_string()),
                    token_logo: Some("some logo".to_string()),
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        let limited_proposal_data =
            original_proposal_data.limited_for_list_proposals(&HashSet::new());

        assert_eq!(
            limited_proposal_data,
            ProposalData {
                proposal: Some(Proposal {
                    action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                        transfer_fee: Some(100),
                        token_name: Some("some name".to_string()),
                        token_symbol: Some("some symbol".to_string()),
                        token_logo: None,
                    },)),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );
    }
}
