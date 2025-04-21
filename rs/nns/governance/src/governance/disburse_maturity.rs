use crate::{
    neuron_store::NeuronStore,
    pb::v1::{
        governance_error::ErrorType, manage_neuron::DisburseMaturity, Account, GovernanceError,
        MaturityDisbursement, NeuronState,
    },
};

use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_governance::maturity_modulation::{
    apply_maturity_modulation, MIN_MATURITY_MODULATION_PERMYRIAD,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_types::PrincipalId;
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;

/// The delay in seconds between initiating a maturity disbursement and the actual disbursement.
const DISBURSEMENT_DELAY_SECONDS: u64 = ONE_DAY_SECONDS * 7;
/// The maximum number of disbursements in a neuron. This makes it possible to do daily
/// disbursements after every reward event (as 10 > 7).
const MAX_NUM_DISBURSEMENTS: usize = 10;
/// The minimum amount of ICP to disburse in a single transaction.
const MINIMUM_DISBURSEMENT_E8S: u64 = E8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InitiateMaturityDisbursementError {
    NeuronNotFound,
    InvalidPercentage,
    InvalidDestination {
        reason: String,
    },
    NeuronSpawning,
    CallerIsNotNeuronController,
    TooManyDisbursements,
    DisbursementTooSmall {
        disbursement_maturity_e8s: u64,
        minimum_disbursement_e8s: u64,
        worst_case_maturity_modulation_basis_points: i32,
    },
    // This error usually indicates a bug in the code.
    Unknown {
        reason: String,
    },
}

impl From<InitiateMaturityDisbursementError> for GovernanceError {
    fn from(error: InitiateMaturityDisbursementError) -> Self {
        match error {
            InitiateMaturityDisbursementError::NeuronNotFound => {
                GovernanceError::new_with_message(ErrorType::NotFound, "Neuron not found")
            }
            InitiateMaturityDisbursementError::InvalidPercentage => {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Invalid percentage: must be between 1 and 100",
                )
            }
            InitiateMaturityDisbursementError::InvalidDestination { reason } => {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("Invalid disbursement destination: {}", reason),
                )
            }
            InitiateMaturityDisbursementError::NeuronSpawning => GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Neuron is spawning and cannot be disbursed",
            ),
            InitiateMaturityDisbursementError::CallerIsNotNeuronController => {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Caller is not the neuron controller",
                )
            }
            InitiateMaturityDisbursementError::TooManyDisbursements => {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "Too many disbursements in progress. Max: {}",
                        MAX_NUM_DISBURSEMENTS,
                    ),
                )
            }
            InitiateMaturityDisbursementError::DisbursementTooSmall {
                disbursement_maturity_e8s,
                minimum_disbursement_e8s,
                worst_case_maturity_modulation_basis_points,
            } => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Disbursement ({disbursement_maturity_e8s}) is too small. After the worst \
                    case maturity modulation ({worst_case_maturity_modulation_basis_points}) \
                    the amount should be at least: {minimum_disbursement_e8s} e8s",
                ),
            ),
            InitiateMaturityDisbursementError::Unknown { reason } => {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Initializing maturity disbursement failed: {reason}"),
                )
            }
        }
    }
}

// There is no reason to put the conversion here other than the fact that it is
// only needed in this file. It's OK to move it to a different file if needed.
impl TryFrom<Account> for AccountIdentifier {
    type Error = String;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let Account { owner, subaccount } = account;
        let Some(owner) = owner else {
            return Err("Owner is required".to_string());
        };
        let subaccount: Option<[u8; 32]> = subaccount
            .map(|s| s.subaccount.try_into())
            .transpose()
            .map_err(|_| "Subaccount must be 32 bytes".to_string())?;

        let icrc1_account = Icrc1Account {
            owner: owner.0,
            subaccount,
        };
        Ok(AccountIdentifier::from(icrc1_account))
    }
}

fn percentage_of_maturity(
    total_maturity_e8s: u64,
    percentage_to_disburse: u32,
) -> Result<u64, InitiateMaturityDisbursementError> {
    (total_maturity_e8s as u128)
        .checked_mul(percentage_to_disburse as u128)
        .and_then(|result| result.checked_div(100))
        .and_then(|result| {
            // This should be impossible as long as `percentage_to_disburse` is between 0 and 100.
            if result > u64::MAX as u128 {
                None
            } else {
                Some(result as u64)
            }
        })
        .ok_or_else(|| InitiateMaturityDisbursementError::Unknown {
            reason: format!(
                "Failed to calculate percentage of maturity: {}% of {} e8s",
                percentage_to_disburse, total_maturity_e8s
            ),
        })
}

fn check_minimum_transaction(
    disbursement_maturity_e8s: u64,
    worst_case_maturity_modulation_basis_points: i32,
    minimum_disbursement_e8s: u64,
) -> Result<(), InitiateMaturityDisbursementError> {
    let disbursement_after_worst_case_maturity_modulation = apply_maturity_modulation(
        disbursement_maturity_e8s,
        worst_case_maturity_modulation_basis_points,
    )
    .map_err(|reason| InitiateMaturityDisbursementError::Unknown { reason })?;
    if disbursement_after_worst_case_maturity_modulation < minimum_disbursement_e8s {
        return Err(InitiateMaturityDisbursementError::DisbursementTooSmall {
            disbursement_maturity_e8s,
            minimum_disbursement_e8s,
            worst_case_maturity_modulation_basis_points,
        });
    }
    Ok(())
}

/// Initiates the maturity disbursement process for a neuron.
pub fn initiate_maturity_disbursement(
    neuron_store: &mut NeuronStore,
    caller: &PrincipalId,
    id: &NeuronId,
    disburse_maturity: &DisburseMaturity,
    now_seconds: u64,
) -> Result<u64, InitiateMaturityDisbursementError> {
    let DisburseMaturity {
        percentage_to_disburse,
        to_account,
    } = disburse_maturity;

    if *percentage_to_disburse == 0 || *percentage_to_disburse > 100 {
        return Err(InitiateMaturityDisbursementError::InvalidPercentage);
    }

    if let Some(to_account) = to_account {
        // Even though the conversion result is not used when initiating, we still want to validate
        // the account identifier so that we only store valid account identifiers in the neuron.
        let _ = AccountIdentifier::try_from(to_account.clone())
            .map_err(|reason| InitiateMaturityDisbursementError::InvalidDestination { reason })?;
    }

    let timestamp_of_disbursement_seconds = now_seconds;
    let finalize_disbursement_timestamp_seconds = now_seconds + DISBURSEMENT_DELAY_SECONDS;

    let (
        is_neuron_spawning,
        is_neuron_controlled_by_caller,
        num_disbursements,
        maturity_e8s_equivalent,
    ) = neuron_store
        .with_neuron(id, |neuron| {
            let is_neuron_spawning = neuron.state(now_seconds) == NeuronState::Spawning;
            let is_neuron_controlled_by_caller = neuron.is_controlled_by(caller);
            let num_disbursements = neuron.maturity_disbursements_in_progress().len();
            let maturity_e8s_equivalent = neuron.maturity_e8s_equivalent;
            (
                is_neuron_spawning,
                is_neuron_controlled_by_caller,
                num_disbursements,
                maturity_e8s_equivalent,
            )
        })
        .map_err(|_| InitiateMaturityDisbursementError::NeuronNotFound)?;

    let disbursement_maturity_e8s =
        percentage_of_maturity(maturity_e8s_equivalent, *percentage_to_disburse)?;
    check_minimum_transaction(
        disbursement_maturity_e8s,
        MIN_MATURITY_MODULATION_PERMYRIAD,
        MINIMUM_DISBURSEMENT_E8S,
    )?;

    if is_neuron_spawning {
        return Err(InitiateMaturityDisbursementError::NeuronSpawning);
    }
    if !is_neuron_controlled_by_caller {
        return Err(InitiateMaturityDisbursementError::CallerIsNotNeuronController);
    }
    if num_disbursements >= MAX_NUM_DISBURSEMENTS {
        return Err(InitiateMaturityDisbursementError::TooManyDisbursements);
    }
    let account_to_disburse_to = Some(to_account.clone().unwrap_or(Account {
        owner: Some(*caller),
        subaccount: None,
    }));

    let disbursement_in_progress = MaturityDisbursement {
        account_to_disburse_to,
        amount_e8s: disbursement_maturity_e8s,
        timestamp_of_disbursement_seconds,
        finalize_disbursement_timestamp_seconds,
    };

    neuron_store
        .with_neuron_mut(id, |neuron| {
            neuron.add_maturity_disbursement_in_progress(disbursement_in_progress);
            neuron.maturity_e8s_equivalent = neuron
                .maturity_e8s_equivalent
                .saturating_sub(disbursement_maturity_e8s);
        })
        .map_err(|_| InitiateMaturityDisbursementError::Unknown {
            reason: "Failed to update neuron even though it was found before".to_string(),
        })?;

    Ok(disbursement_maturity_e8s)
}

#[path = "disburse_maturity_tests.rs"]
#[cfg(test)]
mod tests;
