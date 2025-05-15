use crate::{
    governance::{ledger_helper::MintIcpOperation, Governance},
    neuron_store::NeuronStore,
    pb::v1::{
        governance::{neuron_in_flight_command::Command, NeuronInFlightCommand},
        governance_error::ErrorType,
        manage_neuron::DisburseMaturity,
        Account, FinalizeDisburseMaturity, GovernanceError, MaturityDisbursement, NeuronState,
        Subaccount,
    },
};

use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_governance::maturity_modulation::{
    apply_maturity_modulation, MIN_MATURITY_MODULATION_PERMYRIAD,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_types::PrincipalId;
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;
use std::{cell::RefCell, collections::HashMap, fmt::Display, thread::LocalKey, time::Duration};

/// The delay in seconds between initiating a maturity disbursement and the actual disbursement.
const DISBURSEMENT_DELAY_SECONDS: u64 = ONE_DAY_SECONDS * 7;
/// The maximum number of disbursements in a neuron. This makes it possible to do daily
/// disbursements after every reward event (as 10 > 7).
const MAX_NUM_DISBURSEMENTS: usize = 10;
/// The minimum amount of ICP to disburse in a single transaction.
const MINIMUM_DISBURSEMENT_E8S: u64 = E8;
// We do not retry the task more frequently than once a minute, so that if there is anything wrong
// with the task, we don't use too many resources. How this is chosen: assuming the task can max out
// the 50B instruction limit and it takes 2B instructions per DTS slice, then the task can run for
// 25 rounds; with 1.5 rounds per second, it will take ~ 16 seconds to run. The minimum task
// interval is chosen to be larger than 16 seconds so that the canister would be able to do other
// work in the meantime.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

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
impl TryFrom<Account> for Icrc1Account {
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

        Ok(Icrc1Account {
            owner: owner.0,
            subaccount,
        })
    }
}

// This conversion is needed for neuron lock.
impl From<Icrc1Account> for Account {
    fn from(account: Icrc1Account) -> Self {
        let Icrc1Account { owner, subaccount } = account;

        let owner = Some(PrincipalId::from(owner));
        let subaccount = subaccount.map(|s| Subaccount {
            subaccount: s.to_vec(),
        });
        Account { owner, subaccount }
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
        let _ = Icrc1Account::try_from(to_account.clone())
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

#[derive(Debug, Clone)]
pub struct MaturityDisbursementFinalization {
    pub neuron_id: NeuronId,
    pub account: Icrc1Account,
    pub amount_to_mint_e8s: u64,
    pub original_maturity_e8s_equivalent: u64,
    pub finalize_disbursement_timestamp_seconds: u64,
}

/// Errors that can occur when finalizing a maturity disbursement. The error is just for logging
/// purposes since all user errors should be caught when initiating the disbursement.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FinalizeMaturityDisbursementError {
    NoMaturityModulation,
    NeuronNotFound(NeuronId),
    NoMaturityDisbursement(NeuronId),
    NotTimeToFinalizeMaturityDisbursement {
        neuron_id: NeuronId,
        finalize_disbursement_timestamp_seconds: u64,
        now_seconds: u64,
    },
    MaturityModulationFailure {
        maturity_before_modulation_e8s: u64,
        maturity_modulation_basis_points: i32,
        reason: String,
    },
    NoAccountToDisburseTo(NeuronId),
    AccountConversionFailure {
        reason: String,
    },
    FailToAcquireNeuronLock(NeuronId),
    FailToPopMaturityDisbursement(NeuronId),
    FailToMintIcp {
        neuron_id: NeuronId,
        reason: String,
    },
    FailToRestoreMaturityDisbursement {
        neuron_id: NeuronId,
        reason: String,
    },
}

impl Display for FinalizeMaturityDisbursementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalizeMaturityDisbursementError::NoMaturityModulation => {
                write!(f, "No maturity modulation")
            }
            FinalizeMaturityDisbursementError::NeuronNotFound(neuron_id) => {
                write!(f, "Neuron not found: {:?}", neuron_id)
            }
            FinalizeMaturityDisbursementError::NoMaturityDisbursement(neuron_id) => {
                write!(
                    f,
                    "No maturity disbursement found for neuron: {:?}",
                    neuron_id
                )
            }
            FinalizeMaturityDisbursementError::NotTimeToFinalizeMaturityDisbursement {
                neuron_id,
                finalize_disbursement_timestamp_seconds,
                now_seconds,
            } => write!(
                f,
                "Not time to finalize maturity disbursement for neuron {:?}: \
                finalize_disbursement_timestamp_seconds: {}, now_seconds: {}",
                neuron_id, finalize_disbursement_timestamp_seconds, now_seconds
            ),
            FinalizeMaturityDisbursementError::MaturityModulationFailure {
                maturity_before_modulation_e8s,
                maturity_modulation_basis_points,
                reason,
            } => write!(
                f,
                "Failed to apply maturity modulation of {} basis points to {} e8s: {}",
                maturity_modulation_basis_points, maturity_before_modulation_e8s, reason
            ),
            FinalizeMaturityDisbursementError::NoAccountToDisburseTo(neuron_id) => {
                write!(f, "No account to disburse to for neuron: {:?}", neuron_id)
            }
            FinalizeMaturityDisbursementError::AccountConversionFailure { reason } => {
                write!(f, "Failed to convert account identifier: {}", reason)
            }
            FinalizeMaturityDisbursementError::FailToAcquireNeuronLock(neuron_id) => {
                write!(
                    f,
                    "Failed to acquire neuron lock for neuron: {:?} even though we just \
                    checked the neuron is not locked",
                    neuron_id
                )
            }
            FinalizeMaturityDisbursementError::FailToPopMaturityDisbursement(neuron_id) => {
                write!(
                    f,
                    "Failed to pop maturity disbursement in progress for neuron id {:?} \
                    even though we just found it",
                    neuron_id
                )
            }
            FinalizeMaturityDisbursementError::FailToMintIcp { neuron_id, reason } => write!(
                f,
                "Failed to mint ICP for neuron id {:?}: {}",
                neuron_id, reason
            ),
            FinalizeMaturityDisbursementError::FailToRestoreMaturityDisbursement {
                neuron_id,
                reason,
            } => {
                write!(
                    f,
                    "Maturity disbursement was removed from the neuron {:?}, ICP minting failed \
                    but the disbursement cannot be reversed because of {}. Neuron lock is retained.", 
                    neuron_id,
                    reason
                )
            }
        }
    }
}

/// Returns the next maturity disbursement to finalize. When the function returns
/// `Some(finalization)`, the finalization corresponds to the first disbursement of the neuron with
/// `finalization.neuron_id`. An `Err()` is returned if there is anything unexpected in the process
/// of finding the next maturity disbursement to finalize. On the other hand, Ok(None) means that
/// there are simply no maturity disbursements to finalize at the moment. In theory, this function
/// can be inlined as it is only called by `finalize_maturity_disbursement`. However, it is
/// extracted from `finalize_maturity_disbursement` so that `finalize_maturity_disbursement` mostly
/// contains mutations.
fn next_maturity_disbursement_to_finalize(
    neuron_store: &NeuronStore,
    in_flight_commands: &HashMap<u64, NeuronInFlightCommand>,
    maturity_modulation_basis_points: Option<i32>,
    now_seconds: u64,
) -> Result<Option<MaturityDisbursementFinalization>, FinalizeMaturityDisbursementError> {
    let maturity_modulation_basis_points = maturity_modulation_basis_points
        .ok_or(FinalizeMaturityDisbursementError::NoMaturityModulation)?;

    // Try to find the first neuron eligible for finalizing maturity disbursement, that is not
    // locked.
    let Some(neuron_id) = neuron_store
        .get_neuron_ids_ready_to_finalize_maturity_disbursement(now_seconds)
        .into_iter()
        .find(|neuron_id| !in_flight_commands.contains_key(&neuron_id.id))
    else {
        // If all neurons are locked, we don't need to finalize anything.
        return Ok(None);
    };
    // Either of the errors below indicates a bug in the maturity disbursement index.
    let maturity_disbursement_in_progress = neuron_store
        .with_neuron(&neuron_id, |neuron| {
            neuron.maturity_disbursements_in_progress().first().cloned()
        })
        .map_err(|_| FinalizeMaturityDisbursementError::NeuronNotFound(neuron_id))?
        .ok_or(FinalizeMaturityDisbursementError::NoMaturityDisbursement(
            neuron_id,
        ))?;

    let MaturityDisbursement {
        amount_e8s: original_maturity_e8s_equivalent,
        account_to_disburse_to,
        finalize_disbursement_timestamp_seconds,
        timestamp_of_disbursement_seconds: _,
    } = maturity_disbursement_in_progress;

    // Make sure the disbursement is ready to be finalized. Failure at this step probably means the
    // maturity disbursement index is wrong.
    if now_seconds < finalize_disbursement_timestamp_seconds {
        return Err(
            FinalizeMaturityDisbursementError::NotTimeToFinalizeMaturityDisbursement {
                neuron_id,
                finalize_disbursement_timestamp_seconds,
                now_seconds,
            },
        );
    }

    // Apply the maturity modulation to the disbursement amount. This should not fail unless
    // something else in the system is wrong, such as an insanely large amount of maturity or an
    // incorrect maturity modulation basis points.
    let maturity_to_disburse_after_modulation_e8s = apply_maturity_modulation(
        original_maturity_e8s_equivalent,
        maturity_modulation_basis_points,
    )
    .map_err(
        |reason| FinalizeMaturityDisbursementError::MaturityModulationFailure {
            maturity_before_modulation_e8s: original_maturity_e8s_equivalent,
            maturity_modulation_basis_points,
            reason,
        },
    )?;

    // These should be impossible unless there is some bug, since the initiation of the disbursement
    // ensures the conversion works, and only allows `Some`.
    let account = account_to_disburse_to.ok_or(
        FinalizeMaturityDisbursementError::NoAccountToDisburseTo(neuron_id),
    )?;
    let account = Icrc1Account::try_from(account)
        .map_err(|reason| FinalizeMaturityDisbursementError::AccountConversionFailure { reason })?;

    Ok(Some(MaturityDisbursementFinalization {
        neuron_id,
        account,
        amount_to_mint_e8s: maturity_to_disburse_after_modulation_e8s,
        finalize_disbursement_timestamp_seconds,
        original_maturity_e8s_equivalent,
    }))
}

/// Finalizes the maturity disbursement for a neuron. See
/// `ic_nns_governance::pb::v1::manage_neuron::DisburseMaturity` for more information. Returns the
/// delay until the time when the finalization should be run again.
pub async fn finalize_maturity_disbursement(
    governance: &'static LocalKey<RefCell<Governance>>,
) -> Duration {
    match try_finalize_maturity_disbursement(governance).await {
        Ok(_) => governance.with_borrow(get_delay_until_next_finalization),
        Err(err) => {
            ic_cdk::println!("FinalizeMaturityDisbursementTask failed: {}", err);
            RETRY_INTERVAL
        }
    }
}

/// Tries to finalize the maturity disbursement for the first neuron that is ready to be finalized.
/// Returns an error if there is anything unexpected.
async fn try_finalize_maturity_disbursement(
    governance: &'static LocalKey<RefCell<Governance>>,
) -> Result<(), FinalizeMaturityDisbursementError> {
    let (maturity_disbursement_finalization, now_seconds) = governance.with_borrow(|governance| {
        let now_seconds = governance.env.now();
        let maturity_disbursement_finalization = next_maturity_disbursement_to_finalize(
            &governance.neuron_store,
            &governance.heap_data.in_flight_commands,
            governance
                .heap_data
                .cached_daily_maturity_modulation_basis_points,
            now_seconds,
        );
        (maturity_disbursement_finalization, now_seconds)
    });

    let Some(MaturityDisbursementFinalization {
        neuron_id,
        account,
        amount_to_mint_e8s,
        original_maturity_e8s_equivalent,
        finalize_disbursement_timestamp_seconds,
    }) = maturity_disbursement_finalization?
    else {
        // No disbursement to finalize.
        return Ok(());
    };

    // Step 1: acquire a lock on the neuron, before any mutation is performed. Note that there
    // should not be any `await` before this point, otherwise any data accessed at this point can be
    // stale. Unfortunately we cannot acquire the lock sooner, since the content of the lock needs
    // to be computed above.
    let Ok(mut neuron_lock) = Governance::acquire_neuron_async_lock(
        governance,
        neuron_id,
        now_seconds,
        Command::FinalizeDisburseMaturity(FinalizeDisburseMaturity {
            amount_to_mint_e8s,
            to_account: Some(Account::from(account)),
            finalize_disbursement_timestamp_seconds,
            original_maturity_e8s_equivalent,
        }),
    ) else {
        // This should be impossible since we just checked the neuron is not locked when finding the
        // neuron.
        return Err(FinalizeMaturityDisbursementError::FailToAcquireNeuronLock(
            neuron_id,
        ));
    };

    // Step 2: pop the maturity disbursement in progress. Since this is the first mutation, if it
    // fails, the neuron can still be unlocked as no mutations are performed yet. This is the main
    // thing the neuron lock is protecting against.
    let Ok(Some(maturity_disbursement_in_progress)) = governance.with_borrow_mut(|governance| {
        governance.with_neuron_mut(&neuron_id, |neuron| {
            neuron.pop_maturity_disbursement_in_progress()
        })
    }) else {
        // This should be impossible since we just checked that the disbursement exists in
        // `next_maturity_disbursement_to_finalize`.
        return Err(FinalizeMaturityDisbursementError::FailToPopMaturityDisbursement(neuron_id));
    };

    // Step 3: call ledger to perform the minting. If this fails, the neuron mutation needs to
    // be reversed.
    let mint_icp_operation = MintIcpOperation::new(account, amount_to_mint_e8s);
    let ledger = governance.with_borrow(|governance| governance.get_ledger());
    let mint_result = mint_icp_operation
        .mint_icp_with_ledger(ledger.as_ref(), now_seconds)
        .await;
    let Err(mint_error) = mint_result else {
        // Happy case: the minting was successful so we can exit here.
        return Ok(());
    };

    // Reaching this point means the minting failed and we need to reverse the neuron mutation
    // for consistency.
    let reverse_neuron_result = governance.with_borrow_mut(|governance| {
        governance.with_neuron_mut(&neuron_id, |neuron| {
            neuron.push_front_maturity_disbursement_in_progress(maturity_disbursement_in_progress);
        })
    });
    let Err(reverse_neuron_error) = reverse_neuron_result else {
        // The neuron mutation was successfully reversed and it will be re-tried later.
        return Err(FinalizeMaturityDisbursementError::FailToMintIcp {
            neuron_id,
            reason: mint_error.error_message,
        });
    };

    // Reaching this point means the neuron mutation was performed, the ledger operation failed
    // and the neuron mutation could not be reversed. The best we can do at this point is to
    // retain the neuron lock.
    neuron_lock.retain();
    Err(
        FinalizeMaturityDisbursementError::FailToRestoreMaturityDisbursement {
            neuron_id,
            reason: reverse_neuron_error.error_message,
        },
    )
}

/// Returns the amount of time until the next maturity disbursement finalization should be run.
pub fn get_delay_until_next_finalization(governance: &Governance) -> Duration {
    let next_maturity_disbursement_finalization_timestamp =
        governance.neuron_store.get_next_maturity_disbursement();
    let Some((next_maturity_disbursement_finalization_timestamp, neuron_id)) =
        next_maturity_disbursement_finalization_timestamp
    else {
        // If there are no disbursements yet, then we can wait at least `DISBURSEMENT_DELAY_SECONDS`
        // since new disbursements will be scheduled after this delay.
        return Duration::from_secs(DISBURSEMENT_DELAY_SECONDS);
    };

    let delay_until_next_finalization = Duration::from_secs(
        next_maturity_disbursement_finalization_timestamp.saturating_sub(governance.env.now()),
    );
    let is_neuron_locked = governance
        .heap_data
        .in_flight_commands
        .contains_key(&neuron_id.id);

    if is_neuron_locked {
        // The first neuron eligible for finalization is locked. We should not ignore it since it
        // can be unlocked any time, but we also don't want to retry immediately as it can be locked
        // indefinitely. Therefore, we try to execute at the scheduled time but with throttling.
        delay_until_next_finalization.min(RETRY_INTERVAL)
    } else {
        // This is the normal case - the absolute time of the next disbursement is known, and we
        // calculate the delay based on the current time.
        delay_until_next_finalization
    }
}
#[path = "disburse_maturity_tests.rs"]
#[cfg(test)]
mod tests;
