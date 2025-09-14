use crate::{
    governance::{Governance, ledger_helper::MintIcpOperation},
    neuron_store::NeuronStore,
    pb::v1::{
        Account, FinalizeDisburseMaturity, GovernanceError, MaturityDisbursement, NeuronState,
        Subaccount,
        governance::{NeuronInFlightCommand, neuron_in_flight_command::Command},
        governance_error::ErrorType,
        manage_neuron::DisburseMaturity,
        maturity_disbursement::Destination,
    },
};

use ic_cdk::println;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_governance::maturity_modulation::{
    MIN_MATURITY_MODULATION_PERMYRIAD, apply_maturity_modulation,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, protobuf::AccountIdentifier as AccountIdentifierProto};
use icrc_ledger_types::icrc1::account::Account as Icrc1Account;
use std::{cell::RefCell, collections::HashMap, fmt::Display, thread::LocalKey, time::Duration};

#[cfg(feature = "tla")]
pub use crate::governance::{
    tla,
    tla::{
        FINALIZE_MATURITY_DISBURSEMENT_DESC, GlobalState, InstrumentationState,
        TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX, TlaValue, ToTla,
        account_to_tla, get_tla_globals, tla_update_method,
    },
};
use crate::{tla_log_label, tla_log_locals};
#[cfg(feature = "tla")]
use std::collections::BTreeMap;

/// The delay in seconds between initiating a maturity disbursement and the actual disbursement.
const DISBURSEMENT_DELAY_SECONDS: u64 = ONE_DAY_SECONDS * 7;
/// The maximum number of disbursements in a neuron. This makes it possible to do daily
/// disbursements after every reward event (as 10 > 7).
const MAX_NUM_DISBURSEMENTS: usize = 10;
/// The minimum amount of ICP that need to be minted when disbursing maturity. A neuron can only
/// disburse an amount of maturity that results in minting at least this many ICP (in e8) assuming
/// the worst case maturity modulation. This limit is set to be consistent with the neuron spawning
/// behavior (which maturity disbursement is designed to replace).
pub const MINIMUM_DISBURSEMENT_E8S: u64 = E8;
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
                    format!("Invalid disbursement destination: {reason}"),
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
                    format!("Too many disbursements in progress. Max: {MAX_NUM_DISBURSEMENTS}",),
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

impl Destination {
    pub fn try_new(
        account: &Option<Account>,
        account_identifier: &Option<AccountIdentifierProto>,
        caller: PrincipalId,
    ) -> Result<Self, String> {
        let destination = match (account, account_identifier) {
            (Some(account), None) => Destination::AccountToDisburseTo(account.clone()),
            (None, Some(account_identifier_proto)) => {
                Destination::AccountIdentifierToDisburseTo(account_identifier_proto.clone())
            }
            (None, None) => Destination::AccountToDisburseTo(Account {
                owner: Some(caller),
                subaccount: None,
            }),
            (Some(_), Some(_)) => {
                return Err("Cannot provide both to_account and to_account_identifier".to_string());
            }
        };
        // We make sure we only construct a destination that can be converted to a valid account identifier.
        let _ = destination.try_into_account_identifier()?;
        Ok(destination)
    }

    /// Returns the account identifier to disburse to. This should normally not fail because all the
    /// validations happen at `try_new`. Failure can only happen due to data corruption.
    pub(crate) fn try_into_account_identifier(&self) -> Result<AccountIdentifier, String> {
        match self {
            Destination::AccountToDisburseTo(account) => {
                let icrc1_account = Icrc1Account::try_from(account.clone())?;
                Ok(AccountIdentifier::from(icrc1_account))
            }
            Destination::AccountIdentifierToDisburseTo(account_identifier_proto) => {
                AccountIdentifier::try_from(account_identifier_proto)
                    .map_err(|_| "Invalid account identifier".to_string())
            }
        }
    }

    /// Returns the account to disburse to, if it is specified as `AccountToDisburseTo`. Otherwise,
    /// returns `None` since an `AccountIdentifier` cannot be converted to an `Account`.
    pub fn into_account(&self) -> Option<Account> {
        match self {
            Destination::AccountToDisburseTo(account) => Some(account.clone()),
            Destination::AccountIdentifierToDisburseTo(_) => None,
        }
    }

    /// Returns the 32-byte account identifier (with checksum) to disburse to. This should not fail
    /// because all the validations happens at `try_new`. Failure can only happen due to data
    /// corruption. Note that even when the user specifies an icrc1 account, the corresponding
    /// account identifier is still returned.
    pub fn into_account_identifier_proto(&self) -> Option<AccountIdentifierProto> {
        // Note we should not use `AccountIdentifierProto::from` directly here, since it simply
        // outputs a 28-byte hash without the 4-byte checksum. Instead, we should use the
        // `AccountIdentifier::into_proto_with_checksum` which computes and prepends the checksum.
        self.try_into_account_identifier()
            .ok()
            .map(|id| id.into_proto_with_checksum())
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
                "Failed to calculate percentage of maturity: {percentage_to_disburse}% of {total_maturity_e8s} e8s"
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
        to_account_identifier,
    } = disburse_maturity;

    if *percentage_to_disburse == 0 || *percentage_to_disburse > 100 {
        return Err(InitiateMaturityDisbursementError::InvalidPercentage);
    }

    let destination = Destination::try_new(to_account, to_account_identifier, *caller)
        .map_err(|reason| InitiateMaturityDisbursementError::InvalidDestination { reason })?;

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

    let disbursement_in_progress = MaturityDisbursement {
        destination: Some(destination),
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
struct MaturityDisbursementFinalization {
    neuron_id: NeuronId,
    destination: Destination,
    amount_to_mint_e8s: u64,
    original_maturity_e8s_equivalent: u64,
    finalize_disbursement_timestamp_seconds: u64,
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
                write!(f, "Neuron not found: {neuron_id:?}")
            }
            FinalizeMaturityDisbursementError::NoMaturityDisbursement(neuron_id) => {
                write!(
                    f,
                    "No maturity disbursement found for neuron: {neuron_id:?}"
                )
            }
            FinalizeMaturityDisbursementError::NotTimeToFinalizeMaturityDisbursement {
                neuron_id,
                finalize_disbursement_timestamp_seconds,
                now_seconds,
            } => write!(
                f,
                "Not time to finalize maturity disbursement for neuron {neuron_id:?}: \
                finalize_disbursement_timestamp_seconds: {finalize_disbursement_timestamp_seconds}, now_seconds: {now_seconds}"
            ),
            FinalizeMaturityDisbursementError::MaturityModulationFailure {
                maturity_before_modulation_e8s,
                maturity_modulation_basis_points,
                reason,
            } => write!(
                f,
                "Failed to apply maturity modulation of {maturity_modulation_basis_points} basis points to {maturity_before_modulation_e8s} e8s: {reason}"
            ),
            FinalizeMaturityDisbursementError::NoAccountToDisburseTo(neuron_id) => {
                write!(f, "No account to disburse to for neuron: {neuron_id:?}")
            }
            FinalizeMaturityDisbursementError::AccountConversionFailure { reason } => {
                write!(f, "Failed to convert account identifier: {reason}")
            }
            FinalizeMaturityDisbursementError::FailToAcquireNeuronLock(neuron_id) => {
                write!(
                    f,
                    "Failed to acquire neuron lock for neuron: {neuron_id:?} even though we just \
                    checked the neuron is not locked"
                )
            }
            FinalizeMaturityDisbursementError::FailToPopMaturityDisbursement(neuron_id) => {
                write!(
                    f,
                    "Failed to pop maturity disbursement in progress for neuron id {neuron_id:?} \
                    even though we just found it"
                )
            }
            FinalizeMaturityDisbursementError::FailToMintIcp { neuron_id, reason } => write!(
                f,
                "Failed to mint ICP for neuron id {neuron_id:?}: {reason}"
            ),
            FinalizeMaturityDisbursementError::FailToRestoreMaturityDisbursement {
                neuron_id,
                reason,
            } => {
                write!(
                    f,
                    "Maturity disbursement was removed from the neuron {neuron_id:?}, ICP minting failed \
                    but the disbursement cannot be reversed because of {reason}. Neuron lock is retained."
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
        destination,
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
    let destination = destination.ok_or(
        FinalizeMaturityDisbursementError::NoAccountToDisburseTo(neuron_id),
    )?;

    Ok(Some(MaturityDisbursementFinalization {
        neuron_id,
        destination,
        amount_to_mint_e8s: maturity_to_disburse_after_modulation_e8s,
        finalize_disbursement_timestamp_seconds,
        original_maturity_e8s_equivalent,
    }))
}

#[cfg(feature = "tla")]
macro_rules! tla_snapshotter {
    ($first_arg:expr_2021 $(, $_rest:tt)* ) => {{
        let raw_ptr = ::tla_instrumentation::UnsafeSendPtr($first_arg.with(|g| g.as_ptr()));
        ::std::sync::Arc::new(::std::sync::Mutex::new(move || {
            $crate::governance::tla::get_tla_globals(&raw_ptr)
        }))
    }};
}

/// Finalizes the maturity disbursement for a neuron. See
/// `ic_nns_governance::pb::v1::manage_neuron::DisburseMaturity` for more information. Returns the
/// delay until the time when the finalization should be run again.
// TODO: finish instrumenting this
#[cfg_attr(feature = "tla", tla_update_method(FINALIZE_MATURITY_DISBURSEMENT_DESC.clone(), tla_snapshotter!()))]
pub async fn finalize_maturity_disbursement(
    governance: &'static LocalKey<RefCell<Governance>>,
) -> Duration {
    match try_finalize_maturity_disbursement(governance).await {
        Ok(_) => governance.with_borrow(get_delay_until_next_finalization),
        Err(err) => {
            println!("FinalizeMaturityDisbursementTask failed: {}", err);
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
        destination,
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
            to_account: destination.into_account(),
            to_account_identifier: destination.into_account_identifier_proto(),
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
    let account_identifier = destination
        .try_into_account_identifier()
        .map_err(|reason| FinalizeMaturityDisbursementError::AccountConversionFailure { reason })?;
    let mint_icp_operation = MintIcpOperation::new(account_identifier, amount_to_mint_e8s);
    let ledger = governance.with_borrow(|governance| governance.get_ledger());
    tla_log_locals! {
        neuron_id: neuron_id.id,
        current_disbursement: TlaValue::Record(BTreeMap::from(
            [
                ("account_id".to_string(), account_to_tla(account_identifier)),
                ("amount".to_string(), maturity_disbursement_in_progress.amount_e8s.to_tla_value()),
            ]
        ))
    };
    tla_log_label!("Disburse_Maturity_Timer");
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
