use ic_cdk::{init, post_upgrade, query, update};
use ic_ckbtc_minter::reimbursement::InvalidTransactionError;
use ic_ckbtc_minter::state::eventlog::EventLogger;
use ic_ckbtc_minter::tasks::{TaskType, schedule_now};
use ic_ckbtc_minter::{BuildTxError, CanisterRuntime};
use ic_ckdoge_minter::candid_api::{EstimateWithdrawalFeeError, MinterInfo};
use ic_ckdoge_minter::event::CkDogeEventLogger;
use ic_ckdoge_minter::{
    DOGECOIN_CANISTER_RUNTIME, EstimateFeeArg, EventType, GetEventsArg, UpdateBalanceArgs,
    UpdateBalanceError, Utxo, UtxoStatus,
    candid_api::{
        GetDogeAddressArgs, RetrieveDogeOk, RetrieveDogeStatus, RetrieveDogeStatusRequest,
        RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError, WithdrawalFee,
    },
    event::CkDogeMinterEvent,
    lifecycle::init::MinterArg,
    updates,
};
use ic_http_types::{HttpRequest, HttpResponse};

#[init]
fn init(args: MinterArg) {
    match args {
        MinterArg::Init(args) => {
            let args = ic_ckbtc_minter::lifecycle::init::InitArgs::from(args);
            ic_ckbtc_minter::storage::record_event(
                EventType::Init(args.clone()),
                &DOGECOIN_CANISTER_RUNTIME,
            );
            ic_ckbtc_minter::lifecycle::init::init(args, &DOGECOIN_CANISTER_RUNTIME);
            setup_tasks();

            #[cfg(feature = "self_check")]
            ok_or_die(check_invariants())
        }
        MinterArg::Upgrade(_) => {
            panic!("expected InitArgs got UpgradeArgs");
        }
    }
}

fn setup_tasks() {
    schedule_now(TaskType::ProcessLogic(true), &DOGECOIN_CANISTER_RUNTIME);
    schedule_now(TaskType::RefreshFeePercentiles, &DOGECOIN_CANISTER_RUNTIME);
}

#[unsafe(export_name = "canister_global_timer")]
fn timer() {
    // ic_ckbtc_minter::timer invokes ic_cdk::spawn
    // which must be wrapped in in_executor_context
    // as required by the new ic-cdk-executor.
    ic_cdk::futures::internals::in_executor_context(|| {
        #[cfg(feature = "self_check")]
        ok_or_die(check_invariants());

        ic_ckbtc_minter::timer(DOGECOIN_CANISTER_RUNTIME);
    });
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    let upgrade_args = match minter_arg {
        Some(MinterArg::Init(_)) => {
            panic!("expected Option<UpgradeArgs> got InitArgs.")
        }
        Some(MinterArg::Upgrade(upgrade_arg)) => {
            upgrade_arg.map(ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs::from)
        }
        None => None,
    };
    ic_ckbtc_minter::lifecycle::upgrade::post_upgrade(upgrade_args, &DOGECOIN_CANISTER_RUNTIME);
    setup_tasks();
}

#[update]
async fn get_doge_address(args: GetDogeAddressArgs) -> String {
    updates::get_doge_address(args).await
}

#[query]
fn get_known_utxos(args: UpdateBalanceArgs) -> Vec<Utxo> {
    ic_ckbtc_minter::queries::get_known_utxos(args)
}

#[update]
async fn update_balance(args: UpdateBalanceArgs) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    check_anonymous_caller();
    check_postcondition(
        ic_ckbtc_minter::updates::update_balance::update_balance(args, &DOGECOIN_CANISTER_RUNTIME)
            .await,
    )
}

#[query]
fn estimate_withdrawal_fee(
    arg: EstimateFeeArg,
) -> Result<WithdrawalFee, EstimateWithdrawalFeeError> {
    // This is a **query** endpoint, so mutating the state is not an issue
    // (even when called in replicated mode) since any change will be discarded.
    ic_ckbtc_minter::state::mutate_state(|s| {
        let fee_estimator = DOGECOIN_CANISTER_RUNTIME.fee_estimator(s);
        let withdrawal_amount = arg.amount.unwrap_or(s.fee_based_retrieve_btc_min_amount);

        ic_ckdoge_minter::fees::estimate_retrieve_doge_fee(
            &mut s.available_utxos,
            withdrawal_amount,
            s.last_median_fee_per_vbyte
                .expect("Bitcoin current fee percentiles not retrieved yet."),
            s.max_num_inputs_in_transaction,
            &fee_estimator,
        )
        .map_err(|e| match e {
            BuildTxError::NotEnoughFunds
            | BuildTxError::InvalidTransaction(InvalidTransactionError::TooManyInputs { .. }) => {
                EstimateWithdrawalFeeError::AmountTooHigh
            }
            BuildTxError::AmountTooLow | BuildTxError::DustOutput { .. } => {
                EstimateWithdrawalFeeError::AmountTooLow {
                    min_amount: s.fee_based_retrieve_btc_min_amount,
                }
            }
        })
    })
}

#[update]
async fn retrieve_doge_with_approval(
    args: RetrieveDogeWithApprovalArgs,
) -> Result<RetrieveDogeOk, RetrieveDogeWithApprovalError> {
    check_anonymous_caller();
    let result = ic_ckbtc_minter::updates::retrieve_btc::retrieve_btc_with_approval(
        args.into(),
        &DOGECOIN_CANISTER_RUNTIME,
    )
    .await
    .map(RetrieveDogeOk::from)
    .map_err(RetrieveDogeWithApprovalError::from);
    check_postcondition(result)
}

fn check_anonymous_caller() {
    if ic_cdk::api::msg_caller() == candid::Principal::anonymous() {
        panic!("anonymous caller not allowed")
    }
}

fn check_postcondition<T>(t: T) -> T {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());
    t
}

#[cfg(feature = "self_check")]
fn ok_or_die(result: Result<(), String>) {
    if let Err(msg) = result {
        ic_cdk::println!("{}", msg);
        ic_cdk::trap(&msg);
    }
}

/// Checks that ckDOGE minter state internally consistent.
#[cfg(feature = "self_check")]
fn check_invariants() -> Result<(), String> {
    use ic_ckbtc_minter::state::{
        eventlog::EventLogger, invariants::CheckInvariantsImpl, read_state,
    };
    use ic_ckdoge_minter::event::CkDogeEventLogger;

    let events_logger = CkDogeEventLogger;

    read_state(|s| {
        s.check_invariants()?;

        let events: Vec<_> = events_logger.events_iter().collect();
        let recovered_state = events_logger
            .replay::<CheckInvariantsImpl>(events.clone().into_iter())
            .unwrap_or_else(|e| panic!("failed to replay log {events:?}: {e:?}"));

        recovered_state.check_invariants()?;

        // A running timer can temporarily violate invariants.
        if !s.is_timer_running {
            s.check_semantically_eq(&recovered_state)?;
        }

        Ok(())
    })
}

#[cfg(feature = "self_check")]
#[query]
fn self_check() -> Result<(), String> {
    check_invariants()
}

#[query]
fn retrieve_doge_status(req: RetrieveDogeStatusRequest) -> RetrieveDogeStatus {
    ic_ckbtc_minter::state::read_state(|s| {
        RetrieveDogeStatus::from(s.retrieve_btc_status_v2(req.block_index))
    })
}

#[query]
fn get_minter_info() -> MinterInfo {
    ic_ckbtc_minter::state::read_state(|s| MinterInfo {
        min_confirmations: s.min_confirmations,
        retrieve_doge_min_amount: s.fee_based_retrieve_btc_min_amount,
    })
}

#[update]
async fn get_canister_status() -> ic_cdk::management_canister::CanisterStatusResult {
    ic_cdk::management_canister::canister_status(&ic_cdk::management_canister::CanisterStatusArgs {
        canister_id: ic_cdk::api::canister_self(),
    })
    .await
    .expect("failed to fetch canister status")
}

// TODO XC-495: Currently events from ckBTC are re-used and it might be worthwhile to split
// both types of events:
// 1) ckBTC has some deprecated events only for backwards-compatibility purposes
// 2) Some events, related to KYT are not applicable to Dogecoin.
// 3) Some fundamental types like BitcoinAddress are also misused to fit in a Dogecoin address.
#[query(hidden = true)]
fn get_events(args: GetEventsArg) -> Vec<CkDogeMinterEvent> {
    const MAX_EVENTS_PER_QUERY: usize = 2000;

    CkDogeEventLogger
        .events_iter()
        .skip(args.start as usize)
        .take(MAX_EVENTS_PER_QUERY.min(args.length as usize))
        .collect()
}

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::trap("update call rejected");
    }

    ic_ckbtc_minter::queries::http_request(req)
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CANDID_FILE_PATH").unwrap());
    let old_interface_content = std::fs::read_to_string(&old_interface)
        .unwrap_or_else(|e| panic!("Failed to read interface file {:?}: {}", old_interface, e));

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(&old_interface),
    )
        .unwrap_or_else(|e| {
            panic!(
                "New interface {new_interface} is not equal to old interface {old_interface_content}: {e}",
            )
        });
}
