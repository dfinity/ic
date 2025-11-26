use ic_cdk::{init, post_upgrade, query, update};
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::reimbursement::InvalidTransactionError;
use ic_ckbtc_minter::tasks::{TaskType, schedule_now};
use ic_ckbtc_minter::{BuildTxError, CanisterRuntime};
use ic_ckdoge_minter::candid_api::EstimateWithdrawalFeeError;
use ic_ckdoge_minter::{
    DOGECOIN_CANISTER_RUNTIME, EstimateFeeArg, Event, EventType, GetEventsArg, UpdateBalanceArgs,
    UpdateBalanceError, Utxo, UtxoStatus,
    candid_api::{
        GetDogeAddressArgs, RetrieveDogeOk, RetrieveDogeStatus, RetrieveDogeStatusRequest,
        RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError, WithdrawalFee,
    },
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
    ic_cdk::futures::in_executor_context(|| {
        #[cfg(feature = "self_check")]
        ok_or_die(check_invariants());

        ic_ckbtc_minter::timer(DOGECOIN_CANISTER_RUNTIME);
    });
}

#[post_upgrade]
fn post_upgrade() {
    todo!("XC-495")
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
    // Only the address type matters for the amount of vbytes, not the actual bytes in the address.
    let dummy_minter_address = BitcoinAddress::P2pkh([u8::MAX; 20]);
    let dummy_recipient_address = BitcoinAddress::P2pkh([42_u8; 20]);

    ic_ckbtc_minter::state::read_state(|s| {
        let fee_estimator = DOGECOIN_CANISTER_RUNTIME.fee_estimator(s);
        let withdrawal_amount = arg.amount.unwrap_or(s.fee_based_retrieve_btc_min_amount);

        // TODO DEFI-2518: remove expensive clone operation
        let mut utxos = s.available_utxos.clone();

        ic_ckbtc_minter::queries::estimate_withdrawal_fee(
            &mut utxos,
            withdrawal_amount,
            s.last_median_fee_per_vbyte
                .expect("Dogecoin current fee percentiles not retrieved yet."),
            dummy_minter_address,
            dummy_recipient_address,
            &fee_estimator,
        )
        .map(WithdrawalFee::from)
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
    use ic_ckbtc_minter::{
        state::{eventlog::replay, invariants::CheckInvariantsImpl, read_state},
        storage,
    };

    read_state(|s| {
        s.check_invariants()?;

        let events: Vec<_> = storage::events().collect();
        let recovered_state = replay::<CheckInvariantsImpl>(events.clone().into_iter())
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

// TODO XC-495: Currently events from ckBTC are re-used and it might be worthwhile to split
// both types of events:
// 1) ckBTC has some deprecated events only for backwards-compatibility purposes
// 2) Some events, related to KYT are not applicable to Dogecoin.
// 3) Some fundamental types like BitcoinAddress are also misused to fit in a Dogecoin address.
#[query(hidden = true)]
fn get_events(args: GetEventsArg) -> Vec<Event> {
    const MAX_EVENTS_PER_QUERY: usize = 2000;

    ic_ckbtc_minter::storage::events()
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
