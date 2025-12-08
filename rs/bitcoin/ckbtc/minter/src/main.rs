use candid::Principal;
use ic_btc_interface::Utxo;
use ic_cdk::{init, post_upgrade, query, update};
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::lifecycle::{self, init::MinterArg};
use ic_ckbtc_minter::queries::{EstimateFeeArg, RetrieveBtcStatusRequest, WithdrawalFee};
use ic_ckbtc_minter::reimbursement::InvalidTransactionError;
use ic_ckbtc_minter::state::eventlog::Event;
use ic_ckbtc_minter::state::{
    BtcRetrievalStatusV2, RetrieveBtcStatus, RetrieveBtcStatusV2, mutate_state, read_state,
};
use ic_ckbtc_minter::tasks::{TaskType, schedule_now};
use ic_ckbtc_minter::updates::retrieve_btc::{
    RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk, RetrieveBtcWithApprovalArgs,
    RetrieveBtcWithApprovalError,
};
use ic_ckbtc_minter::updates::{
    self,
    get_btc_address::GetBtcAddressArgs,
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus},
};
use ic_ckbtc_minter::{BuildTxError, CanisterRuntime, IC_CANISTER_RUNTIME, MinterInfo};
use ic_ckbtc_minter::{
    state::eventlog::{EventType, GetEventsArg},
    storage,
};
use ic_http_types::{HttpRequest, HttpResponse};
use icrc_ledger_types::icrc1::account::Account;

#[init]
fn init(args: MinterArg) {
    match args {
        MinterArg::Init(args) => {
            storage::record_event(EventType::Init(args.clone()), &IC_CANISTER_RUNTIME);
            lifecycle::init::init(args, &IC_CANISTER_RUNTIME);
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
    schedule_now(TaskType::ProcessLogic(true), &IC_CANISTER_RUNTIME);
    schedule_now(TaskType::RefreshFeePercentiles, &IC_CANISTER_RUNTIME);
}

#[cfg(feature = "self_check")]
fn ok_or_die(result: Result<(), String>) {
    if let Err(msg) = result {
        ic_cdk::println!("{}", msg);
        ic_cdk::trap(&msg);
    }
}

/// Checks that ckBTC minter state internally consistent.
#[cfg(feature = "self_check")]
fn check_invariants() -> Result<(), String> {
    use ic_ckbtc_minter::state::{eventlog::replay, invariants::CheckInvariantsImpl};

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
#[update]
async fn refresh_fee_percentiles() {
    // Use `TimerLogicGuard` here because:
    // 1. `estimate_fee_per_vbyte` could potentially change the state.
    // 2. `estimate_fee_per_vbyte` is also called from timer
    //    `TaskType::ProcessLogic` and `TaskType::RefreshFeePercentiles`.
    let _guard = match ic_ckbtc_minter::guard::TimerLogicGuard::new() {
        Some(guard) => guard,
        None => return,
    };
    let _ = ic_ckbtc_minter::estimate_fee_per_vbyte(&IC_CANISTER_RUNTIME).await;
}

fn check_postcondition<T>(t: T) -> T {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());
    t
}

fn check_anonymous_caller() {
    if ic_cdk::api::msg_caller() == Principal::anonymous() {
        panic!("anonymous caller not allowed")
    }
}

#[unsafe(export_name = "canister_global_timer")]
fn timer() {
    // ic_ckbtc_minter::timer invokes ic_cdk::spawn
    // which must be wrapped in in_executor_context
    // as required by the new ic-cdk-executor.
    ic_cdk::futures::internals::in_executor_context(|| {
        #[cfg(feature = "self_check")]
        ok_or_die(check_invariants());

        ic_ckbtc_minter::timer(IC_CANISTER_RUNTIME);
    });
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    let mut upgrade_arg: Option<UpgradeArgs> = None;
    if let Some(minter_arg) = minter_arg {
        upgrade_arg = match minter_arg {
            MinterArg::Upgrade(upgrade_args) => upgrade_args,
            MinterArg::Init(_) => panic!("expected Option<UpgradeArgs> got InitArgs."),
        };
    }
    lifecycle::upgrade::post_upgrade(upgrade_arg, &IC_CANISTER_RUNTIME);
    setup_tasks();
}

#[update]
async fn get_btc_address(args: GetBtcAddressArgs) -> String {
    updates::get_btc_address::get_btc_address(args).await
}

#[update]
async fn get_withdrawal_account() -> Account {
    check_anonymous_caller();
    updates::get_withdrawal_account::get_withdrawal_account().await
}

#[update]
async fn retrieve_btc(args: RetrieveBtcArgs) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    check_anonymous_caller();
    check_postcondition(updates::retrieve_btc::retrieve_btc(args, &IC_CANISTER_RUNTIME).await)
}

#[update]
async fn retrieve_btc_with_approval(
    args: RetrieveBtcWithApprovalArgs,
) -> Result<RetrieveBtcOk, RetrieveBtcWithApprovalError> {
    check_anonymous_caller();
    check_postcondition(
        updates::retrieve_btc::retrieve_btc_with_approval(args, &IC_CANISTER_RUNTIME).await,
    )
}

#[query]
fn retrieve_btc_status(req: RetrieveBtcStatusRequest) -> RetrieveBtcStatus {
    read_state(|s| s.retrieve_btc_status(req.block_index))
}

#[query]
fn retrieve_btc_status_v2(req: RetrieveBtcStatusRequest) -> RetrieveBtcStatusV2 {
    read_state(|s| s.retrieve_btc_status_v2(req.block_index))
}

#[query]
fn retrieve_btc_status_v2_by_account(target: Option<Account>) -> Vec<BtcRetrievalStatusV2> {
    read_state(|s| s.retrieve_btc_status_v2_by_account(target))
}

#[query]
fn get_known_utxos(args: UpdateBalanceArgs) -> Vec<Utxo> {
    ic_ckbtc_minter::queries::get_known_utxos(args)
}

#[update]
async fn update_balance(args: UpdateBalanceArgs) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    check_anonymous_caller();
    check_postcondition(updates::update_balance::update_balance(args, &IC_CANISTER_RUNTIME).await)
}

#[update]
async fn get_canister_status() -> ic_cdk::management_canister::CanisterStatusResult {
    ic_cdk::management_canister::canister_status(&ic_cdk::management_canister::CanisterStatusArgs {
        canister_id: ic_cdk::api::canister_self(),
    })
    .await
    .expect("failed to fetch canister status")
}

#[cfg(feature = "self_check")]
#[update]
async fn upload_events(events: Vec<Event>) {
    for event in events {
        storage::record_event(event.payload, &IC_CANISTER_RUNTIME);
    }
}

#[query]
fn estimate_withdrawal_fee(arg: EstimateFeeArg) -> WithdrawalFee {
    // This is a **query** endpoint, so mutating the state is not an issue
    // since any change will be discarded.
    match mutate_state(|s| {
        let fee_estimator = IC_CANISTER_RUNTIME.fee_estimator(s);
        let withdrawal_amount = arg.amount.unwrap_or(s.fee_based_retrieve_btc_min_amount);
        ic_ckbtc_minter::estimate_retrieve_btc_fee(
            &mut s.available_utxos,
            withdrawal_amount,
            s.last_median_fee_per_vbyte
                .expect("Bitcoin current fee percentiles not retrieved yet."),
            &fee_estimator,
        )
    }) {
        Ok(fee) => fee,
        Err(BuildTxError::NotEnoughFunds) => {
            panic!("ERROR: withdrawal amount is too large for the minter")
        }
        Err(e @ BuildTxError::DustOutput { .. } | e @ BuildTxError::AmountTooLow) => panic!(
            "BUG: withdrawal amount is too low ({e:?}), but the withdrawal amount should be large enough to prevent this"
        ),
        Err(BuildTxError::InvalidTransaction(
            e @ InvalidTransactionError::TooManyInputs { .. },
        )) => panic!(
            "ERROR: the minter cannot currently process such a large withdrawal amount because it would require too many inputs ({e:?}), \
            resulting in the transaction being potentially non-standard"
        ),
    }
}

#[query]
fn get_minter_info() -> MinterInfo {
    read_state(|s| MinterInfo {
        check_fee: s.check_fee,
        min_confirmations: s.min_confirmations,
        retrieve_btc_min_amount: s.fee_based_retrieve_btc_min_amount,
    })
}

#[query]
fn get_deposit_fee() -> u64 {
    read_state(|s| s.check_fee)
}

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::trap("update call rejected");
    }

    ic_ckbtc_minter::queries::http_request(req)
}

#[query]
fn get_events(args: GetEventsArg) -> Vec<Event> {
    const MAX_EVENTS_PER_QUERY: usize = 2000;

    storage::events()
        .skip(args.start as usize)
        .take(MAX_EVENTS_PER_QUERY.min(args.length as usize))
        .collect()
}

#[cfg(feature = "self_check")]
#[query]
fn self_check() -> Result<(), String> {
    check_invariants()
}

#[query(hidden = true)]
fn __get_candid_interface_tmp_hack() -> &'static str {
    include_str!(env!("CKBTC_MINTER_DID_PATH"))
}

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};

    fn source_to_str(source: &CandidSource) -> String {
        match source {
            CandidSource::File(f) => std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string()),
            CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(new_name: &str, new: CandidSource, old_name: &str, old: CandidSource) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{new_name} is not compatible with {old_name}!\n\n\
            {new_name}:\n\
            {new_str}\n\n\
            {old_name}:\n\
            {old_str}\n"
                );
                panic!("{e:?}");
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("ckbtc_minter.did");

    check_service_equal(
        "actual ledger candid interface",
        candid_parser::utils::CandidSource::Text(&new_interface),
        "declared candid interface in ckbtc_minter.did file",
        candid_parser::utils::CandidSource::File(old_interface.as_path()),
    );
}
