use candid::Principal;
use ic_btc_interface::Utxo;
use ic_canister_log::export as export_logs;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_ckbtc_minter::dashboard::build_dashboard;
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::lifecycle::{self, init::MinterArg};
use ic_ckbtc_minter::metrics::encode_metrics;
use ic_ckbtc_minter::queries::{EstimateFeeArg, RetrieveBtcStatusRequest, WithdrawalFee};
use ic_ckbtc_minter::state::{
    read_state, BtcRetrievalStatusV2, RetrieveBtcStatus, RetrieveBtcStatusV2,
};
use ic_ckbtc_minter::tasks::{schedule_now, TaskType};
use ic_ckbtc_minter::updates::retrieve_btc::{
    RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk, RetrieveBtcWithApprovalArgs,
    RetrieveBtcWithApprovalError,
};
use ic_ckbtc_minter::updates::{
    self,
    get_btc_address::GetBtcAddressArgs,
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus},
};
use ic_ckbtc_minter::MinterInfo;
use ic_ckbtc_minter::{
    state::eventlog::{Event, GetEventsArg},
    storage, {Log, LogEntry, Priority},
};
use icrc_ledger_types::icrc1::account::Account;
use std::str::FromStr;

#[init]
fn init(args: MinterArg) {
    match args {
        MinterArg::Init(args) => {
            storage::record_event(&Event::Init(args.clone()));
            lifecycle::init::init(args);
            schedule_now(TaskType::ProcessLogic);
            schedule_now(TaskType::RefreshFeePercentiles);
            schedule_now(TaskType::DistributeKytFee);

            #[cfg(feature = "self_check")]
            ok_or_die(check_invariants())
        }
        MinterArg::Upgrade(_) => {
            panic!("expected InitArgs got UpgradeArgs");
        }
    }
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
    use ic_ckbtc_minter::state::eventlog::replay;

    read_state(|s| {
        s.check_invariants()?;

        let events: Vec<_> = storage::events().collect();
        let recovered_state = replay(events.clone().into_iter())
            .unwrap_or_else(|e| panic!("failed to replay log {:?}: {:?}", events, e));

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
async fn distribute_kyt_fee() {
    let _guard = match ic_ckbtc_minter::guard::DistributeKytFeeGuard::new() {
        Some(guard) => guard,
        None => return,
    };
    ic_ckbtc_minter::distribute_kyt_fees().await;
}

#[cfg(feature = "self_check")]
#[update]
async fn refresh_fee_percentiles() {
    let _ = ic_ckbtc_minter::estimate_fee_per_vbyte().await;
}

fn check_postcondition<T>(t: T) -> T {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());
    t
}

fn check_anonymous_caller() {
    if ic_cdk::caller() == Principal::anonymous() {
        panic!("anonymous caller not allowed")
    }
}

#[export_name = "canister_global_timer"]
fn timer() {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());

    ic_ckbtc_minter::timer();
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
    lifecycle::upgrade::post_upgrade(upgrade_arg);
    schedule_now(TaskType::ProcessLogic);
    schedule_now(TaskType::RefreshFeePercentiles);
    schedule_now(TaskType::DistributeKytFee);
}

#[update]
async fn get_btc_address(args: GetBtcAddressArgs) -> String {
    check_anonymous_caller();
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
    check_postcondition(updates::retrieve_btc::retrieve_btc(args).await)
}

#[update]
async fn retrieve_btc_with_approval(
    args: RetrieveBtcWithApprovalArgs,
) -> Result<RetrieveBtcOk, RetrieveBtcWithApprovalError> {
    check_anonymous_caller();
    check_postcondition(updates::retrieve_btc::retrieve_btc_with_approval(args).await)
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
    read_state(|s| {
        s.known_utxos_for_account(&Account {
            owner: args.owner.unwrap_or(ic_cdk::caller()),
            subaccount: args.subaccount,
        })
    })
}

#[update]
async fn update_balance(args: UpdateBalanceArgs) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    check_anonymous_caller();
    check_postcondition(updates::update_balance::update_balance(args).await)
}

#[update]
async fn get_canister_status() -> ic_cdk::api::management_canister::main::CanisterStatusResponse {
    ic_cdk::api::management_canister::main::canister_status(
        ic_cdk::api::management_canister::main::CanisterIdRecord {
            canister_id: ic_cdk::id(),
        },
    )
    .await
    .expect("failed to fetch canister status")
    .0
}

#[query]
fn estimate_withdrawal_fee(arg: EstimateFeeArg) -> WithdrawalFee {
    read_state(|s| {
        ic_ckbtc_minter::estimate_fee(
            &s.available_utxos,
            arg.amount,
            s.last_fee_per_vbyte[50],
            s.kyt_fee,
        )
    })
}

#[query]
fn get_minter_info() -> MinterInfo {
    read_state(|s| MinterInfo {
        kyt_fee: s.kyt_fee,
        min_confirmations: s.min_confirmations,
        retrieve_btc_min_amount: s.retrieve_btc_min_amount,
    })
}

#[query]
fn get_deposit_fee() -> u64 {
    read_state(|s| s.kyt_fee)
}

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        let account_to_utxos_start = match req.raw_query_param("account_to_utxos_start") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length(
                            "failed to parse the 'account_to_utxos_start' parameter",
                        )
                        .build()
                }
            },
            None => 0,
        };
        let dashboard: Vec<u8> = build_dashboard(account_to_utxos_start);
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else if req.path() == "/logs" {
        use serde_json;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build()
                }
            },
            None => 0,
        };

        let mut entries: Log = Default::default();
        for entry in export_logs(&ic_ckbtc_minter::logs::P0) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority: Priority::P0,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        for entry in export_logs(&ic_ckbtc_minter::logs::P1) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority: Priority::P1,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        entries
            .entries
            .retain(|entry| entry.timestamp >= max_skip_timestamp);
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
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
    use candid_parser::utils::{service_equal, CandidSource};

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
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
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
