use candid::candid_method;
use candid::Principal;
use ic_canister_log::export as export_logs;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_ckbtc_minter::dashboard::build_dashboard;
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::lifecycle::{self, init::InitArgs};
use ic_ckbtc_minter::metrics::encode_metrics;
use ic_ckbtc_minter::queries::RetrieveBtcStatusRequest;
use ic_ckbtc_minter::state::{read_state, RetrieveBtcStatus};
use ic_ckbtc_minter::tasks::{schedule_now, TaskType};
use ic_ckbtc_minter::updates::retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk};
use ic_ckbtc_minter::updates::{
    self,
    get_btc_address::GetBtcAddressArgs,
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult},
};
use ic_ckbtc_minter::{
    state::eventlog::{Event, GetEventsArg},
    storage,
};
use ic_icrc1::Account;

#[init]
fn init(args: InitArgs) {
    storage::record_event(&Event::Init(args.clone()));
    lifecycle::init::init(args);
    schedule_now(TaskType::ProcessLogic);

    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants())
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

        // A running heartbeat can temporarily violate invariants.
        if !s.is_timer_running {
            s.check_semantically_eq(&recovered_state)?;
        }

        Ok(())
    })
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
fn post_upgrade(upgrade_args: Option<UpgradeArgs>) {
    lifecycle::upgrade::post_upgrade(upgrade_args)
}

#[candid_method(update)]
#[update]
async fn get_btc_address(args: GetBtcAddressArgs) -> String {
    check_anonymous_caller();
    updates::get_btc_address::get_btc_address(args).await
}

#[candid_method(update)]
#[update]
async fn get_withdrawal_account() -> Account {
    check_anonymous_caller();
    updates::get_withdrawal_account::get_withdrawal_account().await
}

#[candid_method(update)]
#[update]
async fn retrieve_btc(args: RetrieveBtcArgs) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    check_anonymous_caller();
    check_postcondition(updates::retrieve_btc::retrieve_btc(args).await)
}

#[candid_method(query)]
#[query]
fn retrieve_btc_status(req: RetrieveBtcStatusRequest) -> RetrieveBtcStatus {
    check_anonymous_caller();
    read_state(|s| s.retrieve_btc_status(req.block_index))
}

#[candid_method(update)]
#[update]
async fn update_balance(
    args: UpdateBalanceArgs,
) -> Result<UpdateBalanceResult, UpdateBalanceError> {
    check_anonymous_caller();
    check_postcondition(updates::update_balance::update_balance(args).await)
}

#[candid_method(query)]
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
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
        let dashboard: Vec<u8> = build_dashboard();
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else if req.path() == "/logs" {
        use std::io::Write;
        let mut buf = vec![];

        writeln!(&mut buf, "P0 logs:").unwrap();
        for entry in export_logs(&ic_ckbtc_minter::logs::P0) {
            writeln!(
                &mut buf,
                "{} {}:{} {}",
                entry.timestamp, entry.file, entry.line, entry.message
            )
            .unwrap();
        }

        writeln!(&mut buf, "P1 logs:").unwrap();
        for entry in export_logs(&ic_ckbtc_minter::logs::P1) {
            writeln!(
                &mut buf,
                "{} {}:{} {}",
                entry.timestamp, entry.file, entry.line, entry.message
            )
            .unwrap();
        }

        HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain; charset=utf-8")
            .with_body_and_content_length(buf)
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[candid_method(query)]
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

#[query]
fn __get_candid_interface_tmp_hack() -> &'static str {
    include_str!(env!("CKBTC_MINTER_DID_PATH"))
}

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid::utils::CandidSource) -> String {
        match source {
            candid::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_compatible(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_compatible(new, old) {
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

    check_service_compatible(
        "actual ledger candid interface",
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in ckbtc_minter.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
