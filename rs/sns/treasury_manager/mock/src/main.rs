use ic_canister_log::{declare_log_buffer, log};
use ic_cdk::{init, post_upgrade, query, update};
use sns_treasury_manager::{
    AuditTrail, AuditTrailRequest, BalancesRequest, DepositRequest, TreasuryManager,
    TreasuryManagerArg, TreasuryManagerResult, WithdrawRequest,
};
use std::time::Duration;

const PURPOSE: &str = "This is a template canister that is not intended to be used directly.";

const RUN_PERIODIC_TASKS_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

pub(crate) struct MockTreasuryManager {}

impl TreasuryManager for MockTreasuryManager {
    async fn withdraw(&mut self, _request: WithdrawRequest) -> TreasuryManagerResult {
        unimplemented!("{}", PURPOSE)
    }

    async fn deposit(&mut self, _request: DepositRequest) -> TreasuryManagerResult {
        unimplemented!("{}", PURPOSE)
    }

    fn audit_trail(&self, _request: AuditTrailRequest) -> AuditTrail {
        unimplemented!("{}", PURPOSE)
    }

    fn balances(&self, _request: BalancesRequest) -> TreasuryManagerResult {
        unimplemented!("{}", PURPOSE)
    }

    async fn refresh_balances(&mut self) {
        unimplemented!("{}", PURPOSE)
    }

    async fn issue_rewards(&mut self) {
        unimplemented!("{}", PURPOSE)
    }
}

declare_log_buffer!(name = LOG, capacity = 100);

fn log(msg: &str) {
    let msg = format!("[MockTreasuryManager] {msg}");
    ic_cdk::api::debug_print(&msg);
    log!(LOG, "{}", msg);
}

fn canister_state() -> MockTreasuryManager {
    MockTreasuryManager {}
}

fn check_caller_is_controller_or_self() {
    let caller = ic_cdk::api::msg_caller();

    if caller == ic_cdk::api::canister_self() {
        return;
    }

    if ic_cdk::api::is_controller(&caller) {
        return;
    }

    ic_cdk::trap("Only a controller can call this method.");
}

#[update]
async fn deposit(request: DepositRequest) -> TreasuryManagerResult {
    check_caller_is_controller_or_self();

    log("deposit.");

    let result = canister_state().deposit(request).await?;

    Ok(result)
}

#[update]
async fn withdraw(request: WithdrawRequest) -> TreasuryManagerResult {
    check_caller_is_controller_or_self();

    log("withdraw.");

    let result = canister_state().withdraw(request).await?;

    Ok(result)
}

#[query]
fn balances(request: BalancesRequest) -> TreasuryManagerResult {
    canister_state().balances(request)
}

#[query]
fn audit_trail(request: AuditTrailRequest) -> AuditTrail {
    canister_state().audit_trail(request)
}

async fn run_periodic_tasks() {
    log("run_periodic_tasks.");

    let mut state = canister_state();

    state.refresh_balances().await;

    state.issue_rewards().await;
}

fn init_periodic_tasks() {
    let _new_timer_id =
        ic_cdk_timers::set_timer_interval(RUN_PERIODIC_TASKS_INTERVAL, async || {
            run_periodic_tasks().await
        });
}

#[init]
async fn canister_init(arg: TreasuryManagerArg) {
    let TreasuryManagerArg::Init(_init) = arg else {
        ic_cdk::trap("Expected TreasuryManagerArg::Init on canister install.");
    };

    init_periodic_tasks();
}

#[post_upgrade]
fn canister_post_upgrade(arg: TreasuryManagerArg) {
    log("post_upgrade.");

    let TreasuryManagerArg::Upgrade(_upgrade) = arg else {
        ic_cdk::trap("Expected TreasuryManagerArg::Upgrade on canister upgrade.");
    };

    init_periodic_tasks();
}

fn candid_service() -> String {
    candid::export_service!();
    __export_service()
}

fn main() {
    candid::export_service!();
    println!("{}", candid_service());
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid_parser::utils::{CandidSource, service_equal};

    #[test]
    fn test_implemented_interface_matches_declared_interface_exactly() {
        let did_path = std::env::var("TREASURY_MANAGER_DID_PATH")
            .expect("TREASURY_MANAGER_DID_PATH environment variable not set");

        let declared_interface =
            std::fs::read_to_string(&did_path).expect("Failed to read DID file");

        let declared_interface = CandidSource::Text(&declared_interface);

        let implemented_interface_str = candid_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
    }
}
