use crate::candid::{AddErc20Arg, InitArg, UpgradeArg};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::management::IcCanisterRuntime;
use crate::scheduler::{InstallLedgerSuiteArgs, Task, UpgradeOrchestratorArgs};
use crate::state::{init_state, mutate_state, read_state, State};
use crate::storage::{mutate_wasm_store, read_wasm_store, record_icrc1_ledger_suite_wasms};
use ic_canister_log::log;
use std::time::Duration;

const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

pub fn init(init_arg: InitArg) {
    log!(
        INFO,
        "[init]: initialized orchestrator with arg: {:?}",
        init_arg
    );
    init_state(State::from(init_arg));
    mutate_wasm_store(|s| record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time()))
        .expect("BUG: failed to record icrc1 ledger suite wasms during initialisation");
    setup_timers()
}

pub fn post_upgrade(upgrade_arg: Option<UpgradeArg>) {
    //TODO: in case UpgradeArg is present, 1) refresh wasms binaries in stable memory and plan upgrade of managed canisters
    if let Some(arg) = upgrade_arg {
        if arg.upgrade_icrc1_ledger_suite() {
            mutate_wasm_store(|s| record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time()))
                .expect("BUG: failed to record icrc1 ledger suite wasms during upgrade");
        }
        match read_wasm_store(|w| UpgradeOrchestratorArgs::validate_upgrade_arg(w, arg.clone())) {
            Ok(_valid_upgrade_args) => {
                //TODO XC-30 add upgrade managed canisters task
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(execute_tasks()));
            }
            Err(e) => {
                ic_cdk::trap(&format!(
                    "[post_upgrade]: ERROR: invalid arguments to upgrade {:?}: {:?}",
                    arg, e
                ));
            }
        }
    }
    setup_timers()
}

pub fn add_erc20(token: AddErc20Arg) {
    mutate_wasm_store(|s| record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time()))
        .expect("BUG: failed to record icrc1 ledger suite wasms when adding new ERC-20 token");
    match read_state(|s| {
        read_wasm_store(|w| InstallLedgerSuiteArgs::validate_add_erc20(s, w, token.clone()))
    }) {
        Ok(args) => {
            mutate_state(|s| s.add_task(Task::InstallLedgerSuite(args)));
            ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(execute_tasks()));
        }
        Err(e) => {
            ic_cdk::trap(&format!(
                "[add_erc20]: ERROR: invalid arguments to add erc20 token {:?}: {:?}",
                token, e
            ));
        }
    }
    setup_timers()
}

pub fn setup_timers() {
    ic_cdk_timers::set_timer_interval(Duration::from_secs(1), || ic_cdk::spawn(execute_tasks()));
}

async fn execute_tasks() {
    let _guard = match TimerGuard::new() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let mut tasks = read_state(|s| s.tasks().clone());
    let _result = tasks.execute(&IC_CANISTER_RUNTIME).await;
    // TODO: just resettting the tasks is for sure wrong (tasks could have come in between)
    mutate_state(|s| s.set_tasks(tasks));
}
