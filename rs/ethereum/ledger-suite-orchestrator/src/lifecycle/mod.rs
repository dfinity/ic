use crate::candid::{AddErc20Arg, InitArg, UpgradeArg};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::management::IcCanisterRuntime;
use crate::scheduler::{Erc20Contract, Task};
use crate::state::{init_state, mutate_state, read_state, State};
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
    setup_timers()
}

pub fn post_upgrade(_upgrade_arg: Option<UpgradeArg>) {
    setup_timers()
}

pub fn add_erc20(token: AddErc20Arg) {
    let contract = Erc20Contract::try_from(token.contract.clone())
        .unwrap_or_else(|e| ic_cdk::trap(&format!("Invalid ERC-20 contract {:?}: {}", token, e)));
    //TODO XC-29: ensure that contract is not already managed, otherwise trap
    mutate_state(|s| s.add_task(Task::InstallLedgerSuite(contract, token.ledger_init_arg)));

    ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(execute_tasks()));
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
