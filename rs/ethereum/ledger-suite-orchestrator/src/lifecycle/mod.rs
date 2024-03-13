use crate::candid::{AddErc20Arg, InitArg, UpgradeArg};
use crate::guard::TimerGuard;
use crate::logs::INFO;
use crate::management::IcCanisterRuntime;
use crate::scheduler::{InstallLedgerSuiteArgs, Task, UpgradeOrchestratorArgs};
use crate::state::{init_state, mutate_state, read_state, GitCommitHash, State};
use crate::storage::{mutate_wasm_store, read_wasm_store, record_icrc1_ledger_suite_wasms};
use ic_canister_log::log;
use std::str::FromStr;
use std::time::Duration;

const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

pub fn init(init_arg: InitArg) {
    log!(
        INFO,
        "[init]: initialized orchestrator with arg: {:?}",
        init_arg
    );
    init_state(
        State::try_from(init_arg).expect("ERROR: failed to initialize ledger suite orchestrator"),
    );
    setup_tasks_and_timers()
}

pub fn post_upgrade(upgrade_arg: Option<UpgradeArg>) {
    if let Some(arg) = upgrade_arg {
        if arg.upgrade_icrc1_ledger_suite() {
            let git_commit = GitCommitHash::from_str(
                arg.git_commit_hash
                    .as_ref()
                    .expect("ERROR: missing git commit hash"),
            )
            .expect("ERROR: invalid git commit hash");
            mutate_wasm_store(|s| {
                record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time(), git_commit)
            })
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
    read_state(|s| s.validate_config().expect("ERROR: invalid state"));
    setup_tasks_and_timers()
}

pub fn add_erc20(token: AddErc20Arg) {
    let git_commit =
        GitCommitHash::from_str(&token.git_commit_hash).expect("ERROR: invalid git commit hash");
    mutate_wasm_store(|s| record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time(), git_commit))
        .expect("BUG: failed to record icrc1 ledger suite wasms when adding new ERC-20 token");
    match read_state(|s| {
        read_wasm_store(|w| InstallLedgerSuiteArgs::validate_add_erc20(s, w, token.clone()))
    }) {
        Ok(args) => {
            let erc20_token = args.erc20_contract().clone();
            mutate_state(|s| s.add_task(Task::InstallLedgerSuite(args)));
            mutate_state(|s| {
                if let Some(&minter_id) = s.minter_id() {
                    s.add_task(Task::NotifyErc20Added {
                        erc20_token,
                        minter_id,
                    });
                }
            });
            ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(execute_tasks()));
        }
        Err(e) => {
            ic_cdk::trap(&format!(
                "[add_erc20]: ERROR: invalid arguments to add erc20 token {:?}: {:?}",
                token, e
            ));
        }
    }
    read_state(|s| s.validate_config().expect("ERROR: invalid state"));
    setup_tasks_and_timers()
}

pub fn setup_tasks_and_timers() {
    ic_cdk_timers::set_timer_interval(Duration::from_secs(60 * 60), || {
        ic_cdk::spawn(execute_tasks())
    });
}

async fn execute_tasks() {
    let _guard = match TimerGuard::new() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let mut tasks = read_state(|s| s.tasks().clone());
    if !tasks.contains(Task::MaybeTopUp) {
        tasks.add_task(Task::MaybeTopUp);
    }
    assert!(tasks.contains(Task::MaybeTopUp));
    let _result = tasks.execute(&IC_CANISTER_RUNTIME).await;
    // TODO: just resettting the tasks is for sure wrong (tasks could have come in between)
    mutate_state(|s| s.set_tasks(tasks));
}
