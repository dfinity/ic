use crate::candid::{AddErc20Arg, InitArg, UpgradeArg};
use crate::logs::INFO;
use crate::scheduler::{schedule_now, InstallLedgerSuiteArgs, Task, UpgradeOrchestratorArgs};
use crate::state::{init_state, read_state, GitCommitHash, State};
use crate::storage::{mutate_wasm_store, read_wasm_store, record_icrc1_ledger_suite_wasms};
use ic_canister_log::log;
use std::str::FromStr;

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
            schedule_now(Task::InstallLedgerSuite(args));
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
    schedule_now(Task::MaybeTopUp);
}
