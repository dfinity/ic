use crate::candid::{AddErc20Arg, InitArg, UpgradeArg};
use crate::logs::INFO;
use crate::scheduler::{
    schedule_now, InstallLedgerSuiteArgs, Task, UpgradeOrchestratorArgs, IC_CANISTER_RUNTIME,
};
use crate::state::{init_state, mutate_state, read_state, GitCommitHash, State};
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
        if let Some(git_commit_hash) = &arg.git_commit_hash {
            let git_commit_hash =
                GitCommitHash::from_str(git_commit_hash).expect("ERROR: invalid git commit hash");
            let ledger_suite_version = mutate_wasm_store(|s| {
                record_icrc1_ledger_suite_wasms(s, ic_cdk::api::time(), git_commit_hash)
            })
            .expect("BUG: failed to record icrc1 ledger suite wasms during upgrade");
            mutate_state(|s| s.init_ledger_suite_version(ledger_suite_version));
        }
        match read_wasm_store(|w| UpgradeOrchestratorArgs::validate_upgrade_arg(w, arg.clone())) {
            Ok(valid_upgrade_args) => {
                if valid_upgrade_args.upgrade_ledger_suite() {
                    let current_ledger_suite_version =
                        read_state(|s| s.ledger_suite_version().cloned())
                            .expect("BUG: missing ledger suite version");
                    mutate_state(|s| {
                        s.update_ledger_suite_version(
                            valid_upgrade_args
                                .clone()
                                .new_ledger_suite_version(current_ledger_suite_version),
                        )
                    });
                    for erc20 in
                        read_state(|s| s.managed_erc20_tokens_iter().cloned().collect::<Vec<_>>())
                    {
                        schedule_now(
                            Task::UpgradeLedgerSuite(valid_upgrade_args.clone().into_task(erc20)),
                            &IC_CANISTER_RUNTIME,
                        );
                    }
                }
            }
            Err(e) => {
                ic_cdk::trap(&format!(
                    "[post_upgrade]: ERROR: invalid arguments to upgrade {:?}: {:?}",
                    arg, e
                ));
            }
        }
        if let Some(update) = arg.cycles_management {
            mutate_state(|s| update.apply(s.cycles_management_mut()));
        }
    }
    read_state(|s| s.validate_config().expect("ERROR: invalid state"));
    setup_tasks_and_timers()
}

pub fn add_erc20(token: AddErc20Arg) {
    match read_state(|s| {
        read_wasm_store(|w| InstallLedgerSuiteArgs::validate_add_erc20(s, w, token.clone()))
    }) {
        Ok(args) => {
            schedule_now(Task::InstallLedgerSuite(args), &IC_CANISTER_RUNTIME);
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
    schedule_now(Task::DiscoverArchives, &IC_CANISTER_RUNTIME);
    schedule_now(Task::MaybeTopUp, &IC_CANISTER_RUNTIME);
}
