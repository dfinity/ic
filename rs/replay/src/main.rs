//! The main function of ic-replay processes command line arguments.

use clap::Clap;
use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use ic_canister_sandbox_launcher::sandbox_launcher_main;
use ic_replay::cmd::ReplayToolArgs;
use ic_replay::replay;

fn main() {
    // Check if `ic-replay` is running in the canister sandbox mode where it waits
    // for commands from the parent process. This check has to be performed
    // before the arguments are parsed because the parent process does not pass
    // all the normally required arguments of `ic-replay`.
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
    } else {
        crate::replay(ReplayToolArgs::parse());
    }
}
