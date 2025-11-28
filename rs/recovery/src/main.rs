//! The main function of ic-recovery processes command line arguments.
//! Calls the corresponding recovery process CLI.
use clap::Parser;
use ic_canister_sandbox_backend_lib::{
    RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG, RUN_AS_SANDBOX_LAUNCHER_FLAG,
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main,
};
use ic_recovery::{
    RecoveryArgs, cli,
    cmd::{RecoveryToolArgs, SubCommand},
    util,
};

fn main() {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
        return;
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
        return;
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
        return;
    }

    let logger = util::make_logger();
    let args = RecoveryToolArgs::parse();

    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        admin_key_file: args.admin_key_file,
        test_mode: args.test_mode,
        skip_prompts: args.skip_prompts,
        use_local_binaries: args.use_local_binaries,
    };

    let recovery_state = cli::read_and_maybe_update_state(&logger, recovery_args, args.subcmd);

    match recovery_state.subcommand_args {
        SubCommand::AppSubnetRecovery(subnet_recovery_args) => cli::app_subnet_recovery(
            logger.clone(),
            recovery_state.recovery_args,
            subnet_recovery_args,
            recovery_state.neuron_args,
        ),
        SubCommand::NNSRecoverySameNodes(nns_recovery_args) => cli::nns_recovery_same_nodes(
            logger.clone(),
            recovery_state.recovery_args,
            nns_recovery_args,
        ),
        SubCommand::NNSRecoveryFailoverNodes(nns_recovery_args) => {
            cli::nns_recovery_failover_nodes(
                logger.clone(),
                recovery_state.recovery_args,
                nns_recovery_args,
                recovery_state.neuron_args,
            )
        }
    }
}
