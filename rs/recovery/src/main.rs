//! The main function of ic-recovery processes command line arguments.
//! Calls the corresponding recovery process CLI.
use clap::Parser;
use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use ic_canister_sandbox_launcher::sandbox_launcher_main;
use ic_recovery::args_merger::merge;
use ic_recovery::cmd::{RecoveryToolArgs, SubCommand};
use ic_recovery::recovery_state::RecoveryState;
use ic_recovery::RecoveryArgs;
use ic_recovery::{cli, util};
use slog::{info, warn, Logger};

fn main() {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
        return;
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
        return;
    }

    let logger = util::make_logger();
    let args = RecoveryToolArgs::parse();
    let mut recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        key_file: args.key_file,
        test_mode: args.test,
    };
    let mut neuron_args = None;
    let mut subcommand_args = args.subcmd;

    let state =
        RecoveryState::read(&recovery_args.dir).expect("Failed to read the recovery state file");

    if let Some(state) = state {
        info!(
            &logger,
            "Recovery state file found with parameters {}",
            serde_json::to_string_pretty(&state).expect("Failed to stringify the recovery state"),
        );

        if cli::consent_given(&logger, "Resume previously started recovery?") {
            let state = maybe_update_state(&logger, state, &recovery_args, &subcommand_args);
            // Immediately save the state with potentially new arguments
            if let Err(e) = state.save() {
                warn!(logger, "Failed to save the recovery state: {}", e);
            }

            recovery_args = state.recovery_args;
            neuron_args = state.neuron_args;
            subcommand_args = Some(state.subcommand_args);
        }
    }

    match subcommand_args.expect("subcommand not provided") {
        SubCommand::AppSubnetRecovery(subnet_recovery_args) => cli::app_subnet_recovery(
            logger.clone(),
            recovery_args,
            subnet_recovery_args,
            neuron_args,
        ),
        SubCommand::NNSRecoverySameNodes(nns_recovery_args) => {
            cli::nns_recovery_same_nodes(logger.clone(), recovery_args, nns_recovery_args)
        }
        SubCommand::NNSRecoveryFailoverNodes(nns_recovery_args) => {
            cli::nns_recovery_failover_nodes(
                logger.clone(),
                recovery_args,
                nns_recovery_args,
                neuron_args,
            )
        }
    }
}

/// Checks if there are any differences between the arguments passed to the tool in this run
/// compared to the last run. If there are, asks user whether to use the new arguments.
fn maybe_update_state(
    logger: &Logger,
    recovery_state: RecoveryState,
    recovery_args: &RecoveryArgs,
    subcommand_args: &Option<SubCommand>,
) -> RecoveryState {
    let mut updated_recovery_state = recovery_state.clone();

    updated_recovery_state.recovery_args = merge(
        logger,
        "Recovery Arguments",
        &recovery_state.recovery_args,
        recovery_args,
    )
    .unwrap();

    if let Some(subcommand_args) = subcommand_args.as_ref() {
        updated_recovery_state.subcommand_args = merge(
            logger,
            "Subcommand Arguments",
            &recovery_state.subcommand_args,
            subcommand_args,
        )
        .expect(
            "Failed to merge subcommand arguments. \
             Did you use a different subcommand than in the previous run?",
        );
    }

    if updated_recovery_state != recovery_state
        && cli::consent_given(
            logger,
            "The arguments are different now than in the previous run. \
            Use the new arguments?",
        )
    {
        updated_recovery_state
    } else {
        recovery_state
    }
}
