//! The main function of ic-recovery processes command line arguments.
//! Calls the corresponding recovery process CLI.
use clap::Parser;
use ic_recovery::cmd::{RecoveryToolArgs, SubCommand};
use ic_recovery::RecoveryArgs;
use ic_recovery::{cli, util};

fn main() {
    let logger = util::make_logger();

    let args = RecoveryToolArgs::parse();
    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        key_file: args.key_file,
    };

    match args.subcmd {
        SubCommand::AppSubnetRecovery(subnet_recovery_args) => cli::app_subnet_recovery(
            logger.clone(),
            recovery_args,
            subnet_recovery_args,
            args.test,
        ),
        SubCommand::NNSRecoverySameNodes(nns_recovery_args) => cli::nns_recovery_same_nodes(
            logger.clone(),
            recovery_args,
            nns_recovery_args,
            args.test,
        ),
        SubCommand::NNSRecoveryFailoverNodes(nns_recovery_args) => {
            cli::nns_recovery_failover_nodes(
                logger.clone(),
                recovery_args,
                *nns_recovery_args,
                args.test,
            )
        }
    }
}
