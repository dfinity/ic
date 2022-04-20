//! The main function of ic-recovery processes command line arguments.
//! Calls the corresponding recovery process CLI.
use clap::Parser;
use ic_recovery::cli;
use ic_recovery::cmd::{RecoveryToolArgs, SubCommand};
use ic_recovery::RecoveryArgs;
use slog::{o, Drain};

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, o!());

    let args = RecoveryToolArgs::parse();

    match args.subcmd {
        SubCommand::AppSubnetRecovery(subnet_recovery_args) => {
            let recovery_args = RecoveryArgs {
                dir: args.dir,
                nns_url: args.nns_url,
                replica_version: args.replica_version,
                key_file: args.key_file,
            };
            cli::app_subnet_recovery(
                logger.clone(),
                recovery_args,
                subnet_recovery_args,
                args.test,
            )
        }
    }
}
