use clap::Parser;
use ic_backup::backup_helper::BackupHelper;
use ic_backup::cmd::BackupArgs;
use slog::{o, Drain};

fn main() {
    // initialize a logger
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    // initialize backup structure
    let _b = BackupHelper::new(log, BackupArgs::parse()).unwrap();
}
