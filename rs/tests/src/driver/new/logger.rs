#![allow(dead_code)]

use crate::driver::new::constants;
use anyhow::Result;
use slog::{o, Drain, Logger};
use std::fs::File;
use std::{os::unix::prelude::AsRawFd, path::Path};

fn open_append_and_lock_exclusive<P: AsRef<Path>>(p: P) -> Result<File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    let fd = f.as_raw_fd();
    nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
    Ok(f)
}

fn async_drain<D>(d: D) -> slog::Fuse<slog_async::Async>
where
    D: slog::Drain<Err = slog::Never, Ok = ()> + Send + 'static,
{
    slog_async::Async::new(d)
        .chan_size(constants::ASYNC_LOG_CHANNEL_SIZE)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse()
}

/// create a logger that logs to a file; creates all parent directories if they
/// don't exist.
fn new_file_logger<P: AsRef<Path>>(p: P) -> Result<Logger> {
    std::fs::create_dir_all(p.as_ref().parent().expect("no parent"))?;
    let log_file = open_append_and_lock_exclusive(p)?;
    let file_drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(log_file))
        .build()
        .fuse();
    Ok(slog::Logger::root(async_drain(file_drain), o!()))
}

fn multiplex_logger(l1: Logger, l2: Logger) -> Logger {
    slog::Logger::root(slog::Duplicate(l1, l2).fuse(), o!())
}

/// creates a slog::Logger that prints to standard out using an asynchronous drain
pub fn new_stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    slog::Logger::root(async_drain(drain), o!())
}
