use slog::Drain;
pub use slog::{crit, debug, error, info, trace, warn};
pub use slog::{o, Logger};
use std::{fs::File, path::PathBuf};

const CHAN_SIZE: usize = 8192;

/// Creates a logger that is designed to log human-readable output.
/// Full format is used, rather than compact, because we have multiple threads
/// and the nesting in the compact is suitable only for output from single
/// threads.
///
/// A word of warning about logging and signal handling is important.
/// Because `slog-async` spawns a thread that is responsible for printing
/// out log messages, and signal handling is thread-local it is highly advised
/// to be cautious of where you call `mk_logger` from. This is why, for
/// instance, under [crate::pot::execution] we use `println!` instead of making
/// a logger.
pub fn mk_logger(level: slog::Level, tgt: Option<PathBuf>) -> Logger {
    if let Some(file) = tgt {
        let decorator = slog_term::PlainSyncDecorator::new(File::create(file).unwrap());
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain)
            .chan_size(CHAN_SIZE)
            .build()
            .fuse();
        let drain = slog::LevelFilter::new(drain.fuse(), level).fuse();
        slog::Logger::root(drain, o!())
    } else {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain)
            .chan_size(CHAN_SIZE)
            .build()
            .fuse();
        let drain = slog::LevelFilter::new(drain.fuse(), level).fuse();
        slog::Logger::root(drain, o!())
    }
}

pub fn mk_logger_discard(_: slog::Level, _: Option<PathBuf>) -> Logger {
    slog::Logger::root(slog::Discard, o!())
}
