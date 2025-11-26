#![allow(dead_code)]

use crate::driver::constants;
use anyhow::Result;
use slog::{Drain, KV, Key, Level, Logger, OwnedKVList, Record, o};
use slog_term::Decorator;
use std::{fmt, fs::File, io};
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

pub fn new_discard_logger() -> Logger {
    slog::Logger::root(async_drain(slog::Discard), o!())
}

fn multiplex_logger(l1: Logger, l2: Logger) -> Logger {
    slog::Logger::root(slog::Duplicate(l1, l2).fuse(), o!())
}

/// creates a slog::Logger that prints to standard out using an asynchronous drain
pub fn new_stdout_logger(quiet: bool) -> Logger {
    let decorator = slog_term::TermDecorator::new().force_color().build();
    let drain = SysTestLogFormatter::new(decorator);
    if quiet {
        slog::Logger::root(async_drain(drain.filter_level(Level::Info).fuse()), o!())
    } else {
        slog::Logger::root(async_drain(drain.fuse()), o!())
    }
}

struct SysTestLogFormatter<D> {
    decorator: D,
}

impl<D: Decorator> SysTestLogFormatter<D> {
    fn new(decorator: D) -> Self {
        Self { decorator }
    }
}

impl<D: Decorator> Drain for SysTestLogFormatter<D> {
    type Ok = ();
    type Err = io::Error;

    fn log(&self, record: &Record<'_>, values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        self.decorator.with_record(record, values, |rd| {
            let mut kv_serializer = KeyValueSerializer::default();
            record.kv().serialize(record, &mut kv_serializer)?;

            rd.start_timestamp()?;
            let now: time::OffsetDateTime = std::time::SystemTime::now().into();
            write!(
                rd,
                "{}",
                now.format(TIMESTAMP_FORMAT)
                    .map_err(convert_time_fmt_error)?
            )?;

            rd.start_whitespace()?;
            write!(rd, " ")?;

            rd.start_level()?;
            write!(rd, "{}", record.level().as_short_str())?;

            rd.start_location()?;
            write!(rd, "[")?;
            if let Some(ref task_id) = kv_serializer.task_id {
                write!(rd, "{task_id}:")?;
            }

            if let Some(ref output_channel) = kv_serializer.output_channel {
                write!(rd, "{output_channel}]")?;
            } else {
                write!(
                    rd,
                    "{}:{}:{}]",
                    record.location().file,
                    record.location().line,
                    record.location().column
                )?;
            }

            rd.start_whitespace()?;
            write!(rd, " ")?;

            rd.start_msg()?;
            writeln!(rd, "{}", record.msg())?;
            Ok(())
        })
    }
}

fn convert_time_fmt_error(cause: time::error::Format) -> io::Error {
    io::Error::other(cause)
}

const TIMESTAMP_FORMAT: &[time::format_description::FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day] [hour repr:24]:[minute]:[second].[subsecond digits:3]"
);

#[derive(Default)]
struct KeyValueSerializer {
    /// The task id of the task that generated this log message.
    pub task_id: Option<String>,
    /// The channel name (stdout or stderr) if this log line is the output of a subprocess.
    pub output_channel: Option<String>,
}

impl slog::ser::Serializer for KeyValueSerializer {
    /// The trait [slog::ser::Serializer] defines methods for all basic types (`emit_usize`,
    /// `emit_u8`, ...) which all default to emit_arguments. We only expect `task_id` and
    /// `output_channel` to be set (on the record) and ignore all other keys.
    fn emit_arguments(&mut self, key: Key, val: &fmt::Arguments) -> slog::Result {
        match key {
            "task_id" => self.task_id = Some(format!("{val}")),
            "output_channel" => self.output_channel = Some(format!("{val}")),
            _ => (),
        }
        Ok(())
    }
}
