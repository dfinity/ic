use std::ffi::OsStr;
use std::fmt as std_fmt;
use std::fs::OpenOptions;
use std::path::Path;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    Layer,
    filter::LevelFilter,
    fmt::{
        FmtContext,
        format::{FormatEvent, FormatFields, Writer},
        writer::MakeWriterExt,
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

/// Formats kmsg events with syslog priority and identifier prefixes.
struct KmsgFormatter<E> {
    identifier: String,
    inner: E,
}

impl<S, N, E> FormatEvent<S, N> for KmsgFormatter<E>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
    E: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std_fmt::Result {
        write!(
            &mut writer,
            "<{}>{}: ",
            syslog_priority(event.metadata().level()),
            self.identifier,
        )?;
        self.inner.format_event(ctx, writer, event)
    }
}

fn syslog_priority(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

fn syslog_identifier_from_arg0(arg0: Option<&OsStr>) -> String {
    arg0.and_then(|arg0| Path::new(arg0).file_name())
        .filter(|file_name| !file_name.is_empty())
        .unwrap_or_else(|| OsStr::new("ic_os"))
        .to_string_lossy()
        .into_owned()
}

fn syslog_identifier() -> String {
    let arg0 = std::env::args_os().next();
    syslog_identifier_from_arg0(arg0.as_deref())
}

/// Initialize tracing, using journald+stderr if journald is available and falling back to just stderr.
/// Logs with TRACE level.
pub fn init_logging() {
    init_logging_with_level(Level::TRACE);
}

/// Initialize tracing, using journald+stderr if journald is available and falling back to just stderr.
pub fn init_logging_with_level(max_level: Level) {
    let level_filter = LevelFilter::from_level(max_level);

    match tracing_journald::layer() {
        Ok(layer) => tracing_subscriber::registry()
            .with(layer.with_filter(level_filter))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr.with_max_level(max_level)),
            )
            .init(),
        Err(_) => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(level_filter)
            .init(),
    }
}

/// Initialize tracing, writing to `/dev/kmsg` if available and falling back to stderr.
pub fn init_kmsg_logging() {
    let identifier = syslog_identifier();

    match OpenOptions::new().write(true).open("/dev/kmsg") {
        Ok(kmsg) => tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(KmsgFormatter {
                        identifier: identifier.clone(),
                        inner: tracing_subscriber::fmt::format()
                            .without_time()
                            .with_target(false)
                            .with_level(false)
                            .compact(),
                    })
                    .with_writer(move || {
                        kmsg.try_clone()
                            .expect("failed to clone /dev/kmsg file handle")
                    })
                    .with_ansi(false),
            )
            .init(),
        Err(_) => tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(KmsgFormatter {
                        identifier,
                        inner: tracing_subscriber::fmt::format()
                            .without_time()
                            .with_target(false)
                            .with_level(false)
                            .compact(),
                    })
                    .with_writer(std::io::stderr)
                    .with_ansi(false),
            )
            .init(),
    }
}
