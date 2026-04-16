use std::fmt as std_fmt;
use std::fs::OpenOptions;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    fmt::{
        FmtContext, format,
        format::{FormatEvent, FormatFields, Writer},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

/// Formats events with syslog priority prefixes.
struct SyslogPriorityFormatter<E>(E);

impl<S, N, E> FormatEvent<S, N> for SyslogPriorityFormatter<E>
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
            "<{}>",
            syslog_priority(event.metadata().level())
        )?;
        self.0.format_event(ctx, writer, event)
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

/// Initialize tracing, using journald if available and falling back to stderr.
pub fn init_logging() {
    match tracing_journald::layer() {
        Ok(layer) => tracing_subscriber::registry().with(layer).init(),
        Err(_) => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init(),
    }
}

/// Initialize tracing, writing to `/dev/kmsg` if available and falling back to stderr.
pub fn init_kmsg_logging() {
    match OpenOptions::new().write(true).open("/dev/kmsg") {
        Ok(kmsg) => tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(SyslogPriorityFormatter(
                        format()
                            .without_time()
                            .with_target(false)
                            .with_level(false)
                            .compact(),
                    ))
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
                    .event_format(SyslogPriorityFormatter(
                        format()
                            .without_time()
                            .with_target(false)
                            .with_level(false)
                            .compact(),
                    ))
                    .with_writer(std::io::stderr)
                    .with_ansi(false),
            )
            .init(),
    }
}
