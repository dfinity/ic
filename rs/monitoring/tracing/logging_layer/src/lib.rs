use ic_base_types::{NodeId, SubnetId};
use ic_config::logger::{Config as LoggingConfig, Level, LogDestination, LogFormat};
use time::format_description::well_known::Rfc3339;
use tracing::Subscriber;
use tracing_appender::{non_blocking, non_blocking::WorkerGuard};
use tracing_subscriber::{Registry, filter::LevelFilter, fmt, layer::Layer, registry::LookupSpan};

enum InnerFormat {
    Full(fmt::format::Format<fmt::format::Full, fmt::time::UtcTime<Rfc3339>>),
    Json(fmt::format::Format<fmt::format::Json, fmt::time::UtcTime<Rfc3339>>),
}

struct Formatter {
    inner: InnerFormat,
    _node_id: NodeId,
    _subnet_id: SubnetId,
}

impl Formatter {
    fn new(format: LogFormat, node_id: NodeId, subnet_id: SubnetId) -> Self {
        let inner = match format {
            LogFormat::Json => InnerFormat::Json(
                fmt::format::json()
                    .flatten_event(true)
                    .with_timer(fmt::time::UtcTime::rfc_3339())
                    .with_level(true)
                    .with_file(true)
                    .with_line_number(true),
            ),
            LogFormat::TextFull => InnerFormat::Full(
                fmt::format()
                    .with_timer(fmt::time::UtcTime::rfc_3339())
                    .with_level(true)
                    .with_file(true)
                    .with_line_number(true),
            ),
        };
        Self {
            inner,
            _node_id: node_id,
            _subnet_id: subnet_id,
        }
    }
}

impl<S, N> fmt::format::FormatEvent<S, N> for Formatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    // Required method
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        match &self.inner {
            InnerFormat::Json(f) => f.format_event(ctx, writer, event),
            InnerFormat::Full(f) => f.format_event(ctx, writer, event),
        }
    }
}

pub fn logging_layer(
    config: &LoggingConfig,
    node_id: NodeId,
    subnet_id: SubnetId,
) -> (
    impl Layer<Registry> + Send + Sync + use<>,
    Option<WorkerGuard>,
) {
    let formatter = Formatter::new(config.format, node_id, subnet_id);

    let log_destination = config.log_destination.clone();
    let make_writer = move || -> Box<dyn std::io::Write + Send> {
        match &log_destination {
            LogDestination::Stderr => Box::new(std::io::stderr()),
            LogDestination::Stdout => Box::new(std::io::stdout()),
            LogDestination::File(path) => {
                Box::new(std::fs::File::create(path).expect("Creating a file must succeed."))
            }
        }
    };

    let (layer, drop_guard) = if config.block_on_overflow {
        let layer = fmt::Layer::new()
            .event_format(formatter)
            .with_writer(make_writer);
        (layer.boxed(), None)
    } else {
        let (non_blocking_writer, guard) = non_blocking(make_writer());
        let layer = fmt::Layer::new()
            .event_format(formatter)
            .with_writer(non_blocking_writer);
        (layer.boxed(), Some(guard))
    };

    let level_filter = match config.level {
        Level::Trace => LevelFilter::TRACE,
        Level::Debug => LevelFilter::DEBUG,
        Level::Info => LevelFilter::INFO,
        Level::Warning => LevelFilter::WARN,
        Level::Error => LevelFilter::ERROR,
        // TODO: remove this level
        Level::Critical => LevelFilter::ERROR,
    };
    (layer.with_filter(level_filter), drop_guard)
}
