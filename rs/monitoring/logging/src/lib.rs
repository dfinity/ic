use ic_config::logger::{Config as LoggingConfig, LogFormat};
use ic_types::{NodeId, SubnetId};
use tracing::{Level, Subscriber};
use tracing_appender::{non_blocking, non_blocking::WorkerGuard};
use tracing_subscriber::{fmt, layer::Layer, registry::LookupSpan, reload::Handle, Registry};

enum InnerFormat {
    Full(fmt::format::Format<fmt::format::Full>),
    Json(fmt::format::Format<fmt::format::Json>),
}

struct Formatter {
    inner: InnerFormat,
    node_id: NodeId,
    subnet_id: SubnetId,
}

impl Formatter {
    fn new(format: LogFormat, node_id: NodeId, subnet_id: SubnetId) -> Self {
        let inner = match format {
            LogFormat::Json => InnerFormat::Json(
                fmt::format::json()
                    .with_timer(fmt::time::UtcTime::rfc_3339())
                    .with_level(true)
                    .with_file(true)
                    .with_line_number(true),
            ),
            LogFormat::TextFull => InnerFormat::Full(fmt::format::format()),
        };
        Self {
            inner,
            node_id,
            subnet_id,
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
        mut writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        write!(
            &mut writer,
            "node_id: {} subnet_id:{} ",
            self.node_id, self.subnet_id
        )?;

        match &self.inner {
            InnerFormat::Json(f) => f.format_event(ctx, writer, event),
            InnerFormat::Full(f) => f.format_event(ctx, writer, event),
        }
    }
}

pub fn get_logging_layer<T>(
    config: &LoggingConfig,
    node_id: NodeId,
    subnet_id: SubnetId,
) -> (Box<dyn Layer<Registry> + Send + Sync>, Option<WorkerGuard>) {
    let formatter = Formatter::new(config.format, node_id, subnet_id);

    //let non_blocking_log_writer = non_blocking_log_writer.with_max_level(Level::INFO);

    let (non_blocking_writer, guard) = non_blocking(std::io::stdout());

    let mut layer = fmt::Layer::new()
        .event_format(formatter)
        .with_writer(non_blocking_writer);
    (layer.boxed(), None)
}
