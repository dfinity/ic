use std::{fs::File, io::stderr, path::PathBuf};

use axum::Router;
use clap::{ArgAction::Count, Args, ValueEnum};
use tower_http::trace::TraceLayer;
use tracing::{
    enabled, info, info_span, level_filters::LevelFilter, span::EnteredSpan,
    subscriber::set_global_default, Level, Span,
};
use tracing_subscriber::{fmt::layer, layer::SubscriberExt, Registry};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub(crate) enum OptMode {
    StdErr,
    Tee,
    File,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub(crate) enum OptFormat {
    Default,
    Compact,
    Full,
    Json,
}

/// The options for logging
#[derive(Args)]
pub struct LoggingOpts {
    /// Verbose level. By default, INFO will be used. Add a single `-v` to upgrade to
    /// DEBUG, and another `-v` to upgrade to TRACE.
    #[clap(long, short('v'), action = Count)]
    verbose: u8,

    /// Quiet level. The opposite of verbose. A single `-q` will drop the logging to
    /// WARN only, then another one to ERR, and finally another one for FATAL. Another
    /// `-q` will silence ALL logs.
    #[clap(long, short('q'), action = Count)]
    quiet: u8,

    /// Mode to use the logging. "stderr" will output logs in STDERR, "file" will output
    /// logs in a file, and "tee" will do both.
    #[clap(value_enum, long("log"), default_value_t = OptMode::StdErr)]
    logmode: OptMode,

    /// Formatting to use the logging. "stderr" will output logs in STDERR, "file" will output
    /// logs in a file, and "tee" will do both.
    #[clap(value_enum, long("logformat"), default_value_t = OptFormat::Default)]
    logformat: OptFormat,

    /// File to output the log to, when using logmode=tee or logmode=file.
    #[clap(long)]
    logfile: Option<PathBuf>,
}

/// A helper to add tracing with nice spans to `Router`s
/// Add only if the logging level is TRACE to have less CPU load in production
pub fn add_trace_layer(r: Router) -> Router {
    if enabled!(Level::TRACE) {
        r.layer(TraceLayer::new_for_http().make_span_with(Span::current()))
    } else {
        r
    }
}

pub fn setup(opts: LoggingOpts) -> EnteredSpan {
    let filter = match opts.verbose as i64 - opts.quiet as i64 {
        -2 => LevelFilter::ERROR,
        -1 => LevelFilter::WARN,
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        x if x >= 2 => LevelFilter::TRACE,
        // Silent.
        _ => LevelFilter::OFF,
    };

    fn create_file(path: Option<PathBuf>) -> File {
        File::create(path.unwrap_or_else(|| "log.txt".into())).expect("Couldn't open log file")
    }

    // The `layer_format` macro is used to uniformly customize the the format specific options for a layer
    // (e.g. all json should be flattened)
    macro_rules! layer_format {
        (json, $writer:expr) => {
            layer()
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_writer($writer)
        };
        (full, $writer:expr) => {
            layer().with_writer($writer)
        };
        (compact, $writer:expr) => {
            layer().compact().with_writer($writer)
        };
    }
    // The `writer` macro is used to uniformly customize the the writer specific options for a layer
    // (e.g. files don't use ANSI terminal colors)
    macro_rules! writer {
        (file, $format:ident) => {
            layer_format!($format, create_file(opts.logfile)).with_ansi(false)
        };
        (stderr, $format:ident) => {
            layer_format!($format, stderr)
        };
    }
    // The `layer` macro is used to uniformly customize the the writer-format specific options for a layer
    // (e.g. file-json includes the current span [we don't actually do this, it's just an hypothetical example])
    macro_rules! layer {
        ($writer:ident, $format:ident) => {
            writer!($writer, $format)
        };
    }

    // The `install` macro filters to the specified level and adds all the layers to the global subscriber
    macro_rules! install {
        ($($layer:expr),+) => {
            set_global_default(Registry::default().with(filter)$(.with($layer))+)
        }
    }

    match (opts.logmode, opts.logformat) {
        (OptMode::Tee, OptFormat::Default) => {
            install!(layer!(stderr, compact), layer!(file, full))
        }
        (OptMode::Tee, OptFormat::Compact) => {
            install!(layer!(stderr, compact), layer!(file, compact))
        }
        (OptMode::Tee, OptFormat::Full) => install!(layer!(stderr, full), layer!(file, full)),
        (OptMode::Tee, OptFormat::Json) => install!(layer!(stderr, json), layer!(file, json)),
        (OptMode::File, OptFormat::Default | OptFormat::Full) => {
            install!(layer!(file, full))
        }
        (OptMode::File, OptFormat::Compact) => {
            install!(layer!(file, compact))
        }
        (OptMode::File, OptFormat::Json) => install!(layer!(file, json)),
        (OptMode::StdErr, OptFormat::Default | OptFormat::Compact) => {
            install!(layer!(stderr, compact))
        }
        (OptMode::StdErr, OptFormat::Full) => install!(layer!(stderr, full)),
        (OptMode::StdErr, OptFormat::Json) => install!(layer!(stderr, json)),
    }
    .expect("Failed to setup tracing.");

    let span = info_span!(target: "icx_proxy", "icx-proxy").entered();
    info!(target: "icx_proxy", "Log Level: {filter}");
    span
}
