//! These macros provide an interface to ContextLogger
//!
//! # Example
//! ```
//! use ic_context_logger::{Logger, LogMetadata, ContextLogger, info, new_logger};
//! #[derive(Clone, Debug, Default, PartialEq)]
//! struct ExampleContext {
//!     sub_context: Option<ExampleSubContext>,
//! }
//!
//! #[derive(Clone, Debug, Default, PartialEq)]
//! struct ExampleSubContext {
//!     pub field_u64: u64,
//!     pub field_opt_i32: Option<i32>,
//!     pub field_string: String,
//! }
//!
//! /// A ContextLogger that, instead of logging, checks expectations of what
//! /// would be logged
//! #[derive(Clone, Debug, PartialEq)]
//! struct ExampleLogger {
//!     context: ExampleContext,
//! }
//!
//! impl ExampleLogger {
//!     pub fn new() -> Self {
//!         Self {
//!             context: Default::default(),
//!         }
//!     }
//! }
//!
//! impl Logger<ExampleContext> for ExampleLogger {
//!     fn log(&self, message: String, context: ExampleContext, metadata: LogMetadata) {
//!         println!("{}, {:?}, {:?}", message, context, metadata)
//!     }
//!
//!     fn is_enabled_at(&self, _: slog::Level, _: &'static str) -> bool { true }
//!
//!     fn should_sample<T: Into<u32>>(&self, _key: String, _value: T) -> bool { false }
//!
//!     fn is_tag_enabled(&self, _tag: String) -> bool { false }
//!
//!     fn is_n_seconds<T: Into<i32>>(&self, _seconds: T, _metadata: LogMetadata) -> bool { false }
//! }
//!
//! let logger = ContextLogger::<ExampleContext, ExampleLogger>::new(ExampleLogger::new());
//!
//! // Add context. The field `sub_context.field_u64` will map to `12` on all subsequent calls
//! // to `log`.
//! let logger = new_logger!(
//!     logger;
//!     sub_context.field_u64 => 12u64,
//! );
//!
//! // Log an info-level log
//! // Note that sub_context.field_u64 will map to `12` in the output
//! info!(
//!     logger,
//!     "Counting down: {}, {}, {}...", 10, 9, 8;
//!     sub_context.field_opt_i32 => 45,
//!     sub_context.field_string => "foo",
//! )
//! ```

/// Create a new logger with the supplied context
#[macro_export(local_inner_macros)]
macro_rules! new_logger {
    ($logger:expr; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        let mut context = $logger.get_context();
        update_context!(context; $($field $( . $sub_field)* => $value),*);
        $logger.with_new_context(context)
    }};
    ($logger:expr) => {{
        $logger.clone()
    }};
}

/// Log a trace-level message, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! trace {
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Trace, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Trace ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Trace, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        trace!($logger, "");
    }};
}

/// Log a debug-level log, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! debug {
    (tag => $tag:expr, $logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_tag_enabled($tag.to_owned()) {
            log!($logger, slog::Level::Debug, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Debug, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Debug ; $( $field $( . $sub_field)* => $value ),*)
    }};
    (tag => $tag:expr, $logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        if $logger.is_tag_enabled($tag.to_owned()) {
            log!($logger, slog::Level::Debug, $message $(,$args)*)
        }
    }};
    (every_n_seconds => $seconds:expr, $logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Debug)) {
            log!($logger, slog::Level::Debug, $message $(,$args)*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Debug, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        debug!($logger, "");
    }};
}

/// Log an info-level log, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! info {
    (every_n_seconds => $seconds:expr, $logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Info)) {
            log!($logger, slog::Level::Info, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    (tag => $tag:expr, $logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_tag_enabled($tag.to_owned()) {
            log!($logger, slog::Level::Info, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Info, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    (every_n_seconds => $seconds:expr, $logger:expr, $message:expr $(,$args:expr)* ) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Info)) {
            log!($logger, slog::Level::Info, $message $(,$args)*)
        }
    }};
    (every_n_seconds => $seconds:expr, $logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Info)) {
            log!($logger, slog::Level::Info ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Info ; $( $field $( . $sub_field)* => $value ),*)
    }};
    (tag => $tag:expr, $logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        if $logger.is_tag_enabled($tag.to_owned()) {
            log!($logger, slog::Level::Info, $message $(,$args)*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Info, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        info!($logger, "");
    }};
}

/// Log a warn-level log, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! warn {
    (every_n_seconds => $seconds:expr, $logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Warning)) {
            log!($logger, slog::Level::Warning, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Warning, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    (every_n_seconds => $seconds:expr, $logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Warning)) {
            log!($logger, slog::Level::Warning ; $( $field $( . $sub_field)* => $value ),*)
        }
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Warning ; $( $field $( . $sub_field)* => $value ),*)
    }};
    (every_n_seconds => $seconds:expr, $logger:expr, $message:expr $(,$args:expr)* ) => {{
        if $logger.is_n_seconds($seconds, log_metadata!(slog::Level::Warning)) {
            log!($logger, slog::Level::Warning, $message $(,$args)*)
        }
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Warning, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        warn!($logger, "");
    }};
}

/// Log an error-level log, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! error {
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Error, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Error ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Error, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        error!($logger, "");
    }};
}

/// Log a crit-level log, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! crit {
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Critical, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Critical ; $( $field $( . $sub_field)* => $value ),*)
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Critical, $message $(,$args)*)
    }};
    ($logger:expr $(,)*) => {{
        crit!($logger, "");
    }};
}

/// Log a crit-level log, with context fields if given, then panic!()
#[macro_export(local_inner_macros)]
macro_rules! fatal {
    ($logger:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Critical, $message $(,$args)* ; $( $field $( . $sub_field)* => $value ),*);
        std::panic!($message $(,$args)*);
    }};
    ($logger:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        log!($logger, slog::Level::Critical ; $( $field $( . $sub_field)* => $value ),*);
        std::panic!("");
    }};
    ($logger:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        log!($logger, slog::Level::Critical, $message $(,$args)*);
        std::panic!($message $(,$args)*);
    }};
    ($logger:expr $(,)*) => {{
        fatal!($logger, "");
    }};
}

/// Log an entry at the given log level, with context fields if given
#[macro_export(local_inner_macros)]
macro_rules! log {
    ($logger:expr, $level:expr, $message:expr $(,$args:expr)* ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_enabled_at($level, std::module_path!()) {
            let mut context = $logger.get_context();
            update_context!(context; $($field $( . $sub_field)* => $value),*);

            let message = std::format!($message $(,$args)*);
            $logger.log(message, context, log_metadata!($level))
        }
    }};
    ($logger:expr, $level:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.is_enabled_at($level, std::module_path!()) {
            let mut context = $logger.get_context();
            update_context!(context; $($field $( . $sub_field)* => $value),*);

            $logger.log("".into(), context, log_metadata!($level))
        }
    }};
    ($logger:expr, $level:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        if $logger.is_enabled_at($level, std::module_path!()) {
            let message = std::format!($message $(,$args)*);
            $logger.log(message, $logger.get_context(), log_metadata!($level))
        }
    }};
    ($logger:expr $(,)*) => {{
        log!($logger, "");
    }};
}

#[macro_export(local_inner_macros)]
macro_rules! update_context {
    ($context:expr; $( $field:ident $( . $sub_field:ident)* => $value:expr ),*) => {{
        $(
            let mut sub_context = match $context.$field {
                Some(x) => x.clone(),
                None => std::default::Default::default(),
            };

            sub_context $(.$sub_field)* = $value.to_owned().into();
            $context.$field = sub_context.into();
        )*
    }};
}

/// Return a LogMetadata
#[macro_export(local_inner_macros)]
macro_rules! log_metadata {
    ($level:expr) => {{
        $crate::LogMetadata {
            level: $level,
            module_path: std::module_path!(),
            line: std::line!(),
            column: std::column!(),
        }
    }};
}

/// Sample the given log event
///
/// If $logger.should_sample($sample_key, $sample_value) returns true, log the
/// event at INFO level, else do nothing.
#[macro_export(local_inner_macros)]
macro_rules! info_sample {
    ($sample_key:expr => $sample_value:expr, $logger:expr, $message:expr ; $( $field:ident $( . $sub_field:ident)* => $value:expr ),* $(,)*) => {{
        if $logger.should_sample($sample_key.to_owned(), $sample_value) {
            info!($logger, $message ; $( $field $( . $sub_field)* => $value ),*);
        }
    }};
}
