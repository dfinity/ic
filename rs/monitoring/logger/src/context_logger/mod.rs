pub mod macros;

/// Metadata about the log entry
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LogMetadata {
    pub level: slog::Level,
    pub module_path: &'static str,
    pub line: u32,
    pub column: u32,
}

/// Logs data of type `T`
pub trait Logger<T>: Clone {
    /// Log the given log event
    fn log(&self, message: String, data: T, metadata: LogMetadata);

    /// Return true if events should be logged at the given level and module,
    /// false otherwise
    fn is_enabled_at(&self, level: slog::Level) -> bool;

    /// Return true if this is the first log in n seconds, false otherwise
    fn is_n_seconds<V: Into<i32>>(&self, seconds: V, metadata: LogMetadata) -> bool;
}

/// A logger that holds context that can be updated and logged
///
/// Methods of this trait should not be used directly, instead use the macros
/// found in macros.rs
#[derive(Clone)]
pub struct ContextLogger<C, L>
where
    C: Clone + Default,
    L: Logger<C>,
{
    pub context: C,
    pub inner_logger: L,
}

impl<C, L> Default for ContextLogger<C, L>
where
    C: Clone + Default,
    L: Logger<C> + Default,
{
    fn default() -> Self {
        Self {
            context: Default::default(),
            inner_logger: Default::default(),
        }
    }
}

impl<C, L> From<slog::Logger> for ContextLogger<C, L>
where
    C: Clone + Default,
    L: Logger<C> + From<slog::Logger>,
{
    fn from(logger: slog::Logger) -> Self {
        Self {
            context: Default::default(),
            inner_logger: logger.into(),
        }
    }
}

impl<C, L> ContextLogger<C, L>
where
    C: Clone + Default,
    L: Logger<C>,
{
    pub fn new(logger: L) -> Self {
        Self {
            context: C::default(),
            inner_logger: logger,
        }
    }

    pub fn get_context(&self) -> C {
        self.context.clone()
    }

    pub fn with_new_context(&self, context: C) -> Self {
        Self {
            context,
            inner_logger: self.inner_logger.clone(),
        }
    }

    pub fn log(&self, message: String, context: C, metadata: LogMetadata) {
        self.inner_logger.log(message, context, metadata)
    }

    pub fn is_enabled_at(&self, level: slog::Level) -> bool {
        self.inner_logger.is_enabled_at(level)
    }

    pub fn is_n_seconds<T: Into<i32>>(&self, seconds: T, metadata: LogMetadata) -> bool {
        self.inner_logger.is_n_seconds(seconds, metadata)
    }
}

#[cfg(test)]
mod tests {
    use crate::context_logger::{ContextLogger, LogMetadata, Logger};
    use crate::*;

    /// A context type used for testing purposes
    #[derive(Clone, PartialEq, Debug, Default)]
    struct TestContext {
        sub_context1: Option<TestSubContext1>,
        sub_context2: Option<TestSubContext2>,
    }

    #[derive(Clone, PartialEq, Debug, Default)]
    struct TestSubContext1 {
        pub field_u64: u64,
        pub field_opt_i32: Option<i32>,
        pub field_string: String,
    }

    #[derive(Clone, PartialEq, Debug, Default)]
    struct TestSubContext2 {
        pub field_bool: bool,
    }

    /// A Logger that, instead of logging, checks expectations of what
    /// would be logged
    #[derive(Clone, PartialEq, Debug)]
    struct ExpectationLogger {
        context: TestContext,
        expected_context: TestContext,
        expected_message: String,
        expected_level: slog::Level,
    }

    impl ExpectationLogger {
        pub fn new(level: slog::Level) -> Self {
            Self {
                context: Default::default(),
                expected_context: Default::default(),
                expected_message: Default::default(),
                expected_level: level,
            }
        }
    }

    impl Logger<TestContext> for ExpectationLogger {
        fn log(&self, message: String, context: TestContext, metadata: LogMetadata) {
            assert_eq!(message, self.expected_message);
            assert_eq!(context, self.expected_context);
            assert_eq!(metadata.level, self.expected_level);
        }

        fn is_enabled_at(&self, _: slog::Level) -> bool {
            true
        }

        fn is_n_seconds<T: Into<i32>>(&self, _: T, _: LogMetadata) -> bool {
            false
        }
    }

    #[derive(Clone, Default)]
    struct DisabledLogger;

    impl Logger<TestContext> for DisabledLogger {
        fn log(&self, _: String, _: TestContext, _: LogMetadata) {
            panic!("Unexpected call to log()!");
        }

        fn is_enabled_at(&self, _: slog::Level) -> bool {
            false
        }

        fn is_n_seconds<T: Into<i32>>(&self, _: T, _: LogMetadata) -> bool {
            false
        }
    }

    #[derive(Clone, Default)]
    struct EveryNLogger {
        count: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl Logger<TestContext> for EveryNLogger {
        fn log(&self, _: String, _: TestContext, _: LogMetadata) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn is_enabled_at(&self, _: slog::Level) -> bool {
            true
        }

        fn is_n_seconds<T: Into<i32>>(&self, seconds: T, _: LogMetadata) -> bool {
            seconds.into() <= 0
        }
    }

    #[test]
    fn test_macro_new_logger() {
        let inner_logger = ExpectationLogger::new(slog::Level::Info);
        let logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);

        let logger = new_logger!(logger);
        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12_u64);
        logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
            field_u64: 12,
            field_opt_i32: None,
            field_string: "".into(),
        });
        info!(logger)
    }

    #[test]
    fn test_disabled_logger() {
        let inner_logger = DisabledLogger;
        let logger = ContextLogger::<TestContext, DisabledLogger>::new(inner_logger);

        info!(logger)
    }

    #[test]
    #[should_panic(expected = "")]
    fn test_fatal() {
        let inner_logger = ExpectationLogger::new(slog::Level::Info);
        let logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);

        fatal!(logger);
    }

    #[test]
    #[should_panic(expected = "Self-destruct sequence initiated: 10, 9, 8...")]
    fn test_fatal_with_message() {
        let inner_logger = ExpectationLogger::new(slog::Level::Info);
        let logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);

        fatal!(
            logger,
            "Self-destruct sequence initiated: {}, {}, {}...",
            10,
            9,
            8
        );
    }

    #[test]
    #[should_panic(expected = "")]
    fn test_fatal_with_context() {
        let inner_logger = ExpectationLogger::new(slog::Level::Info);
        let logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);

        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12_u64);
        logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
            field_u64: 12,
            field_opt_i32: Some(1),
            field_string: "".into(),
        });

        fatal!(logger; sub_context1.field_opt_i32 => 1);
    }

    #[test]
    #[should_panic(expected = "Fatal error")]
    fn test_fatal_with_message_and_context() {
        let inner_logger = ExpectationLogger::new(slog::Level::Info);
        let logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);

        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12_u64);
        logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
            field_u64: 12,
            field_opt_i32: Some(1),
            field_string: "".into(),
        });

        fatal!(logger, "Fatal error"; sub_context1.field_opt_i32 => 1);
    }

    /// Test the every_n_seconds `info!` calls don't log if the `is_n_seconds`
    /// condition is not satisfied.
    #[test]
    fn test_every_n_seconds_info_does_not_log() {
        let inner_logger = EveryNLogger {
            count: std::sync::Arc::new(std::sync::atomic::AtomicU32::default()),
        };
        let logger = ContextLogger::<TestContext, EveryNLogger>::new(inner_logger);
        info!(every_n_seconds => 1, logger, "Hello {} #{}{}", "world", 4, "!");
        info!(every_n_seconds => 1, logger, "message");
        info!(every_n_seconds => 1, logger ; sub_context1.field_opt_i32 => 1_i32);
        info!(every_n_seconds => 1, logger, "message" ; sub_context1.field_opt_i32 => 1);
        assert!(
            logger
                .inner_logger
                .count
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
        );
    }

    /// Test the every_n_seconds `info!` calls log if the `is_n_seconds`
    /// condition is satisfied.
    #[test]
    fn test_every_n_seconds_info_logs() {
        let inner_logger = EveryNLogger {
            count: std::sync::Arc::new(std::sync::atomic::AtomicU32::default()),
        };
        let logger = ContextLogger::<TestContext, EveryNLogger>::new(inner_logger);
        info!(every_n_seconds => 0, logger, "Hello {} #{}{}", "world", 4, "!");
        info!(every_n_seconds => 0, logger, "message");
        info!(every_n_seconds => 0, logger ; sub_context1.field_opt_i32 => 1_i32);
        info!(every_n_seconds => 0, logger, "message" ; sub_context1.field_opt_i32 => 1);
        assert!(
            logger
                .inner_logger
                .count
                .load(std::sync::atomic::Ordering::SeqCst)
                == 4
        );
    }

    /// Test the every_n_seconds `warn!` calls don't log if the `is_n_seconds`
    /// condition is not satisfied.
    #[test]
    fn test_every_n_seconds_warn_does_not_log() {
        let inner_logger = EveryNLogger {
            count: std::sync::Arc::new(std::sync::atomic::AtomicU32::default()),
        };
        let logger = ContextLogger::<TestContext, EveryNLogger>::new(inner_logger);
        warn!(every_n_seconds => 1, logger, "Hello {} #{}{}", "world", 4, "!");
        warn!(every_n_seconds => 1, logger, "message");
        warn!(every_n_seconds => 1, logger ; sub_context1.field_opt_i32 => 1_i32);
        warn!(every_n_seconds => 1, logger, "message" ; sub_context1.field_opt_i32 => 1);
        assert!(
            logger
                .inner_logger
                .count
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
        );
    }

    /// Test the every_n_seconds `warn!` calls log if the `is_n_seconds`
    /// condition is satisfied.
    #[test]
    fn test_every_n_seconds_warn_logs() {
        let inner_logger = EveryNLogger {
            count: std::sync::Arc::new(std::sync::atomic::AtomicU32::default()),
        };
        let logger = ContextLogger::<TestContext, EveryNLogger>::new(inner_logger);
        warn!(every_n_seconds => 0, logger, "Hello {} #{}{}", "world", 4, "!");
        warn!(every_n_seconds => 0, logger, "message");
        warn!(every_n_seconds => 0, logger ; sub_context1.field_opt_i32 => 1_i32);
        warn!(every_n_seconds => 0, logger, "message" ; sub_context1.field_opt_i32 => 1);
        assert!(
            logger
                .inner_logger
                .count
                .load(std::sync::atomic::Ordering::SeqCst)
                == 4
        );
    }

    /// Given one of the log macros (e.g. info!), generate a function that tests
    /// all branches of the given macro
    macro_rules! test_log_macro {
        ($name:ident, $log_macro:ident, $level:ident) => {
            #[test]
            fn $name() {
                let inner_logger = ExpectationLogger::new(slog::Level::$level);
                let mut logger = ContextLogger::<TestContext, ExpectationLogger>::new(inner_logger);
                $log_macro!(logger);

                logger.inner_logger.expected_message = "Hello world #4!".into();
                $log_macro!(logger, "Hello {} #{}{}", "world", 4, "!");

                logger.inner_logger.expected_message = "".into();

                logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
                    field_u64: 12,
                    field_opt_i32: Some(45),
                    field_string: "foo".into(),
                });

                logger.inner_logger.expected_context.sub_context2 = Some(TestSubContext2 {
                    field_bool: true
                });

                $log_macro!(
                    logger;
                    sub_context1.field_u64 => 12_u64,
                    sub_context1.field_opt_i32 => 45,
                    sub_context1.field_string => "foo",
                    sub_context2.field_bool => true,
                );

                logger.inner_logger.expected_message = "foo bar".into();
                $log_macro!(
                    logger,
                    "foo bar";
                    sub_context1.field_u64 => 12_u64,
                    sub_context1.field_opt_i32 => 45,
                    sub_context1.field_string => "foo",
                    sub_context2.field_bool => true,
                );

                logger.inner_logger.expected_message = "1 2 3 4 5".into();
                $log_macro!(
                    logger,
                    "{} {} {} {} {}", 1, 2, 3, 4, 5;
                    sub_context1.field_u64 => 12_u64,
                    sub_context1.field_opt_i32 => 45,
                    sub_context1.field_string => "foo",
                    sub_context2.field_bool => true,
                );
            }
        }
    }

    test_log_macro!(test_trace, trace, Trace);
    test_log_macro!(test_debug, debug, Debug);
    test_log_macro!(test_info, info, Info);
    test_log_macro!(test_warn, warn, Warning);
    test_log_macro!(test_error, error, Error);
    test_log_macro!(test_crit, crit, Critical);

    /// Check that every form of every macro also accepts a trailing comma.
    ///
    /// These are purely compile-time checks of the macro arms.
    macro_rules! test_trailing_commas {
        ($name:ident, $log_macro:ident) => {
            #[test]
            fn $name() {
                let inner_logger = DisabledLogger;
                let logger = ContextLogger::<TestContext, DisabledLogger>::new(inner_logger);

                $log_macro!(logger,);
                $log_macro!(logger, "message",);
                $log_macro!(logger, "{} {}", 1, 2,);
                $log_macro!(logger; sub_context1.field_u64 => 12_u64,);
                $log_macro!(logger, "message"; sub_context1.field_u64 => 12_u64,);
                $log_macro!(logger, "{} {}", 1, 2; sub_context1.field_u64 => 12_u64,);
            }
        };
    }

    test_trailing_commas!(test_trace_trailing_commas, trace);
    test_trailing_commas!(test_debug_trailing_commas, debug);
    test_trailing_commas!(test_info_trailing_commas, info);
    test_trailing_commas!(test_warn_trailing_commas, warn);
    test_trailing_commas!(test_error_trailing_commas, error);
    test_trailing_commas!(test_crit_trailing_commas, crit);

    /// Same as above, for the `every_n_seconds` forms.
    macro_rules! test_every_n_seconds_trailing_commas {
        ($name:ident, $log_macro:ident) => {
            #[test]
            fn $name() {
                let inner_logger = DisabledLogger;
                let logger = ContextLogger::<TestContext, DisabledLogger>::new(inner_logger);

                $log_macro!(every_n_seconds => 1, logger, "message",);
                $log_macro!(every_n_seconds => 1, logger, "{} {}", 1, 2,);
                $log_macro!(every_n_seconds => 1, logger, "message"; sub_context1.field_u64 => 12_u64,);
                $log_macro!(every_n_seconds => 1, logger, "{} {}", 1, 2; sub_context1.field_u64 => 12_u64,);
            }
        };
    }

    test_every_n_seconds_trailing_commas!(test_debug_every_n_seconds_trailing_commas, debug);
    test_every_n_seconds_trailing_commas!(test_info_every_n_seconds_trailing_commas, info);
    test_every_n_seconds_trailing_commas!(test_warn_every_n_seconds_trailing_commas, warn);

    #[test]
    fn test_remaining_trailing_commas() {
        let inner_logger = DisabledLogger;
        let logger = ContextLogger::<TestContext, DisabledLogger>::new(inner_logger);

        // `error!` only has an `every_n_seconds` form without context fields.
        error!(every_n_seconds => 1, logger, "message",);
        error!(every_n_seconds => 1, logger, "{} {}", 1, 2,);

        // `info!` and `warn!` also have an `every_n_seconds` form without a message.
        info!(every_n_seconds => 1, logger; sub_context1.field_u64 => 12_u64,);
        warn!(every_n_seconds => 1, logger; sub_context1.field_u64 => 12_u64,);

        let logger = new_logger!(logger,);
        let logger = new_logger!(logger; sub_context1.field_u64 => 12_u64,);

        log!(logger, slog::Level::Info, "message",);
        log!(logger, slog::Level::Info, "{} {}", 1, 2,);
        log!(logger, slog::Level::Info; sub_context1.field_u64 => 12_u64,);
        log!(logger, slog::Level::Info, "message"; sub_context1.field_u64 => 12_u64,);
        log!(logger, slog::Level::Info, "{} {}", 1, 2; sub_context1.field_u64 => 12_u64,);

        let mut context = TestContext::default();
        update_context!(context; sub_context1.field_u64 => 12_u64,);
        let _ = log_metadata!(slog::Level::Info,);
    }

    /// `fatal!` always panics, so each of its forms needs its own test.
    macro_rules! fatal_test_logger {
        () => {
            ContextLogger::<TestContext, DisabledLogger>::new(DisabledLogger)
        };
    }

    #[test]
    #[should_panic]
    fn test_fatal_logger_trailing_comma() {
        let logger = fatal_test_logger!();
        fatal!(logger,);
    }

    #[test]
    #[should_panic]
    fn test_fatal_message_trailing_comma() {
        let logger = fatal_test_logger!();
        fatal!(logger, "message",);
    }

    #[test]
    #[should_panic]
    fn test_fatal_args_trailing_comma() {
        let logger = fatal_test_logger!();
        fatal!(logger, "{} {}", 1, 2,);
    }

    #[test]
    #[should_panic]
    fn test_fatal_context_trailing_comma() {
        let logger = fatal_test_logger!();
        fatal!(logger; sub_context1.field_u64 => 12_u64,);
    }

    #[test]
    #[should_panic]
    fn test_fatal_message_and_context_trailing_comma() {
        let logger = fatal_test_logger!();
        fatal!(logger, "message"; sub_context1.field_u64 => 12_u64,);
    }
}
