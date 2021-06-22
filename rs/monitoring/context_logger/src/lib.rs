pub mod macros;

/// Metadata about the log entry
#[derive(Clone, Debug, PartialEq)]
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
    fn is_enabled_at(&self, level: slog::Level, module_path: &'static str) -> bool;

    /// Return true if a `sample!` log with the given key and value should be
    /// logged, false otherwise
    fn should_sample<V: Into<u32>>(&self, key: String, value: V) -> bool;

    /// Return true if a log with the given tag should be logged, false
    /// otherwise
    fn is_tag_enabled(&self, tag: String) -> bool;

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

    pub fn is_enabled_at(&self, level: slog::Level, module_path: &'static str) -> bool {
        self.inner_logger.is_enabled_at(level, module_path)
    }

    pub fn should_sample<T: Into<u32>>(&self, key: String, value: T) -> bool {
        self.inner_logger.should_sample(key, value)
    }

    pub fn is_tag_enabled(&self, tag: String) -> bool {
        self.inner_logger.is_tag_enabled(tag)
    }

    pub fn is_n_seconds<T: Into<i32>>(&self, seconds: T, metadata: LogMetadata) -> bool {
        self.inner_logger.is_n_seconds(seconds, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context type used for testing purposes
    #[derive(Clone, Debug, Default, PartialEq)]
    struct TestContext {
        sub_context1: Option<TestSubContext1>,
        sub_context2: Option<TestSubContext2>,
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct TestSubContext1 {
        pub field_u64: u64,
        pub field_opt_i32: Option<i32>,
        pub field_string: String,
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    struct TestSubContext2 {
        pub field_bool: bool,
    }

    /// A Logger that, instead of logging, checks expectations of what
    /// would be logged
    #[derive(Clone, Debug, PartialEq)]
    struct ExpectationLogger {
        context: TestContext,
        expected_context: TestContext,
        expected_message: String,
        expected_level: slog::Level,
        enabled_tags: Vec<String>,
    }

    impl ExpectationLogger {
        pub fn new(level: slog::Level) -> Self {
            Self {
                context: Default::default(),
                expected_context: Default::default(),
                expected_message: Default::default(),
                expected_level: level,
                enabled_tags: vec![],
            }
        }
    }

    impl Logger<TestContext> for ExpectationLogger {
        fn log(&self, message: String, context: TestContext, metadata: LogMetadata) {
            assert_eq!(message, self.expected_message);
            assert_eq!(context, self.expected_context);
            assert_eq!(metadata.level, self.expected_level);
        }

        fn is_enabled_at(&self, _: slog::Level, _: &'static str) -> bool {
            true
        }

        fn should_sample<T: Into<u32>>(&self, _key: String, _value: T) -> bool {
            false
        }

        fn is_tag_enabled(&self, _tag: String) -> bool {
            false
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

        fn is_enabled_at(&self, _: slog::Level, _: &'static str) -> bool {
            false
        }

        fn should_sample<T: Into<u32>>(&self, _key: String, _value: T) -> bool {
            false
        }

        fn is_tag_enabled(&self, _tag: String) -> bool {
            false
        }

        fn is_n_seconds<T: Into<i32>>(&self, _: T, _: LogMetadata) -> bool {
            false
        }
    }

    #[derive(Clone, Default)]
    struct TagLogger {
        enabled_tags: Vec<String>,
    }

    impl Logger<TestContext> for TagLogger {
        fn log(&self, _: String, _: TestContext, _: LogMetadata) {
            panic!("Expected call to log()!");
        }

        fn is_enabled_at(&self, _: slog::Level, _: &'static str) -> bool {
            true
        }

        fn should_sample<T: Into<u32>>(&self, _key: String, _value: T) -> bool {
            false
        }

        fn is_tag_enabled(&self, tag: String) -> bool {
            self.enabled_tags.contains(&tag)
        }

        fn is_n_seconds<T: Into<i32>>(&self, seconds: T, _: LogMetadata) -> bool {
            seconds.into() <= 0
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

        fn is_enabled_at(&self, _: slog::Level, _: &'static str) -> bool {
            true
        }

        fn should_sample<T: Into<u32>>(&self, _key: String, _value: T) -> bool {
            false
        }

        fn is_tag_enabled(&self, _tag: String) -> bool {
            false
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
        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12u64);
        logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
            field_u64: 12,
            field_opt_i32: None,
            field_string: "".into(),
        });
        info!(logger)
    }

    #[test]
    fn test_disabled_logger() {
        let inner_logger = DisabledLogger::default();
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

        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12u64);
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

        let mut logger = new_logger!(logger; sub_context1.field_u64 => 12u64);
        logger.inner_logger.expected_context.sub_context1 = Some(TestSubContext1 {
            field_u64: 12,
            field_opt_i32: Some(1),
            field_string: "".into(),
        });

        fatal!(logger, "Fatal error"; sub_context1.field_opt_i32 => 1);
    }

    /// If we log a tag that is enabled, a log call should be made. Calling
    /// TagLogger's log method causes a panic, so we should expect the below
    /// panic.
    #[test]
    #[should_panic(expected = "Expected call to log()!")]
    fn test_enabled_tag_is_logged() {
        let inner_logger = TagLogger::default();
        let mut logger = ContextLogger::<TestContext, TagLogger>::new(inner_logger);
        logger.inner_logger.enabled_tags = vec!["my_tag".to_string()];
        info!(tag => "my_tag", logger, "Hello {} #{}{}", "world", 4, "!");
    }

    /// If we log a tag that is not enabled, a log call should not be made.
    /// Calling TagLogger's log method causes a panic, so we should not
    /// expect any panics.
    #[test]
    fn test_enabled_tag_is_not_logged() {
        let inner_logger = TagLogger::default();
        let logger = ContextLogger::<TestContext, TagLogger>::new(inner_logger);
        info!(tag => "my_tag", logger, "Hello {} #{}{}", "world", 4, "!");
        debug!(tag => "my_tag", logger, "Hello {} #{}{}", "world", 4, "!");
        info!(tag => "my_tag", logger, "message");
        debug!(tag => "my_tag", logger, "message");
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
        info!(every_n_seconds => 1, logger ; sub_context1.field_opt_i32 => 1i32);
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
        info!(every_n_seconds => 0, logger ; sub_context1.field_opt_i32 => 1i32);
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
        warn!(every_n_seconds => 1, logger ; sub_context1.field_opt_i32 => 1i32);
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
        warn!(every_n_seconds => 0, logger ; sub_context1.field_opt_i32 => 1i32);
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
                    sub_context1.field_u64 => 12u64,
                    sub_context1.field_opt_i32 => 45,
                    sub_context1.field_string => "foo",
                    sub_context2.field_bool => true,
                );

                logger.inner_logger.expected_message = "foo bar".into();
                $log_macro!(
                    logger,
                    "foo bar";
                    sub_context1.field_u64 => 12u64,
                    sub_context1.field_opt_i32 => 45,
                    sub_context1.field_string => "foo",
                    sub_context2.field_bool => true,
                );

                logger.inner_logger.expected_message = "1 2 3 4 5".into();
                $log_macro!(
                    logger,
                    "{} {} {} {} {}", 1, 2, 3, 4, 5;
                    sub_context1.field_u64 => 12u64,
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
}
