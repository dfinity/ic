#[macro_export]
macro_rules! tla_log_request {
    ($label:expr, $to:expr, $method:expr, $message:expr) => {{
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_request!($label, $to, $method, $message)
    }};
}

#[macro_export]
macro_rules! tla_log_response {
    ($to:expr, $message:expr) => {{
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_response!($to, $message)
    }};
}

#[macro_export]
macro_rules! tla_log_locals {
    ($($args:tt)*) => {
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_locals!($($args)*);
    }
}

#[macro_export]
macro_rules! tla_snapshotter {
    ($first_arg:expr $(, $_rest:tt)* ) => {{
        // Use a block to potentially shadow variables and contain the logic
        let raw_ptr = ::tla_instrumentation::UnsafeSendPtr($first_arg as *const _);
        ::std::sync::Arc::new(::std::sync::Mutex::new(move || {
            $crate::governance::tla::get_tla_globals(&raw_ptr)
        }))
    }};
}

#[macro_export]
macro_rules! tla_log_label {
    ($label:expr) => {
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_label!($label);
    };
}
