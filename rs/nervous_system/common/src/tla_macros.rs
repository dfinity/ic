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
