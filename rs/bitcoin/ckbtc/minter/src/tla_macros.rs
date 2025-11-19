#[macro_export]
macro_rules! tla_log_request {
    ($label:expr_2021, $to:expr_2021, $method:expr_2021, $message:expr_2021) => {{
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_request!($label, $to, $method, $message)
    }};
}

#[macro_export]
macro_rules! tla_log_response {
    ($to:expr_2021, $message:expr_2021) => {{
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
macro_rules! tla_log_label {
    ($label:expr_2021) => {
        #[cfg(feature = "tla")]
        tla_instrumentation::tla_log_label!($label);
    };
}

#[macro_export]
macro_rules! tla_snapshotter {
    () => {{
        ::std::sync::Arc::new(::std::sync::Mutex::new(|| $crate::tla::get_tla_globals()))
    }};
    ($($args:tt)*) => {{
        tla_snapshotter!()
    }};
}
