//! Copy over the definition of the `ic_cdk::println!`
//! [macro](https://github.com/dfinity/cdk-rs/blob/aeea1af77ccdd1be0e35a2ff65e95552bf0ddc2d/ic-cdk/src/lib.rs#L42)
//! to avoid a dependency on the ic_cdk crate.

/// Format and then print the formatted message
#[cfg(target_family = "wasm")]
#[macro_export]
macro_rules! println {
    ($fmt:expr) => ($debug_print(format!($fmt)));
    ($fmt:expr, $($arg:tt)*) => ($debug_print(format!($fmt, $($arg)*)));
}

/// Format and then print the formatted message
#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! println {
    ($fmt:expr) => (std::println!($fmt));
    ($fmt:expr, $($arg:tt)*) => (std::println!($fmt, $($arg)*));
}

/// Prints the given message.
pub fn debug_print<S: std::convert::AsRef<str>>(s: S) {
    let s = s.as_ref();
    ic0::debug_print(s.as_bytes());
}
