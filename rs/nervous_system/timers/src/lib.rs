//! This crate is meant to provide a test-safe version of timers.
//!
//! It is suggested to create your own timers mod in your own crate that looks like the following:
//!
//! mod timers {
//!     #[cfg(not(target_arch = "wasm32"))]
//!     pub use crate::real::{clear_timer, set_timer, set_timer_interval};
//!     #[cfg(target_arch = "wasm32")]
//!     pub use crate::test::{clear_timer, set_timer, set_timer_interval};
//! }
//!
//! At this point, you should rely on `mod timers` from your own crate instead of ic-cdk-timers.
//!
//! This will ensur
//! 9e that you use the ic_cdk_timers version of the functions correctly, while
//! having access to some useful test functions in unit tests such as:
//!
//! get_time_for_timers()
//! advance_time_for_timers(duration:Duration)
//! run_pending_timers()
//! get_timer_by_id(timer_id: TimerId)
//!
//! These functions will allow you to test everything thoroughly.
//!

pub use ic_cdk_timers::TimerId;

#[cfg(target_arch = "wasm32")]
pub use ic_cdk_timers::{clear_timer, set_timer, set_timer_interval};

#[cfg(not(target_arch = "wasm32"))]
pub use test::{clear_timer, set_timer, set_timer_interval};

pub mod test;
