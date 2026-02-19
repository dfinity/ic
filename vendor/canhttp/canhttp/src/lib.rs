//! Library to make [HTTPs outcalls](https://internetcomputer.org/https-outcalls)
//! from a canister on the Internet Computer,
//! leveraging the modularity of the [tower framework](https://rust-lang.guide/guide/learn-async-rust/tower.html).

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub use client::{
    CanisterReadyError, CanisterReadyLayer, CanisterReadyService, Client, HttpsOutcallError,
    IcError, IsReplicatedRequestExtension, MaxResponseBytesRequestExtension,
    TransformContextRequestExtension,
};
pub use convert::ConvertServiceBuilder;

mod client;
pub mod convert;
pub mod cycles;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "multi")]
pub mod multi;
pub mod observability;
pub mod retry;
