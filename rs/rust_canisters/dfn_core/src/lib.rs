#![cfg_attr(nightly_compiler, feature(set_stdio))]
pub mod api;
pub mod endpoint;
pub mod printer;
pub mod setup;
pub mod stable;

pub use api::futures::FutureResult;
pub use api::{call, call_explicit, CanisterId};
pub use endpoint::{
    bytes, from, over, over_async, over_async_explicit, over_async_may_reject, over_explicit,
    over_init, over_may_reject,
};
pub use on_wire::{BytesS, FromS};
