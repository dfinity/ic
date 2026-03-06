pub mod builder;
pub mod fn_builder;
pub(crate) mod render;

#[cfg(test)]
mod tests;

pub use builder::{WatCanisterBuilder, wat_canister};
pub use fn_builder::{WatFnCode, wat_fn};
