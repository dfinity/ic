pub mod canister_snapshot_bits;
pub mod canister_state_bits;
pub mod ingress;
pub mod queues;
pub mod stats;
pub mod sync;
pub mod system_metadata;

#[allow(clippy::all)]
#[path = "../gen/state/state.v1.rs"]
pub mod v1;

#[cfg(test)]
mod tests;
