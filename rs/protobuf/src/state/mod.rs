pub mod canister_state_bits;
pub mod ingress;
pub mod queues;
pub mod sync;
pub mod system_metadata;

#[rustfmt::skip]
#[path = "../../gen/state/state.v1.rs"]
pub mod v1;
