pub mod canister_state_bits;
pub mod ingress;
pub mod queues;
pub mod sync;
pub mod system_metadata;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/state/state.v1.rs"));
}
