//! The `ic_messaging` crate implements (i) deterministic batch processing; and
//! (ii) inter-canister message routing within a subnet and across subnets (also
//! known as cross-net or XNet transfer).

mod message_routing;
pub(crate) mod routing;
mod scheduling;
mod state_machine;

pub use message_routing::MessageRoutingImpl;
