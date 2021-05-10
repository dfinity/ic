//! The `ic_messaging` crate implements (i) deterministic batch processing; and
//! (ii) inter-canister message routing within a subnet and across subnets (also
//! known as cross-net or XNet transfer).

pub mod certified_slice_pool;
pub(crate) mod hyper;
mod message_routing;
pub(crate) mod routing;
mod scheduling;
mod state_machine;
mod xnet_endpoint;
mod xnet_payload_builder;
pub(crate) mod xnet_uri;

pub use message_routing::MessageRoutingImpl;
pub use xnet_endpoint::{XNetEndpoint, XNetEndpointConfig};
pub use xnet_payload_builder::{
    testing as xnet_payload_builder_testing, ExpectedIndices, XNetPayloadBuilderImpl,
};
