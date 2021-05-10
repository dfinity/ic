//! These are Helper traits that wrap a RegistryClient and provide
//! convenience-methods to turn raw bytes into internal data structures.
//! Traits specific to a particular component (crypto comes to mind) will move
//! to the respective crate/component at some point in the future.

pub mod crypto;
pub mod firewall;
pub mod node;
pub mod provisional_whitelist;
pub mod routing_table;
pub mod subnet;
