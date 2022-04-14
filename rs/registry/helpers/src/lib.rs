//! These are Helper traits that wrap a RegistryClient and provide
//! convenience-methods to turn raw bytes into internal data structures.
//! Traits specific to a particular component (crypto comes to mind) will move
//! to the respective crate/component at some point in the future.

pub mod crypto;
pub mod ecdsa_keys;
pub mod firewall;
pub mod node;
pub mod node_operator;
pub mod provisional_whitelist;
pub mod routing_table;
pub mod subnet;
pub mod test_proto;
pub mod unassigned_nodes;
use ic_interfaces::registry::{RegistryClientResult, RegistryValue};

/// Utility function to deserialize the bytes returned from the RegistryClient
/// into a protobuf type.
///
/// This methods panics if the message cannot be deserialized.
pub fn deserialize_registry_value<T: RegistryValue + Default>(
    raw_result: RegistryClientResult<Vec<u8>>,
) -> RegistryClientResult<T> {
    Ok(raw_result?.map(|bytes| T::decode(bytes.as_slice()).expect("Could not decode value.")))
}
