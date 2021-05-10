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
