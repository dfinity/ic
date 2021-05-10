use prost::Message;

/// Wraps around Message::encode and panics on error.
pub(crate) fn encode_or_panic<T: Message>(msg: &T) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    msg.encode(&mut buf).unwrap();
    buf
}

pub fn decode_registry_value<T: Message + Default>(registry_value: Vec<u8>) -> T {
    T::decode(registry_value.as_slice()).unwrap()
}
