use on_wire::{FromWire, IntoWire, NewType};

/// Auxiliary type required for `protobuf` function below to work.
pub struct Protobuf<A>(pub A);

/// This function simplifies implementation of and communication with canisters
/// that talk protobuf.
///
/// It's designed to be used with `over*` family of function from `dfn_core`,
/// just like `bytes`, `json`, etc.
///
/// It can also be used in tests with `canister.query_()` and
/// `canister.update_()` calls.
pub fn protobuf<A, B>(a: Protobuf<A>, b: B) -> (A, Protobuf<B>) {
    on_wire::witness(a, b)
}

impl<T: prost::Message + Default + Sized> FromWire for Protobuf<T> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Protobuf<T>, String> {
        T::decode(&bytes[..])
            .map(Protobuf)
            .map_err(|err| err.to_string())
    }
}

impl<T: prost::Message> IntoWire for Protobuf<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::<u8>::new();
        self.0.encode(&mut buf).map_err(|err| err.to_string())?;
        Ok(buf)
    }
}

impl<T> NewType for Protobuf<T> {
    type Inner = T;
    fn into_inner(self) -> T {
        self.0
    }
    fn from_inner(t: T) -> Self {
        Protobuf(t)
    }
}
