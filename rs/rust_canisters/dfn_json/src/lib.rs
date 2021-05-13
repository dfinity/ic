use on_wire::{witness, FromWire, IntoWire, NewType};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

/// This causes values to be serialized and deserialized using serde's
/// DeserializeOwned and Serialize traits
pub struct Json<A>(pub A);

/// This is a type witness
pub fn json<A, B>(a: Json<A>, b: B) -> (A, Json<B>) {
    witness(a, b)
}

impl<T: DeserializeOwned + Sized> FromWire for Json<T> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Json<T>, String> {
        match serde_json::from_slice(&bytes) {
            Ok(v) => Ok(Json(v)),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl<T: Serialize> IntoWire for Json<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.0).map_err(|e| e.to_string())
    }
}

impl<T> NewType for Json<T> {
    type Inner = T;
    fn into_inner(self) -> T {
        self.0
    }
    fn from_inner(t: T) -> Self {
        Json(t)
    }
}
