/// There are a lot of different ways of communicating with canisters and
/// there's a lot of different ways of encoding those communications. Below is a
/// non exhaustive list of the two and the Cartesian product of functions that
/// we were creating.
///
/// |        | query       | inter canister call | install | endpoint   | ..
/// | bytes  | query_bytes | call_bytes          | ..      | over_bytes | ..
/// | json   | query_json  | call_json           | ..      | over_json  | ..
/// | candid | ..          | call_canid          | ..      | ..         | ..
/// | proto  | ..          | call_proto          | ..      | ..         | ..
///
/// The aim of this package is to abstract and disambiguate over serialization
/// formats when deciding how to communicate with a canister. It is also
/// designed so new communication methods/ serialization formats can easily be
/// added to the Internet Computer.
///
///
///
/// It exists in it's own package because it's both used by canisters and
/// the internet computers test systems.
pub trait FromWire: Sized {
    fn from_bytes(wire: Vec<u8>) -> Result<Self, String>;
}

pub trait IntoWire {
    fn into_bytes(self) -> Result<Vec<u8>, String>;
}

pub trait NewType {
    type Inner;
    fn into_inner(self) -> Self::Inner;
    fn from_inner(_: Self::Inner) -> Self;
}

/// This tells the compiler to just read/write the raw bytes over the wire
// The _S stands for struct and avoids a collision with Bytes in the stdlib
pub struct BytesS(pub Vec<u8>);

/// Every witness is a type specialization of this function
/// The function itself should be a runtime no op
/// Witnesses eliminate ambiguity in internally polymorphic functions, this
/// witness is useless as it removes no ambiguity
/// When rust gets higher order types we can remove this function
// Potentially if we turned this into a 4 arity function we could entirely do
// away with the NewType, it would certainly make the type signatures simpler
pub fn witness<ReturnType: NewType, Payload: NewType>(
    rt: ReturnType,
    payload: Payload::Inner,
) -> (ReturnType::Inner, Payload) {
    (rt.into_inner(), Payload::from_inner(payload))
}

/// This tells communication function that you'd like you communicate using raw
/// bytes
pub fn bytes(a: BytesS, b: Vec<u8>) -> (Vec<u8>, BytesS) {
    witness(a, b)
}

impl FromWire for BytesS {
    fn from_bytes(wire: Vec<u8>) -> Result<BytesS, String> {
        Ok(BytesS(wire))
    }
}

impl IntoWire for BytesS {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        Ok(self.0)
    }
}

impl NewType for BytesS {
    type Inner = Vec<u8>;
    fn into_inner(self) -> Vec<u8> {
        self.0
    }
    fn from_inner(t: Vec<u8>) -> Self {
        BytesS(t)
    }
}

/// This causes values to be serialized and deserialized using rusts From and
/// Into traits. This is nice for a quick proof of concept as these types are
/// widely supported in the rust ecosystem, but are liable to change their
/// encoding format without warning between compiler/library versions.
// The _S stands for struct and avoids a collision with From in the stdlib
pub struct FromS<T>(pub T);

/// This tells communication function that you'd like you communicate using
/// FromS
pub fn from<A, B>(a: FromS<A>, b: B) -> (A, FromS<B>) {
    witness(a, b)
}

impl<T: From<Vec<u8>> + Sized> FromWire for FromS<T> {
    fn from_bytes(wire: Vec<u8>) -> Result<FromS<T>, String> {
        Ok(FromS(T::from(wire)))
    }
}

impl<T: Into<Vec<u8>>> IntoWire for FromS<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        Ok(self.0.into())
    }
}

impl<T> NewType for FromS<T> {
    type Inner = T;
    fn into_inner(self) -> T {
        self.0
    }
    fn from_inner(t: T) -> Self {
        FromS(t)
    }
}

impl IntoWire for Vec<u8> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        Ok(self)
    }
}

impl FromWire for Vec<u8> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        Ok(bytes)
    }
}
