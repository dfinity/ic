use on_wire::{witness, FromWire, IntoWire, NewType};
use prost::Message;

pub struct ProtoBuf<A>(pub A);

impl<A> ProtoBuf<A> {
    pub fn new(a: A) -> Self {
        ProtoBuf(a)
    }

    pub fn get(self) -> A {
        self.0
    }
}

/// This is the witness for protobuf types (types with a prost::Message
/// implementation) and types that convert to a protobuf type (types with a
/// ToProto implementation).
pub fn protobuf<A, B>(a: ProtoBuf<A>, b: B) -> (A, ProtoBuf<B>)
where
    A: ToProto,
    B: ToProto,
{
    witness(a, b)
}

/// This is deliberately less flexible than From/TryFrom because they can have
/// multiple types they can be transformed into, preventing type inference. Each
/// type can only have one proto type it maps to.
pub trait ToProto: Sized {
    type Proto: Message + Default;
    fn from_proto(_: Self::Proto) -> Result<Self, String>;
    fn into_proto(self) -> Self::Proto;
}

impl<Type: Message + Default> ToProto for Type {
    type Proto = Type;

    fn from_proto(pt: Self::Proto) -> Result<Self, String> {
        Ok(pt)
    }

    fn into_proto(self) -> Self::Proto {
        self
    }
}

impl<Type: ToProto> FromWire for ProtoBuf<Type> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let ty = Type::Proto::decode(&bytes[..]).map_err(|e| e.to_string())?;
        Ok(ProtoBuf(Type::from_proto(ty)?))
    }
}

impl<Type: ToProto> IntoWire for ProtoBuf<Type> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        let proto_type = self.0.into_proto();
        let mut buf = Vec::with_capacity(proto_type.encoded_len());
        proto_type.encode(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }
}

impl<T> NewType for ProtoBuf<T> {
    type Inner = T;
    fn into_inner(self) -> T {
        self.0
    }
    fn from_inner(t: T) -> Self {
        ProtoBuf::new(t)
    }
}
