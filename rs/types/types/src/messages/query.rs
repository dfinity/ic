use crate::{
    messages::{
        message_id::hash_of_map, HasCanisterId, HttpHandlerError, HttpUserQuery, MessageId,
        RawHttpRequestVal,
    },
    CanisterId, PrincipalId, UserId,
};
use maplit::btreemap;
use std::convert::TryFrom;

/// Represents a Query that is sent by an end user to a canister.
#[derive(Clone, PartialEq, Debug)]
pub struct UserQuery {
    pub source: UserId,
    pub receiver: CanisterId,
    pub method_name: String,
    pub method_payload: Vec<u8>,
    pub ingress_expiry: u64,
    pub nonce: Option<Vec<u8>>,
}

impl UserQuery {
    // TODO(EXC-235): Avoid the duplication between this method and the one in
    // `HttpUserQuery`.
    pub fn id(&self) -> MessageId {
        use RawHttpRequestVal::*;
        let mut map = btreemap! {
            "request_type".to_string() => String("query".to_string()),
            "canister_id".to_string() => Bytes(self.receiver.get().to_vec()),
            "method_name".to_string() => String(self.method_name.clone()),
            "arg".to_string() => Bytes(self.method_payload.clone()),
            "ingress_expiry".to_string() => U64(self.ingress_expiry),
            "sender".to_string() => Bytes(self.source.get().to_vec()),
        };
        if let Some(nonce) = &self.nonce {
            map.insert("nonce".to_string(), Bytes(nonce.clone()));
        }
        MessageId::from(hash_of_map(&map))
    }
}

impl TryFrom<HttpUserQuery> for UserQuery {
    type Error = HttpHandlerError;

    fn try_from(query: HttpUserQuery) -> Result<Self, Self::Error> {
        Ok(Self {
            source: UserId::from(PrincipalId::try_from(query.sender.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "Converting sender to PrincipalId failed with {}",
                    err
                ))
            })?),
            receiver: CanisterId::try_from(query.canister_id.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "Converting canister_id to PrincipalId failed with {:?}",
                    err
                ))
            })?,
            method_name: query.method_name,
            method_payload: query.arg.0,
            ingress_expiry: query.ingress_expiry,
            nonce: query.nonce.map(|n| n.0),
        })
    }
}

impl HasCanisterId for UserQuery {
    fn canister_id(&self) -> CanisterId {
        self.receiver
    }
}

#[cfg(test)]
mod test {
    use super::super::{Blob, HttpUserQuery};
    use maplit::btreemap;
    use serde::Deserialize;
    use serde_cbor::Value;

    fn bytes(bytes: &[u8]) -> Value {
        Value::Bytes(bytes.to_vec())
    }

    fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    fn number(value: u64) -> Value {
        Value::Integer(value.into())
    }

    /// Makes sure that `val` deserializes to `obj`
    /// Used when testing _incoming_ messages from the HTTP Handler's point of
    /// view
    fn assert_cbor_de_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: Deserialize<'de> + std::fmt::Debug + std::cmp::Eq,
    {
        let obj2 = serde_cbor::value::from_value(val).expect("Could not read CBOR value");
        assert_eq!(*obj, obj2);
    }

    #[test]
    fn decoding_read_query() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(vec![]),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0x04]),
                nonce: None,
                ingress_expiry: 0,
            },
            Value::Map(btreemap! {
                text("arg") => bytes(&[][..]),
                text("canister_id") => bytes(&[42; 8][..]),
                text("method_name") => text("some_method_name"),
                text("sender") => bytes(&[0x04][..]),
                text("ingress_expiry") => number(0),
            }),
        );
    }

    #[test]
    fn decoding_read_query_arg() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(b"Hello, World!".to_vec()),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0; 33]),
                nonce: None,
                ingress_expiry: 0,
            },
            Value::Map(btreemap! {
                text("arg") => bytes(b"Hello, World!"),
                text("canister_id") => bytes(&[42; 8][..]),
                text("method_name") => text("some_method_name"),
                text("sender") => bytes(&[0; 33]),
                text("ingress_expiry") => number(0),
            }),
        );
    }
}
