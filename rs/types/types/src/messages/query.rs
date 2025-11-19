use crate::{
    CanisterId, PrincipalId, UserId,
    messages::{
        HasCanisterId, HttpRequestError, HttpUserQuery, MessageId,
        http::{CallOrQuery, representation_independent_hash_call_or_query},
    },
};
use ic_management_canister_types_private::IC_00;
use std::convert::TryFrom;

/// Represents the source of a query that is sent to a canister.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum QuerySource {
    /// A query sent by the IC to itself.
    System,
    /// A query sent by an end user.
    User {
        user_id: UserId,
        ingress_expiry: u64,
        nonce: Option<Vec<u8>>,
    },
}

impl QuerySource {
    pub fn user_id(&self) -> UserId {
        let principal_id = match self {
            QuerySource::User { user_id, .. } => user_id.get(),
            QuerySource::System => IC_00.get(),
        };
        UserId::from(principal_id)
    }
}

/// Represents a Query that is sent by an end user to a canister.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Query {
    pub source: QuerySource,
    pub receiver: CanisterId,
    pub method_name: String,
    pub method_payload: Vec<u8>,
}

impl Query {
    pub fn source(&self) -> PrincipalId {
        self.source.user_id().get()
    }

    pub fn id(&self) -> MessageId {
        match &self.source {
            QuerySource::User {
                user_id,
                ingress_expiry,
                nonce,
            } => MessageId::from(representation_independent_hash_call_or_query(
                CallOrQuery::Query,
                self.receiver.get().into_vec(),
                &self.method_name,
                self.method_payload.clone(),
                *ingress_expiry,
                user_id.get().into_vec(),
                nonce.as_deref(),
            )),
            QuerySource::System => MessageId::from(representation_independent_hash_call_or_query(
                CallOrQuery::Query,
                self.receiver.get().into_vec(),
                &self.method_name,
                self.method_payload.clone(),
                0,
                IC_00.get().into_vec(),
                None,
            )),
        }
    }
}

impl TryFrom<HttpUserQuery> for Query {
    type Error = HttpRequestError;

    fn try_from(query: HttpUserQuery) -> Result<Self, Self::Error> {
        Ok(Self {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::try_from(query.sender.0).map_err(|err| {
                    HttpRequestError::InvalidPrincipalId(format!(
                        "Converting sender to PrincipalId failed with {err}"
                    ))
                })?),
                ingress_expiry: query.ingress_expiry,
                nonce: query.nonce.map(|n| n.0),
            },
            receiver: CanisterId::try_from(query.canister_id.0).map_err(|err| {
                HttpRequestError::InvalidPrincipalId(format!(
                    "Converting canister_id to PrincipalId failed with {err:?}"
                ))
            })?,
            method_name: query.method_name,
            method_payload: query.arg.0,
        })
    }
}

impl HasCanisterId for Query {
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
