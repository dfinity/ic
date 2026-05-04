use crate::{
    CanisterId, PrincipalId, UserId,
    messages::{
        HasCanisterId, HttpRequestError, HttpUserQuery, MessageId, SenderInfo, SignedSenderInfo,
        http::{
            CallOrQuery, RawSignedSenderInfoSlices, representation_independent_hash_call_or_query,
        },
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
        sender_info: Option<SignedSenderInfo>,
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

    pub fn sender_info(&self) -> Option<SenderInfo> {
        match &self.source {
            QuerySource::User { sender_info, .. } => sender_info.as_ref().map(|si| SenderInfo {
                info: si.info.clone(),
                signer: si.signer,
            }),
            QuerySource::System => None,
        }
    }

    pub fn id(&self) -> MessageId {
        match &self.source {
            QuerySource::User {
                user_id,
                ingress_expiry,
                nonce,
                sender_info,
            } => MessageId::from(representation_independent_hash_call_or_query(
                CallOrQuery::Query,
                self.receiver.as_ref(),
                &self.method_name,
                &self.method_payload,
                *ingress_expiry,
                user_id.get_ref().as_slice(),
                nonce.as_deref(),
                sender_info
                    .as_ref()
                    .map(|sender_info| RawSignedSenderInfoSlices {
                        info: &sender_info.info,
                        signer: sender_info.signer.as_ref(),
                        sig: &sender_info.sig,
                    }),
            )),
            QuerySource::System => MessageId::from(representation_independent_hash_call_or_query(
                CallOrQuery::Query,
                self.receiver.as_ref(),
                &self.method_name,
                &self.method_payload,
                0,
                IC_00.as_ref(),
                None,
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
                sender_info: match query.sender_info {
                    Some(sender_info) => Some(SignedSenderInfo {
                        info: sender_info.info.0,
                        signer: CanisterId::try_from(sender_info.signer.0).map_err(|err| {
                            HttpRequestError::InvalidPrincipalId(format!(
                                "Converting sender_info.signer to PrincipalId failed with {err:?}"
                            ))
                        })?,
                        sig: sender_info.sig.0,
                    }),
                    None => None,
                },
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
    use super::super::{Blob, HttpUserQuery, Query, QuerySource, RawSignedSenderInfo};
    use crate::{CanisterId, UserId, messages::SignedSenderInfo};
    use ic_base_types::PrincipalId;
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
                sender_info: None,
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
                sender_info: None,
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

    #[test]
    fn decoding_read_query_with_sender_info() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(vec![]),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0x04]),
                nonce: Some(Blob(vec![1, 2, 3])),
                ingress_expiry: 0,
                sender_info: Some(RawSignedSenderInfo {
                    info: Blob(vec![1, 2, 3]),
                    signer: Blob(vec![42; 8]),
                    sig: Blob(vec![4, 5, 6]),
                }),
            },
            Value::Map(btreemap! {
                text("arg") => bytes(&[][..]),
                text("canister_id") => bytes(&[42; 8][..]),
                text("method_name") => text("some_method_name"),
                text("sender") => bytes(&[0x04][..]),
                text("nonce") => bytes(&[1, 2, 3][..]),
                text("ingress_expiry") => number(0),
                text("sender_info") => Value::Map(btreemap! {
                    text("info") => bytes(&[1, 2, 3][..]),
                    text("signer") => bytes(&[42; 8][..]),
                    text("sig") => bytes(&[4, 5, 6][..]),
                }),
            }),
        );
    }

    #[test]
    fn decoding_read_query_without_sender_info() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(vec![]),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0x04]),
                nonce: None,
                ingress_expiry: 0,
                sender_info: None,
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
    fn query_message_id_changes_when_sender_info_is_present() {
        let user_id = UserId::from(PrincipalId::new_user_test_id(1));
        let ingress_expiry = 1_000;
        let nonce = Some(vec![1, 2, 3]);
        let receiver = CanisterId::from_u64(1);
        let method_name = "query".to_string();
        let method_payload = vec![4, 5, 6];

        let base_query = Query {
            source: QuerySource::User {
                user_id,
                ingress_expiry,
                nonce: nonce.clone(),
                sender_info: None,
            },
            receiver,
            method_name: method_name.clone(),
            method_payload: method_payload.clone(),
        };

        let query_with_sender_info = Query {
            source: QuerySource::User {
                user_id,
                ingress_expiry,
                nonce,
                sender_info: Some(SignedSenderInfo {
                    info: vec![7, 8, 9],
                    signer: CanisterId::from_u64(2),
                    sig: vec![10, 11, 12],
                }),
            },
            receiver,
            method_name,
            method_payload,
        };

        let id_without_sender_info = base_query.id();
        let id_with_sender_info = query_with_sender_info.id();

        assert_ne!(id_without_sender_info, id_with_sender_info);
    }

    #[test]
    fn query_message_id_is_stable_with_sender_info() {
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_user_test_id(1)),
                ingress_expiry: 1_000,
                nonce: Some(vec![1, 2, 3]),
                sender_info: Some(SignedSenderInfo {
                    info: vec![7, 8, 9],
                    signer: CanisterId::from_u64(2),
                    sig: vec![10, 11, 12],
                }),
            },
            receiver: CanisterId::from_u64(1),
            method_name: "query".to_string(),
            method_payload: vec![4, 5, 6],
        };

        assert_eq!(
            hex::encode(query.id().as_bytes()),
            "d72dc05686e601cc5115c5c39fe02ebf8817dff06aedb28046aeb5bbfc444bb2"
        );
    }

    #[test]
    fn query_message_id_is_stable_without_sender_info() {
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_user_test_id(1)),
                ingress_expiry: 1_000,
                nonce: Some(vec![1, 2, 3]),
                sender_info: None,
            },
            receiver: CanisterId::from_u64(1),
            method_name: "query".to_string(),
            method_payload: vec![4, 5, 6],
        };

        assert_eq!(
            hex::encode(query.id().as_bytes()),
            "17eef00dbc528a593b4f89f8b9d7a8275a04bc8aa3727cd960de2071675cddbe"
        );
    }
}
