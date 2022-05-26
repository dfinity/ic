//! Types related to various messages that the Internet Computer handles.
mod blob;
mod http;
mod ingress_messages;
mod inter_canister;
mod message_id;
mod query;
mod read_state;
mod webauthn;

pub use self::http::{
    Authentication, Certificate, CertificateDelegation, Delegation, HasCanisterId, HttpCallContent,
    HttpCanisterUpdate, HttpQueryContent, HttpQueryResponse, HttpQueryResponseReply, HttpReadState,
    HttpReadStateContent, HttpReadStateResponse, HttpReply, HttpRequest, HttpRequestContent,
    HttpRequestEnvelope, HttpRequestError, HttpResponseStatus, HttpStatusResponse, HttpUserQuery,
    RawHttpRequestVal, ReplicaHealthStatus, SignedDelegation,
};
use crate::{user_id_into_protobuf, user_id_try_from_protobuf, Cycles, Funds, NumBytes, UserId};
pub use blob::Blob;
use ic_base_types::{CanisterId, PrincipalId};
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
pub use ingress_messages::{is_subnet_message, Ingress, SignedIngress, SignedIngressContent};
pub use inter_canister::{
    CallContextId, CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response,
};
pub use message_id::{MessageId, MessageIdError, EXPECTED_MESSAGE_ID_LENGTH};
pub use query::{AnonymousQuery, AnonymousQueryResponse, AnonymousQueryResponseReply, UserQuery};
pub use read_state::ReadState;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::mem::size_of;
pub use webauthn::{WebAuthnEnvelope, WebAuthnSignature};

/// Same as [MAX_INTER_CANISTER_PAYLOAD_IN_BYTES], but of a primitive type
/// that can be used for computation in const context.
pub const MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64: u64 = 2 * 1024 * 1024; // 2 MiB

/// This sets the upper bound on how large a single inter-canister request or
/// response (as returned by `RequestOrResponse::payload_size_bytes()`) can be.
///
/// We know that allowing messages larger than around 2MB has
/// various security and performance impacts on the network.  More specifically,
/// large messages can allow dishonest block makers to always manage to get
/// their blocks notarized; and when the consensus protocol is configured for
/// smaller messages, a large message in the network can cause the finalization
/// rate to drop.
pub const MAX_INTER_CANISTER_PAYLOAD_IN_BYTES: NumBytes =
    NumBytes::new(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64); // 2 MiB

/// The maximum size of an inter-canister request or response that the IC can
/// support.
///
/// This should be strictly larger than MAX_INTER_CANISTER_PAYLOAD_IN_BYTES to
/// account for the additional metadata in the `Request`s and `Response`s.  At
/// the time of writing, these data structures contain some variable length
/// fields (e.g. sender: CanisterId), so it is not possible to statically
/// compute an upper bound on their sizes.  Hopefully the additional space we
/// have allocated here is sufficient.
pub const MAX_XNET_PAYLOAD_IN_BYTES: NumBytes =
    NumBytes::new(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 * 21 / 20); // 2.1 MiB

/// Maximum byte size of a valid inter-canister `Response`.
pub const MAX_RESPONSE_COUNT_BYTES: usize =
    size_of::<RequestOrResponse>() + MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize;

/// An end user's signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserSignature {
    /// The actual signature. End users should sign the `MessageId` computed
    /// from the message that they are signing.
    pub signature: Vec<u8>,
    /// The user's public key whose corresponding private key should have been
    /// used to sign the MessageId.
    pub signer_pubkey: Vec<u8>,

    pub sender_delegation: Option<Vec<SignedDelegation>>,
}

/// Stores info needed for processing and tracking requests to
/// stop canisters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StopCanisterContext {
    Ingress {
        sender: UserId,
        message_id: MessageId,
    },
    Canister {
        sender: CanisterId,
        reply_callback: CallbackId,
        /// The cycles that the request to stop the canister contained.  Stored
        /// here so that they can be returned to the caller in the eventual
        /// reply.
        cycles: Cycles,
    },
}

impl StopCanisterContext {
    pub fn sender(&self) -> &PrincipalId {
        match self {
            StopCanisterContext::Ingress { sender, .. } => sender.get_ref(),
            StopCanisterContext::Canister { sender, .. } => sender.get_ref(),
        }
    }

    pub fn take_cycles(&mut self) -> Cycles {
        match self {
            StopCanisterContext::Ingress { .. } => Cycles::zero(),
            StopCanisterContext::Canister { cycles, .. } => cycles.take(),
        }
    }
}

impl From<&StopCanisterContext> for pb::StopCanisterContext {
    fn from(item: &StopCanisterContext) -> Self {
        match item {
            StopCanisterContext::Ingress { sender, message_id } => Self {
                context: Some(pb::stop_canister_context::Context::Ingress(
                    pb::stop_canister_context::Ingress {
                        sender: Some(user_id_into_protobuf(*sender)),
                        message_id: message_id.as_bytes().to_vec(),
                    },
                )),
            },
            StopCanisterContext::Canister {
                sender,
                reply_callback,
                cycles,
            } => Self {
                context: Some(pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender: Some(pb_types::CanisterId::from(*sender)),
                        reply_callback: reply_callback.get(),
                        funds: Some((&Funds::new(*cycles)).into()),
                        cycles: Some((*cycles).into()),
                    },
                )),
            },
        }
    }
}

impl TryFrom<pb::StopCanisterContext> for StopCanisterContext {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::StopCanisterContext) -> Result<Self, Self::Error> {
        let stop_canister_context =
            match try_from_option_field(value.context, "StopCanisterContext::context")? {
                pb::stop_canister_context::Context::Ingress(
                    pb::stop_canister_context::Ingress { sender, message_id },
                ) => StopCanisterContext::Ingress {
                    sender: user_id_try_from_protobuf(try_from_option_field(
                        sender,
                        "StopCanisterContext::Ingress::sender",
                    )?)?,
                    message_id: MessageId::try_from(message_id.as_slice())?,
                },
                pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender,
                        reply_callback,
                        funds,
                        cycles,
                    },
                ) => {
                    // To maintain backwards compatibility we fall back to reading from `funds` if
                    // `cycles` is not set.
                    let cycles = match try_from_option_field(
                        cycles,
                        "StopCanisterContext::Canister::cycles",
                    ) {
                        Ok(cycles) => cycles,
                        Err(_) => {
                            let mut funds: Funds = try_from_option_field(
                                funds,
                                "StopCanisterContext::Canister::funds",
                            )?;
                            funds.take_cycles()
                        }
                    };

                    StopCanisterContext::Canister {
                        sender: try_from_option_field(
                            sender,
                            "StopCanisterContext::Canister::sender",
                        )?,
                        reply_callback: CallbackId::from(reply_callback),
                        cycles,
                    }
                }
            };
        Ok(stop_canister_context)
    }
}

/// Bytes representation of signed HTTP requests, using CBOR as a serialization
/// format. Use `TryFrom` or `TryInto` to convert between `SignedRequestBytes`
/// and other types, corresponding to serialization/deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedRequestBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl AsRef<[u8]> for SignedRequestBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignedRequestBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SignedRequestBytes(bytes)
    }
}

impl From<SignedRequestBytes> for Vec<u8> {
    fn from(bytes: SignedRequestBytes) -> Vec<u8> {
        bytes.0
    }
}

impl<T: Serialize> TryFrom<HttpRequestEnvelope<T>> for SignedRequestBytes {
    type Error = serde_cbor::Error;

    fn try_from(request: HttpRequestEnvelope<T>) -> Result<Self, Self::Error> {
        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe()?;
        request.serialize(&mut serializer)?;
        Ok(serialized_bytes.into())
    }
}

impl<'a, T> TryFrom<&'a SignedRequestBytes> for HttpRequestEnvelope<T>
where
    for<'b> T: Deserialize<'b>,
{
    type Error = serde_cbor::Error;

    fn try_from(bytes: &'a SignedRequestBytes) -> Result<Self, Self::Error> {
        serde_cbor::from_slice::<HttpRequestEnvelope<T>>(bytes.as_ref())
    }
}

impl SignedRequestBytes {
    /// Return true if the bytes is empty or false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the length (number of bytes).
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::current_time_and_expiry_time;
    use maplit::btreemap;
    use serde_cbor::Value;
    use std::{convert::TryFrom, io::Cursor};

    fn debug_blob(v: Vec<u8>) -> String {
        format!("{:?}", Blob(v))
    }

    #[test]
    fn test_debug_blob() {
        assert_eq!(debug_blob(vec![]), "Blob{empty}");
        assert_eq!(debug_blob(vec![0]), "Blob{00}");
        assert_eq!(debug_blob(vec![255, 0]), "Blob{ff00}");
        assert_eq!(debug_blob(vec![1, 2, 3]), "Blob{010203}");
        assert_eq!(debug_blob(vec![0, 1, 15, 255]), "Blob{4 bytes;00010fff}");
        let long_vec: Vec<u8> = (0_u8..100_u8).collect();
        let long_debug = debug_blob(long_vec);
        assert_eq!(
            long_debug.len(),
            "Blob{100 bytes;}".len() + 100 /*bytes*/ * 2 /* char per byte */
        );
        assert!(
            long_debug.starts_with("Blob{100 bytes;"),
            "long_debug: {}",
            long_debug
        );
        assert!(long_debug.ends_with("63}"), "long_debug: {}", long_debug); // 99 = 16*6 + 3
    }

    fn format_blob(v: Vec<u8>) -> String {
        format!("{}", Blob(v))
    }

    #[test]
    fn test_format_blob() {
        assert_eq!(format_blob(vec![]), "Blob{empty}");
        assert_eq!(format_blob(vec![0]), "Blob{00}");
        assert_eq!(format_blob(vec![255, 0]), "Blob{ff00}");
        assert_eq!(format_blob(vec![1, 2, 3]), "Blob{010203}");
        assert_eq!(format_blob(vec![0, 1, 15, 255]), "Blob{4 bytes;00010fff}");
        let long_vec: Vec<u8> = (0_u8..100_u8).collect();
        let long_str = format_blob(long_vec);
        assert_eq!(
            long_str.len(),
            "Blob{100 bytes;…}".len() + 40 /*max num bytes to format */ * 2 /* char per byte */
        );
        assert!(
            long_str.starts_with("Blob{100 bytes;"),
            "long_str: {}",
            long_str
        );
        // The last printed byte is 39, which is 16*2 + 7
        assert!(long_str.ends_with("27…}"), "long_str: {}", long_str);
    }

    /// Makes sure that `val` deserializes to `obj`
    /// Used when testing _incoming_ messages from the HTTP Handler's point of
    /// view
    fn assert_cbor_de_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: serde::Deserialize<'de> + std::fmt::Debug + std::cmp::Eq,
    {
        let obj2 = serde_cbor::value::from_value(val).expect("Could not read CBOR value");
        assert_eq!(*obj, obj2);
    }

    fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    fn bytes(bs: &[u8]) -> Value {
        Value::Bytes(bs.to_vec())
    }

    fn integer(val: u64) -> Value {
        Value::Integer(val as i128)
    }

    #[test]
    fn decoding_submit_call() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: None,
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b""),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn decoding_submit_call_arg() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"some_arg".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: None,
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b"some_arg"),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn decoding_submit_call_with_nonce() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpCallContent> {
                content: HttpCallContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"some_arg".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: Some(Blob(vec![1, 2, 3, 4, 5])),
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b"some_arg"),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                    text("nonce") => bytes(&[1, 2, 3, 4, 5][..]),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn serialize_via_bincode() {
        let expiry_time = current_time_and_expiry_time().1;
        let update = HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(vec![42; 8]),
                    method_name: "some_method".to_string(),
                    arg: Blob(b"".to_vec()),
                    sender: Blob(vec![0x04]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: Some(Blob(vec![2; 32])),
            sender_sig: Some(Blob(vec![1; 32])),
            sender_delegation: None,
        };
        let signed_ingress = SignedIngress::try_from(update).unwrap();
        let bytes = bincode::serialize(&signed_ingress).unwrap();
        let signed_ingress1 = bincode::deserialize::<SignedIngress>(&bytes);
        assert!(signed_ingress1.is_ok());
    }

    #[test]
    fn serialize_via_bincode_without_signature() {
        let expiry_time = current_time_and_expiry_time().1;
        let update = HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(vec![42; 8]),
                    method_name: "some_method".to_string(),
                    arg: Blob(b"".to_vec()),
                    sender: Blob(vec![0x04]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };
        let signed_ingress = SignedIngress::try_from(update).unwrap();
        let bytes = bincode::serialize(&signed_ingress).unwrap();
        let mut buffer = Cursor::new(&bytes);
        let signed_ingress1: SignedIngress = bincode::deserialize_from(&mut buffer).unwrap();
        assert_eq!(signed_ingress, signed_ingress1);
    }
}
