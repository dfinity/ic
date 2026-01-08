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
    Authentication, Certificate, CertificateDelegation, CertificateDelegationFormat,
    CertificateDelegationMetadata, Delegation, HasCanisterId, HttpCallContent, HttpCanisterUpdate,
    HttpQueryContent, HttpQueryResponse, HttpQueryResponseReply, HttpReadState,
    HttpReadStateContent, HttpReadStateResponse, HttpReply, HttpRequest, HttpRequestContent,
    HttpRequestEnvelope, HttpRequestError, HttpSignedQueryResponse, HttpStatusResponse,
    HttpUserQuery, NodeSignature, QueryResponseHash, RawHttpRequestVal, ReplicaHealthStatus,
    SignedDelegation,
};
pub use crate::methods::SystemMethod;
use crate::time::CoarseTime;
use crate::{Cycles, NumBytes, UserId, user_id_into_protobuf, user_id_try_from_protobuf};
pub use blob::Blob;
use ic_base_types::{CanisterId, PrincipalId};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::CanisterChangeOrigin;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
pub use ingress_messages::{
    Ingress, ParseIngressError, SignedIngress, SignedIngressContent, extract_effective_canister_id,
};
pub use inter_canister::{
    CallContextId, CallbackId, MAX_REJECT_MESSAGE_LEN_BYTES, NO_DEADLINE, Payload, Refund,
    RejectContext, Request, RequestMetadata, RequestOrResponse, Response, StreamMessage,
};
pub use message_id::{EXPECTED_MESSAGE_ID_LENGTH, MessageId, MessageIdError};
use phantom_newtype::Id;
pub use query::{Query, QuerySource};
pub use read_state::ReadState;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use std::mem::size_of;
use std::{convert::TryFrom, sync::Arc};
use strum_macros::EnumIter;
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

/// Error margin (in percentage points) of the deterministic payload size
/// estimate, relative to the actual byte size of the encoded slice.
pub const MAX_XNET_PAYLOAD_SIZE_ERROR_MARGIN_PERCENT: u64 = 5;

/// Maximum byte size of a valid inter-canister `Response`.
pub const MAX_RESPONSE_COUNT_BYTES: usize = size_of::<RequestOrResponse>()
    + size_of::<Response>()
    + MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize;

/// An end user's signature.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct UserSignature {
    /// The actual signature. End users should sign the `MessageId` computed
    /// from the message that they are signing.
    pub signature: Vec<u8>,
    /// The user's public key whose corresponding private key should have been
    /// used to sign the MessageId.
    pub signer_pubkey: Vec<u8>,

    pub sender_delegation: Option<Vec<SignedDelegation>>,
}

pub struct StopCanisterCallIdTag;
pub type StopCanisterCallId = Id<StopCanisterCallIdTag, u64>;

/// Stores info needed for processing and tracking requests to
/// stop canisters.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum StopCanisterContext {
    Ingress {
        sender: UserId,
        message_id: MessageId,
        call_id: Option<StopCanisterCallId>,
    },
    Canister {
        sender: CanisterId,
        reply_callback: CallbackId,
        // TODO(EXC-1450): Make call_id non-optional.
        call_id: Option<StopCanisterCallId>,
        /// The cycles that the request to stop the canister contained.  Stored
        /// here so that they can be returned to the caller in the eventual
        /// reply.
        cycles: Cycles,
        /// Deadline of the the stop canister call, if any (copied from request).
        deadline: CoarseTime,
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

    pub fn call_id(&self) -> &Option<StopCanisterCallId> {
        match &self {
            StopCanisterContext::Ingress { call_id, .. } => call_id,
            StopCanisterContext::Canister { call_id, .. } => call_id,
        }
    }
}

impl From<(CanisterCall, StopCanisterCallId)> for StopCanisterContext {
    fn from(input: (CanisterCall, StopCanisterCallId)) -> Self {
        let (msg, call_id) = input;
        assert_eq!(
            msg.method_name(),
            "stop_canister",
            "Converting a CanisterCall into StopCanisterContext should only happen with stop_canister calls."
        );
        match msg {
            CanisterCall::Request(mut req) => StopCanisterContext::Canister {
                sender: req.sender,
                reply_callback: req.sender_reply_callback,
                call_id: Some(call_id),
                cycles: Arc::make_mut(&mut req).payment.take(),
                deadline: req.deadline,
            },
            CanisterCall::Ingress(ingress) => StopCanisterContext::Ingress {
                sender: ingress.source,
                message_id: ingress.message_id.clone(),
                call_id: Some(call_id),
            },
        }
    }
}

impl From<&StopCanisterContext> for pb::StopCanisterContext {
    fn from(item: &StopCanisterContext) -> Self {
        match item {
            StopCanisterContext::Ingress {
                sender,
                message_id,
                call_id,
            } => Self {
                context: Some(pb::stop_canister_context::Context::Ingress(
                    pb::stop_canister_context::Ingress {
                        sender: Some(user_id_into_protobuf(*sender)),
                        message_id: message_id.as_bytes().to_vec(),
                        call_id: call_id.map(|id| id.get()),
                    },
                )),
            },
            StopCanisterContext::Canister {
                sender,
                reply_callback,
                call_id,
                cycles,
                deadline,
            } => Self {
                context: Some(pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender: Some(pb_types::CanisterId::from(*sender)),
                        reply_callback: reply_callback.get(),
                        call_id: call_id.map(|id| id.get()),
                        cycles: Some((*cycles).into()),
                        deadline_seconds: deadline.as_secs_since_unix_epoch(),
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
                    pb::stop_canister_context::Ingress {
                        sender,
                        message_id,
                        call_id,
                    },
                ) => StopCanisterContext::Ingress {
                    sender: user_id_try_from_protobuf(try_from_option_field(
                        sender,
                        "StopCanisterContext::Ingress::sender",
                    )?)?,
                    message_id: MessageId::try_from(message_id.as_slice())?,
                    call_id: call_id.map(StopCanisterCallId::from),
                },
                pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender,
                        reply_callback,
                        call_id,
                        cycles,
                        deadline_seconds,
                    },
                ) => StopCanisterContext::Canister {
                    sender: try_from_option_field(sender, "StopCanisterContext::Canister::sender")?,
                    reply_callback: CallbackId::from(reply_callback),
                    call_id: call_id.map(StopCanisterCallId::from),
                    cycles: try_from_option_field(cycles, "StopCanisterContext::Canister::cycles")?,
                    deadline: CoarseTime::from_secs_since_unix_epoch(deadline_seconds),
                },
            };
        Ok(stop_canister_context)
    }
}

/// Bytes representation of signed HTTP requests, using CBOR as a serialization
/// format. Use `TryFrom` or `TryInto` to convert between `SignedRequestBytes`
/// and other types, corresponding to serialization/deserialization.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
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

/// A wrapper around ingress messages and canister requests/responses.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CanisterMessage {
    Response(Arc<Response>),
    Request(Arc<Request>),
    Ingress(Arc<Ingress>),
}

impl CanisterMessage {
    /// Helper function to extract the effective canister id.
    pub fn effective_canister_id(&self) -> Option<CanisterId> {
        match &self {
            CanisterMessage::Ingress(ingress) => ingress.effective_canister_id,
            CanisterMessage::Request(request) => request.extract_effective_canister_id(),
            CanisterMessage::Response(_) => None,
        }
    }
}

impl Display for CanisterMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CanisterMessage::Ingress(ingress) => {
                write!(f, "Ingress, method name {},", ingress.method_name)
            }
            CanisterMessage::Request(request) => {
                write!(f, "Request, method name {},", request.method_name)
            }
            CanisterMessage::Response(_) => write!(f, "Response"),
        }
    }
}

impl From<RequestOrResponse> for CanisterMessage {
    fn from(msg: RequestOrResponse) -> Self {
        match msg {
            RequestOrResponse::Request(request) => CanisterMessage::Request(request),
            RequestOrResponse::Response(response) => CanisterMessage::Response(response),
        }
    }
}

/// A wrapper around a canister request and an ingress message.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CanisterCall {
    Request(Arc<Request>),
    Ingress(Arc<Ingress>),
}

impl CanisterCall {
    pub fn sender(&self) -> &PrincipalId {
        match self {
            CanisterCall::Request(msg) => msg.sender.as_ref(),
            CanisterCall::Ingress(msg) => msg.source.as_ref(),
        }
    }

    pub fn method_payload(&self) -> &[u8] {
        match self {
            CanisterCall::Request(msg) => msg.method_payload.as_slice(),
            CanisterCall::Ingress(msg) => msg.method_payload.as_slice(),
        }
    }

    pub fn method_name(&self) -> &str {
        match self {
            CanisterCall::Request(request) => request.method_name.as_str(),
            CanisterCall::Ingress(ingress) => ingress.method_name.as_str(),
        }
    }

    /// Returns the cycles received with this message.
    pub fn cycles(&self) -> Cycles {
        match self {
            CanisterCall::Request(request) => request.payment,
            CanisterCall::Ingress(_) => Cycles::zero(),
        }
    }

    /// Deducts the specified fee from the payment of this message.
    pub fn deduct_cycles(&mut self, fee: Cycles) {
        match self {
            CanisterCall::Request(request) => Arc::make_mut(request).payment -= fee,
            CanisterCall::Ingress(_) => {} // Ingress messages don't have payments
        }
    }

    /// Extracts the cycles received with this message.
    pub fn take_cycles(&mut self) -> Cycles {
        match self {
            CanisterCall::Request(request) => Arc::make_mut(request).payment.take(),
            CanisterCall::Ingress(_) => Cycles::zero(),
        }
    }

    pub fn canister_change_origin(&self, canister_version: Option<u64>) -> CanisterChangeOrigin {
        match self {
            CanisterCall::Ingress(msg) => CanisterChangeOrigin::from_user(msg.source.get()),
            CanisterCall::Request(msg) => {
                CanisterChangeOrigin::from_canister(msg.sender.into(), canister_version)
            }
        }
    }

    /// Returns the deadline of canister requests, `NO_DEADLINE` for ingress
    /// messages.
    pub fn deadline(&self) -> CoarseTime {
        match self {
            CanisterCall::Request(request) => request.deadline,
            CanisterCall::Ingress(_) => NO_DEADLINE,
        }
    }
}

impl TryFrom<CanisterMessage> for CanisterCall {
    type Error = ();

    fn try_from(msg: CanisterMessage) -> Result<Self, Self::Error> {
        match msg {
            CanisterMessage::Request(msg) => Ok(CanisterCall::Request(msg)),
            CanisterMessage::Ingress(msg) => Ok(CanisterCall::Ingress(msg)),
            CanisterMessage::Response(_) => Err(()),
        }
    }
}

/// A canister task can be thought of as a special system message that the IC
/// sends to the canister to execute its heartbeat or the global timer method.
#[derive(Clone, Eq, PartialEq, Hash, Debug, EnumIter)]
pub enum CanisterTask {
    Heartbeat = 1,
    GlobalTimer = 2,
    OnLowWasmMemory = 3,
}

impl From<CanisterTask> for SystemMethod {
    fn from(task: CanisterTask) -> Self {
        match task {
            CanisterTask::Heartbeat => SystemMethod::CanisterHeartbeat,
            CanisterTask::GlobalTimer => SystemMethod::CanisterGlobalTimer,
            CanisterTask::OnLowWasmMemory => SystemMethod::CanisterOnLowWasmMemory,
        }
    }
}

impl Display for CanisterTask {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Heartbeat => write!(f, "Heartbeat task"),
            Self::GlobalTimer => write!(f, "Global timer task"),
            Self::OnLowWasmMemory => write!(f, "On low Wasm memory task"),
        }
    }
}

impl From<&CanisterTask> for pb::execution_task::CanisterTask {
    fn from(task: &CanisterTask) -> Self {
        match task {
            CanisterTask::Heartbeat => pb::execution_task::CanisterTask::Heartbeat,
            CanisterTask::GlobalTimer => pb::execution_task::CanisterTask::Timer,
            CanisterTask::OnLowWasmMemory => pb::execution_task::CanisterTask::OnLowWasmMemory,
        }
    }
}

impl TryFrom<pb::execution_task::CanisterTask> for CanisterTask {
    type Error = ProxyDecodeError;

    fn try_from(task: pb::execution_task::CanisterTask) -> Result<Self, Self::Error> {
        match task {
            pb::execution_task::CanisterTask::Unspecified => {
                Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "CanisterTask",
                    err: format!("Unknown value for canister task {task:?}"),
                })
            }
            pb::execution_task::CanisterTask::Heartbeat => Ok(CanisterTask::Heartbeat),
            pb::execution_task::CanisterTask::Timer => Ok(CanisterTask::GlobalTimer),
            pb::execution_task::CanisterTask::OnLowWasmMemory => Ok(CanisterTask::OnLowWasmMemory),
        }
    }
}

/// A wrapper around canister messages and tasks.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CanisterMessageOrTask {
    Message(CanisterMessage),
    Task(CanisterTask),
}

impl Display for CanisterMessageOrTask {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => std::fmt::Display::fmt(msg, f),
            Self::Task(task) => std::fmt::Display::fmt(task, f),
        }
    }
}

/// A wrapper around canister calls and tasks that are executed in
/// replicated mode.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CanisterCallOrTask {
    Update(CanisterCall),
    Query(CanisterCall),
    Task(CanisterTask),
}

impl CanisterCallOrTask {
    pub fn cycles(&self) -> Cycles {
        match self {
            CanisterCallOrTask::Update(msg) | CanisterCallOrTask::Query(msg) => msg.cycles(),
            CanisterCallOrTask::Task(_) => Cycles::zero(),
        }
    }

    pub fn caller(&self) -> Option<PrincipalId> {
        match self {
            CanisterCallOrTask::Update(msg) | CanisterCallOrTask::Query(msg) => Some(*msg.sender()),
            CanisterCallOrTask::Task(_) => None,
        }
    }

    /// Returns the deadline of canister requests, `NO_DEADLINE` for ingress
    /// messages and tasks.
    pub fn deadline(&self) -> CoarseTime {
        match self {
            CanisterCallOrTask::Update(msg) | CanisterCallOrTask::Query(msg) => msg.deadline(),
            CanisterCallOrTask::Task(_) => NO_DEADLINE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exhaustive::ExhaustiveSet;
    use crate::{Time, time::expiry_time_from_now};
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use maplit::btreemap;
    use serde_cbor::Value;
    use std::{convert::TryFrom, io::Cursor};
    use strum::IntoEnumIterator;

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
            "long_debug: {long_debug}"
        );
        assert!(long_debug.ends_with("63}"), "long_debug: {long_debug}"); // 99 = 16*6 + 3
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
            "long_str: {long_str}"
        );
        // The last printed byte is 39, which is 16*2 + 7
        assert!(long_str.ends_with("27…}"), "long_str: {long_str}");
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
        let expiry_time = expiry_time_from_now();
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
        let expiry_time = expiry_time_from_now();
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
        let expiry_time = expiry_time_from_now();
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
        let expiry_time = expiry_time_from_now();
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
        assert_matches!(signed_ingress1, Ok(signed_ingress1) if signed_ingress == signed_ingress1);
    }

    #[test]
    fn serialize_request_via_bincode() {
        let request = Request {
            receiver: CanisterId::from(13),
            sender: CanisterId::from(17),
            sender_reply_callback: CallbackId::from(100),
            payment: Cycles::from(100_000_000_u128),
            method_name: "method".into(),
            method_payload: vec![0_u8, 1_u8, 2_u8, 3_u8, 4_u8, 5_u8],
            metadata: RequestMetadata::new(13, Time::from_nanos_since_unix_epoch(17)),
            deadline: CoarseTime::from_secs_since_unix_epoch(169),
        };
        let bytes = bincode::serialize(&request).unwrap();
        let request1 = bincode::deserialize::<Request>(&bytes);
        assert_matches!(request1, Ok(request1) if request == request1);
    }

    #[test]
    fn serialize_response_via_bincode() {
        let response = Response {
            originator: CanisterId::from(13),
            respondent: CanisterId::from(17),
            originator_reply_callback: CallbackId::from(100),
            refund: Cycles::from(100_000_000_u128),
            response_payload: Payload::Data(vec![0_u8, 1_u8, 2_u8, 3_u8, 4_u8, 5_u8]),
            deadline: CoarseTime::from_secs_since_unix_epoch(169),
        };
        let bytes = bincode::serialize(&response).unwrap();
        let response1 = bincode::deserialize::<Response>(&bytes);
        assert_matches!(response1, Ok(response1) if response == response1);
    }

    #[test]
    /// Allowing bincode::deserialize_from here since
    /// 1. It's only being used in a test
    /// 2. The deserialized_from is used on data that has just been serialized before the method.
    #[allow(clippy::disallowed_methods)]
    fn serialize_via_bincode_without_signature() {
        let expiry_time = expiry_time_from_now();
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

    #[test]
    fn canister_task_proto_round_trip() {
        for initial in CanisterTask::iter() {
            let encoded = pb::execution_task::CanisterTask::from(&initial);
            let round_trip = CanisterTask::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_canister_task() {
        // If this fails, you are making a potentially incompatible change to `CanisterTask`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            CanisterTask::iter().map(|x| x as i32).collect::<Vec<i32>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn stop_canister_context_proto_round_trip() {
        for initial in StopCanisterContext::exhaustive_set(&mut reproducible_rng()) {
            let encoded = pb::StopCanisterContext::from(&initial);
            let round_trip = StopCanisterContext::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }
}
