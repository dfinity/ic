use crate::{
    CanisterId, CountBytes, Cycles, Funds, NumBytes, Time,
    ingress::WasmResult,
    time::{CoarseTime, UNIX_EPOCH},
};
use ic_error_types::{RejectCode, UserError};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInfoRequest, CanisterMetadataRequest, ClearChunkStoreArgs,
    DeleteCanisterSnapshotArgs, FetchCanisterLogsRequest, InstallChunkedCodeArgs,
    InstallCodeArgsV2, ListCanisterSnapshotArgs, LoadCanisterSnapshotArgs, Method, Payload as _,
    ProvisionalTopUpCanisterArgs, ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs,
    RenameCanisterArgs, StoredChunksArgs, TakeCanisterSnapshotArgs, UpdateSettingsArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
};
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use ic_utils::{byte_slice_fmt::truncate_and_format, str::StrEllipsize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    convert::{From, TryFrom, TryInto},
    hash::{Hash, Hasher},
    mem::size_of,
    str::FromStr,
    sync::Arc,
};

#[cfg(test)]
mod tests;

/// Special value for the `deadline` field of `Requests`, `Callbacks`,
/// `CallOrigins` and `Responses` signifying "no deadline", i.e. a guaranteed
/// response call.
pub const NO_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(0);

pub struct CallbackIdTag;
/// A value used as an opaque nonce to couple outgoing calls with their
/// callbacks.
pub type CallbackId = Id<CallbackIdTag, u64>;

impl CountBytes for CallbackId {
    fn count_bytes(&self) -> usize {
        size_of::<CallbackId>()
    }
}

pub enum CallContextIdTag {}
/// Identifies an incoming call.
pub type CallContextId = Id<CallContextIdTag, u64>;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RequestMetadata {
    /// Indicates how many steps down the call tree a request is, starting at 0.
    call_tree_depth: u64,
    /// The block time (on the respective subnet) at the start of the call at the
    /// root of the call tree that this request is part of.
    call_tree_start_time: Time,
}

impl Default for RequestMetadata {
    fn default() -> Self {
        Self::new(0, UNIX_EPOCH)
    }
}

impl RequestMetadata {
    pub const fn new(call_tree_depth: u64, call_tree_start_time: Time) -> Self {
        Self {
            call_tree_depth,
            call_tree_start_time,
        }
    }

    /// Creates `RequestMetadata` for a new call tree, i.e. with a given start time and depth 0.
    pub fn for_new_call_tree(time: Time) -> Self {
        Self::new(0, time)
    }

    /// Creates `RequestMetadata` for a downstream call from another metadata, i.e. with depth
    /// increased by 1 and the same `call_tree_start_time`.
    pub fn for_downstream_call(&self) -> Self {
        Self::new(self.call_tree_depth + 1, self.call_tree_start_time)
    }

    pub fn call_tree_depth(&self) -> &u64 {
        &self.call_tree_depth
    }

    pub fn call_tree_start_time(&self) -> &Time {
        &self.call_tree_start_time
    }
}

/// Canister-to-canister request message.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize, ValidateEq)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Request {
    pub receiver: CanisterId,
    pub sender: CanisterId,
    pub sender_reply_callback: CallbackId,
    pub payment: Cycles,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    #[validate_eq(Ignore)]
    pub method_payload: Vec<u8>,
    pub metadata: RequestMetadata,
    /// If non-zero, this is a best-effort call.
    pub deadline: CoarseTime,
}

impl Request {
    /// Returns the sender of this `Request`.
    pub fn sender(&self) -> CanisterId {
        self.sender
    }

    /// Takes the payment out of this `Request`.
    pub fn take_cycles(&mut self) -> Cycles {
        self.payment.take()
    }

    /// Returns this `Request`s payload.
    pub fn method_payload(&self) -> &[u8] {
        &self.method_payload
    }

    /// Returns the size of the user-controlled part of this `Request`,
    /// in bytes.
    pub fn payload_size_bytes(&self) -> NumBytes {
        let bytes = self.method_name.len() + self.method_payload.len();
        NumBytes::from(bytes as u64)
    }

    /// Returns `true` if this is the request of a best-effort call
    /// (i.e. if it has a non-zero deadline).
    pub fn is_best_effort(&self) -> bool {
        self.deadline != NO_DEADLINE
    }

    /// Helper function to extract the effective canister id from the payload.
    pub fn extract_effective_canister_id(&self) -> Option<CanisterId> {
        match Method::from_str(&self.method_name) {
            Ok(Method::ProvisionalCreateCanisterWithCycles) => None,
            Ok(Method::StartCanister)
            | Ok(Method::CanisterStatus)
            | Ok(Method::DeleteCanister)
            | Ok(Method::UninstallCode)
            | Ok(Method::DepositCycles)
            | Ok(Method::StopCanister) => match CanisterIdRecord::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::CanisterInfo) => match CanisterInfoRequest::decode(&self.method_payload) {
                Ok(record) => Some(record.canister_id()),
                Err(_) => None,
            },
            Ok(Method::CanisterMetadata) => {
                match CanisterMetadataRequest::decode(&self.method_payload) {
                    Ok(record) => Some(record.canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::UpdateSettings) => match UpdateSettingsArgs::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::InstallCode) => match InstallCodeArgsV2::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::InstallChunkedCode) => {
                match InstallChunkedCodeArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.target_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::ProvisionalTopUpCanister) => {
                match ProvisionalTopUpCanisterArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::UploadChunk) => match UploadChunkArgs::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::ClearChunkStore) => {
                match ClearChunkStoreArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::StoredChunks) => match StoredChunksArgs::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::TakeCanisterSnapshot) => {
                match TakeCanisterSnapshotArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::LoadCanisterSnapshot) => {
                match LoadCanisterSnapshotArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::ListCanisterSnapshots) => {
                match ListCanisterSnapshotArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::DeleteCanisterSnapshot) => {
                match DeleteCanisterSnapshotArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::ReadCanisterSnapshotMetadata) => {
                match ReadCanisterSnapshotMetadataArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::ReadCanisterSnapshotData) => {
                match ReadCanisterSnapshotDataArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::UploadCanisterSnapshotMetadata) => {
                match UploadCanisterSnapshotMetadataArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::UploadCanisterSnapshotData) => {
                match UploadCanisterSnapshotDataArgs::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Ok(Method::RenameCanister) => match RenameCanisterArgs::decode(&self.method_payload) {
                Ok(record) => Some(record.get_canister_id()),
                Err(_) => None,
            },
            Ok(Method::CreateCanister)
            | Ok(Method::SetupInitialDKG)
            | Ok(Method::HttpRequest)
            | Ok(Method::RawRand)
            | Ok(Method::ECDSAPublicKey)
            | Ok(Method::SignWithECDSA)
            | Ok(Method::ReshareChainKey)
            | Ok(Method::SchnorrPublicKey)
            | Ok(Method::SignWithSchnorr)
            | Ok(Method::VetKdPublicKey)
            | Ok(Method::VetKdDeriveKey)
            | Ok(Method::BitcoinGetBalance)
            | Ok(Method::BitcoinGetUtxos)
            | Ok(Method::BitcoinGetBlockHeaders)
            | Ok(Method::BitcoinSendTransaction)
            | Ok(Method::BitcoinSendTransactionInternal)
            | Ok(Method::BitcoinGetSuccessors)
            | Ok(Method::BitcoinGetCurrentFeePercentiles)
            | Ok(Method::NodeMetricsHistory)
            | Ok(Method::SubnetInfo) => {
                // No effective canister id.
                None
            }
            Ok(Method::FetchCanisterLogs) => {
                match FetchCanisterLogsRequest::decode(&self.method_payload) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Request {
            receiver,
            sender,
            sender_reply_callback,
            payment,
            method_name,
            method_payload,
            metadata,
            deadline,
        } = self;
        f.debug_struct("Request")
            .field("receiver", receiver)
            .field("sender", sender)
            .field("sender_reply_callback", sender_reply_callback)
            .field("payment", payment)
            .field("method_name", &method_name.ellipsize(100, 75))
            .field("method_payload", &truncate_and_format(method_payload, 1024))
            .field("metadata", metadata)
            .field("deadline", deadline)
            .finish()
    }
}

/// The context attached when an inter-canister message is rejected.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RejectContext {
    code: RejectCode,
    message: String,
}

/// Minimum length limit that may be imposed on reject messages.
const MIN_REJECT_MESSAGE_LEN_LIMIT_BYTES: usize = 10;
/// Maximum allowed length for reject messages.
pub const MAX_REJECT_MESSAGE_LEN_BYTES: usize = 8 * 1024;

impl RejectContext {
    pub fn new(code: RejectCode, message: impl ToString) -> Self {
        Self::new_with_message_length_limit(code, message, MAX_REJECT_MESSAGE_LEN_BYTES)
    }

    pub fn new_with_message_length_limit(
        code: RejectCode,
        message: impl ToString,
        max_msg_len: usize,
    ) -> Self {
        Self {
            code,
            message: message.to_string().ellipsize(
                // Ensure `max_msg_len` is within reasonable bounds.
                max_msg_len.clamp(
                    MIN_REJECT_MESSAGE_LEN_LIMIT_BYTES,
                    MAX_REJECT_MESSAGE_LEN_BYTES,
                ),
                75,
            ),
        }
    }

    /// A constructor to be used only when decoding from the canonical
    /// representation, so we do not accidentally change the canonical
    /// representation of an already certified `RejectContext`.
    pub fn from_canonical(code: RejectCode, message: impl ToString) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    pub fn code(&self) -> RejectCode {
        self.code
    }

    pub fn message(&self) -> &String {
        &self.message
    }

    /// For use in tests.
    /// Assert that the rejection has the given code and containing the given string.
    pub fn assert_contains(&self, code: RejectCode, message: &str) {
        assert_eq!(self.code, code);
        assert!(
            self.message.contains(message),
            "Unable to match rejection message {} with expected {}",
            self.message,
            message
        );
    }

    /// Returns the size of this `RejectContext` in bytes.
    fn size_bytes(&self) -> NumBytes {
        let size = std::mem::size_of::<RejectCode>() + self.message.len();
        NumBytes::from(size as u64)
    }
}

impl From<UserError> for RejectContext {
    fn from(err: UserError) -> Self {
        Self {
            code: RejectCode::from(err.code()),
            message: err.description().to_string(),
        }
    }
}

/// A union of all possible message payloads.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum Payload {
    /// Opaque payload data of the current message.
    Data(Vec<u8>),
    /// Reject information of the current message (which can only be a
    /// response).
    Reject(RejectContext),
}

impl Payload {
    /// For use in tests.
    /// Assert that the payload is a rejection with the given code and
    /// containing the given string.
    pub fn assert_contains_reject(&self, code: RejectCode, message: &str) {
        match self {
            Self::Reject(err) => err.assert_contains(code, message),
            Self::Data(_) => panic!("Expected a rejection, but got a valid response."),
        }
    }

    /// Returns the size of this `Payload` in bytes.
    pub fn size_bytes(&self) -> NumBytes {
        match self {
            Payload::Data(data) => NumBytes::from(data.len() as u64),
            Payload::Reject(context) => context.size_bytes(),
        }
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(data) => {
                write!(f, "Data([")?;
                write!(f, "{}", truncate_and_format(data, 1024))?;
                write!(f, "])")
            }
            Self::Reject(context) => {
                const KB: usize = 1024;
                let RejectContext { code, message } = context;
                f.debug_struct("Reject")
                    .field("code", code)
                    .field("message", &message.ellipsize(8 * KB, 75))
                    .finish()
            }
        }
    }
}

impl From<Result<Option<WasmResult>, UserError>> for Payload {
    fn from(result: Result<Option<WasmResult>, UserError>) -> Self {
        match result {
            Ok(wasm_result) => match wasm_result {
                None => Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: "No response".to_string(),
                }),
                Some(WasmResult::Reply(payload)) => Payload::Data(payload),
                Some(WasmResult::Reject(reject_msg)) => Payload::Reject(RejectContext {
                    code: RejectCode::CanisterReject,
                    message: reject_msg,
                }),
            },
            Err(user_error) => Payload::Reject(RejectContext {
                code: user_error.reject_code(),
                message: user_error.to_string(),
            }),
        }
    }
}

impl From<&Payload> for pb_queues::response::ResponsePayload {
    fn from(value: &Payload) -> Self {
        match value {
            Payload::Data(d) => pb_queues::response::ResponsePayload::Data(d.clone()),
            Payload::Reject(r) => pb_queues::response::ResponsePayload::Reject(r.into()),
        }
    }
}

impl TryFrom<pb_queues::response::ResponsePayload> for Payload {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_queues::response::ResponsePayload) -> Result<Self, Self::Error> {
        match value {
            pb_queues::response::ResponsePayload::Data(d) => Ok(Payload::Data(d)),
            pb_queues::response::ResponsePayload::Reject(r) => Ok(Payload::Reject(r.try_into()?)),
        }
    }
}

/// Canister-to-canister response message.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, ValidateEq)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Response {
    pub originator: CanisterId,
    pub respondent: CanisterId,
    pub originator_reply_callback: CallbackId,
    pub refund: Cycles,
    #[validate_eq(Ignore)]
    pub response_payload: Payload,
    /// If non-zero, this is a best-effort call.
    pub deadline: CoarseTime,
}

impl Response {
    /// Returns the size in bytes of this `Response`'s payload.
    pub fn payload_size_bytes(&self) -> NumBytes {
        self.response_payload.size_bytes()
    }

    /// Returns `true` if this is the response of a best-effort call
    /// (i.e. if it has a non-zero deadline).
    pub fn is_best_effort(&self) -> bool {
        self.deadline != NO_DEADLINE
    }
}

/// Custom hash implementation, ensuring consistency with previous version
/// without a `deadline`.
///
/// This is a temporary workaround for Consensus integrity checks relying on
/// hashing Rust structs. This can be dropped once those checks are removed.
impl Hash for Response {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Response {
            originator,
            respondent,
            originator_reply_callback,
            refund,
            response_payload,
            deadline,
        } = self;

        originator.hash(state);
        respondent.hash(state);
        originator_reply_callback.hash(state);
        refund.hash(state);
        response_payload.hash(state);

        if *deadline != NO_DEADLINE {
            deadline.hash(state);
        }
    }
}

/// XNet message type (like `Request` and `Response`) for guaranteed delivery of
/// refunds for best-effort calls.
///
/// Represents an _anonymous refund_.
///
/// Refunds are ordered by amount (larger amounts first). Ties are broken by
/// canister ID (smaller IDs first).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, ValidateEq)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Refund {
    /// Whom this refund is to be delivered to.
    recipient: CanisterId,

    /// The amount of cycles being refunded. Non-zero for anonymous refunds.
    amount: Cycles,
}

impl Refund {
    /// Creates a new anonymous refund for the given recipient, in the given
    /// amount.
    pub fn anonymous(recipient: CanisterId, amount: Cycles) -> Self {
        debug_assert!(!amount.is_zero());
        Self { recipient, amount }
    }

    pub fn recipient(&self) -> CanisterId {
        self.recipient
    }

    pub fn amount(&self) -> Cycles {
        self.amount
    }
}

impl PartialOrd for Refund {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Refund {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Order by amount decreasing, then by recipient increasing.
        (Reverse(self.amount), &self.recipient).cmp(&(Reverse(other.amount), &other.recipient))
    }
}

/// Canister-to-canister message.
///
/// The underlying request / response is wrapped within an `Arc`, for cheap
/// cloning.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum RequestOrResponse {
    Request(Arc<Request>),
    Response(Arc<Response>),
}

impl ValidateEq for RequestOrResponse {
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        match (self, rhs) {
            (RequestOrResponse::Request(l), RequestOrResponse::Request(r)) => l.validate_eq(r),
            (RequestOrResponse::Response(l), RequestOrResponse::Response(r)) => l.validate_eq(r),
            _ => Err("RequestOrResponse enum mismatch".to_string()),
        }
    }
}

impl RequestOrResponse {
    pub fn receiver(&self) -> CanisterId {
        match self {
            RequestOrResponse::Request(req) => req.receiver,
            RequestOrResponse::Response(resp) => resp.originator,
        }
    }

    pub fn sender(&self) -> CanisterId {
        match self {
            RequestOrResponse::Request(req) => req.sender,
            RequestOrResponse::Response(resp) => resp.respondent,
        }
    }

    /// Returns the size of the user-controlled part of this message (payload,
    /// method name) in bytes.
    ///
    /// This is the "payload size" based on which cycle costs are calculated;
    /// and is (generally) limited to `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`.
    pub fn payload_size_bytes(&self) -> NumBytes {
        match self {
            RequestOrResponse::Request(req) => req.payload_size_bytes(),
            RequestOrResponse::Response(resp) => resp.payload_size_bytes(),
        }
    }

    /// Returns the amount of cycles contained in this message.
    pub fn cycles(&self) -> Cycles {
        match self {
            RequestOrResponse::Request(req) => req.payment,
            RequestOrResponse::Response(resp) => resp.refund,
        }
    }

    /// Returns the deadline of this message, `NO_DEADLINE` if not set.
    pub fn deadline(&self) -> CoarseTime {
        match self {
            RequestOrResponse::Request(req) => req.deadline,
            RequestOrResponse::Response(resp) => resp.deadline,
        }
    }

    /// Returns `true` if this is the request or response of a best-effort call
    /// (i.e. if it has a non-zero deadline).
    pub fn is_best_effort(&self) -> bool {
        self.deadline() != NO_DEADLINE
    }
}

/// XNet message: request, response or refund.
///
/// The underlying request / response / refund is wrapped within an `Arc`, for
/// cheap cloning.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum StreamMessage {
    Request(Arc<Request>),
    Response(Arc<Response>),
    Refund(Arc<Refund>),
}

impl ValidateEq for StreamMessage {
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        match (self, rhs) {
            (StreamMessage::Request(l), StreamMessage::Request(r)) => l.validate_eq(r),
            (StreamMessage::Response(l), StreamMessage::Response(r)) => l.validate_eq(r),
            (StreamMessage::Refund(l), StreamMessage::Refund(r)) => l.validate_eq(r),
            _ => Err("StreamMessage enum mismatch".to_string()),
        }
    }
}

impl StreamMessage {
    pub fn receiver(&self) -> CanisterId {
        match self {
            StreamMessage::Request(req) => req.receiver,
            StreamMessage::Response(resp) => resp.originator,
            StreamMessage::Refund(refund) => refund.recipient,
        }
    }

    /// Returns the amount of cycles contained in this message.
    pub fn cycles(&self) -> Cycles {
        match self {
            StreamMessage::Request(req) => req.payment,
            StreamMessage::Response(resp) => resp.refund,
            StreamMessage::Refund(refund) => refund.amount,
        }
    }

    /// Returns `true` iff this is a best-effort `Response`.
    pub fn is_best_effort_response(&self) -> bool {
        match self {
            StreamMessage::Response(resp) => resp.is_best_effort(),
            _ => false,
        }
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Request(self).count_bytes()` and
/// `StreamMessage::Request(self).count_bytes()` so we don't need to wrap
/// `self` only to calculate its estimated byte size.
impl CountBytes for Request {
    fn count_bytes(&self) -> usize {
        size_of::<RequestOrResponse>()
            + size_of::<Request>()
            + self.payload_size_bytes().get() as usize
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Response(self).count_bytes()` and
/// `StreamMessage::Response(self).count_bytes()`, so we don't need to wrap
/// `self` only to calculate its estimated byte size.
impl CountBytes for Response {
    fn count_bytes(&self) -> usize {
        size_of::<RequestOrResponse>()
            + size_of::<Response>()
            + self.payload_size_bytes().get() as usize
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `StreamMessage::Refund(self).count_bytes()`, so we don't need to wrap
/// `self` into a `StreamMessage` only to calculate its estimated byte size.
impl CountBytes for Refund {
    fn count_bytes(&self) -> usize {
        size_of::<StreamMessage>() + size_of::<Refund>()
    }
}

/// Ensure that `RequestOrResponse` and `StreamMessage` have the same size, so that
/// their respective `CountBytes` implementations are consistent.
const _: () = {
    assert!(size_of::<RequestOrResponse>() == size_of::<StreamMessage>());
};

impl CountBytes for RequestOrResponse {
    fn count_bytes(&self) -> usize {
        match self {
            RequestOrResponse::Request(req) => req.count_bytes(),
            RequestOrResponse::Response(resp) => resp.count_bytes(),
        }
    }
}

impl CountBytes for StreamMessage {
    fn count_bytes(&self) -> usize {
        match self {
            StreamMessage::Request(req) => req.count_bytes(),
            StreamMessage::Response(resp) => resp.count_bytes(),
            StreamMessage::Refund(refund) => refund.count_bytes(),
        }
    }
}

impl From<Request> for RequestOrResponse {
    fn from(req: Request) -> Self {
        RequestOrResponse::Request(Arc::new(req))
    }
}

impl From<Response> for RequestOrResponse {
    fn from(resp: Response) -> Self {
        RequestOrResponse::Response(Arc::new(resp))
    }
}

impl From<Request> for StreamMessage {
    fn from(req: Request) -> Self {
        StreamMessage::Request(Arc::new(req))
    }
}

impl From<Response> for StreamMessage {
    fn from(resp: Response) -> Self {
        StreamMessage::Response(Arc::new(resp))
    }
}

impl From<Refund> for StreamMessage {
    fn from(refund: Refund) -> Self {
        StreamMessage::Refund(Arc::new(refund))
    }
}

impl From<&RequestMetadata> for pb_queues::RequestMetadata {
    fn from(metadata: &RequestMetadata) -> Self {
        Self {
            call_tree_depth: metadata.call_tree_depth,
            call_tree_start_time_nanos: metadata.call_tree_start_time.as_nanos_since_unix_epoch(),
            call_subtree_deadline_nanos: None,
        }
    }
}

impl From<&Request> for pb_queues::Request {
    fn from(req: &Request) -> Self {
        Self {
            receiver: Some(pb_types::CanisterId::from(req.receiver)),
            sender: Some(pb_types::CanisterId::from(req.sender)),
            sender_reply_callback: req.sender_reply_callback.get(),
            method_name: req.method_name.clone(),
            method_payload: req.method_payload.clone(),
            cycles_payment: Some((req.payment).into()),
            metadata: Some((&req.metadata).into()),
            deadline_seconds: req.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl From<pb_queues::RequestMetadata> for RequestMetadata {
    fn from(metadata: pb_queues::RequestMetadata) -> Self {
        Self {
            call_tree_depth: metadata.call_tree_depth,
            call_tree_start_time: Time::from_nanos_since_unix_epoch(
                metadata.call_tree_start_time_nanos,
            ),
        }
    }
}

impl TryFrom<pb_queues::Request> for Request {
    type Error = ProxyDecodeError;

    fn try_from(req: pb_queues::Request) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver: try_from_option_field(req.receiver, "Request::receiver")?,
            sender: try_from_option_field(req.sender, "Request::sender")?,
            sender_reply_callback: req.sender_reply_callback.into(),
            payment: try_from_option_field(req.cycles_payment, "Request::cycles_payment"),
            method_name: req.method_name,
            method_payload: req.method_payload,
            metadata: req.metadata.map_or_else(Default::default, From::from),
            deadline: CoarseTime::from_secs_since_unix_epoch(req.deadline_seconds),
        })
    }
}

impl From<&RejectContext> for pb_queues::RejectContext {
    fn from(rc: &RejectContext) -> Self {
        Self {
            reject_message: rc.message.clone(),
            reject_code: pb_types::RejectCode::from(rc.code).into(),
        }
    }
}

impl TryFrom<pb_queues::RejectContext> for RejectContext {
    type Error = ProxyDecodeError;

    fn try_from(rc: pb_queues::RejectContext) -> Result<Self, Self::Error> {
        Ok(RejectContext {
            code: RejectCode::try_from(pb_types::RejectCode::try_from(rc.reject_code).map_err(
                |_| ProxyDecodeError::ValueOutOfRange {
                    typ: "RejectContext",
                    err: format!("Unexpected value for reject code {}", rc.reject_code),
                },
            )?)?,
            message: rc.reject_message,
        })
    }
}

impl From<&Response> for pb_queues::Response {
    fn from(rep: &Response) -> Self {
        Self {
            originator: Some(pb_types::CanisterId::from(rep.originator)),
            respondent: Some(pb_types::CanisterId::from(rep.respondent)),
            originator_reply_callback: rep.originator_reply_callback.get(),
            response_payload: Some(pb_queues::response::ResponsePayload::from(
                &rep.response_payload,
            )),
            cycles_refund: Some((rep.refund).into()),
            deadline_seconds: rep.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_queues::Response> for Response {
    type Error = ProxyDecodeError;

    fn try_from(rep: pb_queues::Response) -> Result<Self, Self::Error> {
        Ok(Self {
            originator: try_from_option_field(rep.originator, "Response::originator")?,
            respondent: try_from_option_field(rep.respondent, "Response::respondent")?,
            originator_reply_callback: rep.originator_reply_callback.into(),
            refund: try_from_option_field(rep.cycles_refund, "Response::cycles_refund")?,
            response_payload: try_from_option_field(
                rep.response_payload,
                "Response::response_payload",
            )?,
            deadline: CoarseTime::from_secs_since_unix_epoch(rep.deadline_seconds),
        })
    }
}

impl From<&Refund> for pb_queues::Refund {
    fn from(refund: &Refund) -> Self {
        Self {
            recipient: Some(pb_types::CanisterId::from(refund.recipient)),
            amount: Some((refund.amount).into()),
        }
    }
}

impl TryFrom<pb_queues::Refund> for Refund {
    type Error = ProxyDecodeError;

    fn try_from(refund: pb_queues::Refund) -> Result<Self, Self::Error> {
        Ok(Self {
            recipient: try_from_option_field(refund.recipient, "Refund::recipient")?,
            amount: try_from_option_field(refund.amount, "Refund::amount")?,
        })
    }
}

impl From<&RequestOrResponse> for pb_queues::RequestOrResponse {
    fn from(rr: &RequestOrResponse) -> Self {
        match rr {
            RequestOrResponse::Request(req) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Request(
                    req.as_ref().into(),
                )),
            },
            RequestOrResponse::Response(rep) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Response(
                    rep.as_ref().into(),
                )),
            },
        }
    }
}

impl TryFrom<pb_queues::RequestOrResponse> for RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(rr: pb_queues::RequestOrResponse) -> Result<Self, Self::Error> {
        match rr
            .r
            .ok_or(ProxyDecodeError::MissingField("RequestOrResponse::r"))?
        {
            pb_queues::request_or_response::R::Request(r) => {
                Ok(RequestOrResponse::Request(Arc::new(r.try_into()?)))
            }
            pb_queues::request_or_response::R::Response(r) => {
                Ok(RequestOrResponse::Response(Arc::new(r.try_into()?)))
            }
        }
    }
}

impl From<&StreamMessage> for pb_queues::StreamMessage {
    fn from(sm: &StreamMessage) -> Self {
        match sm {
            StreamMessage::Request(req) => pb_queues::StreamMessage {
                message: Some(pb_queues::stream_message::Message::Request(
                    req.as_ref().into(),
                )),
            },
            StreamMessage::Response(rep) => pb_queues::StreamMessage {
                message: Some(pb_queues::stream_message::Message::Response(
                    rep.as_ref().into(),
                )),
            },
            StreamMessage::Refund(refund) => pb_queues::StreamMessage {
                message: Some(pb_queues::stream_message::Message::Refund(
                    refund.as_ref().into(),
                )),
            },
        }
    }
}

impl TryFrom<pb_queues::StreamMessage> for StreamMessage {
    type Error = ProxyDecodeError;

    fn try_from(sm: pb_queues::StreamMessage) -> Result<Self, Self::Error> {
        match sm
            .message
            .ok_or(ProxyDecodeError::MissingField("StreamMessage::message"))?
        {
            pb_queues::stream_message::Message::Request(r) => {
                Ok(StreamMessage::Request(Arc::new(r.try_into()?)))
            }
            pb_queues::stream_message::Message::Response(r) => {
                Ok(StreamMessage::Response(Arc::new(r.try_into()?)))
            }
            pb_queues::stream_message::Message::Refund(r) => {
                Ok(StreamMessage::Refund(Arc::new(r.try_into()?)))
            }
        }
    }
}

impl From<RequestOrResponse> for StreamMessage {
    fn from(rr: RequestOrResponse) -> Self {
        match rr {
            RequestOrResponse::Request(req) => StreamMessage::Request(req),
            RequestOrResponse::Response(resp) => StreamMessage::Response(resp),
        }
    }
}
