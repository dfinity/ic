use crate::{
    ingress::WasmResult, time::CoarseTime, CanisterId, CountBytes, Cycles, Funds, NumBytes, Time,
};
use ic_error_types::{RejectCode, UserError};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInfoRequest, ClearChunkStoreArgs, DeleteCanisterSnapshotArgs,
    InstallChunkedCodeArgs, InstallCodeArgsV2, ListCanisterSnapshotArgs, LoadCanisterSnapshotArgs,
    Method, Payload as _, ProvisionalTopUpCanisterArgs, StoredChunksArgs, TakeCanisterSnapshotArgs,
    UpdateSettingsArgs, UploadChunkArgs,
};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use ic_utils::{byte_slice_fmt::truncate_and_format, str::StrEllipsize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{
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

impl RequestMetadata {
    pub fn new(call_tree_depth: u64, call_tree_start_time: Time) -> Self {
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
    pub metadata: Option<RequestMetadata>,
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
            Ok(Method::CreateCanister)
            | Ok(Method::SetupInitialDKG)
            | Ok(Method::HttpRequest)
            | Ok(Method::RawRand)
            | Ok(Method::ECDSAPublicKey)
            | Ok(Method::SignWithECDSA)
            | Ok(Method::ComputeInitialIDkgDealings)
            | Ok(Method::SchnorrPublicKey)
            | Ok(Method::SignWithSchnorr)
            | Ok(Method::BitcoinGetBalance)
            | Ok(Method::BitcoinGetUtxos)
            | Ok(Method::BitcoinGetBlockHeaders)
            | Ok(Method::BitcoinSendTransaction)
            | Ok(Method::BitcoinSendTransactionInternal)
            | Ok(Method::BitcoinGetSuccessors)
            | Ok(Method::BitcoinGetCurrentFeePercentiles)
            | Ok(Method::NodeMetricsHistory) => {
                // No effective canister id.
                None
            }
            // `FetchCanisterLogs` method is only allowed for messages sent by
            // end users in non-replicated mode, so we should never reach this point.
            // If we do, we return `None` (which should be no-op) to avoid panicking.
            Ok(Method::FetchCanisterLogs) => None,
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
    /// Returns the size of this `Payload` in bytes.
    fn size_bytes(&self) -> NumBytes {
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
}

/// Custom hash implementation, ensuring consistency with previous version
/// without a `deadline`.
///
/// This is a temporary workaround for Consensus integrity checks relying on
/// hasning Rust structs. This can be dropped once those checks are removed.
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
            (RequestOrResponse::Request(ref l), RequestOrResponse::Request(ref r)) => {
                l.validate_eq(r)
            }
            (RequestOrResponse::Response(ref l), RequestOrResponse::Response(ref r)) => {
                l.validate_eq(r)
            }
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

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Request(self).count_bytes()`, so we don't need to wrap
/// `self` into a `RequestOrResponse` only to calculate its estimated byte size.
impl CountBytes for Request {
    fn count_bytes(&self) -> usize {
        size_of::<RequestOrResponse>()
            + size_of::<Request>()
            + self.payload_size_bytes().get() as usize
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Response(self).count_bytes()`, so we don't need to wrap
/// `self` into a `RequestOrResponse` only to calculate its estimated byte size.
impl CountBytes for Response {
    fn count_bytes(&self) -> usize {
        size_of::<RequestOrResponse>()
            + size_of::<Response>()
            + self.payload_size_bytes().get() as usize
    }
}

impl CountBytes for RequestOrResponse {
    fn count_bytes(&self) -> usize {
        match self {
            RequestOrResponse::Request(req) => req.count_bytes(),
            RequestOrResponse::Response(resp) => resp.count_bytes(),
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

impl From<&RequestMetadata> for pb_queues::RequestMetadata {
    fn from(metadata: &RequestMetadata) -> Self {
        Self {
            call_tree_depth: Some(metadata.call_tree_depth),
            call_tree_start_time_nanos: Some(
                metadata.call_tree_start_time.as_nanos_since_unix_epoch(),
            ),
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
            payment: Some((&Funds::new(req.payment)).into()),
            method_name: req.method_name.clone(),
            method_payload: req.method_payload.clone(),
            cycles_payment: Some((req.payment).into()),
            metadata: req.metadata.as_ref().map(From::from),
            deadline_seconds: req.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl From<pb_queues::RequestMetadata> for RequestMetadata {
    fn from(metadata: pb_queues::RequestMetadata) -> Self {
        Self {
            call_tree_depth: metadata.call_tree_depth.unwrap_or(0),
            call_tree_start_time: Time::from_nanos_since_unix_epoch(
                metadata.call_tree_start_time_nanos.unwrap_or(0),
            ),
        }
    }
}

impl TryFrom<pb_queues::Request> for Request {
    type Error = ProxyDecodeError;

    fn try_from(req: pb_queues::Request) -> Result<Self, Self::Error> {
        // To maintain backwards compatibility we fall back to reading from `payment` if
        // `cycles_payment` is not set.
        let payment = match try_from_option_field(req.cycles_payment, "Request::cycles_payment") {
            Ok(res) => res,
            Err(_) => try_from_option_field::<_, Funds, _>(req.payment, "Request::payment")
                .map(|mut res| res.take_cycles())?,
        };

        Ok(Self {
            receiver: try_from_option_field(req.receiver, "Request::receiver")?,
            sender: try_from_option_field(req.sender, "Request::sender")?,
            sender_reply_callback: req.sender_reply_callback.into(),
            payment,
            method_name: req.method_name,
            method_payload: req.method_payload,
            metadata: req.metadata.map(From::from),
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
            refund: Some((&Funds::new(rep.refund)).into()),
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
        // To maintain backwards compatibility we fall back to reading from `refund` if
        // `cycles_refund` is not set.
        let refund = match try_from_option_field(rep.cycles_refund, "Response::cycles_refund") {
            Ok(res) => res,
            Err(_) => try_from_option_field::<_, Funds, _>(rep.refund, "Response::refund")
                .map(|mut res| res.take_cycles())?,
        };

        Ok(Self {
            originator: try_from_option_field(rep.originator, "Response::originator")?,
            respondent: try_from_option_field(rep.respondent, "Response::respondent")?,
            originator_reply_callback: rep.originator_reply_callback.into(),
            refund,
            response_payload: try_from_option_field(
                rep.response_payload,
                "Response::response_payload",
            )?,
            deadline: CoarseTime::from_secs_since_unix_epoch(rep.deadline_seconds),
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
