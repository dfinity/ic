use crate::{ingress::WasmResult, CanisterId, CountBytes, Cycles, Funds, NumBytes};
use ic_error_types::{RejectCode, TryFromError, UserError};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use ic_utils::{byte_slice_fmt::truncate_and_format, str::StrTruncate};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom, TryInto},
    mem::size_of,
};

pub struct CallbackIdTag;
/// A value used as an opaque nonce to couple outgoing calls with their
/// callbacks.
pub type CallbackId = Id<CallbackIdTag, u64>;

pub enum CallContextIdTag {}
/// Identifies an incoming call.
pub type CallContextId = Id<CallContextIdTag, u64>;

/// Canister-to-canister request message.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Request {
    pub receiver: CanisterId,
    pub sender: CanisterId,
    pub sender_reply_callback: CallbackId,
    pub payment: Cycles,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Vec<u8>,
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
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ receiver: {:?}, ", self.receiver)?;
        write!(f, "sender: {:?}, ", self.sender)?;
        write!(
            f,
            "sender_reply_callback: {:?}, ",
            self.sender_reply_callback
        )?;
        write!(f, "payment: {:?}, ", self.payment)?;
        if self.method_name.len() <= 103 {
            write!(f, "method_name: {:?}, ", self.method_name)?;
        } else {
            write!(
                f,
                "method_name: {:?}..., ",
                self.method_name.safe_truncate(100)
            )?;
        }
        write!(
            f,
            "method_payload: [{}] }}",
            truncate_and_format(&self.method_payload, 1024)
        )?;
        Ok(())
    }
}

/// The context attached when an inter-canister message is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RejectContext {
    pub code: RejectCode,
    pub message: String,
}

impl RejectContext {
    pub fn new(code: RejectCode, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> RejectCode {
        self.code
    }

    pub fn message(&self) -> String {
        self.message.clone()
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
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
                write!(f, "Reject({{ ")?;
                write!(f, "code: {:?}, ", context.code)?;
                if context.message.len() <= 8 * KB {
                    write!(f, "message: {:?} ", context.message)?;
                } else {
                    let mut message = String::with_capacity(8 * KB);
                    message.push_str(context.message.safe_truncate(5 * KB));
                    message.push_str("...");
                    message.push_str(context.message.safe_truncate_right(2 * KB));
                    write!(f, "message: {:?} ", message)?;
                }
                write!(f, "}})")
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

/// Canister-to-canister response message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Response {
    pub originator: CanisterId,
    pub respondent: CanisterId,
    pub originator_reply_callback: CallbackId,
    pub refund: Cycles,
    pub response_payload: Payload,
}

impl Response {
    /// Returns the size in bytes of this `Response`'s payload.
    pub fn payload_size_bytes(&self) -> NumBytes {
        self.response_payload.size_bytes()
    }
}

/// Canister-to-canister message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestOrResponse {
    Request(Request),
    Response(Response),
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
            RequestOrResponse::Response(resp) => resp.response_payload.size_bytes(),
        }
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Request(self).count_bytes()`, so we don't need to wrap
/// `self` into a `RequestOrResponse` only to calculate its estimated byte size.
impl CountBytes for Request {
    fn count_bytes(&self) -> usize {
        size_of::<RequestOrResponse>() + self.method_name.len() + self.method_payload.len()
    }
}

/// Convenience `CountBytes` implementation that returns the same value as
/// `RequestOrResponse::Response(self).count_bytes()`, so we don't need to wrap
/// `self` into a `RequestOrResponse` only to calculate its estimated byte size.
impl CountBytes for Response {
    fn count_bytes(&self) -> usize {
        let var_fields_size = match &self.response_payload {
            Payload::Data(data) => data.len(),
            Payload::Reject(context) => context.message.len(),
        };
        size_of::<RequestOrResponse>() + var_fields_size
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
        RequestOrResponse::Request(req)
    }
}

impl From<Response> for RequestOrResponse {
    fn from(resp: Response) -> Self {
        RequestOrResponse::Response(resp)
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
        })
    }
}

impl From<&RejectContext> for pb_queues::RejectContext {
    fn from(rc: &RejectContext) -> Self {
        Self {
            reject_code: rc.code as u64,
            reject_message: rc.message(),
        }
    }
}

impl TryFrom<pb_queues::RejectContext> for RejectContext {
    type Error = ProxyDecodeError;

    fn try_from(rc: pb_queues::RejectContext) -> Result<Self, Self::Error> {
        Ok(RejectContext {
            code: rc.reject_code.try_into().map_err(|err| match err {
                TryFromError::ValueOutOfRange(code) => ProxyDecodeError::ValueOutOfRange {
                    typ: "RejectContext",
                    err: code.to_string(),
                },
            })?,
            message: rc.reject_message,
        })
    }
}

impl From<&Response> for pb_queues::Response {
    fn from(rep: &Response) -> Self {
        let p = match &rep.response_payload {
            Payload::Data(d) => pb_queues::response::ResponsePayload::Data(d.clone()),
            Payload::Reject(r) => pb_queues::response::ResponsePayload::Reject(r.into()),
        };
        Self {
            originator: Some(pb_types::CanisterId::from(rep.originator)),
            respondent: Some(pb_types::CanisterId::from(rep.respondent)),
            originator_reply_callback: rep.originator_reply_callback.get(),
            refund: Some((&Funds::new(rep.refund)).into()),
            response_payload: Some(p),
            cycles_refund: Some((rep.refund).into()),
        }
    }
}

impl TryFrom<pb_queues::Response> for Response {
    type Error = ProxyDecodeError;

    fn try_from(rep: pb_queues::Response) -> Result<Self, Self::Error> {
        let response_payload = match rep
            .response_payload
            .ok_or(ProxyDecodeError::MissingField("Response::response_payload"))?
        {
            pb_queues::response::ResponsePayload::Data(d) => Payload::Data(d),
            pb_queues::response::ResponsePayload::Reject(r) => Payload::Reject(r.try_into()?),
        };

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
            response_payload,
        })
    }
}

impl From<&RequestOrResponse> for pb_queues::RequestOrResponse {
    fn from(rr: &RequestOrResponse) -> Self {
        match rr {
            RequestOrResponse::Request(req) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Request(req.into())),
            },
            RequestOrResponse::Response(rep) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Response(rep.into())),
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
                Ok(RequestOrResponse::Request(r.try_into()?))
            }
            pb_queues::request_or_response::R::Response(r) => {
                Ok(RequestOrResponse::Response(r.try_into()?))
            }
        }
    }
}
