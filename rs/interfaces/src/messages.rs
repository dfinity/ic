//! Messages used in various components.
use ic_types::{
    messages::{Ingress, Request, Response, StopCanisterContext},
    CanisterId, Cycles, PrincipalId,
};
use std::{convert::TryFrom, sync::Arc};

use std::fmt::{self, Debug, Display, Formatter};

/// A wrapper around ingress messages and canister requests/responses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

/// A wrapper around a canister request and an ingress message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Extracts the cycles received with this message.
    pub fn take_cycles(&mut self) -> Cycles {
        match self {
            CanisterCall::Request(request) => Arc::make_mut(request).payment.take(),
            CanisterCall::Ingress(_) => Cycles::zero(),
        }
    }
}

impl From<CanisterCall> for StopCanisterContext {
    fn from(msg: CanisterCall) -> Self {
        assert_eq!(msg.method_name(), "stop_canister", "Converting a RequestOrIngress into StopCanisterContext should only happen with stop_canister requests.");
        match msg {
            CanisterCall::Request(mut req) => StopCanisterContext::Canister {
                sender: req.sender,
                reply_callback: req.sender_reply_callback,
                cycles: Arc::make_mut(&mut req).payment.take(),
            },
            CanisterCall::Ingress(ingress) => StopCanisterContext::Ingress {
                sender: ingress.source,
                message_id: ingress.message_id.clone(),
            },
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
