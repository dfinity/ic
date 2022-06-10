//! Messages used in various components.
use ic_types::{
    messages::{Ingress, Request, Response, StopCanisterContext},
    Cycles, PrincipalId,
};
use std::{convert::TryFrom, sync::Arc};

use std::fmt::{self, Debug, Display, Formatter};

/// A wrapper around ingress messages and canister requests/responses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CanisterInputMessage {
    Response(Arc<Response>),
    Request(Arc<Request>),
    Ingress(Arc<Ingress>),
}

impl Display for CanisterInputMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CanisterInputMessage::Ingress(ingress) => {
                write!(f, "Ingress, method name {},", ingress.method_name)
            }
            CanisterInputMessage::Request(request) => {
                write!(f, "Request, method name {},", request.method_name)
            }
            CanisterInputMessage::Response(_) => write!(f, "Response"),
        }
    }
}

/// A wrapper around a canister request and an ingress message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestOrIngress {
    Request(Arc<Request>),
    Ingress(Arc<Ingress>),
}

impl RequestOrIngress {
    pub fn sender(&self) -> &PrincipalId {
        match self {
            RequestOrIngress::Request(msg) => msg.sender.as_ref(),
            RequestOrIngress::Ingress(msg) => msg.source.as_ref(),
        }
    }

    pub fn method_payload(&self) -> &[u8] {
        match self {
            RequestOrIngress::Request(msg) => msg.method_payload.as_slice(),
            RequestOrIngress::Ingress(msg) => msg.method_payload.as_slice(),
        }
    }

    pub fn method_name(&self) -> &str {
        match self {
            RequestOrIngress::Request(request) => request.method_name.as_str(),
            RequestOrIngress::Ingress(ingress) => ingress.method_name.as_str(),
        }
    }

    /// Extracts the cycles received with this message.
    pub fn take_cycles(&mut self) -> Cycles {
        match self {
            RequestOrIngress::Request(request) => Arc::make_mut(request).payment.take(),
            RequestOrIngress::Ingress(_) => Cycles::zero(),
        }
    }
}

impl From<RequestOrIngress> for StopCanisterContext {
    fn from(msg: RequestOrIngress) -> Self {
        assert_eq!(msg.method_name(), "stop_canister", "Converting a RequestOrIngress into StopCanisterContext should only happen with stop_canister requests.");
        match msg {
            RequestOrIngress::Request(mut req) => StopCanisterContext::Canister {
                sender: req.sender,
                reply_callback: req.sender_reply_callback,
                cycles: Arc::make_mut(&mut req).payment.take(),
            },
            RequestOrIngress::Ingress(ingress) => StopCanisterContext::Ingress {
                sender: ingress.source,
                message_id: ingress.message_id.clone(),
            },
        }
    }
}

impl TryFrom<CanisterInputMessage> for RequestOrIngress {
    type Error = ();

    fn try_from(msg: CanisterInputMessage) -> Result<Self, Self::Error> {
        match msg {
            CanisterInputMessage::Request(msg) => Ok(RequestOrIngress::Request(msg)),
            CanisterInputMessage::Ingress(msg) => Ok(RequestOrIngress::Ingress(msg)),
            CanisterInputMessage::Response(_) => Err(()),
        }
    }
}
