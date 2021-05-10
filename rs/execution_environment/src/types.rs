//! Various types that are internal to the execution crate.
use ic_types::{
    ingress::IngressStatus,
    messages::{MessageId, Response as CanisterResponse},
};

#[derive(Debug, Eq, PartialEq)]
pub enum Response {
    Ingress(IngressResponse),
    Canister(CanisterResponse),
}

/// An ingress response.
#[derive(Debug, Eq, PartialEq)]
pub struct IngressResponse {
    pub message_id: MessageId,
    pub status: IngressStatus,
}
