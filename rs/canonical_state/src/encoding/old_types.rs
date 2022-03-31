//! Copies of historica canonical types and their conversion logic.
//!
//! Whenever a canonical type is modified, a copy of the "old" type should be
//! made here.

use std::convert::{TryFrom, TryInto};

use crate::CertificationVersion;

use super::types;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{messages::RequestOrResponse, xnet::StreamHeader};
use serde::{Deserialize, Serialize};

// Copy of `types::Request` at canonical version 3 (before the addition of `cycles_payment`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestV3 {
    #[serde(with = "serde_bytes")]
    pub receiver: types::Bytes,
    #[serde(with = "serde_bytes")]
    pub sender: types::Bytes,
    pub sender_reply_callback: u64,
    pub payment: types::Funds,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: types::Bytes,
}

impl From<(&ic_types::messages::Request, CertificationVersion)> for RequestV3 {
    fn from(
        (request, certification_version): (&ic_types::messages::Request, CertificationVersion),
    ) -> Self {
        let funds = types::Funds {
            cycles: (&request.payment, certification_version).into(),
            icp: 0,
        };
        Self {
            receiver: request.receiver.get().to_vec(),
            sender: request.sender.get().to_vec(),
            sender_reply_callback: request.sender_reply_callback.get(),
            payment: funds,
            method_name: request.method_name.clone(),
            method_payload: request.method_payload.clone(),
        }
    }
}

impl TryFrom<RequestV3> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: RequestV3) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver: ic_types::CanisterId::new(request.receiver.as_slice().try_into()?)?,
            sender: ic_types::CanisterId::new(request.sender.as_slice().try_into()?)?,
            sender_reply_callback: request.sender_reply_callback.into(),
            payment: request.payment.cycles.try_into()?,
            method_name: request.method_name,
            method_payload: request.method_payload,
        })
    }
}

// Copy of `types::Response` at canonical version 3 (before the addition of `cycles_refund`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseV3 {
    #[serde(with = "serde_bytes")]
    pub originator: types::Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: types::Bytes,
    pub originator_reply_callback: u64,
    pub refund: types::Funds,
    pub response_payload: types::Payload,
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for ResponseV3 {
    fn from(
        (response, certification_version): (&ic_types::messages::Response, CertificationVersion),
    ) -> Self {
        let funds = types::Funds {
            cycles: (&response.refund, certification_version).into(),
            icp: 0,
        };
        Self {
            originator: response.originator.get().to_vec(),
            respondent: response.respondent.get().to_vec(),
            originator_reply_callback: response.originator_reply_callback.get(),
            refund: funds,
            response_payload: (&response.response_payload, certification_version).into(),
        }
    }
}

impl TryFrom<ResponseV3> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: ResponseV3) -> Result<Self, Self::Error> {
        Ok(Self {
            originator: ic_types::CanisterId::new(response.originator.as_slice().try_into()?)?,
            respondent: ic_types::CanisterId::new(response.respondent.as_slice().try_into()?)?,
            originator_reply_callback: response.originator_reply_callback.into(),
            refund: response.refund.cycles.try_into()?,
            response_payload: response.response_payload.try_into()?,
        })
    }
}

// Copy of `types::RequestOrResponse` at canonical version 3 (before the
// addition of `cycles_refund` to `types::Request` and `types::Response`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOrResponseV3 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestV3>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseV3>,
}

impl From<(&ic_types::messages::RequestOrResponse, CertificationVersion)> for RequestOrResponseV3 {
    fn from(
        (message, certification_version): (
            &ic_types::messages::RequestOrResponse,
            CertificationVersion,
        ),
    ) -> Self {
        match message {
            RequestOrResponse::Request(req) => RequestOrResponseV3 {
                request: Some(RequestV3::from((req, certification_version))),
                response: None,
            },
            RequestOrResponse::Response(resp) => RequestOrResponseV3 {
                request: None,
                response: Some(ResponseV3::from((resp, certification_version))),
            },
        }
    }
}

impl TryFrom<RequestOrResponseV3> for ic_types::messages::RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(message: RequestOrResponseV3) -> Result<Self, Self::Error> {
        match message {
            RequestOrResponseV3 {
                request: Some(request),
                response: None,
            } => Ok(Self::Request(request.try_into()?)),
            RequestOrResponseV3 {
                request: None,
                response: Some(response),
            } => Ok(Self::Response(response.try_into()?)),
            other => Err(ProxyDecodeError::Other(format!(
                "RequestOrResponseV3: expected exactly one of `request` or `response` to be `Some(_)`, got `{:?}`",
                other
            )))
        }
    }
}

// Copy of `types::StreamHeader` at canonical version 6 (before the addition of
// `reject_signals`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeaderV6 {
    pub begin: u64,
    pub end: u64,
    pub signals_end: u64,
}

impl From<(&StreamHeader, CertificationVersion)> for StreamHeaderV6 {
    fn from((header, _certification_version): (&StreamHeader, CertificationVersion)) -> Self {
        Self {
            begin: header.begin.get(),
            end: header.end.get(),
            signals_end: header.signals_end.get(),
        }
    }
}

impl From<StreamHeaderV6> for StreamHeader {
    fn from(header: StreamHeaderV6) -> Self {
        Self {
            begin: header.begin.into(),
            end: header.end.into(),
            signals_end: header.signals_end.into(),
            reject_signals: Default::default(),
        }
    }
}
