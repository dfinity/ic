//! Copies of historical canonical types and their conversion logic.
//!
//! Whenever a canonical type is modified, a copy of the "old" type should be
//! made here.
//!
//! Types of certification versions < MIN_SUPPORTED_CERTIFICATION_VERSION can
//! be removed.

use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
};

use super::types;
use crate::CertificationVersion;
use crate::encoding::types::{
    Bytes, Cycles, Funds, Payload, Refund, RejectSignals, RequestMetadata, STREAM_SUPPORTED_FLAGS,
    StreamFlagBits,
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::time::CoarseTime;
use serde::{Deserialize, Serialize};

/// Canonical representation of `ic_types::messages::RequestOrResponse` at certification version V19.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOrResponseV21 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestV19>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseV19>,
}

impl From<(&ic_types::messages::StreamMessage, CertificationVersion)> for RequestOrResponseV21 {
    fn from(
        (message, certification_version): (
            &ic_types::messages::StreamMessage,
            CertificationVersion,
        ),
    ) -> Self {
        use ic_types::messages::StreamMessage::*;
        match message {
            Request(request) => Self {
                request: Some((request.as_ref(), certification_version).into()),
                response: None,
            },
            Response(response) => Self {
                request: None,
                response: Some((response.as_ref(), certification_version).into()),
            },
            Refund(_) => unreachable!("No `Refund` variant before certification version V22"),
        }
    }
}

impl TryFrom<RequestOrResponseV21> for ic_types::messages::StreamMessage {
    type Error = ProxyDecodeError;

    fn try_from(message: RequestOrResponseV21) -> Result<Self, Self::Error> {
        match message {
            RequestOrResponseV21 {
                request: Some(request),
                response: None,
            } => Ok(Self::Request(Arc::new(request.try_into()?))),
            RequestOrResponseV21 {
                request: None,
                response: Some(response),
            } => Ok(Self::Response(Arc::new(response.try_into()?))),
            other => Err(ProxyDecodeError::Other(format!(
                "RequestOrResponse: expected exactly one of `request` or `response` to be `Some(_)`, got `{other:?}`"
            ))),
        }
    }
}

/// Canonical representation of `ic_types::messages::StreamMessage`at certification version V22.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMessageV22 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestV22>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseV22>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund: Option<Refund>,
}

impl From<(&ic_types::messages::StreamMessage, CertificationVersion)> for StreamMessageV22 {
    fn from(
        (message, certification_version): (
            &ic_types::messages::StreamMessage,
            CertificationVersion,
        ),
    ) -> Self {
        use ic_types::messages::StreamMessage::*;
        match message {
            Request(request) => Self {
                request: Some((request.as_ref(), certification_version).into()),
                response: None,
                refund: None,
            },
            Response(response) => Self {
                request: None,
                response: Some((response.as_ref(), certification_version).into()),
                refund: None,
            },
            Refund(refund) => Self {
                request: None,
                response: None,
                refund: Some((refund.as_ref(), certification_version).into()),
            },
        }
    }
}

impl TryFrom<StreamMessageV22> for ic_types::messages::StreamMessage {
    type Error = ProxyDecodeError;

    fn try_from(message: StreamMessageV22) -> Result<Self, Self::Error> {
        match message {
            StreamMessageV22 {
                request: Some(request),
                response: None,
                refund: None,
            } => Ok(Self::Request(Arc::new(request.try_into()?))),
            StreamMessageV22 {
                request: None,
                response: Some(response),
                refund: None,
            } => Ok(Self::Response(Arc::new(response.try_into()?))),
            StreamMessageV22 {
                request: None,
                response: None,
                refund: Some(refund),
            } => Ok(Self::Refund(Arc::new(refund.try_into()?))),
            other => Err(ProxyDecodeError::Other(format!(
                "StreamMessage: expected exactly one of `request`, `response` or `refund` to be `Some(_)`, got `{other:?}`"
            ))),
        }
    }
}

/// Canonical representation of `ic_types::messages::Request` at certification version V19.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestV19 {
    #[serde(with = "serde_bytes")]
    pub receiver: Bytes,
    #[serde(with = "serde_bytes")]
    pub sender: Bytes,
    pub sender_reply_callback: u64,
    pub payment: Funds,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_payment: Option<Cycles>,
    // TODO(MR-642): Remove `Option` from `metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<types::RequestMetadata>,
    #[serde(skip_serializing_if = "types::is_zero", default)]
    pub deadline: u32,
}

impl From<(&ic_types::messages::Request, CertificationVersion)> for RequestV19 {
    fn from(
        (request, certification_version): (&ic_types::messages::Request, CertificationVersion),
    ) -> Self {
        let funds = Funds {
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
            cycles_payment: None,
            metadata: Some((&request.metadata).into()),
            deadline: request.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<RequestV19> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: RequestV19) -> Result<Self, Self::Error> {
        let payment = match request.cycles_payment {
            Some(cycles) => cycles,
            None => request.payment.cycles,
        }
        .try_into()?;

        Ok(Self {
            receiver: ic_types::CanisterId::unchecked_from_principal(
                request.receiver.as_slice().try_into()?,
            ),
            sender: ic_types::CanisterId::unchecked_from_principal(
                request.sender.as_slice().try_into()?,
            ),
            sender_reply_callback: request.sender_reply_callback.into(),
            payment,
            method_name: request.method_name,
            method_payload: request.method_payload,
            metadata: request.metadata.map_or_else(Default::default, From::from),
            deadline: CoarseTime::from_secs_since_unix_epoch(request.deadline),
        })
    }
}

/// Canonical representation of `ic_types::messages::Request` at certification version V22.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestV22 {
    #[serde(with = "serde_bytes")]
    pub receiver: Bytes,
    #[serde(with = "serde_bytes")]
    pub sender: Bytes,
    pub sender_reply_callback: u64,
    pub payment: Funds,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_payment: Option<Cycles>,
    // TODO(MR-642): Remove `Option` from `metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RequestMetadata>,
    #[serde(skip_serializing_if = "types::is_zero", default)]
    pub deadline: u32,
}

impl From<(&ic_types::messages::Request, CertificationVersion)> for RequestV22 {
    fn from(
        (request, certification_version): (&ic_types::messages::Request, CertificationVersion),
    ) -> Self {
        let funds = Funds {
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
            cycles_payment: None,
            metadata: Some((&request.metadata).into()),
            deadline: request.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<RequestV22> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: RequestV22) -> Result<Self, Self::Error> {
        let payment = match request.cycles_payment {
            Some(cycles) => cycles,
            None => request.payment.cycles,
        }
        .try_into()?;

        Ok(Self {
            receiver: ic_types::CanisterId::unchecked_from_principal(
                request.receiver.as_slice().try_into()?,
            ),
            sender: ic_types::CanisterId::unchecked_from_principal(
                request.sender.as_slice().try_into()?,
            ),
            sender_reply_callback: request.sender_reply_callback.into(),
            payment,
            method_name: request.method_name,
            method_payload: request.method_payload,
            metadata: request.metadata.map_or_else(Default::default, From::from),
            deadline: CoarseTime::from_secs_since_unix_epoch(request.deadline),
        })
    }
}

/// Canonical representation of `ic_types::messages::Response` at certification version V19.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseV19 {
    #[serde(with = "serde_bytes")]
    pub originator: Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: Bytes,
    pub originator_reply_callback: u64,
    pub refund: Funds,
    pub response_payload: Payload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_refund: Option<Cycles>,
    #[serde(skip_serializing_if = "types::is_zero", default)]
    pub deadline: u32,
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for ResponseV19 {
    fn from(
        (response, certification_version): (&ic_types::messages::Response, CertificationVersion),
    ) -> Self {
        let funds = Funds {
            cycles: (&response.refund, certification_version).into(),
            icp: 0,
        };
        Self {
            originator: response.originator.get().to_vec(),
            respondent: response.respondent.get().to_vec(),
            originator_reply_callback: response.originator_reply_callback.get(),
            refund: funds,
            response_payload: (&response.response_payload, certification_version).into(),
            cycles_refund: None,
            deadline: response.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<ResponseV19> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: ResponseV19) -> Result<Self, Self::Error> {
        let refund = match response.cycles_refund {
            Some(cycles) => cycles,
            None => response.refund.cycles,
        }
        .try_into()?;

        Ok(Self {
            originator: ic_types::CanisterId::unchecked_from_principal(
                response.originator.as_slice().try_into()?,
            ),
            respondent: ic_types::CanisterId::unchecked_from_principal(
                response.respondent.as_slice().try_into()?,
            ),
            originator_reply_callback: response.originator_reply_callback.into(),
            refund,
            response_payload: response.response_payload.try_into()?,
            deadline: CoarseTime::from_secs_since_unix_epoch(response.deadline),
        })
    }
}

/// Canonical representation of `ic_types::messages::Response` at certification version V22.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseV22 {
    #[serde(with = "serde_bytes")]
    pub originator: Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: Bytes,
    pub originator_reply_callback: u64,
    pub refund: Funds,
    pub response_payload: Payload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_refund: Option<Cycles>,
    #[serde(skip_serializing_if = "types::is_zero", default)]
    pub deadline: u32,
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for ResponseV22 {
    fn from(
        (response, certification_version): (&ic_types::messages::Response, CertificationVersion),
    ) -> Self {
        let funds = Funds {
            cycles: (&response.refund, certification_version).into(),
            icp: 0,
        };
        Self {
            originator: response.originator.get().to_vec(),
            respondent: response.respondent.get().to_vec(),
            originator_reply_callback: response.originator_reply_callback.get(),
            refund: funds,
            response_payload: (&response.response_payload, certification_version).into(),
            cycles_refund: None,
            deadline: response.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<ResponseV22> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: ResponseV22) -> Result<Self, Self::Error> {
        let refund = match response.cycles_refund {
            Some(cycles) => cycles,
            None => response.refund.cycles,
        }
        .try_into()?;

        Ok(Self {
            originator: ic_types::CanisterId::unchecked_from_principal(
                response.originator.as_slice().try_into()?,
            ),
            respondent: ic_types::CanisterId::unchecked_from_principal(
                response.respondent.as_slice().try_into()?,
            ),
            originator_reply_callback: response.originator_reply_callback.into(),
            refund,
            response_payload: response.response_payload.try_into()?,
            deadline: CoarseTime::from_secs_since_unix_epoch(response.deadline),
        })
    }
}

/// Canonical representation of `ic_types::xnet::StreamHeader` at certification version V19.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeaderV19 {
    pub begin: u64,
    pub end: u64,
    pub signals_end: u64,
    #[serde(default, skip_serializing_if = "types::is_zero")]
    pub reserved_3: u64,
    #[serde(default, skip_serializing_if = "types::is_zero")]
    pub flags: u64,
    #[serde(default, skip_serializing_if = "types::RejectSignals::is_empty")]
    pub reject_signals: RejectSignals,
}

impl From<(&ic_types::xnet::StreamHeader, CertificationVersion)> for StreamHeaderV19 {
    fn from(
        (header, certification_version): (&ic_types::xnet::StreamHeader, CertificationVersion),
    ) -> Self {
        let mut flags = 0;
        let ic_types::xnet::StreamFlags {
            deprecated_responses_only,
        } = *header.flags();
        if deprecated_responses_only {
            flags |= StreamFlagBits::DeprecatedResponsesOnly as u64;
        }

        // Generate deltas representation based on `certification_version` to ensure unique
        // encoding.
        let reject_signals = (
            header.reject_signals(),
            header.signals_end(),
            certification_version,
        )
            .into();

        Self {
            begin: header.begin().get(),
            end: header.end().get(),
            signals_end: header.signals_end().get(),
            reserved_3: 0,
            flags,
            reject_signals,
        }
    }
}

impl TryFrom<StreamHeaderV19> for ic_types::xnet::StreamHeader {
    type Error = ProxyDecodeError;
    fn try_from(header: StreamHeaderV19) -> Result<Self, Self::Error> {
        if header.reserved_3 != 0 {
            return Err(ProxyDecodeError::Other(format!(
                "StreamHeader: field index 3 is populated: {:?}",
                header.reserved_3,
            )));
        }
        if header.flags & !STREAM_SUPPORTED_FLAGS != 0 {
            return Err(ProxyDecodeError::Other(format!(
                "StreamHeader: unsupported flags: got `flags` {:#b}, `supported_flags` {:#b}",
                header.flags, STREAM_SUPPORTED_FLAGS,
            )));
        }
        let flags = ic_types::xnet::StreamFlags {
            deprecated_responses_only: header.flags
                & StreamFlagBits::DeprecatedResponsesOnly as u64
                != 0,
        };

        let reject_signals = types::try_from_deltas(&header.reject_signals, header.signals_end)?;

        Ok(Self::new(
            header.begin.into(),
            header.end.into(),
            header.signals_end.into(),
            reject_signals,
            flags,
        ))
    }
}
