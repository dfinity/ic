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

use crate::CertificationVersion;

use super::types;
use crate::encoding::types::{
    Bytes, Cycles, Funds, StreamFlagBits as StreamFlagBitsV17,
    STREAM_SUPPORTED_FLAGS as STREAM_SUPPORTED_FLAGS_V17,
};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::messages::NO_DEADLINE;
use ic_types::xnet::{RejectReason, RejectSignal, StreamIndex};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Copy of `types::RequestOrResponse` at canonical version 17 (before the
/// addition of `deadline` to `types::Request` and `types::Response`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOrResponseV17 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestV17>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseV17>,
}

impl From<(&ic_types::messages::RequestOrResponse, CertificationVersion)> for RequestOrResponseV17 {
    fn from(
        (message, certification_version): (
            &ic_types::messages::RequestOrResponse,
            CertificationVersion,
        ),
    ) -> Self {
        use ic_types::messages::RequestOrResponse::*;
        match message {
            Request(request) => Self {
                request: Some((request.as_ref(), certification_version).into()),
                response: None,
            },
            Response(response) => Self {
                request: None,
                response: Some((response.as_ref(), certification_version).into()),
            },
        }
    }
}

impl TryFrom<RequestOrResponseV17> for ic_types::messages::RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(message: RequestOrResponseV17) -> Result<Self, Self::Error> {
        match message {
          RequestOrResponseV17 {
              request: Some(request),
              response: None,
          } => Ok(Self::Request(Arc::new(request.try_into()?))),
          RequestOrResponseV17 {
              request: None,
              response: Some(response),
          } => Ok(Self::Response(Arc::new(response.try_into()?))),
          other => Err(ProxyDecodeError::Other(format!(
              "RequestOrResponse: expected exactly one of `request` or `response` to be `Some(_)`, got `{:?}`",
              other
          )))
      }
    }
}

/// Copy of `types::Request` at canonical version 17 (before the addition of `deadline`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestV17 {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<types::RequestMetadata>,
}

impl From<(&ic_types::messages::Request, CertificationVersion)> for RequestV17 {
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
        }
    }
}

impl TryFrom<RequestV17> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: RequestV17) -> Result<Self, Self::Error> {
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
            deadline: NO_DEADLINE,
        })
    }
}

/// Copy of `types::Response` at canonical version 17 (before the addition of `deadline`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseV17 {
    #[serde(with = "serde_bytes")]
    pub originator: Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: Bytes,
    pub originator_reply_callback: u64,
    pub refund: Funds,
    pub response_payload: types::Payload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_refund: Option<Cycles>,
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for ResponseV17 {
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
        }
    }
}

impl TryFrom<ResponseV17> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: ResponseV17) -> Result<Self, Self::Error> {
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
            deadline: NO_DEADLINE,
        })
    }
}

pub fn is_zero<T>(v: &T) -> bool
where
    T: Into<u64> + Copy,
{
    (*v).into() == 0
}

/// Copy of `types::StreamHeader` at canonical version 18 (before the addition of
/// `reject_signals` and deprecation of `reject_signal_deltas`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeaderV18 {
    pub begin: u64,
    pub end: u64,
    pub signals_end: u64,
    /// Delta encoded reject signals: the last signal is encoded as the delta
    /// between `signals_end` and the stream index of the rejected message; all
    /// other signals are encoded as the delta between the next stream index and
    /// the current one.
    ///
    /// Note that `signals_end` is NOT part of the reject signals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reject_signal_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u64,
}

impl From<(&ic_types::xnet::StreamHeader, CertificationVersion)> for StreamHeaderV18 {
    fn from(
        (header, _certification_version): (&ic_types::xnet::StreamHeader, CertificationVersion),
    ) -> Self {
        let mut next_index = header.signals_end();
        let mut reject_signal_deltas = vec![0; header.reject_signals().len()];
        for (i, stream_index) in header
            .reject_signals()
            .iter()
            .enumerate()
            .map(|(i, signal)| {
                // Reject signals at certification version < 19 may not produce signals other than
                // `CanisterMigrating`.
                assert_eq!(signal.reason, RejectReason::CanisterMigrating);
                (i, signal.index)
            })
            .rev()
        {
            assert!(next_index > stream_index);
            reject_signal_deltas[i] = next_index.get() - stream_index.get();
            next_index = stream_index;
        }

        let mut flags = 0;
        let ic_types::xnet::StreamFlags {
            deprecated_responses_only,
        } = *header.flags();
        if deprecated_responses_only {
            flags |= StreamFlagBitsV17::DeprecatedResponsesOnly as u64;
        }

        Self {
            begin: header.begin().get(),
            end: header.end().get(),
            signals_end: header.signals_end().get(),
            reject_signal_deltas,
            flags,
        }
    }
}

impl TryFrom<StreamHeaderV18> for ic_types::xnet::StreamHeader {
    type Error = ProxyDecodeError;
    fn try_from(header: StreamHeaderV18) -> Result<Self, Self::Error> {
        let mut reject_signals = VecDeque::with_capacity(header.reject_signal_deltas.len());
        let mut stream_index = StreamIndex::new(header.signals_end);
        for delta in header.reject_signal_deltas.iter().rev() {
            if stream_index < StreamIndex::new(*delta) {
                // Reject signal deltas are invalid.
                return Err(ProxyDecodeError::Other(format!(
                    "StreamHeader: reject signals are invalid, got `signals_end` {:?}, `reject_signal_deltas` {:?}",
                    header.signals_end,
                    header.reject_signal_deltas,
                )));
            }
            stream_index -= StreamIndex::new(*delta);
            reject_signals.push_front(RejectSignal::new(
                RejectReason::CanisterMigrating,
                stream_index,
            ));
        }

        if header.flags & !STREAM_SUPPORTED_FLAGS_V17 != 0 {
            return Err(ProxyDecodeError::Other(format!(
                "StreamHeader: unsupported flags: got `flags` {:#b}, `supported_flags` {:#b}",
                header.flags, STREAM_SUPPORTED_FLAGS_V17,
            )));
        }
        let flags = ic_types::xnet::StreamFlags {
            deprecated_responses_only: header.flags
                & StreamFlagBitsV17::DeprecatedResponsesOnly as u64
                != 0,
        };

        Ok(Self::new(
            header.begin.into(),
            header.end.into(),
            header.signals_end.into(),
            reject_signals,
            flags,
        ))
    }
}
