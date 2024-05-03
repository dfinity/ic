//! Canonical types for encoding canonical state tree leaves.
//!
//! These structs mirror the ones defined in the `ic-types` crate, with the
//! intent of providing a stable, efficient representation when serialized as
//! CBOR. `From` and `TryFrom` implementations allow converting back and forth
//! between these canonical types and the `ic-types` ones.
//!
//! Enums are encoded as structs with optional fields that are not encoded when
//! `None`. C-like enums are represented as the corresponding unsigned value.
//! Newtypes, such as various IDs are replaced by the wrapped type.
//! `CanisterIds` are represented as byte vectors.

use crate::CertificationVersion;
use ic_error_types::TryFromError;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{messages::NO_DEADLINE, time::CoarseTime, xnet::StreamIndex, Time};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    convert::{From, Into, TryFrom, TryInto},
    sync::Arc,
};
use strum::EnumCount;
use strum_macros::EnumIter;

pub(crate) type Bytes = Vec<u8>;

/// Canonical representation of `ic_types::xnet::StreamHeader`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeader {
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

/// Canonical representation of `ic_types::messages::RequestOrResponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOrResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_tree_depth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_tree_start_time_u64: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_subtree_deadline_u64: Option<u64>,
}

/// Canonical representation of `ic_types::messages::Request`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
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
    pub metadata: Option<RequestMetadata>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub deadline: u32,
}

/// Canonical representation of `ic_types::messages::Response`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    #[serde(with = "serde_bytes")]
    pub originator: Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: Bytes,
    pub originator_reply_callback: u64,
    pub refund: Funds,
    pub response_payload: Payload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles_refund: Option<Cycles>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub deadline: u32,
}

/// Canonical representation of `ic_types::funds::Cycles`.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Cycles {
    pub low: u64,
    // TODO(EXC-337) `Skip` used for maintaining the serialisation backward compatible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u64>,
}

/// Canonical representation of `ic_types::funds::Funds`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Funds {
    pub cycles: Cycles,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub icp: u64,
}

pub fn is_zero<T>(v: &T) -> bool
where
    T: Into<u64> + Copy,
{
    (*v).into() == 0
}

/// Canonical representation of `ic_types::messages::Payload`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject: Option<RejectContext>,
}

/// Canonical representation of `ic_types::messages::RejectContext`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectContext {
    pub code: u8,
    pub message: String,
}

/// Canonical representation of state metadata leaf.
#[derive(Debug, Serialize)]
pub struct SystemMetadata {
    /// The counter used to allocate canister ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_counter: Option<u64>,
    /// Hash bytes of the previous (partial) canonical state.
    pub prev_state_hash: Option<Vec<u8>>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct SubnetMetrics {
    /// The number of canisters on this subnet.
    pub num_canisters: u64,
    /// The total size of the state taken by canisters on this subnet in bytes.
    pub canister_state_bytes: u64,
    /// The total number of cycles consumed by all current and deleted canisters
    /// on this subnet.
    pub consumed_cycles_total: Cycles,
    /// The total number of update transactions processed on this subnet.
    /// Update transactions include all replicated message executions.
    pub update_transactions_total: u64,
}

/// Bits used for encoding `ic_types::xnet::StreamFlags`.
#[derive(EnumCount, EnumIter)]
#[repr(u64)]
pub enum StreamFlagBits {
    DeprecatedResponsesOnly = 1,
}

/// Constant version of `ic_types::xnet::StreamFlags::default()`.
pub const STREAM_DEFAULT_FLAGS: ic_types::xnet::StreamFlags = ic_types::xnet::StreamFlags {
    deprecated_responses_only: false,
};

/// A mask containing the supported bits.
pub const STREAM_SUPPORTED_FLAGS: u64 = (1 << StreamFlagBits::COUNT) - 1;

impl From<(&ic_types::xnet::StreamHeader, CertificationVersion)> for StreamHeader {
    fn from(
        (header, certification_version): (&ic_types::xnet::StreamHeader, CertificationVersion),
    ) -> Self {
        // Replicas with certification version < 9 do not produce reject signals. This
        // includes replicas with certification version 8, but they may "inherit" reject
        // signals from a replica with certification version 9 after a downgrade.
        assert!(
            header.reject_signals().is_empty() || certification_version >= CertificationVersion::V8,
            "Replicas with certification version < 9 should not be producing reject signals"
        );
        // Replicas with certification version < 17 should not have flags set.
        assert!(
            *header.flags() == STREAM_DEFAULT_FLAGS
                || certification_version >= CertificationVersion::V17
        );

        let mut next_index = header.signals_end();
        let mut reject_signal_deltas = vec![0; header.reject_signals().len()];
        for (i, stream_index) in header.reject_signals().iter().enumerate().rev() {
            assert!(next_index > *stream_index);
            reject_signal_deltas[i] = next_index.get() - stream_index.get();
            next_index = *stream_index;
        }

        let mut flags = 0;
        let ic_types::xnet::StreamFlags {
            deprecated_responses_only,
        } = *header.flags();
        if deprecated_responses_only {
            flags |= StreamFlagBits::DeprecatedResponsesOnly as u64;
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

impl TryFrom<StreamHeader> for ic_types::xnet::StreamHeader {
    type Error = ProxyDecodeError;
    fn try_from(header: StreamHeader) -> Result<Self, Self::Error> {
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
            reject_signals.push_front(stream_index);
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

        Ok(Self::new(
            header.begin.into(),
            header.end.into(),
            header.signals_end.into(),
            reject_signals,
            flags,
        ))
    }
}

impl From<(&ic_types::messages::RequestOrResponse, CertificationVersion)> for RequestOrResponse {
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

impl TryFrom<RequestOrResponse> for ic_types::messages::RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(message: RequestOrResponse) -> Result<Self, Self::Error> {
        match message {
            RequestOrResponse {
                request: Some(request),
                response: None,
            } => Ok(Self::Request(Arc::new(request.try_into()?))),
            RequestOrResponse {
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

impl From<&ic_types::messages::RequestMetadata> for RequestMetadata {
    fn from(metadata: &ic_types::messages::RequestMetadata) -> Self {
        RequestMetadata {
            call_tree_depth: Some(*metadata.call_tree_depth()),
            call_tree_start_time_u64: Some(
                metadata.call_tree_start_time().as_nanos_since_unix_epoch(),
            ),
            call_subtree_deadline_u64: None,
        }
    }
}

impl From<RequestMetadata> for ic_types::messages::RequestMetadata {
    fn from(metadata: RequestMetadata) -> Self {
        ic_types::messages::RequestMetadata::new(
            metadata.call_tree_depth.unwrap_or(0),
            Time::from_nanos_since_unix_epoch(metadata.call_tree_start_time_u64.unwrap_or(0)),
        )
    }
}

impl From<(&ic_types::messages::Request, CertificationVersion)> for Request {
    fn from(
        (request, certification_version): (&ic_types::messages::Request, CertificationVersion),
    ) -> Self {
        // Replicas with certification version < 18 should not apply request deadlines.
        debug_assert!(
            request.deadline == NO_DEADLINE || certification_version >= CertificationVersion::V18
        );

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
            metadata: request.metadata.as_ref().and_then(|metadata| {
                (certification_version >= CertificationVersion::V14).then_some(metadata.into())
            }),
            deadline: request.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<Request> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: Request) -> Result<Self, Self::Error> {
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
            metadata: request.metadata.map(From::from),
            deadline: CoarseTime::from_secs_since_unix_epoch(request.deadline),
        })
    }
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for Response {
    fn from(
        (response, certification_version): (&ic_types::messages::Response, CertificationVersion),
    ) -> Self {
        // Replicas with certification version < 18 should not apply response deadlines.
        debug_assert!(
            response.deadline == NO_DEADLINE || certification_version >= CertificationVersion::V18
        );

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

impl TryFrom<Response> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: Response) -> Result<Self, Self::Error> {
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

impl From<(&ic_types::funds::Cycles, CertificationVersion)> for Cycles {
    fn from(
        (cycles, _certification_version): (&ic_types::funds::Cycles, CertificationVersion),
    ) -> Self {
        let (high, low) = cycles.into_parts();
        Self {
            low,
            // For backward compatibility, set to `None` when the upper 8 bytes are missing.
            high: match high {
                0 => None,
                _ => Some(high),
            },
        }
    }
}

impl TryFrom<Cycles> for ic_types::funds::Cycles {
    type Error = ProxyDecodeError;

    fn try_from(cycles: Cycles) -> Result<Self, Self::Error> {
        match cycles.high {
            None => Ok(Self::from(cycles.low)),
            Some(high) => Ok(Self::from_parts(high, cycles.low)),
        }
    }
}

impl From<(&ic_types::funds::Funds, CertificationVersion)> for Funds {
    fn from(
        (funds, certification_version): (&ic_types::funds::Funds, CertificationVersion),
    ) -> Self {
        Self {
            cycles: (&funds.cycles(), certification_version).into(),
            icp: 0,
        }
    }
}

impl TryFrom<Funds> for ic_types::funds::Funds {
    type Error = ProxyDecodeError;

    fn try_from(funds: Funds) -> Result<Self, Self::Error> {
        Ok(Self::new(funds.cycles.try_into()?))
    }
}

impl From<(&ic_types::messages::Payload, CertificationVersion)> for Payload {
    fn from(
        (payload, certification_version): (&ic_types::messages::Payload, CertificationVersion),
    ) -> Self {
        use ic_types::messages::Payload::*;
        match payload {
            Data(data) => Self {
                data: Some(data.clone()),
                reject: None,
            },
            Reject(reject) => Self {
                data: None,
                reject: Some((reject, certification_version).into()),
            },
        }
    }
}

impl TryFrom<Payload> for ic_types::messages::Payload {
    type Error = ProxyDecodeError;

    fn try_from(payload: Payload) -> Result<Self, Self::Error> {
        match payload {
            Payload {
                data: Some(data),
                reject: None,
            } => Ok(Self::Data(data)),
            Payload {
                data: None,
                reject: Some(reject),
            } => Ok(Self::Reject(reject.try_into()?)),
            other => Err(ProxyDecodeError::Other(format!(
                "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `{:?}`",
                other
            ))),
        }
    }
}

impl From<(&ic_types::messages::RejectContext, CertificationVersion)> for RejectContext {
    fn from(
        (context, _certification_version): (
            &ic_types::messages::RejectContext,
            CertificationVersion,
        ),
    ) -> Self {
        Self {
            code: context.code() as u8,
            message: context.message().clone(),
        }
    }
}

impl TryFrom<RejectContext> for ic_types::messages::RejectContext {
    type Error = ProxyDecodeError;

    fn try_from(context: RejectContext) -> Result<Self, Self::Error> {
        Ok(Self::from_canonical(
            (context.code as u64).try_into().map_err(|err| match err {
                TryFromError::ValueOutOfRange(code) => ProxyDecodeError::ValueOutOfRange {
                    typ: "RejectContext",
                    err: code.to_string(),
                },
            })?,
            context.message,
        ))
    }
}

impl
    From<(
        &ic_replicated_state::metadata_state::SystemMetadata,
        CertificationVersion,
    )> for SystemMetadata
{
    fn from(
        (metadata, certification_version): (
            &ic_replicated_state::metadata_state::SystemMetadata,
            CertificationVersion,
        ),
    ) -> Self {
        Self {
            id_counter: if certification_version <= CertificationVersion::V9 {
                Some(0)
            } else {
                None
            },
            prev_state_hash: metadata
                .prev_state_hash
                .as_ref()
                .map(|h| h.get_ref().0.clone()),
        }
    }
}

impl
    From<(
        &ic_replicated_state::metadata_state::SubnetMetrics,
        CertificationVersion,
    )> for SubnetMetrics
{
    fn from(
        (metrics, _certification_version): (
            &ic_replicated_state::metadata_state::SubnetMetrics,
            CertificationVersion,
        ),
    ) -> Self {
        let (high, low) = metrics.consumed_cycles_total().into_parts();
        Self {
            num_canisters: metrics.num_canisters,
            canister_state_bytes: metrics.canister_state_bytes.get(),
            consumed_cycles_total: Cycles {
                low,
                high: Some(high),
            },
            update_transactions_total: metrics.update_transactions_total,
        }
    }
}
