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
use ic_types::{
    Time,
    time::CoarseTime,
    xnet::{RejectReason, RejectSignal, StreamIndex},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    convert::{From, Into, TryFrom, TryInto},
    sync::Arc,
};
use strum::EnumCount;
use strum_macros::EnumIter;

pub(crate) type Bytes = Vec<u8>;

/// Canonical representation of `ic_types::xnet::StreamHeader`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeader {
    pub begin: u64,
    pub end: u64,
    pub signals_end: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reserved_3: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u64,
    #[serde(default, skip_serializing_if = "RejectSignals::is_empty")]
    pub reject_signals: RejectSignals,
}

/// Delta encoded reject signals: the last signal is encoded as the delta
/// between `signals_end` and the stream index of the rejected message; all
/// other signals are encoded as the delta between the next stream index and
/// the current one.
///
/// Note that `signals_end` is NOT part of the reject signals.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectSignals {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canister_migrating_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canister_not_found_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canister_stopped_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canister_stopping_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queue_full_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_of_memory_deltas: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_deltas: Vec<u64>,
}

impl RejectSignals {
    pub fn is_empty(&self) -> bool {
        self.canister_migrating_deltas.is_empty()
            && self.canister_not_found_deltas.is_empty()
            && self.canister_stopped_deltas.is_empty()
            && self.canister_stopping_deltas.is_empty()
            && self.queue_full_deltas.is_empty()
            && self.out_of_memory_deltas.is_empty()
            && self.unknown_deltas.is_empty()
    }
}

/// Canonical representation of `ic_types::messages::StreamMessage`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund: Option<Refund>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RequestMetadata {
    // TODO(MR-642): Remove `Option` from `call_tree_depth` and `call_tree_start_time`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_tree_depth: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_tree_start_time_u64: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_subtree_deadline_u64: Option<u64>,
}

/// Canonical representation of `ic_types::messages::Request`.
#[derive(Debug, Deserialize, Serialize)]
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
    // TODO(MR-642): Remove `Option` from `metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RequestMetadata>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub deadline: u32,
}

/// Canonical representation of `ic_types::messages::Response`.
#[derive(Debug, Deserialize, Serialize)]
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

/// Canonical representation of `ic_types::messages::Refund`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Refund {
    #[serde(with = "serde_bytes")]
    pub recipient: Bytes,
    pub amount: Cycles,
}

/// Canonical representation of `ic_types::funds::Cycles`.
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cycles {
    pub low: u64,
    // TODO(EXC-337) `Skip` used for maintaining the serialisation backward compatible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u64>,
}

/// Canonical representation of `ic_types::funds::Funds`.
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject: Option<RejectContext>,
}

/// Canonical representation of `ic_types::messages::RejectContext`.
#[derive(Debug, Deserialize, Serialize)]
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
    pub deprecated_id_counter: Option<u64>,
    /// Hash bytes of the previous (partial) canonical state.
    pub prev_state_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
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

impl TryFrom<StreamHeader> for ic_types::xnet::StreamHeader {
    type Error = ProxyDecodeError;
    fn try_from(header: StreamHeader) -> Result<Self, Self::Error> {
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

        let reject_signals = try_from_deltas(&header.reject_signals, header.signals_end)?;

        Ok(Self::new(
            header.begin.into(),
            header.end.into(),
            header.signals_end.into(),
            reject_signals,
            flags,
        ))
    }
}

impl From<(&VecDeque<RejectSignal>, StreamIndex, CertificationVersion)> for RejectSignals {
    fn from(
        (reject_signals, signals_end, _certification_version): (
            &VecDeque<RejectSignal>,
            StreamIndex,
            CertificationVersion,
        ),
    ) -> Self {
        // Demux `reject_signals` into vectors of `StreamIndex`.
        let mut demuxed = HashMap::<RejectReason, Vec<StreamIndex>>::new();
        for RejectSignal { reason, index } in reject_signals.iter() {
            demuxed.entry(*reason).or_default().push(*index)
        }
        let mut deltas_for = |reason| -> Vec<u64> {
            demuxed
                .remove(&reason)
                .map(|signals| {
                    let mut next_index = signals_end;
                    let mut reject_signal_deltas = vec![0; signals.len()];
                    for (i, stream_index) in signals.iter().enumerate().rev() {
                        assert!(next_index > *stream_index);
                        reject_signal_deltas[i] = next_index.get() - stream_index.get();
                        next_index = *stream_index;
                    }
                    reject_signal_deltas
                })
                .unwrap_or_default()
        };

        RejectSignals {
            canister_migrating_deltas: deltas_for(RejectReason::CanisterMigrating),
            canister_not_found_deltas: deltas_for(RejectReason::CanisterNotFound),
            canister_stopped_deltas: deltas_for(RejectReason::CanisterStopped),
            canister_stopping_deltas: deltas_for(RejectReason::CanisterStopping),
            queue_full_deltas: deltas_for(RejectReason::QueueFull),
            out_of_memory_deltas: deltas_for(RejectReason::OutOfMemory),
            unknown_deltas: deltas_for(RejectReason::Unknown),
        }
    }
}

pub(crate) fn try_from_deltas(
    reject_signals: &RejectSignals,
    signals_end: u64,
) -> Result<VecDeque<RejectSignal>, ProxyDecodeError> {
    use RejectReason::*;

    let mut reject_signals_map = BTreeMap::<StreamIndex, RejectReason>::new();
    for (reason, deltas) in [
        (CanisterMigrating, &reject_signals.canister_migrating_deltas),
        (CanisterNotFound, &reject_signals.canister_not_found_deltas),
        (CanisterStopped, &reject_signals.canister_stopped_deltas),
        (CanisterStopping, &reject_signals.canister_stopping_deltas),
        (QueueFull, &reject_signals.queue_full_deltas),
        (OutOfMemory, &reject_signals.out_of_memory_deltas),
        (Unknown, &reject_signals.unknown_deltas),
    ] {
        let mut stream_index = StreamIndex::new(signals_end);
        for delta in deltas.iter().rev() {
            if *delta == 0 {
                // Reject signal deltas are invalid; a delta of `0` is forbidden since it would
                // lead to duplicates or a stream_index of `signals_end`.
                return Err(ProxyDecodeError::Other(format!(
                    "StreamHeader: {reason:?} found bad delta: `0` is not allowed in `reject_signal_deltas` {deltas:?}",
                )));
            }
            if stream_index < StreamIndex::new(*delta) {
                // Reject signal deltas are invalid.
                return Err(ProxyDecodeError::Other(format!(
                    "StreamHeader: {reason:?} reject signals are invalid, got `signals_end` {signals_end:?}, `reject_signal_deltas` {deltas:?}",
                )));
            }
            stream_index -= StreamIndex::new(*delta);

            if reject_signals_map.insert(stream_index, reason).is_some() {
                return Err(ProxyDecodeError::Other(
                    "StreamHeader: reject signals are invalid, got duplicates".to_string(),
                ));
            }
        }
    }

    Ok(reject_signals_map
        .iter()
        .map(|(index, reason)| RejectSignal::new(*reason, *index))
        .collect())
}

impl From<(&ic_types::messages::StreamMessage, CertificationVersion)> for StreamMessage {
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

impl TryFrom<StreamMessage> for ic_types::messages::StreamMessage {
    type Error = ProxyDecodeError;

    fn try_from(message: StreamMessage) -> Result<Self, Self::Error> {
        match message {
            StreamMessage {
                request: Some(request),
                response: None,
                refund: None,
            } => Ok(Self::Request(Arc::new(request.try_into()?))),
            StreamMessage {
                request: None,
                response: Some(response),
                refund: None,
            } => Ok(Self::Response(Arc::new(response.try_into()?))),
            StreamMessage {
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
            metadata: request.metadata.map_or_else(Default::default, From::from),
            deadline: CoarseTime::from_secs_since_unix_epoch(request.deadline),
        })
    }
}

impl From<(&ic_types::messages::Response, CertificationVersion)> for Response {
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

impl From<(&ic_types::messages::Refund, CertificationVersion)> for Refund {
    fn from(
        (refund, certification_version): (&ic_types::messages::Refund, CertificationVersion),
    ) -> Self {
        assert!(certification_version >= CertificationVersion::V22);
        Self {
            recipient: refund.recipient().get().to_vec(),
            amount: (&refund.amount(), certification_version).into(),
        }
    }
}

impl TryFrom<Refund> for ic_types::messages::Refund {
    type Error = ProxyDecodeError;

    fn try_from(refund: Refund) -> Result<Self, Self::Error> {
        Ok(Self::anonymous(
            ic_types::CanisterId::unchecked_from_principal(refund.recipient.as_slice().try_into()?),
            refund.amount.try_into()?,
        ))
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
                "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `{other:?}`"
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
        (metadata, _certification_version): (
            &ic_replicated_state::metadata_state::SystemMetadata,
            CertificationVersion,
        ),
    ) -> Self {
        Self {
            deprecated_id_counter: None,
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
