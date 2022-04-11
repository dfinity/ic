//! Ingress types.

use crate::artifact::IngressMessageId;
use crate::{CanisterId, CountBytes, PrincipalId, Time, UserId};
use ic_error_types::{ErrorCode, TryFromError, UserError};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::{convert::TryFrom, fmt};

/// The status of an ingress message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IngressStatus {
    /// The message was successfully inducted into the input queue of
    /// the receiver and should eventually execute.
    ///
    /// Note that inducted messages can expire if they haven't executed within
    /// some time.
    Received {
        receiver: PrincipalId,
        user_id: UserId,
        time: Time,
    },
    /// The message was executed and the execution yielded a
    /// successful result.
    Completed {
        receiver: PrincipalId,
        user_id: UserId,
        result: WasmResult,
        time: Time,
    },
    /// The message was executed and the execution triggered an error.
    Failed {
        receiver: PrincipalId,
        user_id: UserId,
        error: UserError,
        time: Time,
    },
    /// The message is currently being processed.
    Processing {
        receiver: PrincipalId,
        user_id: UserId,
        time: Time,
    },
    /// The call has completed but the reply/reject data has been pruned.
    Done {
        receiver: PrincipalId,
        user_id: UserId,
        time: Time,
    },
    /// The system has no knowledge of this message.  It may have
    /// expired or it failed to induct.
    Unknown,
}

impl IngressStatus {
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            IngressStatus::Received { user_id, .. } => Some(*user_id),
            IngressStatus::Completed { user_id, .. } => Some(*user_id),
            IngressStatus::Failed { user_id, .. } => Some(*user_id),
            IngressStatus::Processing { user_id, .. } => Some(*user_id),
            IngressStatus::Done { user_id, .. } => Some(*user_id),
            IngressStatus::Unknown => None,
        }
    }

    pub fn receiver(&self) -> Option<CanisterId> {
        match self {
            IngressStatus::Received { receiver, .. } => Some(*receiver),
            IngressStatus::Completed { receiver, .. } => Some(*receiver),
            IngressStatus::Failed { receiver, .. } => Some(*receiver),
            IngressStatus::Processing { receiver, .. } => Some(*receiver),
            IngressStatus::Done { receiver, .. } => Some(*receiver),
            IngressStatus::Unknown => None,
        }
        .map(|receiver| {
            CanisterId::new(receiver).expect("Receiver in IngressStatus must be a Canister ID.")
        })
    }

    /// Returns the name of this status as specified in the interface spec:
    /// https://sdk.dfinity.org/docs/interface-spec/index.html#state-tree-request-status
    pub fn as_str(&self) -> &'static str {
        match self {
            IngressStatus::Received { .. } => "received",
            IngressStatus::Completed {
                result: WasmResult::Reply(_),
                ..
            } => "replied",
            IngressStatus::Completed {
                result: WasmResult::Reject(_),
                ..
            } => "rejected",
            IngressStatus::Failed { .. } => "rejected",
            IngressStatus::Processing { .. } => "processing",
            IngressStatus::Done { .. } => "done",
            IngressStatus::Unknown => "unknown",
        }
    }

    /// Returns the byte size of the payload of the ingress status
    pub fn payload_bytes(&self) -> usize {
        match self {
            IngressStatus::Completed { result, .. } => result.count_bytes(),
            IngressStatus::Failed { error, .. } => error.description().as_bytes().len(),
            IngressStatus::Received { .. }
            | IngressStatus::Processing { .. }
            | IngressStatus::Done { .. }
            | IngressStatus::Unknown => 0,
        }
    }
}

/// A list of hashsets that implements IngressSetQuery.
#[derive(Debug, Clone)]
pub struct IngressSets {
    hash_sets: Vec<Arc<HashSet<IngressMessageId>>>,
    min_block_time: Time,
}

impl IngressSets {
    pub fn new(hash_sets: Vec<Arc<HashSet<IngressMessageId>>>, min_block_time: Time) -> Self {
        IngressSets {
            hash_sets,
            min_block_time,
        }
    }

    pub fn get_hash_sets(&self) -> &Vec<Arc<HashSet<IngressMessageId>>> {
        &self.hash_sets
    }

    pub fn get_min_block_time(&self) -> &Time {
        &self.min_block_time
    }
}

/// This struct describes the different types that executing a Wasm function in
/// a canister can produce
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmResult {
    /// Raw response, returned in a "happy" case
    Reply(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Returned with an error message when the canister decides to reject the
    /// message
    Reject(String),
}

impl CountBytes for WasmResult {
    fn count_bytes(&self) -> usize {
        match self {
            WasmResult::Reply(bytes) => bytes.len(),
            WasmResult::Reject(string) => string.as_bytes().len(),
        }
    }
}

impl WasmResult {
    /// Returns the bytes in the result.
    pub fn bytes(self) -> Vec<u8> {
        match self {
            WasmResult::Reply(bytes) => bytes,
            WasmResult::Reject(string) => string.as_bytes().to_vec(),
        }
    }
}

impl fmt::Display for WasmResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            WasmResult::Reply(_) => write!(f, "reply"),
            WasmResult::Reject(reject_str) => {
                write!(f, "reject with error message => [{}]", reject_str)
            }
        }
    }
}

impl From<&WasmResult> for pb_ingress::ingress_status_completed::WasmResult {
    fn from(item: &WasmResult) -> Self {
        match item {
            WasmResult::Reply(bytes) => {
                pb_ingress::ingress_status_completed::WasmResult::Reply(bytes.clone())
            }
            WasmResult::Reject(str) => {
                pb_ingress::ingress_status_completed::WasmResult::Reject(str.clone())
            }
        }
    }
}

impl From<pb_ingress::ingress_status_completed::WasmResult> for WasmResult {
    fn from(item: pb_ingress::ingress_status_completed::WasmResult) -> Self {
        match item {
            pb_ingress::ingress_status_completed::WasmResult::Reply(bytes) => {
                WasmResult::Reply(bytes)
            }
            pb_ingress::ingress_status_completed::WasmResult::Reject(str) => {
                WasmResult::Reject(str)
            }
        }
    }
}

impl From<&IngressStatus> for pb_ingress::IngressStatus {
    fn from(item: &IngressStatus) -> Self {
        use pb_ingress::ingress_status::Status;

        match item {
            IngressStatus::Received {
                receiver,
                user_id,
                time,
            } => Self {
                status: Some(Status::Received(pb_ingress::IngressStatusReceived {
                    receiver: Some(pb_types::PrincipalId::from(*receiver)),
                    user_id: Some(crate::user_id_into_protobuf(*user_id)),
                    time_nanos: time.as_nanos_since_unix_epoch(),
                })),
            },
            IngressStatus::Completed {
                receiver,
                user_id,
                result,
                time,
            } => Self {
                status: Some(Status::Completed(pb_ingress::IngressStatusCompleted {
                    receiver: Some(pb_types::PrincipalId::from(*receiver)),
                    user_id: Some(crate::user_id_into_protobuf(*user_id)),
                    wasm_result: Some(result.into()),
                    time_nanos: time.as_nanos_since_unix_epoch(),
                })),
            },
            IngressStatus::Failed {
                receiver,
                user_id,
                error,
                time,
            } => Self {
                status: Some(Status::Failed(pb_ingress::IngressStatusFailed {
                    receiver: Some(pb_types::PrincipalId::from(*receiver)),
                    user_id: Some(crate::user_id_into_protobuf(*user_id)),
                    err_code: error.code() as u64,
                    err_description: error.description().to_string(),
                    time_nanos: time.as_nanos_since_unix_epoch(),
                })),
            },
            IngressStatus::Processing {
                receiver,
                user_id,
                time,
            } => Self {
                status: Some(Status::Processing(pb_ingress::IngressStatusProcessing {
                    receiver: Some(pb_types::PrincipalId::from(*receiver)),
                    user_id: Some(crate::user_id_into_protobuf(*user_id)),
                    time_nanos: time.as_nanos_since_unix_epoch(),
                })),
            },
            IngressStatus::Done {
                receiver,
                user_id,
                time,
            } => Self {
                status: Some(Status::Done(pb_ingress::IngressStatusDone {
                    receiver: Some(pb_types::PrincipalId::from(*receiver)),
                    user_id: Some(crate::user_id_into_protobuf(*user_id)),
                    time_nanos: time.as_nanos_since_unix_epoch(),
                })),
            },
            IngressStatus::Unknown => Self {
                status: Some(Status::Unknown(pb_ingress::IngressStatusUnknown {})),
            },
        }
    }
}

impl TryFrom<pb_ingress::IngressStatus> for IngressStatus {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::IngressStatus) -> Result<Self, Self::Error> {
        use pb_ingress::ingress_status::Status;

        Ok(
            match item
                .status
                .ok_or(ProxyDecodeError::MissingField("IngressStatus::status"))?
            {
                Status::Received(r) => IngressStatus::Received {
                    receiver: try_from_option_field(
                        r.receiver,
                        "IngressStatus::Received::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(r.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        r.user_id,
                        "IngressStatus::Received::user_id",
                    )?)?,
                },
                Status::Completed(c) => IngressStatus::Completed {
                    receiver: try_from_option_field(
                        c.receiver,
                        "IngressStatus::Completed::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(c.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        c.user_id,
                        "IngressStatus::Completed::user_id",
                    )?)?,
                    result: try_from_option_field(
                        c.wasm_result,
                        "IngressStatus::Completed::wasm_result",
                    )?,
                },
                Status::Failed(f) => IngressStatus::Failed {
                    receiver: try_from_option_field(f.receiver, "IngressStatus::Failed::receiver")?,
                    time: Time::from_nanos_since_unix_epoch(f.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        f.user_id,
                        "IngressStatus::Failed::user_id",
                    )?)?,
                    error: UserError::new(
                        ErrorCode::try_from(f.err_code).map_err(|err| match err {
                            TryFromError::ValueOutOfRange(code) => {
                                ProxyDecodeError::ValueOutOfRange {
                                    typ: "ErrorCode",
                                    err: code.to_string(),
                                }
                            }
                        })?,
                        f.err_description,
                    ),
                },
                Status::Processing(p) => IngressStatus::Processing {
                    receiver: try_from_option_field(
                        p.receiver,
                        "IngressStatus::Processing::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(p.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        p.user_id,
                        "IngressStatus::Processing::user_id",
                    )?)?,
                },
                Status::Done(p) => IngressStatus::Done {
                    receiver: try_from_option_field(p.receiver, "IngressStatus::Done::receiver")?,
                    time: Time::from_nanos_since_unix_epoch(p.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        p.user_id,
                        "IngressStatus::Done::user_id",
                    )?)?,
                },
                Status::Unknown(_) => IngressStatus::Unknown,
            },
        )
    }
}
