//! Ingress types.

use crate::messages::MAX_RESPONSE_COUNT_BYTES;
use crate::{CanisterId, CountBytes, PrincipalId, Time, UserId};
use ic_error_types::{ErrorCode, UserError};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, time::Duration};

/// This constant defines the maximum amount of time an ingress message can wait
/// to start executing after submission before it is expired.  Hence, if an
/// ingress message is submitted at time `t` and it has not been scheduled for
/// execution till time `t+MAX_INGRESS_TTL`, it will be expired.
///
/// At the time of writing, this constant is also used to control how long the
/// status of a completed ingress message (IngressStatus ∈ [Completed, Failed])
/// is maintained by the IC before it is deleted from the ingress history.
pub const MAX_INGRESS_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Duration subtracted from `MAX_INGRESS_TTL` by
/// `current_time_and_expiry_time()` when creating an ingress message.
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);

/// Duration added to `MAX_INGRESS_TTL` when checking the max allowed
/// expiry at the http handler. The purpose is to admit ingress created with
/// MAX_INGRESS_TTL by clients with a slightly skewed local clock instead
/// of rejecting them right away.
pub const PERMITTED_DRIFT_AT_VALIDATOR: Duration = Duration::from_secs(30);

/// Duration added to `MAX_INGRESS_TTL` when checking the max allowed expiry
/// at the artifact manager when it receives ingress from http_handler or p2p.
/// The purpose is to account for time drift between subnet nodes.
///
/// Together with `PERMITTED_DRIFT_AT_VALIDATOR` we give some leeway to
/// accommodate possible time drift both between the user client and a subnet
/// node, and between subnet nodes.
///
/// Note that when a blockmaker creates a payload, it will only choose from
/// its ingress pool based on MAX_INGRESS_TTL. So time drift considerations
/// may lead to more messages being admitted to the ingress pool, but
/// shouldn't impact other parts of the system.
pub const PERMITTED_DRIFT_AT_ARTIFACT_MANAGER: Duration = Duration::from_secs(60);

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
            IngressStatus::Unknown => None,
        }
    }

    pub fn receiver(&self) -> Option<CanisterId> {
        match self {
            IngressStatus::Received { receiver, .. } => Some(*receiver),
            IngressStatus::Completed { receiver, .. } => Some(*receiver),
            IngressStatus::Failed { receiver, .. } => Some(*receiver),
            IngressStatus::Processing { receiver, .. } => Some(*receiver),
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
            IngressStatus::Unknown => "unknown",
        }
    }
}

impl CountBytes for IngressStatus {
    /// For "terminal" statuses the actual size is returned, whereas `MAX_RESPONSE_COUNT_BYTES` is
    /// returned for statuses that can still go to `Completed` or `Failed`.
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<IngressStatus>()
            + match self {
                IngressStatus::Completed { result, .. } => result.count_bytes(),
                IngressStatus::Failed { error, .. } => error.description().as_bytes().len(),
                IngressStatus::Received { .. } | IngressStatus::Processing { .. } => {
                    MAX_RESPONSE_COUNT_BYTES
                }
                IngressStatus::Unknown => 0,
            }
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
                    receiver: try_from_option_field(
                        f.receiver,
                        "IngressStatus::Completed::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(f.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        f.user_id,
                        "IngressStatus::Failed::user_id",
                    )?)?,
                    error: UserError::new(ErrorCode::try_from(f.err_code)?, f.err_description),
                },
                Status::Processing(p) => IngressStatus::Processing {
                    receiver: try_from_option_field(
                        p.receiver,
                        "IngressStatus::Completed::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(p.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        p.user_id,
                        "IngressStatus::Processing::user_id",
                    )?)?,
                },
                Status::Unknown(_) => IngressStatus::Unknown,
            },
        )
    }
}
