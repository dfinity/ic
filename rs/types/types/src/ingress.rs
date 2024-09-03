//! Ingress types.

use crate::artifact::IngressMessageId;
use crate::{CanisterId, CountBytes, PrincipalId, Time, UserId};
use ic_error_types::{ErrorCode, UserError};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::{convert::TryFrom, fmt};

/// The inner state of an ingress message.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum IngressState {
    /// The message was successfully inducted into the input queue of
    /// the receiver and should eventually execute.
    ///
    /// Note that inducted messages can expire if they haven't executed within
    /// some time.
    Received,
    /// The message was executed and the execution yielded a
    /// successful result.
    Completed(WasmResult),
    /// The message was executed and the execution triggered an error.
    Failed(UserError),
    /// The message is currently being processed.
    Processing,
    /// The call has completed but the reply/reject data has been pruned.
    Done,
}

impl IngressState {
    /// Returns `true` if this is one of the terminal states (`Completed`, `Failed`
    /// or `Done`) that automatically expire after a timeout.
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Received | Self::Processing => false,
            Self::Completed(_) | Self::Failed(_) | Self::Done => true,
        }
    }

    /// Returns `true` if this is one of the terminal states (that automatically
    /// expire after a timeout) with a payload (`Completed` or `Failed`).
    pub fn is_terminal_with_payload(&self) -> bool {
        match self {
            Self::Received | Self::Processing | Self::Done => false,
            Self::Completed(_) | Self::Failed(_) => true,
        }
    }
}

/// The status of an ingress message.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum IngressStatus {
    /// The system has knowledge of this message, its status is
    /// described by state
    Known {
        receiver: PrincipalId,
        user_id: UserId,
        time: Time,
        state: IngressState,
    },
    /// The system has no knowledge of this message.  It may have
    /// expired or it failed to induct.
    Unknown,
}

impl IngressStatus {
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            IngressStatus::Known { user_id, .. } => Some(*user_id),
            IngressStatus::Unknown => None,
        }
    }

    pub fn receiver(&self) -> Option<CanisterId> {
        match self {
            IngressStatus::Known { receiver, .. } => Some(*receiver),
            IngressStatus::Unknown => None,
        }
        .map(CanisterId::unchecked_from_principal)
    }

    /// Returns the name of this status as specified in the interface spec:
    /// `<https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-request-status>`
    pub fn as_str(&self) -> &'static str {
        match self {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Received => "received",
                IngressState::Completed(WasmResult::Reply(_)) => "replied",
                IngressState::Completed(WasmResult::Reject(_)) => "rejected",
                IngressState::Failed(_) => "rejected",
                IngressState::Processing => "processing",
                IngressState::Done => "done",
            },
            IngressStatus::Unknown => "unknown",
        }
    }

    /// Returns the byte size of the payload of the ingress status
    pub fn payload_bytes(&self) -> usize {
        match self {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Completed(result) => result.count_bytes(),
                IngressState::Failed(error) => error.description().as_bytes().len(),
                _ => 0,
            },
            IngressStatus::Unknown => 0,
        }
    }

    /// Checks whether the state transition from `self` to `new_status` is valid.
    pub fn is_valid_state_transition(&self, new_status: &IngressStatus) -> bool {
        use IngressState::*;
        use IngressStatus::*;
        match (self, new_status) {
            (Unknown, _) => true,
            (Known { .. }, Unknown) => false,
            (
                Known { state, .. },
                Known {
                    state: new_state, ..
                },
            ) => matches!(
                (&state, &new_state),
                (Received, Processing)
                    | (Received, Completed(_))
                    | (Received, Failed(_))
                    | (Processing, Processing)
                    | (Processing, Completed(_))
                    | (Processing, Failed(_))
            ),
        }
    }
}

/// A list of hashsets that implements IngressSetQuery.
#[derive(Clone, Debug)]
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
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
            IngressStatus::Known {
                receiver,
                user_id,
                time,
                state,
            } => match state {
                IngressState::Received => Self {
                    status: Some(Status::Received(pb_ingress::IngressStatusReceived {
                        receiver: Some(pb_types::PrincipalId::from(*receiver)),
                        user_id: Some(crate::user_id_into_protobuf(*user_id)),
                        time_nanos: time.as_nanos_since_unix_epoch(),
                    })),
                },
                IngressState::Completed(result) => Self {
                    status: Some(Status::Completed(pb_ingress::IngressStatusCompleted {
                        receiver: Some(pb_types::PrincipalId::from(*receiver)),
                        user_id: Some(crate::user_id_into_protobuf(*user_id)),
                        wasm_result: Some(result.into()),
                        time_nanos: time.as_nanos_since_unix_epoch(),
                    })),
                },
                IngressState::Failed(error) => Self {
                    status: Some(Status::Failed(pb_ingress::IngressStatusFailed {
                        receiver: Some(pb_types::PrincipalId::from(*receiver)),
                        user_id: Some(crate::user_id_into_protobuf(*user_id)),
                        err_description: error.description().to_string(),
                        time_nanos: time.as_nanos_since_unix_epoch(),
                        err_code: pb_ingress::ErrorCode::from(error.code()).into(),
                    })),
                },
                IngressState::Processing => Self {
                    status: Some(Status::Processing(pb_ingress::IngressStatusProcessing {
                        receiver: Some(pb_types::PrincipalId::from(*receiver)),
                        user_id: Some(crate::user_id_into_protobuf(*user_id)),
                        time_nanos: time.as_nanos_since_unix_epoch(),
                    })),
                },
                IngressState::Done => Self {
                    status: Some(Status::Done(pb_ingress::IngressStatusDone {
                        receiver: Some(pb_types::PrincipalId::from(*receiver)),
                        user_id: Some(crate::user_id_into_protobuf(*user_id)),
                        time_nanos: time.as_nanos_since_unix_epoch(),
                    })),
                },
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
                Status::Received(r) => IngressStatus::Known {
                    receiver: try_from_option_field(
                        r.receiver,
                        "IngressStatus::Received::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(r.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        r.user_id,
                        "IngressStatus::Received::user_id",
                    )?)?,
                    state: IngressState::Received,
                },
                Status::Completed(c) => IngressStatus::Known {
                    receiver: try_from_option_field(
                        c.receiver,
                        "IngressStatus::Completed::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(c.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        c.user_id,
                        "IngressStatus::Completed::user_id",
                    )?)?,
                    state: IngressState::Completed(try_from_option_field(
                        c.wasm_result,
                        "IngressStatus::Completed::wasm_result",
                    )?),
                },
                Status::Failed(f) => IngressStatus::Known {
                    receiver: try_from_option_field(f.receiver, "IngressStatus::Failed::receiver")?,
                    time: Time::from_nanos_since_unix_epoch(f.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        f.user_id,
                        "IngressStatus::Failed::user_id",
                    )?)?,
                    state: IngressState::Failed(UserError::from_proto(
                        ErrorCode::try_from(pb_ingress::ErrorCode::try_from(f.err_code).map_err(
                            |_| ProxyDecodeError::ValueOutOfRange {
                                typ: "ErrorCode",
                                err: f.err_code.to_string(),
                            },
                        )?)?,
                        f.err_description,
                    )),
                },
                Status::Processing(p) => IngressStatus::Known {
                    receiver: try_from_option_field(
                        p.receiver,
                        "IngressStatus::Processing::receiver",
                    )?,
                    time: Time::from_nanos_since_unix_epoch(p.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        p.user_id,
                        "IngressStatus::Processing::user_id",
                    )?)?,
                    state: IngressState::Processing,
                },
                Status::Done(p) => IngressStatus::Known {
                    receiver: try_from_option_field(p.receiver, "IngressStatus::Done::receiver")?,
                    time: Time::from_nanos_since_unix_epoch(p.time_nanos),
                    user_id: crate::user_id_try_from_protobuf(try_from_option_field(
                        p.user_id,
                        "IngressStatus::Done::user_id",
                    )?)?,
                    state: IngressState::Done,
                },
                Status::Unknown(_) => IngressStatus::Unknown,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exhaustive::ExhaustiveSet;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

    #[test]
    fn wasm_result_proto_round_trip() {
        for result in WasmResult::exhaustive_set(&mut reproducible_rng()) {
            let encoded = pb_ingress::ingress_status_completed::WasmResult::from(&result);
            let round_trip = WasmResult::from(encoded);

            assert_eq!(result, round_trip);
        }
    }
}
