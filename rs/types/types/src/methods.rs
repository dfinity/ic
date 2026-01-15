//! This module contains a collection of types and structs that define the
//! various types of methods in the IC.

use crate::{Cycles, messages::CallContextId, time::CoarseTime};
use ic_base_types::{CanisterId, PrincipalId};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_heap_bytes::DeterministicHeapBytes;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::{canister_state_bits::v1 as pb, queues::v1::Cycles as PbCycles};
use ic_protobuf::types::v1 as pb_types;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom},
    fmt,
};
use strum_macros::EnumIter;

/// Represents the types of methods that a Wasm module can export.
#[derive(
    Clone, DeterministicHeapBytes, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize,
)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum WasmMethod {
    /// An exported update method along with its name.
    ///
    /// Modifications by update calls are persisted upon successful execution.
    Update(String),

    /// An exported query method along with its name.
    ///
    /// Modifications by query calls are NOT persisted upon successful
    /// execution.
    Query(String),

    /// An exported composite query method along with its name.
    /// It is similar to `Query` method above, but support query calls
    /// and for now does not support replicated execution.
    CompositeQuery(String),

    /// An exported system method. Unlike query or update method, there
    /// are a few fixed system methods as defined in `SystemMethod`.
    System(SystemMethod),
}

impl WasmMethod {
    pub fn name(&self) -> String {
        match self {
            Self::Update(name) => name.to_string(),
            Self::Query(name) => name.to_string(),
            Self::CompositeQuery(name) => name.to_string(),
            Self::System(system_method) => system_method.to_string(),
        }
    }
}

impl fmt::Display for WasmMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Update(name) => write!(f, "canister_update {name}"),
            Self::Query(name) => write!(f, "canister_query {name}"),
            Self::CompositeQuery(name) => write!(f, "canister_composite_query {name}"),
            Self::System(system_method) => system_method.fmt(f),
        }
    }
}

impl TryFrom<String> for WasmMethod {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.starts_with("canister_update ") {
            // Take the part after the first space.
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Update(parts[1].to_string()))
        } else if name.starts_with("canister_query ") {
            // Take the part after the first space.
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Query(parts[1].to_string()))
        } else if name.starts_with("canister_composite_query ") {
            // Take the part after the first space.
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::CompositeQuery(parts[1].to_string()))
        } else {
            match SystemMethod::try_from(name.as_ref()) {
                Ok(name) => Ok(WasmMethod::System(name)),
                _ => Err(format!("Cannot convert {name} to WasmFunction.")),
            }
        }
    }
}

impl From<&WasmMethod> for pb::WasmMethod {
    fn from(method: &WasmMethod) -> Self {
        use pb::wasm_method::{SystemMethod as PbSystemMethod, WasmMethod as PbWasmMethod};

        match method {
            WasmMethod::Update(value) => Self {
                wasm_method: Some(PbWasmMethod::Update(value.clone())),
            },
            WasmMethod::Query(value) => Self {
                wasm_method: Some(PbWasmMethod::Query(value.clone())),
            },
            WasmMethod::CompositeQuery(value) => Self {
                wasm_method: Some(PbWasmMethod::CompositeQuery(value.clone())),
            },
            WasmMethod::System(value) => Self {
                wasm_method: Some(PbWasmMethod::System(PbSystemMethod::from(value).into())),
            },
        }
    }
}

impl TryFrom<pb::WasmMethod> for WasmMethod {
    type Error = ProxyDecodeError;

    fn try_from(method: pb::WasmMethod) -> Result<Self, Self::Error> {
        use pb::wasm_method::{SystemMethod as PbSystemMethod, WasmMethod as PbWasmMethod};

        match try_from_option_field(method.wasm_method, "WasmMethod::wasm_method")? {
            PbWasmMethod::Update(update) => Ok(Self::Update(update)),
            PbWasmMethod::Query(query) => Ok(Self::Query(query)),
            PbWasmMethod::CompositeQuery(query) => Ok(Self::CompositeQuery(query)),
            PbWasmMethod::System(system) => {
                let method =
                    PbSystemMethod::try_from(system).unwrap_or(PbSystemMethod::Unspecified);

                Ok(Self::System(SystemMethod::try_from(method)?))
            }
        }
    }
}

/// The various system methods available to canisters.
#[derive(
    Clone,
    DeterministicHeapBytes,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    Deserialize,
    EnumIter,
    Serialize,
)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum SystemMethod {
    /// A system method for initializing a Wasm module.
    CanisterStart = 1,
    /// A system method that is run when initializing a canister.
    CanisterInit = 2,
    /// A system method that is run at the beginning of a canister upgrade.
    CanisterPreUpgrade = 3,
    /// A system method that is run at the end of a canister upgrade.
    CanisterPostUpgrade = 4,
    /// A system method that is run pre-consensus to ask the canister if it
    /// wants to accept an ingress message.
    CanisterInspectMessage = 5,
    /// A system method that is run at regular intervals for cron support.
    CanisterHeartbeat = 6,
    /// A system method that is run after a specified time.
    CanisterGlobalTimer = 7,
    /// A system method that runs when the available Wasm memory is below threshold.
    CanisterOnLowWasmMemory = 8,
}

impl TryFrom<&str> for SystemMethod {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "canister_pre_upgrade" => Ok(SystemMethod::CanisterPreUpgrade),
            "canister_post_upgrade" => Ok(SystemMethod::CanisterPostUpgrade),
            "canister_init" => Ok(SystemMethod::CanisterInit),
            "canister_start" => Ok(SystemMethod::CanisterStart),
            "canister_inspect_message" => Ok(SystemMethod::CanisterInspectMessage),
            "canister_heartbeat" => Ok(SystemMethod::CanisterHeartbeat),
            "canister_global_timer" => Ok(SystemMethod::CanisterGlobalTimer),
            "canister_on_low_wasm_memory" => Ok(SystemMethod::CanisterOnLowWasmMemory),
            _ => Err(format!("Cannot convert {value} to SystemMethod.")),
        }
    }
}

impl fmt::Display for SystemMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::CanisterPreUpgrade => write!(f, "canister_pre_upgrade"),
            Self::CanisterPostUpgrade => write!(f, "canister_post_upgrade"),
            Self::CanisterInit => write!(f, "canister_init"),
            Self::CanisterStart => write!(f, "canister_start"),
            Self::CanisterInspectMessage => write!(f, "canister_inspect_message"),
            Self::CanisterHeartbeat => write!(f, "canister_heartbeat"),
            Self::CanisterGlobalTimer => write!(f, "canister_global_timer"),
            Self::CanisterOnLowWasmMemory => write!(f, "canister_on_low_wasm_memory"),
        }
    }
}

impl From<&SystemMethod> for pb::wasm_method::SystemMethod {
    fn from(method: &SystemMethod) -> Self {
        use pb::wasm_method::SystemMethod as PbSystemMethod;

        match method {
            SystemMethod::CanisterStart => PbSystemMethod::CanisterStart,
            SystemMethod::CanisterInit => PbSystemMethod::CanisterInit,
            SystemMethod::CanisterPreUpgrade => PbSystemMethod::CanisterPreUpgrade,
            SystemMethod::CanisterPostUpgrade => PbSystemMethod::CanisterPostUpgrade,
            SystemMethod::CanisterInspectMessage => PbSystemMethod::CanisterInspectMessage,
            SystemMethod::CanisterHeartbeat => PbSystemMethod::CanisterHeartbeat,
            SystemMethod::CanisterGlobalTimer => PbSystemMethod::CanisterGlobalTimer,
            SystemMethod::CanisterOnLowWasmMemory => PbSystemMethod::CanisterOnLowWasmMemory,
        }
    }
}

impl TryFrom<pb::wasm_method::SystemMethod> for SystemMethod {
    type Error = ProxyDecodeError;

    fn try_from(method: pb::wasm_method::SystemMethod) -> Result<Self, Self::Error> {
        use pb::wasm_method::SystemMethod as PbSystemMethod;

        match method {
            PbSystemMethod::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "SystemMethod",
                err: format!("Unknown value for system method {method:?}"),
            }),
            PbSystemMethod::CanisterStart => Ok(SystemMethod::CanisterStart),
            PbSystemMethod::CanisterInit => Ok(SystemMethod::CanisterInit),
            PbSystemMethod::CanisterPreUpgrade => Ok(SystemMethod::CanisterPreUpgrade),
            PbSystemMethod::CanisterPostUpgrade => Ok(SystemMethod::CanisterPostUpgrade),
            PbSystemMethod::CanisterInspectMessage => Ok(SystemMethod::CanisterInspectMessage),
            PbSystemMethod::CanisterHeartbeat => Ok(SystemMethod::CanisterHeartbeat),
            PbSystemMethod::CanisterGlobalTimer => Ok(SystemMethod::CanisterGlobalTimer),
            PbSystemMethod::CanisterOnLowWasmMemory => Ok(SystemMethod::CanisterOnLowWasmMemory),
        }
    }
}

/// A Wasm closure pointing to the Wasm function table.
///
/// Wasm closures must be created and consumed either as 32- or 64-bit.
/// If the canister migrates from `wasm32` to `wasm64` or back having some
/// outstanding calls, we will try to convert the stored values into
/// the required type and call the function.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct WasmClosure {
    pub func_idx: u32,
    pub env: u64,
}

impl WasmClosure {
    pub fn new(func_idx: u32, env: u64) -> Self {
        Self { func_idx, env }
    }
}

/// A placeholder `CanisterId` for the `Callback::originator` and
/// `Callback::respondent` fields, if the callback was created before February
/// 2022 (i.e. before originator and respondent were recorded).
pub const UNKNOWN_CANISTER_ID: CanisterId =
    CanisterId::unchecked_from_principal(PrincipalId::new_anonymous());

/// Callback holds references to functions executed when a response is received.
/// It also tracks information about the origin of the request.
/// This information is used to validate the response when it is received.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Callback {
    pub call_context_id: CallContextId,
    /// The request sender's ID.
    pub originator: CanisterId,
    /// The ID of the principal that the request was addressed to.
    pub respondent: CanisterId,
    /// The number of cycles that were sent in the original request.
    pub cycles_sent: Cycles,
    /// Cycles prepaid by the caller for response execution.
    ///
    /// `Cycles::zero()` if the `Callback` was created before February 2022.
    pub prepayment_for_response_execution: Cycles,
    /// Cycles prepaid by the caller for response transimission.
    ///
    /// `Cycles::zero()` if the `Callback` was created before February 2022.
    pub prepayment_for_response_transmission: Cycles,
    /// A closure to be executed if the call succeeded.
    pub on_reply: WasmClosure,
    /// A closure to be executed if the call was rejected.
    pub on_reject: WasmClosure,
    /// An optional closure to be executed if the execution of `on_reply` or
    /// `on_reject` traps.
    pub on_cleanup: Option<WasmClosure>,
    /// If non-zero, this is a best-effort call.
    pub deadline: CoarseTime,
}

impl Callback {
    pub fn new(
        call_context_id: CallContextId,
        originator: CanisterId,
        respondent: CanisterId,
        cycles_sent: Cycles,
        prepayment_for_response_execution: Cycles,
        prepayment_for_response_transmission: Cycles,
        on_reply: WasmClosure,
        on_reject: WasmClosure,
        on_cleanup: Option<WasmClosure>,
        deadline: CoarseTime,
    ) -> Self {
        Self {
            call_context_id,
            originator,
            respondent,
            cycles_sent,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
            on_reply,
            on_reject,
            on_cleanup,
            deadline,
        }
    }
}

impl From<&Callback> for pb::Callback {
    fn from(item: &Callback) -> Self {
        Self {
            call_context_id: item.call_context_id.get(),
            originator: Some(pb_types::CanisterId::from(item.originator)),
            respondent: Some(pb_types::CanisterId::from(item.respondent)),
            cycles_sent: Some(item.cycles_sent.into()),
            prepayment_for_response_execution: Some(item.prepayment_for_response_execution.into()),
            prepayment_for_response_transmission: Some(
                item.prepayment_for_response_transmission.into(),
            ),
            on_reply: Some(pb::WasmClosure {
                func_idx: item.on_reply.func_idx,
                env: item.on_reply.env,
            }),
            on_reject: Some(pb::WasmClosure {
                func_idx: item.on_reject.func_idx,
                env: item.on_reject.env,
            }),
            on_cleanup: item.on_cleanup.clone().map(|on_cleanup| pb::WasmClosure {
                func_idx: on_cleanup.func_idx,
                env: on_cleanup.env,
            }),
            deadline_seconds: item.deadline.as_secs_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb::Callback> for Callback {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::Callback) -> Result<Self, Self::Error> {
        let on_reply: pb::WasmClosure =
            try_from_option_field(value.on_reply, "Callback::on_reply")?;
        let on_reject: pb::WasmClosure =
            try_from_option_field(value.on_reject, "Callback::on_reject")?;
        let cycles_sent: PbCycles =
            try_from_option_field(value.cycles_sent, "Callback::cycles_sent")?;

        let prepayment_for_response_execution = try_from_option_field(
            value.prepayment_for_response_execution,
            "Callback::prepayment_for_response_execution",
        )?;
        let prepayment_for_response_transmission = try_from_option_field(
            value.prepayment_for_response_transmission,
            "Callback::prepayment_for_response_transmission",
        )?;

        Ok(Self {
            call_context_id: CallContextId::from(value.call_context_id),
            originator: try_from_option_field(value.originator, "Callback::originator")?,
            respondent: try_from_option_field(value.respondent, "Callback::respondent")?,
            cycles_sent: Cycles::from(cycles_sent),
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
            on_reply: WasmClosure {
                func_idx: on_reply.func_idx,
                env: on_reply.env,
            },
            on_reject: WasmClosure {
                func_idx: on_reject.func_idx,
                env: on_reject.env,
            },
            on_cleanup: value.on_cleanup.map(|on_cleanup| WasmClosure {
                func_idx: on_cleanup.func_idx,
                env: on_cleanup.env,
            }),
            deadline: CoarseTime::from_secs_since_unix_epoch(value.deadline_seconds),
        })
    }
}

/// A reference to a callable function/method in a Wasm module, which can be:
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum FuncRef {
    /// A method that a canister can export.
    Method(WasmMethod),

    /// A closure (index + env) pointing to the Wasm function table. Using
    /// indexes here is ok only as long as Wasm code cannot modify their
    /// tables, once that is possible we have to use Wasm `funcref`s.
    UpdateClosure(WasmClosure),

    QueryClosure(WasmClosure),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exhaustive::ExhaustiveSet;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_protobuf::state::canister_state_bits::v1 as pb;
    use strum::IntoEnumIterator;

    #[test]
    fn system_method_proto_round_trip() {
        for initial in SystemMethod::iter() {
            let encoded = pb::wasm_method::SystemMethod::from(&initial);
            let round_trip = SystemMethod::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_system_method() {
        // If this fails, you are making a potentially incompatible change to `SystemMethod`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            SystemMethod::iter().map(|x| x as i32).collect::<Vec<i32>>(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn wasm_method_proto_round_trip() {
        for method in WasmMethod::exhaustive_set(&mut reproducible_rng()) {
            let encoded = pb::WasmMethod::from(&method);
            let round_trip = WasmMethod::try_from(encoded).unwrap();

            assert_eq!(method, round_trip);
        }
    }
}
