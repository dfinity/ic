//! This module contains a collection of types and structs that define the
//! various types of methods in the IC.

use crate::{messages::CallContextId, Cycles};
use ic_base_types::CanisterId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::{canister_state_bits::v1 as pb, queues::v1::Cycles as PbCycles};
use ic_protobuf::types::v1 as pb_types;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom},
    fmt,
};

/// Represents the types of methods that a Wasm module can export.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    /// An exported system method. Unlike query or update method, there
    /// are a few fixed system methods as defined in `SystemMethod`.
    System(SystemMethod),
}

impl WasmMethod {
    pub fn name(&self) -> String {
        match self {
            Self::Update(name) => name.to_string(),
            Self::Query(name) => name.to_string(),
            Self::System(system_method) => system_method.to_string(),
        }
    }
}

impl fmt::Display for WasmMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Update(name) => write!(f, "canister_update {}", name),
            Self::Query(name) => write!(f, "canister_query {}", name),
            Self::System(system_method) => system_method.fmt(f),
        }
    }
}

impl TryFrom<String> for WasmMethod {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.starts_with("canister_update ") {
            // Take the part after the first space
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Update(parts[1].to_string()))
        } else if name.starts_with("canister_query ") {
            // Take the part after the first space
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Query(parts[1].to_string()))
        } else {
            match SystemMethod::try_from(name.as_ref()) {
                Ok(system_method) => Ok(WasmMethod::System(system_method)),
                _ => Err(format!("Cannot convert {} to WasmFunction.", name)),
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
            WasmMethod::System(value) => Self {
                wasm_method: Some(PbWasmMethod::System(match value {
                    SystemMethod::CanisterStart => PbSystemMethod::CanisterStart,
                    SystemMethod::CanisterInit => PbSystemMethod::CanisterInit,
                    SystemMethod::CanisterPreUpgrade => PbSystemMethod::CanisterPreUpgrade,
                    SystemMethod::CanisterPostUpgrade => PbSystemMethod::CanisterPostUpgrade,
                    SystemMethod::CanisterInspectMessage => PbSystemMethod::CanisterInspectMessage,
                    SystemMethod::CanisterHeartbeat => PbSystemMethod::CanisterHeartbeat,
                    SystemMethod::Empty => PbSystemMethod::Empty,
                } as i32)),
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
            PbWasmMethod::System(system) => {
                let method =
                    PbSystemMethod::from_i32(system).unwrap_or(PbSystemMethod::Unspecified);

                Ok(Self::System(match method {
                    PbSystemMethod::Unspecified => {
                        return Err(ProxyDecodeError::ValueOutOfRange {
                            typ: "WasmMethod::System",
                            err: system.to_string(),
                        })
                    }
                    PbSystemMethod::CanisterStart => SystemMethod::CanisterStart,
                    PbSystemMethod::CanisterInit => SystemMethod::CanisterInit,
                    PbSystemMethod::CanisterPreUpgrade => SystemMethod::CanisterPreUpgrade,
                    PbSystemMethod::CanisterPostUpgrade => SystemMethod::CanisterPostUpgrade,
                    PbSystemMethod::CanisterInspectMessage => SystemMethod::CanisterInspectMessage,
                    PbSystemMethod::CanisterHeartbeat => SystemMethod::CanisterHeartbeat,
                    PbSystemMethod::Empty => SystemMethod::Empty,
                }))
            }
        }
    }
}

/// The various system methods available to canisters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SystemMethod {
    /// A system method for initializing a Wasm module.
    CanisterStart,
    /// A system method that is run when initializing a canister.
    CanisterInit,
    /// A system method that is run at the beginning of a canister upgrade.
    CanisterPreUpgrade,
    /// A system method that is run at the end of a canister upgrade.
    CanisterPostUpgrade,
    /// A system method that is run pre-consensus to ask the canister if it
    /// wants to accept an ingress message.
    CanisterInspectMessage,
    /// A system method that is run at regular intervals for cron support.
    CanisterHeartbeat,
    /// This is introduced as temporary scaffolding to aid in construction of
    /// the initial ExecutionState. This isn't used to execute any actual wasm
    /// but as a way to get to the wasm embedder from execution. Eventually, we
    /// need to rethink some of the API between execution and wasm embedder so
    /// that this is not needed.
    Empty,
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
            "empty" => Ok(SystemMethod::Empty),
            _ => Err(format!("Cannot convert {} to SystemMethod.", value)),
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
            Self::Empty => write!(f, "empty"),
        }
    }
}

/// A Wasm closure pointing to the Wasm function table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmClosure {
    pub func_idx: u32,
    pub env: u32,
}

impl WasmClosure {
    pub fn new(func_idx: u32, env: u32) -> Self {
        Self { func_idx, env }
    }
}

/// Callback holds references to functions executed when a response is received.
/// It also tracks information about the origin of the request.
/// This information is used to validate the response when it is received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Callback {
    pub call_context_id: CallContextId,
    // (EXC-877) Once this is deployed in production,
    // it's safe to make `respondent` and `originator` non-optional.
    // Currently optional to ensure backwards compatibility.
    /// The request's sender id.
    pub originator: Option<CanisterId>,
    /// The id of the principal that the request was addressed to.
    pub respondent: Option<CanisterId>,
    /// The number of cycles that were sent in the original request.
    pub cycles_sent: Cycles,
    /// A closure to be executed if the call succeeded.
    pub on_reply: WasmClosure,
    /// A closure to be executed if the call was rejected.
    pub on_reject: WasmClosure,
    /// An optional closure to be executed if the execution of `on_reply` or
    /// `on_reject` traps.
    pub on_cleanup: Option<WasmClosure>,
}

impl Callback {
    pub fn new(
        call_context_id: CallContextId,
        originator: Option<CanisterId>,
        respondent: Option<CanisterId>,
        cycles_sent: Cycles,
        on_reply: WasmClosure,
        on_reject: WasmClosure,
        on_cleanup: Option<WasmClosure>,
    ) -> Self {
        Self {
            call_context_id,
            originator,
            respondent,
            cycles_sent,
            on_reply,
            on_reject,
            on_cleanup,
        }
    }
}

impl From<&Callback> for pb::Callback {
    fn from(item: &Callback) -> Self {
        Self {
            call_context_id: item.call_context_id.get(),
            originator: item
                .originator
                .as_ref()
                .map(|originator| pb_types::CanisterId::from(*originator)),
            respondent: item
                .respondent
                .as_ref()
                .map(|respondent| pb_types::CanisterId::from(*respondent)),
            cycles_sent: Some(item.cycles_sent.into()),
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

        Ok(Self {
            call_context_id: CallContextId::from(value.call_context_id),
            originator: try_from_option_field(value.originator, "Callback::originator").ok(),
            respondent: try_from_option_field(value.respondent, "Callback::respondent").ok(),
            cycles_sent: Cycles::from(cycles_sent),
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
        })
    }
}

/// A reference to a callable function/method in a Wasm module, which can be:
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FuncRef {
    /// A method that a canister can export.
    Method(WasmMethod),

    /// A closure (index + env) pointing to the Wasm function table. Using
    /// indexes here is ok only as long as Wasm code cannot modify their
    /// tables, once that is possible we have to use Wasm `funcref`s.
    UpdateClosure(WasmClosure),

    QueryClosure(WasmClosure),
}

impl FuncRef {
    /// We utilize the function reference `FuncRef` to decide if a
    /// state modification resulting from evaluating of the proposed
    /// function reference should be committed or not.
    pub fn to_commit(&self) -> bool {
        match self {
            Self::Method(WasmMethod::Update(_))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterStart))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterInit))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterPreUpgrade))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterPostUpgrade))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterHeartbeat))
            | Self::UpdateClosure(_) => true,
            Self::QueryClosure(_)
            | Self::Method(WasmMethod::Query(_))
            | Self::Method(WasmMethod::System(SystemMethod::Empty))
            | Self::Method(WasmMethod::System(SystemMethod::CanisterInspectMessage)) => false,
        }
    }
}
