use candid::{CandidType, Deserialize};
use dfn_core::api::CanisterId;
use ic_base_types::{CanisterInstallMode, PrincipalId};
use ic_crypto_sha::Sha256;
use ic_nns_common::types::MethodAuthzChange;
use ic_nns_constants::memory_allocation_of;
use serde::Serialize;

pub const LOG_PREFIX: &str = "[Root Handler] ";

/// Copied from ic-types::ic_00::CanisterIdRecord.
#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterIdRecord {
    canister_id: CanisterId,
}

impl CanisterIdRecord {
    pub fn get_canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl From<CanisterId> for CanisterIdRecord {
    fn from(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

/// Copy-paste of ic-types::ic_00::CanisterStatusType.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub enum CanisterStatusType {
    // The rename statements are mandatory to comply with the candid interface
    // of the IC management canister. For more details, see:
    // https://sdk.dfinity.org/docs/interface-spec/index.html#ic-candid
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

impl std::fmt::Display for CanisterStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanisterStatusType::Running => write!(f, "running"),
            CanisterStatusType::Stopping => write!(f, "stopping"),
            CanisterStatusType::Stopped => write!(f, "stopped"),
        }
    }
}

/// Partial copy-paste of ic-types::ic_00::CanisterStatusResult.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which is simply discarded).
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub controller: PrincipalId,
    pub memory_size: candid::Nat,
}

impl CanisterStatusResult {
    pub fn controller(&self) -> PrincipalId {
        self.controller
    }
}

/// The payload to a proposal to upgrade a canister.
#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct ChangeNnsCanisterProposalPayload {
    /// Whether the canister should first be stopped before the install_code
    /// method is called.
    ///
    /// The value depend on the canister. For instance:
    /// * Canisters that don't emit any inter-canister call, such as the
    ///   registry canister,
    /// have no reason to be stopped before being upgraded.
    /// * Canisters that emit inter-canister call are at risk of undefined
    ///   behavior if
    /// a callback is delivered to them after the upgrade.
    pub stop_before_installing: bool,

    // -------------------------------------------------------------------- //

    // The fields below are copied from ic_types::ic00::InstallCodeArgs.
    /// Whether to Reinstall or Upgrade a canister.
    ///
    /// To be able to repair the NNS in all circumstances, maximum flexibility
    /// is provided. However, using mode `Reinstall` on a stateful canister
    /// is very dangerous: proposal reviewer should be very cautious when
    /// voting on a `Reinstall` proposal.
    pub mode: CanisterInstallMode,

    /// The id of the canister to change.
    pub canister_id: CanisterId,

    /// The new wasm module to ship.
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,

    /// The new canister args
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,

    #[serde(serialize_with = "serialize_optional_nat")]
    pub compute_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub memory_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub query_allocation: Option<candid::Nat>,

    /// A list of authz changes to enact, in addition to changing new canister.
    /// DEPRECATED: Canisters no longer use dynamic authz.
    pub authz_changes: Vec<MethodAuthzChange>,
}

impl ChangeNnsCanisterProposalPayload {
    fn format(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("ChangeNnsCanisterProposalPayload")
            .field("stop_before_installing", &self.stop_before_installing)
            .field("mode", &self.mode)
            .field("canister_id", &self.canister_id)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("arg_sha256", &format!("{:x?}", arg_sha))
            .field("compute_allocation", &self.compute_allocation)
            .field("memory_allocation", &self.memory_allocation)
            .field("query_allocation", &self.query_allocation)
            .field("authz_changes", &self.authz_changes)
            .finish()
    }
}

impl std::fmt::Debug for ChangeNnsCanisterProposalPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl std::fmt::Display for ChangeNnsCanisterProposalPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl ChangeNnsCanisterProposalPayload {
    pub fn new(
        stop_before_installing: bool,
        mode: CanisterInstallMode,
        canister_id: CanisterId,
    ) -> Self {
        Self {
            stop_before_installing,
            mode,
            canister_id,
            wasm_module: Vec::new(),
            arg: Vec::new(),
            compute_allocation: None,
            memory_allocation: Some(candid::Nat::from(memory_allocation_of(canister_id))),
            query_allocation: None,
            authz_changes: Vec::new(),
        }
    }

    pub fn with_wasm(mut self, wasm_module: Vec<u8>) -> Self {
        self.wasm_module = wasm_module;
        self
    }

    pub fn with_arg(mut self, arg: Vec<u8>) -> Self {
        self.arg = arg;
        self
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct AddNnsCanisterProposalPayload {
    /// A unique name for this NNS canister.
    pub name: String,

    // The field belows are copied from ic_types::ic00::InstallCodeArgs.
    /// The new wasm module to ship.
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,

    pub arg: Vec<u8>,

    #[serde(serialize_with = "serialize_optional_nat")]
    pub compute_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub memory_allocation: Option<candid::Nat>,
    #[serde(serialize_with = "serialize_optional_nat")]
    pub query_allocation: Option<candid::Nat>,

    pub initial_cycles: u64,

    /// A list of authz changes to enact, in addition to installing the new
    /// canister. The expected use is to make other NNS canisters allow
    /// calls coming from the newly-added NNS-canister. Authz changes to the
    /// newly added canisters are not expected to be here: instead, they are
    /// expected to belong to the init payload, `arg`.
    pub authz_changes: Vec<MethodAuthzChange>,
}

impl AddNnsCanisterProposalPayload {
    fn format(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("AddNnsCanisterProposalPayload")
            .field("name", &self.name)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("arg_sha256", &format!("{:x?}", arg_sha))
            .field("compute_allocation", &self.compute_allocation)
            .field("memory_allocation", &self.memory_allocation)
            .field("query_allocation", &self.query_allocation)
            .field("initial_cycles", &self.initial_cycles)
            .field("authz_changes", &self.authz_changes)
            .finish()
    }
}

impl std::fmt::Debug for AddNnsCanisterProposalPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

impl std::fmt::Display for AddNnsCanisterProposalPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f)
    }
}

// The action to take on the canister.
#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub enum CanisterAction {
    Stop,
    Start,
}

// A proposal payload to start/stop any NNS canister.
#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct StopOrStartNnsCanisterProposalPayload {
    pub canister_id: CanisterId,
    pub action: CanisterAction,
}

// Use a serde field attribute to custom serialize the Nat candid type.
fn serialize_optional_nat<S>(nat: &Option<candid::Nat>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match nat.as_ref() {
        Some(num) => serializer.serialize_str(&num.to_string()),
        None => serializer.serialize_none(),
    }
}
