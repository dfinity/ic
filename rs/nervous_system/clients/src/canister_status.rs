use crate::canister_id_record::CanisterIdRecord;
use candid::{CandidType, Deserialize};
use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_management_canister_types::IC_00;
use ic_nervous_system_runtime::Runtime;
use num_traits::cast::ToPrimitive;

impl TryFrom<PrincipalId> for CanisterIdRecord {
    type Error = String;

    fn try_from(principal_id: PrincipalId) -> Result<Self, Self::Error> {
        let canister_id = match CanisterId::try_from(principal_id) {
            Ok(canister_id) => canister_id,
            Err(err) => return Err(format!("{}", err)),
        };

        Ok(canister_id.into())
    }
}

/// Copy-paste of ic-types::ic_00::CanisterStatusType.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize)]
pub enum CanisterStatusType {
    // The rename statements are mandatory to comply with the candid interface
    // of the IC management canister. For more details, see:
    // https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-candid
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    #[default]
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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize)]
pub enum LogVisibility {
    #[default]
    #[serde(rename = "controllers")]
    Controllers = 1,
    #[serde(rename = "public")]
    Public = 2,
}

/// Partial copy-paste of ic-types::ic_00::DefiniteCanisterSettings.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which is simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettings {
    pub controllers: Vec<PrincipalId>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
}

/// Partial copy-paste of ic-types::ic_00::CanisterStatusResult.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which are simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusType,
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub module_hash: Option<Vec<u8>>,
    pub memory_size: candid::Nat,
    pub settings: DefiniteCanisterSettings,
    pub cycles: candid::Nat,
    pub idle_cycles_burned_per_day: Option<candid::Nat>,
    pub reserved_cycles: Option<candid::Nat>,
}

/// Copy-paste of ic-types::ic_00::CanisterStatusResult.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct CanisterStatusResultFromManagementCanister {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub memory_size: candid::Nat,
    pub settings: DefiniteCanisterSettingsFromManagementCanister,
    pub cycles: candid::Nat,
    pub idle_cycles_burned_per_day: candid::Nat,
    pub reserved_cycles: candid::Nat,
}

/// Partial copy-paste of ic-types::ic_00::DefiniteCanisterSettings.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which is simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsFromManagementCanister {
    pub controllers: Vec<PrincipalId>,
    pub compute_allocation: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub freezing_threshold: candid::Nat,
    pub reserved_cycles_limit: candid::Nat,
    pub wasm_memory_limit: candid::Nat,
    pub log_visibility: LogVisibility,
}

impl From<CanisterStatusResultFromManagementCanister> for CanisterStatusResult {
    fn from(value: CanisterStatusResultFromManagementCanister) -> Self {
        let CanisterStatusResultFromManagementCanister {
            status,
            module_hash,
            memory_size,
            settings,
            cycles,
            idle_cycles_burned_per_day,
            reserved_cycles,
        } = value;

        let settings = DefiniteCanisterSettings::from(settings);

        let idle_cycles_burned_per_day = Some(idle_cycles_burned_per_day);
        let reserved_cycles = Some(reserved_cycles);

        CanisterStatusResult {
            status,
            module_hash,
            memory_size,
            settings,
            cycles,
            idle_cycles_burned_per_day,
            reserved_cycles,
        }
    }
}

impl From<DefiniteCanisterSettingsFromManagementCanister> for DefiniteCanisterSettings {
    fn from(value: DefiniteCanisterSettingsFromManagementCanister) -> Self {
        let DefiniteCanisterSettingsFromManagementCanister {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            wasm_memory_limit,
            log_visibility,
        } = value;

        let compute_allocation = Some(compute_allocation);
        let memory_allocation = Some(memory_allocation);
        let freezing_threshold = Some(freezing_threshold);
        let reserved_cycles_limit = Some(reserved_cycles_limit);
        let wasm_memory_limit = Some(wasm_memory_limit);
        let log_visibility = Some(log_visibility);

        DefiniteCanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            wasm_memory_limit,
            log_visibility,
        }
    }
}

impl CanisterStatusResultFromManagementCanister {
    pub fn controllers(&self) -> &[PrincipalId] {
        self.settings.controllers.as_slice()
    }

    pub fn dummy_with_controllers(
        controllers: Vec<PrincipalId>,
    ) -> CanisterStatusResultFromManagementCanister {
        CanisterStatusResultFromManagementCanister {
            status: CanisterStatusType::Running,
            module_hash: None,
            memory_size: candid::Nat::from(42_u32),
            settings: DefiniteCanisterSettingsFromManagementCanister {
                controllers,
                compute_allocation: candid::Nat::from(44_u32),
                memory_allocation: candid::Nat::from(45_u32),
                freezing_threshold: candid::Nat::from(46_u32),
                reserved_cycles_limit: candid::Nat::from(47_u32),
                wasm_memory_limit: candid::Nat::from(48_u32),
                log_visibility: LogVisibility::Controllers,
            },
            cycles: candid::Nat::from(47_u32),
            idle_cycles_burned_per_day: candid::Nat::from(48_u32),
            reserved_cycles: candid::Nat::from(49_u32),
        }
    }
}

pub async fn canister_status<Rt>(
    canister_id_record: CanisterIdRecord,
) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)>
where
    Rt: Runtime,
{
    Rt::call_with_cleanup(IC_00, "canister_status", (canister_id_record,))
        .await
        .map(|response: (CanisterStatusResultFromManagementCanister,)| response.0)
}

/// Copy-and-paste of types from management_canister_types, without deprecated fields.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterStatusResultV2 {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub settings: DefiniteCanisterSettingsArgs,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    pub idle_cycles_burned_per_day: candid::Nat,
}

impl CanisterStatusResultV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: CanisterStatusType,
        module_hash: Option<Vec<u8>>,
        controllers: Vec<PrincipalId>,
        memory_size: NumBytes,
        cycles: u128,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        idle_cycles_burned_per_day: u128,
        wasm_memory_limit: u64,
    ) -> Self {
        Self {
            status,
            module_hash,
            memory_size: candid::Nat::from(memory_size.get()),
            cycles: candid::Nat::from(cycles),
            // the following is spec 0.12/0.13 compat;
            // "\x00" denotes cycles
            settings: DefiniteCanisterSettingsArgs::new(
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
                Some(wasm_memory_limit),
            ),
            idle_cycles_burned_per_day: candid::Nat::from(idle_cycles_burned_per_day),
        }
    }

    pub fn status(&self) -> CanisterStatusType {
        self.status.clone()
    }

    pub fn module_hash(&self) -> Option<Vec<u8>> {
        self.module_hash.clone()
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.settings.controllers()
    }

    pub fn memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_size.0.to_u64().unwrap())
    }

    pub fn cycles(&self) -> u128 {
        self.cycles.0.to_u128().unwrap()
    }

    pub fn freezing_threshold(&self) -> u64 {
        self.settings.freezing_threshold.0.to_u64().unwrap()
    }

    pub fn idle_cycles_burned_per_day(&self) -> u128 {
        self.idle_cycles_burned_per_day.0.to_u128().unwrap()
    }

    /// Get a dummy value for CanisterStatusResultV2.
    pub fn dummy_with_controllers(controllers: Vec<PrincipalId>) -> CanisterStatusResultV2 {
        CanisterStatusResultV2::new(
            CanisterStatusType::Running,
            None,              // module_hash
            controllers,       // controllers
            NumBytes::new(42), // memory_size
            43,                // cycles
            44,                // compute_allocation
            None,              // memory_allocation
            45,                // freezing_threshold
            46,                // idle_cycles_burned_per_day
            47,                // wasm_memory_limit
        )
    }

    pub fn settings(&self) -> DefiniteCanisterSettingsArgs {
        self.settings.clone()
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     controller : principal;
///     compute_allocation: nat;
///     memory_allocation: opt nat;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsArgs {
    pub controllers: Vec<PrincipalId>,
    pub compute_allocation: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub freezing_threshold: candid::Nat,
    pub wasm_memory_limit: Option<candid::Nat>,
}

impl DefiniteCanisterSettingsArgs {
    pub fn new(
        controllers: Vec<PrincipalId>,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        wasm_memory_limit: Option<u64>,
    ) -> Self {
        let memory_allocation = match memory_allocation {
            None => candid::Nat::from(0_u32),
            Some(memory) => candid::Nat::from(memory),
        };
        Self {
            controllers,
            compute_allocation: candid::Nat::from(compute_allocation),
            memory_allocation,
            freezing_threshold: candid::Nat::from(freezing_threshold),
            wasm_memory_limit: wasm_memory_limit.map(candid::Nat::from),
        }
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.controllers.clone()
    }

    pub fn compute_allocation(&self) -> u64 {
        self.compute_allocation.0.to_u64().unwrap()
    }

    pub fn memory_allocation(&self) -> u64 {
        self.memory_allocation.0.to_u64().unwrap()
    }

    pub fn freezing_threshold(&self) -> u64 {
        self.freezing_threshold.0.to_u64().unwrap()
    }
}

impl From<CanisterStatusResultFromManagementCanister> for CanisterStatusResultV2 {
    fn from(value: CanisterStatusResultFromManagementCanister) -> Self {
        Self {
            status: value.status,
            module_hash: value.module_hash,
            settings: DefiniteCanisterSettingsArgs {
                controllers: value.settings.controllers,
                compute_allocation: value.settings.compute_allocation,
                memory_allocation: value.settings.memory_allocation,
                freezing_threshold: value.settings.freezing_threshold,
                wasm_memory_limit: Some(value.settings.wasm_memory_limit),
            },
            memory_size: value.memory_size,
            cycles: value.cycles,
            idle_cycles_burned_per_day: value.idle_cycles_burned_per_day,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canister_status::{
        CanisterStatusResult, CanisterStatusResultFromManagementCanister, CanisterStatusType,
        DefiniteCanisterSettings, DefiniteCanisterSettingsFromManagementCanister,
    };
    use ic_base_types::PrincipalId;

    #[test]
    fn test_canister_status_result_from_trait_for_canister_status_result_from_management_canister()
    {
        let test_principal = PrincipalId::new_user_test_id(1);
        let m = CanisterStatusResultFromManagementCanister {
            status: CanisterStatusType::Running,
            module_hash: Some(vec![1, 2, 3]),
            memory_size: candid::Nat::from(100_u32),
            settings: DefiniteCanisterSettingsFromManagementCanister {
                controllers: vec![test_principal],
                compute_allocation: candid::Nat::from(99_u32),
                memory_allocation: candid::Nat::from(98_u32),
                freezing_threshold: candid::Nat::from(97_u32),
                reserved_cycles_limit: candid::Nat::from(96_u32),
                wasm_memory_limit: candid::Nat::from(95_u32),
                log_visibility: LogVisibility::Controllers,
            },
            cycles: candid::Nat::from(999_u32),
            idle_cycles_burned_per_day: candid::Nat::from(998_u32),
            reserved_cycles: candid::Nat::from(997_u32),
        };

        let expected_canister_status_result = CanisterStatusResult {
            status: CanisterStatusType::Running,
            module_hash: Some(vec![1, 2, 3]),
            memory_size: candid::Nat::from(100_u32),
            settings: DefiniteCanisterSettings {
                controllers: vec![test_principal],
                compute_allocation: Some(candid::Nat::from(99_u32)),
                memory_allocation: Some(candid::Nat::from(98_u32)),
                freezing_threshold: Some(candid::Nat::from(97_u32)),
                reserved_cycles_limit: Some(candid::Nat::from(96_u32)),
                wasm_memory_limit: Some(candid::Nat::from(95_u32)),
                log_visibility: Some(LogVisibility::Controllers),
            },
            cycles: candid::Nat::from(999_u32),
            idle_cycles_burned_per_day: Some(candid::Nat::from(998_u32)),
            reserved_cycles: Some(candid::Nat::from(997_u32)),
        };

        let actual_canister_status_result = CanisterStatusResult::from(m);

        assert_eq!(
            actual_canister_status_result,
            expected_canister_status_result
        );
    }
}
