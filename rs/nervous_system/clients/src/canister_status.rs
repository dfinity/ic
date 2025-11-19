use crate::canister_id_record::CanisterIdRecord;
use candid::{CandidType, Deserialize};
use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_management_canister_types_private::IC_00;
use ic_nervous_system_runtime::Runtime;
use num_traits::cast::ToPrimitive;

impl TryFrom<PrincipalId> for CanisterIdRecord {
    type Error = String;

    fn try_from(principal_id: PrincipalId) -> Result<Self, Self::Error> {
        let canister_id = match CanisterId::try_from(principal_id) {
            Ok(canister_id) => canister_id,
            Err(err) => return Err(format!("{err}")),
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
    Controllers,
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(Vec<PrincipalId>),
}

/// Partial copy-paste of `ic_management_canister_types_private::DefiniteCanisterSettings`, and it's used
/// for the response type in the NNS/SNS Root `canister_status` method.
///
/// Only the fields that we need are copied. Candid deserialization is supposed to be tolerant to
/// having data for unknown fields (which is simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettings {
    pub controllers: Vec<PrincipalId>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
    pub wasm_memory_threshold: Option<candid::Nat>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct MemoryMetrics {
    pub wasm_memory_size: Option<candid::Nat>,
    pub stable_memory_size: Option<candid::Nat>,
    pub global_memory_size: Option<candid::Nat>,
    pub wasm_binary_size: Option<candid::Nat>,
    pub custom_sections_size: Option<candid::Nat>,
    pub canister_history_size: Option<candid::Nat>,
    pub wasm_chunk_store_size: Option<candid::Nat>,
    pub snapshots_size: Option<candid::Nat>,
}

/// Copy-paste of memory metrics from management canister types, used for the management canister `canister_status` method.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct MemoryMetricsFromManagementCanister {
    pub wasm_memory_size: candid::Nat,
    pub stable_memory_size: candid::Nat,
    pub global_memory_size: candid::Nat,
    pub wasm_binary_size: candid::Nat,
    pub custom_sections_size: candid::Nat,
    pub canister_history_size: candid::Nat,
    pub wasm_chunk_store_size: candid::Nat,
    pub snapshots_size: candid::Nat,
}

/// Partial copy-paste of `ic_management_canister_types_private::CanisterStatusResultV2`, and it's used for
/// the response type in the NNS/SNS Root `canister_status` method.
///
/// Only the fields that we need are copied. Candid deserialization is supposed to be tolerant to
/// having data for unknown fields (which is simply discarded).
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
    pub query_stats: Option<QueryStats>,
    pub memory_metrics: Option<MemoryMetrics>,
}

/// Partial copy-paste of `ic_management_canister_types_private::QueryStats`, and it's used for the response
/// type in the NNS/SNS Root `canister_status` method.
///
/// Only the fields that we need are copied. Candid deserialization is supposed to be tolerant to
/// having data for unknown fields (which is simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct QueryStats {
    pub num_calls_total: Option<candid::Nat>,
    pub num_instructions_total: Option<candid::Nat>,
    pub request_payload_bytes_total: Option<candid::Nat>,
    pub response_payload_bytes_total: Option<candid::Nat>,
}

/// Copy-paste of `ic_management_canister_types_private::CanisterStatusResultV2`, and it's used for the
/// `canister_status`` method on the management canister.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct CanisterStatusResultFromManagementCanister {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub memory_size: candid::Nat,
    pub memory_metrics: MemoryMetricsFromManagementCanister,
    pub settings: DefiniteCanisterSettingsFromManagementCanister,
    pub cycles: candid::Nat,
    pub idle_cycles_burned_per_day: candid::Nat,
    pub reserved_cycles: candid::Nat,
    pub query_stats: QueryStatsFromManagementCanister,
}

/// Partial copy-paste of `ic_management_canister_types_private::DefiniteCanisterSettingsArgs`, and it's
/// used for the response type in the management canister `canister_status` method.
///
/// Only the fields that we need are copied. Candid deserialization is supposed to be tolerant to
/// having data for unknown fields (which is simply discarded).
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsFromManagementCanister {
    pub controllers: Vec<PrincipalId>,
    pub compute_allocation: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub freezing_threshold: candid::Nat,
    pub reserved_cycles_limit: candid::Nat,
    pub wasm_memory_limit: candid::Nat,
    pub log_visibility: LogVisibility,
    pub wasm_memory_threshold: candid::Nat,
}

/// Partial copy-paste of `ic_management_canister_types_private::QueryStats`, and it's used for the response
/// type in the management canister `canister_status` method.
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct QueryStatsFromManagementCanister {
    pub num_calls_total: candid::Nat,
    pub num_instructions_total: candid::Nat,
    pub request_payload_bytes_total: candid::Nat,
    pub response_payload_bytes_total: candid::Nat,
}

impl From<CanisterStatusResultFromManagementCanister> for CanisterStatusResult {
    fn from(value: CanisterStatusResultFromManagementCanister) -> Self {
        let CanisterStatusResultFromManagementCanister {
            status,
            module_hash,
            memory_size,
            memory_metrics,
            settings,
            cycles,
            idle_cycles_burned_per_day,
            reserved_cycles,
            query_stats,
        } = value;

        let settings = DefiniteCanisterSettings::from(settings);
        let query_stats = Some(QueryStats::from(query_stats));

        let idle_cycles_burned_per_day = Some(idle_cycles_burned_per_day);
        let reserved_cycles = Some(reserved_cycles);

        let memory_metrics = Some(MemoryMetrics::from(memory_metrics));

        CanisterStatusResult {
            status,
            module_hash,
            memory_size,
            memory_metrics,
            settings,
            cycles,
            idle_cycles_burned_per_day,
            reserved_cycles,
            query_stats,
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
            wasm_memory_threshold,
        } = value;

        let compute_allocation = Some(compute_allocation);
        let memory_allocation = Some(memory_allocation);
        let freezing_threshold = Some(freezing_threshold);
        let reserved_cycles_limit = Some(reserved_cycles_limit);
        let wasm_memory_limit = Some(wasm_memory_limit);
        let log_visibility = Some(log_visibility);
        let wasm_memory_threshold = Some(wasm_memory_threshold);

        DefiniteCanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            wasm_memory_limit,
            log_visibility,
            wasm_memory_threshold,
        }
    }
}

impl From<QueryStatsFromManagementCanister> for QueryStats {
    fn from(value: QueryStatsFromManagementCanister) -> Self {
        let QueryStatsFromManagementCanister {
            num_calls_total,
            num_instructions_total,
            request_payload_bytes_total,
            response_payload_bytes_total,
        } = value;

        let num_calls_total = Some(num_calls_total);
        let num_instructions_total = Some(num_instructions_total);
        let request_payload_bytes_total = Some(request_payload_bytes_total);
        let response_payload_bytes_total = Some(response_payload_bytes_total);

        QueryStats {
            num_calls_total,
            num_instructions_total,
            request_payload_bytes_total,
            response_payload_bytes_total,
        }
    }
}

impl From<MemoryMetricsFromManagementCanister> for MemoryMetrics {
    fn from(value: MemoryMetricsFromManagementCanister) -> Self {
        let MemoryMetricsFromManagementCanister {
            wasm_memory_size,
            stable_memory_size,
            global_memory_size,
            wasm_binary_size,
            custom_sections_size,
            canister_history_size,
            wasm_chunk_store_size,
            snapshots_size,
        } = value;

        MemoryMetrics {
            wasm_memory_size: Some(wasm_memory_size),
            stable_memory_size: Some(stable_memory_size),
            global_memory_size: Some(global_memory_size),
            wasm_binary_size: Some(wasm_binary_size),
            custom_sections_size: Some(custom_sections_size),
            canister_history_size: Some(canister_history_size),
            wasm_chunk_store_size: Some(wasm_chunk_store_size),
            snapshots_size: Some(snapshots_size),
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
            memory_metrics: Default::default(),
            settings: DefiniteCanisterSettingsFromManagementCanister {
                controllers,
                compute_allocation: candid::Nat::from(44_u32),
                memory_allocation: candid::Nat::from(45_u32),
                freezing_threshold: candid::Nat::from(46_u32),
                reserved_cycles_limit: candid::Nat::from(47_u32),
                wasm_memory_limit: candid::Nat::from(48_u32),
                log_visibility: LogVisibility::Controllers,
                wasm_memory_threshold: candid::Nat::from(49_u32),
            },
            query_stats: QueryStatsFromManagementCanister {
                num_calls_total: candid::Nat::from(50_u32),
                num_instructions_total: candid::Nat::from(51_u32),
                request_payload_bytes_total: candid::Nat::from(52_u32),
                response_payload_bytes_total: candid::Nat::from(53_u32),
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
    pub memory_metrics: Option<MemoryMetrics>,
    pub cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    pub idle_cycles_burned_per_day: candid::Nat,
    pub query_stats: Option<QueryStats>,
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
        wasm_memory_threshold: u64,
        memory_metrics: MemoryMetricsFromManagementCanister,
    ) -> Self {
        Self {
            status,
            module_hash,
            memory_size: candid::Nat::from(memory_size.get()),
            memory_metrics: Some(MemoryMetrics::from(memory_metrics)),
            cycles: candid::Nat::from(cycles),
            // the following is spec 0.12/0.13 compat;
            // "\x00" denotes cycles
            settings: DefiniteCanisterSettingsArgs::new(
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
                Some(wasm_memory_limit),
                Some(wasm_memory_threshold),
            ),
            idle_cycles_burned_per_day: candid::Nat::from(idle_cycles_burned_per_day),
            query_stats: Some(QueryStats {
                num_calls_total: Some(candid::Nat::from(0_u64)),
                num_instructions_total: Some(candid::Nat::from(0_u64)),
                request_payload_bytes_total: Some(candid::Nat::from(0_u64)),
                response_payload_bytes_total: Some(candid::Nat::from(0_u64)),
            }),
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
            None,                                           // module_hash
            controllers,                                    // controllers
            NumBytes::new(42),                              // memory_size
            43,                                             // cycles
            44,                                             // compute_allocation
            None,                                           // memory_allocation
            45,                                             // freezing_threshold
            46,                                             // idle_cycles_burned_per_day
            47,                                             // wasm_memory_limit
            41,                                             // wasm_memory_threshold
            MemoryMetricsFromManagementCanister::default(), // memory_metrics
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
    pub wasm_memory_threshold: Option<candid::Nat>,
}

impl From<ic_management_canister_types_private::DefiniteCanisterSettingsArgs>
    for DefiniteCanisterSettingsArgs
{
    fn from(settings: ic_management_canister_types_private::DefiniteCanisterSettingsArgs) -> Self {
        Self {
            controllers: settings.controllers(),
            compute_allocation: settings.compute_allocation(),
            memory_allocation: settings.memory_allocation(),
            freezing_threshold: settings.freezing_threshold(),
            wasm_memory_limit: Some(settings.wasm_memory_limit()),
            wasm_memory_threshold: Some(settings.wasm_memory_threshold()),
        }
    }
}

impl DefiniteCanisterSettingsArgs {
    pub fn new(
        controllers: Vec<PrincipalId>,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        wasm_memory_limit: Option<u64>,
        wasm_memory_threshold: Option<u64>,
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
            wasm_memory_threshold: wasm_memory_threshold.map(candid::Nat::from),
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
                wasm_memory_threshold: Some(value.settings.wasm_memory_threshold),
            },
            memory_size: value.memory_size,
            memory_metrics: Some(MemoryMetrics::from(value.memory_metrics)),
            cycles: value.cycles,
            idle_cycles_burned_per_day: value.idle_cycles_burned_per_day,
            query_stats: Some(QueryStats {
                num_calls_total: Some(value.query_stats.num_calls_total),
                num_instructions_total: Some(value.query_stats.num_instructions_total),
                request_payload_bytes_total: Some(value.query_stats.request_payload_bytes_total),
                response_payload_bytes_total: Some(value.query_stats.response_payload_bytes_total),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canister_status::{
        CanisterStatusResult, CanisterStatusResultFromManagementCanister, CanisterStatusType,
        DefiniteCanisterSettings, DefiniteCanisterSettingsFromManagementCanister, MemoryMetrics,
        MemoryMetricsFromManagementCanister,
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
            memory_metrics: MemoryMetricsFromManagementCanister {
                wasm_memory_size: candid::Nat::from(10_u32),
                stable_memory_size: candid::Nat::from(20_u32),
                global_memory_size: candid::Nat::from(30_u32),
                wasm_binary_size: candid::Nat::from(40_u32),
                custom_sections_size: candid::Nat::from(50_u32),
                canister_history_size: candid::Nat::from(60_u32),
                wasm_chunk_store_size: candid::Nat::from(70_u32),
                snapshots_size: candid::Nat::from(80_u32),
            },
            settings: DefiniteCanisterSettingsFromManagementCanister {
                controllers: vec![test_principal],
                compute_allocation: candid::Nat::from(99_u32),
                memory_allocation: candid::Nat::from(98_u32),
                freezing_threshold: candid::Nat::from(97_u32),
                reserved_cycles_limit: candid::Nat::from(96_u32),
                wasm_memory_limit: candid::Nat::from(95_u32),
                log_visibility: LogVisibility::Controllers,
                wasm_memory_threshold: candid::Nat::from(94_u32),
            },
            cycles: candid::Nat::from(999_u32),
            idle_cycles_burned_per_day: candid::Nat::from(998_u32),
            reserved_cycles: candid::Nat::from(997_u32),
            query_stats: QueryStatsFromManagementCanister {
                num_calls_total: candid::Nat::from(93_u32),
                num_instructions_total: candid::Nat::from(92_u32),
                request_payload_bytes_total: candid::Nat::from(91_u32),
                response_payload_bytes_total: candid::Nat::from(90_u32),
            },
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
                wasm_memory_threshold: Some(candid::Nat::from(94_u32)),
            },
            cycles: candid::Nat::from(999_u32),
            idle_cycles_burned_per_day: Some(candid::Nat::from(998_u32)),
            reserved_cycles: Some(candid::Nat::from(997_u32)),
            query_stats: Some(QueryStats {
                num_calls_total: Some(candid::Nat::from(93_u32)),
                num_instructions_total: Some(candid::Nat::from(92_u32)),
                request_payload_bytes_total: Some(candid::Nat::from(91_u32)),
                response_payload_bytes_total: Some(candid::Nat::from(90_u32)),
            }),
            memory_metrics: Some(MemoryMetrics {
                wasm_memory_size: Some(candid::Nat::from(10_u32)),
                stable_memory_size: Some(candid::Nat::from(20_u32)),
                global_memory_size: Some(candid::Nat::from(30_u32)),
                wasm_binary_size: Some(candid::Nat::from(40_u32)),
                custom_sections_size: Some(candid::Nat::from(50_u32)),
                canister_history_size: Some(candid::Nat::from(60_u32)),
                wasm_chunk_store_size: Some(candid::Nat::from(70_u32)),
                snapshots_size: Some(candid::Nat::from(80_u32)),
            }),
        };

        let actual_canister_status_result = CanisterStatusResult::from(m);

        assert_eq!(
            actual_canister_status_result,
            expected_canister_status_result
        );
    }
}
