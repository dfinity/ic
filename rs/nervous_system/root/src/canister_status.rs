use crate::CanisterIdRecord;
use candid::{CandidType, Deserialize};
use dfn_core::api::call;
use ic_base_types::PrincipalId;
use ic_ic00_types::IC_00;
use lazy_static::lazy_static;
use std::str::FromStr;

// Copied from /rs/replicated_state/src/canister_state/system_state.rs because the
// fields are not exported from there. These values may be present in the response
// from the replica and as such should be overridden.
lazy_static! {
    pub static ref DEFAULT_PRINCIPAL_MULTIPLE_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap();
    pub static ref DEFAULT_PRINCIPAL_ZERO_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("zrl4w-cqaaa-nocon-troll-eraaa-d5qc").unwrap();
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

/// Partial copy-paste of ic-types::ic_00::DefiniteCanisterSettings.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which is simply discarded).
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct DefiniteCanisterSettings {
    pub controllers: Vec<PrincipalId>,
}

/// Partial copy-paste of ic-types::ic_00::CanisterStatusResult.
///
/// Only the fields that we need are copied.
/// Candid deserialization is supposed to be tolerant to having data for unknown
/// fields (which are simply discarded).
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    // TODO NNS1-2170 - Remove this field when our clients no longer depend on it.
    pub controller: PrincipalId,
    pub memory_size: candid::Nat,
    pub settings: DefiniteCanisterSettings,
}

/// Partial copy-paste of ic-types::ic_00::CanisterStatusResult.
///
/// Only the fields we need and are supported from the replica are copied.
/// Notice that `controller` is not present. Candid deserialization is tolerant
/// to having data for unknown fields (which are simply discarded).
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct CanisterStatusResultFromManagementCanister {
    // no controller. This is fine regardless of whether it sends us controller.
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub memory_size: candid::Nat,
    pub settings: DefiniteCanisterSettings,
}

impl CanisterStatusResult {
    pub fn controller(&self) -> PrincipalId {
        self.controller
    }

    /// Overrides any value returned in the non-standard and deprecated field `controller`.
    /// This field can be deprecated from the CanisterStatusResult after downstream clients
    /// have moved from its use. For now, the method severs the tie between the response
    /// from the IC Interface and the response served to clients of NNS Root.
    ///
    /// If the controllers field is empty, this method follows the convention set by the
    /// IC Interface and fills in the Default Principal for the required controller field.
    fn fill_controller_field(self) -> Self {
        let controllers = self.settings.controllers.clone();

        // Let's set `controller` to be the first principal in `controllers`.
        return if let Some(controller) = controllers.first() {
            Self {
                controller: *controller,
                ..self
            }
        } else {
            Self {
                controller: *DEFAULT_PRINCIPAL_ZERO_CONTROLLERS,
                ..self
            }
        };
    }
}

impl From<CanisterStatusResultFromManagementCanister> for CanisterStatusResult {
    fn from(value: CanisterStatusResultFromManagementCanister) -> Self {
        CanisterStatusResult {
            controller: PrincipalId::new_anonymous(),
            status: value.status,
            module_hash: value.module_hash,
            memory_size: value.memory_size,
            settings: value.settings,
        }
        .fill_controller_field()
    }
}

pub async fn canister_status(
    canister_id_record: CanisterIdRecord,
) -> Result<CanisterStatusResultFromManagementCanister, (Option<i32>, String)> {
    call(
        IC_00,
        "canister_status",
        dfn_candid::candid::<CanisterStatusResultFromManagementCanister, (CanisterIdRecord,)>,
        (canister_id_record,),
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::canister_status::{
        CanisterStatusResult, CanisterStatusResultFromManagementCanister, CanisterStatusType,
        DefiniteCanisterSettings, DEFAULT_PRINCIPAL_ZERO_CONTROLLERS,
    };
    use ic_base_types::PrincipalId;

    #[test]
    fn test_canister_status_result_from_management_sets_controller_when_multiple_are_present() {
        let test_principal_1 = PrincipalId::new_user_test_id(1);
        let test_principal_2 = PrincipalId::new_user_test_id(2);
        let status = CanisterStatusResult::from(CanisterStatusResultFromManagementCanister {
            status: CanisterStatusType::Running,
            module_hash: None,
            memory_size: Default::default(),
            settings: DefiniteCanisterSettings {
                controllers: vec![test_principal_1, test_principal_2],
            },
        });
        assert_eq!(status.controller(), test_principal_1);
    }

    #[test]
    fn test_canister_status_result_from_management_sets_controller_when_none_are_present() {
        let status = CanisterStatusResult::from(CanisterStatusResultFromManagementCanister {
            memory_size: Default::default(),
            settings: DefiniteCanisterSettings {
                controllers: vec![],
            },
            status: CanisterStatusType::Running,
            module_hash: None,
        });
        assert_eq!(status.controller(), *DEFAULT_PRINCIPAL_ZERO_CONTROLLERS);
    }

    #[test]
    fn test_canister_status_result_from_trait_for_canister_status_result_from_management_canister()
    {
        let test_principal = PrincipalId::new_user_test_id(1);
        let m = CanisterStatusResultFromManagementCanister {
            status: CanisterStatusType::Running,
            module_hash: Some(vec![1, 2, 3]),
            memory_size: candid::Nat::from(100),
            settings: DefiniteCanisterSettings {
                controllers: vec![test_principal],
            },
        };

        let expected_canister_status_result = CanisterStatusResult {
            status: CanisterStatusType::Running,
            module_hash: Some(vec![1, 2, 3]),
            controller: test_principal,
            memory_size: candid::Nat::from(100),
            settings: DefiniteCanisterSettings {
                controllers: vec![test_principal],
            },
        };

        let actual_canister_status_result = CanisterStatusResult::from(m);

        assert_eq!(
            actual_canister_status_result,
            expected_canister_status_result
        );
    }
}
