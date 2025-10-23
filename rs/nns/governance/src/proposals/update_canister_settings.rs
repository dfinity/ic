use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    pb::v1::{
        GovernanceError, Topic, UpdateCanisterSettings, update_canister_settings::LogVisibility,
    },
    proposals::call_canister::CallCanister,
};

use candid::{Encode, Nat};
use ic_base_types::CanisterId;
use ic_nervous_system_clients::update_settings::{
    CanisterSettings as RootCanisterSettings, LogVisibility as RootLogVisibility,
};
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::GenericValue;
use ic_nns_handler_root_interface::UpdateCanisterSettingsRequest;
use maplit::hashmap;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidUpdateCanisterSettings {
    canister_id: CanisterId,
    settings: RootCanisterSettings,
}

impl TryFrom<UpdateCanisterSettings> for ValidUpdateCanisterSettings {
    type Error = String;

    fn try_from(value: UpdateCanisterSettings) -> Result<Self, Self::Error> {
        let UpdateCanisterSettings {
            canister_id,
            settings,
        } = value;

        let canister_principal_id = canister_id.ok_or("Canister ID is required")?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|e| format!("Invalid canister ID: {e}"))?;

        let settings = settings.ok_or("Settings are required")?;

        if settings.controllers.is_none()
            && settings.compute_allocation.is_none()
            && settings.memory_allocation.is_none()
            && settings.freezing_threshold.is_none()
            && settings.log_visibility.is_none()
            && settings.wasm_memory_limit.is_none()
            && settings.wasm_memory_threshold.is_none()
        {
            return Err("At least one setting must be provided".to_string());
        }

        let controllers = settings
            .controllers
            .map(|controllers| controllers.controllers);
        let compute_allocation = settings.compute_allocation.map(Nat::from);
        let memory_allocation = settings.memory_allocation.map(Nat::from);
        let freezing_threshold = settings.freezing_threshold.map(Nat::from);
        let wasm_memory_limit = settings.wasm_memory_limit.map(Nat::from);
        let wasm_memory_threshold = settings.wasm_memory_threshold.map(Nat::from);
        let log_visibility = match settings.log_visibility {
            Some(log_visibility_i32) => {
                let log_visibility = LogVisibility::try_from(log_visibility_i32);
                match log_visibility {
                    Ok(LogVisibility::Controllers) => Some(RootLogVisibility::Controllers),
                    Ok(LogVisibility::Public) => Some(RootLogVisibility::Public),
                    Ok(LogVisibility::Unspecified) | Err(_) => {
                        return Err(format!("Invalid log visibility {log_visibility_i32}"));
                    }
                }
            }
            None => None,
        };
        // Reserved cycles limit is not supported yet.
        let reserved_cycles_limit = None;

        let settings = RootCanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            wasm_memory_limit,
            log_visibility,
            reserved_cycles_limit,
            wasm_memory_threshold,
        };

        Ok(ValidUpdateCanisterSettings {
            canister_id,
            settings,
        })
    }
}

impl ValidUpdateCanisterSettings {
    pub fn canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    pub fn settings(&self) -> &RootCanisterSettings {
        &self.settings
    }

    pub fn compute_topic_at_creation(&self) -> Topic {
        topic_to_manage_canister(&self.canister_id)
    }

    pub fn allowed_when_resources_are_low(&self) -> bool {
        topic_to_manage_canister(&self.canister_id) == Topic::ProtocolCanisterManagement
    }

    pub fn validate(&self) -> Result<(), GovernanceError> {
        // Validation already happened in TryFrom
        Ok(())
    }
}

impl CallCanister for ValidUpdateCanisterSettings {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        if self.canister_id == ROOT_CANISTER_ID {
            Ok((LIFELINE_CANISTER_ID, "update_root_settings"))
        } else {
            Ok((ROOT_CANISTER_ID, "update_canister_settings"))
        }
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        if self.canister_id == ROOT_CANISTER_ID {
            Encode!(&self.settings)
                .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
        } else {
            let update_settings = UpdateCanisterSettingsRequest {
                canister_id: self.canister_id.get(),
                settings: self.settings.clone(),
            };
            Encode!(&update_settings)
                .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
        }
    }
}

impl From<&ValidUpdateCanisterSettings> for GenericValue {
    fn from(value: &ValidUpdateCanisterSettings) -> Self {
        let canister_id_text = value.canister_id().to_string();
        let mut settings_map = hashmap! {
            "canister_id".to_string() => GenericValue::Text(canister_id_text),
        };

        let settings = value.settings();
        if let Some(ref controllers) = settings.controllers {
            let controllers_vec: Vec<GenericValue> = controllers
                .iter()
                .map(|p| GenericValue::Text(p.to_string()))
                .collect();
            settings_map.insert(
                "controllers".to_string(),
                GenericValue::Array(controllers_vec),
            );
        }

        if let Some(ref compute_allocation) = settings.compute_allocation {
            settings_map.insert(
                "compute_allocation".to_string(),
                GenericValue::Nat(compute_allocation.clone()),
            );
        }

        if let Some(ref memory_allocation) = settings.memory_allocation {
            settings_map.insert(
                "memory_allocation".to_string(),
                GenericValue::Nat(memory_allocation.clone()),
            );
        }

        if let Some(ref freezing_threshold) = settings.freezing_threshold {
            settings_map.insert(
                "freezing_threshold".to_string(),
                GenericValue::Nat(freezing_threshold.clone()),
            );
        }

        if let Some(ref wasm_memory_limit) = settings.wasm_memory_limit {
            settings_map.insert(
                "wasm_memory_limit".to_string(),
                GenericValue::Nat(wasm_memory_limit.clone()),
            );
        }

        if let Some(ref wasm_memory_threshold) = settings.wasm_memory_threshold {
            settings_map.insert(
                "wasm_memory_threshold".to_string(),
                GenericValue::Nat(wasm_memory_threshold.clone()),
            );
        }

        if let Some(ref log_visibility) = settings.log_visibility {
            settings_map.insert(
                "log_visibility".to_string(),
                GenericValue::Text(format!("{log_visibility:?}")),
            );
        }

        GenericValue::Map(settings_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::update_canister_settings::{CanisterSettings, Controllers};
    use candid::Decode;
    use ic_base_types::CanisterId;
    use ic_nns_constants::{LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID};

    #[test]
    fn test_invalid_update_canister_settings() {
        let valid_update_canister_settings = UpdateCanisterSettings {
            canister_id: Some(LEDGER_CANISTER_ID.get()),
            settings: Some(CanisterSettings {
                memory_allocation: Some(1 >> 30),
                ..Default::default()
            }),
        };

        let is_invalid_proposal_with_keywords =
            |update_canister_settings: UpdateCanisterSettings, keywords: Vec<&str>| {
                let error_message = ValidUpdateCanisterSettings::try_from(
                    update_canister_settings.clone(),
                )
                .expect_err(&format!(
                    "Expecting validation error for {update_canister_settings:#?} but got Ok(())"
                ));
                for keyword in keywords {
                    let error_message = error_message.to_lowercase();
                    assert!(
                        error_message.contains(keyword),
                        "{keyword} not found in {error_message:#?}"
                    );
                }
            };

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                canister_id: None,
                ..valid_update_canister_settings.clone()
            },
            vec!["canister id", "required"],
        );

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                settings: None,
                ..valid_update_canister_settings.clone()
            },
            vec!["settings", "required"],
        );

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                settings: Some(Default::default()),
                ..valid_update_canister_settings.clone()
            },
            vec!["at least one setting", "provided"],
        );

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                settings: Some(CanisterSettings {
                    log_visibility: Some(4),
                    ..Default::default()
                }),
                ..valid_update_canister_settings.clone()
            },
            vec!["invalid log visibility", "4"],
        );

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                settings: Some(CanisterSettings {
                    log_visibility: Some(LogVisibility::Unspecified as i32),
                    ..Default::default()
                }),
                ..valid_update_canister_settings.clone()
            },
            vec!["invalid log visibility", "0"],
        );
    }

    #[test]
    fn test_update_sns_w_canister_settings() {
        let update_sns_w_canister_settings = UpdateCanisterSettings {
            canister_id: Some(SNS_WASM_CANISTER_ID.get()),
            // The value of the settings are arbitrary and do not have any meaning.
            settings: Some(CanisterSettings {
                controllers: Some(Controllers {
                    controllers: vec![ROOT_CANISTER_ID.get()],
                }),
                memory_allocation: Some(1 << 32),
                wasm_memory_limit: Some(1 << 31),
                wasm_memory_threshold: Some(1 << 30),
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
            }),
        };

        let valid_update_sns_w_canister_settings =
            ValidUpdateCanisterSettings::try_from(update_sns_w_canister_settings).unwrap();
        assert_eq!(
            valid_update_sns_w_canister_settings.compute_topic_at_creation(),
            Topic::ServiceNervousSystemManagement
        );
        assert_eq!(
            valid_update_sns_w_canister_settings.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "update_canister_settings"))
        );
        assert!(!valid_update_sns_w_canister_settings.allowed_when_resources_are_low());

        let decoded_payload = Decode!(
            &valid_update_sns_w_canister_settings.payload().unwrap(),
            UpdateCanisterSettingsRequest
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            UpdateCanisterSettingsRequest {
                canister_id: SNS_WASM_CANISTER_ID.get(),
                settings: RootCanisterSettings {
                    controllers: Some(vec![ROOT_CANISTER_ID.get()]),
                    memory_allocation: Some(Nat::from(1u64 << 32)),
                    wasm_memory_limit: Some(Nat::from(1u64 << 31)),
                    compute_allocation: Some(Nat::from(10u64)),
                    freezing_threshold: Some(Nat::from(100u64)),
                    log_visibility: Some(RootLogVisibility::Public),
                    reserved_cycles_limit: None,
                    wasm_memory_threshold: Some(Nat::from(1u64 << 30)),
                }
            }
        );
    }

    #[test]
    fn test_update_root_canister_settings() {
        let update_root_canister_settings = UpdateCanisterSettings {
            canister_id: Some(ROOT_CANISTER_ID.get()),
            // The value of the settings are arbitrary and do not have any meaning.
            settings: Some(CanisterSettings {
                controllers: Some(Controllers {
                    controllers: vec![LIFELINE_CANISTER_ID.get()],
                }),
                memory_allocation: Some(1 << 32),
                wasm_memory_limit: Some(1 << 31),
                wasm_memory_threshold: Some(1 << 30),
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
            }),
        };

        let valid_update_root_canister_settings =
            ValidUpdateCanisterSettings::try_from(update_root_canister_settings).unwrap();
        assert_eq!(
            valid_update_root_canister_settings.compute_topic_at_creation(),
            Topic::ProtocolCanisterManagement
        );
        assert_eq!(
            valid_update_root_canister_settings.canister_and_function(),
            Ok((LIFELINE_CANISTER_ID, "update_root_settings"))
        );
        assert!(valid_update_root_canister_settings.allowed_when_resources_are_low());

        let decoded_payload = Decode!(
            &valid_update_root_canister_settings.payload().unwrap(),
            RootCanisterSettings
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            RootCanisterSettings {
                controllers: Some(vec![LIFELINE_CANISTER_ID.get()]),
                memory_allocation: Some(Nat::from(1u64 << 32)),
                wasm_memory_limit: Some(Nat::from(1u64 << 31)),
                compute_allocation: Some(Nat::from(10u64)),
                freezing_threshold: Some(Nat::from(100u64)),
                log_visibility: Some(RootLogVisibility::Public),
                reserved_cycles_limit: None,
                wasm_memory_threshold: Some(Nat::from(1u64 << 30)),
            }
        );
    }

    #[test]
    fn test_update_canister_settings_topic_mapping() {
        let test_cases = vec![
            (LEDGER_CANISTER_ID, Topic::ProtocolCanisterManagement),
            (SNS_WASM_CANISTER_ID, Topic::ServiceNervousSystemManagement),
            (
                CanisterId::from_u64(123_456_789),
                Topic::ApplicationCanisterManagement,
            ),
        ];

        for (canister_id, expected_topic) in test_cases {
            let update_canister_settings = UpdateCanisterSettings {
                canister_id: Some(canister_id.get()),
                settings: Some(CanisterSettings {
                    memory_allocation: Some(1 << 30),
                    ..Default::default()
                }),
            };

            let valid_update_canister_settings =
                ValidUpdateCanisterSettings::try_from(update_canister_settings).unwrap();
            assert_eq!(
                valid_update_canister_settings.compute_topic_at_creation(),
                expected_topic
            );
        }
    }

    #[test]
    fn test_generic_value_conversion() {
        let update_canister_settings = UpdateCanisterSettings {
            canister_id: Some(SNS_WASM_CANISTER_ID.get()),
            settings: Some(CanisterSettings {
                controllers: Some(Controllers {
                    controllers: vec![ROOT_CANISTER_ID.get()],
                }),
                memory_allocation: Some(1 << 32),
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
                wasm_memory_limit: Some(1 << 31),
                wasm_memory_threshold: Some(1 << 30),
            }),
        };

        let valid_update_canister_settings =
            ValidUpdateCanisterSettings::try_from(update_canister_settings).unwrap();
        let generic_value = GenericValue::from(&valid_update_canister_settings);

        let expected_map = hashmap! {
            "canister_id".to_string() => GenericValue::Text(SNS_WASM_CANISTER_ID.to_string()),
            "controllers".to_string() => GenericValue::Array(vec![
                GenericValue::Text(ROOT_CANISTER_ID.get().to_string())
            ]),
            "memory_allocation".to_string() => GenericValue::Nat(Nat::from(1u64 << 32)),
            "compute_allocation".to_string() => GenericValue::Nat(Nat::from(10u64)),
            "freezing_threshold".to_string() => GenericValue::Nat(Nat::from(100u64)),
            "log_visibility".to_string() => GenericValue::Text("Public".to_string()),
            "wasm_memory_limit".to_string() => GenericValue::Nat(Nat::from(1u64 << 31)),
            "wasm_memory_threshold".to_string() => GenericValue::Nat(Nat::from(1u64 << 30)),
        };

        assert_eq!(generic_value, GenericValue::Map(expected_map));
    }
}
