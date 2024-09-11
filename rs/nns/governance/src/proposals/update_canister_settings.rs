use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    enable_new_canister_management_topics,
    pb::v1::{
        update_canister_settings::LogVisibility, GovernanceError, Topic, UpdateCanisterSettings,
    },
    proposals::call_canister::CallCanister,
};

use candid::{Encode, Nat};
use ic_base_types::CanisterId;
use ic_nervous_system_clients::update_settings::{
    CanisterSettings as RootCanisterSettings, LogVisibility as RootLogVisibility,
};
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_handler_root_interface::UpdateCanisterSettingsRequest;

impl UpdateCanisterSettings {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !enable_new_canister_management_topics() {
            return Err(invalid_proposal_error(
                "UpdateCanisterSettings proposal is not yet supported",
            ));
        }

        let _ = self.valid_canister_id()?;
        let _ = self.valid_topic()?;
        let _ = self.canister_and_function()?;
        let _ = self.valid_canister_settings()?;

        Ok(())
    }

    fn valid_canister_id(&self) -> Result<CanisterId, GovernanceError> {
        let canister_principal_id = self
            .canister_id
            .ok_or(invalid_proposal_error("Canister ID is required"))?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|_| invalid_proposal_error("Invalid canister ID"))?;
        Ok(canister_id)
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        Ok(topic_to_manage_canister(&canister_id))
    }

    fn valid_log_visibility(log_visibility_i32: i32) -> Result<RootLogVisibility, GovernanceError> {
        let log_visibility = LogVisibility::try_from(log_visibility_i32);
        match log_visibility {
            Ok(LogVisibility::Controllers) => Ok(RootLogVisibility::Controllers),
            Ok(LogVisibility::Public) => Ok(RootLogVisibility::Public),
            Ok(LogVisibility::Unspecified) | Err(_) => Err(invalid_proposal_error(&format!(
                "Invalid log visibility {log_visibility_i32}"
            ))),
        }
    }

    fn valid_canister_settings(&self) -> Result<RootCanisterSettings, GovernanceError> {
        let settings = self
            .settings
            .as_ref()
            .ok_or(invalid_proposal_error("Settings are required"))?;

        if settings.controllers.is_none()
            && settings.compute_allocation.is_none()
            && settings.memory_allocation.is_none()
            && settings.freezing_threshold.is_none()
            && settings.log_visibility.is_none()
            && settings.wasm_memory_limit.is_none()
        {
            return Err(invalid_proposal_error(
                "At least one setting must be provided",
            ));
        }

        let controllers = settings
            .controllers
            .as_ref()
            .map(|controllers| controllers.controllers.clone());
        let compute_allocation = settings.compute_allocation.map(Nat::from);
        let memory_allocation = settings.memory_allocation.map(Nat::from);
        let freezing_threshold = settings.freezing_threshold.map(Nat::from);
        let wasm_memory_limit = settings.wasm_memory_limit.map(Nat::from);
        let log_visibility = match settings.log_visibility {
            Some(log_visibility) => Some(Self::valid_log_visibility(log_visibility)?),
            None => None,
        };
        // Reserved cycles limit is not supported yet.
        let reserved_cycles_limit = None;
        Ok(RootCanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            wasm_memory_limit,
            log_visibility,
            reserved_cycles_limit,
        })
    }

    pub fn allowed_when_resources_are_low(&self) -> bool {
        let Ok(canister_id) = self.valid_canister_id() else {
            return false;
        };
        topic_to_manage_canister(&canister_id) == Topic::ProtocolCanisterManagement
    }
}

impl CallCanister for UpdateCanisterSettings {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        if canister_id == ROOT_CANISTER_ID {
            Ok((LIFELINE_CANISTER_ID, "update_root_settings"))
        } else {
            Ok((ROOT_CANISTER_ID, "update_canister_settings"))
        }
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        let settings = self.valid_canister_settings()?;

        if canister_id == ROOT_CANISTER_ID {
            Encode!(&settings)
                .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
        } else {
            let update_settings = UpdateCanisterSettingsRequest {
                canister_id: canister_id.get(),
                settings,
            };
            Encode!(&update_settings)
                .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::governance_error::ErrorType;
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
                let error = update_canister_settings.validate().expect_err(&format!(
                    "Expecting validation error for {update_canister_settings:?} but got Ok(())"
                ));
                assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);
                for keyword in keywords {
                    let error_message = error.error_message.to_lowercase();
                    assert!(
                        error_message.contains(keyword),
                        "{} not found in {:#?}",
                        keyword,
                        error_message
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
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
            }),
        };

        assert_eq!(update_sns_w_canister_settings.validate(), Ok(()));
        assert_eq!(
            update_sns_w_canister_settings.valid_topic(),
            Ok(Topic::ServiceNervousSystemManagement)
        );
        assert_eq!(
            update_sns_w_canister_settings.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "update_canister_settings"))
        );
        assert!(!update_sns_w_canister_settings.allowed_when_resources_are_low());

        let decoded_payload = Decode!(
            &update_sns_w_canister_settings.payload().unwrap(),
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
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
            }),
        };

        assert_eq!(update_root_canister_settings.validate(), Ok(()));
        assert_eq!(
            update_root_canister_settings.valid_topic(),
            Ok(Topic::ProtocolCanisterManagement)
        );
        assert_eq!(
            update_root_canister_settings.canister_and_function(),
            Ok((LIFELINE_CANISTER_ID, "update_root_settings"))
        );
        assert!(update_root_canister_settings.allowed_when_resources_are_low());

        let decoded_payload = Decode!(
            &update_root_canister_settings.payload().unwrap(),
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
                Topic::NetworkCanisterManagement,
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

            assert_eq!(update_canister_settings.validate(), Ok(()));
            assert_eq!(update_canister_settings.valid_topic(), Ok(expected_topic),);
        }
    }
}
