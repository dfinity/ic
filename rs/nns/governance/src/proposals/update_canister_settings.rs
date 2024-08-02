use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
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
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_handler_root_interface::UpdateCanisterSettingsRequest;

impl UpdateCanisterSettings {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !cfg!(feature = "test") {
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
        if canister_id == ROOT_CANISTER_ID {
            return Err(invalid_proposal_error(
                "Updating root canister settings is not supported yet.",
            ));
        }
        Ok(canister_id)
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        topic_to_manage_canister(&canister_id)
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
            Some(log_visibility_i32) => Some(Self::valid_log_visibility(log_visibility_i32)?),
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
}

impl CallCanister for UpdateCanisterSettings {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "update_canister_settings"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let canister_id = self.valid_canister_id()?.get();
        let settings = self.valid_canister_settings()?;
        let update_settings = UpdateCanisterSettingsRequest {
            canister_id,
            settings,
        };
        Encode!(&update_settings)
            .map_err(|err| invalid_proposal_error(&format!("Failed to encode payload: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::governance_error::ErrorType;
    #[cfg(feature = "test")]
    use crate::pb::v1::update_canister_settings::{CanisterSettings, Controllers};

    use ic_nns_constants::LEDGER_CANISTER_ID;

    #[cfg(not(feature = "test"))]
    #[test]
    fn update_canister_settings_disabled() {
        let update_canister_settings = UpdateCanisterSettings {
            canister_id: Some(LEDGER_CANISTER_ID.get()),
            settings: Some(Default::default()),
        };

        assert_eq!(
            update_canister_settings.validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Proposal invalid because of UpdateCanisterSettings proposal is not yet supported"
                    .to_string(),
            ))
        );
    }

    #[cfg(feature = "test")]
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
                let error = match update_canister_settings.validate() {
                    Err(error) => error,
                    Ok(_) => panic!(
                        "Expected an error for invalid proposal {:?} but it's valid",
                        update_canister_settings
                    ),
                };
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

        is_invalid_proposal_with_keywords(
            UpdateCanisterSettings {
                canister_id: Some(ROOT_CANISTER_ID.get()),
                ..valid_update_canister_settings.clone()
            },
            vec!["root canister", "not supported"],
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_update_ledger_canister_settings() {
        use candid::Decode;
        use ic_nns_constants::GOVERNANCE_CANISTER_ID;

        let update_ledger_canister_settings = UpdateCanisterSettings {
            canister_id: Some(LEDGER_CANISTER_ID.get()),
            settings: Some(CanisterSettings {
                controllers: Some(Controllers {
                    controllers: vec![GOVERNANCE_CANISTER_ID.get()],
                }),
                memory_allocation: Some(1 << 32),
                wasm_memory_limit: Some(1 << 31),
                compute_allocation: Some(10),
                freezing_threshold: Some(100),
                log_visibility: Some(LogVisibility::Public as i32),
            }),
        };

        assert_eq!(update_ledger_canister_settings.validate(), Ok(()));
        assert_eq!(
            update_ledger_canister_settings.valid_topic(),
            Ok(Topic::ProtocolCanisterManagement)
        );
        assert_eq!(
            update_ledger_canister_settings.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "update_canister_settings"))
        );

        let decoded_payload = Decode!(
            &update_ledger_canister_settings.payload().unwrap(),
            UpdateCanisterSettingsRequest
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            UpdateCanisterSettingsRequest {
                canister_id: LEDGER_CANISTER_ID.get(),
                settings: RootCanisterSettings {
                    controllers: Some(vec![GOVERNANCE_CANISTER_ID.get()]),
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
}
