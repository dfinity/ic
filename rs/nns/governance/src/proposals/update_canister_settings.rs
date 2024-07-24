use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    pb::v1::{
        update_canister_settings::CanisterSettings, GovernanceError, Topic, UpdateCanisterSettings,
    },
    proposals::call_canister::CallCanister,
};

use ic_base_types::CanisterId;
use ic_nns_constants::ROOT_CANISTER_ID;

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
        Ok(canister_id)
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        topic_to_manage_canister(&canister_id)
    }

    fn valid_canister_settings(&self) -> Result<CanisterSettings, GovernanceError> {
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

        Ok(settings.clone())
    }
}

impl CallCanister for UpdateCanisterSettings {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "update_canister_settings"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        // TODO(NNS1-2522): convert to payload to be sent to Root.
        Err(invalid_proposal_error(
            "UpdateCanisterSettings not yet supported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::governance_error::ErrorType;
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
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_update_ledger_canister_settings() {
        let update_ledger_canister_settings = UpdateCanisterSettings {
            canister_id: Some(LEDGER_CANISTER_ID.get()),
            settings: Some(CanisterSettings {
                memory_allocation: Some(1 << 30),
                ..Default::default()
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

        // TODO(NNS1-2522): test payload after it's implemented.
    }
}
