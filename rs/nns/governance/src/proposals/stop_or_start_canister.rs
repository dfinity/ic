use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    pb::v1::{stop_or_start_canister::CanisterAction, GovernanceError, StopOrStartCanister, Topic},
    proposals::call_canister::CallCanister,
};

use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_root::change_canister::{
    CanisterAction as RootCanisterAction, StopOrStartCanisterRequest,
};
use ic_nns_constants::ROOT_CANISTER_ID;

impl StopOrStartCanister {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !cfg!(feature = "test") {
            return Err(invalid_proposal_error(
                "StopOrStartCanister proposal is not yet supported",
            ));
        }

        let _ = self.valid_canister_id()?;
        let _ = self.valid_topic()?;
        let _ = self.valid_canister_action()?;

        Ok(())
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        topic_to_manage_canister(&canister_id)
    }

    fn valid_canister_id(&self) -> Result<CanisterId, GovernanceError> {
        let canister_principal_id = self
            .canister_id
            .ok_or(invalid_proposal_error("Canister ID is required"))?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|_| invalid_proposal_error("Invalid canister ID"))?;
        Ok(canister_id)
    }

    fn valid_canister_action(&self) -> Result<RootCanisterAction, GovernanceError> {
        let canister_action_i32 = match self.action {
            Some(canister_action) => canister_action,
            None => return Err(invalid_proposal_error("Canister action is required")),
        };

        let canister_action_pb =
            CanisterAction::try_from(canister_action_i32).unwrap_or(CanisterAction::Unspecified);

        match canister_action_pb {
            CanisterAction::Stop => Ok(RootCanisterAction::Stop),
            CanisterAction::Start => Ok(RootCanisterAction::Start),
            CanisterAction::Unspecified => Err(invalid_proposal_error(
                "Canister action is unspecified or unrecognized",
            )),
        }
    }
}

impl CallCanister for StopOrStartCanister {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "stop_or_start_nns_canister"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        let action = self.valid_canister_action()?;

        Encode!(&StopOrStartCanisterRequest {
            canister_id,
            action,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::governance_error::ErrorType;
    use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;

    #[cfg(feature = "test")]
    use candid::Decode;

    #[cfg(not(feature = "test"))]
    #[test]
    fn stop_or_start_canister_disabled() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        assert_eq!(
            stop_or_start_canister.validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Proposal invalid because of StopOrStartCanister proposal is not yet supported"
                    .to_string(),
            ))
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_invalid_stop_or_start_canister() {
        let valid_stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        let is_invalid_proposal_with_keywords =
            |stop_or_start_canister: StopOrStartCanister, keywords: Vec<&str>| {
                let error = stop_or_start_canister.validate().unwrap_err();
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
            StopOrStartCanister {
                canister_id: None,
                ..valid_stop_or_start_canister.clone()
            },
            vec!["canister id", "required"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                action: None,
                ..valid_stop_or_start_canister.clone()
            },
            vec!["action", "required"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                action: Some(CanisterAction::Unspecified as i32),
                ..valid_stop_or_start_canister.clone()
            },
            vec!["unspecified or unrecognized", "action"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                action: Some(1000),
                ..valid_stop_or_start_canister.clone()
            },
            vec!["unspecified or unrecognized", "action"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                canister_id: Some(ic_nns_constants::SNS_WASM_CANISTER_ID.get()),
                ..valid_stop_or_start_canister.clone()
            },
            vec!["canister id", "not a protocol canister"],
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_stop_or_start_cycles_minting_canister() {
        for (canister_action, payload_canister_action) in &[
            (CanisterAction::Stop, RootCanisterAction::Stop),
            (CanisterAction::Start, RootCanisterAction::Start),
        ] {
            let stop_or_start_canister = StopOrStartCanister {
                canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
                action: Some(*canister_action as i32),
            };

            assert_eq!(stop_or_start_canister.validate(), Ok(()));
            assert_eq!(
                stop_or_start_canister.valid_topic(),
                Ok(Topic::ProtocolCanisterManagement)
            );
            assert_eq!(
                stop_or_start_canister.canister_and_function(),
                Ok((ROOT_CANISTER_ID, "stop_or_start_nns_canister"))
            );
            let decoded_payload = Decode!(
                &stop_or_start_canister.payload().unwrap(),
                StopOrStartCanisterRequest
            )
            .unwrap();
            assert_eq!(
                decoded_payload,
                StopOrStartCanisterRequest {
                    canister_id: CYCLES_MINTING_CANISTER_ID,
                    action: *payload_canister_action,
                }
            );
        }
    }
}
