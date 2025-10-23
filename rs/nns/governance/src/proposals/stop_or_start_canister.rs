use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    pb::v1::{GovernanceError, StopOrStartCanister, Topic, stop_or_start_canister::CanisterAction},
    proposals::call_canister::CallCanister,
};

use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_root::change_canister::{
    CanisterAction as RootCanisterAction, StopOrStartCanisterRequest,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::GenericValue;
use maplit::hashmap;

const CANISTERS_NOT_ALLOWED_TO_STOP: [&CanisterId; 3] = [
    &ROOT_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
];

#[derive(Debug, Clone, PartialEq)]
pub struct ValidStopOrStartCanister {
    canister_id: CanisterId,
    action: RootCanisterAction,
}

impl TryFrom<StopOrStartCanister> for ValidStopOrStartCanister {
    type Error = String;

    fn try_from(value: StopOrStartCanister) -> Result<Self, Self::Error> {
        let StopOrStartCanister {
            canister_id,
            action,
        } = value;

        let canister_principal_id = canister_id.ok_or("Canister ID is required")?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|e| format!("Invalid canister ID: {e}"))?;

        let action_i32 = action.ok_or("Canister action is required")?;
        let action_pb = CanisterAction::try_from(action_i32).unwrap_or(CanisterAction::Unspecified);

        let action = match action_pb {
            CanisterAction::Stop => RootCanisterAction::Stop,
            CanisterAction::Start => RootCanisterAction::Start,
            CanisterAction::Unspecified => {
                return Err("Canister action is unspecified or unrecognized".to_string());
            }
        };

        // Validate that we're not trying to stop critical canisters
        if CANISTERS_NOT_ALLOWED_TO_STOP.contains(&&canister_id)
            && action == RootCanisterAction::Stop
        {
            return Err("Canister is not allowed to be stopped".to_string());
        }

        Ok(ValidStopOrStartCanister {
            canister_id,
            action,
        })
    }
}

impl ValidStopOrStartCanister {
    pub fn canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    pub fn action(&self) -> &RootCanisterAction {
        &self.action
    }

    pub fn compute_topic_at_creation(&self) -> Topic {
        topic_to_manage_canister(&self.canister_id)
    }

    pub fn validate(&self) -> Result<(), GovernanceError> {
        // Validation already happened in TryFrom
        Ok(())
    }
}

impl CallCanister for ValidStopOrStartCanister {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        Ok((ROOT_CANISTER_ID, "stop_or_start_nns_canister"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        Encode!(&StopOrStartCanisterRequest {
            canister_id: self.canister_id,
            action: self.action,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {e}")))
    }
}

impl From<&ValidStopOrStartCanister> for GenericValue {
    fn from(value: &ValidStopOrStartCanister) -> Self {
        let canister_id = value.canister_id().to_string();
        let action = format!("{:?}", value.action());

        GenericValue::Map(hashmap! {
            "canister_id".to_string() => GenericValue::Text(canister_id),
            "action".to_string() => GenericValue::Text(action),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use candid::Decode;
    use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;

    #[test]
    fn test_invalid_stop_or_start_canister() {
        let valid_stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        let is_invalid_proposal_with_keywords =
            |stop_or_start_canister: StopOrStartCanister, keywords: Vec<&str>| {
                let error_message = ValidStopOrStartCanister::try_from(
                    stop_or_start_canister.clone(),
                )
                .expect_err(&format!(
                    "Expecting validation error for {stop_or_start_canister:#?} but got Ok(())"
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
                canister_id: Some(ROOT_CANISTER_ID.get()),
                action: Some(CanisterAction::Stop as i32),
            },
            vec!["not allowed to be stopped"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                canister_id: Some(LIFELINE_CANISTER_ID.get()),
                action: Some(CanisterAction::Stop as i32),
            },
            vec!["not allowed to be stopped"],
        );

        is_invalid_proposal_with_keywords(
            StopOrStartCanister {
                canister_id: Some(GOVERNANCE_CANISTER_ID.get()),
                action: Some(CanisterAction::Stop as i32),
            },
            vec!["not allowed to be stopped"],
        );
    }

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

            let valid_stop_or_start_canister =
                ValidStopOrStartCanister::try_from(stop_or_start_canister).unwrap();
            assert_eq!(
                valid_stop_or_start_canister.compute_topic_at_creation(),
                Topic::ProtocolCanisterManagement
            );
            assert_eq!(
                valid_stop_or_start_canister.canister_and_function(),
                Ok((ROOT_CANISTER_ID, "stop_or_start_nns_canister"))
            );
            let decoded_payload = Decode!(
                &valid_stop_or_start_canister.payload().unwrap(),
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

    #[test]
    fn test_start_lifeline_canister() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(LIFELINE_CANISTER_ID.get()),
            action: Some(CanisterAction::Start as i32),
        };

        let valid_stop_or_start_canister =
            ValidStopOrStartCanister::try_from(stop_or_start_canister).unwrap();
        assert_eq!(
            valid_stop_or_start_canister.compute_topic_at_creation(),
            Topic::ProtocolCanisterManagement
        );
        assert_eq!(
            valid_stop_or_start_canister.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "stop_or_start_nns_canister"))
        );
        let decoded_payload = Decode!(
            &valid_stop_or_start_canister.payload().unwrap(),
            StopOrStartCanisterRequest
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            StopOrStartCanisterRequest {
                canister_id: LIFELINE_CANISTER_ID,
                action: RootCanisterAction::Start,
            }
        );
    }

    #[test]
    fn test_start_canister_topic_mapping() {
        use ic_base_types::CanisterId;
        use ic_nns_constants::SNS_WASM_CANISTER_ID;

        let test_cases = vec![
            (
                CYCLES_MINTING_CANISTER_ID,
                Topic::ProtocolCanisterManagement,
            ),
            (SNS_WASM_CANISTER_ID, Topic::ServiceNervousSystemManagement),
            (
                CanisterId::from_u64(123_456_789),
                Topic::ApplicationCanisterManagement,
            ),
        ];

        for (canister_id, expected_topic) in test_cases {
            let stop_or_start_canister = StopOrStartCanister {
                canister_id: Some(canister_id.get()),
                action: Some(CanisterAction::Start as i32),
            };

            let valid_stop_or_start_canister =
                ValidStopOrStartCanister::try_from(stop_or_start_canister).unwrap();
            assert_eq!(
                valid_stop_or_start_canister.compute_topic_at_creation(),
                expected_topic
            );
        }
    }

    #[test]
    fn test_generic_value_conversion() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        let valid_stop_or_start_canister =
            ValidStopOrStartCanister::try_from(stop_or_start_canister).unwrap();
        let generic_value = GenericValue::from(&valid_stop_or_start_canister);
        assert_eq!(
            generic_value,
            GenericValue::Map(hashmap! {
                "canister_id".to_string() => GenericValue::Text(CYCLES_MINTING_CANISTER_ID.to_string()),
                "action".to_string() => GenericValue::Text("Stop".to_string()),
            })
        );
    }
}
