use crate::{
    pb::v1::{
        GovernanceError, SelfDescribingValue, StopOrStartCanister, Topic,
        stop_or_start_canister::CanisterAction,
    },
    proposals::{
        call_canister::CallCanister,
        invalid_proposal_error,
        self_describing::{
            LocallyDescribableProposalAction, SelfDescribingProstEnum, ValueBuilder,
        },
        topic_to_manage_canister,
    },
};

use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_root::change_canister::{
    CanisterAction as RootCanisterAction, StopOrStartCanisterRequest,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};

const CANISTERS_NOT_ALLOWED_TO_STOP: [&CanisterId; 3] = [
    &ROOT_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
];

impl StopOrStartCanister {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        let canister_action = self.valid_canister_action()?;
        let _ = self.valid_topic()?;

        // Note that any proposals trying to start governance/root does not make sense since if they
        // are stopped/stopping, they can't be started as they need to be running in order to
        // execute the proposal. However, we don't disallow them as they are harmless.
        if CANISTERS_NOT_ALLOWED_TO_STOP.contains(&&canister_id)
            && canister_action == RootCanisterAction::Stop
        {
            return Err(invalid_proposal_error(
                "Canister is not allowed to be stopped",
            ));
        }

        Ok(())
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        Ok(topic_to_manage_canister(&canister_id))
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
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {e}")))
    }
}

impl LocallyDescribableProposalAction for StopOrStartCanister {
    const TYPE_NAME: &'static str = "Stop or Start Canister";
    const TYPE_DESCRIPTION: &'static str = "Stops or starts an NNS canister.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        let Self {
            canister_id,
            action,
        } = self;

        let action = action.map(SelfDescribingProstEnum::<CanisterAction>::new);

        ValueBuilder::new()
            .add_field_with_empty_as_fallback("canister_id", *canister_id)
            .add_field_with_empty_as_fallback("action", action)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        pb::v1::governance_error::ErrorType,
        proposals::self_describing::LocallyDescribableProposalAction,
    };

    use candid::Decode;
    use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
    use ic_nns_governance_api::SelfDescribingValue;
    use maplit::hashmap;

    #[test]
    fn test_invalid_stop_or_start_canister() {
        let valid_stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        let is_invalid_proposal_with_keywords =
            |stop_or_start_canister: StopOrStartCanister, keywords: Vec<&str>| {
                let error = stop_or_start_canister.validate().expect_err(&format!(
                    "Expecting validation error for {stop_or_start_canister:?} but got Ok(())"
                ));
                assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);
                for keyword in keywords {
                    let error_message = error.error_message.to_lowercase();
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

    #[test]
    fn test_start_lifeline_canister() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(LIFELINE_CANISTER_ID.get()),
            action: Some(CanisterAction::Start as i32),
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

            assert_eq!(stop_or_start_canister.validate(), Ok(()));
            assert_eq!(stop_or_start_canister.valid_topic(), Ok(expected_topic));
        }
    }

    #[test]
    fn test_stop_or_start_canister_to_self_describing_stop() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        };

        let action = stop_or_start_canister.to_self_describing_action();
        let value = SelfDescribingValue::from(action.value.unwrap());

        assert_eq!(
            value,
            SelfDescribingValue::Map(hashmap! {
                "canister_id".to_string() => SelfDescribingValue::Text(CYCLES_MINTING_CANISTER_ID.get().to_string()),
                "action".to_string() => SelfDescribingValue::Text("Stop".to_string()),
            })
        );
    }

    #[test]
    fn test_stop_or_start_canister_to_self_describing_start() {
        let stop_or_start_canister = StopOrStartCanister {
            canister_id: Some(CYCLES_MINTING_CANISTER_ID.get()),
            action: Some(CanisterAction::Start as i32),
        };

        let action = stop_or_start_canister.to_self_describing_action();
        let value = SelfDescribingValue::from(action.value.unwrap());

        assert_eq!(
            value,
            SelfDescribingValue::Map(hashmap! {
                "canister_id".to_string() => SelfDescribingValue::Text(CYCLES_MINTING_CANISTER_ID.get().to_string()),
                "action".to_string() => SelfDescribingValue::Text("Start".to_string()),
            })
        );
    }
}
