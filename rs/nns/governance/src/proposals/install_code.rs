use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    enable_new_canister_management_topics,
    pb::v1::{install_code::CanisterInstallMode, GovernanceError, InstallCode, Topic},
    proposals::call_canister::CallCanister,
};

use candid::{CandidType, Deserialize, Encode};
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterInstallMode as RootCanisterInstallMode;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use serde::Serialize;

// When calling lifeline's upgrade_root method, this is the request. Keep this in sync with
// `rs/nns/handlers/lifeline/impl/lifeline.mo`.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Serialize)]
struct UpgradeRootProposalPayload {
    wasm_module: Vec<u8>,
    module_arg: Vec<u8>,
    stop_upgrade_start: bool,
}

impl InstallCode {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !enable_new_canister_management_topics() {
            return Err(invalid_proposal_error(
                "InstallCode proposal is not yet supported",
            ));
        }

        let _ = self.valid_canister_id()?;
        let _ = self.valid_install_mode()?;
        let _ = self.valid_wasm_module()?;
        let _ = self.valid_topic()?;
        let _ = self.canister_and_function()?;

        // In the future, we could potentially validate the wasm module to see if it's a valid gzip
        // or a valid WASM.

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

    fn valid_install_mode(&self) -> Result<RootCanisterInstallMode, GovernanceError> {
        let install_mode_i32 = match self.install_mode {
            Some(install_mode) => install_mode,
            None => return Err(invalid_proposal_error("Install mode is required")),
        };
        let install_mode_pb = CanisterInstallMode::try_from(install_mode_i32)
            .unwrap_or(CanisterInstallMode::Unspecified);
        match install_mode_pb {
            CanisterInstallMode::Install => Ok(RootCanisterInstallMode::Install),
            CanisterInstallMode::Reinstall => Ok(RootCanisterInstallMode::Reinstall),
            CanisterInstallMode::Upgrade => Ok(RootCanisterInstallMode::Upgrade),
            CanisterInstallMode::Unspecified => Err(invalid_proposal_error(
                "Unspecified or unrecognized install mode",
            )),
        }
    }

    fn valid_wasm_module(&self) -> Result<&Vec<u8>, GovernanceError> {
        // We do not want to copy the (potentially large) wasm module when validating, so we return
        // a reference and let the caller clone it if needed.
        self.wasm_module
            .as_ref()
            .ok_or(invalid_proposal_error("Wasm module is required"))
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        Ok(topic_to_manage_canister(&canister_id))
    }

    fn payload_to_upgrade_root(&self) -> Result<Vec<u8>, GovernanceError> {
        let stop_upgrade_start = !self.skip_stopping_before_installing.unwrap_or(false);
        let wasm_module = self.valid_wasm_module()?.clone();
        let module_arg = self.arg.clone().unwrap_or_default();

        Encode!(&UpgradeRootProposalPayload {
            stop_upgrade_start,
            wasm_module,
            module_arg,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {}", e)))
    }

    fn payload_to_upgrade_non_root(&self) -> Result<Vec<u8>, GovernanceError> {
        let stop_before_installing = !self.skip_stopping_before_installing.unwrap_or(false);
        let mode = self.valid_install_mode()?;
        let canister_id = self.valid_canister_id()?;
        let wasm_module = self.valid_wasm_module()?.clone();
        let arg = self.arg.clone().unwrap_or_default();
        let compute_allocation = None;
        let memory_allocation = None;

        Encode!(&ChangeCanisterRequest {
            stop_before_installing,
            mode,
            canister_id,
            wasm_module,
            arg,
            compute_allocation,
            memory_allocation,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {}", e)))
    }
}

impl CallCanister for InstallCode {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        // Most canisters are upgraded indirectly via root. In such cases, we call root's
        // change_nns_canister method. The exception is when root is to be upgraded. In that case,
        // upgrades are instead done via lifeline's upgrade_root method.
        if canister_id != ROOT_CANISTER_ID {
            return Ok((ROOT_CANISTER_ID, "change_nns_canister"));
        }

        let install_mode = self.valid_install_mode()?;
        match install_mode {
            RootCanisterInstallMode::Install | RootCanisterInstallMode::Reinstall => {
                // We can potentially support those modes in the future by extending what the
                // lifeline canister can do. However there is no reason to do so currently: (1) the
                // install mode is only useful when root does not have any code, which we don't
                // expect to happen. (2) as the root canister does not have state, there is no
                // reason to do reinstall instead of upgrade; for getting out of open call context
                // problems, only uninstalling and reinstalling the root canister would help
                // (uninstall cancels open calls), and that is achieved by
                // HardResetNnsRootToVersion.
                Err(invalid_proposal_error(&format!(
                    "InstallCode mode {:?} is not supported for root canister, consider using \
                     HardResetNnsRootToVersion proposal instead",
                    install_mode
                )))
            }
            RootCanisterInstallMode::Upgrade => Ok((LIFELINE_CANISTER_ID, "upgrade_root")),
        }
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let canister_id = self.valid_canister_id()?;

        if canister_id == ROOT_CANISTER_ID {
            self.payload_to_upgrade_root()
        } else {
            self.payload_to_upgrade_non_root()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pb::v1::governance_error::ErrorType;

    use ic_nns_constants::REGISTRY_CANISTER_ID;

    #[cfg(feature = "test")]
    use candid::Decode;

    #[cfg(not(feature = "test"))]
    #[test]
    fn test_install_code_disabled() {
        let install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: None,
            skip_stopping_before_installing: None,
        };

        assert_eq!(
            install_code.validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Proposal invalid because of InstallCode proposal is not yet \
                 supported"
                    .to_string(),
            ))
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_invalid_install_code_proposal() {
        let valid_install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
        };

        let is_invalid_proposal_with_keywords = |install_code: InstallCode, keywords: Vec<&str>| {
            let error = install_code
                .validate()
                .expect_err("Expecting validation error for {install_code:?} but got Ok(())");
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
            InstallCode {
                canister_id: None,
                ..valid_install_code.clone()
            },
            vec!["canister id", "required"],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                install_mode: None,
                ..valid_install_code.clone()
            },
            vec!["install mode", "required"],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                install_mode: Some(1000),
                ..valid_install_code.clone()
            },
            vec!["unspecified or unrecognized", "install mode"],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                install_mode: Some(CanisterInstallMode::Unspecified as i32),
                ..valid_install_code.clone()
            },
            vec!["unspecified or unrecognized", "install mode"],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                wasm_module: None,
                ..valid_install_code.clone()
            },
            vec!["wasm module", "required"],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                canister_id: Some(ROOT_CANISTER_ID.get()),
                install_mode: Some(CanisterInstallMode::Install as i32),
                ..valid_install_code.clone()
            },
            vec![
                "installcode mode install",
                "not supported for root canister",
                "hardresetnnsroottoversion",
            ],
        );

        is_invalid_proposal_with_keywords(
            InstallCode {
                canister_id: Some(ROOT_CANISTER_ID.get()),
                install_mode: Some(CanisterInstallMode::Reinstall as i32),
                ..valid_install_code.clone()
            },
            vec![
                "installcode mode reinstall",
                "not supported for root canister",
                "hardresetnnsroottoversion",
            ],
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_upgrade_non_root_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
        };

        assert_eq!(install_code.validate(), Ok(()));
        assert_eq!(
            install_code.valid_topic(),
            Ok(Topic::ProtocolCanisterManagement)
        );
        assert_eq!(
            install_code.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "change_nns_canister"))
        );
        let decoded_payload =
            Decode!(&install_code.payload().unwrap(), ChangeCanisterRequest).unwrap();
        assert_eq!(
            decoded_payload,
            ChangeCanisterRequest {
                stop_before_installing: true,
                mode: RootCanisterInstallMode::Upgrade,
                canister_id: REGISTRY_CANISTER_ID,
                wasm_module: vec![1, 2, 3],
                arg: vec![4, 5, 6],
                compute_allocation: None,
                memory_allocation: None,
            }
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_upgrade_root_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(ROOT_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
        };

        assert_eq!(install_code.validate(), Ok(()));
        assert_eq!(
            install_code.valid_topic(),
            Ok(Topic::ProtocolCanisterManagement)
        );
        assert_eq!(
            install_code.canister_and_function(),
            Ok((LIFELINE_CANISTER_ID, "upgrade_root"))
        );
        let decoded_payload =
            Decode!(&install_code.payload().unwrap(), UpgradeRootProposalPayload).unwrap();
        assert_eq!(
            decoded_payload,
            UpgradeRootProposalPayload {
                stop_upgrade_start: true,
                wasm_module: vec![1, 2, 3],
                module_arg: vec![4, 5, 6],
            }
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_reinstall_code_non_root_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(LIFELINE_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Reinstall as i32),
            arg: None,
            skip_stopping_before_installing: Some(true),
        };

        assert_eq!(install_code.validate(), Ok(()));
        assert_eq!(
            install_code.valid_topic(),
            Ok(Topic::ProtocolCanisterManagement)
        );
        assert_eq!(
            install_code.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "change_nns_canister"))
        );
        let decoded_payload =
            Decode!(&install_code.payload().unwrap(), ChangeCanisterRequest).unwrap();
        assert_eq!(
            decoded_payload,
            ChangeCanisterRequest {
                stop_before_installing: false,
                mode: RootCanisterInstallMode::Reinstall,
                canister_id: LIFELINE_CANISTER_ID,
                wasm_module: vec![1, 2, 3],
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
            }
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_upgrade_canisters_topic_mapping() {
        use ic_base_types::CanisterId;
        use ic_nns_constants::SNS_WASM_CANISTER_ID;

        let test_cases = vec![
            (REGISTRY_CANISTER_ID, Topic::ProtocolCanisterManagement),
            (SNS_WASM_CANISTER_ID, Topic::ServiceNervousSystemManagement),
            (
                CanisterId::from_u64(123_456_789),
                Topic::NetworkCanisterManagement,
            ),
        ];

        for (canister_id, expected_topic) in test_cases {
            let install_code = InstallCode {
                canister_id: Some(canister_id.get()),
                wasm_module: Some(vec![1, 2, 3]),
                install_mode: Some(CanisterInstallMode::Upgrade as i32),
                arg: Some(vec![4, 5, 6]),
                skip_stopping_before_installing: None,
            };

            assert_eq!(install_code.validate(), Ok(()));
            assert_eq!(install_code.valid_topic(), Ok(expected_topic));
        }
    }
}
