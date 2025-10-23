use super::{invalid_proposal_error, topic_to_manage_canister};
use crate::{
    pb::v1::{GovernanceError, InstallCode, Topic, install_code::CanisterInstallMode},
    proposals::call_canister::CallCanister,
};

use candid::{CandidType, Deserialize, Encode, Nat};
use ic_base_types::CanisterId;
use ic_management_canister_types_private::CanisterInstallMode as RootCanisterInstallMode;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::GenericValue;
use maplit::hashmap;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidInstallCode {
    canister_id: CanisterId,
    install_mode: RootCanisterInstallMode,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
    wasm_module_hash: Vec<u8>,
    arg_hash: Option<Vec<u8>>,
    skip_stopping_before_installing: bool,
}

impl TryFrom<InstallCode> for ValidInstallCode {
    type Error = String;

    fn try_from(value: InstallCode) -> Result<Self, Self::Error> {
        let InstallCode {
            canister_id,
            install_mode,
            wasm_module,
            arg,
            skip_stopping_before_installing,
            wasm_module_hash,
            arg_hash,
        } = value;

        let canister_principal_id = canister_id.ok_or("Canister ID is required")?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|e| format!("Invalid canister ID: {e}"))?;
        let install_mode = install_mode.ok_or("Install mode is required")?;
        let install_mode =
            CanisterInstallMode::try_from(install_mode).unwrap_or(CanisterInstallMode::Unspecified);
        let install_mode = RootCanisterInstallMode::try_from(install_mode)?;
        let wasm_module = wasm_module.ok_or("Wasm module is required")?;
        let wasm_module_hash = wasm_module_hash.ok_or("Wasm module hash is somehow empty")?;
        let arg = arg.ok_or("Argument is required")?;
        let skip_stopping_before_installing = skip_stopping_before_installing.unwrap_or(false);

        if canister_id == ROOT_CANISTER_ID && install_mode != RootCanisterInstallMode::Upgrade {
            return Err(format!(
                "InstallCode mode {install_mode:?} is not supported for root canister, consider using \
                HardResetNnsRootToVersion proposal instead"
            ));
        }

        Ok(ValidInstallCode {
            canister_id,
            install_mode,
            wasm_module,
            arg,
            wasm_module_hash,
            arg_hash,
            skip_stopping_before_installing,
        })
    }
}

impl TryFrom<CanisterInstallMode> for RootCanisterInstallMode {
    type Error = String;

    fn try_from(value: CanisterInstallMode) -> Result<Self, Self::Error> {
        match value {
            CanisterInstallMode::Install => Ok(RootCanisterInstallMode::Install),
            CanisterInstallMode::Reinstall => Ok(RootCanisterInstallMode::Reinstall),
            CanisterInstallMode::Upgrade => Ok(RootCanisterInstallMode::Upgrade),
            CanisterInstallMode::Unspecified => {
                Err("Unspecified or unrecognized install mode".to_string())
            }
        }
    }
}

// When calling lifeline's upgrade_root method, this is the request. Keep this in sync with
// `rs/nns/handlers/lifeline/impl/lifeline.mo`.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
struct UpgradeRootProposalPayload {
    wasm_module: Vec<u8>,
    module_arg: Vec<u8>,
    stop_upgrade_start: bool,
}

impl ValidInstallCode {
    pub fn canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    pub fn install_mode(&self) -> &RootCanisterInstallMode {
        &self.install_mode
    }

    pub fn wasm_module_hash(&self) -> &[u8] {
        &self.wasm_module_hash
    }

    pub fn arg_hash(&self) -> &Option<Vec<u8>> {
        &self.arg_hash
    }

    pub fn skip_stopping_before_installing(&self) -> bool {
        self.skip_stopping_before_installing
    }

    pub fn compute_topic_at_creation(&self) -> Topic {
        topic_to_manage_canister(&self.canister_id)
    }

    fn payload_to_upgrade_root(&self) -> Result<Vec<u8>, GovernanceError> {
        let stop_upgrade_start = !self.skip_stopping_before_installing;
        let wasm_module = self.wasm_module.clone();
        let module_arg = self.arg.clone();

        Encode!(&UpgradeRootProposalPayload {
            stop_upgrade_start,
            wasm_module,
            module_arg,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {e}")))
    }

    fn payload_to_upgrade_non_root(&self) -> Result<Vec<u8>, GovernanceError> {
        let stop_before_installing = !self.skip_stopping_before_installing;
        let mode = self.install_mode;
        let canister_id = self.canister_id;
        let wasm_module = self.wasm_module.clone();
        let arg = self.arg.clone();

        Encode!(&ChangeCanisterRequest {
            stop_before_installing,
            mode,
            canister_id,
            wasm_module,
            arg,
            chunked_canister_wasm: None,
        })
        .map_err(|e| invalid_proposal_error(&format!("Failed to encode payload: {e}")))
    }

    pub fn allowed_when_resources_are_low(&self) -> bool {
        topic_to_manage_canister(&self.canister_id) == Topic::ProtocolCanisterManagement
    }
}

impl CallCanister for ValidInstallCode {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        // Most canisters are upgraded indirectly via root. In such cases, we call root's
        // change_nns_canister method. The exception is when root is to be upgraded. In that case,
        // upgrades are instead done via lifeline's upgrade_root method.
        if self.canister_id != ROOT_CANISTER_ID {
            Ok((ROOT_CANISTER_ID, "change_nns_canister"))
        } else {
            Ok((LIFELINE_CANISTER_ID, "upgrade_root"))
        }
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        if self.canister_id == ROOT_CANISTER_ID {
            self.payload_to_upgrade_root()
        } else {
            self.payload_to_upgrade_non_root()
        }
    }
}

impl From<&ValidInstallCode> for GenericValue {
    fn from(value: &ValidInstallCode) -> Self {
        let canister_id = value.canister_id().to_string();
        let install_mode = format!("{:?}", value.install_mode());
        let skip_stopping_before_installing = if value.skip_stopping_before_installing() {
            Nat::from(1u8)
        } else {
            Nat::from(0u8)
        };
        let mut generic_map = hashmap! {
            "canister_id".to_string() => GenericValue::Text(canister_id),
            "install_mode".to_string() => GenericValue::Text(install_mode),
            "skip_stopping_before_installing".to_string() => GenericValue::Nat(skip_stopping_before_installing),
            "wasm_module_hash".to_string() => GenericValue::Blob(value.wasm_module_hash().to_vec()),
        };

        if let Some(arg_hash) = value.arg_hash() {
            generic_map.insert("arg_hash".to_string(), GenericValue::Blob(arg_hash.clone()));
        }

        GenericValue::Map(generic_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use candid::Decode;
    use ic_base_types::CanisterId;
    use ic_crypto_sha2::Sha256;
    use ic_nns_constants::{REGISTRY_CANISTER_ID, SNS_WASM_CANISTER_ID};

    #[test]
    fn test_invalid_install_code_proposal() {
        let valid_install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
            wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
            arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
        };

        let is_invalid_proposal_with_keywords = |install_code: InstallCode, keywords: Vec<&str>| {
            let error_message = ValidInstallCode::try_from(install_code.clone()).expect_err(
                &format!("Expecting validation error for {install_code:#?} but got Ok(())"),
            );
            for keyword in keywords {
                let error_message = error_message.to_lowercase();
                assert!(
                    error_message.contains(keyword),
                    "{keyword} not found in {error_message:#?}"
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
                arg: None,
                ..valid_install_code.clone()
            },
            vec!["argument", "required"],
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

    #[test]
    fn test_upgrade_non_root_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
            wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
            arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
        };

        let valid_install_code = ValidInstallCode::try_from(install_code).unwrap();
        assert_eq!(
            valid_install_code.compute_topic_at_creation(),
            Topic::ProtocolCanisterManagement
        );
        assert_eq!(
            valid_install_code.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "change_nns_canister"))
        );
        assert!(valid_install_code.allowed_when_resources_are_low());
        let decoded_payload = Decode!(
            &valid_install_code.payload().unwrap(),
            ChangeCanisterRequest
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            ChangeCanisterRequest {
                stop_before_installing: true,
                mode: RootCanisterInstallMode::Upgrade,
                canister_id: REGISTRY_CANISTER_ID,
                wasm_module: vec![1, 2, 3],
                arg: vec![4, 5, 6],
                chunked_canister_wasm: None,
            }
        );
    }

    #[test]
    fn test_upgrade_root_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(ROOT_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
            wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
            arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
        };

        let valid_install_code = ValidInstallCode::try_from(install_code).unwrap();
        assert_eq!(
            valid_install_code.compute_topic_at_creation(),
            Topic::ProtocolCanisterManagement
        );
        assert_eq!(
            valid_install_code.canister_and_function(),
            Ok((LIFELINE_CANISTER_ID, "upgrade_root"))
        );
        assert!(valid_install_code.allowed_when_resources_are_low());
        let decoded_payload = Decode!(
            &valid_install_code.payload().unwrap(),
            UpgradeRootProposalPayload
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            UpgradeRootProposalPayload {
                stop_upgrade_start: true,
                wasm_module: vec![1, 2, 3],
                module_arg: vec![4, 5, 6],
            }
        );
    }

    #[test]
    fn test_reinstall_code_non_protocol_canister() {
        let install_code = InstallCode {
            canister_id: Some(SNS_WASM_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Reinstall as i32),
            arg: Some(vec![]),
            skip_stopping_before_installing: Some(true),
            wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
            arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
        };

        let valid_install_code = ValidInstallCode::try_from(install_code).unwrap();
        assert_eq!(
            valid_install_code.compute_topic_at_creation(),
            Topic::ServiceNervousSystemManagement
        );
        assert_eq!(
            valid_install_code.canister_and_function(),
            Ok((ROOT_CANISTER_ID, "change_nns_canister"))
        );
        assert!(!valid_install_code.allowed_when_resources_are_low());
        let decoded_payload = Decode!(
            &valid_install_code.payload().unwrap(),
            ChangeCanisterRequest
        )
        .unwrap();
        assert_eq!(
            decoded_payload,
            ChangeCanisterRequest {
                stop_before_installing: false,
                mode: RootCanisterInstallMode::Reinstall,
                canister_id: SNS_WASM_CANISTER_ID,
                wasm_module: vec![1, 2, 3],
                arg: vec![],
                chunked_canister_wasm: None,
            }
        );
    }

    #[test]
    fn test_upgrade_canisters_topic_mapping() {
        let test_cases = vec![
            (REGISTRY_CANISTER_ID, Topic::ProtocolCanisterManagement),
            (SNS_WASM_CANISTER_ID, Topic::ServiceNervousSystemManagement),
            (
                CanisterId::from_u64(123_456_789),
                Topic::ApplicationCanisterManagement,
            ),
        ];

        for (canister_id, expected_topic) in test_cases {
            let install_code = InstallCode {
                canister_id: Some(canister_id.get()),
                wasm_module: Some(vec![1, 2, 3]),
                install_mode: Some(CanisterInstallMode::Upgrade as i32),
                arg: Some(vec![4, 5, 6]),
                skip_stopping_before_installing: None,
                wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
            };

            let valid_install_code = ValidInstallCode::try_from(install_code).unwrap();
            assert_eq!(
                valid_install_code.compute_topic_at_creation(),
                expected_topic
            );
        }
    }

    #[test]
    fn test_generic_value_conversion() {
        let install_code = InstallCode {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            wasm_module: Some(vec![1, 2, 3]),
            install_mode: Some(CanisterInstallMode::Upgrade as i32),
            arg: Some(vec![4, 5, 6]),
            skip_stopping_before_installing: None,
            wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
            arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
        };

        let valid_install_code = ValidInstallCode::try_from(install_code).unwrap();
        let generic_value = GenericValue::from(&valid_install_code);
        assert_eq!(
            generic_value,
            GenericValue::Map(hashmap! {
                "canister_id".to_string() => GenericValue::Text(REGISTRY_CANISTER_ID.to_string()),
                "install_mode".to_string() => GenericValue::Text("Upgrade".to_string()),
                "skip_stopping_before_installing".to_string() => GenericValue::Nat(Nat::from(0u8)),
                "wasm_module_hash".to_string() => GenericValue::Blob(Sha256::hash(&[1, 2, 3]).to_vec()),
                "arg_hash".to_string() => GenericValue::Blob(Sha256::hash(&[4, 5, 6]).to_vec()),
            })
        );
    }
}
