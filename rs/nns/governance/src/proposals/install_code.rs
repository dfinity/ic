use crate::{
    pb::v1::{
        governance_error::ErrorType, install_code::CanisterInstallMode, GovernanceError,
        InstallCode, Topic,
    },
    proposals::call_canister::CallCanister,
};

use candid::Encode;
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterInstallMode as RootCanisterInstallMode;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{
    BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID, CYCLES_LEDGER_CANISTER_ID,
    CYCLES_LEDGER_INDEX_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID,
    GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, ICP_LEDGER_ARCHIVE_1_CANISTER_ID,
    ICP_LEDGER_ARCHIVE_CANISTER_ID, LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID,
    LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};

const PROTOCOL_CANISTER_IDS: [&CanisterId; 16] = [
    &REGISTRY_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &CYCLES_MINTING_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
    &GENESIS_TOKEN_CANISTER_ID,
    &ICP_LEDGER_ARCHIVE_CANISTER_ID,
    &LEDGER_INDEX_CANISTER_ID,
    &ICP_LEDGER_ARCHIVE_1_CANISTER_ID,
    &SUBNET_RENTAL_CANISTER_ID,
    &EXCHANGE_RATE_CANISTER_ID,
    &BITCOIN_MAINNET_CANISTER_ID,
    &BITCOIN_TESTNET_CANISTER_ID,
    &CYCLES_LEDGER_CANISTER_ID,
    &CYCLES_LEDGER_INDEX_CANISTER_ID,
];

impl InstallCode {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !cfg!(feature = "test") {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal is not yet supported",
            ));
        }

        let _ = self.valid_canister_id()?;
        let _ = self.valid_install_mode()?;
        let _ = self.valid_topic()?;

        if self.wasm_module.is_none() {
            return Err(Self::invalid_proposal_error("Wasm module is required"));
        }

        Ok(())
    }

    fn valid_canister_id(&self) -> Result<CanisterId, GovernanceError> {
        let canister_principal_id = self
            .canister_id
            .ok_or(Self::invalid_proposal_error("Canister ID is required"))?;
        let canister_id = CanisterId::try_from(canister_principal_id)
            .map_err(|_| Self::invalid_proposal_error("Invalid canister ID"))?;
        if canister_id == ROOT_CANISTER_ID {
            // TODO(NNS1-3190): support changing root canister
            Err(Self::invalid_proposal_error(
                "InstallCode for root canister is not supported yet",
            ))
        } else {
            Ok(canister_id)
        }
    }

    fn valid_install_mode(&self) -> Result<RootCanisterInstallMode, GovernanceError> {
        let install_mode_i32 = match self.install_mode {
            Some(install_mode) => install_mode,
            None => return Err(Self::invalid_proposal_error("Install mode is required")),
        };
        let install_mode_pb = CanisterInstallMode::try_from(install_mode_i32)
            .unwrap_or(CanisterInstallMode::Unspecified);
        match install_mode_pb {
            CanisterInstallMode::Install => Ok(RootCanisterInstallMode::Install),
            CanisterInstallMode::Reinstall => Ok(RootCanisterInstallMode::Reinstall),
            CanisterInstallMode::Upgrade => Ok(RootCanisterInstallMode::Upgrade),
            CanisterInstallMode::Unspecified => Err(Self::invalid_proposal_error(
                "Unspecified or unrecognized install mode",
            )),
        }
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        if PROTOCOL_CANISTER_IDS.contains(&&canister_id) {
            Ok(Topic::ProtocolCanisterManagement)
        } else {
            Err(Self::invalid_proposal_error(
                "Canister ID is not a protocol canister",
            ))
        }
    }

    fn invalid_proposal_error(reason: &str) -> GovernanceError {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("InstallCode proposal invalid because of {}", reason),
        )
    }
}

impl CallCanister for InstallCode {
    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        let canister_id = self.valid_canister_id()?;
        if canister_id == ROOT_CANISTER_ID {
            // TODO(NNS1-3190): support changing root canister
            return Err(Self::invalid_proposal_error(
                "InstallCode for root canister is not supported yet",
            ));
        }
        Ok((ROOT_CANISTER_ID, "change_nns_canister"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let stop_before_installing = !self.skip_stopping_before_installing.unwrap_or(false);
        let mode = self.valid_install_mode()?;
        let canister_id = self.valid_canister_id()?;
        let wasm_module = self
            .wasm_module
            .clone()
            .ok_or(Self::invalid_proposal_error("Wasm module is required"))?;
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
        .map_err(|e| Self::invalid_proposal_error(&format!("Failed to encode payload: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "InstallCode proposal is not yet supported".to_string(),
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

        assert_eq!(
            InstallCode {
                canister_id: None,
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Canister ID is required".to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                install_mode: None,
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Install mode is required".to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                install_mode: Some(1000),
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Unspecified or unrecognized install mode"
                    .to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                install_mode: Some(CanisterInstallMode::Unspecified as i32),
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Unspecified or unrecognized install mode"
                    .to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                wasm_module: None,
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Wasm module is required".to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                canister_id: Some(ROOT_CANISTER_ID.get()),
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of InstallCode for root canister is not \
                 supported yet"
                    .to_string(),
            ))
        );
        assert_eq!(
            InstallCode {
                canister_id: Some(ic_nns_constants::SNS_WASM_CANISTER_ID.get()),
                ..valid_install_code.clone()
            }
            .validate(),
            Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "InstallCode proposal invalid because of Canister ID is not a protocol canister"
                    .to_string(),
            ))
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
}
