use crate::{
    are_create_canister_and_install_code_proposals_enabled,
    pb::v1::{
        CreateCanisterAndInstallCode, GovernanceError, SelfDescribingValue, Topic,
        canister_settings::{LogVisibility, SnapshotVisibility},
        governance_error::ErrorType,
        wasm_module,
    },
    proposals::{
        call_canister::{CallCanister, CallCanisterReply},
        invalid_proposal_error,
        self_describing::{DocumentedAction, ValueBuilder},
    },
};
use candid::{Decode, Encode, Nat};
use ic_base_types::CanisterId;
use ic_nervous_system_clients::update_settings::{
    CanisterSettings as RootCanisterSettings, LogVisibility as RootLogVisibility,
    SnapshotVisibility as RootSnapshotVisibility,
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_handler_root_interface as root;

impl CreateCanisterAndInstallCode {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if !are_create_canister_and_install_code_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "CreateCanisterAndInstallCode proposals are not enabled yet.",
            ));
        }

        let Self {
            host_subnet_id,
            canister_settings,
            wasm_module,

            // Validating these is trivial.
            install_arg: _,
            // This is populated by us (the Governance canister), it's not checked.
            install_arg_hash: _,
        } = self;

        let mut defects = vec![];

        // Validate host_subnet_id.
        if host_subnet_id.is_none() {
            defects.push("host_subnet_id is required".to_string());
        }

        // Validate wasm_module.
        match wasm_module {
            Some(wasm) => {
                if let Err(wasm_defects) = wasm.validate() {
                    defects.extend(wasm_defects);
                }
            }
            None => {
                defects.push("wasm_module is required".to_string());
            }
        }

        // Validate canister_settings.
        if let Some(settings) = canister_settings
            && let Err(err) = RootCanisterSettings::try_from(settings)
        {
            defects.push(err.error_message);
        }

        // Assemble (and return) final result.
        if !defects.is_empty() {
            return Err(invalid_proposal_error(&defects.join("; ")));
        }
        Ok(())
    }

    pub fn valid_topic(&self) -> Result<Topic, GovernanceError> {
        // This is consistent with topic_to_manage_canister.
        Ok(Topic::ApplicationCanisterManagement)
    }

    /// Returns a copy with potentially large fields (wasm_module content,
    /// install_arg) elided. Hashes are preserved. This avoids cloning large
    /// blobs when only metadata is needed (esp. for conversion to
    /// SelfDescribingValue).
    pub fn abridge(&self) -> Self {
        let Self {
            host_subnet_id,
            canister_settings,
            wasm_module,
            install_arg_hash,

            // Not used.
            install_arg: _,
        } = self;

        Self {
            host_subnet_id: *host_subnet_id,
            canister_settings: canister_settings.clone(),
            wasm_module: wasm_module.as_ref().map(|w| w.abridge()),
            install_arg: None,
            install_arg_hash: install_arg_hash.clone(),
        }
    }
}

/// Converts to equivalent request to the Root canister's
/// create_canister_and_install_code method.
impl TryFrom<CreateCanisterAndInstallCode> for root::CreateCanisterAndInstallCodeRequest {
    type Error = GovernanceError;

    fn try_from(value: CreateCanisterAndInstallCode) -> Result<Self, GovernanceError> {
        let CreateCanisterAndInstallCode {
            host_subnet_id,
            canister_settings,
            wasm_module,
            install_arg,

            // Not needed for the request.
            install_arg_hash: _,
        } = value;

        let host_subnet_id =
            host_subnet_id.ok_or_else(|| invalid_proposal_error("host_subnet_id is required"))?;

        let canister_settings = canister_settings
            .as_ref()
            .map(RootCanisterSettings::try_from)
            .transpose()?;

        let wasm_module = wasm_module
            .and_then(|w| w.content)
            .map(|content| {
                let wasm_module::Content::Inlined(bytes) = content;
                bytes
            })
            .ok_or_else(|| invalid_proposal_error("wasm_module is required"))?;

        let install_arg = install_arg.unwrap_or_default();

        Ok(Self {
            host_subnet_id,
            canister_settings,
            wasm_module,
            install_arg,
        })
    }
}

impl TryFrom<LogVisibility> for RootLogVisibility {
    type Error = GovernanceError;

    fn try_from(value: LogVisibility) -> Result<Self, GovernanceError> {
        match value {
            LogVisibility::Controllers => Ok(RootLogVisibility::Controllers),
            LogVisibility::Public => Ok(RootLogVisibility::Public),
            LogVisibility::Unspecified => Err(invalid_proposal_error("Invalid log visibility")),
        }
    }
}

impl TryFrom<SnapshotVisibility> for RootSnapshotVisibility {
    type Error = GovernanceError;

    fn try_from(value: SnapshotVisibility) -> Result<Self, GovernanceError> {
        match value {
            SnapshotVisibility::Controllers => Ok(RootSnapshotVisibility::Controllers),
            SnapshotVisibility::Public => Ok(RootSnapshotVisibility::Public),
            SnapshotVisibility::Unspecified => {
                Err(invalid_proposal_error("Invalid snapshot visibility"))
            }
        }
    }
}

impl TryFrom<&crate::pb::v1::CanisterSettings> for RootCanisterSettings {
    type Error = GovernanceError;

    fn try_from(original: &crate::pb::v1::CanisterSettings) -> Result<Self, GovernanceError> {
        let crate::pb::v1::CanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            log_visibility,
            snapshot_visibility,
            wasm_memory_limit,
            wasm_memory_threshold,
        } = original;

        let controllers = controllers.as_ref().map(|c| c.controllers.clone());

        let log_visibility = match log_visibility {
            Some(log_visibility) => {
                let log_visibility = LogVisibility::try_from(*log_visibility)
                    .map_err(|_| invalid_proposal_error("Invalid log visibility"))?;
                Some(RootLogVisibility::try_from(log_visibility)?)
            }
            None => None,
        };

        let snapshot_visibility = match snapshot_visibility {
            Some(snapshot_visibility) => {
                let snapshot_visibility = SnapshotVisibility::try_from(*snapshot_visibility)
                    .map_err(|_| invalid_proposal_error("Invalid snapshot visibility"))?;
                Some(RootSnapshotVisibility::try_from(snapshot_visibility)?)
            }
            None => None,
        };

        Ok(RootCanisterSettings {
            controllers,
            compute_allocation: compute_allocation.map(Nat::from),
            memory_allocation: memory_allocation.map(Nat::from),
            freezing_threshold: freezing_threshold.map(Nat::from),
            reserved_cycles_limit: None,
            log_visibility,
            snapshot_visibility,
            wasm_memory_limit: wasm_memory_limit.map(Nat::from),
            wasm_memory_threshold: wasm_memory_threshold.map(Nat::from),
        })
    }
}

impl CallCanister for CreateCanisterAndInstallCode {
    type Reply = root::CreateCanisterAndInstallCodeOk;

    fn canister_and_function(&self) -> Result<(CanisterId, &str), GovernanceError> {
        if !are_create_canister_and_install_code_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "CreateCanisterAndInstallCode proposals are not enabled yet.",
            ));
        }

        Ok((ROOT_CANISTER_ID, "create_canister_and_install_code"))
    }

    fn payload(&self) -> Result<Vec<u8>, GovernanceError> {
        if !are_create_canister_and_install_code_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "CreateCanisterAndInstallCode proposals are not enabled yet.",
            ));
        }

        let request = root::CreateCanisterAndInstallCodeRequest::try_from(self.clone())?;

        Encode!(&request).map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Failed to encode CreateCanisterAndInstallCode: {}", e),
            )
        })
    }
}

impl CallCanisterReply for root::CreateCanisterAndInstallCodeOk {
    fn try_decode(encoded_reply: &[u8]) -> Result<Option<Self>, GovernanceError> {
        let result =
            Decode!(encoded_reply, root::CreateCanisterAndInstallCodeResponse).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Failed to decode CreateCanisterAndInstallCodeResponse: {err}"),
                )
            })?;

        let result = Result::from(result).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Root returned error for CreateCanisterAndInstallCode: {:?}",
                    err
                ),
            )
        })?;

        Ok(Some(result))
    }
}

impl DocumentedAction for CreateCanisterAndInstallCode {
    const NAME: &'static str = "Create Canister and Install Code";
    const DESCRIPTION: &'static str = r#"Create a new canister and install code into it. \
        Can be hosted by a non-NNS subnet. Unlike with NnsCanisterInstall, the created \
        canister is not considered an "NNS" canister. The canister is created by the NNS \
        Root canister, which means that if no controllers are specified, Root will be the \
        controller by default. The target subnet can be the NNS subnet, but does not have
        to be. The host subnet should probably be a trusted subnet."#;
}

impl From<CreateCanisterAndInstallCode> for SelfDescribingValue {
    fn from(value: CreateCanisterAndInstallCode) -> Self {
        let CreateCanisterAndInstallCode {
            host_subnet_id,
            canister_settings,
            wasm_module,
            install_arg: _,
            install_arg_hash,
        } = value;

        let wasm_module_hash = wasm_module.and_then(|w| w.hash);

        ValueBuilder::new()
            .add_field("host_subnet_id", host_subnet_id)
            .add_field("canister_settings", canister_settings)
            .add_field("wasm_module_hash", wasm_module_hash)
            .add_field("install_arg_hash", install_arg_hash)
            .build()
    }
}
