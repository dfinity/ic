use crate::governance::Governance;
use crate::{
    governance::log_prefix,
    logs::{ERROR, INFO},
    pb::v1::{
        governance_error::ErrorType, ExecuteGenericNervousSystemFunction, GovernanceError,
        NervousSystemFunction,
    },
    proposal::ValidGenericNervousSystemFunction,
    types::Environment,
};
use candid::{Decode, Encode};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResultFromManagementCanister, CanisterStatusType},
    update_settings::{CanisterSettings, UpdateSettings},
};
use std::convert::TryFrom;

/// Attempts to return a canister id given a principal id and returns an error if no id or an
/// invalid id were given.
pub fn get_canister_id(canister_id: &Option<PrincipalId>) -> Result<CanisterId, GovernanceError> {
    let canister_id = canister_id.ok_or_else(|| {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "No canister ID was specified.",
        )
    })?;

    Ok(CanisterId::unchecked_from_principal(canister_id))
}

/// Upgrades a canister controlled by governance.
pub async fn upgrade_canister_directly(
    env: &dyn Environment,
    canister_id: CanisterId,
    wasm: Vec<u8>,
    arg: Vec<u8>,
) -> Result<(), GovernanceError> {
    log!(
        INFO,
        "{}Begin: Stop canister {}.",
        log_prefix(),
        canister_id
    );
    stop_canister(env, canister_id).await?;
    log!(INFO, "{}End: Stop canister {}.", log_prefix(), canister_id);

    log!(
        INFO,
        "{}Begin: Install code into canister {}",
        log_prefix(),
        canister_id
    );
    let install_result = install_code(env, canister_id, wasm, arg)
        // No question mark operator here, because we always want to re-start
        // the canister after attempting install_code, even if install_code
        // fails.
        .await;
    log!(
        INFO,
        "{}End: Install code into canister {}",
        log_prefix(),
        canister_id
    );

    log!(
        INFO,
        "{}Begin: Re-start canister {}",
        log_prefix(),
        canister_id
    );
    start_canister(env, canister_id).await?;
    log!(
        INFO,
        "{}End: Re-start canister {}",
        log_prefix(),
        canister_id
    );

    install_result
}

/// Installs a new wasm to a canister id (target canister must be controlled by governance).
async fn install_code(
    env: &dyn Environment,
    canister_id: CanisterId,
    wasm: Vec<u8>,
    arg: Vec<u8>,
) -> Result<(), GovernanceError> {
    let install_code_args = ic_management_canister_types::InstallCodeArgs {
        mode: ic_management_canister_types::CanisterInstallMode::Upgrade,
        canister_id: canister_id.get(),
        wasm_module: wasm,
        arg,
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: env.canister_version(),
    };

    env.call_canister(
        ic_management_canister_types::IC_00,
        "install_code",
        Encode!(&install_code_args).expect("Unable to encode install_code args."),
    )
    .await
    .map(|_reply| ())
    .map_err(|err| {
        let err = GovernanceError::new_with_message(
            ErrorType::External,
            format!("Failed to install code into the target canister: {:?}", err),
        );
        log!(ERROR, "{}{:?}", log_prefix(), err);
        err
    })
}

/// Starts a canister with a given id (target canister must be controlled by governance).
async fn start_canister(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<(), GovernanceError> {
    env.call_canister(
        CanisterId::ic_00(),
        "start_canister",
        Encode!(&CanisterIdRecord::from(canister_id))
            .expect("Unable to encode start_canister args."),
    )
    .await
    .map(|_reply| ())
    .map_err(|err| {
        let err = GovernanceError::new_with_message(
            ErrorType::External,
            format!("Failed to restart the target canister: {:?}", err),
        );
        log!(ERROR, "{}{:?}", log_prefix(), err);
        err
    })
}

/// Stops a canister with a given id (target canister must be controlled by governance).
async fn stop_canister(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<(), GovernanceError> {
    let serialized_canister_id = candid::Encode!(&CanisterIdRecord::from(canister_id))
        .expect("Unable to encode stop_canister args.");

    let result = env
        .call_canister(
            CanisterId::ic_00(),
            "stop_canister",
            serialized_canister_id.clone(),
        )
        .await
        .map_err(|err| {
            let err = GovernanceError::new_with_message(
                ErrorType::External,
                format!("Unable to stop the target canister: {:?}", err),
            );
            log!(ERROR, "{}{:?}", log_prefix(), err);
            err
        });

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            log!(
                ERROR,
                "{}Attempting to restart canister {}",
                log_prefix(),
                canister_id
            );
            Err(match start_canister(env, canister_id).await {
                Ok(_) => err,
                Err(extra_err) => GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "{}Error restarting canister \
                         {} after failed start: {}.  Error stopping: {}",
                        log_prefix(),
                        canister_id,
                        extra_err,
                        err
                    ),
                ),
            })
        }
    }?;

    // Wait until canister is in the stopped state.
    loop {
        let status = canister_status(env, canister_id).await?;
        if status.status == CanisterStatusType::Stopped {
            return Ok(());
        }

        log!(
            INFO,
            "{}Still waiting for canister {} to stop. status: {:?}",
            log_prefix(),
            canister_id,
            status
        );
    }
}

async fn canister_status(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<CanisterStatusResultFromManagementCanister, GovernanceError> {
    let serialized_canister_id = candid::Encode!(&CanisterIdRecord::from(canister_id))
        .expect("Unable to encode stop_canister args.");

    let result = env
        .call_canister(
            CanisterId::ic_00(),
            "canister_status",
            serialized_canister_id.clone(),
        )
        .await;
    match result {
        Ok(ok) => {
            let decoded = Decode!(&ok, CanisterStatusResultFromManagementCanister)
                .expect("Unable to decode canister_status response.");
            Ok(decoded)
        }

        // This is probably a permanent error, so we give up right away.
        Err(err) => {
            let err = GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "An error occurred while waiting for the target canister to stop: {:?}",
                    err
                ),
            );
            log!(ERROR, "{}{:?}", log_prefix(), err);
            Err(err)
        }
    }
}

/// Validates and renders a generic nervous system function (i.e., a non-native SNS proposal).
pub async fn perform_execute_generic_nervous_system_function_validate_and_render_call(
    env: &dyn Environment,
    function: NervousSystemFunction,
    call: ExecuteGenericNervousSystemFunction,
) -> Result<String, String> {
    // Get the canister id and the method against which we validate and render the proposal.
    let valid_function = ValidGenericNervousSystemFunction::try_from(&function)?;

    let result = env
        .call_canister(
            valid_function.validator_canister_id,
            &valid_function.validator_method,
            call.payload,
        )
        .await;

    // Convert result.
    match result {
        Err(err) => Err(format!(
            "Canister method call to validate and render proposal payload of NervousSystemFunction: {:?} failed: {:?}",
            valid_function.id, err
        )),
        Ok(reply) => {
            let result = Decode!(&reply, Result<String,String>);
            match result {
                Err(e) => Err(format!(
                    "Error decoding reply from proposal payload validate and render call: {}",
                    e
                )),
                Ok(value) => match value {
                    Err(e) => Err(format!("Invalid proposal: {}", e)),
                    Ok(rendering) => Ok(rendering),
                },
            }
        }
    }
}

/// Executes a generic nervous system function (i.e., a non-native SNS proposal).
pub async fn perform_execute_generic_nervous_system_function_call(
    env: &dyn Environment,
    function: NervousSystemFunction,
    call: ExecuteGenericNervousSystemFunction,
) -> Result<(), GovernanceError> {
    // Get the canister id and the method against which we execute the proposal.
    let valid_function = ValidGenericNervousSystemFunction::try_from(&function)
        .map_err(|e| GovernanceError::new_with_message(ErrorType::InvalidProposal, e))?;

    let result = env
        .call_canister(
            valid_function.target_canister_id,
            &valid_function.target_method,
            call.payload,
        )
        .await;

    // Convert result.
    match result {
        Err(err) => Err(GovernanceError::new_with_message(
            ErrorType::External,
            format!("Canister method call to execute proposal failed: {:?}", err),
        )),

        Ok(_reply) => {
            // TODO: Do something with reply. E.g. store it in the proposal,
            // and/or deserialize it so that we can detect whether there was an
            // application-level error, as opposed to a communication
            // error. Detecting application error could be done as follows:
            //
            //   candid::!Decode(&reply, Result<String, String>)
            //
            // This could then be converted into a Result<(), GovernanceError>.
            // For now, any reply is considered a success.
            Ok(())
        }
    }
}

pub async fn update_root_canister_settings(
    governance: &Governance,
    settings: CanisterSettings,
) -> Result<(), GovernanceError> {
    let update_settings_args = UpdateSettings {
        canister_id: PrincipalId::from(governance.proto.root_canister_id_or_panic()),
        settings,
        // allowed to be None
        sender_canister_version: None,
    };
    governance
        .env
        .call_canister(
            ic_management_canister_types::IC_00,
            "update_settings",
            Encode!(&update_settings_args).expect("Unable to encode update_settings args."),
        )
        .await
        .map(|_reply| ())
        .map_err(|err| {
            let err = GovernanceError::new_with_message(
                ErrorType::External,
                format!("Failed to update settings of the root canister: {:?}", err),
            );
            log!(ERROR, "{}{:?}", log_prefix(), err);
            err
        })
}
