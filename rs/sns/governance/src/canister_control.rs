use std::convert::TryFrom;

use candid::{Decode, Encode};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_nervous_system_root::{CanisterIdRecord, CanisterStatusResult, CanisterStatusType};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use crate::{
    governance::log_prefix,
    pb::v1::{
        governance_error::ErrorType, ExecuteNervousSystemFunction, GovernanceError,
        NervousSystemFunction,
    },
    proposal::ValidNervousSystemFunction,
    types::Environment,
};

pub fn get_canister_id(canister_id: &Option<PrincipalId>) -> Result<CanisterId, GovernanceError> {
    let canister_id = canister_id.ok_or_else(|| {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "No canister ID was specified.",
        )
    })?;

    CanisterId::new(canister_id).map_err(|err| {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("Specified canister ID was invalid: {:?}", err,),
        )
    })
}

pub async fn upgrade_canister_directly(
    env: &dyn Environment,
    canister_id: CanisterId,
    wasm: Vec<u8>,
) -> Result<(), GovernanceError> {
    println!("{}Begin: Stop canister {}.", log_prefix(), canister_id);
    stop_canister(env, canister_id).await?;
    println!("{}End: Stop canister {}.", log_prefix(), canister_id);

    println!(
        "{}Begin: Install code into canister {}",
        log_prefix(),
        canister_id
    );
    let install_result = install_code(env, canister_id, wasm)
        // No question mark operator here, because we always want to re-start
        // the canister after attempting install_code, even if install_code
        // fails.
        .await;
    println!(
        "{}End: Install code into canister {}",
        log_prefix(),
        canister_id
    );

    println!("{}Begin: Re-start canister {}", log_prefix(), canister_id);
    start_canister(env, canister_id).await?;
    println!("{}End: Re-start canister {}", log_prefix(), canister_id);

    install_result
}

pub async fn install_code(
    env: &dyn Environment,
    canister_id: CanisterId,
    wasm: Vec<u8>,
) -> Result<(), GovernanceError> {
    const MEMORY_ALLOCATION_BYTES: u64 = 1_u64 << 30;

    let install_code_args = ic_ic00_types::InstallCodeArgs {
        mode: ic_ic00_types::CanisterInstallMode::Upgrade,
        canister_id: canister_id.get(),
        wasm_module: wasm,
        arg: vec![],
        compute_allocation: None,
        memory_allocation: Some(candid::Nat::from(MEMORY_ALLOCATION_BYTES)),
        query_allocation: None,
    };

    env.call_canister(
        ic_ic00_types::IC_00,
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
        println!("{}{:?}", log_prefix(), err);
        err
    })
}

pub async fn start_canister(
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
        println!("{}{:?}", log_prefix(), err);
        err
    })
}

pub async fn stop_canister(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<(), GovernanceError> {
    let serialize_canister_id = candid::Encode!(&CanisterIdRecord::from(canister_id))
        .expect("Unable to encode stop_canister args.");

    env.call_canister(
        CanisterId::ic_00(),
        "stop_canister",
        serialize_canister_id.clone(),
    )
    .await
    .map_err(|err| {
        let err = GovernanceError::new_with_message(
            ErrorType::External,
            format!("Unable to stop the target canister: {:?}", err),
        );
        println!("{}{:?}", log_prefix(), err);
        err
    })?;

    // Wait until canister is in the stopped state.
    loop {
        let result = env
            .call_canister(
                CanisterId::ic_00(),
                "canister_status",
                serialize_canister_id.clone(),
            )
            .await;
        let status = match result {
            Ok(ok) => Decode!(&ok, CanisterStatusResult)
                .expect("Unable to decode canister_status response."),

            // This is probably a permanent error, so we give up right away.
            Err(err) => {
                let err = GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "An error occurred while waiting for the target canister to stop: {:?}",
                        err
                    ),
                );
                println!("{}{:?}", log_prefix(), err);
                return Err(err);
            }
        };

        if status.status == CanisterStatusType::Stopped {
            return Ok(());
        }

        println!(
            "{}Still waiting for canister {} to stop. status: {:?}",
            log_prefix(),
            canister_id,
            status
        );
    }
}

pub async fn perform_execute_nervous_system_function_validate_and_render_call(
    env: &dyn Environment,
    function: NervousSystemFunction,
    call: ExecuteNervousSystemFunction,
) -> Result<String, String> {
    // Get the canister id and the method against which we validate and render the proposal.
    let valid_function = ValidNervousSystemFunction::try_from(&function)?;

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

pub async fn perform_execute_nervous_system_function_call(
    env: &dyn Environment,
    function: NervousSystemFunction,
    call: ExecuteNervousSystemFunction,
) -> Result<(), GovernanceError> {
    // Get the canister id and the method against which we execute the proposal.
    let valid_function = ValidNervousSystemFunction::try_from(&function)
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
