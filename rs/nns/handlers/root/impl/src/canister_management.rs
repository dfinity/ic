#![allow(deprecated)]
use crate::PROXIED_CANISTER_CALLS_TRACKER;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::{
    api::call::{RejectionCode, call_with_payment},
    call, caller, print,
};
use ic_management_canister_types_private::{
    CanisterInstallMode::Install, CanisterSettingsArgsBuilder, CreateCanisterArgs, InstallCodeArgs,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    management_canister_client::ManagementCanisterClient,
    update_settings::{CanisterSettings, UpdateSettings},
};
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use ic_nervous_system_root::change_canister::{
    AddCanisterRequest, CanisterAction, StopOrStartCanisterRequest, start_canister, stop_canister,
};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_common::{
    registry::{get_value, mutate_registry},
    types::CallCanisterRequest,
};
use ic_nns_handler_root_interface::{
    ChangeCanisterControllersRequest, ChangeCanisterControllersResponse,
    UpdateCanisterSettingsError, UpdateCanisterSettingsRequest, UpdateCanisterSettingsResponse,
};
use ic_protobuf::{
    registry::nns::v1::{NnsCanisterRecord, NnsCanisterRecords},
    types::v1 as pb,
};
use ic_registry_keys::make_nns_canister_records_key;
use ic_registry_transport::pb::v1::{Precondition, RegistryMutation, registry_mutation::Type};
use prost::Message;

pub async fn do_add_nns_canister(request: AddCanisterRequest) {
    let key = make_nns_canister_records_key().into_bytes();
    let name = request.name.clone();

    // We first need to claim the name of this new canister. Indeed, even though we
    // don't yet know its ID, if we create it first and then find out the name
    // is already taken, that would be bad. So, first, we create a record.

    // First, just to make sure that the key exists, because the libraries around
    // the registry don't have good ways to deal with defaults. So we try to
    // insert, but do nothing with the results.
    let _ = mutate_registry(
        vec![RegistryMutation {
            mutation_type: Type::Insert as i32,
            key: key.clone(),
            value: Vec::<u8>::new(),
        }],
        Vec::<Precondition>::new(),
    )
    .await;

    // Now the key should exist. Let's get its value.
    let (mut nns_canister_records, nns_canister_records_version): (NnsCanisterRecords, u64) =
        get_value(&key, None).await.unwrap();

    // Make sure the name is free
    let old_record = nns_canister_records
        .canisters
        .insert(name.clone(), NnsCanisterRecord::default());
    assert!(
        old_record.is_none(),
        "Trying to add an NNS canister called '{}', but we already have \
             a record for that name: '{:?}'",
        request.name,
        old_record
    );

    // Commit, so as to reserve the name
    let name_reserved_version = mutate_registry(
        vec![RegistryMutation {
            mutation_type: Type::Update as i32,
            key: key.clone(),
            value: nns_canister_records.encode_to_vec(),
        }],
        vec![Precondition {
            key: key.clone(),
            expected_version: nns_canister_records_version,
        }],
    )
    .await
    .unwrap();

    let id_or_error = try_to_create_and_install_canister(request).await;
    let id = id_or_error.unwrap();
    // TODO(NNS-81): If it did not work, remove the name from the registry

    nns_canister_records.canisters.insert(
        name.clone(),
        NnsCanisterRecord {
            id: Some(pb::CanisterId::from(id)),
        },
    );

    mutate_registry(
        vec![RegistryMutation {
            mutation_type: Type::Update as i32,
            key: key.clone(),
            value: nns_canister_records.encode_to_vec(),
        }],
        vec![Precondition {
            key: key.clone(),
            expected_version: name_reserved_version,
        }],
    )
    .await
    .unwrap();
    // TODO(NNS-81): Handle failure in the case we couldn't write the canister id
    // into the registry
}

/// Tries to create and install the canister specified in the request. Does not
/// care about the name service. This function is supposed never to panic, so
/// that cleanup can be done if the install does not go through.
async fn try_to_create_and_install_canister(
    request: AddCanisterRequest,
) -> Result<CanisterId, String> {
    let compute_allocation = request
        .compute_allocation
        .map(|ca| ca.0.try_into())
        .transpose()
        .map_err(|_| "Provided compute allocation is too large")?;
    let memory_allocation = request
        .memory_allocation
        .map(|ma| ma.0.try_into())
        .transpose()
        .map_err(|_| "Provided memory allocation is too large")?;
    let settings = CanisterSettingsArgsBuilder::new()
        .with_maybe_compute_allocation(compute_allocation)
        .with_maybe_memory_allocation(memory_allocation)
        .build();
    let create_args = CreateCanisterArgs {
        settings: Some(settings),
        sender_canister_version: Some(ic_cdk::api::canister_version()),
    };
    let (id,): (CanisterIdRecord,) = call_with_payment(
        CanisterId::ic_00().get().0,
        "create_canister",
        (create_args,),
        request.initial_cycles,
    )
    .await
    .map_err(|(code, msg)| format!("error code {}: {}", code as i32, msg))?;

    let install_args = InstallCodeArgs {
        mode: Install,
        canister_id: id.get_canister_id().get(),
        wasm_module: request.wasm_module,
        arg: request.arg,
        sender_canister_version: Some(ic_cdk::api::canister_version()),
    };
    let install_res: Result<(), (RejectionCode, String)> =
        call(CanisterId::ic_00().get().0, "install_code", (install_args,)).await;

    install_res.map_err(|(code, msg)| format!("error code {}: {}", code as i32, msg))?;

    Ok(id.get_canister_id())
}

// Stops or starts any NNS canister.
pub async fn stop_or_start_nns_canister(
    request: StopOrStartCanisterRequest,
) -> Result<(), (i32, String)> {
    match request.action {
        CanisterAction::Start => start_canister::<CdkRuntime>(request.canister_id).await,
        CanisterAction::Stop => stop_canister::<CdkRuntime>(request.canister_id).await,
    }
}

pub async fn call_canister(proposal: CallCanisterRequest) {
    print(format!(
        "Calling {}::{}...",
        proposal.canister_id, proposal.method_name,
    ));

    let CallCanisterRequest {
        canister_id,
        method_name,
        payload,
    } = &proposal;

    let _tracker = ProxiedCanisterCallsTracker::start_tracking(
        &PROXIED_CANISTER_CALLS_TRACKER,
        PrincipalId::from(caller()),
        *canister_id,
        method_name,
        payload,
    );

    let res = CdkRuntime::call_bytes_with_cleanup(*canister_id, method_name, payload)
        .await
        .map_err(|(code, msg)| format!("Error: {code}:{msg}"));

    print(format!(
        "Call {}::{} returned {:?}",
        proposal.canister_id, proposal.method_name, res,
    ));

    res.unwrap();
}

pub async fn change_canister_controllers(
    change_canister_controllers_request: ChangeCanisterControllersRequest,
    management_canister_client: &mut impl ManagementCanisterClient,
) -> ChangeCanisterControllersResponse {
    let update_settings_args = UpdateSettings {
        canister_id: change_canister_controllers_request.target_canister_id,
        settings: CanisterSettings {
            controllers: Some(change_canister_controllers_request.new_controllers),
            ..Default::default()
        },
        sender_canister_version: management_canister_client.canister_version(),
    };

    match management_canister_client
        .update_settings(update_settings_args)
        .await
    {
        Ok(()) => ChangeCanisterControllersResponse::ok(),
        Err((code, description)) => {
            ChangeCanisterControllersResponse::error(Some(code), description)
        }
    }
}

pub async fn update_canister_settings(
    update_canister_settings_request: UpdateCanisterSettingsRequest,
    management_canister_client: &mut impl ManagementCanisterClient,
) -> UpdateCanisterSettingsResponse {
    let update_settings_args = UpdateSettings {
        canister_id: update_canister_settings_request.canister_id,
        settings: update_canister_settings_request.settings,
        sender_canister_version: management_canister_client.canister_version(),
    };

    match management_canister_client
        .update_settings(update_settings_args)
        .await
    {
        Ok(()) => UpdateCanisterSettingsResponse::Ok(()),
        Err((code, description)) => {
            UpdateCanisterSettingsResponse::Err(UpdateCanisterSettingsError {
                code: Some(code),
                description,
            })
        }
    }
}
