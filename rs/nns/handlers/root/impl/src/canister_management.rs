use crate::PROXIED_CANISTER_CALLS_TRACKER;
use dfn_core::api::{call, call_bytes, call_with_funds, caller, print, CanisterId, Funds};
use ic_management_canister_types::{CanisterInstallMode::Install, InstallCodeArgs};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    management_canister_client::ManagementCanisterClient,
    update_settings::{CanisterSettings, UpdateSettings},
};
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use ic_nervous_system_root::change_canister::{
    start_canister, stop_canister, AddCanisterRequest, CanisterAction, StopOrStartCanisterRequest,
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_common::{
    registry::{get_value, mutate_registry},
    types::CallCanisterProposal,
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
use ic_registry_transport::pb::v1::{registry_mutation::Type, Precondition, RegistryMutation};
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
    let (id,): (CanisterIdRecord,) = call_with_funds(
        CanisterId::ic_00(),
        "create_canister",
        dfn_candid::candid_multi_arity,
        (),
        Funds::new(request.initial_cycles),
    )
    .await
    .map_err(|(code, msg)| {
        format!(
            "{}{}",
            code.map(|c| format!("error code {}: ", c))
                .unwrap_or_default(),
            msg
        )
    })?;
    let install_args = InstallCodeArgs {
        mode: Install,
        canister_id: id.get_canister_id().get(),
        wasm_module: request.wasm_module,
        arg: request.arg,
        compute_allocation: request.compute_allocation,
        memory_allocation: request.memory_allocation,
        sender_canister_version: Some(dfn_core::api::canister_version()),
    };
    let install_res: Result<(), (Option<i32>, String)> = call(
        CanisterId::ic_00(),
        "install_code",
        dfn_candid::candid_multi_arity,
        (install_args,),
    )
    .await;
    install_res.map_err(|(code, msg)| {
        format!(
            "{}{}",
            code.map(|c| format!("error code {}: ", c))
                .unwrap_or_default(),
            msg
        )
    })?;
    Ok(id.get_canister_id())
}

// Stops or starts any NNS canister.
pub async fn stop_or_start_nns_canister(
    request: StopOrStartCanisterRequest,
) -> Result<(), (i32, String)> {
    match request.action {
        CanisterAction::Start => start_canister::<DfnRuntime>(request.canister_id).await,
        CanisterAction::Stop => stop_canister::<DfnRuntime>(request.canister_id).await,
    }
}

pub async fn call_canister(proposal: CallCanisterProposal) {
    print(format!(
        "Calling {}::{}...",
        proposal.canister_id, proposal.method_name,
    ));

    let CallCanisterProposal {
        canister_id,
        method_name,
        payload,
    } = &proposal;

    let _tracker = ProxiedCanisterCallsTracker::start_tracking(
        &PROXIED_CANISTER_CALLS_TRACKER,
        caller(),
        *canister_id,
        method_name,
        payload,
    );

    let res = call_bytes(*canister_id, method_name, payload, Funds::zero())
        .await
        .map_err(|(code, msg)| format!("Error: {}:{}", code.unwrap_or_default(), msg));

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
