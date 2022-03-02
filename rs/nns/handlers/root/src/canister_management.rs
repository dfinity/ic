use dfn_core::api::{call, call_with_funds, CanisterId, Funds};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{CanisterInstallMode::Install, PrincipalId};

use futures::future::join_all;
use ic_ic00_types::{InstallCodeArgs, IC_00};
use ic_nervous_system_root::{
    AddNnsCanisterProposalPayload, CanisterAction, CanisterIdRecord, CanisterStatusResult,
    CanisterStatusType, ChangeNnsCanisterProposalPayload, StopOrStartNnsCanisterProposalPayload,
    LOG_PREFIX,
};
use ic_nns_common::{
    registry::{encode_or_panic, get_value, mutate_registry},
    types::{AuthzChangeOp, MethodAuthzChange},
};
use ic_protobuf::registry::nns::v1::{NnsCanisterRecord, NnsCanisterRecords};
use ic_protobuf::types::v1 as pb;
use ic_registry_keys::make_nns_canister_records_key;
use ic_registry_transport::pb::v1::{registry_mutation::Type, Precondition, RegistryMutation};
use std::collections::HashMap;
use std::convert::TryFrom;

pub async fn canister_status(canister_id_record: CanisterIdRecord) -> CanisterStatusResult {
    call(
        IC_00,
        "canister_status",
        dfn_candid::candid,
        (canister_id_record,),
    )
    .await
    .unwrap()
}

pub async fn update_authz(
    changed_canister: CanisterId,
    methods_authz_changes: Vec<MethodAuthzChange>,
) {
    // Group changes by canister id and change principal_or_self if it was None
    let mut grouped_changes: HashMap<CanisterId, Vec<MethodAuthzChange>> = HashMap::new();
    for method_authz_change in methods_authz_changes {
        let principal = method_authz_change.principal;
        let method_name = method_authz_change.method_name;
        let canister = method_authz_change.canister;
        match method_authz_change.operation {
            AuthzChangeOp::Authorize { add_self } => {
                let change_vec = grouped_changes.entry(canister).or_insert_with(Vec::new);
                let principal_to_add = if add_self {
                    PrincipalId::from(changed_canister)
                } else {
                    principal.expect("Expected a principal to be added")
                };

                change_vec.push(MethodAuthzChange {
                    canister,
                    method_name,
                    principal: Some(principal_to_add),
                    operation: AuthzChangeOp::Authorize { add_self: false },
                });
            }
            AuthzChangeOp::Deauthorize => {
                let change_vec = grouped_changes.entry(canister).or_insert_with(Vec::new);
                change_vec.push(MethodAuthzChange {
                    canister,
                    method_name,
                    principal,
                    operation: AuthzChangeOp::Deauthorize,
                });
            }
        };
    }

    join_all(
        grouped_changes
            .into_iter()
            .map(|(canister, changes)| async move {
                match call(
                    canister,
                    "update_authz",
                    dfn_candid::candid,
                    (changes.clone(),),
                )
                .await
                {
                    Ok(()) => {
                        println!(
                            "{}Successfully updated authz for canister: {}. \
                                Changes: {:?}",
                            LOG_PREFIX, canister, changes
                        );
                    }
                    Err((error_code, error)) => println!(
                        "{}Error updating authz. Error code: {:?}. Error: {}",
                        LOG_PREFIX, error_code, error
                    ),
                }
            }),
    )
    .await;
}

pub async fn do_change_nns_canister(payload: ChangeNnsCanisterProposalPayload) {
    let canister_id = payload.canister_id;
    let authz_changes = payload.authz_changes.clone();
    let stop_before_installing = payload.stop_before_installing;

    if stop_before_installing {
        stop_canister(canister_id).await;
    }

    // Ship code to the canister.
    //
    // Note that there's no guarantee that the canister to install/reinstall/upgrade
    // is actually stopped here, even if stop_before_installing is true. This is
    // because there could be a concurrent proposal to restart it. This could be
    // guaranteed with a "stopped precondition" in the management canister, or
    // with some locking here.
    let res = install_code(payload).await;
    // For once, we don't want to unwrap the result here. The reason is that, if the
    // installation failed (e.g., the wasm was rejected because it's invalid),
    // then we want to restart the canister. So we just keep the res to be
    // unwrapped later.

    // Restart the canister, if needed
    if stop_before_installing {
        start_canister(canister_id).await;
    }

    // Update authz of other canisters, if required.
    update_authz(canister_id, authz_changes).await;

    // Check the result of the install_code
    res.unwrap();
}

/// Calls the "install_code" method of the management canister.
async fn install_code(
    payload: ChangeNnsCanisterProposalPayload,
) -> ic_cdk::api::call::CallResult<()> {
    let install_code_args = InstallCodeArgs {
        mode: payload.mode,
        canister_id: payload.canister_id.get(),
        wasm_module: payload.wasm_module,
        arg: payload.arg,
        compute_allocation: payload.compute_allocation,
        memory_allocation: payload.memory_allocation,
        query_allocation: payload.query_allocation,
    };
    // Warning: despite dfn_core::call returning a Result, it actually traps when
    // the callee traps! Use the public cdk instead, which does not have this
    // issue.
    ic_cdk::api::call::call(
        ic_cdk::export::Principal::try_from(IC_00.get().as_slice()).unwrap(),
        "install_code",
        (&install_code_args,),
    )
    .await
}

async fn start_canister(canister_id: CanisterId) {
    // start_canister returns the candid empty type, which cannot be parsed using
    // dfn_candid::candid
    let res: Result<(), (Option<i32>, String)> = call(
        CanisterId::ic_00(),
        "start_canister",
        dfn_candid::candid_multi_arity,
        (CanisterIdRecord::from(canister_id),),
    )
    .await;

    // Let's make sure this worked. We can abort if not.
    res.unwrap();
    println!("{}Restart call successful.", LOG_PREFIX);
}

/// Stops the given canister, and polls until the `Stopped` state is reached.
///
/// Warning: there's no guarantee that this ever finishes!
/// TODO(NNS-65)
async fn stop_canister(canister_id: CanisterId) {
    // stop_canister returns the candid empty type, which cannot be parsed using
    // dfn_candid::candid
    let res: Result<(), (Option<i32>, String)> = call(
        CanisterId::ic_00(),
        "stop_canister",
        dfn_candid::candid_multi_arity,
        (CanisterIdRecord::from(canister_id),),
    )
    .await;

    // Let's make sure this worked. We can abort if not.
    res.unwrap();

    // Now wait
    loop {
        let status: CanisterStatusResult = call(
            CanisterId::ic_00(),
            "canister_status",
            dfn_candid::candid,
            (CanisterIdRecord::from(canister_id),),
        )
        .await
        .unwrap();

        if status.status == CanisterStatusType::Stopped {
            return;
        }
        println!(
            "{}Waiting for {:?} to stop. Current status: {}",
            LOG_PREFIX, canister_id, status.status
        );
    }
}

pub async fn do_add_nns_canister(payload: AddNnsCanisterProposalPayload) {
    let key = make_nns_canister_records_key().into_bytes();
    let authz_changes = payload.authz_changes.clone();
    let name = payload.name.clone();

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
    assert!(old_record.is_none(), "Trying to add an NNS canister called '{}', but we already have a record for that name: '{:?}'", payload.name, old_record);

    // Commit, so as to reserve the name
    let name_reserved_version = mutate_registry(
        vec![RegistryMutation {
            mutation_type: Type::Update as i32,
            key: key.clone(),
            value: encode_or_panic(&nns_canister_records),
        }],
        vec![Precondition {
            key: key.clone(),
            expected_version: nns_canister_records_version,
        }],
    )
    .await
    .unwrap();

    let id_or_error = try_to_create_and_install_canister(payload).await;
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
            value: encode_or_panic(&nns_canister_records),
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

    // Update authz of other canisters, if required.
    update_authz(id, authz_changes).await;
}

/// Tries to create and install the canister specified in the payload. Does not
/// care about the name service. This function is supposed never to panic, so
/// that cleanup can be done if the install does not go through.
async fn try_to_create_and_install_canister(
    payload: AddNnsCanisterProposalPayload,
) -> Result<CanisterId, String> {
    let (id,): (CanisterIdRecord,) = call_with_funds(
        CanisterId::ic_00(),
        "create_canister",
        dfn_candid::candid_multi_arity,
        (),
        Funds::new(payload.initial_cycles),
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
        wasm_module: payload.wasm_module,
        arg: payload.arg,
        compute_allocation: payload.compute_allocation,
        memory_allocation: payload.memory_allocation,
        query_allocation: payload.query_allocation,
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
pub async fn stop_or_start_nns_canister(payload: StopOrStartNnsCanisterProposalPayload) {
    match payload.action {
        CanisterAction::Start => start_canister(payload.canister_id).await,
        CanisterAction::Stop => stop_canister(payload.canister_id).await,
    }
}
