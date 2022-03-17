use dfn_core::api::{call, call_with_funds, CanisterId, Funds};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::CanisterInstallMode::Install;

use ic_ic00_types::InstallCodeArgs;
use ic_nervous_system_root::{
    start_canister, stop_canister, update_authz, AddCanisterProposal, CanisterAction,
    CanisterIdRecord, StopOrStartCanisterProposal,
};
use ic_nns_common::registry::{encode_or_panic, get_value, mutate_registry};
use ic_protobuf::registry::nns::v1::{NnsCanisterRecord, NnsCanisterRecords};
use ic_protobuf::types::v1 as pb;
use ic_registry_keys::make_nns_canister_records_key;
use ic_registry_transport::pb::v1::{registry_mutation::Type, Precondition, RegistryMutation};

pub async fn do_add_nns_canister(proposal: AddCanisterProposal) {
    let key = make_nns_canister_records_key().into_bytes();
    let authz_changes = proposal.authz_changes.clone();
    let name = proposal.name.clone();

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
        proposal.name,
        old_record
    );

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

    let id_or_error = try_to_create_and_install_canister(proposal).await;
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

/// Tries to create and install the canister specified in the proposal. Does not
/// care about the name service. This function is supposed never to panic, so
/// that cleanup can be done if the install does not go through.
async fn try_to_create_and_install_canister(
    proposal: AddCanisterProposal,
) -> Result<CanisterId, String> {
    let (id,): (CanisterIdRecord,) = call_with_funds(
        CanisterId::ic_00(),
        "create_canister",
        dfn_candid::candid_multi_arity,
        (),
        Funds::new(proposal.initial_cycles),
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
        wasm_module: proposal.wasm_module,
        arg: proposal.arg,
        compute_allocation: proposal.compute_allocation,
        memory_allocation: proposal.memory_allocation,
        query_allocation: proposal.query_allocation,
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
pub async fn stop_or_start_nns_canister(proposal: StopOrStartCanisterProposal) {
    match proposal.action {
        CanisterAction::Start => start_canister(proposal.canister_id).await,
        CanisterAction::Stop => stop_canister(proposal.canister_id).await,
    }
}
