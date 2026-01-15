use candid::{CandidType, Decode, Encode, Principal};
use canister_test::Project;
use canister_test::Wasm;
use ic_crypto_sha2::Sha256;
use ic_management_canister_types::CanisterSettings;
use ic_nns_constants::{REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::common::{
    NnsInitPayloadsBuilder, build_mainnet_registry_wasm, build_registry_wasm,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use salt_sharing_api::InitArg;
use serde::de::DeserializeOwned;

/// Builds the WASM for the salt-sharing canister.
pub fn build_salt_sharing_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("salt-sharing-canister", &[])
}

pub async fn install_registry_canister(
    pocket_ic: &PocketIc,
    with_mainnet_nns_canister_versions: bool,
    custom_initial_registry_mutations: Option<Vec<RegistryAtomicMutateRequest>>,
) {
    let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();

    if let Some(custom_initial_registry_mutations) = custom_initial_registry_mutations {
        nns_init_payload_builder.with_initial_mutations(custom_initial_registry_mutations);
    } else {
        nns_init_payload_builder.with_initial_invariant_compliant_mutations();
    }

    let nns_init_payload = nns_init_payload_builder.build();

    let registry_wasm = if with_mainnet_nns_canister_versions {
        build_mainnet_registry_wasm()
    } else {
        build_registry_wasm()
    };

    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "registry canister",
        REGISTRY_CANISTER_ID,
        Encode!(&nns_init_payload.registry).unwrap(),
        registry_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
}

pub async fn install_canister(
    pocket_ic: &PocketIc,
    canister_name: &str,
    subnet_id: Principal,
    arg: Vec<u8>,
    wasm: Wasm,
) -> Principal {
    let memory_allocation = None;
    let controllers = None;
    let sender = None;

    let settings = Some(CanisterSettings {
        memory_allocation,
        controllers,
        ..Default::default()
    });

    let canister_id = pocket_ic
        .create_canister_on_subnet(sender, settings, subnet_id)
        .await;

    pocket_ic
        .install_canister(canister_id, wasm.bytes(), arg, sender)
        .await;

    println!(
        "Installed {canister_name} with canister_id = {canister_id} on subnet_id = {subnet_id}",
    );

    canister_id
}

pub async fn get_installed_wasm_hash(pocket_ic: &PocketIc, canister_id: Principal) -> [u8; 32] {
    let module_hash = pocket_ic
        .canister_status(canister_id, None)
        .await
        .unwrap()
        .module_hash
        .unwrap();

    module_hash.try_into().unwrap_or_else(|v: Vec<_>| {
        panic!("Expected a Vec of length 32 but it has {} bytes.", v.len())
    })
}

pub async fn canister_call<R: DeserializeOwned + CandidType>(
    pocket_ic: &PocketIc,
    method: &str,
    method_type: &str,
    canister_id: Principal,
    sender: Principal,
    payload: Vec<u8>,
) -> Result<R, String> {
    let result = match method_type {
        "query" => pocket_ic
            .query_call(canister_id, sender, method, payload)
            .await
            .map_err(|err| err.to_string())?,
        "update" => pocket_ic
            .update_call(canister_id, sender, method, payload)
            .await
            .map_err(|err| err.to_string())?,
        _ => panic!("{method_type} is not allowed"),
    };

    let decoded: R = Decode!(&result, R).unwrap();

    Ok(decoded)
}

pub async fn setup_subnets_and_registry_canister() -> PocketIc {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .build_async()
        .await;

    // Install registry canister. It is the only canister that salt-sharing canister interacts with.
    let with_mainnet_nns_canister_versions = false;
    install_registry_canister(&pocket_ic, with_mainnet_nns_canister_versions, None).await;

    pocket_ic
}

pub async fn install_salt_sharing_canister_on_ii_subnet(
    pocket_ic: &PocketIc,
    init_arg: InitArg,
) -> (Principal, Wasm) {
    let wasm = build_salt_sharing_wasm();
    let wasm_hash = Sha256::hash(&wasm.clone().bytes());

    let ii_subnet_id = {
        let topology = pocket_ic.topology().await;
        topology.get_ii().unwrap()
    };

    let canister_id = install_canister(
        pocket_ic,
        "salt-sharing canister",
        ii_subnet_id,
        Encode!(&init_arg).unwrap(),
        wasm.clone(),
    )
    .await;

    assert_eq!(
        get_installed_wasm_hash(pocket_ic, canister_id).await,
        wasm_hash,
    );

    (canister_id, wasm)
}
