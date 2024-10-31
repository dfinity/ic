use pocket_ic::PocketIcBuilder;
use rate_limits_api::{
    AddConfigResponse, GetConfigResponse,
    InputConfig, InputRule, Version,
};
use canister_test::{Project, Wasm};
use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use rate_limits_api::InitArg;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::CanisterSettings;
use ic_crypto_sha2::Sha256;

// TODO: Should be factored out
use ic_nns_constants::{
    self, 
    REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_test_utils::common::{
    modify_wasm_bytes,
    build_mainnet_registry_wasm,
    build_registry_wasm, NnsInitPayloadsBuilder,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use pocket_ic::WasmResult;

pub const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

/// Builds the WASM for the Rate Limits canister.
pub fn build_rate_limits_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("rate-limits-canister", &[])
}

pub async fn install_nns_canisters(
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
        "Registry",
        REGISTRY_CANISTER_ID,
        Encode!(&nns_init_payload.registry).unwrap(),
        registry_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
}

pub async fn install_canister(
    pocket_ic: &PocketIc,
    name: &str,
    subnet_id: Principal,
    arg: Vec<u8>,
    wasm: Wasm,
) -> PrincipalId {
    let memory_allocation = None;
    let controllers = None;
    let settings = Some(CanisterSettings {
        memory_allocation,
        controllers,
        ..Default::default()
    });
    let canister_id = pocket_ic
        .create_canister_on_subnet(None, settings, subnet_id)
        .await;
    pocket_ic
        .install_canister(canister_id, wasm.bytes(), arg, None)
        .await;
    pocket_ic
        .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    println!(
        "Installed the {} canister ({}) onto {:?}",
        name, canister_id, subnet_id
    );
    PrincipalId::from(canister_id)
}

pub async fn get_installed_wasm_hash(
    pocket_ic: &PocketIc,
    canister_id: PrincipalId,
) -> [u8; 32] {
    let module_hash = pocket_ic.canister_status(
        canister_id.into(),
        None,
    )
    .await
    .unwrap()
    .module_hash
    .unwrap();

    module_hash
        .try_into()
        .unwrap_or_else(|v: Vec<_>| {
            panic!("Expected a Vec of length 32 but it has {} bytes.", v.len())
        })
}

pub async fn add_config(
    pocket_ic: &PocketIc,
    rate_limit_canister: PrincipalId,
    sender: PrincipalId,
    schema_version: u64,
    rules: Vec<InputRule>,
) -> Result<AddConfigResponse, String> {
    let result = pocket_ic
        .update_call(
            rate_limit_canister.into(),
            sender.into(),
            "add_config",
            Encode!(&InputConfig {
                schema_version: schema_version.into(),
                rules,
            })
            .unwrap(),
        )
        .await
        .map_err(|err| err.to_string())?;
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to add_config failed: {:#?}", s),
    };
    Ok(Decode!(&result, AddConfigResponse).unwrap())
}

pub async fn get_config(
    pocket_ic: &PocketIc,
    rate_limit_canister: PrincipalId,
    sender: PrincipalId,
    version: Option<Version>,
) -> Result<GetConfigResponse, String> {
    let result = pocket_ic
        .update_call( // could be query
            rate_limit_canister.into(),
            sender.into(),
            "get_config",
            Encode!(&version).unwrap(),
        )
        .await
        .map_err(|err| err.to_string())?;
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_config failed: {:#?}", s),
    };
    Ok(Decode!(&result, GetConfigResponse).unwrap())
}

#[tokio::test]
async fn test() {
    // 1. Prepare the world.
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .build_async()
        .await;

    let ii_subnet_id = {
        let topology = pocket_ic.topology().await;
        topology.get_ii().unwrap()
    };

    let with_mainnet_nns_canister_versions = false;
    install_nns_canisters(
        &pocket_ic,
        with_mainnet_nns_canister_versions,
        None,
    )
    .await;

    let wasm = build_rate_limits_wasm();

    let initial_payload = InitArg {
        authorized_principal: None,
        registry_polling_period_secs: 1,
    };

    let rate_limit_canister = install_canister(
        &pocket_ic, 
        "Rate Limits Canister", 
        ii_subnet_id,
        Encode!(&initial_payload).unwrap(), 
        wasm.clone(),
    ).await;

    let wasm_hash = Sha256::hash(&wasm.clone().bytes());
    assert_eq!(
        get_installed_wasm_hash(&pocket_ic, rate_limit_canister).await,
        wasm_hash,
    );

    // 2. Run code under test.

    let add_config_response = add_config(
        &pocket_ic,
        rate_limit_canister,
        PrincipalId::new_anonymous(),
        0,
        vec![],
    ).await.unwrap();

    println!("add_config_response = {:#?}", add_config_response);

    let get_config_response = get_config(
        &pocket_ic,
        rate_limit_canister,
        PrincipalId::new_anonymous(),
        Some(0),
    ).await.unwrap();

    println!("get_config_response = {:#?}", get_config_response);

    let new_wasm_bytes = modify_wasm_bytes(&wasm.clone().bytes(), 42);
    let new_wasm_hash = Sha256::hash(&new_wasm_bytes[..]);
    assert_ne!(wasm_hash, new_wasm_hash);

    pocket_ic.upgrade_canister(
        rate_limit_canister.into(),
        new_wasm_bytes,
        Encode!(&initial_payload).unwrap(),
        None,
    ).await
    .unwrap();

    assert_eq!(
        get_installed_wasm_hash(&pocket_ic, rate_limit_canister).await,
        new_wasm_hash,
    );

    // panic!("Hello Rate Limits!");
}