use pocket_ic::PocketIcBuilder;
use rate_limits_api::{
    v1::{RateLimitRule, RequestType},
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, IncidentId, InputConfig, InputRule, RuleId, Version,
};
use canister_test::Project;
use canister_test::Wasm;
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use rate_limits_api::InitArg;
use pocket_ic::nonblocking::PocketIc;
use ic_base_types::SubnetId;
use pocket_ic::CanisterSettings;

// TODO: Should be factored out
use ic_nns_constants::{
    self, ALL_NNS_CANISTER_IDS, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
    REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_test_utils::{
    common::{
        build_governance_wasm, build_ledger_wasm, build_lifeline_wasm,
        build_mainnet_governance_wasm, build_mainnet_ledger_wasm, build_mainnet_lifeline_wasm,
        build_mainnet_registry_wasm, build_mainnet_root_wasm, build_mainnet_sns_wasms_wasm,
        build_registry_wasm, build_root_wasm, build_sns_wasms_wasm, NnsInitPayloadsBuilder,
    },
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_index_ng_sns_wasm,
        build_ledger_sns_wasm, build_mainnet_archive_sns_wasm, build_mainnet_governance_sns_wasm,
        build_mainnet_index_ng_sns_wasm, build_mainnet_ledger_sns_wasm,
        build_mainnet_root_sns_wasm, build_mainnet_swap_sns_wasm, build_root_sns_wasm,
        build_swap_sns_wasm, ensure_sns_wasm_gzipped,
    },
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use prost::Message;
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

    let (governance_wasm, ledger_wasm, root_wasm, lifeline_wasm, sns_wasm_wasm, registry_wasm) =
        if with_mainnet_nns_canister_versions {
            (
                build_mainnet_governance_wasm(),
                build_mainnet_ledger_wasm(),
                build_mainnet_root_wasm(),
                build_mainnet_lifeline_wasm(),
                build_mainnet_sns_wasms_wasm(),
                build_mainnet_registry_wasm(),
            )
        } else {
            (
                build_governance_wasm(),
                build_ledger_wasm(),
                build_root_wasm(),
                build_lifeline_wasm(),
                build_sns_wasms_wasm(),
                build_registry_wasm(),
            )
        };

    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "ICP Ledger",
        LEDGER_CANISTER_ID,
        Encode!(&nns_init_payload.ledger).unwrap(),
        ledger_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "NNS Root",
        ROOT_CANISTER_ID,
        Encode!(&nns_init_payload.root).unwrap(),
        root_wasm,
        Some(LIFELINE_CANISTER_ID.get()),
    )
    .await;
    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "NNS Governance",
        GOVERNANCE_CANISTER_ID,
        nns_init_payload.governance.encode_to_vec(),
        governance_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "Lifeline",
        LIFELINE_CANISTER_ID,
        Encode!(&nns_init_payload.lifeline).unwrap(),
        lifeline_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
    ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister(
        pocket_ic,
        "NNS SNS-W",
        SNS_WASM_CANISTER_ID,
        Encode!(&nns_init_payload.sns_wasms).unwrap(),
        sns_wasm_wasm,
        Some(ROOT_CANISTER_ID.get()),
    )
    .await;
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
    // 1. Prepare the world
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

    let rate_limits_canister = pocket_ic.create_canister().await;


    let initial_payload = InitArg {
        authorized_principal: None,
        registry_polling_period_secs: 1,
    };

    println!("rate_limits_canister = {:?}", rate_limits_canister);

    let rate_limit_canister = install_canister(
        &pocket_ic, 
        "Rate Limits Canister", 
        ii_subnet_id,
        Encode!(&initial_payload).unwrap(), 
        wasm,
    ).await;

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

    panic!("Hello Rate Limits!");
}