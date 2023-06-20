use crate::driver::{
    boundary_node::BoundaryNodeVm,
    test_env::TestEnv,
    test_env_api::{
        HasPublicApiUrl, HasTopologySnapshot, HasWasm, IcNodeContainer, IcNodeSnapshot,
        NnsCustomizations,
    },
};
use crate::nns::set_authorized_subnetwork_list;
use crate::sns_client::add_subnet_to_sns_deploy_whitelist;
use crate::util::{block_on, create_canister, install_canister, runtime_from_url};
use candid::Principal;
use candid::{CandidType, Encode};
use ic_base_types::SubnetId;
use ic_ledger_core::Tokens;
use ic_registry_subnet_type::SubnetType;
use icp_ledger::AccountIdentifier;
use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::HashMap;

pub const INTERNET_IDENTITY_WASM: &str =
    "external/ii_test_canister/file/internet_identity_test.wasm";
pub const NNS_DAPP_WASM: &str = "external/nns_dapp_canister/file/nns_dapp_canister.wasm";
pub const SNS_AGGREGATOR_WASM: &str = "external/sns_aggregator/file/sns_aggregator_dev.wasm";

/// Init and post_upgrade arguments for NNS frontend dapp.
#[derive(Debug, Default, Eq, PartialEq, CandidType, Serialize, Deserialize)]
pub struct CanisterArguments {
    pub args: Vec<(String, String)>,
}

pub fn nns_dapp_customizations() -> NnsCustomizations {
    let mut ledger_balances = HashMap::new();
    ledger_balances.insert(
        AccountIdentifier::from_hex(
            "5b315d2f6702cb3a27d826161797d7b2c2e131cd312aece51d4d5574d1247087",
        )
        .unwrap(),
        Tokens::from_tokens(1000000000).unwrap(),
    );
    ledger_balances.insert(
        AccountIdentifier::from_hex(
            "2b8fbde99de881f695f279d2a892b1137bfe81a42d7694e064b1be58701e1138",
        )
        .unwrap(),
        Tokens::from_tokens(1000000000).unwrap(),
    );
    NnsCustomizations {
        ledger_balances: Some(ledger_balances),
        neurons: None,
        install_at_ids: false,
    }
}

pub fn install_sns_aggregator(
    env: &TestEnv,
    boundary_node_name: &str,
    sns_node: IcNodeSnapshot,
) -> Principal {
    let boundary_node = env
        .get_deployed_boundary_node(boundary_node_name)
        .unwrap()
        .get_snapshot()
        .unwrap();
    let farm_url = boundary_node.get_playnet().unwrap();

    let sns_agent = sns_node.build_default_agent();
    let sns_aggregator_wasm = env.load_wasm(SNS_AGGREGATOR_WASM);
    let logger = env.logger();
    block_on(async move {
        let sns_aggregator_canister_id =
            create_canister(&sns_agent, sns_node.effective_canister_id()).await;
        install_canister(
            &sns_agent,
            sns_aggregator_canister_id,
            sns_aggregator_wasm.as_slice(),
            Encode!(&()).unwrap(),
        )
        .await;
        info!(
            logger,
            "SNS aggregator: https://{}.{}", sns_aggregator_canister_id, farm_url
        );
        sns_aggregator_canister_id
    })
}

pub fn install_ii_and_nns_dapp(
    env: &TestEnv,
    boundary_node_name: &str,
    sns_aggregator_canister_id: Option<Principal>,
) -> (Principal, Principal) {
    let boundary_node = env
        .get_deployed_boundary_node(boundary_node_name)
        .unwrap()
        .get_snapshot()
        .unwrap();
    let farm_url = boundary_node.get_playnet().unwrap();
    let https_farm_url = format!("https://{}", farm_url);
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();

    let ii_canister_id =
        nns_node.create_and_install_canister_with_arg(INTERNET_IDENTITY_WASM, None);

    let nns_dapp_wasm = env.load_wasm(NNS_DAPP_WASM);
    let logger = env.logger();
    block_on(async move {
        let nns_dapp_canister_id =
            create_canister(&nns_agent, nns_node.effective_canister_id()).await;
        let nns_dapp_args = vec![
            ("API_HOST".to_string(), https_farm_url.clone()),
            ("CYCLES_MINTING_CANISTER_ID".to_string(), "rkp4c-7iaaa-aaaaa-aaaca-cai".to_string()),
            ("DFX_NETWORK".to_string(), "farm".to_string()),
            ("FEATURE_FLAGS".to_string(), "{\"ENABLE_CKBTC\":false,\"ENABLE_CKTESTBTC\":false,\"ENABLE_SNS_2\":false,\"ENABLE_SNS_AGGREGATOR\":false,\"ENABLE_SNS_VOTING\":false}".to_string()),
            ("FETCH_ROOT_KEY".to_string(), "true".to_string()),
            ("GOVERNANCE_CANISTER_ID".to_string(), "rrkah-fqaaa-aaaaa-aaaaq-cai".to_string()),
            ("GOVERNANCE_CANISTER_URL".to_string(), format!("https://rrkah-fqaaa-aaaaa-aaaaq-cai.{}", farm_url)),
            ("HOST".to_string(), https_farm_url.clone()),
            ("IDENTITY_SERVICE_URL".to_string(), format!("https://{}.{}",  ii_canister_id, farm_url)),
            ("LEDGER_CANISTER_ID".to_string(), "ryjl3-tyaaa-aaaaa-aaaba-cai".to_string()),
            ("LEDGER_CANISTER_URL".to_string(), format!("https://ryjl3-tyaaa-aaaaa-aaaba-cai.{}", farm_url)),
            ("OWN_CANISTER_ID".to_string(), nns_dapp_canister_id.to_string()),
            ("OWN_CANISTER_URL".to_string(), format!("https://{}.{}", nns_dapp_canister_id, farm_url)),
            ("ROBOTS".to_string(), "<meta name=\"robots\" content=\"noindex, nofollow\" />".to_string()),
            ("SNS_AGGREGATOR_URL".to_string(), sns_aggregator_canister_id.map(|s| format!("https://{}.{}", s, farm_url)).unwrap_or_else(|| "".to_string())),
            ("STATIC_HOST".to_string(), https_farm_url),
            ("WASM_CANISTER_ID".to_string(), "qaa6y-5yaaa-aaaaa-aaafa-cai".to_string())
        ];
        install_canister(
            &nns_agent,
            nns_dapp_canister_id,
            nns_dapp_wasm.as_slice(),
            Encode!(&CanisterArguments {
                args: nns_dapp_args
            })
            .unwrap(),
        )
        .await;
        info!(
            logger,
            "Internet Identity: https://{}.{}", ii_canister_id, farm_url
        );
        info!(
            logger,
            "NNS frontend dapp: https://{}.{}", nns_dapp_canister_id, farm_url
        );
        (ii_canister_id, nns_dapp_canister_id)
    })
}

pub fn set_authorized_subnets(env: &TestEnv) {
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    block_on(async move {
        let app_subnet_ids: Vec<_> = topology
            .subnets()
            .filter_map(|s| (s.subnet_type() == SubnetType::Application).then_some(s.subnet_id))
            .collect();
        set_authorized_subnetwork_list(&nns_runtime, None, app_subnet_ids)
            .await
            .unwrap();
    });
}

pub fn set_sns_subnet(env: &TestEnv, subnet_id: SubnetId) {
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    block_on(async move {
        add_subnet_to_sns_deploy_whitelist(&nns_runtime, subnet_id).await;
    });
}
