use candid::Principal;
use candid::{CandidType, Encode};
use canister_test::{Canister, Wasm};
use ic_base_types::SubnetId;
use ic_ledger_core::Tokens;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_AGGREGATOR_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_test_utils::governance::install_nns_canister_by_proposal;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{
        HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsCustomizations,
        load_wasm,
    },
};
use ic_system_test_driver::nns::set_authorized_subnetwork_list;
use ic_system_test_driver::sns_client::add_subnet_to_sns_deploy_whitelist;
use ic_system_test_driver::util::{block_on, create_canister, install_canister, runtime_from_url};
use icp_ledger::AccountIdentifier;
use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::HashMap;
use url::Url;

use std::env;

/// Init and post_upgrade arguments for SNS aggregator.
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct Config {
    pub update_interval_ms: u64,
    pub fast_interval_ms: u64,
}

/// Init and post_upgrade arguments for NNS frontend dapp.
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum SchemaLabel {
    Map,
    AccountsInStableMemory,
}
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct CanisterArguments {
    pub args: Vec<(String, String)>,
    pub schema: Option<SchemaLabel>,
}

/// Initializes the ICP ledger canister with 1e9 ICP on an account
/// controlled by a secret key with the following PEM file:
/// -----BEGIN EC PRIVATE KEY-----
/// MHQCAQEEICJxApEbuZznKFpV+VKACRK30i6+7u5Z13/DOl18cIC+oAcGBSuBBAAK
/// oUQDQgAEPas6Iag4TUx+Uop+3NhE6s3FlayFtbwdhRVjvOar0kPTfE/N8N6btRnd
/// 74ly5xXEBNSXiENyxhEuzOZrIWMCNQ==
/// -----END EC PRIVATE KEY-----
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
        registry_canister_init_payload: Default::default(),
    }
}

pub fn install_sns_aggregator(
    env: &TestEnv,
    ic_gateway_url: &Url,
    sns_node: IcNodeSnapshot,
) -> Principal {
    let sns_agent = sns_node.build_default_agent();
    let sns_aggregator_wasm = load_wasm(env::var("SNS_AGGREGATOR_WASM_PATH").unwrap());
    let logger = env.logger();
    block_on(async move {
        let sns_aggregator_canister_id =
            create_canister(&sns_agent, sns_node.effective_canister_id()).await;
        install_canister(
            &sns_agent,
            sns_aggregator_canister_id,
            sns_aggregator_wasm.as_slice(),
            Encode!(&Some(Config {
                update_interval_ms: 1_000,
                fast_interval_ms: 100,
            }))
            .unwrap(),
        )
        .await;
        let ic_gateway_domain = ic_gateway_url.domain().unwrap();
        info!(
            logger,
            "SNS aggregator: https://{}.{ic_gateway_domain}", sns_aggregator_canister_id,
        );
        sns_aggregator_canister_id
    })
}

/// Installs II, NNS dapp, and Subnet Rental Canister.
/// The Subnet Rental Canister is installed since otherwise
/// the canister ID of the ckETH ledger (required by the NNS dapp)
/// would conflict with the Subnet Rental Canister ID on mainnet.
pub fn install_ii_nns_dapp_and_subnet_rental(
    env: &TestEnv,
    ic_gateway_url: &Url,
    sns_aggregator_canister_id: Option<Principal>,
) -> (Principal, Principal) {
    let ic_gateway_domain = ic_gateway_url.domain().unwrap().to_string();

    // deploy the II canister
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let ii_canister_id =
        nns_node.create_and_install_canister_with_arg(&env::var("II_WASM_PATH").unwrap(), None);

    // create the NNS dapp canister so that its canister ID is allocated
    // and the Subnet Rental Canister gets its mainnet canister ID in the next step
    // it can't be installed yet since we need to get the ckETH ledger canister ID first
    let nns_agent = nns_node.build_default_agent();
    let nns_dapp_canister_id =
        block_on(
            async move { create_canister(&nns_agent, nns_node.effective_canister_id()).await },
        );

    // deploy the Subnet Rental Canister
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    block_on(async move {
        install_nns_canister_by_proposal(
            &Canister::new(&nns, SUBNET_RENTAL_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            Wasm::from_bytes(load_wasm(env::var("SUBNET_RENTAL_WASM_PATH").unwrap())),
            None,
        )
        .await;
    });

    // now that we know all required canister IDs, install the NNS dapp
    let nns_agent = nns_node.build_default_agent();
    let nns_dapp_wasm = load_wasm(env::var("NNS_DAPP_WASM_PATH").unwrap());
    let logger = env.logger();
    block_on(async move {
        // The configuration values have been adapted from
        // `https://github.com/dfinity/nns-dapp/blob/5126b011ac52f9f8544c37d18bc15603756a7e3c/scripts/nns-dapp/test-config-assets/mainnet/arg.did`.
        let nns_dapp_metadata = vec![
              ("API_HOST".to_string(), ic_gateway_url.to_string()),
              ("CYCLES_MINTING_CANISTER_ID".to_string(), CYCLES_MINTING_CANISTER_ID.to_string()),
              ("DFX_NETWORK".to_string(), "local".to_string()),
              ("FEATURE_FLAGS".to_string(), "{\"DISABLE_CKTOKENS\":true,\"DISABLE_IMPORT_TOKEN_VALIDATION_FOR_TESTING\":false,\"ENABLE_APY_PORTFOLIO\":true,\"ENABLE_CKTESTBTC\":false,\"ENABLE_DISBURSE_MATURITY\":true,\"ENABLE_LAUNCHPAD_REDESIGN\":true,\"ENABLE_NEW_TABLES\":true,\"ENABLE_NNS_TOPICS\":false,\"ENABLE_SNS_TOPICS\":true}".to_string()),
              ("FETCH_ROOT_KEY".to_string(), "true".to_string()),
              ("GOVERNANCE_CANISTER_ID".to_string(), GOVERNANCE_CANISTER_ID.to_string()),
              ("HOST".to_string(), ic_gateway_url.to_string()),
              /* ICP swap canister is not deployed by the test driver! */
              ("ICP_SWAP_URL".to_string(), format!("https://uvevg-iyaaa-aaaak-ac27q-cai.raw.{ic_gateway_domain}/")),
              ("IDENTITY_SERVICE_URL".to_string(), format!("https://{ii_canister_id}.{ic_gateway_domain}")),
              ("INDEX_CANISTER_ID".to_string(), LEDGER_CANISTER_ID.to_string()),
              ("LEDGER_CANISTER_ID".to_string(), LEDGER_CANISTER_ID.to_string()),
              ("OWN_CANISTER_ID".to_string(), nns_dapp_canister_id.to_string()),
              /* plausible.io API might not work anyway so the value of `PLAUSIBLE_DOMAIN` is pretty much arbitrary */
              ("PLAUSIBLE_DOMAIN".to_string(), format!("{nns_dapp_canister_id}.{ic_gateway_domain}")),
              ("ROBOTS".to_string(), "".to_string()),
              ("SNS_AGGREGATOR_URL".to_string(), format!("https://{}.{}", sns_aggregator_canister_id.unwrap_or(SNS_AGGREGATOR_CANISTER_ID.into()), ic_gateway_domain)),
              ("STATIC_HOST".to_string(), ic_gateway_url.to_string()),
              ("TVL_CANISTER_ID".to_string(), nns_dapp_canister_id.to_string()),
              ("WASM_CANISTER_ID".to_string(), SNS_WASM_CANISTER_ID.to_string()),
            ];
        let nns_dapp_init_args = Some(CanisterArguments {
            args: nns_dapp_metadata,
            schema: Some(SchemaLabel::AccountsInStableMemory),
        });
        install_canister(
            &nns_agent,
            nns_dapp_canister_id,
            nns_dapp_wasm.as_slice(),
            Encode!(&nns_dapp_init_args).unwrap(),
        )
        .await;
        info!(
            logger,
            "Internet Identity: https://{}.{}", ii_canister_id, ic_gateway_domain
        );
        info!(
            logger,
            "NNS frontend dapp: https://{}.{}", nns_dapp_canister_id, ic_gateway_domain
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
