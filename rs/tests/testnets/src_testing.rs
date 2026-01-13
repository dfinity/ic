// Set up a testnet containing:
//   one 1-node System subnet for the NNS,
//   one 1-node System subnet for exchange rate canister,
//   32 1-node Application subnets filling the canister ID ranges between the NNS and the exchange rate canister and also used for the cycles wallet,
//   one API boundary node
//   one ic-gateway and a p8s (with grafana) VM.
// All replica nodes use the default resources.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create src_testing --output-dir=./src_testing -- --test_tmpdir=./src_testing
//
// The --output-dir=./src_testing will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./src_testing will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i src_testing/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae",
//         "ipv6": "2a0b:21c0:4003:2:5034:46ff:fe3c:e76f"
//       }
//     ],
//     "subnet_id": "5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe",
//     "subnet_type": "application"
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     "prometheus": "Prometheus Web UI at http://prometheus.src_testing--1692597750709.testnet.farm.dfinity.systems",
//     "grafana": "Grafana at http://grafana.src_testing--1692597750709.testnet.farm.dfinity.systems",
//     "progress_clock": "IC Progress Clock at http://grafana.src_testing--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s\u0026from=now-5m\u0026to=now",
//
// Happy testing!

use anyhow::Result;

use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm};
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::util::{block_on, create_canister};
use ic_xrc_types::{Asset, AssetClass, ExchangeRateMetadata};
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental, nns_dapp_customizations, set_authorized_subnets,
};
use std::env;
use std::str::FromStr;
use xrc_mock::{ExchangeRate, Response, XrcMockInitPayload};

const DEFAULT_XRC_PRINCIPAL_STR: &str = "uf6dk-hyaaa-aaaaq-qaaaq-cai";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

/// CXDR is an asset whose rate is derived from more sources than the XDR rate.
/// The input rate to this method is the integer multiple of 1e-9 CXDR that is worth 1 ICP,
/// e.g., `rate` equal to `12_000_000_000` corresponds to the conversion rate of 12 CXDR for 1 ICP.
fn new_icp_cxdr_mock_exchange_rate_canister_init_payload(rate: u64) -> XrcMockInitPayload {
    XrcMockInitPayload {
        response: Response::ExchangeRate(ExchangeRate {
            rate,
            base_asset: Some(Asset {
                symbol: "ICP".to_string(),
                class: AssetClass::Cryptocurrency,
            }),
            quote_asset: Some(Asset {
                symbol: "CXDR".to_string(),
                class: AssetClass::FiatCurrency,
            }),
            metadata: Some(ExchangeRateMetadata {
                decimals: 9,
                base_asset_num_queried_sources: 7,
                base_asset_num_received_rates: 5,
                quote_asset_num_queried_sources: 10,
                quote_asset_num_received_rates: 4,
                standard_deviation: 0,
                forex_timestamp: None,
            }),
        }),
    }
}

pub fn setup(env: TestEnv) {
    // start p8s for metrics and dashboards
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");

    // set up IC
    let mut ic = InternetComputer::new().with_api_boundary_nodes(1);
    // the following subnets are gonna have IDs 1, 2, 3, ...
    for _ in 0..32 {
        ic = ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(1));
    }
    ic = ic.add_subnet(
        Subnet::new(SubnetType::System)
            .with_features(SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            })
            .add_nodes(1),
    );
    // the last system subnet is the root subnet with ID 0
    ic = ic.add_subnet(Subnet::new(SubnetType::System).add_nodes(1));
    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    // set up NNS canisters
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );

    // sets the application subnets as "authorized" for canister creation by CMC
    set_authorized_subnets(&env);

    // deploy ic-gateway
    let ic_gatewway_name = "ic-gateway";
    IcGatewayVm::new(ic_gatewway_name)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(ic_gatewway_name).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    env.sync_with_prometheus();

    // install II, NNS dapp, and Subnet Rental Canister
    install_ii_nns_dapp_and_subnet_rental(&env, &ic_gateway_url, None);

    // install the Exchange Rate Canister
    let topology = env.topology_snapshot();
    // define the Exchange Rate Canister ID on mainnet
    let default_xrc_principal_id = PrincipalId::from_str(DEFAULT_XRC_PRINCIPAL_STR).unwrap();
    let default_xrc_canister_id: CanisterId = default_xrc_principal_id.try_into().unwrap();
    // find the subnet containing the Exchange Rate Canister ID
    let xrc_subnets = topology
        .subnets()
        .filter(|s| {
            s.subnet_canister_ranges()
                .into_iter()
                .any(|r| r.contains(&default_xrc_canister_id))
        })
        .collect::<Vec<_>>();
    // this subnet must be unique
    assert_eq!(xrc_subnets.len(), 1);
    let xrc_subnet = xrc_subnets.into_iter().next().unwrap();
    // and of the system subnet type
    assert_eq!(xrc_subnet.subnet_type(), SubnetType::System);
    let xrc_node = xrc_subnet.nodes().next().unwrap();
    let xrc_agent = xrc_node.build_default_agent();
    // we create a trivial canister to fill the first canister ID on the Exchange Rate Canister subnet
    block_on(async move {
        create_canister(&xrc_agent, xrc_node.effective_canister_id()).await;
    });
    // the second canister ID on the Exchange Rate Canister subnet belongs to the Exchange Rate Canister
    let xrc_node = xrc_subnet.nodes().next().unwrap();
    // we set the exchange rate to 12 XDR per 1 ICP
    let xrc_payload = new_icp_cxdr_mock_exchange_rate_canister_init_payload(12_000_000_000);
    let xrc_canister_id = xrc_node.create_and_install_canister_with_arg(
        &env::var("XRC_WASM_PATH").expect("XRC_WASM_PATH not set"),
        Some(Encode!(&xrc_payload).unwrap()),
    );
    assert_eq!(xrc_canister_id, default_xrc_principal_id.into());
}
