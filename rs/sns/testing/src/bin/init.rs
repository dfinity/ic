use clap::Parser;
use ic_sns_testing::NnsInitArgs;
use ic_sns_testing::bootstrap::bootstrap_nns;
use ic_sns_testing::utils::{TREASURY_PRINCIPAL_ID, get_identity_principal};
use icp_ledger::Tokens;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig, InstanceHttpGatewayConfig};
use pocket_ic::{PocketIcBuilder, Time};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

async fn nns_init(args: NnsInitArgs) {
    let state_dir = if let Some(state_dir) = args.state_dir {
        state_dir
    } else {
        let tempdir = tempdir().unwrap();
        println!(
            "Using temporary PocketIC state directory: {}",
            tempdir.path().display()
        );
        tempdir.keep()
    };
    let all_icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        icp_token: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_token: Some(IcpFeaturesConfig::DefaultConfig),
        nns_governance: Some(IcpFeaturesConfig::DefaultConfig),
        sns: Some(IcpFeaturesConfig::DefaultConfig),
        ii: Some(IcpFeaturesConfig::DefaultConfig),
        nns_ui: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    // We set the time of the PocketIC instance to the current time so that
    // neurons are not too old when we make the instance "live" later.
    // Setting the time to the current time has no impact on determinism of
    // `deciding_nns_neuron_id`.
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: Some(args.ic_network_port),
        domains: None,
        https_config: None,
    };
    let pocket_ic = PocketIcBuilder::new()
        .with_server_url(args.server_url)
        .with_state_dir(state_dir)
        .with_icp_features(all_icp_features)
        .with_initial_time(Time::from_nanos_since_unix_epoch(current_time))
        .with_http_gateway(http_gateway_config)
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let dev_principal_id = get_identity_principal(&args.dev_identity).unwrap();

    let treasury_principal_id = if let Some(icp_treasury_identity) = args.icp_treasury_identity {
        get_identity_principal(&icp_treasury_identity).unwrap()
    } else {
        println!(
            "Using default treasury principal ID: {}",
            *TREASURY_PRINCIPAL_ID
        );
        *TREASURY_PRINCIPAL_ID
    };

    let deciding_nns_neuron_id = bootstrap_nns(
        &pocket_ic,
        vec![
            (
                treasury_principal_id,
                Tokens::from_tokens(10_000_000).unwrap(),
            ),
            (dev_principal_id, Tokens::from_tokens(100).unwrap()),
        ],
        dev_principal_id,
    )
    .await;

    // Only start auto progress on the instance after bootstrapping NNS
    // to keep the execution deterministic (modulo initial time) as long as possible.
    pocket_ic.auto_progress().await;

    let endpoint = pocket_ic.url().unwrap();
    println!("PocketIC endpoint: {endpoint}");

    println!("NNS initialized");
    println!(
        "Use the following Neuron ID for further testing: {}",
        deciding_nns_neuron_id.id
    );
}

#[tokio::main]
async fn main() {
    let args = NnsInitArgs::parse();
    nns_init(args).await
}
