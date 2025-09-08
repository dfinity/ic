/* tag::catalog[]
Title:: II and NNS Frontend Dapp Test

Goal:: Ensure that II and NNS frontend dapp canisters can be installed on a system subnet and reached via a BN.

Runbook::
. Set up one system subnet and one BN.
. Install II and NNS frontend dapp onto the system subnet.
. Access II via an HTTP request to the BN with a retry loop as the BN needs some time to come up.
. Access NNS frontend dapp via an HTTP request to the BN with a retry loop as the BN needs some time to come up.

Success:: The test driver can download an HTML page from II and NNS frontend dapp via a BN.

end::catalog[] */

use anyhow::{Result, bail};

use candid::Principal;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, secs},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use libflate::gzip::Decoder;
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental, nns_dapp_customizations, set_authorized_subnets,
};
use std::io::Read;
use url::Url;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .with_api_boundary_nodes(1)
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    set_authorized_subnets(&env);
}

fn get_html(env: &TestEnv, ic_gateway_url: Url, canister_id: Principal, dapp_anchor: &str) {
    // prepend canister_id to url
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    let dapp_url = format!("https://{canister_id}.{ic_gateway_domain}");
    let log = env.logger();
    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            format!("get html from {}", dapp_url),
            &log,
            secs(600),
            secs(30),
            async || {
                let client = reqwest::Client::builder()
                    .use_rustls_tls()
                    .https_only(true)
                    .http1_only()
                    .build()?;

                let resp = client
                    .get(dapp_url.clone())
                    .header("Accept-Encoding", "gzip")
                    .header("User-Agent", "systest") // to prevent getting the service worker
                    .send()
                    .await?;

                let status = resp.status();
                if !status.is_success() {
                    bail!(
                        "Failed to get HTML from {}: status code {:?}",
                        dapp_url,
                        status
                    );
                }

                let body_bytes = resp.bytes().await?.to_vec();
                if let Ok(body) = String::from_utf8(body_bytes.clone()) {
                    if body.contains("503 Service Temporarily Unavailable") {
                        bail!("BN is not ready yet!");
                    } else if body.contains(dapp_anchor) {
                        return Ok(());
                    } else {
                        panic!("Unexpected response from BN!");
                    }
                };

                let mut decoder = Decoder::new(&body_bytes[..]).unwrap();
                let mut decoded_data = Vec::new();
                decoder.read_to_end(&mut decoded_data).unwrap();

                let body = String::from_utf8(decoded_data.to_vec()).unwrap();
                assert!(body.contains(dapp_anchor));

                Ok(())
            }
        )
        .await
    })
    .unwrap_or_else(|_| panic!("{} should deliver a proper HTML page!", dapp_url.as_str()));
}

pub fn test(env: TestEnv) {
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let (ii_canister_id, nns_dapp_canister_id) =
        install_ii_nns_dapp_and_subnet_rental(&env, &ic_gateway_url, None);
    let ii_anchor = "<title>Internet Identity</title>";
    let nns_dapp_anchor = "<title>Network Nervous System</title>";
    get_html(&env, ic_gateway_url.clone(), ii_canister_id, ii_anchor);
    get_html(&env, ic_gateway_url, nns_dapp_canister_id, nns_dapp_anchor);
}
