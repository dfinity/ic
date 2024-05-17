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

use anyhow::{bail, Result};

use candid::Principal;
use hyper::Client;
use hyper_rustls::HttpsConnectorBuilder;
use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::{
    boundary_node::{BoundaryNode, BoundaryNodeVm},
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{retry, secs, HasTopologySnapshot, NnsCanisterWasmStrategy},
};
use ic_tests::nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental, nns_dapp_customizations, set_authorized_subnets,
};
use ic_tests::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_tests::retry_with_msg;
use ic_tests::systest;
use ic_tests::util::block_on;
use libflate::gzip::Decoder;
use std::io::Read;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

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
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        nns_dapp_customizations(),
    );
    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");
    set_authorized_subnets(&env);
}

fn get_html(env: &TestEnv, farm_url: &str, canister_id: Principal, dapp_anchor: &str) {
    let log = env.logger();
    let dapp_url = &format!("https://{}.{}", canister_id, farm_url);
    retry_with_msg!(
        format!("get html from {}", dapp_url),
        log.clone(),
        secs(600),
        secs(30),
        || {
            block_on(async {
                let https_connector = HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_only()
                    .enable_http1()
                    .build();
                let client = Client::builder().build::<_, hyper::Body>(https_connector);

                let req = hyper::Request::builder()
                    .method(hyper::Method::GET)
                    .uri(dapp_url)
                    .header("Accept-Encoding", "gzip")
                    .header("User-Agent", "systest") // to prevent getting the service worker
                    .body(hyper::Body::from(""))?;

                let resp = client.request(req).await?;

                let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
                if let Ok(body) = String::from_utf8(body_bytes.to_vec()) {
                    if body.contains("503 Service Temporarily Unavailable") {
                        bail!("BN is not ready yet!");
                    } else if body.contains(dapp_anchor) {
                        return Ok(());
                    } else {
                        panic!("Unexpected response from BN!");
                    }
                };

                let body_vec = body_bytes.to_vec();
                let mut decoder = Decoder::new(&body_vec[..]).unwrap();
                let mut decoded_data = Vec::new();
                decoder.read_to_end(&mut decoded_data).unwrap();

                let body = String::from_utf8(decoded_data.to_vec()).unwrap();
                assert!(body.contains(dapp_anchor));

                Ok(())
            })
        }
    )
    .unwrap_or_else(|_| panic!("{} should deliver a proper HTML page!", canister_id));
}

pub fn test(env: TestEnv) {
    let (ii_canister_id, nns_dapp_canister_id) =
        install_ii_nns_dapp_and_subnet_rental(&env, BOUNDARY_NODE_NAME, None);
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();
    let farm_url = boundary_node.get_playnet().unwrap();

    let ii_anchor = "<title>Internet Identity</title>";
    let nns_dapp_anchor = "<title>NNS Dapp</title>";
    get_html(&env, &farm_url, ii_canister_id, ii_anchor);
    get_html(&env, &farm_url, nns_dapp_canister_id, nns_dapp_anchor);
}
