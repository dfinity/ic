/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_registry_subnet_features::SubnetFeatures;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::boundary_node::BoundaryNode;
use ic_system_test_driver::driver::prometheus_vm::HasPrometheus;
use ic_system_test_driver::driver::prometheus_vm::PrometheusVm;
use ic_system_test_driver::driver::boundary_node::BoundaryNodeVm;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::test_env_api::RetrieveIpv4Addr;
use ic_system_test_driver::driver::test_env_api::get_dependency_path;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Cycles;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use proxy_canister::{RemoteHttpRequest, RemoteHttpStressRequest, RemoteHttpStressResponse};
use ic_system_test_driver::driver::universal_vm::UniversalVm;
use slog::{info, Logger};

const NS_IN_1_SEC: u64 = 1_000_000_000;
//TODO(mihailjianu): rename this maybe.
const BN_NAME: &str = "socks-bn";

// TODO(mihailjianu): perhaps investigate the high qps difference between 4 nodes and 40 nodes. 
// Could be that because there are more adapters, more of them are slower than normal?

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    //TODO(mihailjianu): trim this setup.
    println!("debuggg socks setup");
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");

    // Set up Universal VM with HTTP Bin testing service

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .enable_ipv4()
        .start(&env)
        .expect("failed to set up universal VM");

    start_httpbin_on_uvm(&env);
    info!(&logger, "Started Universal VM!");

    // Create raw BN vm to get ipv6 address with which we configure IC.
    let bn_vm = BoundaryNode::new(BN_NAME.to_string())
        .allocate_vm(&env)
        .unwrap();
    let bn_ipv6 = bn_vm.ipv6();

    info!(&logger, "Created raw BN with IP {}!", bn_ipv6);

    // Create IC with injected socks proxy.
    InternetComputer::new()
        .with_socks_proxy(format!("socks5://[{bn_ipv6}]:1080"))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);

    // Start BN.
    bn_vm
        .for_ic(&env, "")
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    env.sync_with_prometheus_by_name("", env.get_playnet_url(BN_NAME));

    let boundary_node_vm = env
        .get_deployed_boundary_node(BN_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(
        &logger,
        "Boundary node {BN_NAME} has IPv4 {:?} and IPv6 {:?}",
        boundary_node_vm.block_on_ipv4().unwrap(),
        boundary_node_vm.ipv6()
    );

    info!(&logger, "Checking BN health");
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    // Because we are stressing the outcalls feature with ~100K requests, and each requests costs ~6-7 billion cycles,
    // the default 100T starting cycles would not be enough cover the cost of all the requests.
    let proxy_canister =
        create_proxy_canister_with_cycles(&env, &runtime, &node, Cycles::new(1 << 127));
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        stress_test_proxy_canister(
            &proxy_canister,
            format!("https://[{webserver_ipv6}]:20443"),
            logger,
        )
        .await;
    });
}

async fn stress_test_proxy_canister(proxy_canister: &Canister<'_>, url: String, logger: Logger) {
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 500).await;
    return;

    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 500).await;
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 1000).await;
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 2000).await;
}

async fn do_request(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
    concurrent_requests: u64,
) -> Result<u64, anyhow::Error> {
    let proxy_canister = proxy_canister.clone();
    let url = url.clone();

    let context = "There is context to be appended in body";
    let res = proxy_canister
        .update_(
            "send_requests_in_parallel",
            candid_one::<
                Result<RemoteHttpStressResponse, (RejectionCode, String)>,
                RemoteHttpStressRequest,
            >,
            RemoteHttpStressRequest {
                request: RemoteHttpRequest {
                    request: UnvalidatedCanisterHttpRequestArgs {
                        url: url.clone(),
                        headers: vec![],
                        body: None,
                        transform: Some(TransformContext {
                            function: TransformFunc(candid::Func {
                                principal: proxy_canister.canister_id().get().0,
                                method: "transform_with_context".to_string(),
                            }),
                            context: context.as_bytes().to_vec(),
                        }),
                        method: HttpMethod::GET,
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                count: concurrent_requests,
            },
        )
        .await
        .map_err(|e| anyhow!("Update call to proxy canister failed with {:?}", e))?;

    if !matches!(res, Ok(ref x) if x.response.status == 200 && x.response.body.contains(context)) {
        //bail!("Http request failed response: {:?}", res);
        info!(logger, "Info Http request failed response: {:?}", res);
    } else {
        let res = res.unwrap();
        info!(
            logger,
            "All {} concurrent requests succeeded!", concurrent_requests
        );

        let duration_ns = res.duration_ns;
        return Ok(duration_ns)
    }
    Ok(0)
}

pub async fn test_proxy_canister(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: Logger,
    concurrent_requests: u64,
) {
    let mut experiments = 0;
    let max_experiments = 1;
    let mut total_duration_ns = 0;

    // We leave the experiment running for at least one minute.
    while total_duration_ns < 60 * NS_IN_1_SEC && experiments < max_experiments {
        experiments += 1;

        let single_call_duration_ns = ic_system_test_driver::retry_with_msg_async!(
            format!(
                "calling send_requests_in_parallel of proxy canister {} with URL {}",
                proxy_canister.canister_id(),
                url
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                do_request(proxy_canister, url.clone(), &logger, concurrent_requests).await
            }
        )
        .await
        .expect("Timeout or repeated failure on canister HTTP calls");

        total_duration_ns += single_call_duration_ns;
    }

    let elapsed_secs = total_duration_ns as f64 / NS_IN_1_SEC as f64;
    println!("total_duration_ns: {}", total_duration_ns);
    let qps = (concurrent_requests * experiments) as f64 / elapsed_secs;
    info!(
        logger,
        "average qps for {} concurrent request(s) and {} experiment(s) is {}",
        concurrent_requests,
        experiments,
        qps
    );
    //assert!(qps > 100.0);
}
