// Set up a testnet for exercising HTTPS outcalls by hand:
//   a 1-node System subnet, a 13-node Application subnet (both with HTTP outcalls
//   enabled), an API boundary node, an ic-gateway, a p8s (with grafana) VM, and a
//   universal VM running httpbin for the outcalls to target.
//
// The HTTPS outcalls test canister is installed on the Application subnet with a
// large cycle balance, since the cycles an outcall attaches come out of it.
//
// You can set up this testnet by executing the following commands:
//
//   $ ./ci/tools/container-run.sh
//   $ bazel run //rs/tests/testnets:https_outcalls --test_tmpdir=./https_outcalls -- --keepalive
//
// Once it is up, look for the "HTTPS OUTCALLS TESTNET" banner at the end of the
// output: it lists the canister's id, the URL to reach it at, and the httpbin URL
// to point outcalls at.
//
// The --test_tmpdir=./https_outcalls will store the remaining test output in the
// specified directory. This is useful to have access to in case you need to SSH
// into an IC node for example like:
//
//   $ ssh -i https_outcalls/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Happy testing!

use anyhow::Result;
use candid::{Decode, Encode, Principal};
use canister_http::{
    UNIVERSAL_VM_NAME, await_nodes_healthy, get_universal_vm_address, start_httpbin_on_uvm,
};
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm},
    prometheus_vm::PrometheusUrls,
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{
        HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsCustomizations,
        get_dependency_path_from_env, load_wasm,
    },
    universal_vm::UniversalVm,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{assert_create_agent, block_on, create_and_install_with_cycles};
use ic_types_cycles::Cycles;
use slog::{info, warn};
use std::env;
use url::Url;

/// Big enough that the subnet behaves like a production one — a 13-node
/// Application subnet is the smallest mainnet size.
const APP_SUBNET_NODES: usize = 13;

/// The cycle balance the test canister is created with. Outcalls are paid out of
/// it, and under legacy pricing a request that leaves `max_response_bytes` unset
/// is charged for the largest response it could get back, so keep it generous.
const CANISTER_CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

/// The `TestEnv` keys the two installed canisters' ids are recorded under, so that
/// `report` can pick them up again.
const TEST_CANISTER_PATH: &str = "https_outcalls_test_canister_id";
const CANDID_UI_PATH: &str = "candid_ui_canister_id";

/// Grafana dashboards worth a direct link. Their uids come from the dashboards
/// the Prometheus VM syncs into Grafana.
const HTTPS_OUTCALLS_DASHBOARD: &str = "https-outcalls";
const CANISTER_HTTP_DASHBOARD: &str = "consensus-canister-http";
const PROGRESS_CLOCK_DASHBOARD: &str = "ic-progress-clock";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        // Reporting runs as a trailing test rather than at the end of `setup`: the
        // task that brings up the Prometheus VM runs in parallel with setup, so its
        // URLs are only recorded once every setup task has finished. It also puts
        // the banner at the very end of the output, where it is easiest to find.
        .add_test(systest!(log))
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    let with_outcalls = || SubnetFeatures {
        http_requests: true,
        ..SubnetFeatures::default()
    };

    // The universal VM and the IC take a while to come up, so start them together.
    std::thread::scope(|s| {
        s.spawn(|| {
            UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
                .with_config_img(get_dependency_path_from_env("HTTP_UVM_CONFIG_IMAGE_PATH"))
                .enable_ipv4()
                .start(&env)
                .expect("failed to set up the universal VM");
        });

        s.spawn(|| {
            InternetComputer::new()
                .add_subnet(
                    Subnet::new(SubnetType::System)
                        .with_features(with_outcalls())
                        .add_nodes(1),
                )
                .add_subnet(
                    Subnet::new(SubnetType::Application)
                        .with_features(with_outcalls())
                        .add_nodes(APP_SUBNET_NODES),
                )
                .with_api_boundary_nodes(1)
                .setup_and_start(&env)
                .expect("failed to set up the IC under test");

            await_nodes_healthy(&env);
            install_nns_with_customizations_and_check_progress(
                env.topology_snapshot(),
                NnsCustomizations::default(),
            );
        });
    });

    // Both the firewall rules httpbin needs and the canister install talk to the
    // nodes, so they only run once the IC is up.
    start_httpbin_on_uvm(&env);

    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to set up ic-gateway");

    let test_canister = install(
        &env,
        "the HTTPS outcalls test canister",
        wasm_from_env("HTTPS_OUTCALLS_TEST_CANISTER_WASM_PATH"),
    );
    // Installed alongside so that the test canister can be driven from a browser:
    // the Candid UI talks to whichever IC serves it, so it has to live here rather
    // than being used from mainnet.
    let mut candid_ui_wasm = wasm_from_env("CANDID_UI_WASM_PATH");
    talk_to_this_ic_not_mainnet(&mut candid_ui_wasm);
    let candid_ui = install(&env, "the Candid UI canister", candid_ui_wasm);

    // `report` runs afterwards and has no way of knowing which canister is which,
    // so record them.
    env.write_json_object(TEST_CANISTER_PATH, &test_canister)
        .expect("could not record the test canister's id");
    env.write_json_object(CANDID_UI_PATH, &candid_ui)
        .expect("could not record the Candid UI canister's id");
}

/// Reads a canister wasm from the path the `wasm_path_var` environment variable
/// points at.
fn wasm_from_env(wasm_path_var: &str) -> Vec<u8> {
    load_wasm(env::var(wasm_path_var).unwrap_or_else(|_| panic!("{wasm_path_var} is not set")))
}

/// Rewrites the vendored Candid UI so that it talks to this testnet rather than to
/// mainnet.
///
/// The UI works out which IC to call from the page's own hostname, recognising only
/// mainnet, localhost and two cloud IDEs; anything else — a Farm playnet domain
/// included — falls back to `https://icp-api.io`. The page loads fine and then
/// sends every call to mainnet, where a testnet's low canister ids name real
/// canisters, so the failures read as if they came from the testnet itself.
///
/// One entry of its suffix list is replaced with a suffix that Farm domains match.
/// The replacement is exactly as long as what it replaces, so nothing in the module
/// shifts; and matching on a *suffix* keeps the whole hostname as the host, which
/// is what serving the UI from its own canister subdomain needs.
fn talk_to_this_ic_not_mainnet(wasm: &mut [u8]) {
    /// Recognised by the Candid UI, and of no use on a testnet.
    const GITPOD: &[u8] = b".gitpod.io";
    /// Matches `<canister>.<playnet>.farm.dfinity.systems`.
    const FARM: &[u8] = b"ty.systems";
    const _: () = assert!(GITPOD.len() == FARM.len());

    let occurrences: Vec<usize> = wasm
        .windows(GITPOD.len())
        .enumerate()
        .filter(|(_, window)| *window == GITPOD)
        .map(|(offset, _)| offset)
        .collect();
    let [offset] = occurrences[..] else {
        panic!(
            "expected the Candid UI to mention {} exactly once, found it {} times; \
             its host resolution must have changed, so check that it still falls \
             back to mainnet before patching it",
            String::from_utf8_lossy(GITPOD),
            occurrences.len()
        )
    };
    wasm[offset..offset + FARM.len()].copy_from_slice(FARM);
}

/// Installs `wasm` on the application subnet with a large cycle balance.
fn install(env: &TestEnv, description: &str, wasm: Vec<u8>) -> Principal {
    let node = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
        .next()
        .expect("the application subnet has no nodes");

    let canister_id = block_on(create_and_install_with_cycles(
        &node.build_default_agent(),
        node.effective_canister_id(),
        &wasm,
        CANISTER_CYCLES,
    ));
    info!(
        env.logger(),
        "Installed {description} as {canister_id} with {CANISTER_CYCLES}"
    );
    canister_id
}

/// Checks both ways a tool can fetch `canister`'s Candid interface, over both
/// routes a tool can take to reach it, so that a UI which cannot load it is
/// diagnosed here rather than in a browser console.
///
/// The Candid UI reads the `candid:service` metadata first and falls back to the
/// `__get_candid_interface_tmp_hack` query, giving up with "Cannot fetch candid
/// file" if neither answers — and it swallows the metadata failure as a console
/// warning, which makes the cause easy to miss.
///
/// Three routes are checked, because they have turned out not to be equivalent:
/// a replica node directly, the ic-gateway on its bare domain, and the ic-gateway
/// on the Candid UI's own canister subdomain. The last is the one a browser takes,
/// since the UI's agent derives its host from `window.location.origin`, so only it
/// says whether the UI can actually load.
fn check_candid_interface(env: &TestEnv, canister: Principal, candid_ui: Principal, gateway: &Url) {
    let node = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
        .next()
        .expect("the application subnet has no nodes");
    check_candid_interface_over(env, canister, "a replica node", node.build_default_agent());

    check_candid_interface_over(
        env,
        canister,
        "the ic-gateway",
        block_on(assert_create_agent(gateway.as_str())),
    );

    // What the browser does: the Candid UI is served from its own subdomain, so
    // that is the host its agent talks to.
    let domain = gateway.domain().expect("the ic-gateway URL has no domain");
    let subdomain = format!("https://{candid_ui}.{domain}");
    check_candid_interface_over(
        env,
        canister,
        "the Candid UI's own subdomain, as the browser does",
        block_on(assert_create_agent(&subdomain)),
    );

    // Print the verified URL rather than only the fact that it works. Every launch
    // draws a fresh playnet domain while canister ids stay the same, and testnets
    // kept alive keep answering — so a URL from an earlier run looks identical and
    // still loads, just from the wrong IC. Clicking the line that proves the check
    // passed cannot pick up the wrong one.
    info!(
        env.logger(),
        "Verified: the Candid UI at {subdomain}/?id={canister} can load the \
         canister's interface."
    );
}

/// Checks that `agent` can fetch `canister`'s Candid interface, both from the
/// metadata and from the query that serves it.
fn check_candid_interface_over(env: &TestEnv, canister: Principal, route: &str, agent: Agent) {
    let logger = env.logger();

    // Reading the metadata is not essential — the query below is enough for the
    // Candid UI — so report it rather than failing on it.
    match block_on(agent.read_state_canister_metadata(canister, "candid:service")) {
        Ok(did) => info!(
            logger,
            "Over {route}, the candid:service metadata of {canister} reads back ({} bytes).",
            did.len()
        ),
        Err(err) => warn!(
            logger,
            "Over {route}, the candid:service metadata of {canister} could not be read: {err}. \
             Tools that rely on it fall back to the __get_candid_interface_tmp_hack query."
        ),
    }

    let interface = block_on(
        agent
            .query(&canister, "__get_candid_interface_tmp_hack")
            .with_arg(Encode!().expect("encoding empty arguments cannot fail"))
            .call(),
    )
    .unwrap_or_else(|err| {
        panic!(
            "Over {route}, the test canister does not serve its Candid interface ({err}), \
             so the Candid UI will not be able to load it"
        )
    });
    let interface: String =
        Decode!(&interface, String).expect("the Candid interface did not decode as text");
    info!(
        logger,
        "Over {route}, the Candid interface of {canister} is served as a query ({} bytes).",
        interface.len()
    );
}

/// Logs everything needed to drive the canister by hand.
fn log(env: TestEnv) {
    let test_canister: Principal = env
        .read_json_object(TEST_CANISTER_PATH)
        .expect("the test canister's id was not recorded");
    let candid_ui: Principal = env
        .read_json_object(CANDID_UI_PATH)
        .expect("the Candid UI canister's id was not recorded");

    let gateway = env
        .get_deployed_ic_gateway(IC_GATEWAY_VM_NAME)
        .expect("the ic-gateway was not deployed")
        .get_public_url();

    check_candid_interface(&env, test_canister, candid_ui, &gateway);
    let domain = gateway.domain().expect("the ic-gateway URL has no domain");
    let httpbin = format!("https://[{}]", get_universal_vm_address(&env));
    let PrometheusUrls {
        prometheus_url,
        grafana_url,
    } = PrometheusUrls::read_attribute(&env);

    info!(
        env.logger(),
        "\n\
         ========================= HTTPS OUTCALLS TESTNET =========================\n\
         \n\
         Candid UI .......... https://{candid_ui}.{domain}/?id={test_canister}\n\
         Test canister ...... {test_canister}\n\
         Outcall target ..... {httpbin}   (httpbin on the universal VM)\n\
         IC endpoint ........ {gateway}\n\
         \n\
         Grafana ............ {grafana_url}\n\
           HTTPS outcalls ... {grafana_url}/d/{HTTPS_OUTCALLS_DASHBOARD}\n\
           CanisterHttp ..... {grafana_url}/d/{CANISTER_HTTP_DASHBOARD}\n\
           progress clock ... {grafana_url}/d/{PROGRESS_CLOCK_DASHBOARD}\n\
         Prometheus ......... {prometheus_url}\n\
         \n\
         Open the Candid UI above in a browser to call the canister. Point its\n\
         outcalls at the target: the replicas trust that certificate, and nothing\n\
         on the public internet is reachable from them. Try\n\
         {httpbin}/ascii/hello, or /bytes/<n> for a response of a given size.\n\
         \n\
         From the command line instead:\n\
         \n\
           dfx canister --network {gateway} call {test_canister} \\\n\
             http_request_fully_replicated \\\n\
             '(\"{httpbin}/ascii/hello\", variant {{ get }}, vec {{}}, null, null,\n\
               opt variant {{ strip_headers }}, null,\n\
               opt variant {{ pay_as_you_go }}, 1_000_000_000 : nat)'\n\
         \n\
           dfx canister --network {gateway} call --query {test_canister} cycle_balance '()'\n\
         \n\
         =========================================================================="
    );
}
