/* tag::catalog[]
Title:: Payload Builder Size Tests

Goal:: Test the consensus payload builder and the accompaning payload validator.

Runbook::
. Set up two subnets with one fast node each
. Install a universal canister in both, one is called target canister the other assist canister.
. The assist canister will be used to send the xnet data to the target canister.
. Send a bunch of large xnet and ingress messages to the same canister. Expect it to handle all of them eventually

Success:: The payload builder respects the boundaries set by the registry, while the payload validator
accepts all payloads generated by the payload builder.

Coverage::
. The system handles well under the load of large ingress messages and xnet messages at the same time.

end::catalog[] */

use ic_agent::{Agent, AgentError};
use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, TopologySnapshot},
    },
    util::UniversalCanister,
};
use ic_universal_canister::{call_args, wasm};

use anyhow::Result;
use futures::{join, stream::FuturesUnordered, StreamExt};
use slog::{info, Logger};
use std::sync::Arc;

const NUM_MSGS: usize = 32;
const MAX_SIZE: usize = 2 * 1024 * 1024;
const MSG_SIZE: usize = 2 * 1000 * 1000;

#[derive(Debug)]
enum PayloadType {
    Ingress(usize),
    XNet(usize),
}

/// The configuration that is used for the dual workload test.
/// In this configuration, all sizes are set to 2MiB.
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(1)
                .with_max_block_payload_size(MAX_SIZE as u64)
                .with_max_ingress_message_size(MAX_SIZE as u64),
        )
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// Tests, that the internet computer behaves well, when there is a high load of
/// ingress messages and xnet messages on the same subnet.
fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    info!(log, "Checking readiness of all nodes after the IC setup...");
    topology.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(log, "All nodes are ready, IC setup succeeded.");
    let (
        (assist_agent, assist_effective_canister_id),
        (target_agent, target_effective_canister_id),
    ) = setup_agents(topology);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let (assist_unican, target_unican) = setup_unicans(
            &log,
            &assist_agent,
            assist_effective_canister_id,
            &target_agent,
            target_effective_canister_id,
        )
        .await;

        let calls = (0..NUM_MSGS)
            .flat_map(|x| vec![PayloadType::XNet(x), PayloadType::Ingress(x)])
            .map(|report| {
                (
                    target_unican.clone(),
                    assist_unican.clone(),
                    report,
                    log.clone(),
                )
            })
            .map(|(target_unican, assist_unican, report, logger)| {
                make_dual_call(target_unican, assist_unican, report, MSG_SIZE, logger)
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>();

        info!(log, "Calls are setup, will be submitted now");
        let reports = calls.await;
        info!(log, "Report: {:?}", reports)
    });
}

async fn make_dual_call<'a>(
    target_unican: Arc<UniversalCanister<'a>>,
    assist_unican: Arc<UniversalCanister<'a>>,
    call_ctx: PayloadType,
    size: usize,
    logger: Logger,
) -> PayloadType {
    match call_ctx {
        PayloadType::XNet(i) => {
            make_xnet_call(&target_unican, &assist_unican, size)
                .await
                .unwrap();
            info!(logger, "XNet call {:?} finished", i);
        }
        PayloadType::Ingress(i) => {
            make_ingress_call(&target_unican, size).await.unwrap();
            info!(logger, "Ingress call {:?} finished", i);
        }
    }

    call_ctx
}

fn setup_agents(
    topology_snapshot: TopologySnapshot,
) -> ((Agent, PrincipalId), (Agent, PrincipalId)) {
    let target_node_nns = topology_snapshot.root_subnet().nodes().next().unwrap();
    let assist_node_app = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    let assist_agent_app = assist_node_app.with_default_agent(|agent| async move { agent });
    let target_agent_nns = target_node_nns.with_default_agent(|agent| async move { agent });
    (
        (assist_agent_app, assist_node_app.effective_canister_id()),
        (target_agent_nns, target_node_nns.effective_canister_id()),
    )
}

async fn setup_unicans<'a>(
    logger: &Logger,
    assist_agent: &'a Agent,
    assist_effective_canister_id: PrincipalId,
    target_agent: &'a Agent,
    target_effective_canister_id: PrincipalId,
) -> (Arc<UniversalCanister<'a>>, Arc<UniversalCanister<'a>>) {
    // Install a `UniversalCanister` on each
    let (assist_unican, target_unican) = join!(
        UniversalCanister::new_with_retries(assist_agent, assist_effective_canister_id, logger),
        UniversalCanister::new_with_retries(target_agent, target_effective_canister_id, logger)
    );

    // NOTE: Since we will be making calls to these canisters in parallel, we have
    // to make it `Send`.
    let (assist_unican, target_unican) = (Arc::new(assist_unican), Arc::new(target_unican));

    // Grow the stable memory so it can actually store the amount of data
    join!(
        stable_grow(&assist_unican, 100),
        stable_grow(&target_unican, 100)
    );

    (assist_unican, target_unican)
}

/// Grow the canisters stable memory by the given number of pages
async fn stable_grow(unican: &UniversalCanister<'_>, num_pages: u32) {
    unican
        .update(wasm().stable_grow(num_pages).reply())
        .await
        .unwrap();
}

/// Makes an ingress call to the specified canister with a message of the
/// specified size.
async fn make_ingress_call(
    dst: &UniversalCanister<'_>,
    size: usize,
) -> Result<Vec<u8>, AgentError> {
    // NOTE: We use reply here before stable write, since we don't actually
    // care about the write, we just want to send a large message.
    dst.update(wasm().reply().stable_write(0, &vec![0; size]))
        .await
}

/// Makes a XNet call from the `src` canister to the `dst` canister with a
/// message of the specified size
async fn make_xnet_call(
    dst: &UniversalCanister<'_>,
    src: &UniversalCanister<'_>,
    size: usize,
) -> Result<Vec<u8>, AgentError> {
    src.update(
        wasm().inter_update(
            dst.canister_id(),
            call_args()
                // NOTE: We use reply here before stable write, since we don't actually
                // care about the write, we just want to send a large message.
                .other_side(wasm().reply().stable_write(0, &vec![0; size]))
                .on_reply(wasm().reply()),
        ),
    )
    .await
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}