/* tag::catalog[]
Title:: Consensus Liveness with Equivocating Blocks

Goal:: Demonstrate that the consensus can progress even in the presence of
equivocating blocks.

Runbook::
. Set up one subnets with 3f+1 nodes, f of which malicious.
. Install a universal canister in an honest node.
. Continuously push messages to the canister's stable memory
. Pull the last sent message and compare with the expectation.

Success:: Check the messages have really been written to memory
by pulling the last one from a different node.
The `ekg::finalized_height_progress_within` does not detect any stuck node. This is part of `ekg::basic_monitoring`, and
hence, checked by default.

Coverage::
. Consensus doesn't break in the presence of simple malicious behavior


end::catalog[] */

use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::UniversalCanister,
};
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use slog::{debug, info, Logger};

const MSG_LEN: usize = 8;
// Seed for a random generator
const RND_SEED: u64 = 42;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_propose_equivocating_blocks();
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(3)
                .add_malicious_nodes(1, malicious_behaviour),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    info!(log, "Checking readiness of all nodes after the IC setup...");
    topology.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(log, "All nodes are ready, IC setup succeeded.");
    let mut honest_nodes = topology.root_subnet().nodes().filter(|n| !n.is_malicious());
    let node_1 = honest_nodes.next().unwrap();
    let node_2 = honest_nodes.next().unwrap();
    info!(
        log,
        "Two selected honest nodes are: id={} and id={}", node_1.node_id, node_2.node_id
    );
    let agent_1 = node_1.with_default_agent(|agent| async move { agent });
    let agent_2 = node_2.with_default_agent(|agent| async move { agent });
    assert_ne!(node_1.node_id, node_2.node_id);
    let malicious_node = topology
        .root_subnet()
        .nodes()
        .find(|n| n.is_malicious())
        .expect("No malicious node found in the subnet.");
    info!(
        log,
        "Node with id={} is malicious with behavior={:?}",
        malicious_node.node_id,
        malicious_node.malicious_behavior().unwrap()
    );
    // The test in itself consists in installing the universal canister and
    // pushing a number of messages to stable memory. Finally, we read the
    // last pushed message and check it matches what we expect.
    //
    // We'll run for `n` rounds and expect the stable memory to be:
    //
    //  |   msg1  |    msg2    |     ....    |    msgN    |
    //  0        len         2*len      (n-1)*len        n*len
    //
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    let (last_pulled_msg, last_pushed_msg) = rt.block_on(do_the_work(
        &log,
        &mut rng,
        &agent_1,
        node_1.effective_canister_id(),
        &agent_2,
    ));
    assert_eq!(last_pulled_msg, last_pushed_msg);
}

async fn do_the_work<R: Rng>(
    logger: &Logger,
    rng: &mut R,
    agent_1: &Agent,
    n1_effective_canister_id: PrincipalId,
    agent_2: &Agent,
) -> (Vec<u8>, Vec<u8>) {
    debug!(logger, "Starting do_the_work");
    let (rs, last_pushed_msg, ucan) =
        push_messages_to(logger, rng, agent_1, n1_effective_canister_id).await;
    let last_pulled_msg = pull_message_from(logger, rs, agent_2, ucan).await;
    (last_pulled_msg, last_pushed_msg.to_vec())
}

async fn push_messages_to<R: Rng>(
    logger: &Logger,
    rng: &mut R,
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> (u32, [u8; MSG_LEN], Principal) {
    info!(logger, "Installing universal canister...");
    let can = UniversalCanister::new(agent, effective_canister_id).await;
    info!(
        logger,
        "Universal canister with id={} installed successfully",
        can.canister_id()
    );
    info!(logger, "Sending messages to stable storage...");
    let rounds: u32 = rng.gen_range(2..5);
    let mut msg: [u8; MSG_LEN] = [0; MSG_LEN];
    for i in 0..rounds {
        rng.fill_bytes(&mut msg);
        can.store_to_stable(i * (MSG_LEN as u32), &msg).await;
        let sleep_t = rng.gen_range(200..1200);
        tokio::time::sleep(std::time::Duration::from_millis(sleep_t)).await;
        debug!(logger, "push_message_to_stable";
                 "message" => format!("{:?}", msg),
                 "sleep" => sleep_t
        );
    }
    (rounds, msg, can.canister_id())
}

async fn pull_message_from(log: &Logger, rounds: u32, agent: &Agent, ucan: Principal) -> Vec<u8> {
    info!(log, "Reading from universal canister id={}", ucan);
    let can = UniversalCanister::from_canister_id(agent, ucan);
    let last_msg = can
        .try_read_stable((rounds - 1) * (MSG_LEN as u32), MSG_LEN as u32)
        .await;
    info!(log, "try_to_read_message_from_stable"; "message" => format!("{:?}", last_msg));
    last_msg
}
