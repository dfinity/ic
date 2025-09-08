use ic_agent::Agent;
/// Common test function for a couple of system tests;
use ic_agent::export::Principal;
use ic_base_types::PrincipalId;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::{UniversalCanister, assert_malicious_from_topo},
};
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use slog::{Logger, debug, info};

const MSG_LEN: usize = 8;
// Seed for a random generator
const RND_SEED: u64 = 42;

pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    info!(
        log,
        "Checking readiness of all honest nodes after the IC setup..."
    );
    for subnet in topology.subnets() {
        for node in subnet.nodes() {
            // Note that we don't check that malicious nodes are healthy, because it could happen
            // that malicious nodes crash themselves by, for example, adding invalid artifacts to
            // their own artifact pools and breaking some invariants resulting in a crash.
            // TODO(CON-1455): investigate if we can prevent malicious nodes from crashing.
            if !node.is_malicious() {
                node.await_status_is_healthy()
                    .expect("Honest node should become healthy eventually")
            }
        }
    }
    info!(log, "All honest nodes are ready, IC setup succeeded.");

    let mut honest_nodes = topology.root_subnet().nodes().filter(|n| !n.is_malicious());
    let node_1 = honest_nodes.next().unwrap();
    let node_2 = honest_nodes.next().unwrap();
    info!(
        log,
        "Two selected honest nodes are: id={} and id={}", node_1.node_id, node_2.node_id
    );
    let agent_1 = node_1.build_default_agent();
    let agent_2 = node_2.build_default_agent();
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

    info!(log, "Checking for malicious logs...");
    assert_malicious_from_topo(&topology, vec!["allow_malicious_behavior: true"]);
    info!(log, "Malicious log check succeeded.");
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
    let can = UniversalCanister::new_with_retries(agent, effective_canister_id, logger).await;
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
