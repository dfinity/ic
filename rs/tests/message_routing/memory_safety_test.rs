/* tag::catalog[]
Title:: Memory Safety Test

Goal:: Memory never corrupts canister state. The objective is to have
canisters that randomly access all of their available persisted memory, over
multiple rounds, to ensure that no pattern of changes can result in corrupted
state.

Runbook::
. Deploy a subnet with 4 replicas and install a test canister with largish state
. Exercise this canister with a combination of updates, queries, ingress queries
and traps
. Cycle through all replicas suspending a single replica for x minutes forcing
it to fall behind triggering state_sync from remaining replicas

Success:: State hashes computed by all nodes at a given height agree and
CUP height keeps on advancing

end::catalog[] */

use anyhow::Result;
use candid::{Decode, Encode};
use ic_agent::Agent;
use ic_agent::export::Principal;
use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer},
    },
    util::*,
};
use ic_types::Height;
use ic_utils::interfaces::ManagementCanister;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use slog::info;

const MEMORY_SAFETY_CANISTER: &[u8] = include_bytes!("./memory_safety.wasm");
const MAX_MEM_SIZE: u128 = 128 * 1024;
const TEST_MEM_SIZE: u128 = 64 * 1024;
const MAX_NODES: usize = 4;
// Seed for a random generator
const RND_SEED: u64 = 42;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(20))
                .add_nodes(MAX_NODES),
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
    let node = topology.root_subnet().nodes().next().unwrap();
    let agent = node.with_default_agent(|agent| async move { agent });
    let canister_id =
        block_on(async move { install_canister(&agent, node.effective_canister_id()).await });
    let mut should_match = 0;
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    for (i, node) in topology.root_subnet().nodes().enumerate() {
        let agent = node.with_default_agent(|agent| async move { agent });
        should_match = block_on(async {
            verify(&canister_id, &agent, should_match).await;
            modify_mem_and_verify(&mut rng, &canister_id, &agent, i as u8).await
        });
        info!(log, "restarting the node with id={}", node.node_id);
        node.vm().reboot();
        // Wait until the re-started node becomes ready.
        info!(log, "waiting for the node to be become ready...");
        node.await_status_is_healthy().unwrap();
        info!(log, "node with id={} is ready", node.node_id);
    }
}

async fn install_canister(agent: &Agent, effective_canister_id: PrincipalId) -> Principal {
    // Create a canister.
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap()
        .0;

    // Install the memory safety canister.
    mgr.install_code(&canister_id, MEMORY_SAFETY_CANISTER)
        .call_and_wait()
        .await
        .expect("Couldn't install?");

    let arg = Encode!(&MAX_MEM_SIZE).unwrap();
    agent
        .update(&canister_id, "init_array")
        .with_arg(arg)
        .call_and_wait()
        .await
        .expect("could not push message to stable");

    canister_id
}

async fn verify(canister_id: &Principal, agent: &Agent, should_match: u128) {
    let mut curr: u128 = 0;
    for _ in 0..3 {
        let arg = Encode!().unwrap();
        let rs = agent
            .query(canister_id, "compute_sum")
            .with_arg(arg)
            .call()
            .await;
        curr = Decode!(rs.unwrap().as_slice(), u128).unwrap();

        if should_match != curr {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
    }

    assert_eq!(should_match, curr);
}

async fn modify_mem_and_verify<R: Rng>(
    rng: &mut R,
    canister_id: &Principal,
    agent: &Agent,
    val_to_write: u8,
) -> u128 {
    let rounds: u32 = rng.gen_range(1..8);
    let mut should_match = 0;
    for i in 0..rounds {
        let new_val_to_write = i + val_to_write as u32;
        should_match = new_val_to_write as u128 * TEST_MEM_SIZE;
        let arg = Encode!(&(val_to_write + i as u8), &TEST_MEM_SIZE).unwrap();
        let rs = agent
            .update(canister_id, "query_and_update")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("could not push message to stable");
        let wrote = Decode!(rs.as_slice(), u128).unwrap();
        assert_eq!(wrote, TEST_MEM_SIZE);

        verify(canister_id, agent, should_match).await;
    }

    should_match
}
