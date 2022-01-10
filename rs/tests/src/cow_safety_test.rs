/* tag::catalog[]
Title:: COW Safety Test

Goal:: COW memory never corrupts canister state. The objective is to have
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

use ic_agent::Agent;
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcManager,
};
use slog::{info, Logger};

use ic_agent::export::Principal;
use ic_types::Height;
use rand::Rng;

use crate::util::*;
use candid::{Decode, Encode};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;

const COW_SAFETY_CANISTER: &[u8] = include_bytes!("cow_safety.wasm");
const MAX_MEM_SIZE: u128 = 128 * 1024;
const TEST_MEM_SIZE: u128 = 64 * 1024;
const MAX_NODES: usize = 4;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(20))
                .add_nodes(MAX_NODES),
        )
}

/// Here we define the test workflow. This particular test does change
/// the environment, hence, it receives a `pot::MutContext`.
pub fn test(mut man: IcManager, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(do_the_work(&ctx.logger, &mut man, ctx));
}

async fn do_the_work(logger: &Logger, mgr: &mut IcManager, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let mut handle = mgr.handle();

    let node = handle
        .as_permutation(&mut rng)
        .find(|ep| !ep.is_root_subnet)
        .unwrap();
    node.assert_ready(ctx).await;

    let agent = assert_create_agent(node.url.as_str()).await;
    let canister_id = install_canister(&agent).await;

    let mut should_match = 0;
    for i in 0..MAX_NODES {
        let mut node = handle.public_api_endpoints.pop().unwrap();

        assert!(!node.is_root_subnet);
        let agent = assert_create_agent(node.url.as_str()).await;

        verify(&canister_id, &agent, should_match).await;

        should_match = modify_mem_and_verify(&mut rng, &canister_id, &agent, i as u8).await;

        info!(logger, "restarting node {:?}", node.runtime_descriptor);

        mgr.restart_node(&mut node);

        // Wait until the re-started node becomes ready.
        node.assert_ready(ctx).await;
    }
}

async fn install_canister(agent: &Agent) -> Principal {
    // Create a canister.
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .call_and_wait(delay())
        .await
        .unwrap()
        .0;

    // Install the cow safety canister.
    mgr.install_code(&canister_id, COW_SAFETY_CANISTER)
        .call_and_wait(delay())
        .await
        .expect("Couldn't install?");

    agent
        .update(&canister_id, "init_array")
        .with_arg(&Encode!(&MAX_MEM_SIZE).unwrap())
        .call_and_wait(delay())
        .await
        .expect("could not push message to stable");

    canister_id
}

async fn verify(canister_id: &Principal, agent: &Agent, should_match: u128) {
    let mut curr: u128 = 0;
    for _ in 0..3 {
        let rs = agent
            .query(canister_id, "compute_sum")
            .with_arg(&Encode!().unwrap())
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
        let rs = agent
            .update(canister_id, "query_and_update")
            .with_arg(&Encode!(&(val_to_write + i as u8), &TEST_MEM_SIZE).unwrap())
            .call_and_wait(delay())
            .await
            .expect("could not push message to stable");
        let wrote = Decode!(rs.as_slice(), u128).unwrap();
        assert_eq!(wrote, TEST_MEM_SIZE);

        verify(canister_id, agent, should_match).await;
    }

    should_match
}
