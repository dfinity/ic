/* tag::catalog[]
Title:: Subnet makes progress despite one third of the nodes being stressed.

Runbook::
0. Instantiate an IC with one System subnet larger than the current production NNS.
1. Install NNS canisters on the System subnet.
2. Build and install canister that stores msgs.
3. Let subnet run idle for a few minutes and confirm that it is up and running by storing message.
4. Stop f nodes and confirm subnet still is available.
5. Stop f+1 nodes and confirm that subnet is not making progress.
6. Restart one node such that we have f faulty nodes again and confirm subnet is available again.
7. Let subnet run idle with f faulty nodes and confirm that everything works.

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{AmountOfMemoryKiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    systest,
    util::{MessageCanister, assert_create_agent, block_on},
};
use ic_types::Height;
use slog::info;
use std::time::Duration;

// Timeout parameters
const TASK_TIMEOUT: Duration = Duration::from_secs(320 * 60);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(350 * 60);
const UPDATE_MSG_1: &str = "This beautiful prose should be persisted for future generations";
const UPDATE_MSG_2: &str = "I just woke up";
const UPDATE_MSG_3: &str = "And this beautiful prose should be persisted for future generations";
const UPDATE_MSG_4: &str = "However this prose will NOT be persisted for future generations";
const UPDATE_MSG_5: &str = "This will be persisted again!";
const UPDATE_MSG_6: &str = "Fell asleep again!";

const FAULTY: usize = 16;
const NODES: usize = 3 * FAULTY + 1; // 49

const IDLE_DURATION: Duration = Duration::from_secs(10 * 60);

pub fn setup(env: TestEnv) {
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(8)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(4195000)), // 4GiB
        boot_image_minimal_size_gibibytes: None,
    };
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                // Use low DKG interval to confirm system works across interval boundaries.
                .with_dkg_interval_length(Height::from(99))
                .add_nodes(NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .with_dkg_interval_length(Height::from(49))
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(
        &log,
        "Step 0: Checking readiness of all nodes after the IC setup ..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");

    info!(
        &log,
        "Step 1: Installing NNS canisters on the System subnet ..."
    );
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");

    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet. ..."
    );
    let subnet = env.topology_snapshot().subnets().next().unwrap();
    let node = subnet.nodes().last().unwrap();
    let agent = block_on(assert_create_agent(node.get_public_url().as_str()));
    let message_canister = block_on(MessageCanister::new(&agent, node.effective_canister_id()));
    info!(&log, "Installation of counter canisters has succeeded.");

    info!(
        log,
        "Step 3: Assert that update call to the canister succeeds"
    );
    block_on(message_canister.try_store_msg(UPDATE_MSG_1)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_1.to_string()))
    );

    info!(log, "Step 4: Run idle for a few min");
    block_on(async { tokio::time::sleep(IDLE_DURATION).await });
    block_on(message_canister.try_store_msg(UPDATE_MSG_2)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_2.to_string()))
    );

    info!(log, "Step 5: Kill {} nodes", FAULTY);
    let nodes: Vec<_> = subnet.nodes().collect();
    for node in nodes.iter().take(FAULTY) {
        node.vm().kill();
    }
    for node in nodes.iter().take(FAULTY) {
        node.await_status_is_unavailable()
            .expect("Node still healthy");
    }

    info!(
        log,
        "Step 6: Assert that update call succeeds in presence of {} faulty nodes", FAULTY
    );
    block_on(message_canister.try_store_msg(UPDATE_MSG_3)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_3.to_string()))
    );

    info!(
        log,
        "Step 7: Kill an additonal node causing consensus to stop due to {} (f+1) faulty nodes",
        FAULTY + 1
    );
    nodes[FAULTY].vm().kill();
    nodes[FAULTY]
        .await_status_is_unavailable()
        .expect("Node still healthy");

    // Verify that it is not possible to write message
    if let Ok(Ok(result)) = block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            message_canister.try_store_msg(UPDATE_MSG_4),
        )
        .await
    }) {
        panic!("expected the update to fail, got {result:?}");
    };

    info!(log, "Step 8: Restart one node again",);
    nodes[FAULTY].vm().start();
    for n in nodes.iter().skip(FAULTY) {
        n.await_status_is_healthy().unwrap();
    }
    ic_consensus_system_test_utils::assert_node_is_making_progress(
        &nodes[FAULTY],
        &log,
        Height::new(1),
    );

    info!(log, "Storing message '{}' ...", UPDATE_MSG_5);
    block_on(message_canister.try_store_msg(UPDATE_MSG_5)).expect("Update canister call failed.");
    info!(log, "Reading message '{}' ...", UPDATE_MSG_5);
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_5.to_string()))
    );

    info!(
        log,
        "Step 9: Run idle for a few min on faulty node boundary"
    );
    block_on(async { tokio::time::sleep(IDLE_DURATION).await });
    block_on(message_canister.try_store_msg(UPDATE_MSG_6)).expect("Update canister call failed.");
    assert_eq!(
        block_on(message_canister.try_read_msg()),
        Ok(Some(UPDATE_MSG_6.to_string()))
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(TASK_TIMEOUT) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(OVERALL_TIMEOUT) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
