/* tag::catalog[]
Goal:: Token balance is update correctly despite node failure

Runbook::
. Setup IC with NNS and app subnet with four nodes each
. Install 2 universal canisters on app subnet
. Top them up with ICP
. Kill one node
. Transfer ICP from one canister to the other
. Kill another node
. Restart the first node
. Transfer ICP from one canister to the other

Success:: balances obtained by queries matches expected balances after transfers

end::catalog[] */
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, NnsInstallationBuilder,
};
use ic_system_test_driver::util;

use canister_test::Canister;
use ic_nns_constants::{LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_types::CanisterId;
use icp_ledger::DEFAULT_TRANSFER_FEE;
use slog::{info, Logger};
use std::convert::TryFrom;
use std::time::Duration;

const MAX_NUMBER_OF_RETRIES: usize = 5;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System).add_nodes(3))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let nns_nodes: Vec<_> = env.topology_snapshot().root_subnet().nodes().collect();
    let nns_node = nns_nodes.first().unwrap();
    let app_node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    info!(log, "Creating nns agent ...");
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    info!(log, "Creating app agent ...");
    let app_agent = app_node.with_default_agent(|agent| async move { agent });
    info!(log, "Installing NNS canisters...");
    NnsInstallationBuilder::new()
        .install(nns_node, &env)
        .expect("Could not install NNS canisters");
    let nns_runtime =
        util::runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let ledger = Canister::new(&nns_runtime, LEDGER_CANISTER_ID);
    info!(log, "Upgrading lifeline canister...");
    let lifeline = util::block_on(util::UniversalCanister::upgrade(
        &nns_runtime,
        &nns_agent,
        &LIFELINE_CANISTER_ID,
    ));
    info!(log, "Upgraded successfully");
    info!(log, "Creating two universal canisters...");
    let can1 = util::block_on(util::UniversalCanister::new(
        &app_agent,
        app_node.effective_canister_id(),
    ));
    let can2 = util::block_on(util::UniversalCanister::new(
        &app_agent,
        app_node.effective_canister_id(),
    ));
    info!(
        log,
        "Topping up canisters with amounts of ICP needed for subsequent operations to succeed.."
    );
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let fee = DEFAULT_TRANSFER_FEE.get_e8s();
    transfer(
        &log,
        &rt,
        &ledger.clone(),
        &lifeline,
        &can1.clone(),
        1000 + 2 * fee,
    );
    transfer(
        &log,
        &rt,
        &ledger.clone(),
        &lifeline,
        &can2.clone(),
        1000 + 2 * fee,
    );
    info!(log, "Topped up");

    // Kill one NNS node. Three out of four nodes are still operational which is
    // enough for the subnet to make progress and thus complete the transfer
    // successfully.
    info!(&log, "Killing nns node and transferring ICP...");
    nns_nodes[1].vm().kill();
    transfer(
        &log,
        &rt,
        &ledger.clone(),
        &can1.clone(),
        &can2.clone(),
        100,
    );

    // Kill another NNS node. With two malfunctioned nodes, the network is stuck,
    // i.e. all update requests will be rejected.
    info!(log, "Killing and restarting nns nodes...");
    nns_nodes[2].vm().kill();
    // Restart the node killed first.
    nns_nodes[1].vm().start();

    // A transfer request can be started right away, even though the rejoined node
    // is likely not yet ready. Its completion will be delayed until the rejoined node is up.
    //
    // Note: the moment when a node starts accepting requests is succeeded by a short period of time
    // when the node is not full operational, e.g. a WASM module is not yet installed.
    // Thus, a transfer may not be successful at first attempt.
    info!(&log, "Initiating transfer...");
    for i in 0..MAX_NUMBER_OF_RETRIES {
        if transfer(
            &log,
            &rt,
            &ledger.clone(),
            &can2.clone(),
            &can1.clone(),
            100,
        ) {
            return;
        }
        info!(
            log,
            "Transfer attempt {} failed, {} attempts left", i, MAX_NUMBER_OF_RETRIES
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!("Failed to make a transfer after rejoining a node.")
}

/// Transfers `amount` of ICP between two given canisters and verifies that the
/// balance of the target canister is `amount` more than before the request.
/// Crashes if the update request doesn't succeed or the balance is not as
/// expected afterwards.
fn transfer(
    log: &Logger,
    rt: &tokio::runtime::Runtime,
    ledger: &Canister,
    from: &util::UniversalCanister,
    to: &util::UniversalCanister,
    amount: u64,
) -> bool {
    rt.block_on(async move {
        let new_balance = util::transact_icp(log, ledger, from, amount, to).await;
        match new_balance {
            Ok(nb) => {
                let balance = util::get_icp_balance(
                    ledger,
                    &CanisterId::try_from(to.canister_id().as_slice()).unwrap(),
                    None,
                )
                .await
                .expect("cannot get balance");
                assert_eq!(nb, balance);
            }
            Err(e) => {
                info!(log, "transfer failed: {}", e);
                return false;
            }
        }
        true
    })
}
