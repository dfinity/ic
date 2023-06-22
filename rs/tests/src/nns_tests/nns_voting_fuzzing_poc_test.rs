use slog::{info, Logger};

use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use crate::util::{block_on, runtime_from_url};

use crate::driver::ic::InternetComputer;
use ic_nns_governance::pb::v1::{GovernanceError, NeuronInfo};

use canister_test::Canister;
use dfn_candid::candid_one;

use ic_nns_common::types::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::governance_error::ErrorType;
use ic_registry_subnet_type::SubnetType;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

/// A test runs within a given IC configuration.
pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

/// This is a simple example (proof of concept) of how the Proptest framework
/// can be employed to fuzz test a canister API method.
///
/// What is tested here is not very interesting. The intention is that this can
/// serve as a basis to write more interesting fuzz tests for canisters using
/// the Proptest framework in the future.
///
/// Note that `TestRunner::run` cannot be used since that does not work for
/// `async` methods. Also, the `proptest!` macro cannot be used in this context
/// because it is intended for unit tests (i.e. with `#[test]` annotation)
pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    info!(log, "Installing NNS canisters on the root subnet...");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(log, "NNS canisters installed successfully.");
    block_on(async move {
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

        let mut runner = TestRunner::default();
        for _ in 0..256 {
            let neuron_id = Box::new((0..u64::MAX).new_tree(&mut runner).unwrap());
            assert!(
                get_neuron_returns_not_found_error(&governance, &log, neuron_id.current()).await
            );
            // If the assertion fails, it would be possible to apply 'shrinking'
            // to find the 'simplest' input that causes a failure. We could do
            // this at a later point.
            // See https://altsysrq.github.io/proptest-book/proptest/tutorial/shrinking-basics.html.
        }
    });
}

async fn get_neuron_returns_not_found_error(
    governance: &Canister<'_>,
    log: &Logger,
    neuron_id: u64,
) -> bool {
    info!(log, "getting neuron info for neuron id {:?}", neuron_id);
    let result = governance
        .query_(
            "get_neuron_info",
            candid_one::<Result<NeuronInfo, GovernanceError>, NeuronId>,
            NeuronId(neuron_id),
        )
        .await;
    result.unwrap()
        == Err(GovernanceError {
            error_type: ErrorType::NotFound as i32,
            error_message: "".to_string(),
        })
}
