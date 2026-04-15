// Interactive testnet: NNS on Farm, one bare-metal machine (via IPMI like `sev_recovery.rs`)
// that joins the registry, then a CreateSubnet proposal places that node alone on a new
// Application subnet.
//
// The host may be AMD SEV-SNP-capable or not. When `TRUSTED_EXECUTION_ENVIRONMENT` is set in the
// environment (any value), SetupOS is built with the trusted execution path enabled, as in
// `nested::setup`. Omit it for bare metal without SEV-SNP.
//
// Prerequisites:
//   - `BARE_METAL_HOST_SECRETS` must name an INI file with bare-metal login info
//     (same as `//rs/tests/nested:sev_recovery`). Without it, setup fails.
//
// Setup example (pass `--test_env` so the driver sees it):
//
//   $ ./ci/container/container-run.sh
//   $ ict testnet create baremetal_app_subnet --verbose --output-dir=./test_tmpdir -- \
//       --test_tmpdir=./test_tmpdir \
//       --test_env BARE_METAL_HOST_SECRETS="$(realpath /path/to/host.ini)" \
//       --test_env TRUSTED_EXECUTION_ENVIRONMENT=true   # false for non-SEV
//
// The bare-metal guest IPv6 appears in the driver log after registration; SSH uses the
// same admin key layout as other testnets under `test_tmpdir`.

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::nested::NestedNodes;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::nns::{
    CanisterCyclesCostSchedule, get_governance_canister, get_software_version_from_snapshot,
    submit_create_application_subnet_proposal, vote_and_execute_proposal,
};
use ic_system_test_driver::util::{block_on, runtime_from_url};
use nested::{
    create_bare_metal_node, create_bare_metal_session, registration, util::setup_ic_infrastructure,
};
use nns_dapp::set_authorized_subnets;
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(std::time::Duration::MAX)
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    let logger = env.logger();

    if std::env::var_os("BARE_METAL_HOST_SECRETS").is_none() {
        panic!(
            "BARE_METAL_HOST_SECRETS is not set (path to bare-metal host INI).\n\
             Export it, e.g. export BARE_METAL_HOST_SECRETS=\"$(realpath host.ini)\",\n\
             or pass --test_env=BARE_METAL_HOST_SECRETS=\"$(realpath host.ini)\" to ict/bazel."
        );
    }

    setup_ic_infrastructure(&env, /* dkg_interval */ None, /* is_fast */ true);

    let enable_tee = std::env::var_os("TRUSTED_EXECUTION_ENVIRONMENT").is_some();
    info!(
        logger,
        "Bare-metal nested node: trusted_execution_environment (SEV-SNP path) = {}", enable_tee
    );

    let bare_metal = create_bare_metal_session(&env);
    let mut nodes = NestedNodes {
        nodes: vec![create_bare_metal_node(&bare_metal, enable_tee)],
    };
    nodes
        .setup_and_start(&env)
        .expect("failed to start bare-metal nested node");

    registration(env.clone());

    let topology_before = env.topology_snapshot();
    let unassigned: Vec<_> = topology_before
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect();
    assert_eq!(
        unassigned.len(),
        1,
        "expected exactly one unassigned node (the bare-metal guest)"
    );
    let bare_metal_node_id = unassigned[0];

    let nns_node = topology_before
        .root_subnet()
        .nodes()
        .next()
        .expect("NNS subnet must have a node");
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns);

    let version = block_on(get_software_version_from_snapshot(&nns_node))
        .expect("replica version for create-subnet proposal");

    info!(
        logger,
        "Creating Application subnet with single bare-metal node {}", bare_metal_node_id
    );
    let proposal_id = block_on(submit_create_application_subnet_proposal(
        &governance,
        vec![bare_metal_node_id],
        version,
        Some(CanisterCyclesCostSchedule::Normal),
        Some(0),
    ));
    block_on(vote_and_execute_proposal(&governance, proposal_id));

    let topology_after = block_on(topology_before.block_for_newer_registry_version())
        .expect("registry did not update after CreateSubnet");

    let app_subnets: Vec<_> = topology_after
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect();
    assert_eq!(
        app_subnets.len(),
        1,
        "expected exactly one application subnet"
    );
    let app_nodes: Vec<_> = app_subnets[0].nodes().collect();
    assert_eq!(app_nodes.len(), 1, "application subnet must be single-node");
    assert_eq!(
        app_nodes[0].node_id, bare_metal_node_id,
        "application subnet node must be the bare-metal node"
    );
    assert_eq!(
        topology_after.unassigned_nodes().count(),
        0,
        "no unassigned nodes after subnet creation"
    );

    // Same as `io_perf_benchmark`: authorize application subnets for cycles / toolchains
    // (e.g. subnet-load-tester) that assume an authorized app subnet list on the NNS.
    set_authorized_subnets(&env);

    info!(
        logger,
        "Bare-metal application subnet is ready (subnet_id = {}, node_id = {}, tee = {})",
        app_subnets[0].subnet_id,
        bare_metal_node_id,
        enable_tee
    );
}
