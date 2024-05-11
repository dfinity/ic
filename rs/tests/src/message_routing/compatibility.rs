/* tag::catalog[]
Title:: XNet messaging backward/forward compatibility with current mainnet version.

Goal:: Ensure IC upgrade doesn't break XNet communication

Runbook::
0. Deploy 1 root and 2 app subnets and install NNS canisters onto root,
   all running mainnet version.
1. Bless current version.
2. Run XNet test between two app subnets (success criteria same as for SLO test).
3. Upgrade one app subnet to current version.
4. Run XNet test again.
5. Downgrade back to mainnet.
6. Run XNet test again.

Success::
1. XNet test successfully completes for all version combinations

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::{PotSetupFn, SysTestFn};
use crate::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasDependencies, HasIcDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot,
};
use crate::message_routing::xnet_slo_test;
use crate::orchestrator::utils::{
    rw_message::install_nns_and_check_progress,
    upgrade::{
        assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
        UpdateImageType,
    },
};
use crate::util::block_on;
use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};
use std::time::Duration;

const DKG_INTERVAL: u64 = 9;
const NODES_PER_SUBNET: usize = 1;

#[derive(Debug, Default, Clone)]
pub struct Config {
    with_prometheus: bool,
}

impl Config {
    pub fn with_prometheus(self) -> Self {
        Self {
            with_prometheus: true,
        }
    }

    /// Builds the IC instance.
    pub fn build(self) -> impl PotSetupFn {
        move |env: TestEnv| setup(env, self)
    }

    /// Returns a test function based on this configuration.
    pub fn test(self) -> impl SysTestFn {
        move |env: TestEnv| test(env)
    }
}

// Generic setup
fn setup(env: TestEnv, config: Config) {
    fn subnet(subnet_type: SubnetType, custom_dkg: Option<u64>) -> Subnet {
        let mut subnet = Subnet::new(subnet_type).add_nodes(NODES_PER_SUBNET);
        if let Some(dkg_interval) = custom_dkg {
            subnet = subnet.with_dkg_interval_length(ic_types::Height::from(dkg_interval));
        }
        subnet
    }
    if config.with_prometheus {
        PrometheusVm::default()
            .start(&env)
            .expect("failed to start prometheus VM");
    }
    let ic = InternetComputer::new().with_mainnet_config();
    ic.add_subnet(subnet(SubnetType::System, None))
        .add_subnet(subnet(SubnetType::Application, Some(DKG_INTERVAL)))
        .add_subnet(subnet(SubnetType::Application, Some(DKG_INTERVAL)))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    install_nns_and_check_progress(env.topology_snapshot());
    if config.with_prometheus {
        env.sync_with_prometheus();
    }
}

pub fn test(env: TestEnv) {
    block_on(test_async(env));
}

// Generic test
pub async fn test_async(env: TestEnv) {
    let logger = env.logger();

    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();

    let app_subnets: Vec<_> = env
        .topology_snapshot()
        .subnets()
        .filter(|s| s.subnet_id != env.topology_snapshot().root_subnet_id())
        .map(|s| (s.subnet_id, s.clone(), s.nodes().next().unwrap()))
        .collect();

    let xnet_test_config = xnet_slo_test::Config::new(2, 1, Duration::from_secs(30), 10);

    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .unwrap();

    let original_branch_version = env
        .read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")
        .expect("tip-of-branch IC version");

    let (upgrade_subnet_id, _, upgrade_node) = app_subnets.first().unwrap();
    let upgrade_version = format!("{}-test", original_branch_version);

    info!(&logger, "Blessing upgrade version.");

    let sha256 = env.get_ic_os_update_img_test_sha256().unwrap();
    let upgrade_url = env.get_ic_os_update_img_test_url().unwrap();
    bless_replica_version(
        &nns_node,
        &original_branch_version,
        UpdateImageType::ImageTest,
        &logger,
        &sha256,
        vec![upgrade_url.to_string()],
    )
    .await;

    info!(&logger, "Blessed all versions.");

    info!(&logger, "Starting XNet test between 2 app subnets.");

    xnet_slo_test::test_async_impl(
        env.clone(),
        app_subnets.clone().into_iter().map(|(_, _, node)| node),
        xnet_test_config.clone(),
        &logger,
    )
    .await;

    info!(&logger, "Upgrading 1 app subnet.");

    upgrade_to(
        &nns_node,
        *upgrade_subnet_id,
        upgrade_node,
        &upgrade_version,
        &logger,
    )
    .await;

    info!(&logger, "Starting XNet test between 2 app subnets.");

    xnet_slo_test::test_async_impl(
        env.clone(),
        app_subnets.clone().into_iter().map(|(_, _, node)| node),
        xnet_test_config.clone(),
        &logger,
    )
    .await;

    info!(&logger, "Downgrading app subnet back to initial version.");

    upgrade_to(
        &nns_node,
        *upgrade_subnet_id,
        upgrade_node,
        &mainnet_version,
        &logger,
    )
    .await;

    info!(&logger, "Starting XNet test between 2 app subnets.");

    xnet_slo_test::test_async_impl(
        env,
        app_subnets.clone().into_iter().map(|(_, _, node)| node),
        xnet_test_config,
        &logger,
    )
    .await;
}

async fn upgrade_to(
    nns_node: &IcNodeSnapshot,
    subnet_id: ic_types::SubnetId,
    subnet_node: &IcNodeSnapshot,
    target_version: &str,
    logger: &Logger,
) {
    deploy_guestos_to_all_subnet_nodes(
        nns_node,
        &ic_types::ReplicaVersion::try_from(target_version).unwrap(),
        subnet_id,
    )
    .await;
    assert_assigned_replica_version(subnet_node, target_version, logger.clone());
}
