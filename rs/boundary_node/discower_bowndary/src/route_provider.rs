use std::time::Instant;
use std::{fmt::Debug, sync::Arc, time::Duration};

use crate::messages::FetchedNodes;
use crate::snapshot::Snapshot;
use crate::{
    check::HealthCheck, fetch::NodesFetcher, fetch_actor::NodesFetchActor,
    health_manager_actor::HealthManagerActor, node::Node, types::GlobalShared,
};
use arc_swap::ArcSwap;
use ic_agent::{agent::http_transport::route_provider::RouteProvider, AgentError};
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, info, warn};
use url::Url;

const SERVICE_NAME: &str = "HealthCheckRouteProvider";
const HEALTHY_SEED_CHECK_INTERVAL: Duration = Duration::from_millis(10);
const HEALTHY_SEED_CHECK_TIMEOUT: Duration = Duration::from_millis(1000);

/// Main orchestrator.
#[derive(Debug)]
pub struct HealthCheckRouteProvider<S> {
    fetcher: Arc<dyn NodesFetcher>,
    fetch_period: Duration,
    checker: Arc<dyn HealthCheck>,
    check_period: Duration,
    snapshot: GlobalShared<S>,
    tracker: TaskTracker,
    token: CancellationToken,
    seeds: Vec<Node>,
}

impl<S> RouteProvider for HealthCheckRouteProvider<S>
where
    S: Snapshot + 'static,
{
    fn route(&self) -> Result<Url, AgentError> {
        let snapshot = self.snapshot.load();
        let node = snapshot.next().ok_or_else(|| {
            AgentError::RouteProviderError("No healthy API domains found for routing.".to_string())
        })?;
        Ok(node.to_routing_url())
    }
}

impl<S> HealthCheckRouteProvider<S>
where
    S: Snapshot + 'static,
{
    pub fn new(
        snapshot: S,
        fetcher: Arc<dyn NodesFetcher>,
        fetch_period: Duration,
        checker: Arc<dyn HealthCheck>,
        check_period: Duration,
        seeds: Vec<Node>,
    ) -> Self {
        Self {
            fetcher,
            fetch_period,
            checker,
            check_period,
            seeds,
            snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
        }
    }

    /// Starts two background tasks:
    /// - Task1: NodesFetchActor
    ///   - Periodically fetches existing API nodes (gets latest nodes topology) and sends discovered nodes to HealthManagerActor.
    /// - Task2: HealthManagerActor:
    ///   - Listens to the fetched nodes messages from the NodesFetchActor.
    ///   - Starts/stops health check tasks (HealthCheckActors) based on the newly added/removed nodes.
    ///   - These spawned health check tasks periodically update the snapshot with the latest node health info.
    pub async fn run(&self) {
        info!("{SERVICE_NAME}: start run() ");
        // Communication channel between fetcher and health_manager.
        let (fetch_sender, fetch_receiver) = watch::channel(None);

        // Start the receiving part first.
        let health_manager_actor = HealthManagerActor::new(
            Arc::clone(&self.checker),
            self.check_period,
            Arc::clone(&self.snapshot),
            fetch_receiver,
            self.token.clone(),
        );
        self.tracker
            .spawn(async move { health_manager_actor.run().await });

        // Dispatch all seed nodes for initial health checks
        if let Err(err) = fetch_sender.send(Some(FetchedNodes {
            nodes: self.seeds.clone(),
        })) {
            error!("{SERVICE_NAME}: failed to send results to HealthManager: {err:?}");
        }

        // Try to wait a tiny bit till snapshot is populated with at least one healthy seed.
        // This will reduce the errors on the client side, if route() is called immediately after run().
        self.try_await_first_healthy_seed().await;

        let fetch_actor = NodesFetchActor::new(
            Arc::clone(&self.fetcher),
            self.fetch_period,
            fetch_sender,
            Arc::clone(&self.snapshot),
            self.token.clone(),
        );
        self.tracker.spawn(async move { fetch_actor.run().await });

        info!("{SERVICE_NAME}: NodesFetchActor and HealthManagerActor started successfully");
    }

    // TODO: active polling is not optimal, it's better to await for notification.
    // However, since this phase lasts for only a short transitional period (HEALTHY_SEED_CHECK_TIMEOUT) this could be acceptable.
    async fn try_await_first_healthy_seed(&self) {
        let now = Instant::now();
        while now.elapsed() < HEALTHY_SEED_CHECK_TIMEOUT {
            if self.snapshot.load().has_healthy_nodes() {
                info!(
                    "{SERVICE_NAME}: healthy seed was found after {:?}",
                    now.elapsed()
                );
                return;
            }
            sleep(HEALTHY_SEED_CHECK_INTERVAL).await;
        }
        error!(
            "{SERVICE_NAME}: no healthy seeds found after {:?}",
            now.elapsed()
        );
    }

    // Kill all running tasks.
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
        warn!("{SERVICE_NAME}: gracefully stopped");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use super::*;
    use crate::check::HealthCheck;
    use crate::checker_mock::NodeHealthCheckerMock;
    use crate::fetch::NodesFetcher;
    use crate::fetcher_mock::NodesFetchMock;
    use crate::snapshot::IC0_SEED_DOMAIN;
    use crate::snapshot_health_based::HealthBasedSnapshot;
    use crate::test_helpers::{assert_routed_domains, route_n_times};

    static TRACING_INIT: Once = Once::new();

    pub fn setup_tracing() {
        TRACING_INIT.call_once(|| {
            FmtSubscriber::builder().with_max_level(Level::TRACE).init();
        });
    }

    #[tokio::test]
    async fn test_routing_with_topology_and_node_health_updates() {
        setup_tracing();
        // Arrange.
        // A single healthy node exists in the topology. This node happens to be the seed node.
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        ));
        route_provider.run().await;

        // This time span is required for the snapshot to be fully updated with the new nodes topology and health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // Only a single node exists, which is initially healthy.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into()], 3);

        // Test 2: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Two nodes are added to the topology.
        checker.modify_domains_health(vec![("api1.com", true), ("api2.com", true)]);
        fetcher.overwrite_existing_domains(vec!["ic0.app", "api1.com", "api2.com"]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec!["ic0.app".into(), "api1.com".into(), "api2.com".into()],
            2,
        );

        // Test 3:  multiple route() calls return 2 different domains with equal fairness (repetition).
        // One node is set to unhealthy.
        checker.modify_domains_health(vec![("api1.com", false)]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into(), "api2.com".into()], 3);

        // Test 4: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Unhealthy node is set back to healthy.
        checker.modify_domains_health(vec![("api1.com", true)]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec!["ic0.app".into(), "api1.com".into(), "api2.com".into()],
            2,
        );

        // Test 5: multiple route() calls return 3 different domains with equal fairness (repetition).
        // One healthy node is added, but another one goes unhealthy.
        checker.modify_domains_health(vec![("api3.com", true), ("ic0.app", false)]);
        fetcher.overwrite_existing_domains(vec!["ic0.app", "api1.com", "api2.com", "api3.com"]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec!["api3.com".into(), "api1.com".into(), "api2.com".into()],
            2,
        );

        // Test 6: multiple route() calls return a single domain=api1.com.
        // One node is set to unhealthy and one is removed from the topology.
        checker.modify_domains_health(vec![("api3.com", false)]);
        fetcher.overwrite_existing_domains(vec!["ic0.app", "api1.com", "api3.com"]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["api1.com".into()], 3);
        route_provider.stop().await;
    }

    #[tokio::test]
    async fn test_routing_with_no_healthy_nodes_returns_an_error() {
        setup_tracing();
        // Arrange.
        // A single seed node which is initially healthy.
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        ));
        route_provider.run().await;

        // Test 1: multiple route() calls return a single domain=ic0.app, as the seed is healthy.
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into()], 3);

        // Test 2: calls to route() return an error, as no healthy nodes exist.
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, false)]);
        for _ in 0..4 {
            tokio::time::sleep(check_interval).await;
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError(
                    "No healthy API domains found for routing.".to_string()
                )
            );
        }
        route_provider.stop().await;
    }

    #[tokio::test]
    async fn test_route_with_no_healthy_seeds_errors() {
        setup_tracing();
        // Arrange.
        let fetcher = Arc::new(NodesFetchMock::new());
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let checker = Arc::new(NodeHealthCheckerMock::new());
        // No healthy seed nodes present, this should lead to errors.
        checker.modify_domains_health(vec![]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        ));
        route_provider.run().await;

        // Test 1: calls to route() return an error, as no healthy seeds exist.
        for _ in 0..4 {
            tokio::time::sleep(check_interval).await;
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError(
                    "No healthy API domains found for routing.".to_string()
                )
            );
        }
        route_provider.stop().await;
    }

    #[tokio::test]
    async fn test_route_with_unhealthy_seeds_becoming_healthy() {
        setup_tracing();
        // Arrange.
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN, "api1.com"]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let checker = Arc::new(NodeHealthCheckerMock::new());
        // No healthy seeds present, this should lead to errors.
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, false), ("api1.com", false)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        ));
        route_provider.run().await;

        // Test 1: calls to route() return an error, as no healthy seeds exist.
        for _ in 0..4 {
            tokio::time::sleep(check_interval).await;
            let result = route_provider.route();
            assert_eq!(
                result.unwrap_err(),
                AgentError::RouteProviderError(
                    "No healthy API domains found for routing.".to_string()
                )
            );
        }

        // Test 2: calls to route() return both seeds, as they become healthy.
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true), ("api1.com", true)]);
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into(), "api1.com".into()], 3);

        route_provider.stop().await;
    }

    #[tokio::test]
    async fn test_route_with_one_healthy_and_one_unhealthy_seed() {
        setup_tracing();
        // Arrange.
        let fetcher = Arc::new(NodesFetchMock::new());
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN, "api1.com"]);
        let checker = Arc::new(NodeHealthCheckerMock::new());
        // One healthy seed is present, it should be discovered during the transient time.
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true), ("api1.com", false)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN), Node::new("api1.com")],
        ));
        route_provider.run().await;

        // Test 1: calls to route() return only a healthy seed ic0.app.
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into()], 3);

        // Test 2: calls to route() return two healthy seeds, as the unhealthy seed becomes healthy.
        checker.modify_domains_health(vec![("api1.com", true)]);
        tokio::time::sleep(2 * check_interval).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into(), "api1.com".into()], 3);

        route_provider.stop().await;
    }

    #[tokio::test]
    async fn test_routing_with_an_empty_fetched_list_of_api_nodes() {
        setup_tracing();
        // Arrange.
        // A single seed node, which is initially healthy.
        let fetcher = Arc::new(NodesFetchMock::new());
        // Check resiliency to an empty list of fetched API nodes (this should never happen in normal IC operation).
        fetcher.overwrite_existing_domains(vec![]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        ));
        route_provider.run().await;

        // This time span is required for the snapshot to be fully updated with the new nodes topology and health info.
        let snapshot_update_duration = fetch_interval + 2 * check_interval;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // HealthManager shouldn't update the snapshot, if the fetched nodes list is empty.
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into()], 3);

        // Test 2: multiple route() calls should now return 3 different domains with equal fairness (repetition).
        // Three nodes are added to the topology, i.e. now the fetched nodes list is non-empty.
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN, "api1.com", "api2.com"]);
        checker.modify_domains_health(vec![
            (IC0_SEED_DOMAIN, true),
            ("api1.com", true),
            ("api2.com", true),
        ]);
        tokio::time::sleep(snapshot_update_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec!["ic0.app".into(), "api1.com".into(), "api2.com".into()],
            2,
        );
        route_provider.stop().await;
    }
}
