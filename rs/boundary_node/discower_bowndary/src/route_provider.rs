use std::{fmt::Debug, sync::Arc, time::Duration};

use crate::{
    check::HealthCheck, fetch::NodesFetcher, fetch_actor::NodesFetchActor,
    health_manager_actor::HealthManagerActor, snapshot::Snapshot, types::GlobalShared,
};
use arc_swap::ArcSwap;
use ic_agent::{agent::http_transport::route_provider::RouteProvider, AgentError};
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use url::Url;

/// Main orchestrator.
#[derive(Debug)]
pub struct HealthCheckRouteProvider {
    fetcher: Arc<dyn NodesFetcher>,
    fetch_period: Duration,
    checker: Arc<dyn HealthCheck>,
    check_period: Duration,
    snapshot: GlobalShared<Snapshot>,
    tracker: TaskTracker,
    token: CancellationToken,
}

impl RouteProvider for HealthCheckRouteProvider {
    fn route(&self) -> Result<Url, AgentError> {
        let snapshot = self.snapshot.load();
        let node = snapshot.next().expect("failed to get a node");
        Ok(node.into())
    }
}

impl HealthCheckRouteProvider {
    pub fn new(
        fetcher: Arc<dyn NodesFetcher>,
        fetch_period: Duration,
        checker: Arc<dyn HealthCheck>,
        check_period: Duration,
        seed_domains: Vec<&str>,
    ) -> Self {
        Self {
            fetcher,
            fetch_period,
            checker,
            check_period,
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot::new(seed_domains))),
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
        }
    }

    /// Starts three background tasks:
    /// - task1: NodesFetchActor, which periodically fetches existing nodes (gets latest nodes topology) and sends all nodes to HealthManagerActor.
    /// - task2: HealthManagerActor:
    ///   - Listens to the fetched nodes messages from the NodesFetchActor
    ///   - TODO: infers the newly added and removed nodes
    ///   - Spawns health check tasks for every node received. These spawned HealthCheckActors periodically update the snapshot with the latest health info.
    pub async fn run(&self) {
        // Communication channel between fetcher and health_manager.
        let (fetch_sender, fetch_receiver) = watch::channel(None);

        let fetch_actor = NodesFetchActor::new(
            Arc::clone(&self.fetcher),
            self.fetch_period,
            fetch_sender,
            Arc::clone(&self.snapshot),
            self.token.clone(),
        );
        self.tracker.spawn(async move { fetch_actor.run().await });

        let health_manager_actor = HealthManagerActor::new(
            Arc::clone(&self.checker),
            self.check_period,
            Arc::clone(&self.snapshot),
            fetch_receiver,
            self.token.clone(),
        );
        self.tracker
            .spawn(async move { health_manager_actor.run().await });
        println!("HealthCheckRouteProvider: all actors spawned successfully");
    }

    // Kill all running tasks.
    pub async fn stop(&self) {
        println!("HealthCheckRouteProvider stop() was called");
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::HealthCheck;
    use crate::checker_mock::NodeHealthCheckerMock;
    use crate::fetch::NodesFetcher;
    use crate::fetcher_mock::NodesFetchMock;
    use crate::snapshot::IC0_SEED_DOMAIN;
    use crate::test_helpers::{assert_routed_domains, route_n_times};

    #[tokio::test]
    async fn test_routing_with_topology_and_node_health_updates() {
        // Arrange.
        // A single healthy node exists in the topology. This node happens to be the seed node.
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![IC0_SEED_DOMAIN]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let fetch_delta = Duration::from_secs(1);
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(IC0_SEED_DOMAIN, true)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![IC0_SEED_DOMAIN],
        ));
        route_provider.run().await;

        // Test 1: multiple route() calls return a single domain=ic0.app.
        // Only a single node exists, which is initially healthy.
        let fetch_await_duration = fetch_interval + fetch_delta; // wait this time for the fetcher to propagate topology changes.
        tokio::time::sleep(fetch_await_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into()], 3);

        // Test 2: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Two nodes are added to the topology.
        checker.modify_domains_health(vec![("api1.com", true), ("api2.com", true)]);
        fetcher.overwrite_existing_domains(vec!["ic0.app", "api1.com", "api2.com"]);
        tokio::time::sleep(fetch_await_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(
            routed_domains,
            vec!["ic0.app".into(), "api1.com".into(), "api2.com".into()],
            2,
        );

        // Test 3:  multiple route() calls return 2 different domains with equal fairness (repetition).
        // One node is set to unhealthy.
        checker.modify_domains_health(vec![("api1.com", false)]);
        tokio::time::sleep(fetch_await_duration).await;
        let routed_domains = route_n_times(6, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["ic0.app".into(), "api2.com".into()], 3);

        // Test 4: multiple route() calls return 3 different domains with equal fairness (repetition).
        // Unhealthy node is set back to healthy.
        checker.modify_domains_health(vec![("api1.com", true)]);
        tokio::time::sleep(fetch_await_duration).await;
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
        tokio::time::sleep(fetch_await_duration).await;
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
        tokio::time::sleep(fetch_await_duration).await;
        let routed_domains = route_n_times(3, Arc::clone(&route_provider));
        assert_routed_domains(routed_domains, vec!["api1.com".into()], 3);
    }
}
