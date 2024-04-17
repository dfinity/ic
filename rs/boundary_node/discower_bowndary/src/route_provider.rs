use std::{fmt::Debug, sync::Arc, time::Duration};

use crate::{
    check::{HealthCheck, NodeHealthCheckerMock},
    fetch::{NodesFetchMock, NodesFetcher},
    fetch_actor::NodesFetchActor,
    health_manager_actor::HealthManagerActor,
    snapshot::{Snapshot, SEED_DOMAIN},
    types::GlobalShared,
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
    ) -> Self {
        Self {
            fetcher,
            fetch_period,
            checker,
            check_period,
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot::new())),
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

impl Default for HealthCheckRouteProvider {
    // TODO: remove these mocks in the future
    fn default() -> Self {
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![SEED_DOMAIN]);
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(SEED_DOMAIN, true)]);
        Self {
            fetcher: Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_period: Duration::from_secs(5),
            checker: Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_period: Duration::from_secs(1),
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot::new())),
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::hash::Hash;

    use super::*;
    use crate::check::{HealthCheck, NodeHealthCheckerMock};
    use crate::fetch::{NodesFetchMock, NodesFetcher};
    use crate::snapshot::SEED_DOMAIN;

    fn route_n_times(n: usize, f: Arc<HealthCheckRouteProvider>) -> Vec<String> {
        (0..n)
            .map(|_| f.route().unwrap().domain().unwrap().to_string())
            .collect()
    }

    fn assert_routed_domains<T>(actual: Vec<T>, expected: Vec<T>, expected_repetitions: usize)
    where
        T: AsRef<str> + Eq + Hash + Debug + Ord,
    {
        fn build_count_map<T>(items: &[T]) -> HashMap<&T, usize>
        where
            T: Eq + Hash,
        {
            items.iter().fold(HashMap::new(), |mut map, item| {
                *map.entry(item).or_insert(0) += 1;
                map
            })
        }
        let count_actual = build_count_map(&actual);
        let count_expected = build_count_map(&expected);

        let mut keys_actual = count_actual.keys().collect::<Vec<_>>();
        keys_actual.sort();
        let mut keys_expected = count_expected.keys().collect::<Vec<_>>();
        keys_expected.sort();
        // Assert all routed domains are present.
        assert_eq!(keys_actual, keys_expected);

        // Assert the expected repetition count of each routed domain.
        let actual_repetitions = count_actual.values().collect::<Vec<_>>();
        assert!(actual_repetitions
            .iter()
            .all(|&x| x == &expected_repetitions));
    }

    #[tokio::test]
    async fn test_routing_with_topology_and_node_health_updates() {
        // Arrange.
        // A single healthy node exists in the topology. This node happens to be the seed node.
        let fetcher = Arc::new(NodesFetchMock::new());
        fetcher.overwrite_existing_domains(vec![SEED_DOMAIN]);
        let fetch_interval = Duration::from_secs(3); // periodicity of checking current topology
        let fetch_delta = Duration::from_secs(1);
        let checker = Arc::new(NodeHealthCheckerMock::new());
        checker.modify_domains_health(vec![(SEED_DOMAIN, true)]);
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
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
