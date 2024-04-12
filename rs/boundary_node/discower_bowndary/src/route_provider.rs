use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use ic_agent::{agent::http_transport::route_provider::RouteProvider, AgentError};
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use url::Url;

use crate::{
    check::{HealthCheck, NodeHealthCheckerMock},
    fetch::{NodesFetchMock, NodesFetcher},
    fetch_actor::NodesFetchActor,
    health_manager_actor::HealthManagerActor,
    snapshot::Snapshot,
    types::GlobalShared,
};

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
        let node = snapshot.random_node().expect("failed to get a node");
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
        Self {
            fetcher: Arc::new(NodesFetchMock),
            fetch_period: Duration::from_secs(5),
            checker: Arc::new(NodeHealthCheckerMock),
            check_period: Duration::from_secs(1),
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot::new())),
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{HealthCheck, NodeHealthCheckerMock};
    use crate::fetch::{NodesFetchMock, NodesFetcher};

    #[tokio::test]
    async fn test_basic_routing() {
        // Arrange
        let fetcher = Arc::new(NodesFetchMock) as Arc<dyn NodesFetcher>;
        let fetch_interval = Duration::from_secs(6);
        let checker = Arc::new(NodeHealthCheckerMock) as Arc<dyn HealthCheck>;
        let check_interval = Duration::from_secs(1);
        let route_provider = Box::new(HealthCheckRouteProvider::new(
            fetcher,
            fetch_interval,
            checker,
            check_interval,
        ));
        // Act: run() should spawn tasks internally and return immediately
        route_provider.run().await;
        let route_url = route_provider.route().expect("failed to get a routing url");
        // Assert
        assert_eq!(route_url.to_string(), "https://ic0.app/api/v2/");
        tokio::time::sleep(Duration::from_secs(4)).await;
        route_provider.stop().await;

        // for debugging purposes run a bit longer
        // tokio::time::sleep(Duration::from_secs(20)).await;
        // route_provider.stop().await;
        // // tokio::time::sleep(Duration::from_secs(1)).await;
        // println!("no new messages expected");
        // tokio::time::sleep(Duration::from_secs(20)).await;
        // println!("finished");
    }
}
