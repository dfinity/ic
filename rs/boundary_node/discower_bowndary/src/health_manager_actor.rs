use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error, warn};

use crate::{
    check::HealthCheck,
    check_actor::HealthCheckActor,
    messages::{FetchedNodes, NodeHealthChanged},
    node::Node,
    snapshot::{NodesChanged, Snapshot},
    types::{GlobalShared, ReceiverMpsc, ReceiverWatch, SenderMpsc},
};

const SERVICE_NAME: &str = "HealthManagerActor";

const CHANNEL_BUFFER: usize = 128;

pub struct HealthManagerActor {
    checker: Arc<dyn HealthCheck>,
    check_period: Duration,
    snapshot: GlobalShared<Snapshot>,
    fetch_receiver: ReceiverWatch<FetchedNodes>,
    check_sender: SenderMpsc<NodeHealthChanged>,
    check_receiver: ReceiverMpsc<NodeHealthChanged>,
    token: CancellationToken,
    nodes_token: CancellationToken,
    nodes_tracker: TaskTracker,
}

impl HealthManagerActor {
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        check_period: Duration,
        snapshot: GlobalShared<Snapshot>,
        fetch_receiver: ReceiverWatch<FetchedNodes>,
        token: CancellationToken,
    ) -> Self {
        let (check_sender, check_receiver) = mpsc::channel(CHANNEL_BUFFER);

        Self {
            checker,
            check_period,
            snapshot,
            fetch_receiver,
            check_sender,
            check_receiver,
            token,
            nodes_token: CancellationToken::new(),
            nodes_tracker: TaskTracker::new(),
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Read messages from fetch actor
                result = self.fetch_receiver.changed() => {
                    if let Err(err) = result {
                        error!("{SERVICE_NAME}: nodes fetch sender has been dropped: {err:?}");
                        self.token.cancel();
                        continue;
                    }
                    self.handle_fetch_update().await;
                }
                // Read messages from check actors
                Some(msg) = self.check_receiver.recv() => {
                    self.handle_health_changed(msg).await;
                }
                _ = self.token.cancelled() => {
                    self.stop_checks().await;
                    self.check_receiver.close();
                    warn!("{SERVICE_NAME}: was gracefully cancelled, all node health checks stopped");
                    break;
                }
            }
        }
    }

    async fn handle_health_changed(&mut self, msg: NodeHealthChanged) {
        let current_snapshot = self.snapshot.load_full();
        let mut new_snapshot: Snapshot = (*current_snapshot).clone();
        if let Err(err) = new_snapshot.update_node_health(&msg.node, msg.health) {
            error!("{SERVICE_NAME}: failed to update snapshot: {err:?}");
            return;
        }
        self.snapshot.store(Arc::new(new_snapshot));
    }

    async fn handle_fetch_update(&mut self) {
        let FetchedNodes { nodes } = self
            .fetch_receiver
            .borrow_and_update()
            .clone()
            .expect("can't be None as change was detected");
        if nodes.is_empty() {
            error!("{SERVICE_NAME}: list of fetched nodes is empty");
            // This is a bug in the IC.
            // Updating snapshot with [], would lead to an irrecoverable error.
            // We avoid such updates and just wait for a non-empty lists.
            return;
        }
        debug!("{SERVICE_NAME}: fetched nodes received {:?}", nodes);
        let current_snapshot = self.snapshot.load_full();
        let mut new_snapshot: Snapshot = (*current_snapshot).clone();
        let sync_result = new_snapshot.sync_with(&nodes);
        if let Ok(NodesChanged(true)) = sync_result {
            self.snapshot.store(Arc::new(new_snapshot));
            self.stop_checks().await;
            self.start_checks(nodes);
        }
    }

    fn start_checks(&mut self, nodes: Vec<Node>) {
        // Create a cancellation token for all started checks.
        self.nodes_token = CancellationToken::new();
        for node in nodes {
            debug!("{SERVICE_NAME}: starting health check for node {node:?}",);
            let actor = HealthCheckActor::new(
                Arc::clone(&self.checker),
                self.check_period,
                node,
                self.check_sender.clone(),
                self.nodes_token.clone(),
            );
            self.nodes_tracker.spawn(async move { actor.run().await });
        }
    }

    async fn stop_checks(&self) {
        debug!("{SERVICE_NAME}: stopping all running health checks");
        self.nodes_token.cancel();
        self.nodes_tracker.close();
        self.nodes_tracker.wait().await;
    }
}
