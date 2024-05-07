use std::{sync::Arc, time::Duration};

use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::{
    fetch::NodesFetcher,
    messages::FetchedNodes,
    snapshot::Snapshot,
    types::{GlobalShared, SenderWatch},
};

const SERVICE_NAME: &str = "NodesFetchActor";

pub struct NodesFetchActor<S> {
    fetcher: Arc<dyn NodesFetcher>,
    period: Duration,
    fetched_nodes_sender: SenderWatch<FetchedNodes>,
    snapshot: GlobalShared<S>,
    token: CancellationToken,
}

impl<S> NodesFetchActor<S>
where
    S: Snapshot,
{
    pub fn new(
        fetcher: Arc<dyn NodesFetcher>,
        period: Duration,
        fetched_nodes_sender: SenderWatch<FetchedNodes>,
        snapshot: GlobalShared<S>,
        token: CancellationToken,
    ) -> Self {
        Self {
            fetcher,
            period,
            fetched_nodes_sender,
            snapshot,
            token,
        }
    }

    pub async fn run(self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                        let snapshot = self.snapshot.load();
                        let Some(node) = snapshot.next() else {
                            error!("{SERVICE_NAME}: failed to get next node from snapshot");
                            continue;
                        };

                        let nodes = match self.fetcher.fetch(node.into()).await {
                            Ok(nodes) => nodes,
                            Err(err) => {
                                error!("{SERVICE_NAME}: failed to fetch nodes: {err:?}");
                                continue;
                            }
                        };

                        if let Err(err) = self.fetched_nodes_sender.send(Some(
                            FetchedNodes {nodes}
                        )) {
                            error!("{SERVICE_NAME}: failed to send results to HealthManager: {err:?}");
                        }
                }
                _ = self.token.cancelled() => {
                    warn!("{SERVICE_NAME}: was gracefully cancelled");
                    break;
                }
            }
        }
    }
}
