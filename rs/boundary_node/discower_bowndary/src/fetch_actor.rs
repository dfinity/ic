use std::{sync::Arc, time::Duration};

use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::{
    fetch::NodesFetcher,
    messages::FetchedNodes,
    snapshot::Snapshot,
    types::{GlobalShared, SenderWatch},
};

pub struct NodesFetchActor {
    fetcher: Arc<dyn NodesFetcher>,
    period: Duration,
    fetched_nodes_sender: SenderWatch<FetchedNodes>,
    snapshot: GlobalShared<Snapshot>,
    token: CancellationToken,
}

impl NodesFetchActor {
    pub fn new(
        fetcher: Arc<dyn NodesFetcher>,
        period: Duration,
        fetched_nodes_sender: SenderWatch<FetchedNodes>,
        snapshot: GlobalShared<Snapshot>,
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
                        let node = snapshot.next().expect("no node found");
                        let nodes = self.fetcher.fetch(node.into()).await.unwrap();
                        let msg = Some(
                            FetchedNodes {nodes}
                        );
                        if self.fetched_nodes_sender.send(msg).is_err() {
                            println!("NodesFetchActor: failed to send results to health manager");
                        } else {
                            println!("NodesFetchActor: sent results to health manager");
                        }
                }
                _ = self.token.cancelled() => {
                    println!("NodesFetchActor: gracefully cancelled.");
                    break;
                }
            }
        }
    }
}
