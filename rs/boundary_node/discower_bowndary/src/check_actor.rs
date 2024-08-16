use std::{sync::Arc, time::Duration};

use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::{check::HealthCheck, messages::NodeHealthUpdate, node::Node, types::SenderMpsc};

const SERVICE_NAME: &str = "HealthCheckActor";

pub struct HealthCheckActor {
    checker: Arc<dyn HealthCheck>,
    period: Duration,
    node: Node,
    health_manager_sender: SenderMpsc<NodeHealthUpdate>,
    token: CancellationToken,
}

impl HealthCheckActor {
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        node: Node,
        health_manager_sender: SenderMpsc<NodeHealthUpdate>,
        token: CancellationToken,
    ) -> Self {
        Self {
            checker,
            period,
            node,
            health_manager_sender,
            token,
        }
    }

    pub async fn run(self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let new_health = self.checker.check(&self.node).await.unwrap_or_default();
                    let health_update = NodeHealthUpdate {
                        node: self.node.clone(),
                        health: new_health,
                    };
                    // Send results back to health manager for updating the snapshot.
                    // It can never fail in our case
                    if let Err(err) = self.health_manager_sender.send(health_update).await {
                        error!("{SERVICE_NAME}: failed to send results to HealthManagerActor: {err:?}");
                    }
                }
                _ = self.token.cancelled() => {
                    debug!("{SERVICE_NAME}: for node {:?} was gracefully cancelled", self.node);
                    break;
                }
            }
        }
    }
}
