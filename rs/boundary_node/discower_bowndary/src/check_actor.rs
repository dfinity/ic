use std::{sync::Arc, time::Duration};

use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::{
    check::{HealthCheck, HealthCheckResult},
    messages::NodeHealthChanged,
    node::Node,
    types::SenderMpsc,
};

const SERVICE_NAME: &str = "HealthCheckActor";

pub struct HealthCheckActor {
    checker: Arc<dyn HealthCheck>,
    period: Duration,
    node: Node,
    health_state: Option<HealthCheckResult>,
    health_manager_sender: SenderMpsc<NodeHealthChanged>,
    token: CancellationToken,
}

impl HealthCheckActor {
    pub fn new(
        checker: Arc<dyn HealthCheck>,
        period: Duration,
        node: Node,
        health_manager_sender: SenderMpsc<NodeHealthChanged>,
        token: CancellationToken,
    ) -> Self {
        Self {
            checker,
            period,
            node,
            health_manager_sender,
            token,
            health_state: None,
        }
    }

    pub async fn run(mut self) {
        let mut interval = time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let new_health = self.checker.check(&self.node).await.unwrap_or(HealthCheckResult {is_healthy: false});
                    if self.health_state.as_ref() != Some(&new_health) {
                        self.health_state = Some(new_health.clone());
                        let health_changed = NodeHealthChanged {
                            node: self.node.clone(),
                            health: new_health,
                        };
                        // Send results back to health manager for updating the snapshot.
                        // It can never fail in our case
                        if let Err(err) = self.health_manager_sender.send(health_changed).await {
                            error!("{SERVICE_NAME}: failed to send results to HealthManagerActor: {err:?}");
                        }
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
