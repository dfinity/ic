//! Contains bouncer logic for the ingress pool(s).

use ic_interfaces::{
    ingress_pool::IngressPoolThrottler,
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue},
    time_source::TimeSource,
};
use ic_limits::MAX_INGRESS_TTL;
use ic_types::artifact::IngressMessageId;
use std::sync::Arc;
use std::time::Duration;

/// BouncerFactory implementation for the ingress pool(s).
pub struct IngressBouncer {
    time_source: Arc<dyn TimeSource>,
}

impl IngressBouncer {
    /// Creates a new BouncerFactory
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self { time_source }
    }
}

impl<Pool: IngressPoolThrottler> BouncerFactory<IngressMessageId, Pool> for IngressBouncer {
    fn new_bouncer(&self, _pool: &Pool) -> Bouncer<IngressMessageId> {
        // EXPLANATION: Because ingress messages are included in blocks, consensus
        // does not rely on ingress gossip for correctness. Ingress gossip exists to
        // reduce latency in cases where replicas don't have enough ingress messages
        // to fill their block. Once a replica's pool is full, ingress gossip just
        // causes redundant traffic between replicas, and is thus not needed.
        // Please note that all P2P ingress messages will be dropped if 'exceeds_threshold'
        // returns true until the next invocation of 'get_priority_function'.
        let time_source = self.time_source.clone();
        Box::new(move |ingress_id| {
            let start = time_source.get_relative_time();
            let range = start..=start + MAX_INGRESS_TTL;
            if range.contains(&ingress_id.expiry()) {
                BouncerValue::Wants
            } else {
                BouncerValue::Unwanted
            }
        })
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
    }
}
