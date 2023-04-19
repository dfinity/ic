//! The module contains logic for accepting adverts from the P2P clients and reliably broadcasting
//! them to peers.
use crate::event_handler::GossipArc;
use ic_interfaces::artifact_manager::AdvertBroadcaster;
use ic_logger::{error, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{artifact::ArtifactTag, p2p::GossipAdvert};
use prometheus::IntCounterVec;
use std::thread::JoinHandle;
use tokio::sync::mpsc::{
    error::{SendError, TrySendError},
    Receiver, Sender,
};

#[derive(Clone)]
pub struct AdvertBroadcasterImpl {
    log: ReplicaLogger,
    sender: Sender<GossipAdvert>,
    congested_adverts: IntCounterVec,
    total_adverts: IntCounterVec,
}

impl AdvertBroadcasterImpl {
    pub fn new(
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        sender: Sender<GossipAdvert>,
    ) -> Self {
        let congested_adverts = metrics_registry.int_counter_vec(
        "p2p_client_congested_adverts_total",
        "Total number of artifact advertisements with high latencies observed by the client/consensus thread, grouped by artifact type.",
        &["type"],
    );
        let total_adverts = metrics_registry.int_counter_vec(
            "p2p_client_adverts_total",
            "Total number of artifact advertisements by clients, grouped by artifact type.",
            &["type"],
        );

        Self {
            log,
            sender,
            congested_adverts,
            total_adverts,
        }
    }
}

impl AdvertBroadcaster for AdvertBroadcasterImpl {
    fn process_delta(&self, advert: GossipAdvert) {
        let artifact_id_label = ArtifactTag::from(&advert.artifact_id).into();
        self.total_adverts
            .with_label_values(&[artifact_id_label])
            .inc();
        match self.sender.try_send(advert) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                error!(self.log, "Send advert channel closed.");
            }
            Err(TrySendError::Full(advert)) => {
                self.congested_adverts
                    .with_label_values(&[artifact_id_label])
                    .inc();
                // 'blocking_send' won't block consensus past initialization because the loop, inside the
                // P2P_AdvertTxThread, that consumes adverts and calls 'broadcast_advert' doesn't block.
                // However, the processor's thread may block when send is called only during start-up until
                // the P2P_AdvertTxThread is started. Hence no adverts will be dropped on startup.
                if let Err(SendError(_)) = self.sender.blocking_send(advert) {
                    error!(self.log, "Send advert channel closed.");
                }
            }
        };
    }
}

/// Starts the thread that receives locally generated adverts and tries to broadcasts them.
pub(crate) fn start_advert_send_thread(
    log: ReplicaLogger,
    mut rx: Receiver<GossipAdvert>,
    gossip: GossipArc,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("P2P_AdvertTxThread".to_string())
        .spawn(move || {
            while let Some(advert) = rx.blocking_recv() {
                // 'broadcast_advert' is non IO blocking, hence making
                // the consumption of new messages immediate.
                gossip.broadcast_advert(advert);
            }
            error!(log, "P2P_AdvertTxThread stopped.")
        })
        .unwrap()
}
