//! The module contains logic for accepting adverts from the P2P clients and reliably broadcasting
//! them to peers.
use crate::event_handler::GossipArc;
use ic_logger::{error, replica_logger::ReplicaLogger};
use ic_types::p2p::GossipAdvert;
use tokio::sync::mpsc::Receiver;

pub(crate) fn start_advert_broadcast_task(
    rt_handle: tokio::runtime::Handle,
    log: ReplicaLogger,
    mut rx: Receiver<GossipAdvert>,
    gossip: GossipArc,
) {
    rt_handle.clone().spawn(async move {
        while let Some(advert) = rx.recv().await {
            let gossip_clone = gossip.clone();
            // 'broadcast_advert' is non IO blocking, hence making
            // the consumption of new messages immediate.
            rt_handle.spawn_blocking(move || gossip_clone.broadcast_advert(advert));
        }
        error!(log, "P2P_AdvertBroadcastTask stopped.");
    });
}
