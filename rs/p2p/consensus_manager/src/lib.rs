use std::sync::{Arc, RwLock};

use axum::Router;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_interfaces::{
    artifact_pool::{UnvalidatedArtifact, ValidatedPoolReader},
    time_source::TimeSource,
};
use ic_logger::ReplicaLogger;
use ic_quic_transport::Transport;
use ic_types::artifact::{Advert, ArtifactKind};
use tokio::{runtime::Handle, select, sync::mpsc::Receiver};

pub fn build_axum_router<Artifact: ArtifactKind>(
    _log: ReplicaLogger,
    _rt: Handle,
    _pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
) -> (Router, Receiver<()>) {
    todo!("")
}

pub fn start_consensus_manager<Artifact: ArtifactKind + 'static>(
    log: ReplicaLogger,
    rt: Handle,
    // Locally produced adverts to send to the node's peers.
    adverts_to_send: Receiver<Advert<Artifact>>,
    // Adverts received from peers
    adverts_received: Receiver<()>,
    pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    sender: CrossbeamSender<UnvalidatedArtifact<Artifact::Message>>,
    time_source: Arc<dyn TimeSource>,
    transport: Arc<dyn Transport>,
) where
    <Artifact as ArtifactKind>::Message: Send,
    <Artifact as ArtifactKind>::Id: Send,
    <Artifact as ArtifactKind>::Attribute: Send,
{
    let manager = ConsensusManager {
        _log: log,
        _rt: rt.clone(),
        adverts_to_send,
        _adverts_received: adverts_received,
        _pool: pool,
        _sender: sender,
        _time_source: time_source,
        _transport: transport,
    };

    rt.spawn(manager.run());
}

struct ConsensusManager<Artifact: ArtifactKind> {
    _log: ReplicaLogger,
    _rt: Handle,
    _adverts_received: Receiver<()>,
    adverts_to_send: Receiver<Advert<Artifact>>,
    _pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    _sender: CrossbeamSender<UnvalidatedArtifact<Artifact::Message>>,
    _time_source: Arc<dyn TimeSource>,
    _transport: Arc<dyn Transport>,
}

impl<Artifact: ArtifactKind> ConsensusManager<Artifact> {
    async fn run(mut self) {
        loop {
            select! {
                Some(_advert) = self.adverts_to_send.recv() =>{
                    todo!("");
                }
            }
        }
    }
}
