use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
    task::Poll,
    time::Duration,
};

use crate::{
    consensus::{TestConsensus, U64Artifact},
    create_peer_manager_and_registry_handle, temp_crypto_component_with_tls_keys,
    RegistryConsensusHandle,
};
use axum::Router;
use either::Either;
use futures::{future::BoxFuture, FutureExt};
use ic_artifact_manager::run_artifact_processor;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::{
    p2p::artifact_manager::{ArtifactProcessorEvent, JoinGuard},
    p2p::state_sync::StateSyncClient,
    time_source::SysTimeSource,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::SubnetTopology;
use ic_quic_transport::{QuicTransport, Transport};
use ic_state_manager::state_sync::types::StateSyncMessage;
use ic_types::{artifact::UnvalidatedArtifactMutation, NodeId, RegistryVersion};
use quinn::{
    self,
    udp::{EcnCodepoint, Transmit},
    AsyncUdpSocket,
};
use tokio::{
    select,
    sync::{mpsc, oneshot, watch, Notify},
};
use turmoil::Sim;

struct CustomUdp {
    ip: IpAddr,
    inner: turmoil::net::UdpSocket,
}

impl CustomUdp {
    const ECN: EcnCodepoint = EcnCodepoint::Ect0;

    pub fn new(ip: IpAddr, inner: turmoil::net::UdpSocket) -> Self {
        Self { ip, inner }
    }
}

impl std::fmt::Debug for CustomUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CustomUdp")
    }
}

impl AsyncUdpSocket for CustomUdp {
    fn poll_send(
        &self,
        _state: &quinn::udp::UdpState,
        cx: &mut std::task::Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let fut = self.inner.writable();
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(x) => x?,
            Poll::Pending => return Poll::Pending,
        };

        let mut transmits_sent = 0;
        for transmit in transmits {
            let buffer: &[u8] = &transmit.contents;
            let mut bytes_sent = 0;
            loop {
                match self.inner.try_send_to(buffer, transmit.destination) {
                    Ok(x) => bytes_sent += x,
                    Err(e) => {
                        if matches!(e.kind(), io::ErrorKind::WouldBlock) {
                            break;
                        }
                        return Poll::Ready(Err(e));
                    }
                }
                if bytes_sent == buffer.len() {
                    break;
                }
                if bytes_sent > buffer.len() {
                    panic!("Bug: Should not send more bytes then in buffer");
                }
            }
            transmits_sent += 1;
        }

        Poll::Ready(Ok(transmits_sent))
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let fut = self.inner.readable();
        tokio::pin!(fut);

        match fut.poll(cx) {
            Poll::Ready(x) => x?,
            Poll::Pending => {
                return Poll::Pending;
            }
        };

        assert!(bufs.len() == meta.len());

        let mut packets_received = 0;
        for (m, b) in meta.iter_mut().zip(bufs) {
            match self.inner.try_recv_from(b) {
                Ok((bytes_received, addr)) => {
                    m.addr = addr;
                    m.len = bytes_received;
                    m.stride = bytes_received;
                    m.ecn = Some(Self::ECN);
                    m.dst_ip = Some(self.ip);
                }
                Err(e) => {
                    if matches!(e.kind(), io::ErrorKind::WouldBlock) {
                        break;
                    }
                    return Poll::Ready(Err(e));
                }
            }
            packets_received += 1;
        }

        Poll::Ready(Ok(packets_received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
/// Runs the tokio simulation until provided closure evaluates to true.
/// If Ok(true) is returned all clients have completed.
pub fn wait_for<F>(sim: &mut Sim, f: F) -> turmoil::Result
where
    F: Fn() -> bool,
{
    while !f() {
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

/// Runs the tokio simulation for the provided duration.
/// If Ok(true) is returned all clients have completed.
pub fn run_simulation_for(sim: &mut Sim, timeout: Duration) -> turmoil::Result {
    let now = sim.elapsed();
    loop {
        if sim.elapsed() > timeout + now {
            break;
        }
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

/// Runs the tokio simulation until the timeout is reached.
/// Panics if simulation finishes or condition evaluates to true.
pub fn wait_for_timeout<F>(sim: &mut Sim, f: F, timeout: Duration) -> turmoil::Result
where
    F: Fn() -> bool,
{
    let now = sim.elapsed();
    loop {
        if f() {
            return Err("Provided condition evaluated to true".into());
        }

        if sim.elapsed() > timeout + now {
            break;
        }
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

pub enum PeerManagerAction {
    Add((NodeId, RegistryVersion)),
    Remove((NodeId, RegistryVersion)),
}

pub fn add_peer_manager_to_sim(
    sim: &mut Sim,
    stop_notify: Arc<Notify>,
    log: ReplicaLogger,
) -> (
    mpsc::UnboundedSender<PeerManagerAction>,
    watch::Receiver<SubnetTopology>,
    RegistryConsensusHandle,
) {
    let (peer_manager_sender, mut peer_manager_receiver) = oneshot::channel();
    #[allow(clippy::disallowed_methods)]
    let (peer_manager_cmd_sender, mut peer_manager_cmd_receiver) = mpsc::unbounded_channel();
    sim.client("peer-manager", async move {
        let rt = tokio::runtime::Handle::current();
        let (_jh, topology_watcher, mut registry_handler) =
            create_peer_manager_and_registry_handle(&rt, log);

        let _ = peer_manager_sender.send((topology_watcher, registry_handler.clone()));

        // Listen for peer manager actions of finished notification.
        loop {
            select! {
                _ = stop_notify.notified() => {
                    break;
                }
                Some(action) = peer_manager_cmd_receiver.recv() => {
                    match action {
                        PeerManagerAction::Add((peer, rv)) => {
                            registry_handler.add_node(
                                rv,
                                peer,
                                Some(&turmoil::lookup(peer.to_string()).to_string())
                            );
                        }
                        PeerManagerAction::Remove((peer, rv)) => {
                            registry_handler.remove_node(
                                rv,
                                peer,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    });

    // Get topology receiver.
    loop {
        if let Ok((watcher, registry_handler)) = peer_manager_receiver.try_recv() {
            break (peer_manager_cmd_sender, watcher, registry_handler);
        }
        sim.step().unwrap();
    }
}

#[allow(clippy::type_complexity)]
pub fn add_transport_to_sim<F>(
    sim: &mut Sim,
    log: ReplicaLogger,
    peer: NodeId,
    registry_handler: RegistryConsensusHandle,
    topology_watcher: watch::Receiver<SubnetTopology>,
    conn_checker: Option<Router>,
    crypto: Option<Arc<dyn TlsConfig + Send + Sync>>,
    state_sync_client: Option<Arc<dyn StateSyncClient<Message = StateSyncMessage>>>,
    consensus_manager: Option<TestConsensus<U64Artifact>>,
    post_setup_future: F,
) where
    F: Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static,
{
    let node_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 4100).into();
    let consensus_manager = consensus_manager.map(|m| Arc::new(RwLock::new(m.clone())));

    let node_crypto =
        crypto.unwrap_or_else(|| temp_crypto_component_with_tls_keys(&registry_handler, peer));
    registry_handler.registry_client.update_to_latest_version();

    sim.host(peer.to_string(), move || {
        let log = log.clone();
        let registry_client = registry_handler.registry_client.clone();
        let node_crypto_clone = node_crypto.clone();
        let conn_checker_clone = conn_checker.clone();
        let topology_watcher_clone = topology_watcher.clone();
        let post_setup_future_clone = post_setup_future.clone();
        let state_sync_client_clone = state_sync_client.clone();
        let consensus_manager_clone = consensus_manager.clone();

        async move {
            let metrics_registry = MetricsRegistry::default();
            let mut consensus_builder = ic_consensus_manager::ConsensusManagerBuilder::new(
                log.clone(),
                tokio::runtime::Handle::current(),
                metrics_registry,
            );

            let mut router = conn_checker_clone;
            let udp_listener = turmoil::net::UdpSocket::bind(node_addr).await.unwrap();
            let this_ip = turmoil::lookup(peer.to_string());
            let custom_udp = CustomUdp::new(this_ip, udp_listener);

            let state_sync_rx = if let Some(ref state_sync) = state_sync_client_clone {
                let (state_sync_router, state_sync_rx) = ic_state_sync_manager::build_axum_router(
                    state_sync.clone(),
                    log.clone(),
                    &MetricsRegistry::default(),
                );
                router = Some(router.unwrap_or_default().merge(state_sync_router));
                Some(state_sync_rx)
            } else {
                None
            };

            let _artifact_processor_jh = if let Some(consensus) = consensus_manager_clone {
                let (artifact_processor_jh, artifact_manager_event_rx, artifact_sender) =
                    start_test_processor(
                        consensus.clone(),
                        consensus.clone().read().unwrap().clone(),
                    );
                let pfn_producer = Arc::new(consensus.clone().read().unwrap().clone());
                consensus_builder.add_client(
                    artifact_manager_event_rx,
                    consensus,
                    pfn_producer,
                    artifact_sender,
                );
                router = Some(router.unwrap_or_default().merge(consensus_builder.router()));

                Some(artifact_processor_jh)
            } else {
                None
            };

            let transport = Arc::new(QuicTransport::start(
                &log,
                &MetricsRegistry::default(),
                &tokio::runtime::Handle::current(),
                node_crypto_clone,
                registry_client,
                peer,
                topology_watcher_clone.clone(),
                Either::Right(custom_udp),
                router.unwrap_or_default(),
            ));

            consensus_builder.run(transport.clone(), topology_watcher_clone.clone());

            if let Some(state_sync_rx) = state_sync_rx {
                ic_state_sync_manager::start_state_sync_manager(
                    &log,
                    &MetricsRegistry::default(),
                    &tokio::runtime::Handle::current(),
                    transport.clone(),
                    state_sync_client_clone.unwrap().clone(),
                    state_sync_rx,
                );
            }

            post_setup_future_clone(peer, transport).await;
            Ok(())
        }
    });
}

pub fn waiter_fut(
) -> impl Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static {
    |_, _| {
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        .boxed()
    }
}

#[allow(clippy::type_complexity)]
pub fn start_test_processor(
    pool: Arc<RwLock<TestConsensus<U64Artifact>>>,
    change_set_producer: TestConsensus<U64Artifact>,
) -> (
    Box<dyn JoinGuard>,
    mpsc::Receiver<ArtifactProcessorEvent<U64Artifact>>,
    mpsc::UnboundedSender<UnvalidatedArtifactMutation<U64Artifact>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let time_source = Arc::new(SysTimeSource::new());
    let client = ic_artifact_manager::processors::Processor::new(pool, change_set_producer);
    let (jh, sender) = run_artifact_processor(
        time_source,
        MetricsRegistry::default(),
        Box::new(client),
        move |req| {
            let _ = tx.blocking_send(req);
        },
    );
    (jh, rx, sender)
}
