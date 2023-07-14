use std::{
    collections::{HashMap, HashSet},
    error::Error,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
    task::Poll,
    time::Duration,
};

use axum::Router;
use bytes::Bytes;
use either::Either;
use futures::future::join_all;
use http::Request;
use ic_icos_sev::Sev;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    create_peer_manager_and_registry_handle, temp_crypto_component_with_tls_keys,
    RegistryConsensusHandle,
};
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{QuicTransport, Transport};
use ic_types::{NodeId, RegistryVersion};
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

pub struct CustomUdp {
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

/// Utility to check connectivity between peers.
/// Requires that transport has the `router()` installed
/// and periodically call `check` in a loop.
#[derive(Clone, Debug)]
#[allow(clippy::type_complexity)]
pub struct ConnectivityChecker {
    peers: Arc<RwLock<HashMap<NodeId, HashSet<NodeId>>>>,
}

impl ConnectivityChecker {
    pub fn new(peers: &[NodeId]) -> Self {
        let mut hm = HashMap::new();

        for peer in peers {
            hm.insert(*peer, HashSet::new());
        }

        Self {
            peers: Arc::new(RwLock::new(hm)),
        }
    }

    /// Router used by check function to verify connectivity.
    pub fn router() -> Router {
        Router::new().route("/Ping", axum::routing::get(|| async { "Pong" }))
    }

    /// Checks connectivity of this peer to peers provided in `add_peer` function.
    pub async fn check(&self, this_peer: NodeId, transport: &QuicTransport) {
        // Collect rpc futures to all peers
        let mut futs = vec![];
        for peer in transport.peers() {
            let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
            futs.push(async move {
                (
                    tokio::time::timeout(Duration::from_secs(1), transport.rpc(&peer, request))
                        .await,
                    peer,
                )
            });
        }
        let futs_res = join_all(futs).await;
        // Apply results of rpc futures
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(&this_peer).unwrap().clear();
        for res in futs_res {
            match res {
                (Ok(Ok(_)), peer) => {
                    peers.get_mut(&this_peer).unwrap().insert(peer);
                }
                (_, peer) => {
                    peers.get_mut(&this_peer).unwrap().remove(&peer);
                }
            }
        }
    }

    /// Every peer is connected to every other peer.
    pub fn fully_connected(&self) -> bool {
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            for p2 in peers.keys() {
                if p1 != p2 && !self.connected_pair(p1, p2) {
                    return false;
                }
            }
        }
        true
    }

    /// This peer is not reachable by any other peer.
    pub fn unreachable(&self, this_peer: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            if this_peer != p1 && !self.disconnected_from(p1, this_peer) {
                return false;
            }
        }
        true
    }

    /// Clear connected status table for this peer
    pub fn reset(&self, peer: &NodeId) {
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(peer).unwrap().clear();
    }

    /// Check if a both peers are connected to each other.
    fn connected_pair(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();
        let connected_peer_2 = peers.get(peer_2).unwrap();

        connected_peer_1.contains(peer_2) && connected_peer_2.contains(peer_1)
    }

    /// Checks if peer1 is disconnected from peer2.
    pub fn disconnected_from(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();

        !connected_peer_1.contains(peer_2)
    }
}

/// Runs the tokio simulation until provided closure evaluates to true.
/// If Ok(true) is returned all clients have completed.
pub fn wait_for<F>(sim: &mut Sim, f: F) -> Result<bool, Box<dyn Error>>
where
    F: Fn() -> bool,
{
    while !f() {
        if sim.step()? {
            panic!("Simulation finished while checking condtion");
        }
    }
    Ok(false)
}

// TODO: remove after first node remove test.
#[allow(dead_code)]
pub enum PeerManagerAction {
    Add((NodeId, u16, RegistryVersion)),
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
                        PeerManagerAction::Add((peer, port, rv)) => {
                            registry_handler.add_node(
                                rv,
                                peer,
                                &turmoil::lookup(peer.to_string()).to_string(),
                                port
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

pub fn add_transport_to_sim(
    sim: &mut Sim,
    log: ReplicaLogger,
    peer: NodeId,
    port: u16,
    registry_handler: RegistryConsensusHandle,
    topology_watcher: watch::Receiver<SubnetTopology>,
    conn_checker: ConnectivityChecker,
) {
    let node_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    let node_crypto = temp_crypto_component_with_tls_keys(&registry_handler, peer);
    registry_handler.registry_client.update_to_latest_version();

    sim.host(peer.to_string(), move || {
        let log = log.clone();
        let registry_client = registry_handler.registry_client.clone();
        let node_crypto_clone = node_crypto.clone();
        let conn_checker_clone = conn_checker.clone();
        let topology_watcher_clone = topology_watcher.clone();

        async move {
            let udp_listener = turmoil::net::UdpSocket::bind(node_addr).await.unwrap();
            let this_ip = turmoil::lookup(peer.to_string());
            let custom_udp = CustomUdp::new(this_ip, udp_listener);

            let router = Router::new().merge(ConnectivityChecker::router());

            let sev_handshake = Sev::new(peer, registry_client.clone());

            let transport = QuicTransport::build(
                tokio::runtime::Handle::current(),
                log,
                node_crypto_clone,
                registry_client,
                Arc::new(sev_handshake),
                peer,
                topology_watcher_clone,
                Either::Right(custom_udp),
                &MetricsRegistry::default(),
                router,
            );

            loop {
                conn_checker_clone.check(peer, &transport).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    });
}
