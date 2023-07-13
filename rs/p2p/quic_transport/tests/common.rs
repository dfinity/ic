use std::{
    collections::{HashMap, HashSet},
    error::Error,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    task::Poll,
    time::Duration,
};

use axum::Router;
use bytes::Bytes;
use futures::future::join_all;
use http::Request;
use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_quic_transport::{QuicTransport, Transport};
use ic_types::{NodeId, RegistryVersion};
use quinn::{
    self,
    udp::{EcnCodepoint, Transmit},
    AsyncUdpSocket,
};
use rustls::{
    self,
    client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    server::{ClientCertVerified, ClientCertVerifier},
    ClientConfig, DigitallySignedStruct, ServerConfig, ServerName,
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

pub struct DummyTlsConfig {
    client_config: ClientConfig,
    server_config: ServerConfig,
}

impl DummyTlsConfig {
    pub fn new(node: NodeId) -> Self {
        Self {
            client_config: Self::create_client_config(node),
            server_config: Self::create_server_config(node),
        }
    }

    fn create_client_config(node: NodeId) -> ClientConfig {
        let certificate = CertWithPrivateKey::builder()
            .cn(node.to_string())
            .build_ed25519();

        let private_key = rustls::PrivateKey(
            certificate
                .key_pair()
                .private_key_to_der()
                .expect("failed to serialize private key"),
        );
        let cert_chain = vec![rustls::Certificate(certificate.cert_der())];

        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_single_cert(cert_chain, private_key)
            .expect("Failed to create TLS client config")
    }

    fn create_server_config(node: NodeId) -> ServerConfig {
        let certificate = CertWithPrivateKey::builder()
            .cn(node.to_string())
            .build_ed25519();

        let private_key = rustls::PrivateKey(
            certificate
                .key_pair()
                .private_key_to_der()
                .expect("failed to serialize private key"),
        );
        let cert_chain = vec![rustls::Certificate(certificate.cert_der())];

        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(NoVerifier))
            .with_single_cert(cert_chain, private_key)
            .expect("Failed to create TLS server config")
    }
}

impl TlsConfig for DummyTlsConfig {
    fn server_config(
        &self,
        _allowed_clients: ic_crypto_tls_interfaces::AllowedClients,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<rustls::ServerConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        Ok(self.server_config.clone())
    }

    /// Server and client should send certificate ids
    fn server_config_without_client_auth(
        &self,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<rustls::ServerConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        unimplemented!("Not needed for transport tests");
    }

    fn client_config(
        &self,
        _server: ic_types::NodeId,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<rustls::ClientConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        Ok(self.client_config.clone())
    }
}

struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ClientCertVerifier for NoVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("Should not auth with tls 1.2")
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::client::WebPkiVerifier::verification_schemes()
    }

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
}

pub fn mock_registry_client() -> Arc<MockRegistryClient> {
    let mut registry_client = MockRegistryClient::new();
    registry_client
        .expect_get_latest_version()
        .return_const(RegistryVersion::from(1));

    Arc::new(registry_client)
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
