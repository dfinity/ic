use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
};

use ic_crypto_test_utils::tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry_mocks::MockRegistryClient;
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
