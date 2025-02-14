use std::{sync::Arc, time::Duration};

use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{messages::CertificateDelegation, SubnetId};
use prometheus::{Histogram, IntCounter};
use tokio::{sync::watch, task::JoinHandle};

use crate::load_root_delegation;

const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Spawns a task which periodically fetches the nns delegation.
pub fn start_nns_delegation_manager(
    metrics_registry: &MetricsRegistry,
    config: Config,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
) -> (
    JoinHandle<()>,
    watch::Receiver<Option<CertificateDelegation>>,
) {
    let manager = DelegationManager {
        config,
        log,
        subnet_id,
        nns_subnet_id,
        registry_client,
        tls_config,
        metrics: DelegationManagerMetrics::new(metrics_registry),
    };

    let delegation = rt_handle.block_on(manager.fetch());

    let (tx, rx) = watch::channel(delegation);

    (rt_handle.spawn(manager.run(tx)), rx)
}

struct DelegationManagerMetrics {
    updates: IntCounter,
    update_duration: Histogram,
    delegation_size: Histogram,
}

impl DelegationManagerMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            updates: metrics_registry.int_counter(
                "nns_delegation_manager_updates",
                "How many times has the nns delegation been updated",
            ),
            update_duration: metrics_registry.histogram(
                "nns_delegation_manager_update_duration",
                "How long it took to update the nns delegation, in seconds",
                // (1ms, 2ms, 5ms, ..., 10s, 20s, 50s)
                decimal_buckets(-3, 1),
            ),
            delegation_size: metrics_registry.histogram(
                "nns_delegation_manager_delegation_size",
                "How big is the delegation, in bytes",
                // (1, 2, 5, ..., 1MB, 2MB, 5MB)
                decimal_buckets(0, 6),
            ),
        }
    }
}

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    metrics: DelegationManagerMetrics,
}

impl DelegationManager {
    async fn fetch(&self) -> Option<CertificateDelegation> {
        let _timer = self.metrics.update_duration.start_timer();

        let delegation = load_root_delegation(
            &self.config,
            &self.log,
            self.subnet_id,
            self.nns_subnet_id,
            self.registry_client.as_ref(),
            self.tls_config.as_ref(),
        )
        .await;

        self.metrics.delegation_size.observe(
            delegation
                .as_ref()
                .map(|d| d.certificate.len() as f64)
                .unwrap_or_default(),
        );

        self.metrics.updates.inc();

        delegation
    }

    async fn run(self, sender: watch::Sender<Option<CertificateDelegation>>) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);

        loop {
            let _ = interval.tick().await;

            let delegation = self.fetch().await;

            // FIXME(kpop): what to do when we fail, i.e., all receivers are dropped
            let _ = sender.send(delegation);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::Cbor;

    use super::*;

    use axum::response::IntoResponse;
    use axum_server::tls_rustls::RustlsConfig;
    use ic_certification_test_utils::serialize_to_cbor;
    use ic_certification_test_utils::{
        encoded_time, generate_root_of_trust, CertificateBuilder, CertificateData,
    };
    use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
    use ic_crypto_tree_hash::{flatmap, lookup_path, Label, LabeledTree};
    use ic_crypto_utils_threshold_sig_der::public_key_to_der;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_registry::{
        add_single_subnet_record, add_subnet_key_record, add_subnet_list_record,
        SubnetRecordBuilder,
    };
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::messages::Certificate;
    use ic_types::{
        messages::{Blob, HttpReadStateResponse},
        NodeId,
    };
    use rand::thread_rng;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, SignatureScheme,
    };
    use std::{net::SocketAddr, sync::Arc};

    const NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_1;
    const NON_NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_2;
    const NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_1;
    const NON_NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_2;

    // Get a free port on this host to which we can connect transport to.
    fn get_free_localhost_socket_addr() -> SocketAddr {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseport(false).unwrap();
        socket.set_reuseaddr(false).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.local_addr().unwrap()
    }

    async fn generate_self_signed_cert() -> RustlsConfig {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();

        let cert_der = CertificateDer::from(cert);

        RustlsConfig::from_der(vec![cert_der.as_ref().to_vec()], key_pair.serialize_der())
            .await
            .unwrap()
    }

    /// Sets up all the dependencies.
    fn set_up(rt_handle: tokio::runtime::Handle) -> (Arc<FakeRegistryClient>, MockTlsConfig) {
        let registry_version = 1;

        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        add_single_subnet_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[NNS_NODE_ID])
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            NON_NNS_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[NON_NNS_NODE_ID])
                .build(),
        );

        let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
        let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());

        add_subnet_key_record(
            &data_provider,
            registry_version,
            NON_NNS_SUBNET_ID,
            non_nns_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            nns_public_key,
        );

        add_subnet_list_record(
            &data_provider,
            registry_version,
            vec![NNS_SUBNET_ID, NON_NNS_SUBNET_ID],
        );

        let addr = get_free_localhost_socket_addr();

        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            ..Default::default()
        };

        data_provider
            .add(
                &make_node_record_key(NNS_NODE_ID),
                registry_version.into(),
                Some(node_record),
            )
            .unwrap();

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));

        registry_client.update_to_latest_version();

        let canister_id_ranges = vec![(canister_test_id(0), canister_test_id(10))];

        let (_certificate, _root_pk, cbor) =
            CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                Label::from("subnet") => LabeledTree::SubTree(flatmap![
                    Label::from(NON_NNS_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                        Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&canister_id_ranges)),
                        Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&non_nns_public_key.into_bytes()).unwrap()),
                    ])
                ]),
                Label::from("time") => LabeledTree::Leaf(encoded_time(42))
            ])))
            .with_root_of_trust(nns_public_key, nns_secret_key)
            .build();

        let mocked_response = HttpReadStateResponse {
            certificate: Blob(cbor),
        };

        rt_handle.spawn(async move {
            let c = mocked_response.clone();
            let router = axum::routing::any(move || async { Cbor(c).into_response() });

            axum_server::bind_rustls(addr, generate_self_signed_cert().await)
                .serve(router.into_make_service())
                .await
                .unwrap()
        });

        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer,
                _intermediates: &[CertificateDer],
                _server_name: &ServerName,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let accept_any_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        let mut tls_config = MockTlsConfig::new();
        tls_config
            .expect_client_config()
            .returning(move |_, _| Ok(accept_any_config.clone()));

        (registry_client, tls_config)
    }

    #[test]
    fn nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (registry_client, tls_config) = set_up(rt.handle().clone());

        let (_, rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt.handle().clone(),
            NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
        );

        assert!(rx.borrow().is_none());
    }

    #[test]
    fn non_nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (registry_client, tls_config) = set_up(rt.handle().clone());

        let (_, rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt.handle().clone(),
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
        );

        let delegation = rx
            .borrow()
            .clone()
            .expect("Should return Some delegation on non NNS subnet");
        let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
            .expect("Should have returned a valid certificate");
        let tree = LabeledTree::try_from(parsed_delegation.tree)
            .expect("Should return a valid state tree");
        match lookup_path(&tree, &[b"subnet", NON_NNS_SUBNET_ID.get_ref().as_ref()]) {
            Some(LabeledTree::SubTree(..)) => (),
            _ => panic!("Didn't find the subnet path in the state tree"),
        }
    }
}
