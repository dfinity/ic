//! Internet Computer Boundary Node Control Plane
//!
//! See README.md for details.
use anyhow::Result;
use async_trait::async_trait;
use futures::future::join_all;
use hyper::{
    body::HttpBody, client::HttpConnector, server::conn::Http, service::service_fn, Body, Client,
    Method, Request, Response, Uri,
};
use hyper_tls::HttpsConnector;
use ic_crypto_utils_basic_sig::conversions::pem::der_to_pem;
use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use ic_registry_client::{
    client::{
        create_data_provider, DataProviderConfig, RegistryClient, RegistryClientImpl,
        RegistryDataProvider,
    },
    helper::{
        crypto::CryptoRegistry,
        node::NodeRegistry,
        routing_table::RoutingTableRegistry,
        subnet::{SubnetListRegistry, SubnetRegistry},
    },
};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use lazy_static::lazy_static;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509Name, X509,
    },
};
use prometheus::{
    register_int_counter, register_int_gauge, Encoder, IntCounter, IntGauge, TextEncoder,
};

use fix_hidden_lifetime_bug::fix_hidden_lifetime_bug;
use serde::Serialize;
use slog::{error, slog_o, trace, warn, Drain, Logger};
use std::convert::TryInto;

use std::{
    collections::{HashMap, HashSet},
    fs::{read_dir, remove_file, File},
    io::{stdout, BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::exit,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    task::JoinHandle,
    time::{sleep, timeout},
    try_join,
};
use tokio_openssl::SslStream;
use url::Url;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_BATCH_SIZE: usize = 32;
const PROBE_SLEEP_SECONDS: u64 = 5;

lazy_static! {
    pub static ref GET_STATUS_ERRORS: IntCounter =
        register_int_counter!("get_status_errors", "Number of errors during get of status")
            .unwrap();
    pub static ref STATUS_CHANGES: IntCounter =
        register_int_counter!("status_changes", "Number of times status has changed").unwrap();
    pub static ref NODE_DOWN_EVENTS: IntCounter = register_int_counter!(
        "node_down_events",
        "Number of times a node has transitioned to down"
    )
    .unwrap();
    pub static ref NODE_UP_EVENTS: IntCounter = register_int_counter!(
        "node_up_events",
        "Number of times a node has transitioned to up"
    )
    .unwrap();
    pub static ref ROUTE_UPDATES: IntCounter =
        register_int_counter!("route_updates", "Number of times routes have been updated").unwrap();
    pub static ref NODES_UP: IntGauge =
        register_int_gauge!("nodes_up", "Number of nodes which are considered up").unwrap();
    pub static ref NODES_DOWN: IntGauge =
        register_int_gauge!("nodes_down", "Number of nodes which are considered down").unwrap();
    pub static ref STATUS: IntGauge =
        register_int_gauge!("status_good", "Status: 1 == good, 0 == bad").unwrap();
    pub static ref REGISTRY_POLL_FAILURES: IntCounter = register_int_counter!(
        "registry_poll_failures",
        "Number of times registry polling failed"
    )
    .unwrap();
}

gflags::define! {
    --nns_urls: &str
}
gflags::define! {
    --nns_public_key: &Path
}
gflags::define! {
    --routes_dir: &Path
}
gflags::define! {
    --metrics_port: u16
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = gflags::parse();
    if !args.is_empty() {
        eprintln!("error: extra arguments on the command line");
        exit(1);
    }
    if !NNS_URLS.is_present() || NNS_URLS.flag.is_empty() {
        eprintln!("error: nns_urls flag missing or empty");
        exit(1);
    }
    if !ROUTES_DIR.is_present() {
        eprintln!("error: routes_dir flag missing");
        exit(1);
    }
    let plain = slog_term::PlainSyncDecorator::new(stdout());
    let log = Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!());
    let _guard = slog_scope::set_global_logger(log.clone());
    STATUS.set(0); // Set status to "bad" until it is "good".

    let metrics_join_handle = if METRICS_PORT.is_present() {
        // Start metrics server.
        let (public_key, private_key) = generate_tls_key_pair();
        let metrics_service = service_fn(move |_req| {
            let metrics_registry = ic_metrics::MetricsRegistry::global();
            let encoder = TextEncoder::new();

            async move {
                let metric_families = metrics_registry.prometheus_registry().gather();
                let mut buffer = vec![];
                encoder.encode(&metric_families, &mut buffer).unwrap();
                Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
            }
        });
        let mut addr = "[::]:9090".parse::<SocketAddr>().unwrap();
        addr.set_port(METRICS_PORT.flag);
        let metrics_join_handle = spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Err(e) => {
                    error!(log, "HTTP exporter server error: {}", e);
                    return;
                }
                Ok(listener) => listener,
            };
            let http = Http::new();
            loop {
                let log = log.clone();
                let http = http.clone();
                let public_key = public_key.clone();
                let private_key = private_key.clone();
                if let Ok((stream, _)) = listener.accept().await {
                    spawn(async move {
                        let mut b = [0_u8; 1];
                        if stream.peek(&mut b).await.is_ok() {
                            if b[0] == 22 {
                                // TLS
                                match perform_tls_server_handshake(
                                    stream,
                                    &public_key,
                                    &private_key,
                                    Vec::new(),
                                )
                                .await
                                {
                                    Err(e) => warn!(log, "TLS error: {}", e),
                                    Ok((stream, _peer_id)) => {
                                        if let Err(e) =
                                            http.serve_connection(stream, metrics_service).await
                                        {
                                            trace!(log, "Connection error: {}", e);
                                        }
                                    }
                                };
                            } else {
                                // HTTP
                                if let Err(e) = http.serve_connection(stream, metrics_service).await
                                {
                                    trace!(log, "Connection error: {}", e);
                                }
                            }
                        }
                    });
                }
            }
        });
        Some(metrics_join_handle)
    } else {
        None
    };

    let nns_public_key = if NNS_PUBLIC_KEY.is_present() {
        Some(
            parse_threshold_sig_key(&NNS_PUBLIC_KEY.flag.to_path_buf())
                .expect("unable to parse NNS public key"),
        )
    } else {
        None
    };
    let nns_urls = NNS_URLS
        .flag
        .split_terminator(',')
        .map(|s| Url::parse(s))
        .collect::<Result<Vec<Url>, _>>()
        .expect("unable to parse nns url");
    let data_provider = create_data_provider(
        &DataProviderConfig::RegistryCanisterUrl(nns_urls.clone()),
        nns_public_key,
    );
    let client = make_https_client();
    let dir = ROUTES_DIR.flag.to_path_buf();
    let status = get_status(&nns_urls, &client, &dir).await;
    eprintln!("got status from NNS");
    let mut registry_client = Arc::new(RegistryClientImpl::new(data_provider.clone(), None));
    loop {
        while let Err(e) = registry_client.try_polling_latest_version(100) {
            eprintln!("error: try_polling_latest_version failed: {}, retrying", e);
            REGISTRY_POLL_FAILURES.inc();
            sleep(Duration::from_secs(10)).await;
        }
        // At this point, before we start the background thread, we should have a
        // reasonably recent registry version available in the registry client.
        match registry_client.fetch_and_start_polling() {
            Ok(_) => break,
            Err(e) => {
                eprintln!("error: fetch_and_start_polling failed: {}, retrying", e);
                REGISTRY_POLL_FAILURES.inc();
                registry_client = Arc::new(RegistryClientImpl::new(data_provider.clone(), None));
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
    STATUS.set(1); // Set status to "good".
    let routes_join_handle = start_routes_export(
        dir,
        registry_client,
        nns_urls,
        status,
        data_provider,
        client,
    );
    if let Some(metrics_join_handle) = metrics_join_handle {
        if let Err(error) = try_join!(routes_join_handle, metrics_join_handle) {
            eprintln!("error: {}", error);
        }
    } else if let Err(error) = try_join!(routes_join_handle) {
        eprintln!("error: {}", error);
    }
    Ok(())
}

#[derive(Debug, Serialize, Default)]
struct NodeRoute {
    node_id: String,
    socket_addr: String,
    tls_certificate_pem: String,
}

#[derive(Debug, Serialize, Default)]
struct SubnetRoute {
    subnet_id: String,
    nodes: Vec<NodeRoute>,
}

#[derive(Debug, Serialize, Default)]
struct CanisterRoute {
    start_canister_id: String,
    end_canister_id: String,
    subnet_id: String,
}

#[derive(Debug, Serialize, Default)]
struct Routes {
    registry_version: u64,
    nns_subnet_id: String,
    canister_routes: Vec<CanisterRoute>,
    subnets: Vec<SubnetRoute>,
}

type HttpsClient = Client<HttpsConnector<HttpConnector>>;

/// Setup HTTPS client which does not validate the self-signed certificate.
fn make_https_client() -> HttpsClient {
    let native_tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .use_sni(false)
        .build()
        .expect("failed to build tls connector");
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    let https_connector = HttpsConnector::from((http_connector, native_tls_connector.into()));
    Client::builder()
        .pool_idle_timeout(Some(Duration::from_secs(600)))
        .pool_max_idle_per_host(1)
        .build::<_, hyper::Body>(https_connector)
}

// This is required during the transition for checking healthiness of the
// replica.
async fn is_node_down(node: &str, client: &HttpsClient) -> bool {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{}/api/v2/status", node))
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(""))
        .unwrap();
    // Any failures w.r.t. to getting a status response from replica implies the
    // replica is down.
    match timeout(PROBE_TIMEOUT, client.request(req)).await {
        Err(_) => true,
        Ok(Err(_)) => true,
        Ok(Ok(response)) => {
            // This should always succeed. Check the serialization tests below.
            let cbor_response =
                serde_cbor::from_slice(&hyper::body::to_bytes(response).await.unwrap().to_vec())
                    .unwrap();
            // This should always succeed. Check the serialization tests below.
            if let Ok(status) = serde_cbor::value::from_value::<HttpStatusResponse>(cbor_response) {
                return Some(ReplicaHealthStatus::Healthy) != status.replica_health_status;
            } else {
                eprintln!("unable to get deserialize status");
            }
            true
        }
    }
}

async fn get_status(nns_urls: &[Url], client: &HttpsClient, dir: &Path) -> Vec<u8> {
    let mut first = true;
    loop {
        for nns_url in nns_urls {
            let url = nns_url.join("api/v2/status");
            let uri: Uri = url
                .unwrap()
                .to_string()
                .parse::<Uri>()
                .expect("unable to parse status URL");
            match timeout(STATUS_TIMEOUT, client.get(uri)).await {
                Err(_) => (),
                Ok(Err(_)) => (),
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        return response.into_body().data().await.unwrap().unwrap().to_vec();
                    }
                }
            }
        }
        if first {
            first = false;
            eprintln!("unable to get status from NNS");
            clear_routes_dir(dir);
        }
        GET_STATUS_ERRORS.inc();
        sleep(STATUS_TIMEOUT).await;
    }
}

fn clear_routes_dir(dir: &Path) {
    for entry in read_dir(dir).expect("unable to read_dir() routes_dir") {
        let entry = entry.expect("unable to access entry from read_dir");
        let path = entry.path();
        // Note: path.ends_with() does not work.
        if path.is_dir() || !path.to_str().unwrap().ends_with(".routes") {
            continue;
        }
        remove_file(path.clone()).unwrap_or_else(|_| panic!("unable to remove_file {:?}", path));
    }
}

#[async_trait]
trait HealthChecker: Send + Sync {
    async fn is_node_down(&self, node: &str, client: &HttpsClient) -> bool;
}

struct Probe {}
#[async_trait]
impl HealthChecker for Probe {
    async fn is_node_down(&self, node: &str, client: &HttpsClient) -> bool {
        is_node_down(node, client).await
    }
}

#[allow(clippy::manual_async_fn)]
#[fix_hidden_lifetime_bug]
async fn batched_probe(
    nodes_down_map: &mut HashMap<String, bool>,
    client: &HttpsClient,
    health_checker: Box<dyn HealthChecker>,
) -> bool {
    let probe_chunks = nodes_down_map.keys().cloned().collect::<Vec<_>>();
    let probe_chunks = probe_chunks.chunks(PROBE_BATCH_SIZE).collect::<Vec<_>>();
    let mut is_down_results: Vec<bool> = Vec::with_capacity(nodes_down_map.len());
    let mut down_changed = false;
    for probe_chunk in probe_chunks {
        let futs = probe_chunk
            .iter()
            .map(|s| (health_checker.is_node_down(s, client)))
            .collect::<Vec<_>>();
        is_down_results.append(&mut join_all(futs).await);
    }

    for ((node, old_state), new_state) in nodes_down_map
        .iter_mut()
        .zip(is_down_results.iter())
        .filter(|((_, old_state), new_state)| old_state != new_state)
    {
        let state_str = match new_state {
            true => {
                NODE_DOWN_EVENTS.inc();
                "down"
            }
            false => {
                NODE_UP_EVENTS.inc();
                "up"
            }
        };
        eprintln!("{} is {}", node, state_str);
        *old_state = *new_state;
        down_changed = true;
    }

    let down = nodes_down_map.iter().filter(|(_, state)| **state).count();
    let up = nodes_down_map.len() - down;
    NODES_UP.set(up.try_into().unwrap_or_else(|_| NODES_UP.get()));
    NODES_DOWN.set(down.try_into().unwrap_or_else(|_| NODES_DOWN.get()));
    down_changed
}

fn start_routes_export(
    dir: PathBuf,
    mut registry_client: Arc<RegistryClientImpl>,
    nns_urls: Vec<Url>,
    mut status: Vec<u8>,
    data_provider: Arc<dyn RegistryDataProvider>,
    client: HttpsClient,
) -> JoinHandle<()> {
    clear_routes_dir(&dir);
    spawn(async move {
        let mut first = true;
        let mut last_registry_version = registry_client.get_latest_version();
        let mut down_changed = false;
        // Map from node socket_addr to a bool: true == node is down.
        let mut nodes_down = HashMap::new();
        // Worklist of nodes to be probed.
        loop {
            let data_provider = data_provider.clone();
            let new_status = get_status(&nns_urls, &client, &dir).await;
            if status != new_status {
                status = new_status;
                eprintln!("status from NNS changed");
                clear_routes_dir(&dir);
                STATUS_CHANGES.inc();
                registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
                if let Err(e) = registry_client.fetch_and_start_polling() {
                    panic!("fetch_and_start_polling failed: {}", e);
                }
            }
            let registry_client = registry_client.clone();
            let registry_version = registry_client.get_latest_version();
            if first || down_changed || registry_version != last_registry_version {
                first = false;
                last_registry_version = registry_version;
                ROUTE_UPDATES.inc();
                let mut filepath = dir.clone();
                filepath.push(format!("{:020}.routes", registry_version.get()));
                let file = File::create(filepath.to_str().expect("missing routes filename"))
                    .expect("unable to open routing_configuration file for write");
                let mut writer = BufWriter::new(&file);
                let routes = get_routes(registry_client, &mut nodes_down).unwrap();
                let routes_json = serde_json::to_string(&routes).expect("failed json conversion");
                writer
                    .write_all(routes_json.as_bytes())
                    .expect("write failure");
            }

            down_changed = batched_probe(&mut nodes_down, &client, Box::new(Probe {})).await;
            sleep(Duration::from_secs(PROBE_SLEEP_SECONDS)).await;
        }
    })
}

// Get Routes from the registry, removing nodes which are 'down'.  Also, update
// the 'down' map to remove nodes which are no longer part of the network and
// adding any new nodes with an initial status of not-down.
fn get_routes(
    registry_client: Arc<dyn RegistryClient>,
    down: &mut HashMap<String, bool>,
) -> Result<Routes, String> {
    let mut nodes = HashSet::new();
    let mut routes = Routes::default();
    let registry_version = registry_client.get_latest_version();
    routes.registry_version = registry_version.get();
    let nns_subnet_id = registry_client
        .get_root_subnet_id(registry_version)
        .map_err(|_| "unable to get root subnet id")?
        .ok_or("bad subnet id, no nns")?;
    routes.nns_subnet_id = nns_subnet_id.to_string();
    let subnet_ids = registry_client
        .get_subnet_ids(registry_version)
        .map_err(|_| "unable to get subnet ids")?
        .ok_or("bad subnet ids")?;
    for subnet_id in subnet_ids {
        let mut subnet_routes = SubnetRoute {
            subnet_id: subnet_id.to_string(),
            ..Default::default()
        };
        let node_ids = registry_client
            .get_node_ids_on_subnet(subnet_id, registry_version)
            .map_err(|_| "unable to get subnet node ids")?
            .ok_or("bad subnet node ids")?;
        for node_id in node_ids {
            let mut node_route = NodeRoute::default();
            let transport_info = registry_client
                .get_transport_info(node_id, registry_version)
                .map_err(|_| "unable to get transport info")?
                .ok_or("bad transport info")?;
            let http = transport_info.http.ok_or("missing http transport_info")?;
            node_route.node_id = node_id.to_string();
            if http.ip_addr.contains(':') && !http.ip_addr.contains('[') {
                node_route.socket_addr =
                    "[".to_string() + &http.ip_addr + "]" + ":" + &http.port.to_string();
            } else {
                node_route.socket_addr = http.ip_addr + ":" + &http.port.to_string();
            }
            nodes.insert(node_route.socket_addr.clone());
            if !down.contains_key(&node_route.socket_addr) {
                down.insert(node_route.socket_addr.clone(), false);
            } else if *down.get(&node_route.socket_addr).unwrap() {
                continue;
            }
            let cert = registry_client
                .get_tls_certificate(node_id, registry_version)
                .map_err(|_| "unable to get node tls certificate")?
                .ok_or("bad node tls certificate")?;
            let pem = der_to_pem(cert.certificate_der.as_slice(), "CERTIFICATE");
            node_route.tls_certificate_pem = pem;
            subnet_routes.nodes.push(node_route);
        }
        routes.subnets.push(subnet_routes);
    }
    let canister_routes = registry_client
        .get_routing_table(registry_version)
        .map_err(|_| "unable to get canister routing table")?
        .ok_or("bad canister routing table")?;
    routes.canister_routes = canister_routes
        .0
        .iter()
        .map(|(range, subnet_id)| CanisterRoute {
            start_canister_id: range.start.to_string(),
            end_canister_id: range.end.to_string(),
            subnet_id: subnet_id.to_string(),
        })
        .collect();
    down.retain(|k, _v| nodes.contains(k));
    Ok(routes)
}

const MIN_PROTOCOL_VERSION: Option<SslVersion> = Some(SslVersion::TLS1_3);
const ALLOWED_CIPHER_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
const ALLOWED_SIGNATURE_ALGORITHMS: &str = "ed25519";

pub fn tls_acceptor(
    private_key: &PKey<Private>,
    server_cert: &X509,
    trusted_client_certs: Vec<X509>,
) -> core::result::Result<SslAcceptor, openssl::ssl::Error> {
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
        .expect("Failed to initialize the acceptor.");
    builder.set_min_proto_version(MIN_PROTOCOL_VERSION)?;
    builder.set_ciphersuites(ALLOWED_CIPHER_SUITES)?;
    builder.set_sigalgs_list(ALLOWED_SIGNATURE_ALGORITHMS)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_verify_cert_store(cert_store(trusted_client_certs)?)?;
    builder.set_verify_depth(2);
    builder.set_private_key(private_key)?;
    builder.set_certificate(server_cert)?;
    builder.check_private_key()?;
    Ok(builder.build())
}

async fn perform_tls_server_handshake(
    tcp_stream: TcpStream,
    self_cert: &X509,
    private_key: &PKey<Private>,
    trusted_client_certs: Vec<X509>,
) -> core::result::Result<(SslStream<TcpStream>, Option<X509>), String> {
    let tls_acceptor = tls_acceptor(private_key, self_cert, trusted_client_certs.clone())
        .map_err(|e| e.to_string())?;
    let ssl = Ssl::new(tls_acceptor.context()).unwrap();
    let mut tls_stream = SslStream::new(ssl, tcp_stream).unwrap();
    Pin::new(&mut tls_stream).accept().await.unwrap();
    let peer_cert = tls_stream.ssl().peer_certificate();
    Ok((tls_stream, peer_cert))
}

pub fn generate_tls_key_pair() -> (X509, PKey<Private>) {
    let private_key = PKey::generate_ed25519().expect("failed to create Ed25519 key pair");
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "boundary-node-control-plane.dfinity.org")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&private_key).unwrap();
    builder.sign(&private_key, MessageDigest::null()).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    let not_after =
        Asn1Time::from_str_x509("99991231235959Z").expect("unable to parse not after as ASN1Time");
    builder.set_not_after(&not_after).unwrap();
    let certificate: X509 = builder.build();
    (certificate, private_key)
}

fn cert_store(certs: Vec<X509>) -> core::result::Result<X509Store, openssl::ssl::Error> {
    let mut cert_store_builder =
        X509StoreBuilder::new().expect("Failed to init X509 store builder.");
    for cert in certs {
        cert_store_builder.add_cert(cert.clone())?;
    }
    Ok(cert_store_builder.build())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use ic_crypto_tls::generate_tls_keys;
    use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
    use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
    use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
    use ic_registry_keys::{
        make_crypto_tls_cert_key, make_routing_table_record_key, ROOT_SUBNET_ID_KEY,
    };
    use ic_registry_routing_table::RoutingTable;
    use ic_test_utilities::p2p::test_group_set_registry;
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};

    use ic_types::messages::Blob;
    use ic_types::{RegistryVersion, SubnetId};

    use serde::{Deserialize, Serialize};

    use ic_test_utilities::types::ids::SUBNET_1;
    pub const ROOT_SUBNET_ID: SubnetId = SUBNET_1;
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const COMMON_NAME: &str = "common name";
    const NOT_AFTER: &str = "20701231235959Z";

    // Once the migration to the new healthiness check is done those tests can be
    // removed.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub struct OldHttpStatusResponse {
        pub ic_api_version: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub root_key: Option<Blob>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub impl_version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub impl_hash: Option<String>,
    }

    #[test]
    fn all_is_updated() {
        let a = HttpStatusResponse {
            ic_api_version: "2".to_string(),
            root_key: None,
            impl_version: None,
            impl_hash: None,
            replica_health_status: Some(ReplicaHealthStatus::Healthy),
        };
        let bin = serde_cbor::to_vec(&a).unwrap();
        let b: HttpStatusResponse = serde_cbor::from_slice(&bin).unwrap();
        assert_eq!(b.ic_api_version, "2");
        assert_eq!(b.root_key, None);
        assert_eq!(b.impl_version, None);
        assert_eq!(b.impl_hash, None);
        assert_eq!(b.replica_health_status, Some(ReplicaHealthStatus::Healthy));
    }

    #[test]
    fn boundary_node_is_updated_first() {
        let a = OldHttpStatusResponse {
            ic_api_version: "2".to_string(),
            root_key: None,
            impl_version: None,
            impl_hash: None,
        };
        let bin = serde_cbor::to_vec(&a).unwrap();
        let b: HttpStatusResponse = serde_cbor::from_slice(&bin).unwrap();
        assert_eq!(b.ic_api_version, "2");
        assert_eq!(b.root_key, None);
        assert_eq!(b.impl_version, None);
        assert_eq!(b.impl_hash, None);
        assert_eq!(b.replica_health_status, None);
    }

    #[test]
    fn replica_is_updated_first() {
        let a = HttpStatusResponse {
            ic_api_version: "2".to_string(),
            root_key: None,
            impl_version: None,
            impl_hash: None,
            replica_health_status: Some(ReplicaHealthStatus::Healthy),
        };

        let bin = serde_cbor::to_vec(&a).unwrap();
        let b: OldHttpStatusResponse = serde_cbor::from_slice(&bin).unwrap();
        assert_eq!(b.ic_api_version, "2");
        assert_eq!(b.root_key, None);
        assert_eq!(b.impl_version, None);
        assert_eq!(b.impl_hash, None);
    }

    struct TestNodeDown {}
    #[async_trait]
    impl HealthChecker for TestNodeDown {
        async fn is_node_down(&self, node: &str, _: &HttpsClient) -> bool {
            println!("PROBE: {} is down", node);
            true
        }
    }

    struct TestNodeUp {}
    #[async_trait]
    impl HealthChecker for TestNodeUp {
        async fn is_node_down(&self, node: &str, _: &HttpsClient) -> bool {
            println!("PROBE: {} is up", node);
            false
        }
    }

    struct TestOddNodeDown {
        count: std::sync::atomic::AtomicU32,
    }
    #[async_trait]
    impl HealthChecker for TestOddNodeDown {
        async fn is_node_down(&self, node: &str, _: &HttpsClient) -> bool {
            let seq = self.count.fetch_add(1, Ordering::SeqCst);
            if seq % 2 != 0 {
                println!("PROBE:{} is down", node);
                true
            } else {
                println!("PROBE:{} is up", node);
                false
            }
        }
    }

    const MAX_NODES: u16 = 100;
    #[tokio::test]
    async fn dead_node_detection() {
        let registry_version = REG_V1;
        // Set up a registry just enough info to call get_routes().
        let node_port_allocation = Arc::new((0..MAX_NODES).collect::<Vec<_>>());
        let mut nodes_down_map = HashMap::new();
        let data_provider = test_group_set_registry(subnet_test_id(0), node_port_allocation);

        let (tls_pubkey, _p_key) = generate_tls_keys(COMMON_NAME, NOT_AFTER);

        // Use a single tls cert for all Nodes. This is a stress test
        // and we don't want to generate thousands of unique certs
        for node_id in (0..MAX_NODES as u64).map(|i| node_test_id(i)) {
            data_provider
                .add(
                    &make_crypto_tls_cert_key(node_id),
                    registry_version,
                    Some(tls_pubkey.to_proto()),
                )
                .expect("failed to add TLS cert to registry");
        }

        let root_subnet_id = SubnetIdProto {
            principal_id: Some(PrincipalIdIdProto {
                raw: ROOT_SUBNET_ID.get_ref().to_vec(),
            }),
        };
        data_provider
            .add(ROOT_SUBNET_ID_KEY, REG_V1, Some(root_subnet_id))
            .expect("failed to add root subnet ID to registry");

        let routing_table_record = PbRoutingTable::from(RoutingTable::default());
        data_provider
            .add(
                &make_routing_table_record_key(),
                REG_V1,
                Some(routing_table_record),
            )
            .expect("failed to add routing table to registry");

        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
        registry_client.fetch_and_start_polling().unwrap();

        /* Check initial routes */
        let routes = get_routes(registry_client.clone(), &mut nodes_down_map).unwrap();
        assert!(routes.subnets[0].nodes.len() == MAX_NODES as usize);
        assert!(nodes_down_map.len() == MAX_NODES as usize);

        /* Detect all nodes are alive */
        let down_changed = batched_probe(
            &mut nodes_down_map,
            &make_https_client(),
            Box::new(TestNodeUp {}),
        )
        .await;
        assert!(!down_changed);

        /* detect all nodes are dead */
        let down_changed = batched_probe(
            &mut nodes_down_map,
            &make_https_client(),
            Box::new(TestNodeDown {}),
        )
        .await;
        assert!(down_changed);
        assert!(nodes_down_map.values().filter(|v| **v).count() == MAX_NODES as usize);

        /* detect half  nodes as dead */
        let down_changed = batched_probe(
            &mut nodes_down_map,
            &make_https_client(),
            Box::new(TestOddNodeDown {
                count: AtomicU32::new(0),
            }),
        )
        .await;
        assert!(down_changed);
        assert!(nodes_down_map.values().filter(|v| **v).count() == (MAX_NODES as usize) / 2);

        /* Check if routes to deads nodes are disabled. */
        let routes = get_routes(registry_client, &mut nodes_down_map).unwrap();
        assert!(routes.subnets[0].nodes.len() == (MAX_NODES as usize) / 2);
        assert!(nodes_down_map.len() == MAX_NODES as usize);
    }
}
