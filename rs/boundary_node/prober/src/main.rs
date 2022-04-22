//! Internet Computer Boundary Node Prober
//!
//! See README.md for details.

extern crate slog;
extern crate slog_scope;

use anyhow::Result;
use async_trait::async_trait;
use boundary_node_control_plane::{NodeRoute, Routes, SubnetRoute};
use candid::{CandidType, Principal};
use garcon::Delay;
use hyper::{server::conn::Http, service::service_fn, Body, Response};
use ic_agent::Agent;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::management_canister::builders::{CanisterInstall, InstallMode};
use ic_utils::interfaces::management_canister::MgmtMethod;
use ic_utils::interfaces::ManagementCanister;
use lazy_static::lazy_static;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Name, X509},
};
use prometheus::{
    register_int_counter, register_int_gauge_vec, Encoder, IntCounter, IntGaugeVec, TextEncoder,
};
use serde::{Deserialize, Serialize};
use slog::*;
use std::{
    collections::HashMap,
    convert::TryInto,
    fs,
    io::{BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::Instant,
    try_join,
};
use tokio_openssl::SslStream;

const COUNTER_CANISTER_WAT: &[u8] = include_bytes!("counter.wat");
const ROUTES: &str = ".routes";
const WALLETS: &str = ".wallets";
const CANISTER: &str = ".canisters";
const IDENTITY_FILE: &str = "identity.pem";
const CYCLES: u64 = 190_000_000_000_u64;
const PROBE_INTERVAL: Duration = Duration::from_secs(300);
const CANISTER_CREATE_INTERVAL: Duration = Duration::from_secs(21600);

#[derive(Serialize, Deserialize, Clone)]
struct Canisters {
    subnet: HashMap<String, String>,
}

#[derive(CandidType)]
struct In {
    canister_id: Principal,
}

#[derive(Clone)]
struct ProberDefinition {
    canisters: Canisters,
    wallets: Canisters,
    routes: Routes,
    routes_dir: PathBuf,
    wallets_dir: PathBuf,
    identity_path: PathBuf,
}

#[async_trait]
trait ProberLoader: ProberClone + Send + Sync {
    fn reload(&mut self);
    fn get_canisters(&self) -> HashMap<String, String>;
    fn remove_canister(&mut self, subnet: &str);
    fn add_canister(&mut self, subnet: String, canister: String);
    fn get_wallet(&self, subnet: &str) -> Option<&String>;
    fn get_routes(&self) -> Vec<SubnetRoute>;
    fn export_canister_data(&self, canisters: &Canisters);
    async fn create_agent_and_waiter(&self, url: &str, mainnet: bool) -> BoxResult<(Agent, Delay)>;
    async fn create_canister(
        &self,
        url: String,
        wallet_id: String,
        mainnet: bool,
    ) -> Result<Principal, String>;
    async fn cleanup_old_canisters(
        &self,
        url: String,
        canister: String,
        wallet_canister: String,
        mainnet: bool,
    ) -> Result<(), String>;
    async fn execute_probe(
        &self,
        url: &str,
        canister_id: &Principal,
        mainnet: bool,
    ) -> Result<(), String>;
}

trait ProberClone {
    fn clone_box(&self) -> Box<dyn ProberLoader>;
}

impl<T> ProberClone for T
where
    T: 'static + ProberLoader + Clone,
{
    fn clone_box(&self) -> Box<dyn ProberLoader> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ProberLoader> {
    fn clone(&self) -> Box<dyn ProberLoader> {
        self.clone_box()
    }
}

type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;

lazy_static! {
    pub static ref PROBES_COMPLETED: IntCounter =
        register_int_counter!("probes_completed", "Number of probes completed").unwrap();
    pub static ref CREATE_CANISTER_FAILURE: IntGaugeVec = register_int_gauge_vec!(
        "create_canister_failure",
        "Create canister failure on a given subnet.",
        &["subnet_id"]
    )
    .unwrap();
    pub static ref CLEANUP_CANISTER_FAILURE: IntGaugeVec = register_int_gauge_vec!(
        "cleanup_canister_failure",
        "Cleanup canister failure on a given subnet.",
        &["subnet_id"]
    )
    .unwrap();
    pub static ref CREATE_CANISTER_SUCCESS: IntGaugeVec = register_int_gauge_vec!(
        "create_canister_success",
        "Create canister success on a given subnet.",
        &["subnet_id"]
    )
    .unwrap();
    pub static ref NODE_PROBE_FAILURE: IntGaugeVec = register_int_gauge_vec!(
        "node_probe_failure",
        "Probe failure on a particular node",
        &["node_id"]
    )
    .unwrap();
    pub static ref NODE_PROBE_SUCCESS: IntGaugeVec = register_int_gauge_vec!(
        "node_probe_success",
        "Probe success on a particular node",
        &["node_id"]
    )
    .unwrap();
    pub static ref NODE_PROBE_LATENCY: IntGaugeVec = register_int_gauge_vec!(
        "node_probe_latency",
        "Probe latency on a particular node",
        &["node_id"]
    )
    .unwrap();
    pub static ref SUBNET_PROBE_FAILURE: IntGaugeVec = register_int_gauge_vec!(
        "subnet_probe_failure",
        "Probe failure on a particular subnet",
        &["subnet_id"]
    )
    .unwrap();
}

gflags::define! {
    --routes_dir: &Path
}
gflags::define! {
    --wallets_dir: &Path
}
gflags::define! {
    --metrics_port: u16
}
gflags::define! {
    --mainnet = false
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = gflags::parse();
    if !args.is_empty() {
        eprintln!("error: extra arguments on the command line");
        std::process::exit(1);
    }
    if !ROUTES_DIR.is_present() {
        eprintln!("error: routes_dir flag missing");
        std::process::exit(1);
    }
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let log = slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!());
    let _guard = slog_scope::set_global_logger(log.clone());

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
        let metrics_join_handle = tokio::spawn(async move {
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
                    tokio::spawn(async move {
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
    let routes = read_file_data(ROUTES_DIR.flag, ROUTES);
    let wallets = read_file_data(WALLETS_DIR.flag, WALLETS);
    let routes: Routes = match routes {
        Ok(routes_data) => serde_json::from_value(routes_data).unwrap(),
        Err(_) => {
            panic!("Could not load routes data");
        }
    };

    let wallets: Canisters = match wallets {
        Ok(wallets_data) => serde_json::from_value(wallets_data).unwrap(),
        Err(_) => {
            panic!("Could not load wallets data");
        }
    };
    let canisters = read_file_data(WALLETS_DIR.flag, CANISTER);
    let canisters: Canisters = match canisters {
        Ok(canisters) => serde_json::from_value(canisters).unwrap(),
        Err(_) => {
            let subnet = HashMap::new();
            Canisters { subnet }
        }
    };
    let mut identity_path = WALLETS_DIR.flag.to_path_buf();
    identity_path.push(IDENTITY_FILE);
    eprintln!("Wallets and subnet mapping : {:?}", wallets.subnet);
    let prober_definition = ProberDefinition {
        canisters,
        wallets,
        routes,
        routes_dir: ROUTES_DIR.flag.to_path_buf(),
        wallets_dir: WALLETS_DIR.flag.to_path_buf(),
        identity_path,
    };
    start_probe_event_loop(Box::new(prober_definition), MAINNET.flag).await;

    if let Some(metrics_join_handle) = metrics_join_handle {
        if let Err(error) = try_join!(metrics_join_handle) {
            eprintln!("error: {}", error);
        }
    }

    Ok(())
}

async fn start_probe_event_loop(mut prober_definition: Box<dyn ProberLoader>, mainnet: bool) {
    // Flag which defines whether canisters need to be deleted
    let mut cleanup_canisters = HashMap::new();
    for subnet in prober_definition.get_canisters().keys() {
        cleanup_canisters.insert(subnet.clone(), true);
    }
    // Flag which defines whether canisters should be created in the upcoming
    // event-loop iteration.
    let mut create_canisters = HashMap::new();
    let canister_start = Instant::now();
    // When canisters should be recreated
    let mut canister_refresh = canister_start + CANISTER_CREATE_INTERVAL;
    loop {
        let probe_start = Instant::now();
        let probe_end = probe_start + PROBE_INTERVAL;
        let subnets = &prober_definition.get_routes();
        let mut futures = HashMap::new();
        // Cleanup old canisters
        for subnet in subnets {
            let subnet_id = &subnet.subnet_id;
            let subnet_wallet = prober_definition.get_wallet(subnet_id);
            let url = subnet.nodes[0].socket_addr.clone();
            // Cleanup canister only if wallet exists
            let wallet = match subnet_wallet {
                Some(wallet) => wallet.clone(),
                None => continue,
            };

            // If this canister cleanup flag is true, and exists, delete it.
            if **cleanup_canisters.get(subnet_id).get_or_insert(&false)
                && prober_definition.get_canisters().get(subnet_id).is_some()
            {
                let canister_id = prober_definition
                    .get_canisters()
                    .get(subnet_id)
                    .unwrap()
                    .clone();
                eprintln!("Cleaning up canister {}", canister_id);
                let prober_def = prober_definition.clone();
                let future = tokio::spawn(async move {
                    prober_def
                        .cleanup_old_canisters(url, canister_id, wallet, mainnet)
                        .await
                });
                futures.insert(subnet_id.clone(), future);
            }
        }

        // Await cleanup result and handle success or failure cases.
        for (subnet_id, future) in futures {
            let result = future.await;
            match result {
                Ok(_) => {
                    // Canister has been cleaned up
                    prober_definition.remove_canister(&*subnet_id);
                    // A new canister must be created on this subnet
                    create_canisters.insert(subnet_id.clone(), true);
                    // No canisters need to be cleaned on this subnet.
                    cleanup_canisters.insert(subnet_id.clone(), false);
                    CLEANUP_CANISTER_FAILURE
                        .with_label_values(&[&*subnet_id])
                        .set(0);
                }
                Err(e) => {
                    eprintln!("Failed to delete old canister with error: {:?}", e);
                    CLEANUP_CANISTER_FAILURE
                        .with_label_values(&[&*subnet_id])
                        .set(1);
                }
            }
        }

        let mut futures = HashMap::new();
        // Create new canisters if needed
        for subnet in subnets {
            let subnet_id = &subnet.subnet_id;
            // Create canisters if needed
            if **create_canisters.get(subnet_id).get_or_insert(&true)
                && prober_definition.get_canisters().get(subnet_id).is_none()
            {
                eprintln!("Creating canister with subnet {}", subnet_id);
                let subnet_wallet = prober_definition.get_wallet(subnet_id);
                let url = subnet.nodes[0].socket_addr.clone();
                // Create canister only if wallet exists.
                let future = match subnet_wallet {
                    Some(wallet) => {
                        let wallet = wallet.clone();
                        let prober_def = prober_definition.clone();
                        tokio::spawn(async move {
                            prober_def.create_canister(url, wallet, mainnet).await
                        })
                    }
                    None => continue,
                };
                futures.insert(subnet_id.clone(), future);
            }
        }

        // Await and handle canister creation success and error cases
        for (subnet_id, future) in futures {
            let result = future.await;
            match result {
                Ok(Ok(canister)) => {
                    create_canisters.insert(subnet_id.clone(), false);
                    prober_definition.add_canister(subnet_id.clone(), canister.clone().to_text());
                    // Create canister succeeded.
                    CREATE_CANISTER_FAILURE
                        .with_label_values(&[&subnet_id])
                        .set(0);
                    CREATE_CANISTER_SUCCESS
                        .with_label_values(&[&subnet_id])
                        .set(1);
                }
                Ok(Err(e)) => {
                    eprintln!("Canister creation failed with error {:?}", e);
                    // Set canister creation failure metric.
                    CREATE_CANISTER_FAILURE
                        .with_label_values(&[&subnet_id])
                        .set(1);
                    CREATE_CANISTER_SUCCESS
                        .with_label_values(&[&subnet_id])
                        .set(0);
                    continue;
                }
                Err(e) => {
                    eprintln!("Canister creation failed with error {:?}", e);
                    // Set canister creation failure metric.
                    CREATE_CANISTER_FAILURE
                        .with_label_values(&[&subnet_id])
                        .set(1);
                    CREATE_CANISTER_SUCCESS
                        .with_label_values(&[&subnet_id])
                        .set(0);
                    continue;
                }
            }
        }

        // Export canister data to persist information about the new canisters
        prober_definition.export_canister_data(&Canisters {
            subnet: prober_definition.get_canisters().clone(),
        });

        let mut futures = Vec::new();
        for subnet in subnets {
            let subnet_id = &subnet.subnet_id;
            eprintln!("Executing probe on subnet {}", subnet_id);
            if prober_definition.get_canisters().get(subnet_id).is_none() {
                continue;
            }
            let canister_id =
                Principal::from_text(prober_definition.get_canisters().get(subnet_id).unwrap())
                    .unwrap();
            let nodes = subnet.nodes.clone();
            let subnet_id = subnet.subnet_id.clone();
            let prober_def = prober_definition.clone();
            futures.push(tokio::spawn(async move {
                probe_subnet(nodes, prober_def, subnet_id, canister_id, mainnet).await
            }));
        }
        for future in futures {
            let result = future.await;
            match result {
                Ok(_) => {}
                Err(_) => eprintln!("Probe tasks failed to join"),
            }
        }
        let now = Instant::now();
        // If it is time to refresh canisters, set all subnets to cleanup canisters.
        if now > canister_refresh {
            for subnet in subnets {
                eprintln!("Deleting and recreating new canisters");
                cleanup_canisters.insert(subnet.subnet_id.clone(), true);
                canister_refresh = now + CANISTER_CREATE_INTERVAL;
            }
        }
        prober_definition.reload();
        // Sleep until probe interval expires
        if now < probe_end {
            eprintln!("Sleep until next iteration");
            tokio::time::sleep(probe_end.duration_since(now)).await;
        }
    }
}

#[async_trait]
impl ProberLoader for ProberDefinition {
    fn reload(&mut self) {
        let routes = read_file_data(&self.routes_dir, ROUTES);
        let wallets = read_file_data(&self.wallets_dir, WALLETS);
        if let Ok(initial_routes) = routes {
            self.routes = serde_json::from_value(initial_routes).unwrap()
        }
        if let Ok(initial_wallets) = wallets {
            self.wallets = serde_json::from_value(initial_wallets).unwrap()
        }
    }

    fn get_canisters(&self) -> HashMap<String, String> {
        self.canisters.subnet.clone()
    }

    fn remove_canister(&mut self, subnet: &str) {
        self.canisters.subnet.remove(subnet);
    }

    fn add_canister(&mut self, subnet: String, canister: String) {
        self.canisters.subnet.insert(subnet, canister);
    }

    fn get_wallet(&self, subnet: &str) -> Option<&String> {
        self.wallets.subnet.get(subnet)
    }

    fn get_routes(&self) -> Vec<SubnetRoute> {
        self.routes.subnets.clone()
    }

    fn export_canister_data(&self, canisters: &Canisters) {
        let mut filepath = self.wallets_dir.to_path_buf();
        filepath.push("current.canisters");
        let file = fs::File::create(filepath.to_str().expect("Missing canister filename"))
            .expect("unable to open canister configuration file for write");
        let mut writer = BufWriter::new(&file);
        let routes_json = serde_json::to_string(canisters).expect("failed json conversion");
        writer
            .write_all(routes_json.as_bytes())
            .expect("write failure");
    }

    async fn create_agent_and_waiter(&self, url: &str, mainnet: bool) -> BoxResult<(Agent, Delay)> {
        let url = format!("{}{}", "http://", url);
        let identity =
            ic_agent::identity::BasicIdentity::from_pem_file(&self.identity_path).unwrap();
        let agent = Agent::builder()
            .with_transport(
                ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport::create(url)
                    .unwrap(),
            )
            .with_identity(identity)
            .build()
            .unwrap();
        if !mainnet {
            agent.fetch_root_key().await?;
        }
        let waiter = garcon::Delay::builder()
            .throttle(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(60 * 5))
            .build();
        Ok((agent, waiter))
    }

    async fn create_canister(
        &self,
        url: String,
        wallet_id: String,
        mainnet: bool,
    ) -> Result<Principal, String> {
        let wallet_id =
            Principal::from_text(wallet_id).map_err(|_| "Wallet ID could not be parsed")?;
        let (agent, waiter) = self
            .create_agent_and_waiter(&*url, mainnet)
            .await
            .map_err(|e| format!("Agent could not be created {:?}", e))?;
        let wallet = ic_utils::Canister::builder()
            .with_agent(&agent)
            .with_canister_id(wallet_id)
            .with_interface(ic_utils::interfaces::Wallet)
            .build()
            .unwrap();
        let result = wallet
            .wallet_create_canister(CYCLES, None, None, None, None, waiter.clone())
            .await
            .map_err(|e| format!("Canister creation call failed with err {:?}", e))?;
        let canister_id = result.canister_id;
        let wasm_module = wabt::wat2wasm(COUNTER_CANISTER_WAT).unwrap();

        let install_args = CanisterInstall {
            mode: InstallMode::Install,
            canister_id,
            wasm_module,
            arg: vec![],
        };
        let mgr = ManagementCanister::create(&agent);
        wallet
            .call_forward(
                mgr.update_("install_code").with_arg(install_args).build(),
                0,
            )
            .unwrap()
            .call_and_wait(waiter)
            .await
            .map_err(|e| format!("Canister Installation failed with err {:?}", e))?;
        Ok(canister_id)
    }

    async fn cleanup_old_canisters(
        &self,
        url: String,
        canister: String,
        wallet_canister: String,
        mainnet: bool,
    ) -> Result<(), String> {
        let canister_id =
            Principal::from_text(canister).map_err(|_| "Canister ID could not be parsed")?;
        let wallet_canister =
            Principal::from_text(wallet_canister).map_err(|_| "Wallet ID could not be parsed")?;
        let (agent, waiter) = self
            .create_agent_and_waiter(&*url, mainnet)
            .await
            .map_err(|_| "Agent could not be created")?;
        let wallet = ic_utils::Canister::builder()
            .with_agent(&agent)
            .with_canister_id(wallet_canister)
            .with_interface(ic_utils::interfaces::Wallet)
            .build()
            .unwrap();
        let mgr = ManagementCanister::create(&agent);
        let cycles: u64 = 0;
        wallet
            .call_forward(
                mgr.update_(MgmtMethod::StopCanister.as_ref())
                    .with_arg(In { canister_id })
                    .build(),
                cycles,
            )
            .unwrap()
            .call_and_wait(waiter.clone())
            .await
            .map_err(|_| "Canister could not be stopped")?;
        wallet
            .call_forward(
                mgr.update_(MgmtMethod::DeleteCanister.as_ref())
                    .with_arg(In { canister_id })
                    .build(),
                cycles,
            )
            .unwrap()
            .call_and_wait(waiter)
            .await
            .map_err(|_| "Canister could not be uninstalled")?;
        Ok(())
    }

    // Probes a canister on a given node. Returns Ok() if query and update succeed.
    // Returns true if update succeeds logically (computation is an expected value).
    async fn execute_probe(
        &self,
        url: &str,
        canister_id: &Principal,
        mainnet: bool,
    ) -> Result<(), String> {
        let (agent, waiter): (Agent, Delay) = self
            .create_agent_and_waiter(url, mainnet)
            .await
            .map_err(|_| "Couldn't create agent")?;
        let result = agent
            .query(canister_id, "read")
            .with_arg(vec![0; 100])
            .call()
            .await;
        let read_result = u32::from_le_bytes(
            result
                .map_err(|_| "could not convert result to u32")?
                .try_into()
                .map_err(|_| "could not convert result to u32")?,
        );
        eprintln!("READ");
        eprintln!("{:?}", read_result);
        let result = agent
            .update(canister_id, "write")
            .with_arg(vec![0; 100])
            .call_and_wait(waiter)
            .await;
        let write_result = u32::from_le_bytes(
            result
                .map_err(|_| "could not convert result to u32")?
                .try_into()
                .map_err(|_| "could not convert result to u32")?,
        );
        eprintln!("UPDATE");
        eprintln!("{:?}", write_result);
        if (read_result + 1) != write_result {
            return Err("Update call result did not match expected result.".to_string());
        }
        Ok(())
    }
}

fn read_file_data(dir: &Path, file_type: &str) -> BoxResult<serde_json::Value> {
    let dir = fs::read_dir(dir)?;
    let mut entries: Vec<PathBuf> = dir
        .filter(Result::is_ok)
        .map(|e| e.unwrap().path())
        .filter(|e| e.to_str().unwrap().ends_with(file_type))
        .collect();
    entries.sort();
    let file_name = entries.last().ok_or("No file found")?;
    eprintln!("filename: {:?}", file_name);
    let file = fs::File::open(file_name).expect("file should open read only");
    let json: serde_json::Value =
        serde_json::from_reader(file).expect("file should be proper JSON");
    Ok(json)
}

async fn probe_subnet(
    nodes: Vec<NodeRoute>,
    prober_definition: Box<dyn ProberLoader>,
    subnet_id: String,
    canister_id: Principal,
    mainnet: bool,
) {
    for node in nodes {
        let url = &node.socket_addr;
        let instant = Instant::now();
        let prober_def = prober_definition.clone();
        let probe_result = prober_def.execute_probe(url, &canister_id, mainnet).await;
        NODE_PROBE_LATENCY
            .with_label_values(&[&*node.node_id])
            .set(instant.elapsed().as_secs() as i64);
        PROBES_COMPLETED.inc();
        // If there is a probe error, probe fails so emit a 1 metric.
        // If success, probe succeeded, so emit a 0 metric.
        let failure_metric = match probe_result {
            Ok(_) => 0,
            Err(_) => 1,
        };
        NODE_PROBE_FAILURE
            .with_label_values(&[&*node.node_id])
            .set(failure_metric);
        SUBNET_PROBE_FAILURE
            .with_label_values(&[&*subnet_id])
            .set(failure_metric);
        // Inverse failure metric for success metrics.
        if failure_metric == 1 {
            NODE_PROBE_SUCCESS
                .with_label_values(&[&*node.node_id])
                .set(0);
        } else {
            NODE_PROBE_SUCCESS
                .with_label_values(&[&*node.node_id])
                .set(1);
        }
    }
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
    name.append_entry_by_nid(Nid::COMMONNAME, "boundary-node-prober.dfinity.org")
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
    use super::*;

    #[derive(Clone)]
    struct FakeProber {
        canisters: Canisters,
        wallets: Canisters,
        routes: Routes,
    }

    #[async_trait]
    impl ProberLoader for FakeProber {
        fn reload(&mut self) {}

        fn get_canisters(&self) -> HashMap<String, String> {
            self.canisters.subnet.clone()
        }

        fn remove_canister(&mut self, subnet: &str) {
            self.canisters.subnet.remove(subnet);
        }

        fn add_canister(&mut self, subnet: String, canister: String) {
            self.canisters.subnet.insert(subnet, canister);
        }

        fn get_wallet(&self, subnet: &str) -> Option<&String> {
            self.wallets.subnet.get(subnet)
        }

        fn get_routes(&self) -> Vec<SubnetRoute> {
            self.routes.subnets.clone()
        }

        fn export_canister_data(&self, _canisters: &Canisters) {}

        async fn create_agent_and_waiter(
            &self,
            url: &str,
            _mainnet: bool,
        ) -> BoxResult<(Agent, Delay)> {
            let url = format!("{}{}", "http://", url);
            let agent = Agent::builder()
                .with_transport(
                    ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport::create(url)
                        .unwrap(),
                )
                .build()
                .unwrap();
            let waiter = garcon::Delay::builder()
                .throttle(std::time::Duration::from_millis(500))
                .timeout(std::time::Duration::from_secs(60 * 5))
                .build();
            Ok((agent, waiter))
        }

        async fn create_canister(
            &self,
            _url: String,
            _wallet_id: String,
            _mainnet: bool,
        ) -> Result<Principal, String> {
            Ok(Principal::management_canister())
        }

        async fn cleanup_old_canisters(
            &self,
            _url: String,
            _canister: String,
            _wallet_canister: String,
            _mainnet: bool,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn execute_probe(
            &self,
            _url: &str,
            _canister_id: &Principal,
            _mainnet: bool,
        ) -> Result<(), String> {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        }
    }

    fn create_mock_prober(sample_principal: &str) -> Box<dyn ProberLoader> {
        let canisters = HashMap::new();
        let canisters = Canisters { subnet: canisters };
        let mut wallets = HashMap::new();
        wallets.insert(sample_principal.to_string(), sample_principal.to_string());
        let wallets = Canisters { subnet: wallets };

        let node_route = NodeRoute {
            node_id: sample_principal.to_string(),
            socket_addr: "example.com".parse().unwrap(),
            tls_certificate_pem: "".parse().unwrap(),
        };

        let subnet = SubnetRoute {
            subnet_id: sample_principal.to_string(),
            nodes: vec![node_route],
        };

        let routes = Routes {
            registry_version: 1,
            nns_subnet_id: sample_principal.to_string(),
            canister_routes: vec![],
            subnets: vec![subnet],
        };

        Box::new(FakeProber {
            canisters,
            wallets,
            routes,
        })
    }

    #[tokio::test]
    async fn event_loop_test() {
        let sample_principal = Principal::management_canister().to_text();
        let mock_prober = create_mock_prober(&sample_principal);
        tokio::spawn(async move {
            start_probe_event_loop(mock_prober, false).await;
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            NODE_PROBE_SUCCESS
                .get_metric_with_label_values(&[&sample_principal])
                .unwrap()
                .get(),
            1
        );
        assert_eq!(PROBES_COMPLETED.get(), 1);
        assert_eq!(
            CREATE_CANISTER_SUCCESS
                .get_metric_with_label_values(&[&sample_principal])
                .unwrap()
                .get(),
            1
        );
        assert_eq!(
            CREATE_CANISTER_FAILURE
                .get_metric_with_label_values(&[&sample_principal])
                .unwrap()
                .get(),
            0
        );
        assert!(
            NODE_PROBE_LATENCY
                .get_metric_with_label_values(&[&sample_principal])
                .unwrap()
                .get()
                > 0
        )
    }
}
