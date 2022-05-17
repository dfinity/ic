use std::{
    cmp::{max, min},
    collections::HashMap,
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use candid::CandidType;
use garcon::Delay;
use ic_agent::{
    agent::http_transport::ReqwestHttpReplicaV2Transport, ic_types::Principal,
    identity::BasicIdentity, Agent,
};
use ic_utils::{
    call::AsyncCall,
    interfaces,
    interfaces::{
        management_canister::{
            builders::{CanisterInstall, InstallMode},
            MgmtMethod,
        },
        wallet::CreateResult,
        ManagementCanister,
    },
    Canister,
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{handler::Handler, routing::get, Extension, Router};
use clap::Parser;
use futures::{future::TryFutureExt, stream::FuturesUnordered};
use glob::glob;
use hyper::{Body, Request, Response, StatusCode};
use mockall::automock;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::{global, sdk::Resource, KeyValue};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use serde::Deserialize;
use tokio::{task, time::Instant};
use tracing::info;

mod metrics;
use metrics::{MetricParams, WithMetrics};

const MILLISECOND: Duration = Duration::from_millis(1);
const MINUTE: Duration = Duration::from_secs(60);

const BILLION: u64 = 1_000_000_000;

const CANISTER_WAT: &[u8] = include_bytes!("canister.wat");

#[derive(Parser)]
#[clap(name = "Prober")]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "routes")]
    routes_dir: PathBuf,

    #[clap(long, default_value = "wallets.json")]
    wallets_path: PathBuf,

    #[clap(long, default_value = "identity.pem")]
    identity_path: PathBuf,

    #[clap(long)]
    root_key_path: Option<PathBuf>,

    #[clap(long, default_value_t = 200 * BILLION)]
    canister_cycles_amount: u64,

    #[clap(long, default_value = "24h")]
    canister_ttl: humantime::Duration,

    #[clap(long, default_value = "1m")]
    probe_interval: humantime::Duration,

    #[clap(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("failed to set global subscriber");

    let exporter = opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("service", "prober")]))
        .init();
    let meter = global::meter("prober");

    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { exporter }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let loader = ContextLoader::new(cli.routes_dir.clone(), cli.wallets_path.clone());
    let loader = WithMetrics(loader, MetricParams::new(&meter, "load"));

    let creator = Creator::new(cli.canister_cycles_amount);
    let creator = WithMetrics(creator, MetricParams::new(&meter, "create"));

    let wasm_module = wabt::wat2wasm(CANISTER_WAT).context("failed convert wat to wasm")?;

    let installer = Installer::new(wasm_module);
    let installer = WithMetrics(installer, MetricParams::new(&meter, "install"));

    let prober = Prober {};
    let prober = WithMetrics(prober, MetricParams::new(&meter, "probe"));

    let stopper = Stopper {};
    let stopper = WithMetrics(stopper, MetricParams::new(&meter, "stop"));

    let deleter = Deleter {};
    let deleter = WithMetrics(deleter, MetricParams::new(&meter, "delete"));

    let canister_ops = CanisterOps {
        creator,
        installer,
        prober,
        stopper,
        deleter,
    };

    let f = File::open(cli.identity_path).context("failed to open identity file")?;
    let identity = BasicIdentity::from_pem(f).context("failed to create basic identity")?;

    let root_key = cli
        .root_key_path
        .map(fs::read)
        .transpose()
        .context("failed to open root key")?;

    let create_agent = create_agent_fn(Arc::new(identity), root_key);

    let runner = Runner::new(
        loader,
        create_agent,
        canister_ops,
        cli.canister_ttl.into(),
        cli.probe_interval.into(),
    );

    let runner = WithMetrics(runner, MetricParams::new(&meter, "run"));
    let runner = WithThrottle(runner, ThrottleParams::new(1 * MINUTE));
    let mut runner = runner;

    info!(
        msg = "Starting prober",
        routes = cli.routes_dir.to_str(),
        wallets = cli.wallets_path.to_str(),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let _ = tokio::try_join!(
        task::spawn(async move {
            loop {
                let _ = runner.run().await;
            }
        }),
        task::spawn(
            axum::Server::bind(&cli.metrics_addr)
                .serve(metrics_router.into_make_service())
                .map_err(|err| anyhow!("server failed: {:?}", err))
        )
    )
    .context("prober failed to run")?;

    Ok(())
}

#[async_trait]
trait Run: Sync + Send {
    async fn run(&mut self) -> Result<(), Error>;
}

struct CanisterOps<C, I, P, S, D> {
    creator: C,
    installer: I,
    prober: P,
    stopper: S,
    deleter: D,
}

struct Runner<L, C, I, P, S, D> {
    loader: Arc<L>,
    create_agent: Box<dyn CreateAgentFn>,
    canister_ops: Arc<CanisterOps<C, I, P, S, D>>,
    canister_ttl: Duration,
    probe_interval: Duration,
}

impl<L, C, I, P, S, D> Runner<L, C, I, P, S, D> {
    fn new(
        loader: L,
        create_agent: impl CreateAgentFn,
        canister_ops: CanisterOps<C, I, P, S, D>,
        canister_ttl: Duration,
        probe_interval: Duration,
    ) -> Self {
        Self {
            loader: Arc::new(loader),
            create_agent: Box::new(create_agent),
            canister_ops: Arc::new(canister_ops),
            canister_ttl,
            probe_interval,
        }
    }
}

#[async_trait]
impl<L, C, I, P, S, D> Run for Runner<L, C, I, P, S, D>
where
    L: Load,
    C: Create,
    I: Install,
    P: Probe,
    S: Stop,
    D: Delete,
{
    async fn run(&mut self) -> Result<(), Error> {
        let ServiceContext { wallets, routes } = self
            .loader
            .load()
            .await
            .context("failed to load service context")?;

        let futs = FuturesUnordered::new();

        for (subnet_id, wallet_id) in wallets.subnet {
            let canister_ops = Arc::clone(&self.canister_ops);
            let canister_ttl = self.canister_ttl;
            let probe_interval = self.probe_interval;

            // Find the subnet routes for the given wallet
            let subnet = routes
                .subnets
                .iter()
                .find(|subnet| subnet.subnet_id == subnet_id);

            let subnet = match subnet {
                Some(subnet) => subnet,
                None => continue,
            };

            // Create an agent for each node in the subnet
            let agents = subnet
                .nodes
                .iter()
                .cloned()
                .map(&mut self.create_agent)
                .collect::<Result<Vec<(String, String, Agent)>, Error>>()
                .context("failed to create agent")?;

            futs.push(task::spawn(async move {
                use opentelemetry::trace::FutureExt;

                let (node_id, socket_addr, agent) = &agents[0];

                let _ctx = opentelemetry::Context::current_with_baggage(vec![
                    KeyValue::new("subnet_id", subnet_id.to_string()),
                    KeyValue::new("node_id", node_id.to_string()),
                    KeyValue::new("socket_addr", socket_addr.to_string()),
                ]);

                let canister_id = canister_ops
                    .creator
                    .create(agent, &wallet_id)
                    .with_context(_ctx.clone())
                    .await?;

                canister_ops
                    .installer
                    .install(agent, &wallet_id, canister_id)
                    .with_context(_ctx.clone())
                    .await?;

                let start_time = Instant::now();
                let end_time = start_time + canister_ttl;

                for (node_id, socket_addr, agent) in agents.iter().cycle() {
                    let _ctx = opentelemetry::Context::current_with_baggage(vec![
                        KeyValue::new("subnet_id", subnet_id.to_string()),
                        KeyValue::new("node_id", node_id.to_string()),
                        KeyValue::new("socket_addr", socket_addr.to_string()),
                    ]);

                    canister_ops
                        .prober
                        .probe(agent, canister_id)
                        .with_context(_ctx.clone())
                        .await?;

                    tokio::time::sleep(max(
                        Duration::ZERO,
                        min(probe_interval, end_time - Instant::now()),
                    ))
                    .await;

                    if Instant::now() > end_time {
                        break;
                    }
                }

                canister_ops
                    .stopper
                    .stop(agent, &wallet_id, canister_id)
                    .with_context(_ctx.clone())
                    .await?;

                canister_ops
                    .deleter
                    .delete(agent, &wallet_id, canister_id)
                    .with_context(_ctx.clone())
                    .await?;

                let ret: Result<(), Error> = Ok(());
                ret
            }));
        }

        // TODO(or.ricon): runner should return error if an error was encountered
        // or runner should return a vector of results
        // should also flatten JoinErrors ?
        for fut in futs {
            let _ = fut.await?;
        }

        Ok(())
    }
}

trait CreateAgentFn:
    'static + FnMut(NodeRoute) -> Result<(String, String, Agent), Error> + Sync + Send
{
}
impl<F: 'static + FnMut(NodeRoute) -> Result<(String, String, Agent), Error> + Sync + Send>
    CreateAgentFn for F
{
}

fn create_agent_fn(identity: Arc<BasicIdentity>, root_key: Option<Vec<u8>>) -> impl CreateAgentFn {
    move |node_route: NodeRoute| {
        let NodeRoute {
            node_id,
            socket_addr,
        } = node_route;

        let transport = ReqwestHttpReplicaV2Transport::create(format!("http://{}", socket_addr))
            .context("failed to create transport")?;

        let identity = Arc::clone(&identity);

        let agent = Agent::builder()
            .with_transport(transport)
            .with_arc_identity(identity)
            .build()
            .context("failed to build agent")?;

        if let Some(root_key) = &root_key {
            agent
                .set_root_key(root_key.clone())
                .context("failed to set root key")?;
        }

        Ok((node_id, socket_addr, agent))
    }
}

#[derive(Clone)]
struct MetricsHandlerArgs {
    exporter: PrometheusExporter,
}

async fn metrics_handler(
    Extension(MetricsHandlerArgs { exporter }): Extension<MetricsHandlerArgs>,
    _: Request<Body>,
) -> Response<Body> {
    let metric_families = exporter.registry().gather();

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}

#[derive(Debug, Deserialize, PartialEq)]
struct Wallets {
    subnet: HashMap<String, String>,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
struct NodeRoute {
    node_id: String,
    socket_addr: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct SubnetRoute {
    subnet_id: String,
    nodes: Vec<NodeRoute>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Routes {
    subnets: Vec<SubnetRoute>,
}

#[derive(Debug, PartialEq)]
struct ServiceContext {
    wallets: Wallets,
    routes: Routes,
}

#[automock]
#[async_trait]
trait Load: Sync + Send {
    async fn load(&self) -> Result<ServiceContext, Error>;
}

struct ContextLoader {
    routes_dir: PathBuf,
    wallets_path: PathBuf,
}

impl ContextLoader {
    fn new(routes_dir: PathBuf, wallets_path: PathBuf) -> Self {
        Self {
            routes_dir,
            wallets_path,
        }
    }
}

#[async_trait]
impl Load for ContextLoader {
    async fn load(&self) -> Result<ServiceContext, Error> {
        // Wallets
        let f = File::open(&self.wallets_path)
            .with_context(|| format!("failed to open file {}", &self.wallets_path.display()))?;
        let wallets: Wallets = serde_json::from_reader(f).context("failed to parse json")?;

        // Routes
        let glob_pattern = Path::new(&self.routes_dir).join("*.routes");

        let mut paths: Vec<_> = glob(glob_pattern.to_str().unwrap())
            .context("failed to read glob pattern")?
            .flat_map(Result::ok)
            .collect();

        paths.sort();

        let path = paths.last();
        if path.is_none() {
            return Err(anyhow!("no routes file"));
        }
        let path = path.unwrap();

        let f = File::open(&path)
            .with_context(|| format!("failed to open file {}", &path.display()))?;
        let routes: Routes = serde_json::from_reader(f).context("failed to parse json")?;

        Ok(ServiceContext { wallets, routes })
    }
}

#[automock]
#[async_trait]
trait Create: 'static + Sync + Send {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error>;
}

struct Creator {
    canister_cycles_amount: u64,
}

impl Creator {
    fn new(canister_cycles_amount: u64) -> Self {
        Self {
            canister_cycles_amount,
        }
    }
}

#[async_trait]
impl Create for Creator {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error> {
        let wallet = Canister::builder()
            .with_agent(agent)
            .with_canister_id(wallet_id)
            .with_interface(interfaces::Wallet)
            .build()
            .context("failed to build wallet")?;

        let waiter = Delay::builder()
            .throttle(500 * MILLISECOND)
            .timeout(5 * MINUTE)
            .build();

        let CreateResult { canister_id } = wallet
            .wallet_create_canister(
                self.canister_cycles_amount, // cycles
                None,                        // controllers
                None,                        // compute_allocation
                None,                        // memory_allocation
                None,                        // freezing_threshold
                waiter,                      // waiter
            )
            .await
            .context("failed to create canister")?;

        Ok(canister_id)
    }
}

#[automock]
#[async_trait]
trait Install: 'static + Sync + Send {
    async fn install(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error>;
}

struct Installer {
    wasm_module: Vec<u8>,
}

impl Installer {
    fn new(wasm_module: Vec<u8>) -> Self {
        Self { wasm_module }
    }
}

#[async_trait]
impl Install for Installer {
    async fn install(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let mgmt_canister = ManagementCanister::create(agent);

        let install_call = mgmt_canister
            .update_(MgmtMethod::InstallCode.as_ref())
            .with_arg(CanisterInstall {
                mode: InstallMode::Install,
                canister_id,
                wasm_module: self.wasm_module.clone(),
                arg: vec![],
            })
            .build();

        let wallet = Canister::builder()
            .with_agent(agent)
            .with_canister_id(wallet_id)
            .with_interface(interfaces::Wallet)
            .build()
            .context("failed to build wallet")?;

        let install_call = wallet
            .call_forward(install_call, 0)
            .context("failed to forward call")?;

        let waiter = Delay::builder()
            .throttle(500 * MILLISECOND)
            .timeout(5 * MINUTE)
            .build();

        install_call
            .call_and_wait(waiter)
            .await
            .context("failed to install canister")?;

        Ok(())
    }
}

#[automock]
#[async_trait]
trait Probe: 'static + Sync + Send {
    async fn probe(&self, agent: &Agent, canister_id: Principal) -> Result<(), Error>;
}

struct Prober {}

#[async_trait]
impl Probe for Prober {
    async fn probe(&self, agent: &Agent, canister_id: Principal) -> Result<(), Error> {
        let read_result = agent
            .query(&canister_id, "read")
            .with_arg(vec![0; 100])
            .call()
            .await
            .context("failed to query canister")?;

        let read_result: [u8; 4] = read_result
            .try_into()
            .map_err(|_| anyhow!("failed to extract read result"))?;

        let read_result = u32::from_le_bytes(read_result);

        let waiter = Delay::builder()
            .throttle(500 * MILLISECOND)
            .timeout(5 * MINUTE)
            .build();

        let write_result = agent
            .update(&canister_id, "write")
            .with_arg(vec![0; 100])
            .call_and_wait(waiter)
            .await
            .context("failed to update canister")?;

        let write_result: [u8; 4] = write_result
            .try_into()
            .map_err(|_| anyhow!("failed to extract write result"))?;

        let write_result = u32::from_le_bytes(write_result);

        if write_result != read_result + 1 {
            return Err(anyhow!(
                "wrong output: {} != {}",
                write_result,
                read_result + 1
            ));
        }

        Ok(())
    }
}

#[automock]
#[async_trait]
trait Stop: 'static + Sync + Send {
    async fn stop(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error>;
}

struct Stopper {}

#[async_trait]
impl Stop for Stopper {
    async fn stop(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let mgmt_canister = ManagementCanister::create(agent);

        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        let stop_call = mgmt_canister
            .update_(MgmtMethod::StopCanister.as_ref())
            .with_arg(In { canister_id })
            .build();

        let wallet = Canister::builder()
            .with_agent(agent)
            .with_canister_id(wallet_id)
            .with_interface(interfaces::Wallet)
            .build()
            .context("failed to build wallet")?;

        let stop_call = wallet
            .call_forward(stop_call, 0)
            .context("failed to forward call")?;

        let waiter = Delay::builder()
            .throttle(500 * MILLISECOND)
            .timeout(5 * MINUTE)
            .build();

        stop_call
            .call_and_wait(waiter)
            .await
            .context("failed to stop canister")?;

        Ok(())
    }
}

#[automock]
#[async_trait]
trait Delete: 'static + Sync + Send {
    async fn delete(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error>;
}

struct Deleter {}

#[async_trait]
impl Delete for Deleter {
    async fn delete(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let mgmt_canister = ManagementCanister::create(agent);

        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        let delete_call = mgmt_canister
            .update_(MgmtMethod::DeleteCanister.as_ref())
            .with_arg(In { canister_id })
            .build();

        let wallet = Canister::builder()
            .with_agent(agent)
            .with_canister_id(wallet_id)
            .with_interface(interfaces::Wallet)
            .build()
            .context("failed to build wallet")?;

        let delete_call = wallet
            .call_forward(delete_call, 0)
            .context("failed to forward call")?;

        let waiter = Delay::builder()
            .throttle(500 * MILLISECOND)
            .timeout(5 * MINUTE)
            .build();

        delete_call
            .call_and_wait(waiter)
            .await
            .context("failed to delete canister")?;

        Ok(())
    }
}

struct ThrottleParams {
    throttle_duration: Duration,
    next_time: Option<Instant>,
}

impl ThrottleParams {
    fn new(throttle_duration: Duration) -> Self {
        Self {
            throttle_duration,
            next_time: None,
        }
    }
}

struct WithThrottle<T>(T, ThrottleParams);

#[async_trait]
impl<T: Run + Send + Sync> Run for WithThrottle<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let current_time = Instant::now();
        let next_time = self.1.next_time.unwrap_or(current_time);

        if next_time > current_time {
            tokio::time::sleep(next_time - current_time).await;
        }
        self.1.next_time = Some(Instant::now() + self.1.throttle_duration);

        self.0.run().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mockall::predicate;

    #[tokio::test]
    async fn it_loads() -> Result<(), Error> {
        use indoc::indoc;
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;

        // Create route files
        let routes_dir = tempdir()?;

        for (name, content) in &[
            ("001.routes", "{}"),
            ("002.routes", "{}"),
            (
                "003.routes",
                indoc! {r#"{
                    "canister_routes": [{ "subnet_id": "subnet-1" }],
                    "subnets": [
                        {
                            "subnet_id": "subnet-1",
                            "nodes": [{ "node_id": "node-1", "socket_addr": "socket-1" }]
                        }
                    ]
                }"#},
            ),
        ] {
            let file_path = routes_dir.path().join(name);
            let mut file = File::create(file_path)?;
            writeln!(file, "{}", content)?;
        }

        // Create wallets file
        let wallets_dir = tempdir()?;

        let file_path = wallets_dir.path().join("wallets.json");
        let mut file = File::create(file_path)?;
        writeln!(
            file,
            "{}",
            indoc! {r#"{
                "subnet": {
                    "subnet-1": "wallet-1"
                }
            }"#}
        )?;

        // Create loader
        let loader = ContextLoader::new(
            routes_dir.path().to_path_buf(),
            wallets_dir.path().join("wallets.json"),
        );

        let out = loader.load().await?;
        assert_eq!(
            out,
            ServiceContext {
                routes: Routes {
                    subnets: vec![SubnetRoute {
                        subnet_id: String::from("subnet-1"),
                        nodes: vec![NodeRoute {
                            node_id: String::from("node-1"),
                            socket_addr: String::from("socket-1"),
                        }],
                    }],
                },
                wallets: Wallets {
                    subnet: HashMap::from([(String::from("subnet-1"), String::from("wallet-1"))]),
                },
            }
        );

        Ok(())
    }

    #[tokio::test]
    async fn it_runs() -> Result<(), Error> {
        let mut loader = MockLoad::new();
        loader.expect_load().times(1).returning(|| {
            Ok(ServiceContext {
                routes: Routes {
                    subnets: vec![SubnetRoute {
                        subnet_id: String::from("subnet-1"),
                        nodes: vec![NodeRoute {
                            node_id: String::from("node-1"),
                            socket_addr: String::from("socket-1"),
                        }],
                    }],
                },
                wallets: Wallets {
                    subnet: HashMap::from([(String::from("subnet-1"), String::from("wallet-1"))]),
                },
            })
        });

        let mut creator = MockCreate::new();
        creator
            .expect_create()
            .times(1)
            .with(
                predicate::always(),       // agent
                predicate::eq("wallet-1"), // wallet_id
            )
            .returning(|_, _| {
                Ok(Principal::from_text(String::from(
                    "rwlgt-iiaaa-aaaaa-aaaaa-cai",
                ))?)
            });

        let mut installer = MockInstall::new();
        installer
            .expect_install()
            .times(1)
            .with(
                predicate::always(),       // agent
                predicate::eq("wallet-1"), // wallet_id
                predicate::function(|id: &Principal| {
                    id.to_string() == "rwlgt-iiaaa-aaaaa-aaaaa-cai"
                }), // canister_id
            )
            .returning(|_, _, _| Ok(()));

        let mut prober = MockProbe::new();
        prober
            .expect_probe()
            // .times(1)
            .with(
                predicate::always(), // agent
                predicate::function(|id: &Principal| {
                    id.to_string() == "rwlgt-iiaaa-aaaaa-aaaaa-cai"
                }), // canister_id
            )
            .returning(|_, _| Ok(()));

        let mut stopper = MockStop::new();
        stopper
            .expect_stop()
            .times(1)
            .with(
                predicate::always(),       // agent
                predicate::eq("wallet-1"), // wallet_id
                predicate::function(|id: &Principal| {
                    id.to_string() == "rwlgt-iiaaa-aaaaa-aaaaa-cai"
                }), // canister_id
            )
            .returning(|_, _, _| Ok(()));

        let mut deleter = MockDelete::new();
        deleter
            .expect_delete()
            .times(1)
            .with(
                predicate::always(),       // agent
                predicate::eq("wallet-1"), // wallet_id
                predicate::function(|id: &Principal| {
                    id.to_string() == "rwlgt-iiaaa-aaaaa-aaaaa-cai"
                }), // canister_id
            )
            .returning(|_, _, _| Ok(()));

        let create_agent = |route: NodeRoute| -> Result<(String, String, Agent), Error> {
            assert_eq!(route.node_id, "node-1");
            assert_eq!(route.socket_addr, "socket-1");

            let transport = ReqwestHttpReplicaV2Transport::create("http://test")
                .context("failed to create transport")?;

            let agent = Agent::builder().with_transport(transport).build()?;

            Ok((route.node_id, route.socket_addr, agent))
        };

        let mut runner = Runner::new(
            loader,       // loader
            create_agent, // create_agent
            CanisterOps {
                creator,
                installer,
                prober,
                stopper,
                deleter,
            },
            Duration::ZERO, // canister_ttl
            1 * MINUTE,     // probe_interval
        );

        runner.run().await?;

        Ok(())
    }
}
