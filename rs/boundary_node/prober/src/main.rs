use std::{
    collections::HashMap,
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use candid::{CandidType, Principal};
use ic_agent::{
    agent::http_transport::reqwest_transport::ReqwestTransport, identity::BasicIdentity, Agent,
};
use ic_utils::{
    canister::Argument,
    interfaces,
    interfaces::{
        management_canister::{
            builders::{CanisterInstall, InstallMode},
            MgmtMethod,
        },
        wallet::CreateResult,
    },
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{body::Body, handler::Handler, routing::get, Extension, Router};
use clap::Parser;
use futures::stream::FuturesUnordered;
use glob::glob;
use hyper::{Request, Response, StatusCode};
use mockall::automock;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::{metrics::MeterProvider, KeyValue};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::metrics::MeterProviderBuilder;
use prometheus::{labels, Encoder as PrometheusEncoder, Registry, TextEncoder};
use serde::Deserialize;
use tokio::{net::TcpListener, task, time::Instant};
use tracing::info;

mod metrics;
use metrics::{MetricParams, WithMetrics};

mod retry;
use retry::WithRetry;

const SERVICE_NAME: &str = "prober";

const MINUTE: Duration = Duration::from_secs(60);

const BILLION: u128 = 1_000_000_000;

const CANISTER_WAT: &str = include_str!("canister.wat");

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
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
    canister_cycles_amount: u128,

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

    // Metrics
    let registry: Registry = Registry::new_custom(
        None,
        Some(labels! {"service".into() => SERVICE_NAME.into()}),
    )
    .unwrap();
    let exporter = exporter().with_registry(registry.clone()).build()?;
    let provider = MeterProviderBuilder::default()
        .with_reader(exporter)
        .build();
    let meter = provider.meter(SERVICE_NAME);

    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { registry }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let loader = RoutesLoader::new(cli.routes_dir.clone());
    let loader = WithMetrics(loader, MetricParams::new(&meter, SERVICE_NAME, "load"));
    let loader = Arc::new(loader);

    let f = File::open(&cli.wallets_path)
        .with_context(|| format!("failed to open file {}", &cli.wallets_path.display()))?;
    let wallets: Wallets = serde_json::from_reader(f).context("failed to parse json")?;

    let creator = Creator::new(cli.canister_cycles_amount);
    let creator = WithMetrics(
        creator,
        MetricParams::new(&meter, SERVICE_NAME, "canister_op"),
    );
    let creator = WithRetry::new(creator, 1);

    let wasm_module = wat::parse_str(CANISTER_WAT).context("failed convert wat to wasm")?;

    let installer = Installer::new(wasm_module);
    let installer = WithMetrics(
        installer,
        MetricParams::new(&meter, SERVICE_NAME, "canister_op"),
    );
    let installer = WithRetry::new(installer, 1);

    let prober = Prober {};
    let prober = WithMetrics(
        prober,
        MetricParams::new(&meter, SERVICE_NAME, "canister_op"),
    );

    let stopper = Stopper {};
    let stopper = WithMetrics(
        stopper,
        MetricParams::new(&meter, SERVICE_NAME, "canister_op"),
    );
    let stopper = WithRetry::new(stopper, 1);

    let deleter = Deleter {};
    let deleter = WithMetrics(
        deleter,
        MetricParams::new(&meter, SERVICE_NAME, "canister_op"),
    );
    let deleter = WithRetry::new(deleter, 1);

    let canister_ops = Arc::new(CanisterOps {
        creator,
        installer,
        prober,
        stopper,
        deleter,
    });

    let f = File::open(cli.identity_path).context("failed to open identity file")?;
    let identity = Arc::new(BasicIdentity::from_pem(f).context("failed to create basic identity")?);

    let root_key = cli
        .root_key_path
        .map(fs::read)
        .transpose()
        .context("failed to open root key")?;

    info!(
        msg = "Starting prober",
        routes = cli.routes_dir.to_str(),
        wallets = cli.wallets_path.to_str(),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let futs = FuturesUnordered::new();

    for (subnet_id, wallet_id) in wallets.subnet.into_iter() {
        let st_runner = SubnetTestRunner::new(
            loader.clone(),
            create_agent_fn(identity.clone(), root_key.clone()),
            canister_ops.clone(),
            cli.canister_ttl.into(),
            cli.probe_interval.into(),
        );
        let st_runner = WithMetrics(st_runner, MetricParams::new(&meter, SERVICE_NAME, "run"));
        let mut st_runner = WithThrottle(st_runner, ThrottleParams::new(1 * MINUTE));

        futs.push(task::spawn(async move {
            let context = TestContext {
                wallet_id,
                subnet_id,
            };
            loop {
                let _ = st_runner.run(&context).await;
            }
        }));
    }

    futs.push(task::spawn(async move {
        let listener = TcpListener::bind(&cli.metrics_addr).await.unwrap();
        axum::serve(listener, metrics_router.into_make_service())
            .await
            .map_err(|err| anyhow!("server failed: {:?}", err))
    }));

    for fut in futs {
        let _ = fut.await?;
    }

    Ok(())
}

#[async_trait]
trait Run: Sync + Send {
    async fn run(&mut self, context: &TestContext) -> Result<(), Error>;
}

struct CanisterOps<C, I, P, S, D> {
    creator: C,
    installer: I,
    prober: P,
    stopper: S,
    deleter: D,
}

struct SubnetTestRunner<L, C, I, P, S, D> {
    loader: Arc<L>,
    create_agent: Box<dyn CreateAgentFn>,
    canister_ops: Arc<CanisterOps<C, I, P, S, D>>,
    canister_ttl: Duration,
    probe_interval: Duration,
}

impl<L, C, I, P, S, D> SubnetTestRunner<L, C, I, P, S, D> {
    fn new(
        loader: Arc<L>,
        create_agent: impl CreateAgentFn,
        canister_ops: Arc<CanisterOps<C, I, P, S, D>>,
        canister_ttl: Duration,
        probe_interval: Duration,
    ) -> Self {
        Self {
            loader,
            create_agent: Box::new(create_agent),
            canister_ops,
            canister_ttl,
            probe_interval,
        }
    }
}

#[async_trait]
impl<L, C, I, P, S, D> Run for SubnetTestRunner<L, C, I, P, S, D>
where
    L: Load,
    C: Create,
    I: Install,
    P: Probe,
    S: Stop,
    D: Delete,
{
    async fn run(&mut self, context: &TestContext) -> Result<(), Error> {
        // Create an agent for each node in the subnet
        use opentelemetry::trace::FutureExt;

        let routes = self.loader.load().await?;

        let subnet = routes
            .subnets
            .iter()
            .find(|subnet| subnet.subnet_id == context.subnet_id)
            .ok_or_else(|| anyhow!("Subnet not found"))?;

        let agents = subnet
            .nodes
            .iter()
            .cloned()
            .map(&self.create_agent)
            .collect::<Result<Vec<(String, String, Agent)>, Error>>()
            .context("failed to create agent")?;

        let subnet_id = context.subnet_id.as_str();
        let canister_ops = Arc::clone(&self.canister_ops);
        let wallet_id = context.wallet_id.as_str();

        let (node_id, socket_addr, agent) = &agents[0];

        let _ctx = opentelemetry::Context::current_with_baggage(vec![
            KeyValue::new("subnet_id", subnet_id.to_string()),
            KeyValue::new("node_id", node_id.to_string()),
            KeyValue::new("socket_addr", socket_addr.to_string()),
        ]);

        let canister_id = canister_ops
            .creator
            .create(agent, wallet_id)
            .with_context(_ctx.clone())
            .await?;

        canister_ops
            .installer
            .install(agent, wallet_id, canister_id)
            .with_context(_ctx.clone())
            .await?;

        let start_time = Instant::now();
        let end_time = start_time + self.canister_ttl;

        for (node_id, socket_addr, agent) in agents.iter().cycle() {
            let _ctx = opentelemetry::Context::current_with_baggage(vec![
                KeyValue::new("subnet_id", subnet_id.to_string()),
                KeyValue::new("node_id", node_id.to_string()),
                KeyValue::new("socket_addr", socket_addr.to_string()),
            ]);

            // Continue probing continuously, even if probing fails
            let _ = canister_ops
                .prober
                .probe(agent, canister_id)
                .with_context(_ctx.clone())
                .await;

            tokio::time::sleep(
                self.probe_interval
                    .clamp(Duration::ZERO, end_time - Instant::now()),
            )
            .await;

            if Instant::now() > end_time {
                break;
            }
        }

        canister_ops
            .stopper
            .stop(agent, wallet_id, canister_id)
            .with_context(_ctx.clone())
            .await?;

        canister_ops
            .deleter
            .delete(agent, wallet_id, canister_id)
            .with_context(_ctx.clone())
            .await?;
        Ok(())
    }
}

trait CreateAgentFn:
    'static + Fn(NodeRoute) -> Result<(String, String, Agent), Error> + Sync + Send
{
}
impl<F: 'static + Fn(NodeRoute) -> Result<(String, String, Agent), Error> + Sync + Send>
    CreateAgentFn for F
{
}

fn create_agent_fn(identity: Arc<BasicIdentity>, root_key: Option<Vec<u8>>) -> impl CreateAgentFn {
    move |node_route: NodeRoute| {
        let NodeRoute {
            node_id,
            socket_addr,
        } = node_route;

        let transport = ReqwestTransport::create(format!("http://{}", socket_addr))
            .context("failed to create transport")?;

        let identity = Arc::clone(&identity);

        let agent = Agent::builder()
            .with_transport(transport)
            .with_arc_identity(identity)
            .build()
            .context("failed to build agent")?;

        if let Some(root_key) = &root_key {
            agent.set_root_key(root_key.clone());
        }

        Ok((node_id, socket_addr, agent))
    }
}

#[derive(Clone)]
struct MetricsHandlerArgs {
    registry: Registry,
}

async fn metrics_handler(
    Extension(MetricsHandlerArgs { registry }): Extension<MetricsHandlerArgs>,
    _: Request<Body>,
) -> Response<Body> {
    let metric_families = registry.gather();

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

#[derive(Clone, PartialEq, Debug, Deserialize)]
struct Wallets {
    subnet: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
struct NodeRoute {
    node_id: String,
    socket_addr: String,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
struct SubnetRoute {
    subnet_id: String,
    nodes: Vec<NodeRoute>,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
struct Routes {
    subnets: Vec<SubnetRoute>,
}

#[derive(Clone, PartialEq, Debug)]
struct TestContext {
    wallet_id: String,
    subnet_id: String,
}

#[automock]
#[async_trait]
trait Load: Sync + Send {
    async fn load(&self) -> Result<Routes, Error>;
}

struct RoutesLoader {
    routes_dir: PathBuf,
}

impl RoutesLoader {
    fn new(routes_dir: PathBuf) -> Self {
        Self { routes_dir }
    }
}

#[async_trait]
impl Load for RoutesLoader {
    async fn load(&self) -> Result<Routes, Error> {
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

        let f =
            File::open(path).with_context(|| format!("failed to open file {}", &path.display()))?;
        let routes: Routes = serde_json::from_reader(f).context("failed to parse json")?;

        Ok(routes)
    }
}

#[automock]
#[async_trait]
trait Create: 'static + Sync + Send {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error>;
}

struct Creator {
    canister_cycles_amount: u128,
}

impl Creator {
    fn new(canister_cycles_amount: u128) -> Self {
        Self {
            canister_cycles_amount,
        }
    }
}

#[async_trait]
impl Create for Creator {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error> {
        let principal = Principal::from_str(wallet_id).unwrap();
        let wallet = interfaces::WalletCanister::create(agent, principal)
            .await
            .context("failed to build wallet")?;

        let CreateResult { canister_id } = wallet
            .wallet_create_canister(
                self.canister_cycles_amount, // cycles
                None,                        // controllers
                None,                        // compute_allocation
                None,                        // memory_allocation
                None,                        // freezing_threshold
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
        let mut install_args = Argument::new();
        install_args.set_idl_arg(CanisterInstall {
            mode: InstallMode::Install,
            canister_id,
            wasm_module: self.wasm_module.clone(),
            arg: vec![],
        });

        let principal = Principal::from_str(wallet_id).unwrap();
        let wallet = interfaces::WalletCanister::create(agent, principal)
            .await
            .context("failed to build wallet")?;

        let install_call = wallet.call(
            Principal::management_canister(),
            MgmtMethod::InstallCode.as_ref(),
            install_args,
            0,
        );

        install_call
            .call_and_wait()
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

        let write_result = agent
            .update(&canister_id, "write")
            .with_arg(vec![0; 100])
            .call_and_wait()
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
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        let mut stop_args = Argument::new();
        stop_args.set_idl_arg(In { canister_id });

        let principal = Principal::from_str(wallet_id).unwrap();
        let wallet = interfaces::WalletCanister::create(agent, principal)
            .await
            .context("failed to build wallet")?;

        let stop_call = wallet.call(
            Principal::management_canister(),
            MgmtMethod::StopCanister.as_ref(),
            stop_args,
            0,
        );

        stop_call
            .call_and_wait()
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
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        let mut delete_args = Argument::new();
        delete_args.set_idl_arg(In { canister_id });

        let principal = Principal::from_str(wallet_id).unwrap();
        let wallet = interfaces::WalletCanister::create(agent, principal)
            .await
            .context("failed to build wallet")?;

        let delete_call = wallet.call(
            Principal::management_canister(),
            MgmtMethod::DeleteCanister.as_ref(),
            delete_args,
            0,
        );

        delete_call
            .call_and_wait()
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
    async fn run(&mut self, context: &TestContext) -> Result<(), Error> {
        let current_time = Instant::now();
        let next_time = self.1.next_time.unwrap_or(current_time);

        if next_time > current_time {
            tokio::time::sleep(next_time - current_time).await;
        }
        self.1.next_time = Some(Instant::now() + self.1.throttle_duration);

        self.0.run(context).await
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

        // Create loader
        let loader = RoutesLoader::new(routes_dir.path().to_path_buf());

        let out = loader.load().await?;
        assert_eq!(
            out,
            Routes {
                subnets: vec![SubnetRoute {
                    subnet_id: String::from("subnet-1"),
                    nodes: vec![NodeRoute {
                        node_id: String::from("node-1"),
                        socket_addr: String::from("socket-1"),
                    }],
                }],
            },
        );

        Ok(())
    }

    #[tokio::test]
    async fn it_runs() -> Result<(), Error> {
        let mut loader = MockLoad::new();
        loader.expect_load().times(1).returning(|| {
            Ok(Routes {
                subnets: vec![SubnetRoute {
                    subnet_id: String::from("subnet-1"),
                    nodes: vec![NodeRoute {
                        node_id: String::from("node-1"),
                        socket_addr: String::from("socket-1"),
                    }],
                }],
            })
        });
        let wallets = Wallets {
            subnet: HashMap::from([(String::from("subnet-1"), String::from("wallet-1"))]),
        };

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

            let transport =
                ReqwestTransport::create("http://test").context("failed to create transport")?;

            let agent = Agent::builder().with_transport(transport).build()?;

            Ok((route.node_id, route.socket_addr, agent))
        };

        let mut runner = SubnetTestRunner::new(
            Arc::new(loader),
            create_agent, // create_agent
            Arc::new(CanisterOps {
                creator,
                installer,
                prober,
                stopper,
                deleter,
            }),
            Duration::ZERO, // canister_ttl
            1 * MINUTE,     // probe_interval
        );

        let subnet_service_context = wallets
            .subnet
            .into_iter()
            .map(|(subnet_id, wallet_id)| TestContext {
                wallet_id,
                subnet_id,
            })
            .next()
            .expect("Loader didn't find a subnet");

        runner.run(&subnet_service_context).await?;

        Ok(())
    }
}
