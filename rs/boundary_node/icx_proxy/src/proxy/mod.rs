use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use anyhow::{Context, Error};
use axum::{handler::Handler, middleware, Router};
use http::Request;
use hyper::body::Incoming;
use hyper::{self, Response, StatusCode, Uri};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use ic_agent::agent::{
    http_transport::{
        hyper_transport::HyperTransport, route_provider::RouteProvider as RouteProviderTrait,
    },
    Agent, AgentError,
};
use opentelemetry::metrics::Meter;
use std::convert::Infallible;
use tokio::net::UnixListener;
use tower::Service;
use tracing::{error, info, warn, Span};
use url::Url;

use crate::{
    canister_id::ResolverState,
    http_client::{Body, HyperService},
    logging::add_trace_layer,
    metrics::{with_metrics_middleware, HttpMetricParams},
    proxy::domain_canister::DomainCanisterMatcher,
    validate::Validate,
    DomainAddr,
};

pub mod agent;
pub mod denylist;
pub mod domain_canister;
pub mod geoip;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
pub const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

pub enum ListenProto {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// The options for the proxy server
pub struct ProxyOpts {
    /// The address to bind to.
    pub listen: ListenProto,

    /// A set of replicas to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    pub replicas: Vec<DomainAddr>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    pub debug: bool,

    /// Whether or not to fetch the root key from the replica back end.
    pub fetch_root_key: bool,

    /// The root key to use
    pub root_key: Option<PathBuf>,
}

pub use agent::{handler as agent_handler, Pool};

trait HandleError {
    type B;
    fn handle_error(self, debug: bool) -> Response<Self::B>;
}
impl<B> HandleError for Result<Response<B>, anyhow::Error>
where
    String: Into<B>,
    &'static str: Into<B>,
{
    type B = B;
    fn handle_error(self, debug: bool) -> Response<B> {
        match self {
            Err(err) => {
                Span::current().record("code", 500);
                Span::current().record("error", err.to_string());
                error!("");

                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(if debug {
                        format!("Internal Error: {:?}", err).into()
                    } else {
                        "Internal Server Error".into()
                    })
                    .unwrap()
            }

            Ok(v) => {
                let status = v.status().as_u16();
                Span::current().record("code", status);

                if status >= 500 {
                    warn!("")
                } else {
                    info!("")
                }

                v
            }
        }
    }
}

pub struct SetupArgs<V, C> {
    pub validator: V,
    pub domain_match: Option<Arc<DomainCanisterMatcher>>,
    pub geoip: Option<Arc<geoip::GeoIp>>,
    pub denylist: Option<Arc<denylist::Denylist>>,
    pub resolver: ResolverState,
    pub client: C,
    pub meter: Meter,
}

pub fn setup<C: HyperService<Body> + 'static>(
    args: SetupArgs<impl Validate + Clone + 'static, C>,
    opts: ProxyOpts,
) -> Result<Runner, anyhow::Error> {
    let client = args.client;

    let root_key = if let Some(v) = opts.root_key {
        fs::read(v).expect("failed to read root key")
    } else {
        Vec::new()
    };

    let replicas = opts
        .replicas
        .iter()
        .map(|v| {
            let transport =
                HyperTransport::create_with_service(v.domain.to_string(), client.clone())
                    .context("failed to create transport")?
                    .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

            let agent = Agent::builder()
                .with_transport(transport)
                .build()
                .context("fail to create agent")?;

            if !root_key.is_empty() {
                agent.set_root_key(root_key.clone());
            }

            Ok((agent, v.domain.clone()))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let fetch_root_keys = if opts.fetch_root_key {
        replicas.clone()
    } else {
        Vec::new()
    };

    let agent_service = agent_handler.with_state(AppState(Arc::new(AppStateInner {
        agent: None,
        replica_pool: Pool::new(replicas),
        domain_match: args.domain_match,
        geoip: args.geoip,
        denylist: args.denylist,
        validator: args.validator,
        resolver: args.resolver,
        debug: opts.debug,
    })));

    let http_metrics = HttpMetricParams::new(&args.meter);
    let metrics_layer = middleware::from_fn_with_state(http_metrics, with_metrics_middleware);

    Ok(Runner {
        router: add_trace_layer(
            Router::new()
                .fallback_service(agent_service)
                .layer(metrics_layer),
        ),
        listen: opts.listen,
        fetch_root_keys,
    })
}

#[derive(Debug)]
struct RouteProvider(Url);

impl RouteProviderTrait for RouteProvider {
    fn route(&self) -> Result<Url, AgentError> {
        Ok(self.0.clone())
    }
}

pub fn setup_unix_socket<C: HyperService<Body> + 'static>(
    args: SetupArgs<impl Validate + Clone + 'static, C>,
    opts: ProxyOpts,
) -> Result<Runner, anyhow::Error> {
    // Hostname can be anything, the URL is just here to make Agent happy
    // It will be overridden with the Unix socket in the client later on
    let url = Url::parse("http://0.0.0.0")?;
    let provider = RouteProvider(url);

    let transport = HyperTransport::create_with_service_route(Arc::new(provider), args.client)
        .context("failed to create transport")?
        .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

    let agent = Agent::builder()
        .with_transport(transport)
        .build()
        .context("fail to create agent")?;

    let root_key = if let Some(v) = opts.root_key {
        fs::read(v).expect("failed to read root key")
    } else {
        Vec::new()
    };

    if !root_key.is_empty() {
        agent.set_root_key(root_key.clone());
    }

    let agent_service = agent_handler.with_state(AppState(Arc::new(AppStateInner {
        agent: Some(agent),
        replica_pool: Pool::new(vec![]),
        domain_match: args.domain_match,
        geoip: args.geoip,
        denylist: args.denylist,
        validator: args.validator,
        resolver: args.resolver,
        debug: opts.debug,
    })));

    let http_metrics = HttpMetricParams::new(&args.meter);
    let metrics_layer = middleware::from_fn_with_state(http_metrics, with_metrics_middleware);

    Ok(Runner {
        router: add_trace_layer(
            Router::new()
                .fallback_service(agent_service)
                .layer(metrics_layer),
        ),
        listen: opts.listen,
        fetch_root_keys: vec![],
    })
}

#[derive(Clone)]
pub struct AppState<V>(Arc<AppStateInner<V>>);

struct AppStateInner<V> {
    agent: Option<Agent>,
    domain_match: Option<Arc<DomainCanisterMatcher>>,
    geoip: Option<Arc<geoip::GeoIp>>,
    denylist: Option<Arc<denylist::Denylist>>,
    replica_pool: Pool,
    resolver: ResolverState,
    validator: V,
    debug: bool,
}

impl<V> AppState<V> {
    pub fn new_for_testing(
        replicas: Vec<(Agent, Uri)>,
        resolver: ResolverState,
        validator: V,
    ) -> Self {
        Self(Arc::new(AppStateInner {
            agent: None,
            domain_match: None,
            geoip: None,
            denylist: None,
            replica_pool: Pool::new(replicas),
            resolver,
            validator,
            debug: true,
        }))
    }

    pub fn pool(&self) -> &Pool {
        &self.0.replica_pool
    }
    pub fn resolver(&self) -> &ResolverState {
        &self.0.resolver
    }
    pub fn validator(&self) -> &V {
        &self.0.validator
    }
    pub fn debug(&self) -> bool {
        self.0.debug
    }
    pub fn domain_match(&self) -> Option<Arc<DomainCanisterMatcher>> {
        self.0.domain_match.clone()
    }
    pub fn geoip(&self) -> Option<Arc<geoip::GeoIp>> {
        self.0.geoip.clone()
    }
    pub fn denylist(&self) -> Option<Arc<denylist::Denylist>> {
        self.0.denylist.clone()
    }
}

pub struct Runner {
    router: Router,
    listen: ListenProto,
    fetch_root_keys: Vec<(Agent, Uri)>,
}

impl Runner {
    pub async fn run(self) -> Result<(), Error> {
        for (agent, uri) in self.fetch_root_keys.into_iter() {
            agent
                .fetch_root_key()
                .await
                .with_context(|| format!("fail to fetch root key for {uri}"))?;
        }

        match self.listen {
            ListenProto::Tcp(x) => {
                info!("Starting server. Listening on http://{}/", x);
                let listener = tokio::net::TcpListener::bind(x).await?;
                axum::serve(
                    listener,
                    self.router
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .context("failed to start proxy server")?;
            }

            ListenProto::Unix(x) => {
                info!("Starting server. Listening on unix:{:?}", x);

                // Remove the socket file if it's there
                if x.exists() {
                    std::fs::remove_file(&x).expect("unable to remove socket");
                }

                let uds = UnixListener::bind(x.clone()).unwrap();

                std::fs::set_permissions(&x, std::fs::Permissions::from_mode(0o666))
                    .expect("unable to set permissions on socket");

                let mut make_service = self.router.into_make_service();

                // See https://github.com/tokio-rs/axum/blob/main/examples/serve-with-hyper/src/main.rs for
                // more details about this setup
                loop {
                    let (socket, _remote_addr) = uds.accept().await.unwrap();

                    let tower_service = unwrap_infallible(make_service.call(&socket).await);

                    tokio::spawn(async move {
                        let socket = TokioIo::new(socket);

                        let hyper_service =
                            hyper::service::service_fn(move |request: Request<Incoming>| {
                                tower_service.clone().call(request)
                            });

                        if let Err(err) =
                            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(socket, hyper_service)
                                .await
                        {
                            eprintln!("failed to serve connection: {err:#}");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}
