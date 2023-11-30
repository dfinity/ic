use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Error};
use axum::{handler::Handler, middleware, Router};
use hyper::{self, Response, StatusCode, Uri};
use ic_agent::agent::{http_transport::hyper_transport::HyperReplicaV2Transport, Agent};
use opentelemetry::metrics::Meter;
use tracing::{error, info};

use crate::{
    canister_id::ResolverState,
    http_client::{Body, HyperService},
    logging::add_trace_layer,
    metrics::{with_metrics_middleware, HttpMetricParams},
    validate::Validate,
    DomainAddr,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
pub const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

/// The options for the proxy server
pub struct ProxyOpts {
    /// The address to bind to.
    pub address: SocketAddr,

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

pub mod agent;

use agent::{handler_wrapper as agent_handler, Pool};

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
                error!("Internal Error during request:\n{}", err);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(if debug {
                        format!("Internal Error: {:?}", err).into()
                    } else {
                        "Internal Server Error".into()
                    })
                    .unwrap()
            }
            Ok(v) => v,
        }
    }
}

pub struct SetupArgs<V, C> {
    pub validator: V,
    pub resolver: ResolverState,
    pub client: C,
    pub meter: Meter,
}

pub fn setup<C: HyperService<Body> + 'static>(
    args: SetupArgs<impl Validate + Clone + 'static, C>,
    opts: ProxyOpts,
) -> Result<Runner, anyhow::Error> {
    let client = args.client;

    let root_key = if let Some(root_key) = opts.root_key {
        fs::read(&root_key)
            .with_context(|| format!("fail to read root key from {}", root_key.display()))?
    } else {
        Vec::new()
    };

    let replicas = opts
        .replicas
        .iter()
        .map(|v| {
            let transport =
                HyperReplicaV2Transport::create_with_service(v.domain.to_string(), client.clone())
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
        replica_pool: Pool::new(replicas),
        validator: args.validator,
        resolver: args.resolver,
        debug: opts.debug,
        client,
    })));

    let http_metrics = HttpMetricParams::new(&args.meter);
    let metrics_layer = middleware::from_fn_with_state(http_metrics, with_metrics_middleware);

    Ok(Runner {
        router: add_trace_layer(
            Router::new()
                .fallback_service(agent_service)
                .layer(metrics_layer),
        ),
        address: opts.address,
        fetch_root_keys,
    })
}

#[derive(Clone)]
pub struct AppState<V, C>(Arc<AppStateInner<V, C>>);

struct AppStateInner<V, C> {
    replica_pool: Pool,
    resolver: ResolverState,
    validator: V,
    client: C,
    debug: bool,
}

impl<V, C> AppState<V, C> {
    pub fn pool(&self) -> &Pool {
        &self.0.replica_pool
    }
    pub fn resolver(&self) -> &ResolverState {
        &self.0.resolver
    }
    pub fn validator(&self) -> &V {
        &self.0.validator
    }
    pub fn client(&self) -> &C {
        &self.0.client
    }
    pub fn debug(&self) -> bool {
        self.0.debug
    }
}

pub struct Runner {
    router: Router,
    address: SocketAddr,
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

        info!("Starting server. Listening on http://{}/", self.address);
        axum::Server::bind(&self.address)
            .serve(
                self.router
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .context("failed to start proxy server")?;

        Ok(())
    }
}
