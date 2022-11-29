use std::{fs, net::SocketAddr, path::PathBuf, sync::atomic::AtomicUsize};

use anyhow::{Context, Error};
use axum::{handler::Handler, Extension, Router};
use hyper::{self, Response, StatusCode, Uri};
use ic_agent::{agent::http_transport::HyperReplicaV2Transport, Agent};
use tracing::{error, info};

use crate::{
    canister_id::Resolver as CanisterIdResolver,
    http_client::{Body, HyperService},
    logging::add_trace_layer,
    validate::Validate,
    DomainAddr,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

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

mod agent;

use agent::{handler as agent_handler, Args as AgentArgs, ArgsInner as AgentArgsInner};

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

pub struct SetupArgs<V, R, C> {
    pub validator: V,
    pub resolver: R,
    pub client: C,
}

pub fn setup<C: HyperService<Body> + 'static>(
    args: SetupArgs<impl Validate + 'static, impl CanisterIdResolver + 'static, C>,
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
                HyperReplicaV2Transport::create_with_service(v.domain.clone(), client.clone())
                    .context("failed to create transport")?
                    .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

            let agent = Agent::builder()
                .with_transport(transport)
                .build()
                .context("fail to create agent")?;

            if !root_key.is_empty() {
                agent
                    .set_root_key(root_key.clone())
                    .context("fail to set root key")?;
            }

            Ok((agent, v.domain.clone()))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let fetch_root_keys = if opts.fetch_root_key {
        replicas.clone()
    } else {
        Vec::new()
    };

    let agent_service = agent_handler
        .layer(Extension(AgentArgs::from(AgentArgsInner {
            validator: Box::new(args.validator),
            resolver: Box::new(args.resolver),
            counter: AtomicUsize::new(0),
            replicas,
            debug: opts.debug,
        })))
        .into_service();

    Ok(Runner {
        router: add_trace_layer(Router::new().fallback(agent_service)),
        address: opts.address,
        fetch_root_keys,
    })
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
