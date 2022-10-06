use std::{
    future::Future,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
};

use anyhow::{bail, Context};
use axum::{handler::Handler, routing::any, Extension, Router};
use clap::Args;
use hyper::{self, Response, StatusCode, Uri};
use ic_agent::{agent::http_transport::HyperReplicaV2Transport, Agent};
use tracing::{error, info};

use crate::{
    canister_id::Resolver as CanisterIdResolver,
    http_client::{Body, HyperService},
    logging::add_trace_layer,
    validate::Validate,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

/// The options for the proxy server
#[derive(Args)]
pub struct Opts {
    /// The address to bind to.
    #[clap(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    /// A replica to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: Vec<Uri>,

    /// An address to forward any requests from /_/
    #[clap(long)]
    proxy: Option<Uri>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,

    /// Whether or not to fetch the root key from the replica back end. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    fetch_root_key: bool,
}

mod agent;
mod forward;

use agent::{handler as agent_handler, Args as AgentArgs, ArgsInner as AgentArgsInner};
use forward::{handler as forward_handler, Args as ForwardArgs, ArgsInner as ForwardArgsInner};

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

pub fn setup<C: 'static + HyperService<Body>>(
    args: SetupArgs<impl Validate + 'static, impl CanisterIdResolver + 'static, C>,
    opts: Opts,
) -> Result<Runner, anyhow::Error> {
    let client = args.client;

    let agent_args = Extension(AgentArgs::from(AgentArgsInner {
        validator: Box::new(args.validator),
        resolver: Box::new(args.resolver),
        counter: AtomicUsize::new(0),
        replicas: opts
            .replica
            .iter()
            .map(|replica_url| {
                let transport = HyperReplicaV2Transport::create_with_service(
                    replica_url.clone(),
                    client.clone(),
                )
                .context("failed to create transport")?
                .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

                let agent = Agent::builder()
                    .with_transport(transport)
                    .build()
                    .context("Could not create agent...")?;
                Ok((agent, replica_url.clone()))
            })
            .collect::<Result<_, anyhow::Error>>()?,
        debug: opts.debug,
        fetch_root_key: opts.fetch_root_key,
    }));

    let agent_service = agent_handler.layer(agent_args).into_service();

    let router = Router::new();
    // Setup `/_/` proxy for dfx if requested
    let router = if let Some(proxy_url) = opts.proxy {
        info!("Setting up `/_/` proxy to `{proxy_url}`");
        if proxy_url.scheme().is_none() {
            bail!("No schema found on `proxy_url`");
        }
        let forward_args = Extension(Arc::new(ForwardArgs::from(ForwardArgsInner {
            client: client.clone(),
            counter: AtomicUsize::new(0),
            proxy_urls: vec![proxy_url],
            debug: opts.debug,
        })));
        let forward_to_replica = Extension(Arc::new(ForwardArgs::from(ForwardArgsInner {
            client,
            counter: AtomicUsize::new(0),
            proxy_urls: opts.replica,
            debug: opts.debug,
        })));
        let forward_service = any(forward_handler::<C>.layer(forward_args));
        let forward_to_replica_service = any(forward_handler::<C>.layer(forward_to_replica));
        router
            // Exclude `/_/raw` from the proxy
            .route("/_/raw", agent_service.clone())
            .route("/_/raw/*path", agent_service.clone())
            // Proxy `/api` to the replica
            .route("/api", forward_to_replica_service.clone())
            .route("/api/*path", forward_to_replica_service)
            // Proxy everything else under `/_` to the `proxy_url`
            .route("/_", forward_service.clone())
            .route("/_/", forward_service.clone())
            .route("/_/:not_raw", forward_service.clone())
            .route("/_/:not_raw/*path", forward_service)
    } else {
        router
    };
    Ok(Runner {
        router: add_trace_layer(router.fallback(agent_service)),
        address: opts.address,
    })
}

pub struct Runner {
    router: Router,
    address: SocketAddr,
}
impl Runner {
    pub fn run(self) -> impl Future<Output = Result<(), hyper::Error>> {
        info!("Starting server. Listening on http://{}/", self.address);
        axum::Server::bind(&self.address).serve(
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
    }
}
