use std::{net::SocketAddr, sync::atomic::AtomicUsize};

use anyhow::{Context, Error};
use axum::{handler::Handler, Extension, Router};
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
pub struct ProxyOpts {
    /// The address to bind to.
    pub address: SocketAddr,

    /// A set of replicas to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    pub replica_uris: Vec<Uri>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    pub debug: bool,

    /// Whether or not to fetch the root key from the replica back end. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    pub fetch_root_key: bool,
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

    let replicas = opts
        .replica_uris
        .iter()
        .map(|replica_uri| {
            let transport =
                HyperReplicaV2Transport::create_with_service(replica_uri.clone(), client.clone())
                    .context("failed to create transport")?
                    .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

            let agent = Agent::builder()
                .with_transport(transport)
                .build()
                .context("fail to create agent")?;

            Ok((agent, replica_uri.clone()))
        })
        .collect::<Result<_, anyhow::Error>>()?;

    let agent_service = agent_handler
        .layer(Extension(AgentArgs::from(AgentArgsInner {
            validator: Box::new(args.validator),
            resolver: Box::new(args.resolver),
            counter: AtomicUsize::new(0),
            replicas,
            debug: opts.debug,
            fetch_root_key: opts.fetch_root_key,
        })))
        .into_service();

    Ok(Runner {
        router: add_trace_layer(Router::new().fallback(agent_service)),
        address: opts.address,
    })
}

pub struct Runner {
    router: Router,
    address: SocketAddr,
}

impl Runner {
    pub async fn run(self) -> Result<(), Error> {
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
