//! IC replica probe that executes a query or update method on a canister.
//!
//! Supported query parameters:
//!  * `replica` (required): a host-port combination to probe, e.g.
//!    `replica=[::1]:2198`
//!  * `canister` (required): the ID of the canister to probe
//!  * `query` (either this or `update` is required): method to query
//!  * `update` (either this or `query` is required): method to make update call
//!    against
//!  * `arg` (optional): arguments for the probed method, e.g. `arg=DIDL%00%00`
//!
//! Sample query that should work against a Governance canister (modulo valid
//! prober and replica IP addresses):
//!
//! ```text
//! curl -v http://[::1]:2198/probe/ic?replica=[::1]:8080\&canister=rrkah-fqaaa-aaaaa-aaaaq-cai\&query=get_neuron_ids\&arg=DIDL%00%00
//! ```
//!
//! It queries the `get_neuron_ids` method with "nullary input", i.e. `()`. (See
//! these [Candid tests](https://github.com/dfinity/candid/blob/master/test/prim.test.did)
//! for more Candid examples.)

use super::{
    bad_request, duration_to, set_once, unwrap_param, ParamIterator, ProbeError, ProbeResult,
};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_metrics::{MetricsRegistry, Timer};
use ic_types::{CanisterId, PrincipalId};
use lazy_static::lazy_static;
use prometheus::{Gauge, IntGauge};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use slog::{info, Logger};
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use url::Url;
use IcCallType::*;

lazy_static! {
    /// HTTP client, reused across probes for efficiency.
    static ref CLIENT: HttpClient = HttpClient::new();

    /// Static keypair of the `ic-prober` sender.
    static ref KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(1_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };

    /// Incrementing nonce used to identify sent requests.
    static ref NONCE: AtomicU64 = AtomicU64::new(0);
}

/// IC probe metrics.
struct Metrics {
    /// Duration of IC request.
    duration: Gauge,
    /// Length of IC response content.
    content_length: IntGauge,
    /// Whether the IC request completed successfully or not.
    success: IntGauge,
}

impl Metrics {
    fn new(registry: &MetricsRegistry) -> Self {
        let duration = registry.gauge("probe_ic_duration_seconds", "Duration of IC request.");
        let content_length =
            registry.int_gauge("probe_ic_content_length", "Length of IC response content.");
        let success = registry.int_gauge(
            "probe_ic_success",
            "Whether the IC request ompleted successfully or not.",
        );

        // Default content length to -1 (in case of any error).
        content_length.set(-1);

        Self {
            duration,
            content_length,
            success,
        }
    }
}

/// Probes the given IC replica-canister-method combination.
///
/// Supported query parameters:
///  * `replica` (required): a host-port combination to probe, e.g.
///    `replica=1.2.3.4:2198`
///  * `canister` (required): the ID of the canister to probe
///  * `query` (either this or `update` is required): method to query
///  * `update` (either this or `query` is required): method to make update call
///    against
///  * `arg` (optional): arguments for the probed method, e.g. `arg=DIDL%00%00`
pub async fn probe(params: ParamIterator<'_>, deadline: Instant, log: &Logger) -> ProbeResult {
    let params = Params::try_from(params)?;

    let url = Url::parse(&format!("http://{}", params.replica))
        .map_err(|err| bad_request(err.to_string()))?;

    let registry = MetricsRegistry::new();
    let metrics = Metrics::new(&registry);

    let timeout = duration_to(deadline);
    let agent = Agent::new_with_client(CLIENT.clone(), url, Sender::from_keypair(&KEYPAIR))
        .with_ingress_timeout(timeout)
        .with_query_timeout(timeout);

    let timer = Timer::start();
    let result = match params.call_type {
        Update => {
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec();
            agent
                .execute_update(&params.canister, params.method.as_ref(), params.arg, nonce)
                .await
        }
        Query => {
            agent
                .execute_query(&params.canister, params.method.as_ref(), params.arg)
                .await
        }
    };
    metrics.duration.set(timer.elapsed());

    match result {
        Ok(response) => {
            metrics
                .content_length
                .set(response.map(|r| r.len()).unwrap_or(0) as i64);
            metrics.success.set(1);
        }

        Err(err) => info!(
            log,
            "Error probing canister {} on replica {}: {}", params.canister, params.replica, err
        ),
    }
    Ok(registry)
}

/// Probe parameters, parsed from URL parameters.
struct Params<'a> {
    replica: Cow<'a, str>,
    canister: CanisterId,
    method: Cow<'a, str>,
    call_type: IcCallType,
    arg: Vec<u8>,
}

const REPLICA: &str = "replica";
const CANISTER: &str = "canister";
const QUERY: &str = "query";
const UPDATE: &str = "update";
const ARG: &str = "arg";

impl<'a> Params<'a> {
    fn try_from(params: ParamIterator<'a>) -> Result<Self, ProbeError> {
        let mut replica = None;
        let mut canister = None;
        let mut query = None;
        let mut update = None;
        let mut arg = None;
        for (param, value) in params {
            match param.as_ref() {
                REPLICA => set_once(&mut replica, REPLICA, value)?,
                CANISTER => set_once(&mut canister, CANISTER, value)?,
                QUERY => set_once(&mut query, QUERY, value)?,
                UPDATE => set_once(&mut update, UPDATE, value)?,
                ARG => set_once(&mut arg, ARG, value)?,
                _ => {
                    return Err(bad_request(format!("Unexpected query param: {}", param)));
                }
            }
        }
        let replica = unwrap_param(replica, REPLICA)?;
        let canister = unwrap_param(canister, CANISTER)?;
        let canister = PrincipalId::from_str(canister.as_ref())
            .map_err(|err| bad_request(format!("Invalid canister ID: {}: {}", canister, err)))?;
        let canister = CanisterId::new(canister)
            .map_err(|err| bad_request(format!("Invalid canister ID: {}: {}", canister, err)))?;
        let arg = unwrap_param(arg, ARG)?.as_bytes().to_vec();

        let (call_type, method) = match (query, update) {
            (Some(query), None) => (Query, query),
            (None, Some(update)) => (Update, update),
            (None, None) | (Some(_), Some(_)) => {
                return Err(bad_request(format!(
                    "Exactly one of `{}` or `{}` query params must be specified",
                    QUERY, UPDATE
                )));
            }
        };

        Ok(Self {
            replica,
            canister,
            method,
            call_type,
            arg,
        })
    }
}

/// IC call type: update or query.
enum IcCallType {
    Update,
    Query,
}
