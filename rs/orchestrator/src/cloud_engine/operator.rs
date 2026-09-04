//! Client for the per-engine `engine-operator` canister.
//!
//! This is the "engine registry" that contains all the necessary config for the
//! all-in-one node (e.g., domain names, DNS API URLs and API keys, ACME account,
//! etc.).
//!
//! Every record is deliberately all-`opt` on the canister side so that the
//! interface can grow without a breaking change; candid drops wire fields that
//! are absent from these types, so added fields cannot break here either.

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_types::CanisterId;
use serde::Deserialize;

#[derive(CandidType, Deserialize, Debug)]
pub(super) enum OperatorApiError {
    Unauthorized,
    NotFound,
    BadRequest(String),
    Internal(String),
}

#[derive(CandidType, Deserialize)]
enum OperatorResponse<T> {
    #[serde(rename = "ok")]
    Ok(T),
    #[serde(rename = "err")]
    Err(OperatorApiError),
}

#[derive(CandidType, Deserialize, Default)]
pub(super) struct HttpGatewayConfig {
    pub base_domains: Option<Vec<String>>,
    pub dns_api_url: Option<String>,
    pub dns_api_key: Option<String>,
}

#[derive(CandidType, Deserialize, Default)]
pub(super) struct AcmeCredentials {
    pub id: Option<String>,
    pub key_pkcs8: Option<String>,
    pub directory: Option<String>,
}

/// Why a call to the operator did not yield a config.
pub(super) enum OperatorError {
    /// The operator did not (yet) recognise us as one of its engine's nodes. Its
    /// `isNode` check reads a transient cache that stays empty until the first
    /// successful registry refetch after an install or upgrade, so this is
    /// expected right after either and never fatal.
    NotReady,
    /// Transport, decoding, or any other operator-side failure.
    Failed(String),
}

pub(super) type OperatorResult<T> = Result<T, OperatorError>;

/// Reads the engine configuration off the operator canister.
pub(super) struct OperatorClient<'a> {
    agent: &'a Agent,
    canister_id: Principal,
}

impl<'a> OperatorClient<'a> {
    pub(super) fn new(agent: &'a Agent, canister_id: CanisterId) -> Self {
        Self {
            agent,
            canister_id: canister_id.get().0,
        }
    }

    pub(super) async fn http_gateway_config(&self) -> OperatorResult<HttpGatewayConfig> {
        self.query("getHttpGatewayConfig").await
    }

    pub(super) async fn acme_credentials(&self) -> OperatorResult<AcmeCredentials> {
        self.query("getHttpGatewayAcmeCredentials").await
    }

    /// Runs one of the operator's `shared query` endpoints. Both take no
    /// argument and answer with the same `ok`/`err` envelope.
    async fn query<T>(&self, method: &str) -> OperatorResult<T>
    where
        T: CandidType + for<'de> Deserialize<'de>,
    {
        let arg = Encode!().map_err(|err| {
            OperatorError::Failed(format!("could not encode the argument of {method}: {err}"))
        })?;

        let response = self
            .agent
            .query(&self.canister_id, method)
            .with_arg(arg)
            .call()
            .await
            .map_err(|err| OperatorError::Failed(format!("{method} failed: {err}")))?;

        match Decode!(&response, OperatorResponse<T>).map_err(|err| {
            OperatorError::Failed(format!("could not decode the response of {method}: {err}"))
        })? {
            OperatorResponse::Ok(value) => Ok(value),
            OperatorResponse::Err(OperatorApiError::Unauthorized) => Err(OperatorError::NotReady),
            OperatorResponse::Err(err) => {
                Err(OperatorError::Failed(format!("{method} rejected: {err:?}")))
            }
        }
    }
}
