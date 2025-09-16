//! An agent to talk to the Internet Computer through the public endpoints.
use crate::{
    cbor::{parse_query_response, prepare_query, prepare_read_state, prepare_update},
    http_client::{HttpClient, HttpClientConfig},
};
use backoff::backoff::Backoff;
use ic_canister_client_sender::Sender;
use ic_crypto_tree_hash::Path;
use ic_management_canister_types_private::{IC_00, InstallCodeArgs, Method, Payload};
use ic_protobuf::types::v1 as pb;
use ic_read_state_response_parser::{RequestStatus, parse_read_state_response};
use ic_types::{
    CanisterId,
    consensus::catchup::CatchUpPackageParam,
    crypto::threshold_sig::ThresholdSigPublicKey,
    messages::{Blob, HttpStatusResponse, MessageId, ReplicaHealthStatus},
    time::expiry_time_from_now,
};
use prost::Message;
use serde_cbor::value::Value as CBOR;
use std::{fmt, sync::Arc, time::Duration, time::Instant};
use tokio::time::sleep_until;
use url::Url;

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_update' call.
const INGRESS_TIMEOUT: Duration = Duration::from_secs(60 * 6);

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_query' call.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

const MIN_POLL_INTERVAL: Duration = Duration::from_millis(500);
// The value must be smaller than `ic_http_handler::MAX_TCP_PEEK_TIMEOUT_SECS`.
// See VER-1060 for details.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
const POLL_INTERVAL_MULTIPLIER: f64 = 1.2;

/// The HTTP path for query calls on the replica.
// TODO is this how v1 api works can we just change the URL?
pub fn query_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{cid}/query")
}

pub fn read_state_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{cid}/read_state")
}

/// The HTTP path for update calls on the replica.
pub fn update_path(cid: CanisterId) -> String {
    format!("api/v2/canister/{cid}/call")
}

const NODE_STATUS_PATH: &str = "api/v2/status";
const CATCH_UP_PACKAGE_PATH: &str = "/_/catch_up_package";

pub fn get_backoff_policy() -> backoff::ExponentialBackoff {
    backoff::ExponentialBackoff {
        initial_interval: MIN_POLL_INTERVAL,
        current_interval: MIN_POLL_INTERVAL,
        randomization_factor: 0.1,
        multiplier: POLL_INTERVAL_MULTIPLIER,
        start_time: std::time::Instant::now(),
        max_interval: MAX_POLL_INTERVAL,
        max_elapsed_time: None,
        clock: backoff::SystemClock::default(),
    }
}

/// An agent to talk to the Internet Computer through the public endpoints.
#[derive(Clone)]
pub struct Agent {
    /// Url of the replica to target. This should NOT contain a URL path like
    /// "/api/v2/canister/_/call".
    pub url: Url,

    // How long to wait and poll for ingress requests? This is independent from the expiry time
    // send as part of the HTTP body.
    // TODO(SCL-237): After the cleanup is complete, this method should be private.
    pub ingress_timeout: Duration,

    // How long to wait for queries.
    query_timeout: Duration,

    // Per reqwest document, cloning a client does not clone the actual connection pool inside.
    // Therefore directly owning a client as opposed to a reference is the standard way to go.
    http_client: Arc<HttpClient>,

    pub sender: Sender,

    /// The values that any 'sender' field should have when issuing
    /// calls with the user corresponding to this Agent.
    pub sender_field: Blob,

    /// Public key against which we should verify response.
    pub nns_public_key: Option<ThresholdSigPublicKey>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("url", &self.url)
            .field("ingress_timeout", &self.ingress_timeout)
            .field("query_timeout", &self.query_timeout)
            .field("sender", &self.sender_field)
            .finish()
    }
}

impl Agent {
    /// Creates an agent.
    ///
    /// `url`: Url of the replica to target. This should NOT contain a URL path
    /// like "/api/v2/canister/_/call". It should contain a port, if needed.
    ///
    /// The `sender` identifies the sender on whose behalf the requests are
    /// sent. If the requests are authenticated, the corresponding `pub_key` and
    /// `sender_sig` field are set in the request envelope.
    pub fn new(url: Url, sender: Sender) -> Self {
        let http_client = Arc::new(HttpClient::new());
        Self::build_agent(url, http_client, sender)
    }

    pub fn new_with_http_client_config(
        url: Url,
        sender: Sender,
        http_client_config: HttpClientConfig,
    ) -> Self {
        let http_client = Arc::new(HttpClient::new_with_config(http_client_config));
        Self::build_agent(url, http_client, sender)
    }

    /// Creates an agent.
    ///
    /// Same as above except gives the caller the option to retain a
    /// pre-existing client.
    pub fn new_with_client(http_client: HttpClient, url: Url, sender: Sender) -> Self {
        Self::build_agent(url, Arc::new(http_client), sender)
    }

    /// This is needed by rust_canister tests
    pub fn new_for_test(&self, sender: Sender) -> Self {
        Self::build_agent(self.url.clone(), self.http_client.clone(), sender)
    }

    /// Helper to create the agent
    fn build_agent(url: Url, http_client: Arc<HttpClient>, sender: Sender) -> Self {
        let sender_field = Blob(sender.get_principal_id().into_vec());
        Self {
            url,
            ingress_timeout: INGRESS_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            http_client,
            sender,
            sender_field,
            nns_public_key: None,
        }
    }

    /// Sets the timeout for ingress requests.
    pub fn with_ingress_timeout(mut self, ingress_timeout: Duration) -> Self {
        self.ingress_timeout = ingress_timeout;
        self
    }

    /// Sets the nns key to verify requests with.
    pub fn with_nns_public_key(mut self, nns_public_key: ThresholdSigPublicKey) -> Self {
        self.nns_public_key = Some(nns_public_key);
        self
    }

    /// Sets the timeout for queries.
    pub fn with_query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }

    /// Queries the cup endpoint given the provided CatchUpPackageParams.
    pub async fn query_cup_endpoint(
        &self,
        param: Option<CatchUpPackageParam>,
    ) -> Result<Option<pb::CatchUpPackage>, String> {
        let body = param
            .and_then(|param| serde_cbor::to_vec(&param).ok())
            .unwrap_or_default();
        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                CATCH_UP_PACKAGE_PATH,
                body,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await?;

        // Response is either empty or a protobuf encoded byte stream.
        let cup = if bytes.is_empty() {
            None
        } else {
            Some(pb::CatchUpPackage::decode(&bytes[..]).map_err(|e| {
                format!("Failed to deserialize CUP from protobuf, got: {bytes:?} - error {e:?}")
            })?)
        };

        Ok(cup)
    }

    /// Calls the query method 'method' on the given canister,
    /// optionally with 'arguments'.
    pub async fn execute_query(
        &self,
        canister_id: &CanisterId,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let envelope = prepare_query(
            &self.sender,
            canister_id,
            method,
            arg,
            self.sender_field.clone(),
        )
        .map_err(|e| format!("Failed to prepare query: {e}"))?;
        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                &query_path(*canister_id),
                envelope.into(),
                tokio::time::Instant::now() + self.query_timeout,
            )
            .await?;
        let cbor = bytes_to_cbor(bytes)?;

        let call_response = parse_query_response(&cbor)?;
        if call_response.status == "replied" {
            Ok(call_response.reply)
        } else {
            Err(format!(
                "The response of a canister query call contained status '{}' and message '{:?}'",
                call_response.status, call_response.reject_message
            ))
        }
    }

    /// Calls the update method 'method' on the given canister,
    /// optionally with 'arguments'.
    pub async fn execute_update<S: ToString>(
        &self,
        effective_canister_id: &CanisterId,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + self.ingress_timeout;
        let mut backoff = get_backoff_policy();
        let (http_body, request_id) = prepare_update(
            &self.sender,
            canister_id,
            method,
            arguments,
            nonce,
            expiry_time_from_now(),
            self.sender_field.clone(),
        )
        .map_err(|err| format!("{err}"))?;
        self.http_client
            .post_with_response(
                &self.url,
                &update_path(*effective_canister_id),
                http_body.into(),
                tokio::time::Instant::from_std(deadline),
            )
            .await?;

        // Check request status for the first time after 2s (~ time between blocks)
        let mut next_poll_time = Instant::now() + Duration::from_secs(2);

        // The first poll should not be immediate because a successful status request
        // will take at least the time between consensus blocks.
        while next_poll_time < deadline {
            sleep_until(tokio::time::Instant::from_std(next_poll_time)).await;
            next_poll_time = Instant::now() + backoff.next_backoff().expect("Backoff interval MUST be available. If you see this error the backoff is misconfigured.");
            match self
                .wait_ingress(request_id.clone(), deadline, effective_canister_id)
                .await
            {
                Ok(request_status) => match request_status.status.as_ref() {
                    "replied" => {
                        return Ok(request_status.reply);
                    }
                    "done" => {
                        return Err(
                            "The call has completed but the reply/reject data has been pruned."
                                .to_string(),
                        );
                    }
                    "unknown" | "received" | "processing" => {}
                    _ => {
                        return Err(format!(
                            "unexpected result: {:?} - {:?}",
                            request_status.status, request_status.reject_message
                        ));
                    }
                },
                Err(e) => return Err(format!("Unexpected error: {e:?}")),
            }
        }
        Err(format!(
            "Request took longer than the deadline {deadline:?} to complete."
        ))
    }

    /// Requests the status of a pending request once.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    ///
    /// Returns the entire CBOR value from the response, without trying to
    /// interpret it.
    async fn request_status_once(
        &self,
        request_id: MessageId,
        deadline: Instant,
        effective_canister_id: &CanisterId,
    ) -> Result<CBOR, String> {
        let path = Path::new(vec!["request_status".into(), request_id.into()]);
        let signed_request_bytes =
            prepare_read_state(&self.sender, &[path], self.sender_field.clone())
                .map_err(|e| format!("Failed to prepare read state: {e:?}"))?;

        let bytes = self
            .http_client
            .post_with_response(
                &self.url,
                &read_state_path(*effective_canister_id),
                signed_request_bytes.into(),
                tokio::time::Instant::from_std(deadline),
            )
            .await?;
        bytes_to_cbor(bytes)
    }

    /// Requests the status of a pending canister update call request exactly
    /// once using the `read_state` API.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    pub async fn wait_ingress(
        &self,
        request_id: MessageId,
        deadline: Instant,
        effective_canister_id: &CanisterId,
    ) -> Result<RequestStatus, String> {
        let cbor = self
            .request_status_once(request_id.clone(), deadline, effective_canister_id)
            .await?;

        parse_read_state_response(
            &request_id,
            effective_canister_id,
            self.nns_public_key.as_ref(),
            cbor,
        )
    }

    async fn get_status(&self) -> Result<HttpStatusResponse, String> {
        let bytes = self
            .http_client
            .get_with_response(
                &self.url,
                NODE_STATUS_PATH,
                tokio::time::Instant::now() + self.query_timeout,
            )
            .await?;
        let resp = bytes_to_cbor(bytes)?;
        serde_cbor::value::from_value::<HttpStatusResponse>(resp)
            .map_err(|source| format!("decoding to HttpStatusResponse failed: {source}"))
    }

    /// Requests the root key of this node by querying /api/v2/status
    pub async fn root_key(&self) -> Result<Option<Blob>, String> {
        let response = self.get_status().await?;
        Ok(response.root_key)
    }

    /// Checks if the target replica is healthy.
    pub async fn is_replica_healthy(&self) -> bool {
        if let Ok(response) = self.get_status().await {
            return response.replica_health_status == Some(ReplicaHealthStatus::Healthy);
        }
        false
    }

    pub fn http_client(&self) -> &HttpClient {
        self.http_client.as_ref()
    }

    // Ships a binary wasm module to a canister.
    pub async fn install_canister(&self, install_args: InstallCodeArgs) -> Result<(), String> {
        let effective_canister_id: CanisterId =
            CanisterId::try_from(install_args.canister_id).unwrap();
        self.execute_update(
            &effective_canister_id,
            &IC_00,
            Method::InstallCode,
            install_args.encode(),
            vec![],
        )
        .await
        .map(|_| ())
    }
}

fn bytes_to_cbor(bytes: Vec<u8>) -> Result<CBOR, String> {
    let cbor = serde_cbor::from_slice(&bytes).map_err(|e| {
        format!(
            "Agent::bytes_to_cbor: Failed to parse result from IC, got: {:?} - error {:?}",
            String::from_utf8(
                bytes
                    .iter()
                    .copied()
                    .flat_map(std::ascii::escape_default)
                    .collect()
            )
            .expect("ASCII is legal utf8"),
            e
        )
    })?;
    Ok(cbor)
}
