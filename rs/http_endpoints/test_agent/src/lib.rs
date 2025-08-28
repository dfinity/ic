use ic_crypto_tree_hash::Path;
use ic_http_endpoints_public::{query, read_state};
use ic_types::{
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
        HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, MessageId, SignedIngress,
    },
    time::current_time,
    PrincipalId,
};
use reqwest::{header::CONTENT_TYPE, StatusCode};
use serde_cbor::Value as CBOR;
use std::{net::SocketAddr, time::Duration};
use url::Url;

const INGRESS_EXPIRY_DURATION: Duration = Duration::from_secs(300);
const METHOD_NAME: &str = "test";
const SENDER: PrincipalId = PrincipalId::new_anonymous();
const ARG: Vec<u8> = vec![];
pub const APPLICATION_CBOR: &str = "application/cbor";

pub async fn wait_for_status_healthy(addr: &SocketAddr) -> Result<(), &'static str> {
    let fut = async {
        loop {
            let url = format!("http://{}/api/v2/status", addr);

            let response = reqwest::Client::new()
                .get(url)
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await;

            let Ok(response) = response else {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            };

            if response.status() != StatusCode::OK {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }

            let Ok(response) = response.bytes().await else {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            };

            let replica_status = serde_cbor::from_slice::<CBOR>(&response)
                .expect("Status endpoint is a valid CBOR.");

            if let CBOR::Map(map) = replica_status {
                if let Some(CBOR::Text(status)) =
                    map.get(&CBOR::Text("replica_health_status".to_string()))
                {
                    if status == "healthy" {
                        return;
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .map_err(|_| "Timeout while waiting for http endpoint to be healthy")
}

#[derive(Copy, Clone, Debug)]
pub enum Call {
    V2,
    V3,
    V4,
}

#[derive(Clone, Debug)]
pub struct IngressMessage {
    canister_id: PrincipalId,
    effective_canister_id: PrincipalId,
    ingress_expiry: u64,
    method_name: String,
}

impl Default for IngressMessage {
    fn default() -> Self {
        Self {
            canister_id: PrincipalId::default(),
            effective_canister_id: PrincipalId::default(),
            ingress_expiry: (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch(),
            method_name: METHOD_NAME.to_string(),
        }
    }
}

impl IngressMessage {
    pub fn with_canister_id(
        mut self,
        canister_id: PrincipalId,
        effective_canister_id: PrincipalId,
    ) -> Self {
        self.canister_id = canister_id;
        self.effective_canister_id = effective_canister_id;
        self
    }
    pub fn with_ingress_expiry(mut self, ingress_expiry: Duration) -> Self {
        self.ingress_expiry = (current_time() + ingress_expiry).as_nanos_since_unix_epoch();
        self
    }
    pub fn with_method_name(mut self, method_name: String) -> Self {
        self.method_name = method_name;
        self
    }

    pub fn envelope(&self) -> HttpRequestEnvelope<HttpCallContent> {
        let call_content = self.call_content();

        HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        }
    }

    pub fn call_content(&self) -> HttpCallContent {
        HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(self.canister_id.into_vec()),
                method_name: self.method_name.clone(),
                ingress_expiry: self.ingress_expiry,
                arg: Blob(ARG),
                sender: Blob(SENDER.into_vec()),
                nonce: Some(Blob(vec![])),
            },
        }
    }

    pub fn message_id(&self) -> MessageId {
        let signed_ingress: SignedIngress = self.envelope().try_into().unwrap();
        signed_ingress.id()
    }
}

impl Call {
    pub async fn call(
        self,
        addr: SocketAddr,
        ingress_message: IngressMessage,
    ) -> reqwest::Response {
        let url = self.url(addr, ingress_message.effective_canister_id);
        Self::call_with_url(url, ingress_message).await
    }

    pub async fn call_with_custom_body(
        self,
        addr: SocketAddr,
        effective_canister_id: PrincipalId,
        body: Vec<u8>,
    ) -> reqwest::Response {
        let url = self.url(addr, effective_canister_id);
        send_request(url, body).await
    }

    pub async fn call_with_url(url: String, ingress_message: IngressMessage) -> reqwest::Response {
        let envelope = ingress_message.envelope();
        let body = serde_cbor::to_vec(&envelope).unwrap();
        send_request(url, body).await
    }

    pub fn url(self, addr: SocketAddr, effective_canister_id: PrincipalId) -> String {
        let version = match self {
            Call::V2 => "v2",
            Call::V3 => "v3",
            Call::V4 => "v4",
        };

        format!(
            "http://{}/api/{}/canister/{}/call",
            addr, version, effective_canister_id
        )
    }
}

pub struct Query {
    canister_id: PrincipalId,
    effective_canister_id: PrincipalId,
    version: query::Version,
}

impl Query {
    pub fn new(
        canister_id: PrincipalId,
        effective_canister_id: PrincipalId,
        version: query::Version,
    ) -> Self {
        Self {
            canister_id,
            effective_canister_id,
            version,
        }
    }

    pub async fn query(self, addr: SocketAddr) -> reqwest::Response {
        let url = Self::url(addr, self.version, self.effective_canister_id);
        Self::query_with_url_and_canister_id(url, self.canister_id).await
    }

    pub async fn query_with_body(&self, addr: SocketAddr, body: Vec<u8>) -> reqwest::Response {
        let url = Self::url(addr, self.version, self.effective_canister_id);
        send_request(url, body).await
    }

    pub fn url(socket: SocketAddr, version: query::Version, canister_id: PrincipalId) -> String {
        let version_str = match version {
            query::Version::V2 => "v2",
            query::Version::V3 => "v3",
        };

        format!(
            "http://{socket}/api/{version_str}/canister/{}/query",
            canister_id
        )
    }

    pub fn query_content(canister_id: PrincipalId) -> HttpQueryContent {
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();
        HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(canister_id.into_vec()),
                method_name: METHOD_NAME.to_string(),
                arg: Blob(ARG),
                sender: Blob(SENDER.into_vec()),
                ingress_expiry,
                nonce: Some(Blob(vec![])),
            },
        }
    }

    pub async fn query_with_url_and_canister_id(
        url: String,
        canister_id: PrincipalId,
    ) -> reqwest::Response {
        let call_content = Self::query_content(canister_id);

        let envelope = HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        send_request(url, body).await
    }
}

pub struct CanisterReadState {
    paths: Vec<Path>,
    effective_canister_id: PrincipalId,
    version: read_state::canister::Version,
}

impl CanisterReadState {
    pub fn new(
        paths: Vec<Path>,
        effective_canister_id: PrincipalId,
        version: read_state::canister::Version,
    ) -> Self {
        Self {
            paths,
            effective_canister_id,
            version,
        }
    }

    pub async fn read_state(self, addr: SocketAddr) -> reqwest::Response {
        let url = Self::url(addr, self.version, self.effective_canister_id);
        Self::read_state_with_custom_url(url, self.paths).await
    }

    pub async fn read_state_with_body(self, addr: SocketAddr, body: Vec<u8>) -> reqwest::Response {
        let url = Self::url(addr, self.version, self.effective_canister_id);
        send_request(url, body).await
    }

    pub async fn read_state_at_url(self, mut url: Url) -> reqwest::Response {
        let version_str = match self.version {
            read_state::canister::Version::V2 => "v2",
            read_state::canister::Version::V3 => "v3",
        };

        url.set_path(&format!(
            "api/{version_str}/canister/{}/read_state",
            self.effective_canister_id
        ));

        Self::read_state_with_custom_url(url.to_string(), self.paths).await
    }

    pub fn url(
        addr: SocketAddr,
        version: read_state::canister::Version,
        effective_canister_id: PrincipalId,
    ) -> String {
        let version_str = match version {
            read_state::canister::Version::V2 => "v2",
            read_state::canister::Version::V3 => "v3",
        };

        format!("http://{addr}/api/{version_str}/canister/{effective_canister_id}/read_state")
    }

    pub fn read_state_content(paths: Vec<Path>) -> HttpReadStateContent {
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

        HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                paths,
                sender: Blob(SENDER.into_vec()),
                ingress_expiry,
                nonce: None,
            },
        }
    }

    pub async fn read_state_with_custom_url(url: String, paths: Vec<Path>) -> reqwest::Response {
        let call_content = Self::read_state_content(paths);

        let envelope = HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        send_request(url, body).await
    }
}

pub struct SubnetReadState {
    pub subnet_id: PrincipalId,
    pub version: read_state::subnet::Version,
}

impl SubnetReadState {
    pub async fn read_state_with_body(&self, addr: SocketAddr, body: Vec<u8>) -> reqwest::Response {
        send_request(Self::url(addr, self.version, self.subnet_id), body).await
    }

    pub async fn read_state_with_custom_url(url: String, paths: Vec<Path>) -> reqwest::Response {
        let call_content = Self::read_state_content(paths);
        let envelope = HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };
        let body = serde_cbor::to_vec(&envelope).unwrap();

        send_request(url, body).await
    }

    pub fn read_state_content(paths: Vec<Path>) -> HttpReadStateContent {
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

        HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                paths,
                sender: Blob(SENDER.into_vec()),
                ingress_expiry,
                nonce: None,
            },
        }
    }

    pub fn url(
        addr: SocketAddr,
        version: read_state::subnet::Version,
        subnet_id: PrincipalId,
    ) -> String {
        let version_str = match version {
            read_state::subnet::Version::V2 => "v2",
            read_state::subnet::Version::V3 => "v3",
        };

        format!("http://{addr}/api/{version_str}/subnet/{subnet_id}/read_state")
    }
}

async fn send_request(url: String, body: Vec<u8>) -> reqwest::Response {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    client
        .post(url)
        .body(body)
        .header(CONTENT_TYPE, APPLICATION_CBOR)
        .send()
        .await
        .unwrap()
}
