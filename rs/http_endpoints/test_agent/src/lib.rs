use ic_crypto_tree_hash::Path;
use ic_http_endpoints_public::{query, read_state};
use ic_types::{
    PrincipalId,
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
        HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, MessageId, SignedIngress,
    },
    time::current_time,
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
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
            let url = format!("http://{addr}/api/v2/status");

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

            if let CBOR::Map(map) = replica_status
                && let Some(CBOR::Text(status)) =
                    map.get(&CBOR::Text("replica_health_status".to_string()))
                && status == "healthy"
            {
                return;
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

    fn envelope(&self) -> HttpRequestEnvelope<HttpCallContent> {
        let call_content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(self.canister_id.into_vec()),
                method_name: self.method_name.clone(),
                ingress_expiry: self.ingress_expiry,
                arg: Blob(ARG),
                sender: Blob(SENDER.into_vec()),
                nonce: None,
            },
        };

        HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
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
        let envelope = ingress_message.envelope();
        let body = serde_cbor::to_vec(&envelope).unwrap();

        let version = match self {
            Call::V2 => "v2",
            Call::V3 => "v3",
            Call::V4 => "v4",
        };

        let url = format!(
            "http://{}/api/{}/canister/{}/call",
            addr, version, ingress_message.effective_canister_id
        );

        reqwest::Client::new()
            .post(url)
            .body(body)
            .header(CONTENT_TYPE, APPLICATION_CBOR)
            .send()
            .await
            .unwrap()
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
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

        let call_content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(self.canister_id.into_vec()),
                method_name: METHOD_NAME.to_string(),
                arg: Blob(ARG),
                sender: Blob(SENDER.into_vec()),
                ingress_expiry,
                nonce: None,
            },
        };

        let envelope = HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();
        let version_str = match self.version {
            query::Version::V2 => "v2",
            query::Version::V3 => "v3",
        };
        let url = format!(
            "http://{addr}/api/{version_str}/canister/{}/query",
            self.effective_canister_id
        );

        reqwest::Client::new()
            .post(url)
            .body(body)
            .header(CONTENT_TYPE, APPLICATION_CBOR)
            .send()
            .await
            .unwrap()
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
        let url_string = format!("http://{addr}");
        let url = Url::parse(&url_string).unwrap();
        self.read_state_at_url(url).await
    }

    pub async fn read_state_at_url(self, mut url: Url) -> reqwest::Response {
        let ingress_expiry = (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

        let call_content = HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                paths: self.paths,
                sender: Blob(SENDER.into_vec()),
                ingress_expiry,
                nonce: None,
            },
        };

        let envelope = HttpRequestEnvelope {
            content: call_content,
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        let version_str = match self.version {
            read_state::canister::Version::V2 => "v2",
            read_state::canister::Version::V3 => "v3",
        };

        url.set_path(&format!(
            "api/{version_str}/canister/{}/read_state",
            self.effective_canister_id
        ));

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
}
