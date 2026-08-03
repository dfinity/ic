use crate::{CkEthSetup, JsonRpcProvider, MAX_TICKS};
use pocket_ic::PocketIc;
use pocket_ic::common::rest::{
    CanisterHttpMethod, CanisterHttpReject, CanisterHttpReply, CanisterHttpRequest,
    CanisterHttpResponse, MockCanisterHttpResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use strum::IntoEnumIterator;

trait Matcher {
    fn matches(&self, request: &CanisterHttpRequest) -> bool;
}

pub struct MockJsonRpcProviders {
    stubs: Vec<StubOnce>,
}

//variants are prefixed by Eth because it's the names of those methods in the Ethereum JSON-RPC API
#[allow(clippy::enum_variant_names)]
#[derive(Clone, PartialEq, Debug, strum_macros::Display, strum_macros::EnumString)]
pub enum JsonRpcMethod {
    #[strum(serialize = "eth_getBlockByNumber")]
    EthGetBlockByNumber,

    #[strum(serialize = "eth_getLogs")]
    EthGetLogs,

    #[strum(serialize = "eth_getTransactionCount")]
    EthGetTransactionCount,

    #[strum(serialize = "eth_getTransactionReceipt")]
    EthGetTransactionReceipt,

    #[strum(serialize = "eth_feeHistory")]
    EthFeeHistory,

    #[strum(serialize = "eth_sendRawTransaction")]
    EthSendRawTransaction,
}

#[derive(Debug)]
pub struct JsonRpcRequest {
    pub method: JsonRpcMethod,
    id: u64,
    params: serde_json::Value,
}

impl FromStr for JsonRpcRequest {
    type Err = String;

    fn from_str(request_body: &str) -> Result<Self, Self::Err> {
        let mut json_request: serde_json::Value = serde_json::from_str(request_body).unwrap();
        let method = json_request
            .get("method")
            .and_then(|method| method.as_str())
            .and_then(|method| JsonRpcMethod::from_str(method).ok())
            .ok_or("BUG: missing JSON RPC method")?;
        let id = json_request
            .get("id")
            .and_then(|id| id.as_u64())
            .ok_or("BUG: missing request ID")?;
        let params = json_request
            .get_mut("params")
            .ok_or("BUG: missing request parameters")?
            .take();
        Ok(Self { method, id, params })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct JsonRpcRequestMatcher {
    http_method: CanisterHttpMethod,
    provider: JsonRpcProvider,
    json_rpc_method: JsonRpcMethod,
    match_request_params: Option<serde_json::Value>,
    max_response_bytes: Option<u64>,
}

impl JsonRpcRequestMatcher {
    pub fn new(provider: JsonRpcProvider, method: JsonRpcMethod) -> Self {
        Self {
            http_method: CanisterHttpMethod::POST,
            provider,
            json_rpc_method: method,
            match_request_params: None,
            max_response_bytes: None,
        }
    }

    pub fn new_for_all_providers(method: JsonRpcMethod) -> BTreeMap<JsonRpcProvider, Self> {
        JsonRpcProvider::iter()
            .map(|provider| (provider, Self::new(provider, method.clone())))
            .collect()
    }

    pub fn with_request_params(mut self, params: Option<serde_json::Value>) -> Self {
        self.match_request_params = params;
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: Option<u64>) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    fn tick_until_next_http_request(&self, env: &PocketIc) {
        for _ in 0..MAX_TICKS {
            let has_matching_request = env
                .get_canister_http()
                .iter()
                .any(|request| self.matches(request));
            if has_matching_request {
                break;
            }
            env.tick();
            env.advance_time(Duration::from_nanos(1));
        }
    }

    pub fn find_rpc_call(&self, env: &PocketIc) -> Option<CanisterHttpRequest> {
        self.tick_until_next_http_request(env);
        env.get_canister_http()
            .into_iter()
            .find(|request| self.matches(request))
    }
}

impl Matcher for JsonRpcRequestMatcher {
    fn matches(&self, request: &CanisterHttpRequest) -> bool {
        let has_json_content_type_header = request.headers.iter().any(|header| {
            header.name.to_lowercase() == "content-type" && header.value == "application/json"
        });
        let has_expected_max_response_bytes =
            match (self.max_response_bytes, request.max_response_bytes) {
                (Some(expected), Some(actual)) => expected == actual,
                (Some(_), None) => false,
                (None, _) => true,
            };
        let request_body = std::str::from_utf8(&request.body).unwrap();
        let json_rpc_request =
            JsonRpcRequest::from_str(request_body).expect("BUG: invalid JSON RPC request");

        self.http_method == request.http_method
            && self.provider.url() == request.url
            && has_expected_max_response_bytes
            && has_json_content_type_header
            && self.json_rpc_method == json_rpc_request.method
            && self
                .match_request_params
                .as_ref()
                .map(|expected_params| expected_params == &json_rpc_request.params)
                .unwrap_or(true)
    }
}

#[derive(Clone, PartialEq, Debug)]
struct StubOnce {
    matcher: JsonRpcRequestMatcher,
    response_result: serde_json::Value,
}

impl StubOnce {
    fn expect_no_matching_rpc_call(self, env: &PocketIc) {
        if let Some(request) = self.matcher.find_rpc_call(env) {
            panic!(
                "expect no request matching the stub {self:?} but found one {}",
                request.request_id
            );
        }
    }

    fn expect_rpc_call(self, env: &PocketIc) {
        let request = self.matcher.find_rpc_call(env).unwrap_or_else(|| {
            panic!(
                "no request found matching the stub {:?}. Current requests {}",
                self,
                debug_http_outcalls(env)
            )
        });
        let request_id = {
            let request_body = std::str::from_utf8(&request.body).unwrap();
            JsonRpcRequest::from_str(request_body)
                .expect("BUG: invalid JSON RPC request")
                .id
        };

        let response_body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0",
            "result": self.response_result,
            "id": request_id,
        }))
        .unwrap();

        let response = match request.max_response_bytes {
            Some(max_response_bytes) if (response_body.len() as u64) > max_response_bytes => {
                CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
                    reject_code: crate::REJECT_CODE_SYS_FATAL,
                    message: format!("Http body exceeds size limit of {max_response_bytes} bytes."),
                })
            }
            _ => CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: response_body,
            }),
        };

        env.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: request.subnet_id,
            request_id: request.request_id,
            response,
            additional_responses: vec![],
        });
        env.tick();
    }
}

pub fn debug_http_outcalls(env: &PocketIc) -> String {
    let mut debug_str = vec![];
    for request in env.get_canister_http() {
        let request_body = std::str::from_utf8(&request.body).unwrap();
        debug_str.push(format!(
            "{:?} {} (max_response_bytes={:?}) {}",
            request.http_method, request.url, request.max_response_bytes, request_body
        ));
    }
    debug_str.join("\n")
}

impl MockJsonRpcProviders {
    pub fn when(json_rpc_method: JsonRpcMethod) -> MockJsonRpcProvidersBuilder {
        MockJsonRpcProvidersBuilder {
            json_rpc_method,
            json_rpc_params: None,
            max_response_bytes: None,
            responses: Default::default(),
        }
    }

    pub fn expect_rpc_calls<T: AsRef<CkEthSetup>>(self, cketh: T) {
        let cketh = cketh.as_ref();
        for stub in self.stubs {
            stub.expect_rpc_call(&cketh.env);
        }
    }

    pub fn expect_no_rpc_calls<T: AsRef<CkEthSetup>>(self, cketh: T) {
        let cketh = cketh.as_ref();
        for stub in self.stubs {
            stub.expect_no_matching_rpc_call(&cketh.env);
        }
    }
}

pub struct MockJsonRpcProvidersBuilder {
    json_rpc_method: JsonRpcMethod,
    json_rpc_params: Option<serde_json::Value>,
    max_response_bytes: Option<u64>,
    responses: BTreeMap<JsonRpcProvider, serde_json::Value>,
}

impl MockJsonRpcProvidersBuilder {
    pub fn with_request_params(mut self, params: serde_json::Value) -> Self {
        self.json_rpc_params = Some(params);
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = Some(max_response_bytes);
        self
    }

    pub fn respond_with<T: Serialize>(self, provider: JsonRpcProvider, response: T) -> Self {
        self.respond_for_providers_with(std::iter::once(provider), response)
    }

    pub fn respond_for_providers_with<T: Serialize, I: IntoIterator<Item = JsonRpcProvider>>(
        mut self,
        providers: I,
        response: T,
    ) -> Self {
        let response = serde_json::to_value(response).unwrap();
        for provider in providers {
            self.responses.insert(provider, response.clone());
        }
        self
    }

    pub fn modify_response<T: Serialize + DeserializeOwned, F: FnMut(&mut T)>(
        mut self,
        provider: JsonRpcProvider,
        mutator: &mut F,
    ) -> Self {
        let previous_serialized_response = self
            .responses
            .remove(&provider)
            .expect("BUG: no responses registered for provider");
        let mut previous_response: T = serde_json::from_value(previous_serialized_response)
            .expect("BUG: cannot deserialize previous response");
        mutator(&mut previous_response);
        self.respond_with(provider, previous_response)
    }

    pub fn respond_for_all_with<T: Serialize>(self, response: T) -> Self {
        self.respond_for_providers_with(JsonRpcProvider::iter(), response)
    }

    pub fn modify_response_for_all<T: Serialize + DeserializeOwned, F: FnMut(&mut T)>(
        mut self,
        mutator: &mut F,
    ) -> Self {
        for provider in JsonRpcProvider::iter() {
            self = self.modify_response(provider, mutator)
        }
        self
    }

    pub fn build(self) -> MockJsonRpcProviders {
        assert!(
            !self.responses.is_empty(),
            "BUG: Missing at least one response for the mock!"
        );
        let mut stubs = Vec::with_capacity(self.responses.len());
        self.responses.into_iter().for_each(|(provider, response)| {
            stubs.push(StubOnce {
                matcher: JsonRpcRequestMatcher::new(provider, self.json_rpc_method.clone())
                    .with_request_params(self.json_rpc_params.clone())
                    .with_max_response_bytes(self.max_response_bytes),
                response_result: response,
            });
        });
        MockJsonRpcProviders { stubs }
    }
}
