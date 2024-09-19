use crate::{assert_reply, CkEthSetup, MAX_TICKS};
use candid::{Decode, Encode};
use ic_cdk::api::management_canister::http_request::{
    HttpResponse as OutCallHttpResponse, TransformArgs,
};
use ic_state_machine_tests::{
    CallbackId, CanisterHttpMethod, CanisterHttpRequestContext, CanisterHttpResponsePayload,
    PayloadBuilder, RejectCode, StateMachine,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use strum::IntoEnumIterator;

trait Matcher {
    fn matches(&self, context: &CanisterHttpRequestContext) -> bool;
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, strum_macros::EnumIter)]
pub enum JsonRpcProvider {
    //order is top-to-bottom and must match order used in production
    BlockPi,
    PublicNode,
    LlamaNodes,
}

impl JsonRpcProvider {
    fn url(&self) -> &str {
        match self {
            JsonRpcProvider::BlockPi => "https://ethereum.blockpi.network/v1/rpc/public",
            JsonRpcProvider::PublicNode => "https://ethereum-rpc.publicnode.com",
            JsonRpcProvider::LlamaNodes => "https://eth.llamarpc.com",
        }
    }
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

    fn tick_until_next_http_request(&self, env: &StateMachine) {
        let method = self.json_rpc_method.to_string();
        for _ in 0..MAX_TICKS {
            let matching_method = env
                .canister_http_request_contexts()
                .values()
                .any(|context| {
                    JsonRpcRequest::from_str(
                        std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                    )
                    .expect("BUG: invalid JSON RPC method")
                    .method
                    .to_string()
                        == method
                });
            if matching_method {
                break;
            }
            env.tick();
            env.advance_time(Duration::from_nanos(1));
        }
    }

    pub fn find_rpc_call(
        &self,
        env: &StateMachine,
    ) -> Option<(CallbackId, CanisterHttpRequestContext)> {
        self.tick_until_next_http_request(env);
        env.canister_http_request_contexts()
            .into_iter()
            .find(|(_id, context)| self.matches(context))
    }
}

impl Matcher for JsonRpcRequestMatcher {
    fn matches(&self, context: &CanisterHttpRequestContext) -> bool {
        let has_json_content_type_header = context
            .headers
            .iter()
            .any(|header| header.name == "Content-Type" && header.value == "application/json");
        let has_expected_max_response_bytes =
            match (self.max_response_bytes, context.max_response_bytes) {
                (Some(expected), Some(actual)) => expected == actual.get(),
                (Some(_), None) => false,
                (None, _) => true,
            };
        let request_body = context
            .body
            .as_ref()
            .map(|body| std::str::from_utf8(body).unwrap())
            .expect("BUG: missing request body");
        let json_rpc_request =
            JsonRpcRequest::from_str(request_body).expect("BUG: invalid JSON RPC request");

        self.http_method == context.http_method
            && self.provider.url() == context.url
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
    fn expect_no_matching_rpc_call(self, env: &StateMachine) {
        if let Some((id, _)) = self.matcher.find_rpc_call(env) {
            panic!(
                "expect no request matching the stub {:?} but found one {}",
                self, id
            );
        }
    }

    fn expect_rpc_call(self, env: &StateMachine) {
        let (id, context) = self.matcher.find_rpc_call(env).unwrap_or_else(|| {
            panic!(
                "no request found matching the stub {:?}. Current requests {}",
                self,
                debug_http_outcalls(env)
            )
        });
        let request_id = {
            let request_body = context
                .body
                .as_ref()
                .map(|body| std::str::from_utf8(body).unwrap())
                .expect("BUG: missing request body");
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

        if let Some(max_response_bytes) = context.max_response_bytes {
            if (response_body.len() as u64) > max_response_bytes.get() {
                let mut payload = PayloadBuilder::new();
                payload = payload.http_response_failure(
                    id,
                    RejectCode::SysFatal,
                    format!(
                        "Http body exceeds size limit of {} bytes.",
                        max_response_bytes
                    ),
                );
                env.execute_payload(payload);
                return;
            }
        }

        let clean_up_context = match context.transform.clone() {
            Some(transform) => transform.context,
            None => vec![],
        };
        let transform_arg = TransformArgs {
            response: OutCallHttpResponse {
                status: 200_u8.into(),
                headers: vec![],
                body: response_body,
            },
            context: clean_up_context.to_vec(),
        };
        let canister_id_cleanup_response = context.request.sender;
        let clean_up_response = Decode!(
            &assert_reply(
                env.execute_ingress(
                    canister_id_cleanup_response,
                    "cleanup_response",
                    Encode!(&transform_arg).unwrap(),
                )
                .expect("failed to query transform http response")
            ),
            OutCallHttpResponse
        )
        .unwrap();

        if let Some(max_response_bytes) = context.max_response_bytes {
            if (clean_up_response.body.len() as u64) > max_response_bytes.get() {
                let mut payload = PayloadBuilder::new();
                payload = payload.http_response_failure(
                    id,
                    RejectCode::SysFatal,
                    format!(
                        "Http body exceeds size limit of {} bytes.",
                        max_response_bytes
                    ),
                );
                env.execute_payload(payload);
                return;
            }
        }

        let http_response = CanisterHttpResponsePayload {
            status: 200_u128,
            headers: vec![],
            body: clean_up_response.body,
        };
        let mut payload = PayloadBuilder::new();
        payload = payload.http_response(id, &http_response);
        env.execute_payload(payload);
    }
}

fn debug_http_outcalls(env: &StateMachine) -> String {
    let mut debug_str = vec![];
    for context in env.canister_http_request_contexts().values() {
        let request_body = context
            .body
            .as_ref()
            .map(|body| std::str::from_utf8(body).unwrap())
            .expect("BUG: missing request body");
        debug_str.push(format!(
            "{:?} {} (max_response_bytes={:?}) {}",
            context.http_method, context.url, context.max_response_bytes, request_body
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

    pub fn respond_with<T: Serialize>(mut self, provider: JsonRpcProvider, response: T) -> Self {
        self.responses
            .insert(provider, serde_json::to_value(response).unwrap());
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

    pub fn respond_for_all_with<T: Serialize + Clone>(mut self, response: T) -> Self {
        for provider in JsonRpcProvider::iter() {
            self = self.respond_with(provider, response.clone());
        }
        self
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
