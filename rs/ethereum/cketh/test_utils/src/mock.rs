use crate::{assert_reply, CkEthSetup, MAX_TICKS};
use candid::{Decode, Encode};
use ic_cdk::api::management_canister::http_request::{
    HttpResponse as OutCallHttpResponse, TransformArgs,
};
use pocket_ic::common::rest::{
    CanisterHttpMethod, CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse,
    MockCanisterHttpResponse,
};
use pocket_ic::PocketIc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use strum::IntoEnumIterator;

trait Matcher {
    fn matches(&self, context: &CanisterHttpRequest) -> bool;
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

    fn tick_until_next_http_request(&self, env: &PocketIc) {
        let method = self.json_rpc_method.to_string();
        for _ in 0..MAX_TICKS {
            let matching_method = env.get_canister_http().into_iter().any(|context| {
                JsonRpcRequest::from_str(std::str::from_utf8(&context.body).unwrap())
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

    pub fn find_rpc_call(&self, env: &PocketIc) -> Option<CanisterHttpRequest> {
        self.tick_until_next_http_request(env);
        env.get_canister_http()
            .into_iter()
            .find(|request| self.matches(request))
    }
}

impl Matcher for JsonRpcRequestMatcher {
    fn matches(&self, context: &CanisterHttpRequest) -> bool {
        let has_json_content_type_header = context
            .headers
            .iter()
            .any(|header| header.name == "Content-Type" && header.value == "application/json");
        let has_expected_max_response_bytes =
            match (self.max_response_bytes, context.max_response_bytes) {
                (Some(expected), Some(actual)) => expected == actual,
                (Some(_), None) => false,
                (None, _) => true,
            };
        let json_rpc_request =
            JsonRpcRequest::from_str(std::str::from_utf8(&context.body).unwrap())
                .expect("BUG: invalid JSON RPC request");

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
    fn expect_no_matching_rpc_call(self, env: &PocketIc) {
        if let Some(request) = self.matcher.find_rpc_call(env) {
            panic!(
                "expect no request matching the stub {:?} but found one {:?}",
                self, request
            );
        }
    }

    fn expect_rpc_call(self, env: &PocketIc) {
        println!(
            "HTTP requests before expect_rpc_call {}",
            debug_http_outcalls(env)
        );
        let request = self.matcher.find_rpc_call(env).unwrap_or_else(|| {
            panic!(
                "no request found matching the stub {:?}. Current requests {}",
                self,
                debug_http_outcalls(env)
            )
        });
        let json_rpc_request =
            JsonRpcRequest::from_str(std::str::from_utf8(&request.body).unwrap())
                .expect("BUG: invalid JSON RPC request");
        let request_id = json_rpc_request.id;

        let response_body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0",
            "result": self.response_result,
            "id": request_id,
        }))
        .unwrap();

        // if let Some(max_response_bytes) = request.max_response_bytes {
        //     if (response_body.len() as u64) > max_response_bytes.get() {
        //         let mut payload = PayloadBuilder::new();
        //         payload = payload.http_response_failure(
        //             id,
        //             RejectCode::SysFatal,
        //             format!(
        //                 "Http body exceeds size limit of {} bytes.",
        //                 max_response_bytes
        //             ),
        //         );
        //         env.execute_payload(payload);
        //         return;
        //     }
        // }
        //
        // let clean_up_context = match context.transform.clone() {
        //     Some(transform) => transform.context,
        //     None => vec![],
        // };
        // let transform_arg = TransformArgs {
        //     response: OutCallHttpResponse {
        //         status: 200_u8.into(),
        //         headers: vec![],
        //         body: response_body,
        //     },
        //     context: clean_up_context.to_vec(),
        // };
        // let canister_id_cleanup_response = context.request.sender;
        // let clean_up_response = Decode!(
        //     &assert_reply(
        //         env.execute_ingress(
        //             canister_id_cleanup_response,
        //             "cleanup_response",
        //             Encode!(&transform_arg).unwrap(),
        //         )
        //         .expect("failed to query transform http response")
        //     ),
        //     OutCallHttpResponse
        // )
        // .unwrap();
        //
        // if let Some(max_response_bytes) = context.max_response_bytes {
        //     if (clean_up_response.body.len() as u64) > max_response_bytes.get() {
        //         let mut payload = PayloadBuilder::new();
        //         payload = payload.http_response_failure(
        //             id,
        //             RejectCode::SysFatal,
        //             format!(
        //                 "Http body exceeds size limit of {} bytes.",
        //                 max_response_bytes
        //             ),
        //         );
        //         env.execute_payload(payload);
        //         return;
        //     }
        // }
        //
        // let http_response = CanisterHttpResponsePayload {
        //     status: 200_u128,
        //     headers: vec![],
        //     body: clean_up_response.body,
        // };
        // let mut payload = PayloadBuilder::new();
        // payload = payload.http_response(id, &http_response);
        // env.execute_payload(payload);

        println!("JSON RPC mock response {:?}", json_rpc_request);
        println!("Matcher {:?}", self.matcher);
        env.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: request.subnet_id,
            request_id: request.request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200_u16,
                headers: vec![],
                body: response_body,
            }),
            additional_responses: vec![],
        });
        env.tick();
        env.tick();
        println!(
            "HTTP requests after expect_rpc_call {}",
            debug_http_outcalls(env)
        );
    }
}

pub fn debug_http_outcalls(env: &PocketIc) -> String {
    let mut debug_str = vec![];
    for context in env.get_canister_http().into_iter() {
        let request_body = std::str::from_utf8(&context.body).unwrap();
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
