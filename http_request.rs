//! Canister HTTP request.

use crate::api::call::{call_with_payment128, CallResult};
use candid::{
    parser::types::FuncMode,
    types::{Function, Serializer, Type},
    CandidType, Principal,
};
use core::hash::Hash;
use serde::{Deserialize, Serialize};

/// "transform" function of type: `func (http_request) -> (http_response) query`
#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TransformFunc(pub candid::Func);

impl CandidType for TransformFunc {
    fn _ty() -> Type {
        Type::Func(Function {
            modes: vec![FuncMode::Query],
            args: vec![TransformArgs::ty()],
            rets: vec![HttpResponse::ty()],
        })
    }

    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        serializer.serialize_function(self.0.principal.as_slice(), &self.0.method)
    }
}

/// Type used for encoding/decoding:
/// `record {
///     response : http_response;
///     context : blob;
/// }`
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransformArgs {
    /// Raw response from remote service, to be transformed
    pub response: HttpResponse,

    /// Context for response transformation
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

/// Type used for encoding/decoding:
/// `record {
///     function : func (record {response : http_response; context : blob}) -> (http_response) query;
///     context : blob;
/// }`
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransformContext {
    /// Reference function with signature: `func (record {response : http_response; context : blob}) -> (http_response) query;`.
    pub function: TransformFunc,

    /// Context to be passed to `transform` function to transform HTTP response for consensus
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

impl TransformContext {
    /// Construct `TransformContext` from a transform function.
    ///
    /// # example
    ///
    /// ```no_run
    /// # use ic_cdk::api::management_canister::http_request::{TransformContext, TransformArgs, HttpResponse};
    /// #[ic_cdk::query]
    /// fn my_transform(arg: TransformArgs) -> HttpResponse {
    ///     // ...
    /// # unimplemented!()
    /// }
    /// # fn main() {
    /// # let context = vec![];
    /// let transform = TransformContext::new(my_transform, context);
    /// # }
    /// ```
    pub fn new<T>(func: T, context: Vec<u8>) -> Self
    where
        T: Fn(TransformArgs) -> HttpResponse,
    {
        Self {
            function: TransformFunc(candid::Func {
                principal: crate::id(),
                method: get_function_name(func).to_string(),
            }),
            context,
        }
    }
}

fn get_function_name<F>(_: F) -> &'static str {
    let full_name = std::any::type_name::<F>();
    match full_name.rfind(':') {
        Some(index) => &full_name[index + 1..],
        None => full_name,
    }
}

/// HTTP header.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpHeader {
    /// Name
    pub name: String,
    /// Value
    pub value: String,
}

/// HTTP method.
///
/// Currently support following methods.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub enum HttpMethod {
    /// GET
    #[serde(rename = "get")]
    GET,
    /// POST
    #[serde(rename = "post")]
    POST,
    /// HEAD
    #[serde(rename = "head")]
    HEAD,
}

/// Argument type of [http_request].
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CanisterHttpRequestArgument {
    /// The requested URL.
    pub url: String,
    /// The maximal size of the response in bytes. If None, 2MiB will be the limit.
    /// This value affects the cost of the http request and it is highly recommended
    /// to set it as low as possible to avoid unnecessary extra costs.
    /// See also the pricing section of HTTP outcalls documentation at
    /// https://internetcomputer.org/docs/current/developer-docs/integrations/http_requests/http_requests-how-it-works#pricing.
    pub max_response_bytes: Option<u64>,
    /// The method of HTTP request.
    pub method: HttpMethod,
    /// List of HTTP request headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// Optionally provide request body.
    pub body: Option<Vec<u8>>,
    /// Name of the transform function which is `func (transform_args) -> (http_response) query`.
    pub transform: Option<TransformContext>,
}

/// The returned HTTP response.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpResponse {
    /// The response status (e.g., 200, 404).
    pub status: candid::Nat,
    /// List of HTTP response headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// The response’s body.
    pub body: Vec<u8>,
}

/// Make an HTTP request to a given URL and return the HTTP response, possibly after a transformation.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// This method handles the cycles cost calculation under the hood which assuming the canister is on a 13-node Application Subnet.
/// If the canister is on a 34-node Application Subnets, you may have to compute the cost by yourself and call [http_request_with_cycles] instead.
///
/// Check [this page](https://internetcomputer.org/docs/current/developer-docs/production/computation-and-storage-costs) for more details.
pub async fn http_request(arg: CanisterHttpRequestArgument) -> CallResult<(HttpResponse,)> {
    let cycles = http_request_required_cycles(&arg);
    call_with_payment128(
        Principal::management_canister(),
        "http_request",
        (arg,),
        cycles,
    )
    .await
}

/// Make an HTTP request to a given URL and return the HTTP response, possibly after a transformation.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// Check [this page](https://internetcomputer.org/docs/current/developer-docs/production/computation-and-storage-costs) for more details.
///
/// If the canister is on a 13-node Application Subnet, you can call [http_request] instead which handles cycles cost calculation under the hood.
pub async fn http_request_with_cycles(
    arg: CanisterHttpRequestArgument,
    cycles: u128,
) -> CallResult<(HttpResponse,)> {
    call_with_payment128(
        Principal::management_canister(),
        "http_request",
        (arg,),
        cycles,
    )
    .await
}

fn http_request_required_cycles(arg: &CanisterHttpRequestArgument) -> u128 {
    let max_response_bytes = match arg.max_response_bytes {
        Some(ref n) => *n as u128,
        None => 2 * 1024 * 1024u128, // default 2MiB
    };
    let arg_raw = candid::utils::encode_args((arg,)).expect("Failed to encode arguments.");
    // The coefficients can be found in [this page](https://internetcomputer.org/docs/current/developer-docs/production/computation-and-storage-costs).
    // 12 is "http_request".len().
    400_000_000u128 + 100_000u128 * (arg_raw.len() as u128 + 12 + max_response_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_cycles_some_max() {
        let url = "https://example.com".to_string();
        let arg = CanisterHttpRequestArgument {
            url,
            max_response_bytes: Some(3000),
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            transform: None,
        };
        assert_eq!(http_request_required_cycles(&arg), 718500000u128);
    }

    #[test]
    fn required_cycles_none_max() {
        let url = "https://example.com".to_string();
        let arg = CanisterHttpRequestArgument {
            url,
            max_response_bytes: None,
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            transform: None,
        };
        assert_eq!(http_request_required_cycles(&arg), 210132900000u128);
    }

    #[test]
    fn get_function_name_work() {
        fn func() {}
        assert_eq!(get_function_name(func), "func");
    }
}
