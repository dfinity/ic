//! Canister HTTP request.

use crate::api::call::{call_with_payment128, CallResult};
use candid::{
    parser::types::FuncMode,
    types::{Function, Serializer, Type},
    CandidType, Principal,
};
use core::hash::Hash;
use serde::{Deserialize, Serialize};

/// "transform" function of type: `func (http_response) -> (http_response) query`
#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct TransformFunc(pub candid::Func);

impl CandidType for TransformFunc {
    fn _ty() -> Type {
        Type::Func(Function {
            modes: vec![FuncMode::Query],
            args: vec![HttpResponse::ty()],
            rets: vec![HttpResponse::ty()],
        })
    }

    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        serializer.serialize_function(self.0.principal.as_slice(), &self.0.method)
    }
}

/// "transform" reference function type:
/// `opt variant { function: func (http_response) -> (http_response) query }`
#[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
pub enum TransformType {
    /// reference function with signature: `func (http_response) -> (http_response) query`
    #[serde(rename = "function")]
    Function(TransformFunc),
}

impl TransformType {
    /// Construct `TransformType` from a transform function.
    ///
    /// # example
    ///
    /// ```ignore
    /// #[ic_cdk_macros::query]
    /// fn my_transform(arg: HttpResponse) -> HttpResponse {
    ///     ...
    /// }
    ///
    /// let transform = TransformType::from_transform_function(my_transform);
    /// ```
    pub fn from_transform_function<T>(func: T) -> Self
    where
        T: Fn(HttpResponse) -> HttpResponse,
    {
        Self::Function(TransformFunc(candid::Func {
            principal: crate::id(),
            method: get_function_name(func).to_string(),
        }))
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
#[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
pub struct CanisterHttpRequestArgument {
    /// The requested URL.
    pub url: String,
    /// The maximal size of the response in bytes. If None, 2MiB will be the limit.
    pub max_response_bytes: Option<u64>,
    /// The method of HTTP request.
    pub method: HttpMethod,
    /// List of HTTP request headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// Optionally provide request body.
    pub body: Option<Vec<u8>>,
    /// Name of the transform function which is `func (http_response) -> (http_response) query`.
    pub transform: Option<TransformType>,
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
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// See source code for the exact function.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
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

fn http_request_required_cycles(arg: &CanisterHttpRequestArgument) -> u128 {
    let max_response_bytes = match arg.max_response_bytes {
        Some(ref n) => *n as u128,
        None => 2 * 1024 * 1024u128, // default 2MiB
    };
    let arg_raw = candid::utils::encode_args((arg,)).expect("Failed to encode arguments.");
    // TODO: this formula should be documented somewhere
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
        assert_eq!(http_request_required_cycles(&arg), 716500000u128);
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
        assert_eq!(http_request_required_cycles(&arg), 210130900000u128);
    }

    #[test]
    fn get_function_name_work() {
        fn func() {}
        assert_eq!(get_function_name(func), "func");
    }
}
