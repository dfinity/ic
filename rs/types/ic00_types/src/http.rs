use crate::Payload;
use candid::{
    parser::types::FuncMode,
    types::{Function, Serializer, Type},
    CandidType, Deserialize,
};
use ic_base_types::PrincipalId;
use serde::Serialize;

/// Encapsulating the corresponding candid `func` type.
#[derive(Debug, Clone, Deserialize)]
pub struct TransformFunc(pub candid::Func);

impl CandidType for TransformFunc {
    fn _ty() -> Type {
        Type::Func(Function {
            modes: vec![FuncMode::Query],
            args: vec![CanisterHttpResponsePayload::ty()],
            rets: vec![CanisterHttpResponsePayload::ty()],
        })
    }

    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        serializer.serialize_function(self.0.principal.as_slice(), &self.0.method)
    }
}

/// Enum used for encoding/decoding:
/// `variant { function: func (http_response) -> (http_response) query }`
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum TransformType {
    /// Reference function with signature: `func (http_response) -> (http_response) query`.
    #[serde(rename = "function")]
    Function(TransformFunc),
}

/// Struct used for encoding/decoding
/// `(http_request : (record {
//     url : text;
//     max_response_bytes: opt nat64;
//     headers : vec http_header;
//     method : variant { get; head; post };
//     body : opt blob;
//     transform : opt variant { function: func (http_response) -> (http_response) query };
//   })`
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterHttpRequestArgs {
    pub url: String,
    pub max_response_bytes: Option<u64>,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
    pub method: HttpMethod,
    pub transform: Option<TransformType>,
}

impl Payload<'_> for CanisterHttpRequestArgs {}

impl CanisterHttpRequestArgs {
    /// Return the principal id of the canister that supports the transform function,
    /// or None if it was not specified.
    pub fn transform_principal(&self) -> Option<PrincipalId> {
        self.transform
            .as_ref()
            .map(|transform_type| match transform_type {
                TransformType::Function(func) => PrincipalId::from(func.0.principal),
            })
    }

    /// Return the name of the transform function, or None if it was not specified.
    pub fn transform_method(&self) -> Option<String> {
        self.transform
            .as_ref()
            .map(|transform_type| match transform_type {
                TransformType::Function(func) => func.0.method.clone(),
            })
    }
}

/// Struct used for encoding/decoding
/// `(record {
/// name: text;
/// value: text;
/// })`;
#[derive(CandidType, Clone, Deserialize, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl Payload<'_> for HttpHeader {}

#[derive(Clone, Debug, PartialEq, CandidType, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    #[serde(rename = "get")]
    GET,
    #[serde(rename = "post")]
    POST,
    #[serde(rename = "head")]
    HEAD,
}

/// Represents the response for a canister http request.
/// Struct used for encoding/decoding
/// `(record {
/// status: nat;
/// headers: vec http_header;
/// body: blob;
/// })`;
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponsePayload {
    pub status: u128,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl Payload<'_> for CanisterHttpResponsePayload {}
