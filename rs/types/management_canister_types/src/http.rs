use crate::{BoundedVec, DataSize, Payload};
use candid::{CandidType, Deserialize};
use ic_base_types::PrincipalId;
use serde::Serialize;

/// Struct used for encoding/decoding
/// ```text
/// record {
///   response : http_response;
///   context : blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct TransformArgs {
    pub response: CanisterHttpResponsePayload,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

impl Payload<'_> for TransformArgs {}

// Encapsulating the corresponding candid `func` type.
candid::define_function!(pub TransformFunc : (TransformArgs) -> (CanisterHttpResponsePayload) query);

/// Struct used for encoding/decoding
/// ```text
/// record {
///   function : func (record {response : http_response; context : blob}) -> (http_response) query;
///   context : blob;
/// }
/// ```
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct TransformContext {
    /// Reference function with signature: `func (record {response : http_response; context : blob}) -> (http_response) query;`.
    pub function: TransformFunc,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

/// Kibibyte or 1024 bytes.
const KIB: usize = 1_024;

/// Maximum number of HTTP headers in the request.
///
/// Described in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request>.
const HTTP_HEADERS_MAX_NUMBER: usize = 64;

/// Maximum size of all the HTTP headers in the request.
///
/// Described in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request>.
const HTTP_HEADERS_TOTAL_MAX_SIZE: usize = 48 * KIB;

/// Maximum size of a single HTTP header in the request.
///
/// Described in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request>.
const HTTP_HEADERS_ELEMENT_MAX_SIZE: usize = 16 * KIB; // name + value = 8KiB + 8KiB

/// The numeric representation for the Legacy pricing version.
pub const PRICING_VERSION_LEGACY: u32 = 1;
/// The numeric representation for the Pay-As-You-Go pricing version.
pub const PRICING_VERSION_PAY_AS_YOU_GO: u32 = 2;

/// The default pricing version for HTTP outcalls.
///
/// If the field is missing, this is the version that will be assumed by the replica.
/// Described in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request>.
pub const DEFAULT_HTTP_OUTCALLS_PRICING_VERSION: u32 = PRICING_VERSION_LEGACY;

/// A set of all allowed pricing versions for HTTP outcalls.
///
/// If the pricing version provided in the request is not in this set, the request will use the default pricing version.
pub const ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS: &[u32] = &[PRICING_VERSION_LEGACY];

/// HTTP headers bounded by total size.
pub type BoundedHttpHeaders = BoundedVec<
    HTTP_HEADERS_MAX_NUMBER,
    HTTP_HEADERS_TOTAL_MAX_SIZE,
    HTTP_HEADERS_ELEMENT_MAX_SIZE,
    HttpHeader,
>;

/// Struct used for encoding/decoding
/// ```text
/// record {
///   url : text;
///   max_response_bytes : opt nat64;
///   headers : vec http_header;
///   method : variant { get; head; post };
///   body : opt blob;
///   transform : opt record {
///     function : func (record {response : http_response; context : blob}) -> (http_response) query;
///     context : blob;
///   };
///   is_replicated : opt bool;
///   pricing_version : opt nat32;
/// }
/// ```
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterHttpRequestArgs {
    pub url: String,
    pub max_response_bytes: Option<u64>,
    pub headers: BoundedHttpHeaders,
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub body: Option<Vec<u8>>,
    pub method: HttpMethod,
    pub transform: Option<TransformContext>,
    pub is_replicated: Option<bool>,
    pub pricing_version: Option<u32>,
}

impl Payload<'_> for CanisterHttpRequestArgs {}

impl CanisterHttpRequestArgs {
    /// Return the principal id of the canister that supports the transform function,
    /// or None if it was not specified.
    pub fn transform_principal(&self) -> Option<PrincipalId> {
        self.transform
            .as_ref()
            .map(|transform_context| PrincipalId::from(transform_context.function.0.principal))
    }
}

#[test]
fn test_http_headers_max_number() {
    // This test verifies the number of HTTP headers stays within the allowed limit.
    use ic_error_types::ErrorCode;

    const THRESHOLD: usize = 64;
    for headers_count in (52..=76).step_by(2) {
        // Arrange.
        let header = HttpHeader {
            name: "name".to_string(),
            value: "value".to_string(),
        };
        let headers = BoundedHttpHeaders::new(vec![header; headers_count]);
        let args = CanisterHttpRequestArgs {
            url: "http://example.com".to_string(),
            max_response_bytes: None,
            headers,
            body: None,
            method: HttpMethod::GET,
            transform: None,
            is_replicated: None,
            pricing_version: None,
        };

        // Act.
        let result = CanisterHttpRequestArgs::decode(&args.encode());

        // Assert.
        if headers_count <= THRESHOLD {
            // Verify decoding without errors for allowed sizes.
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), args);
        } else {
            // Verify decoding with errors for disallowed sizes.
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                error.description().contains(&format!(
                    "Deserialize error: The number of elements exceeds maximum allowed {THRESHOLD}"
                )),
                "Actual: {}",
                error.description()
            );
        }
    }
}

#[test]
fn test_http_headers_max_total_size() {
    // This test verifies the size of HTTP headers stays within the allowed limit.
    use ic_error_types::ErrorCode;

    const THRESHOLD: usize = 48 * KIB;
    // Don't use fractional step size, it must not overlap with the threshold.
    let step_size = THRESHOLD / 20 + 1;
    assert_ne!(THRESHOLD % step_size, 0);
    for aimed_headers_total_size in (16 * KIB..=64 * KIB).step_by(step_size) {
        // Arrange.
        let header = HttpHeader {
            name: String::from_utf8(vec![b'x'; step_size]).unwrap(),
            value: String::new(),
        };
        let item_size = header.data_size();
        let headers_count = aimed_headers_total_size / item_size;
        let headers = BoundedHttpHeaders::new(vec![header; headers_count]);
        let actual_headers_total_size = headers.get().data_size();
        let args = CanisterHttpRequestArgs {
            url: "http://example.com".to_string(),
            max_response_bytes: None,
            headers,
            body: None,
            method: HttpMethod::GET,
            transform: None,
            is_replicated: None,
            pricing_version: None,
        };

        // Act.
        let result = CanisterHttpRequestArgs::decode(&args.encode());

        // Assert.
        if actual_headers_total_size <= THRESHOLD {
            // Verify decoding without errors for allowed sizes.
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), args);
        } else {
            // Verify decoding with errors for disallowed sizes.
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                error.description().contains(&format!(
                    "Deserialize error: The total data size exceeds maximum allowed {THRESHOLD}"
                )),
                "Actual: {}",
                error.description()
            );
        }
    }
}

#[test]
fn test_http_headers_max_element_size() {
    // This test verifies the size of any single HTTP header in headers stays within the allowed limit.
    use ic_error_types::ErrorCode;

    const THRESHOLD: usize = 16 * KIB;
    for single_header_size in (4 * KIB..=24 * KIB).step_by(2 * KIB) {
        // Arrange.
        let header = HttpHeader {
            name: String::from_utf8(vec![b'x'; single_header_size]).unwrap(),
            value: String::new(),
        };
        let headers = BoundedHttpHeaders::new(vec![header; 2]);
        let args = CanisterHttpRequestArgs {
            url: "http://example.com".to_string(),
            max_response_bytes: None,
            headers,
            body: None,
            method: HttpMethod::GET,
            transform: None,
            is_replicated: None,
            pricing_version: None,
        };

        // Act.
        let result = CanisterHttpRequestArgs::decode(&args.encode());

        // Assert.
        if single_header_size <= THRESHOLD {
            // Verify decoding without errors for allowed sizes.
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), args);
        } else {
            // Verify decoding with errors for disallowed sizes.
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                error.description().contains(&format!(
                    "Deserialize error: The single element data size exceeds maximum allowed {THRESHOLD}"
                )),
                "Actual: {}",
                error.description()
            );
        }
    }
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   name : text;
///   value : text;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl Payload<'_> for HttpHeader {}

impl DataSize for HttpHeader {
    fn data_size(&self) -> usize {
        self.name.data_size() + self.value.data_size()
    }
}

#[test]
fn test_http_header_data_size() {
    let test_cases = vec![
        // name, value, expected_size
        ("", "", 0),
        ("a", "", 1),
        ("", "b", 1),
        ("a", "b", 2),
    ];
    for (name, value, expected_size) in test_cases {
        let header = HttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        };
        assert_eq!(
            header.data_size(),
            expected_size,
            "Header size does not match for {header:?}"
        );
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
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
/// ```text
/// record {
///   status : nat;
///   headers : vec http_header;
///   body : blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct CanisterHttpResponsePayload {
    pub status: u128,
    pub headers: Vec<HttpHeader>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

impl Payload<'_> for CanisterHttpResponsePayload {}
