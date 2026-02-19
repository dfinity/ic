#[cfg(test)]
mod tests;

use crate::constants::{API_KEY_MAX_SIZE, API_KEY_REPLACE_STRING, MESSAGE_FILTER_MAX_SIZE};
use crate::memory::get_api_key;
use crate::providers::SupportedRpcService;
use crate::util::hostname_from_url;
use crate::validate::validate_api_key;
use candid::CandidType;
use canlog::{LogFilter, RegexSubstitution};
use derive_more::{From, Into};
use evm_rpc_types::{LegacyRejectionCode, RpcApi, RpcError, ValidationError};
use ic_management_canister_types::HttpHeader;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub enum ResolvedRpcService {
    Api(RpcApi),
    Provider(Provider),
}

impl ResolvedRpcService {
    pub fn api(&self, override_provider: &OverrideProvider) -> Result<RpcApi, RpcError> {
        let initial_api = match self {
            Self::Api(api) => api.clone(),
            Self::Provider(provider) => provider.api(),
        };
        override_provider.apply(initial_api).map_err(|regex_error| {
            RpcError::ValidationError(ValidationError::Custom(format!(
                "BUG: regex should have been validated when initially set. Error: {regex_error}"
            )))
        })
    }

    pub fn post(
        &self,
        override_provider: &OverrideProvider,
    ) -> Result<http::request::Builder, RpcError> {
        let api = self.api(override_provider)?;
        let mut request_builder = http::Request::post(api.url);
        for HttpHeader { name, value } in api.headers.unwrap_or_default() {
            request_builder = request_builder.header(name, value);
        }
        Ok(request_builder)
    }
}

pub trait MetricValue {
    fn metric_value(&self) -> f64;
}

impl MetricValue for u32 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

impl MetricValue for u64 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

impl MetricValue for u128 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

pub trait MetricLabels {
    fn metric_labels(&self) -> Vec<(&str, &str)>;
}

impl<A: MetricLabels, B: MetricLabels> MetricLabels for (A, B) {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        [self.0.metric_labels(), self.1.metric_labels()].concat()
    }
}

impl<A: MetricLabels, B: MetricLabels, C: MetricLabels> MetricLabels for (A, B, C) {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        [
            self.0.metric_labels(),
            self.1.metric_labels(),
            self.2.metric_labels(),
        ]
        .concat()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricRpcMethod {
    pub method: String,
    pub is_manual_request: bool,
}

impl From<RpcMethod> for MetricRpcMethod {
    fn from(method: RpcMethod) -> Self {
        MetricRpcMethod {
            method: method.clone().name(),
            is_manual_request: matches!(method, RpcMethod::Custom(_)),
        }
    }
}

impl MetricLabels for MetricRpcMethod {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        let mut labels = vec![("method", self.method.as_str())];
        if self.is_manual_request {
            labels.push(("is_manual_request", "true"));
        }
        labels
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricRpcService {
    pub host: String,
    pub is_supported: bool,
}

impl MetricLabels for MetricRpcService {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        let mut labels = vec![("host", self.host.as_str())];
        if self.is_supported {
            labels.push(("is_supported_provider", "true"));
        }
        labels
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricHttpStatusCode(pub String);

impl From<u32> for MetricHttpStatusCode {
    fn from(value: u32) -> Self {
        MetricHttpStatusCode(value.to_string())
    }
}

impl MetricLabels for MetricHttpStatusCode {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        vec![("status", &self.0)]
    }
}

impl MetricLabels for LegacyRejectionCode {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        let code = match self {
            LegacyRejectionCode::NoError => "NO_ERROR",
            LegacyRejectionCode::SysFatal => "SYS_FATAL",
            LegacyRejectionCode::SysTransient => "SYS_TRANSIENT",
            LegacyRejectionCode::DestinationInvalid => "DESTINATION_INVALID",
            LegacyRejectionCode::CanisterReject => "CANISTER_REJECT",
            LegacyRejectionCode::CanisterError => "CANISTER_ERROR",
            LegacyRejectionCode::Unknown => "UNKNOWN",
        };

        vec![("code", code)]
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CandidType, Deserialize)]
pub struct Metrics {
    pub requests: HashMap<(MetricRpcMethod, MetricRpcService), u64>,
    pub responses: HashMap<(MetricRpcMethod, MetricRpcService, MetricHttpStatusCode), u64>,
    #[serde(rename = "inconsistentResponses")]
    pub inconsistent_responses: HashMap<(MetricRpcMethod, MetricRpcService), u64>,
    #[serde(rename = "cyclesCharged")]
    pub cycles_charged: HashMap<(MetricRpcMethod, MetricRpcService), u128>,
    #[serde(rename = "errHttpOutcall")]
    pub err_http_outcall: HashMap<(MetricRpcMethod, MetricRpcService, LegacyRejectionCode), u64>,
    #[serde(rename = "errMaxResponseSizeExceeded")]
    pub err_max_response_size_exceeded: HashMap<(MetricRpcMethod, MetricRpcService), u64>,
    #[serde(rename = "errNoConsensus")]
    pub err_no_consensus: HashMap<(MetricRpcMethod, MetricRpcService), u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcMethod {
    EthCall,
    EthFeeHistory,
    EthGetLogs,
    EthGetBlockByNumber,
    EthGetTransactionCount,
    EthGetTransactionReceipt,
    EthSendRawTransaction,
    Custom(String),
}

impl RpcMethod {
    pub fn name(self) -> String {
        match self {
            RpcMethod::EthCall => "eth_call".to_string(),
            RpcMethod::EthFeeHistory => "eth_feeHistory".to_string(),
            RpcMethod::EthGetLogs => "eth_getLogs".to_string(),
            RpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber".to_string(),
            RpcMethod::EthGetTransactionCount => "eth_getTransactionCount".to_string(),
            RpcMethod::EthGetTransactionReceipt => "eth_getTransactionReceipt".to_string(),
            RpcMethod::EthSendRawTransaction => "eth_sendRawTransaction".to_string(),
            RpcMethod::Custom(name) => name,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ApiKey(String);

impl ApiKey {
    /// Explicitly read API key (use sparingly)
    pub fn read(&self) -> &str {
        &self.0
    }
}

// Enable printing data structures which include an API key
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{API_KEY_REPLACE_STRING}")
    }
}

impl TryFrom<String> for ApiKey {
    type Error = String;
    fn try_from(key: String) -> Result<ApiKey, Self::Error> {
        validate_api_key(&key)?;
        Ok(ApiKey(key))
    }
}

impl Storable for ApiKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: API_KEY_MAX_SIZE,
        is_fixed_size: false,
    };
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, From, Into)]
pub struct StorableLogFilter(LogFilter);

impl Storable for StorableLogFilter {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        serde_json::to_vec(self)
            .expect("Error while serializing `LogFilter`")
            .into()
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_json::from_slice(&bytes).expect("Error while deserializing `LogFilter`")
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MESSAGE_FILTER_MAX_SIZE,
        is_fixed_size: true,
    };
}

pub type ProviderId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstHeader {
    pub name: &'static str,
    pub value: &'static str,
}

impl<'a> From<&'a ConstHeader> for HttpHeader {
    fn from(header: &'a ConstHeader) -> Self {
        HttpHeader {
            name: header.name.to_string(),
            value: header.value.to_string(),
        }
    }
}

/// Internal RPC provider representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub provider_id: ProviderId,
    pub chain_id: u64,
    pub access: RpcAccess,
    pub alias: Option<SupportedRpcService>,
}

impl Provider {
    pub fn api(&self) -> evm_rpc_types::RpcApi {
        match &self.access {
            RpcAccess::Authenticated { auth, public_url } => match get_api_key(self.provider_id) {
                Some(api_key) => match auth {
                    RpcAuth::BearerToken { url } => evm_rpc_types::RpcApi {
                        url: url.to_string(),
                        headers: Some(vec![evm_rpc_types::HttpHeader {
                            name: "Authorization".to_string(),
                            value: format!("Bearer {}", api_key.read()),
                        }]),
                    },
                    RpcAuth::UrlParameter { url_pattern } => evm_rpc_types::RpcApi {
                        url: url_pattern.replace(API_KEY_REPLACE_STRING, api_key.read()),
                        headers: None,
                    },
                },
                None => evm_rpc_types::RpcApi {
                    url: public_url
                        .unwrap_or_else(|| {
                            panic!(
                                "API key not yet initialized for provider: {}",
                                self.provider_id
                            )
                        })
                        .to_string(),
                    headers: None,
                },
            },
            RpcAccess::Unauthenticated { public_url } => evm_rpc_types::RpcApi {
                url: public_url.to_string(),
                headers: None,
            },
        }
    }

    pub fn hostname(&self) -> Option<String> {
        hostname_from_url(match &self.access {
            RpcAccess::Authenticated { auth, .. } => match auth {
                RpcAuth::BearerToken { url } => url,
                RpcAuth::UrlParameter { url_pattern } => url_pattern,
            },
            RpcAccess::Unauthenticated { public_url } => public_url,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcAccess {
    Authenticated {
        auth: RpcAuth,
        /// Public URL to use when the API key is not available.
        public_url: Option<&'static str>,
    },
    Unauthenticated {
        public_url: &'static str,
    },
}

impl RpcAccess {
    pub fn public_url(&self) -> Option<&'static str> {
        match self {
            RpcAccess::Authenticated { public_url, .. } => *public_url,
            RpcAccess::Unauthenticated { public_url } => Some(public_url),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OverrideProvider {
    pub override_url: Option<RegexSubstitution>,
}

impl OverrideProvider {
    /// Override the resolved provider API (url and headers).
    ///
    /// # Limitations
    ///
    /// Currently, only the url can be replaced by regular expression. Headers will be reset.
    ///
    /// # Security considerations
    ///
    /// The resolved provider API may contain sensitive data (such as API keys) that may be extracted
    /// by using the override mechanism. Since only the controller of the canister can set the override parameters,
    /// upon canister initialization or upgrade, it's the controller's responsibility to ensure that this is not a problem
    /// (e.g., if only used for local development).
    pub fn apply(&self, api: RpcApi) -> Result<RpcApi, regex::Error> {
        match &self.override_url {
            None => Ok(api),
            Some(substitution) => {
                let regex = substitution.pattern.compile()?;
                let new_url = regex.replace_all(&api.url, &substitution.replacement);
                Ok(RpcApi {
                    url: new_url.to_string(),
                    headers: None,
                })
            }
        }
    }
}

impl TryFrom<evm_rpc_types::OverrideProvider> for OverrideProvider {
    type Error = regex::Error;

    fn try_from(
        evm_rpc_types::OverrideProvider { override_url }: evm_rpc_types::OverrideProvider,
    ) -> Result<Self, Self::Error> {
        override_url
            .map(|url| url.pattern.compile().map(|_| url))
            .transpose()
            .map(|substitution| Self {
                override_url: substitution,
            })
    }
}

impl Storable for OverrideProvider {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        serde_json::to_vec(self)
            .expect("Error while serializing `OverrideProvider`")
            .into()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_json::from_slice(&bytes).expect("Error while deserializing `Storable`")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcAuth {
    /// API key will be used in an Authorization header as Bearer token, e.g.,
    /// `Authorization: Bearer API_KEY`
    BearerToken {
        url: &'static str,
    },
    UrlParameter {
        url_pattern: &'static str,
    },
}
