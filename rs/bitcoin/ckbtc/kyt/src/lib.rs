use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum KytMode {
    /// In this mode, the canister will not make any HTTP calls and return empty
    /// alert lists for all requests.
    AcceptAll,
    /// In this mode, the canister will mark generate bogus alerts for all requests.
    RejectAll,
    /// In this mode, the canister will call Chainalysis API for each request.
    Normal,
}

impl fmt::Display for KytMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KytMode::AcceptAll => write!(f, "AcceptAll"),
            KytMode::RejectAll => write!(f, "RejectAll"),
            KytMode::Normal => write!(f, "Normal"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct InitArg {
    /// The principal of the minter canister.
    pub minter_id: Principal,
    /// The list of callers who can update the API key.
    pub maintainers: Vec<Principal>,
    /// The mode in which this canister runs.
    pub mode: KytMode,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct SetApiKeyArg {
    pub api_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct UpgradeArg {
    pub minter_id: Option<Principal>,
    pub maintainers: Option<Vec<Principal>>,
    pub mode: Option<KytMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub enum LifecycleArg {
    InitArg(InitArg),
    UpgradeArg(UpgradeArg),
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct DepositRequest {
    pub caller: Principal,
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum AlertLevel {
    Severe,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum ExposureType {
    Direct,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct Alert {
    pub level: AlertLevel,
    pub category: Option<String>,
    pub service: Option<String>,
    pub exposure_type: ExposureType,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct FetchAlertsResponse {
    pub external_id: String,
    pub alerts: Vec<Alert>,
    pub provider: Principal,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct WithdrawalAttempt {
    /// The caller who initiated the request.
    pub caller: Principal,
    /// A unique withdrawal identifier.
    pub id: String,
    /// The BTC amount in Satoshi.
    pub amount: u64,
    /// The destination Bitcoin address.
    pub address: String,
    /// Timestamp of the withdrawal in seconds.
    pub timestamp_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub enum Error {
    TemporarilyUnavailable(String),
}
