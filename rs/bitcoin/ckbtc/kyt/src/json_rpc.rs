use ic_cdk::api::call::call_with_payment128;
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::http_request::HttpResponse;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
};
use num_traits::ToPrimitive;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

pub type ExternalId = String;

thread_local! {
    /// Stats for the number HTTP responses by status.
    pub static HTTP_CALL_STATS: RefCell<BTreeMap<u16, u64>> = RefCell::default();
}

// Registering a transaction
// https://docs.chainalysis.com/api/kyt/#registration

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum Network {
    #[serde(alias = "BITCOIN")]
    Bitcoin,
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Asset {
    Btc,
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Received,
}

#[derive(Eq, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTransferRequest {
    pub network: Network,
    pub asset: Asset,
    pub transfer_reference: String,
    pub direction: Direction,
}

#[derive(Eq, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTransferResponse {
    pub transfer_reference: String,
    /// The timestamp when the transfer was last updated, in the UTC ISO 8601 format.
    /// NOTE: After the initial POST request, this value will be None until KYT processes the transfer.
    /// We must poll the summary endpoint until updated_at returns a value.
    ///
    /// See: https://docs.chainalysis.com/api/kyt/guides/#workflows-polling-the-summary-endpoints
    pub updated_at: Option<String>,
    pub external_id: ExternalId,
}

impl RegisterTransferResponse {
    /// Returns true if the transfer registration completed and it's safe to use the external id to
    /// fetch alerts.
    pub fn ready(&self) -> bool {
        self.updated_at.is_some()
    }
}

#[derive(Eq, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSummaryRequest {
    pub external_id: ExternalId,
}

// https://docs.chainalysis.com/api/kyt/#transfers-get-a-summary
#[derive(Eq, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSummaryResponse {
    pub updated_at: Option<String>,
}

// https://docs.chainalysis.com/api/kyt/#withdrawal-attempts-get-a-summary
#[derive(Eq, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalSummaryResponse {
    pub updated_at: Option<String>,
}

// Register withdrawal
// https://docs.chainalysis.com/api/kyt/#transfers-get-a-summary
#[derive(PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWithdrawalRequest {
    pub network: Network,
    pub asset: Asset,
    pub attempt_identifier: String,
    pub address: String,
    pub asset_amount: f64,
    pub attempt_timestamp: String,
}

#[derive(Eq, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWithdrawalResponse {
    pub updated_at: Option<String>,
    pub external_id: ExternalId,
}

impl RegisterWithdrawalResponse {
    /// Returns true if the withdrawal registration completed and it's safe to use the external id to
    /// fetch alerts.
    pub fn ready(&self) -> bool {
        self.updated_at.is_some()
    }
}

// Alerts
// https://docs.chainalysis.com/api/kyt/#transfers-get-alerts

#[derive(Eq, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAlertsRequest {
    pub external_id: ExternalId,
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertLevel {
    Severe,
    High,
    Medium,
    Low,
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExposureType {
    Direct,
    Indirect,
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub alert_level: AlertLevel,
    pub category: Option<String>,
    pub service: Option<String>,
    pub exposure_type: ExposureType,
}

#[derive(Debug, Deserialize)]
pub struct GetAlertsResponse {
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Error {
    pub status: u16,
    pub error: Option<String>,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            Some(kind) => write!(f, "{}: {}", kind, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl Error {
    pub fn is_access_denied_error(&self) -> bool {
        self.status == 403
    }
}

pub async fn http_call<I: Serialize, O: DeserializeOwned>(
    method: HttpMethod,
    api_key: String,
    endpoint: String,
    payload: I,
) -> CallResult<Result<O, Error>> {
    const KIB: u64 = 1024;
    let payload = serde_json::to_string(&payload).unwrap();
    let request = CanisterHttpRequestArgument {
        url: format!("https://api.chainalysis.com/api/kyt/{}", endpoint),
        max_response_bytes: Some(100 * KIB),
        method,
        headers: vec![
            HttpHeader {
                name: "Token".to_string(),
                value: api_key,
            },
            HttpHeader {
                name: "Content-type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: Some(payload.into_bytes()),
        transform: Some(TransformContext::from_name(
            "cleanup_response".to_owned(),
            vec![],
        )),
    };

    // Details of the values used in the following lines can be found here:
    // https://internetcomputer.org/docs/current/developer-docs/production/computation-and-storage-costs
    const HTTP_MAX_SIZE: u128 = 2 * 1024 * 1024;
    let base_cycles = 400_000_000u128 + 100_000u128 * (2 * HTTP_MAX_SIZE);

    const BASE_SUBNET_SIZE: u128 = 13;
    const SUBNET_SIZE: u128 = 34;
    let cycles = base_cycles * SUBNET_SIZE / BASE_SUBNET_SIZE;

    let (response,): (HttpResponse,) = call_with_payment128(
        candid::Principal::management_canister(),
        "http_request",
        (request,),
        cycles,
    )
    .await?;

    HTTP_CALL_STATS.with(|c| {
        *c.borrow_mut()
            .entry(response.status.0.to_u16().unwrap())
            .or_default() += 1
    });

    Ok(if response.status < 300u64 {
        let result: O = serde_json::from_slice(&response.body).unwrap_or_else(|e| {
            panic!(
                "failed to decode response {}: {}",
                String::from_utf8_lossy(&response.body),
                e
            )
        });
        Ok(result)
    } else {
        let e: Error = serde_json::from_slice(&response.body).unwrap_or_else(|e| {
            panic!(
                "failed to decode error {}: {}",
                String::from_utf8_lossy(&response.body),
                e
            )
        });
        Err(e)
    })
}

#[test]
fn test_registration_encoding() {
    let request = RegisterTransferRequest {
        network: Network::Bitcoin,
        asset: Asset::Btc,
        transfer_reference: "2d9bfc3a47c2c9cfd0170198782979ed327442e5ed1c8a752bced24d490347d4:1H7aVb2RZiBmdbnzazQgVj2hWR3eEZPg6v".to_string(),
        direction: Direction::Received,
    };
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        serde_json::json!({
            "network": "Bitcoin",
            "asset": "BTC",
            "transferReference": "2d9bfc3a47c2c9cfd0170198782979ed327442e5ed1c8a752bced24d490347d4:1H7aVb2RZiBmdbnzazQgVj2hWR3eEZPg6v",
            "direction": "received",
        }),
    );
}

#[test]
fn test_registration_response_decoding() {
    let response: RegisterTransferResponse = serde_json::from_str(
        r#"
{
    "updatedAt": null,
    "asset": "BTC",
    "network": "BITCOIN",
    "transferReference": "2d9bfc3a47c2c9cfd0170198782979ed327442e5ed1c8a752bced24d490347d4:1H7aVb2RZiBmdbnzazQgVj2hWR3eEZPg6v",
    "tx": null,
    "idx": null,
    "usdAmount": null,
    "assetAmount": null,
    "timestamp": null,
    "outputAddress": null,
    "externalId": "fc8e053e-8833-344d-b025-40559eafd16f"
}
"#,
    )
    .unwrap();
    assert_eq!(
        response,
        RegisterTransferResponse {
            transfer_reference: "2d9bfc3a47c2c9cfd0170198782979ed327442e5ed1c8a752bced24d490347d4:1H7aVb2RZiBmdbnzazQgVj2hWR3eEZPg6v".to_string(),
            external_id: "fc8e053e-8833-344d-b025-40559eafd16f".to_string(),
            updated_at: None,
        }
    );
}

#[test]
fn test_alerts_decoding() {
    let response: GetAlertsResponse = serde_json::from_str(
        r#"
{
    "alerts": [
        {
            "alertLevel": "HIGH",
            "category": "custom address",
            "service": "Play Royal",
            "externalId": "906ff226-8b64-11eb-8e52-7b35a3dc1742",
            "alertAmount": 5000.00,
            "exposureType": "DIRECT"
        }
    ]
}
"#,
    )
    .unwrap();
    assert_eq!(
        response.alerts,
        vec![Alert {
            alert_level: AlertLevel::High,
            category: Some("custom address".to_string()),
            service: Some("Play Royal".to_string()),
            exposure_type: ExposureType::Direct,
        }]
    );
}
