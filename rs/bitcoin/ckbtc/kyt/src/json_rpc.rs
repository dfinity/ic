use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub type ExternalId = String;

// Registering a transaction
// https://docs.chainalysis.com/api/kyt/#registration

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    #[serde(alias = "BITCOIN")]
    Bitcoin,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Asset {
    Btc,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Received,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTransferRequest {
    pub network: Network,
    pub asset: Asset,
    pub transfer_reference: String,
    pub direction: Direction,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTransferResponse {
    pub transfer_reference: String,
    pub external_id: ExternalId,
}

// Register withdrawal
// https://docs.chainalysis.com/api/kyt/#transfers-get-a-summary
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWithdrawalRequest {
    pub network: Network,
    pub asset: Asset,
    pub attempt_identifier: String,
    pub address: String,
    pub asset_amount: f64,
    pub attempt_timestamp: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWithdrawalResponse {
    pub updated_at: Option<String>,
    pub external_id: ExternalId,
}

// Alerts
// https://docs.chainalysis.com/api/kyt/#transfers-get-alerts

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAlertsRequest {
    pub external_id: ExternalId,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertLevel {
    Severe,
    High,
    Medium,
    Low,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExposureType {
    Direct,
    Indirect,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub status: u16,
    pub error: Option<String>,
    pub message: String,
}

pub async fn http_call<I: Serialize, O: DeserializeOwned>(
    method: HttpMethod,
    api_key: String,
    endpoint: String,
    payload: I,
) -> CallResult<Result<O, Error>> {
    let payload = serde_json::to_string(&payload).unwrap();
    let request = CanisterHttpRequestArgument {
        url: format!("https://api.chainalysis.com/api/kyt/{}", endpoint),
        max_response_bytes: None,
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
        transform: Some(TransformContext::new(super::cleanup_response, vec![])),
    };
    let (response,) = http_request(request).await?;
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
        serde_json::to_value(&request).unwrap(),
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
            external_id: "fc8e053e-8833-344d-b025-40559eafd16f".to_string()
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
