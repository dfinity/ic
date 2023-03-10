use candid::candid_method;
use candid::Principal;
use ckbtc_kyt::{
    Alert, AlertLevel, Error, ExposureType, FetchAlertsResponse, KytMode, LifecycleArg, Outpoint,
    WithdrawalAttempt,
};
use ic_canisters_http_types as http;
use ic_cdk::api::management_canister::http_request::{HttpMethod, HttpResponse, TransformArgs};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory as VM};
use ic_stable_structures::storable::Storable;
use ic_stable_structures::{DefaultMemoryImpl, RestrictedMemory as RM, StableCell, StableLog};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt;

mod dashboard;
mod json_rpc;

/// The number of Wasm pages to use for the canister metadata.
const METADATA_PAGES: u64 = 16;
const EVENT_INDEX_ID: MemoryId = MemoryId::new(0);
const EVENT_DATA_ID: MemoryId = MemoryId::new(1);

type RestrictedMemory = RM<DefaultMemoryImpl>;
type VirtualMemory = VM<RestrictedMemory>;

#[derive(Default, Clone, PartialEq, Eq)]
struct Cbor<T>(pub T);

impl<T> std::ops::Deref for Cbor<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Cbor<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Storable for Cbor<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(&self.0, &mut buf).unwrap();
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(ciborium::de::from_reader(bytes.as_ref()).unwrap())
    }
}

fn default_kyt_mode() -> KytMode {
    KytMode::Normal
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    api_key: String,
    minter_id: Principal,
    maintainers: Vec<Principal>,
    #[serde(default = "default_kyt_mode")]
    mode: KytMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: "".to_string(),
            minter_id: Principal::anonymous(),
            maintainers: vec![],
            mode: default_kyt_mode(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "ts")]
    pub timestamp: u64,
    #[serde(rename = "kind")]
    pub kind: EventKind,
}

impl Event {
    /// Returns a textual representation of the event timestamp in UTC timezone.
    pub fn timestamp_string(&self) -> String {
        format_timestamp(self.timestamp)
    }

    /// Returns the name of the event type.
    pub fn kind_str(&self) -> &'static str {
        match &self.kind {
            EventKind::UtxoCheck { .. } => "utxo_check",
            EventKind::AddressCheck { .. } => "address_check",
            EventKind::ApiKeyUpdate { .. } => "api_key_update",
        }
    }

    /// Returns an externalId if this even is a check event.
    pub fn external_id(&self) -> Option<&str> {
        match &self.kind {
            EventKind::UtxoCheck { external_id, .. } => Some(external_id),
            EventKind::AddressCheck { external_id, .. } => Some(external_id),
            EventKind::ApiKeyUpdate { .. } => None,
        }
    }

    /// Returns false if the event is a check event and it had alerts.
    pub fn ok(&self) -> bool {
        match &self.kind {
            EventKind::UtxoCheck { alerts, .. } => alerts.is_empty(),
            EventKind::AddressCheck { alerts, .. } => alerts.is_empty(),
            EventKind::ApiKeyUpdate { .. } => true,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "utxo_check")]
    UtxoCheck {
        #[serde(rename = "txid")]
        txid: [u8; 32],
        #[serde(rename = "vout")]
        vout: u32,
        #[serde(rename = "external_id")]
        external_id: String,
        #[serde(rename = "alerts")]
        alerts: Vec<Alert>,
    },
    #[serde(rename = "address_check")]
    AddressCheck {
        #[serde(rename = "id")]
        withdrawal_id: String,
        #[serde(rename = "address")]
        address: String,
        #[serde(rename = "amount")]
        amount: u64,
        #[serde(rename = "external_id")]
        external_id: String,
        #[serde(rename = "alerts")]
        alerts: Vec<Alert>,
    },
    #[serde(rename = "api_key_update")]
    ApiKeyUpdate,
}

thread_local! {
    static MEMORY_MANAGER: MemoryManager<RestrictedMemory> =
        MemoryManager::init(
            RestrictedMemory::new(
                DefaultMemoryImpl::default(),
                METADATA_PAGES..u64::MAX/65536 - 1
            ));

    static CONFIG_CELL: RefCell<StableCell<Cbor<Config>, RestrictedMemory>> = RefCell::new(
        StableCell::init(
            RestrictedMemory::new(
                DefaultMemoryImpl::default(),
                0..METADATA_PAGES
            ),
            Cbor(Config::default()),
        ).expect("failed to initialize the config cell")
    );

    static EVENT_LOG: StableLog<Cbor<Event>, VirtualMemory, VirtualMemory> = MEMORY_MANAGER.with(|mm| {
        StableLog::init(mm.get(EVENT_INDEX_ID), mm.get(EVENT_DATA_ID))
    }).expect("failed to initialize the event log");
}

fn api_key() -> String {
    CONFIG_CELL.with(|cell| cell.borrow().get().api_key.clone())
}

fn kyt_mode() -> KytMode {
    CONFIG_CELL.with(|cell| cell.borrow().get().mode.clone())
}

fn record_event(kind: EventKind) {
    EVENT_LOG
        .with(|log| {
            log.append(&Cbor(Event {
                timestamp: ic_cdk::api::time(),
                kind,
            }))
        })
        .expect("failed to append an event");
}

pub struct DisplayTxid<'a>(pub &'a [u8]);

impl fmt::Display for DisplayTxid<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().rev() {
            write!(fmt, "{:02x}", *b)?
        }
        Ok(())
    }
}

fn caller_is_maintainer() -> Result<(), String> {
    let caller = ic_cdk::caller();
    let allowed = CONFIG_CELL.with(|cell| cell.borrow().get().maintainers.contains(&caller));
    if allowed {
        Ok(())
    } else {
        Err("The caller does not have permission to call this endpoint".to_string())
    }
}

fn caller_is_minter() -> Result<(), String> {
    let caller = ic_cdk::caller();
    let allowed = CONFIG_CELL.with(|cell| cell.borrow().get().minter_id == caller);
    if allowed {
        Ok(())
    } else {
        Err("Only ckBTC minter can call this method".to_string())
    }
}

#[init]
#[candid_method(init)]
fn init(arg: LifecycleArg) {
    let arg = match arg {
        LifecycleArg::InitArg(arg) => arg,
        LifecycleArg::UpgradeArg(_) => ic_cdk::trap("expected an InitArg on canister install"),
    };

    CONFIG_CELL.with(move |cell| {
        cell.borrow_mut()
            .set(Cbor(Config {
                api_key: arg.api_key,
                minter_id: arg.minter_id,
                maintainers: arg.maintainers,
                mode: arg.mode,
            }))
            .expect("failed to initialize the config");
    })
}

#[post_upgrade]
fn post_upgrade(arg: LifecycleArg) {
    let arg = match arg {
        LifecycleArg::UpgradeArg(arg) => arg,
        LifecycleArg::InitArg(_) => ic_cdk::trap("expected an UpgradeArg on canister install"),
    };

    CONFIG_CELL.with(|cell| {
        let mut config = cell.borrow().get().clone();
        if let Some(api_key) = arg.api_key {
            config.api_key = api_key;
        }
        if let Some(minter_id) = arg.minter_id {
            config.minter_id = minter_id;
        }
        if let Some(maintainers) = arg.maintainers {
            config.maintainers = maintainers;
        }
        if let Some(mode) = arg.mode {
            config.mode = mode;
        }
        cell.borrow_mut()
            .set(config)
            .expect("failed to update the config cell");
    })
}

#[update(guard = "caller_is_maintainer")]
#[candid_method(update)]
fn set_api_key(api_key: String) {
    CONFIG_CELL.with(|cell| {
        if cell.borrow().get().api_key != api_key {
            let mut config = cell.borrow().get().clone();
            config.api_key = api_key;
            cell.borrow_mut()
                .set(config)
                .expect("failed to encode config");
            record_event(EventKind::ApiKeyUpdate);
        }
    });
}

#[update(guard = "caller_is_minter")]
#[candid_method(update)]
async fn fetch_utxo_alerts(outpoint: Outpoint) -> Result<FetchAlertsResponse, Error> {
    let (external_id, alerts) = match kyt_mode() {
        KytMode::Normal => {
            let external_id = http_register_tx(outpoint.clone()).await?;
            let alerts = http_get_utxo_alerts(external_id.clone()).await?;
            (external_id, alerts)
        }
        KytMode::DryRun => (ic_cdk::api::time().to_string(), vec![]),
    };
    record_event(EventKind::UtxoCheck {
        txid: outpoint.txid,
        vout: outpoint.vout,
        alerts: alerts.clone(),
        external_id: external_id.clone(),
    });
    Ok(FetchAlertsResponse {
        external_id,
        alerts,
    })
}

#[update(guard = "caller_is_minter")]
#[candid_method(update)]
async fn fetch_withdrawal_alerts(
    withdrawal: WithdrawalAttempt,
) -> Result<FetchAlertsResponse, Error> {
    let (external_id, alerts) = match kyt_mode() {
        KytMode::Normal => {
            let external_id = http_register_withdrawal(withdrawal.clone()).await?;
            let alerts = http_get_withdrawal_alerts(external_id.clone()).await?;
            (external_id, alerts)
        }
        KytMode::DryRun => (ic_cdk::api::time().to_string(), vec![]),
    };
    record_event(EventKind::AddressCheck {
        withdrawal_id: withdrawal.id,
        address: withdrawal.address,
        amount: withdrawal.amount,
        alerts: alerts.clone(),
        external_id: external_id.clone(),
    });
    Ok(FetchAlertsResponse {
        external_id,
        alerts,
    })
}

#[query]
#[candid_method(query)]
fn txid_to_bytes(txid: String) -> Vec<u8> {
    let trimmed = txid.trim();
    let mut bytes =
        hex::decode(trimmed).unwrap_or_else(|e| panic!("invalid hex string {}: {}", trimmed, e));
    bytes.reverse();
    bytes
}

#[query]
#[candid_method(query)]
fn cleanup_response(mut args: TransformArgs) -> HttpResponse {
    args.response.headers.clear();
    if args.response.status >= 300u64 {
        // The error response might contain non-deterministic fields that make it impossible to reach consensus,
        // such as timestamps:
        // {"timestamp":"2023-03-01T20:35:49.416+00:00","status":403,"error":"Forbidden","message":"AccessDenied","path":"/api/kyt/v2/users/cktestbtc/transfers"}
        let error: json_rpc::Error = serde_json::from_slice(&args.response.body).unwrap();
        args.response.body = serde_json::to_string(&error).unwrap().into_bytes();
    }
    args.response
}

#[query]
#[candid_method(query)]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    if req.path() == "/dashboard" {
        use askama::Template;
        let (minter_id, maintainers) = CONFIG_CELL.with(|cell| {
            let data = cell.borrow().get().clone().0;
            (data.minter_id, data.maintainers)
        });

        let events: Vec<Event> = EVENT_LOG.with(|log| {
            const MAX_EVENTS: u64 = 100;
            let n = log.len();
            let skip_events = n.saturating_sub(MAX_EVENTS) as usize;
            log.iter().skip(skip_events).map(|Cbor(e)| e).collect()
        });
        let dashboard = dashboard::DashboardTemplate {
            minter_id,
            maintainers,
            events,
        }
        .render()
        .unwrap();
        http::HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else {
        http::HttpResponseBuilder::not_found().build()
    }
}

async fn http_register_tx(outpoint: Outpoint) -> Result<json_rpc::ExternalId, Error> {
    let response: json_rpc::RegisterTransferResponse = json_rpc::http_call(
        HttpMethod::POST,
        api_key(),
        "v2/users/cktestbtc/transfers".to_string(),
        json_rpc::RegisterTransferRequest {
            network: json_rpc::Network::Bitcoin,
            asset: json_rpc::Asset::Btc,
            transfer_reference: format!("{}:{}", DisplayTxid(&outpoint.txid), outpoint.vout),
            direction: json_rpc::Direction::Received,
        },
    )
    .await
    .expect("failed to register transfer")
    .map_err(json_error_to_candid)?;
    Ok(response.external_id)
}

async fn http_get_utxo_alerts(external_id: json_rpc::ExternalId) -> Result<Vec<Alert>, Error> {
    let response: json_rpc::GetAlertsResponse = json_rpc::http_call(
        HttpMethod::GET,
        api_key(),
        format!("v2/transfers/{}/alerts", external_id),
        json_rpc::GetAlertsRequest { external_id },
    )
    .await
    .expect("failed to fetch alerts")
    .map_err(json_error_to_candid)?;
    Ok(response
        .alerts
        .into_iter()
        .map(json_alert_to_candid)
        .collect())
}

async fn http_register_withdrawal(
    withdrawal: WithdrawalAttempt,
) -> Result<json_rpc::ExternalId, Error> {
    let response: json_rpc::RegisterWithdrawalResponse = json_rpc::http_call(
        HttpMethod::POST,
        api_key(),
        "v2/users/ckbtc/withdrawal-attempts".to_string(),
        json_rpc::RegisterWithdrawalRequest {
            network: json_rpc::Network::Bitcoin,
            asset: json_rpc::Asset::Btc,
            attempt_identifier: withdrawal.id,
            asset_amount: withdrawal.amount as f64 / 1e8,
            address: withdrawal.address,
            attempt_timestamp: format_timestamp(withdrawal.timestamp_nanos),
        },
    )
    .await
    .expect("failed to register a withdrawal")
    .map_err(json_error_to_candid)?;
    Ok(response.external_id)
}

async fn http_get_withdrawal_alerts(
    external_id: json_rpc::ExternalId,
) -> Result<Vec<Alert>, Error> {
    let response: json_rpc::GetAlertsResponse = json_rpc::http_call(
        HttpMethod::GET,
        api_key(),
        format!("v2/withdrawal-attempts/{}/alerts", external_id),
        json_rpc::GetAlertsRequest { external_id },
    )
    .await
    .expect("failed to fetch alerts")
    .map_err(json_error_to_candid)?;
    Ok(response
        .alerts
        .into_iter()
        .map(json_alert_to_candid)
        .collect())
}

fn format_timestamp(ts_nanos: u64) -> String {
    let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(ts_nanos as i128).unwrap();
    // 2020-12-09T17:25:40+00:00
    let format =
        time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
            .unwrap();
    dt_offset.format(&format).unwrap()
}

fn json_alert_to_candid(alert: json_rpc::Alert) -> Alert {
    Alert {
        level: match alert.alert_level {
            json_rpc::AlertLevel::Severe => AlertLevel::Severe,
            json_rpc::AlertLevel::High => AlertLevel::High,
            json_rpc::AlertLevel::Medium => AlertLevel::Medium,
            json_rpc::AlertLevel::Low => AlertLevel::Low,
        },
        category: alert.category,
        service: alert.service,
        exposure_type: match alert.exposure_type {
            json_rpc::ExposureType::Direct => ExposureType::Direct,
            json_rpc::ExposureType::Indirect => ExposureType::Indirect,
        },
    }
}

fn json_error_to_candid(e: json_rpc::Error) -> Error {
    match e.error {
        Some(kind) => Error::TemporarilyUnavailable(format!("{}: {}", kind, e.message)),
        None => Error::TemporarilyUnavailable(e.message),
    }
}

fn main() {}

#[test]
fn test_date_formatting() {
    assert_eq!(
        format_timestamp(1677770607672807382),
        "2023-03-02T15:23:27+00:00".to_string()
    );
}

#[test]
fn check_candid_interface_compatibility() {
    use candid::utils::{service_compatible, CandidSource};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("kyt.did");

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
