use candid::{Encode, Principal};
use ic_http_types::{HttpRequest, HttpResponse};
use pocket_ic::nonblocking::PocketIc;
use salt_sharing_api::{GetSaltError, GetSaltResponse, InitArg, SaltGenerationStrategy};
use salt_sharing_canister_integration_tests::pocket_ic_helpers::{
    canister_call, install_salt_sharing_canister_on_ii_subnet, setup_subnets_and_registry_canister,
};
use std::time::SystemTime;

use chrono::{TimeZone, Utc};
use std::str::FromStr;

// Make IC progress by this (ad-hoc) number of blocks to observe the effect of the inter-canister calls and timers
const TICKS: u32 = 100;
// This metric is exposed by the canister and corresponds to a timestamp when the salt was last regenerated
const SALT_METRIC: &str = "last_salt_id";
const UPGRADE_METRIC: &str = "last_successful_canister_upgrade";

#[tokio::test]
async fn main() {
    let pocket_ic = setup_subnets_and_registry_canister().await;
    // Set system time on the IC.
    let time = SystemTime::from(Utc.with_ymd_and_hms(2024, 2, 25, 0, 0, 0).unwrap());
    pocket_ic.set_time(time.into()).await;
    // Install salt canister
    let init_payload = InitArg {
        regenerate_now: true,
        salt_generation_strategy: SaltGenerationStrategy::StartOfMonth,
        registry_polling_interval_secs: 60,
    };
    let (canister_id, wasm) =
        install_salt_sharing_canister_on_ii_subnet(&pocket_ic, init_payload).await;
    // Check access control
    let response: GetSaltResponse = canister_call(
        &pocket_ic,
        "get_salt",
        "query",
        canister_id,
        Principal::anonymous(),
        Encode!(&b"").unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.unwrap_err(), GetSaltError::Unauthorized);
    // Check access control (inspect_message hook)
    let response: Result<GetSaltResponse, String> = canister_call(
        &pocket_ic,
        "get_salt",
        "update",
        canister_id,
        Principal::anonymous(),
        Encode!(&b"").unwrap(),
    )
    .await;
    let err_msg = response.unwrap_err();
    assert!(
        err_msg.contains(
            "message_inspection_failed: method call is prohibited in the current context"
        )
    );
    // Initialize metrics extractor for the canister, which helps to make indirect assertions about canister state
    let metrics_extractor = MetricsExtractor {
        canister_id,
        pocket_ic: &pocket_ic,
    };
    // Salt should not be initialized immediately after canister's installation
    let salt_id = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert_eq!(salt_id, 0);
    // But once some rounds pass, salt should be initialized
    tick_n_times(&pocket_ic, TICKS).await;
    let salt_id = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert!(salt_id > 0);
    // Till the very last day of the month salt should not be regenerated (note leap year)
    let time = SystemTime::from(Utc.with_ymd_and_hms(2024, 2, 29, 0, 0, 0).unwrap());
    pocket_ic.set_time(time.into()).await;
    tick_n_times(&pocket_ic, TICKS).await;
    let salt_id_0 = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert_eq!(salt_id_0, salt_id);
    // But on the first calendar day of next month salt should be regenerated
    let time = SystemTime::from(Utc.with_ymd_and_hms(2024, 3, 1, 0, 0, 0).unwrap());
    pocket_ic.set_time(time.into()).await;
    tick_n_times(&pocket_ic, TICKS).await;
    let salt_id_1 = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert!(salt_id_1 > salt_id_0);
    // Now we upgrade the canister without immediate salt regeneration
    let canister_upgrade_time_1 = metrics_extractor
        .try_get_metric::<u64>(UPGRADE_METRIC)
        .await
        .unwrap();
    let init_payload = InitArg {
        regenerate_now: false, // do not regenerate salt immediately
        salt_generation_strategy: SaltGenerationStrategy::StartOfMonth,
        registry_polling_interval_secs: 60,
    };
    pocket_ic
        .upgrade_canister(
            canister_id,
            wasm.clone().bytes(),
            Encode!(&init_payload).unwrap(),
            None,
        )
        .await
        .expect("failed to upgrade canister");
    tick_n_times(&pocket_ic, TICKS).await;
    let last_salt_id_upgraded = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert_eq!(last_salt_id_upgraded, salt_id_1);
    let canister_upgrade_time_2 = metrics_extractor
        .try_get_metric::<u64>(UPGRADE_METRIC)
        .await
        .unwrap();
    assert!(canister_upgrade_time_2 > canister_upgrade_time_1);
    // Now we upgrade canister with an immediate salt regeneration
    let init_payload = InitArg {
        regenerate_now: true, // regenerate salt on upgrade
        salt_generation_strategy: SaltGenerationStrategy::StartOfMonth,
        registry_polling_interval_secs: 60,
    };
    pocket_ic
        .upgrade_canister(
            canister_id,
            wasm.bytes(),
            Encode!(&init_payload).unwrap(),
            None,
        )
        .await
        .expect("failed to upgrade canister");
    tick_n_times(&pocket_ic, TICKS).await;
    let last_salt_id_upgraded = metrics_extractor
        .try_get_metric::<u64>(SALT_METRIC)
        .await
        .unwrap();
    assert!(last_salt_id_upgraded > salt_id_1);
    let canister_upgrade_time_3 = metrics_extractor
        .try_get_metric::<u64>(UPGRADE_METRIC)
        .await
        .unwrap();
    assert!(canister_upgrade_time_3 > canister_upgrade_time_2);
}

struct MetricsExtractor<'a> {
    canister_id: Principal,
    pocket_ic: &'a PocketIc,
}

impl MetricsExtractor<'_> {
    pub async fn try_get_metric<T>(&self, pattern: &str) -> Result<T, String>
    where
        T: FromStr,
    {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: vec![],
            body: vec![].into(),
        };

        let response: HttpResponse = canister_call(
            self.pocket_ic,
            "http_request",
            "query",
            self.canister_id,
            Principal::anonymous(),
            Encode!(&request).map_err(|_| "failed to encode request".to_string())?,
        )
        .await
        .map_err(|_| "http request failed".to_string())?;

        let metrics = String::from_utf8_lossy(&response.body)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();

        metrics
            .into_iter()
            .find(|metric| metric.starts_with(pattern))
            .and_then(|metric| metric.split_whitespace().nth(1)?.parse().ok())
            .ok_or_else(|| "metric not found".to_string())
    }
}

async fn tick_n_times(pocket_ic: &PocketIc, n: u32) {
    for _ in 0..n {
        pocket_ic.tick().await;
    }
}
