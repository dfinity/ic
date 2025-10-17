use crate::dashboard::build_dashboard;
use crate::metrics::encode_metrics;
use crate::{Log, LogEntry, Priority};
use candid::CandidType;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use serde::{Deserialize, Serialize};

#[derive(CandidType, Deserialize)]
pub struct RetrieveBtcStatusRequest {
    pub block_index: u64,
}

#[derive(CandidType, Deserialize)]
pub struct EstimateFeeArg {
    pub amount: Option<u64>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, CandidType, Serialize, Deserialize, Default)]
pub struct WithdrawalFee {
    pub minter_fee: u64,
    pub bitcoin_fee: u64,
}

pub fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_canister_log::export as export_logs;

    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        let account_to_utxos_start = match req.raw_query_param("account_to_utxos_start") {
            Some(arg) => match arg.parse::<u64>() {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length(
                            "failed to parse the 'account_to_utxos_start' parameter",
                        )
                        .build();
                }
            },
            None => 0,
        };
        let dashboard: Vec<u8> = build_dashboard(account_to_utxos_start);
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else if req.path() == "/logs" {
        use serde_json;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match arg.parse::<u64>() {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build();
                }
            },
            None => 0,
        };

        let mut entries: Log = Default::default();
        for entry in export_logs(&crate::logs::P0) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority: Priority::P0,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        for entry in export_logs(&crate::logs::P1) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority: Priority::P1,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        entries
            .entries
            .retain(|entry| entry.timestamp >= max_skip_timestamp);
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}
