use crate::dashboard::build_dashboard;
use crate::metrics::encode_metrics;
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
    match req.path() {
        "/metrics" => {
            let mut writer = ic_metrics_encoder::MetricsEncoder::new(
                vec![],
                ic_cdk::api::time() as i64 / 1_000_000,
            );

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
        }
        "/dashboard" => {
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
        }
        "/logs" => {
            use crate::logs::Priority;
            use canlog::{Log, Sort};
            use std::str::FromStr;

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

            let mut log: Log<Priority> = Default::default();

            match req.raw_query_param("priority").map(Priority::from_str) {
                Some(Ok(priority)) => log.push_logs(priority),
                Some(Err(_)) | None => {
                    log.push_logs(Priority::Info);
                    log.push_logs(Priority::Debug);
                }
            }

            log.entries
                .retain(|entry| entry.timestamp >= max_skip_timestamp);

            fn ordering_from_query_params(sort: Option<&str>, max_skip_timestamp: u64) -> Sort {
                match sort.map(Sort::from_str) {
                    Some(Ok(order)) => order,
                    Some(Err(_)) | None => {
                        if max_skip_timestamp == 0 {
                            Sort::Ascending
                        } else {
                            Sort::Descending
                        }
                    }
                }
            }

            log.sort_logs(ordering_from_query_params(
                req.raw_query_param("sort"),
                max_skip_timestamp,
            ));

            const MAX_BODY_SIZE: usize = 2_000_000;
            HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
                .build()
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}
