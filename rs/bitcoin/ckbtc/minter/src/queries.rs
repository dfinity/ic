use crate::address::BitcoinAddress;
use crate::dashboard::build_dashboard;
use crate::fees::FeeEstimator;
use crate::metrics::encode_metrics;
use crate::state::read_state;
use crate::state::utxos::UtxoSet;
use crate::tx::TransactionVersion;
use crate::updates::update_balance::UpdateBalanceArgs;
use crate::{BuildTxError, build_unsigned_transaction_from_inputs, utxos_selection};
use candid::CandidType;
use ic_btc_interface::Utxo;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use icrc_ledger_types::icrc1::account::Account;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Deserialize)]
pub struct RetrieveBtcStatusRequest {
    pub block_index: u64,
}

#[derive(CandidType, Deserialize)]
pub struct EstimateFeeArg {
    /// Withdrawal amount in base unit.
    pub amount: Option<u64>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, CandidType, Serialize, Deserialize, Default)]
pub struct WithdrawalFee {
    pub minter_fee: u64,
    pub bitcoin_fee: u64,
}

pub fn get_known_utxos(args: UpdateBalanceArgs) -> Vec<Utxo> {
    read_state(|s| {
        s.known_utxos_for_account(&Account {
            owner: args.owner.unwrap_or(ic_cdk::api::msg_caller()),
            subaccount: args.subaccount,
        })
    })
}

pub fn estimate_withdrawal_fee<F: FeeEstimator>(
    available_utxos: &mut UtxoSet,
    withdrawal_amount: u64,
    median_fee_millisatoshi_per_vbyte: u64,
    minter_address: BitcoinAddress,
    recipient_address: BitcoinAddress,
    max_num_inputs_in_transaction: usize,
    tx_version: TransactionVersion,
    fee_estimator: &F,
) -> Result<WithdrawalFee, BuildTxError> {
    // We simulate the algorithm that selects UTXOs for the
    // specified amount.
    let selected_utxos = utxos_selection(withdrawal_amount, available_utxos, 1);

    build_unsigned_transaction_from_inputs(
        &selected_utxos,
        vec![(recipient_address, withdrawal_amount)],
        &minter_address,
        max_num_inputs_in_transaction,
        median_fee_millisatoshi_per_vbyte,
        tx_version,
        fee_estimator,
    )
    .map(|(unsigned_tx, _change_output, fee)| {
        assert_eq!(
            unsigned_tx.outputs.len(),
            2,
            "BUG: expected 1 output to the recipient and one change output to the minter, \
                so that the totality of the fee is paid in full by the recipient"
        );
        fee
    })
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
