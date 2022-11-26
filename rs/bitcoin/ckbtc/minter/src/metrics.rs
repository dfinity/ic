use crate::state;

pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    metrics.encode_gauge(
        "ckbtc_minter_stable_memory_bytes",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_cycle_balance",
        ic_cdk::api::canister_balance128() as f64,
        "Cycle balance on this canister.",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_incomplete_retrieve_btc_requests_count",
        state::read_state(|s| s.count_incomplete_retrieve_btc_requests()) as f64,
        "Total count of incomplete retrieve btc requests",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_pending_retrieve_btc_requests_count",
        state::read_state(|s| s.pending_retrieve_btc_requests.len()) as f64,
        "Count of pending retrieve btc requests",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_in_flight_retrieve_btc_requests_count",
        state::read_state(|s| s.requests_in_flight.len()) as f64,
        "Count of in flight retrieve btc requests",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_submitted_retrieve_btc_requests_count",
        state::read_state(|s| s.submitted_requests.len()) as f64,
        "Count of submitted retrieve btc requests",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_min_confiramtions",
        state::read_state(|s| s.min_confirmations) as f64,
        "Min number of confirmations on BTC network",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_count_of_available_utxos",
        state::read_state(|s| s.available_utxos.len()) as f64,
        "Count of available utxos",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_min_retrievable_amount",
        state::read_state(|s| s.retrieve_btc_min_amount) as f64,
        "Minimum number of ckBTC withdrawable",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_total_BTC_managed",
        state::read_state(|s| s.count_total_btc()) as f64,
        "Total BTC managed",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_managed_addresses_count",
        state::read_state(|s| s.utxos_state_addresses.len()) as f64,
        "Managed addresses count",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_outpoint_count",
        state::read_state(|s| s.outpoint_account.len()) as f64,
        "Outpoint to address count",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_update_balance_principal_count",
        state::read_state(|s| s.update_balance_principals.len()) as f64,
        "Update balance principal count",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_retrieve_btc_principal_count",
        state::read_state(|s| s.retrieve_btc_principals.len()) as f64,
        "Retrieve btc principal count",
    )?;
    Ok(())
}
