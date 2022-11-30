use crate::state;

pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

    metrics.encode_gauge(
        "ckbtc_minter_stable_memory_bytes",
        ic_cdk::api::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
        "Size of the stable memory allocated by this canister.",
    )?;
    metrics.encode_gauge(
        "ckbtc_minter_cycle_balance",
        ic_cdk::api::canister_balance128() as f64,
        "Cycle balance on this canister.",
    )?;

    metrics
        .gauge_vec(
            "ckbtc_minter_retrieve_btc_request_count",
            "Total count of incomplete retrieve btc requests, by status.",
        )?
        .value(
            &[("status", "pending")],
            state::read_state(|s| s.pending_retrieve_btc_requests.len()) as f64,
        )?
        .value(
            &[("status", "signing")],
            state::read_state(|s| {
                s.requests_in_flight
                    .values()
                    .filter(|v| matches!(v, state::InFlightStatus::Signing))
                    .count()
            }) as f64,
        )?
        .value(
            &[("status", "sending")],
            state::read_state(|s| {
                s.requests_in_flight
                    .values()
                    .filter(|v| matches!(*v, state::InFlightStatus::Sending { .. }))
                    .count()
            }) as f64,
        )?
        .value(
            &[("status", "submitted")],
            state::read_state(|s| s.submitted_requests.len()) as f64,
        )?;

    metrics.encode_gauge(
        "ckbtc_minter_stored_finalized_requests",
        state::read_state(|s| s.finalized_requests.len()) as f64,
        "Total number of finalized retrieve_btc requests the minter keeps in memory.",
    )?;

    metrics.encode_counter(
        "ckbtc_minter_finalized_requests",
        state::read_state(|s| s.finalized_requests_count) as f64,
        "Total number of finalized retrieve_btc requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_min_retrievable_amount",
        state::read_state(|s| s.retrieve_btc_min_amount) as f64,
        "Minimum number of ckBTC a user can withdraw.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_min_confirmations",
        state::read_state(|s| s.min_confirmations) as f64,
        "Min number of confirmations on BTC network",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_utxos_available",
        state::read_state(|s| s.available_utxos.len()) as f64,
        "Total number of UTXOs the minter can use for retrieve_btc requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_btc_balance",
        state::read_state(|s| s.available_utxos.iter().map(|u| u.value).sum::<u64>()) as f64,
        "Total BTC amount locked in available UTXOs.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_managed_addresses_count",
        state::read_state(|s| s.utxos_state_addresses.len()) as f64,
        "Total number of minter addresses owning UTXOs.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_outpoint_count",
        state::read_state(|s| s.outpoint_account.len()) as f64,
        "Total number of outputs the minter has to remember.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_concurrent_update_balance_count",
        state::read_state(|s| s.update_balance_principals.len()) as f64,
        "Total number of concurrent update_blanace requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_concurrent_retrieve_btc_count",
        state::read_state(|s| s.retrieve_btc_principals.len()) as f64,
        "Total number of concurrent retrieve_btc requests.",
    )?;

    Ok(())
}
