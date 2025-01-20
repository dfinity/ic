use crate::state;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Error;
use std::time::Duration;

thread_local! {
    pub static GET_UTXOS_CLIENT_CALLS: Cell<u64> = Cell::default();
    pub static GET_UTXOS_MINTER_CALLS: Cell<u64> = Cell::default();
    pub static UPDATE_CALL_LATENCY: RefCell<BTreeMap<usize,LatencyHistogram>> = RefCell::default();
}

pub(crate) const BUCKETS_MS: [u64; 7] = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000];

#[derive(Default, Clone, Copy)]
pub struct LatencyHistogram {
    latency_buckets: [u64; BUCKETS_MS.len() + 1],
    latency_sum: u64,
}

impl LatencyHistogram {
    pub fn observe_latency(&mut self, latency: Duration) {
        let latency_ms = latency.as_millis() as u64;
        let bucket_index = BUCKETS_MS
            .iter()
            .enumerate()
            .find_map(|(bucket_index, bucket_upper_bound)| {
                if latency_ms <= *bucket_upper_bound {
                    Some(bucket_index)
                } else {
                    None
                }
            })
            .unwrap_or(self.latency_buckets.len() - 1); // infinity bucket
        self.latency_buckets[bucket_index] += 1;
        self.latency_sum += latency_ms;
    }

    /// Returns an iterator over the histogram buckets as tuples containing the bucket upper bound
    /// (inclusive), and the count of observed values within the bucket.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (f64, f64)> + '_ {
        BUCKETS_MS
            .iter()
            .map(|bucket| *bucket as f64)
            .chain(std::iter::once(f64::INFINITY))
            .zip(self.latency_buckets.iter().cloned())
            .map(|(k, v)| (k, v as f64))
    }

    /// Returns the sum of all observed latencies in milliseconds.
    pub(crate) fn sum(&self) -> u64 {
        self.latency_sum
    }
}

pub fn observe_latency(num_utxos: usize, start_ns: u64, end_ns: u64) {
    let duration = Duration::from_nanos(end_ns.saturating_sub(start_ns));
    UPDATE_CALL_LATENCY.with_borrow_mut(|metrics| {
        metrics
            .entry(num_utxos)
            .or_default()
            .observe_latency(duration)
    });
}

pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

    metrics.encode_gauge(
        "stable_memory_bytes",
        ic_cdk::api::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
        "Size of the stable memory allocated by this canister.",
    )?;

    metrics.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister.",
    )?;

    let cycle_balance = ic_cdk::api::canister_balance128() as f64;

    metrics.encode_gauge(
        "ckbtc_minter_cycle_balance",
        cycle_balance,
        "Cycle balance on this canister.",
    )?;

    metrics
        .gauge_vec("cycle_balance", "Cycle balance on this canister.")?
        .value(&[("canister", "ckbtc-minter")], cycle_balance)?;

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
            state::read_state(|s| {
                s.submitted_transactions
                    .iter()
                    .map(|tx| tx.requests.len())
                    .sum::<usize>()
            }) as f64,
        )?;

    metrics
        .gauge_vec(
            "ckbtc_minter_btc_transaction_count",
            "Total count of non-finalized btc transaction, by status.",
        )?
        .value(
            &[("status", "submitted")],
            state::read_state(|s| s.submitted_transactions.len() as f64),
        )?
        .value(
            &[("status", "stuck")],
            state::read_state(|s| s.stuck_transactions.len() as f64),
        )?;

    metrics.encode_gauge(
        "ckbtc_minter_longest_resubmission_chain_size",
        state::read_state(|s| s.longest_resubmission_chain_size() as f64),
        "The length of the longest active transaction resubmission chain.",
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

    metrics.encode_counter(
        "ckbtc_minter_minted_tokens",
        state::read_state(|s| s.tokens_minted) as f64,
        "Total number of minted tokens.",
    )?;

    metrics.encode_counter(
        "ckbtc_minter_burned_tokens",
        state::read_state(|s| s.tokens_burned) as f64,
        "Total number of burned tokens.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_min_retrievable_amount",
        state::read_state(|s| s.retrieve_btc_min_amount) as f64,
        "Minimum number of ckBTC a user can withdraw.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_fee_based_min_retrievable_amount",
        state::read_state(|s| s.fee_based_retrieve_btc_min_amount) as f64,
        "Minimum number of ckBTC a user can withdraw (fee based).",
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

    metrics
        .counter_vec(
            "ckbtc_minter_get_utxos_calls",
            "Number of get_utxos calls the minter issued, labeled by source.",
        )?
        .value(&[("source", "client")], GET_UTXOS_CLIENT_CALLS.get() as f64)?
        .value(&[("source", "minter")], GET_UTXOS_MINTER_CALLS.get() as f64)?;

    metrics.encode_gauge(
        "ckbtc_minter_btc_balance",
        state::read_state(|s| s.get_total_btc_managed()) as f64,
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
        "Total number of concurrent update_balance requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_concurrent_retrieve_btc_count",
        state::read_state(|s| s.retrieve_btc_principals.len()) as f64,
        "Total number of concurrent retrieve_btc requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_global_timer_timestamp",
        crate::tasks::global_timer() as f64,
        "The deadline for the next global timer event.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_median_fee_per_vbyte",
        state::read_state(|s| s.last_fee_per_vbyte[50]) as f64,
        "Median Bitcoin transaction fee per vbyte in Satoshi.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_owed_kyt_amount",
        state::read_state(|s| s.owed_kyt_amount.iter().map(|e| e.1).sum::<u64>()) as f64,
        "The total amount of ckBTC that minter owes to the KYT canister.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_suspended_utxos_without_account_count",
        state::read_state(|s| s.suspended_utxos.utxos_without_account().len()) as f64,
        "Total number of suspended UTXOs without account.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_ignored_utxos_count",
        state::read_state(|s| s.ignored_utxos().count()) as f64,
        "Total number of suspended UTXOs due to a too small value.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_quarantined_utxos_count",
        state::read_state(|s| s.quarantined_utxos().count()) as f64,
        "Total number of suspended UTXOs due to being marked as tainted.",
    )?;

    let mut histogram_vec = metrics.histogram_vec(
        "ckbtc_minter_update_calls_latency",
        "The latency of ckBTC minter `update_balance` calls in milliseconds.",
    )?;

    UPDATE_CALL_LATENCY.with_borrow(|histograms| -> Result<(), Error> {
        for (num_new_utxos, histogram) in histograms {
            histogram_vec = histogram_vec.histogram(
                &[("num_new_utxos", &num_new_utxos.to_string())],
                histogram.iter(),
                histogram.sum() as f64,
            )?;
        }
        Ok(())
    })?;

    Ok(())
}

/// Returns the amount of heap memory in bytes that has been allocated.
#[cfg(target_arch = "wasm32")]
pub fn heap_memory_size_bytes() -> usize {
    const WASM_PAGE_SIZE_BYTES: usize = 65536;
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn heap_memory_size_bytes() -> usize {
    0
}
