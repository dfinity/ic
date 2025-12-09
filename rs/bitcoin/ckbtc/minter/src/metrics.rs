use crate::management::CallSource;
use crate::state;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Error;
use std::time::Duration;

pub type NumUtxoPages = u32;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum MetricsResult {
    Ok,
    Err,
}

impl MetricsResult {
    pub fn as_str(&self) -> &str {
        match self {
            MetricsResult::Ok => "success",
            MetricsResult::Err => "failure",
        }
    }
}

thread_local! {
    pub static GET_UTXOS_CLIENT_CALLS: Cell<u64> = Cell::default();
    pub static GET_UTXOS_MINTER_CALLS: Cell<u64> = Cell::default();
    pub static UPDATE_CALL_LATENCY: RefCell<BTreeMap<NumUtxoPages,LatencyHistogram>> = RefCell::default();
    pub static GET_UTXOS_CALL_LATENCY: RefCell<BTreeMap<(NumUtxoPages, CallSource),LatencyHistogram>> = RefCell::default();
    pub static GET_UTXOS_RESULT_SIZE: RefCell<BTreeMap<CallSource,NumUtxosHistogram>> = RefCell::default();
    pub static GET_UTXOS_CACHE_HITS : Cell<u64> = Cell::default();
    pub static GET_UTXOS_CACHE_MISSES: Cell<u64> = Cell::default();
    pub static SIGN_WITH_ECDSA_LATENCY: RefCell<BTreeMap<MetricsResult, LatencyHistogram>> = RefCell::default();
}

pub const BUCKETS_DEFAULT_MS: [u64; 8] =
    [500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, u64::MAX];
pub const BUCKETS_SIGN_WITH_ECDSA_MS: [u64; 8] =
    [1_000, 2_000, 4_000, 6_000, 8_000, 12_000, 20_000, u64::MAX];
pub const BUCKETS_UTXOS: [u64; 8] = [1, 4, 16, 64, 256, 1024, 4096, u64::MAX];

pub struct NumUtxosHistogram(pub Histogram<8>);

impl Default for NumUtxosHistogram {
    fn default() -> Self {
        Self(Histogram::new(&BUCKETS_UTXOS))
    }
}

pub struct LatencyHistogram(pub Histogram<8>);

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self(Histogram::new(&BUCKETS_DEFAULT_MS))
    }
}

impl LatencyHistogram {
    pub fn observe_latency(&mut self, start_ns: u64, end_ns: u64) {
        let duration = Duration::from_nanos(end_ns.saturating_sub(start_ns));
        self.0.observe_value(duration.as_millis() as u64)
    }
}

#[derive(Clone, Copy)]
pub struct Histogram<const NUM_BUCKETS: usize> {
    bucket_upper_bounds: &'static [u64; NUM_BUCKETS],
    bucket_counts: [u64; NUM_BUCKETS],
    value_sum: u64,
}

impl<const NUM_BUCKETS: usize> Histogram<NUM_BUCKETS> {
    pub fn new(bucket_upper_bounds: &'static [u64; NUM_BUCKETS]) -> Self {
        Histogram {
            bucket_upper_bounds,
            bucket_counts: [0; NUM_BUCKETS],
            value_sum: 0,
        }
    }

    pub fn observe_value(&mut self, value: u64) {
        let bucket_index = self
            .bucket_upper_bounds
            .iter()
            .enumerate()
            .find_map(|(bucket_index, bucket_upper_bound)| {
                if value <= *bucket_upper_bound {
                    Some(bucket_index)
                } else {
                    None
                }
            })
            .expect("BUG: all values should be less than or equal to the last bucket upper bound");
        self.bucket_counts[bucket_index] += 1;
        self.value_sum += value;
    }

    /// Returns an iterator over the histogram buckets as tuples containing the bucket upper bound
    /// (inclusive), and the count of observed values within the bucket.
    pub fn iter(&self) -> impl Iterator<Item = (f64, f64)> + '_ {
        self.bucket_upper_bounds
            .iter()
            .enumerate()
            .map(|(bucket_index, bucket_upper_bound)| {
                if bucket_index == (NUM_BUCKETS - 1) {
                    f64::INFINITY
                } else {
                    *bucket_upper_bound as f64
                }
            })
            .zip(self.bucket_counts.iter().cloned())
            .map(|(k, v)| (k, v as f64))
    }

    /// Returns the sum of all observed latencies in milliseconds.
    pub fn sum(&self) -> u64 {
        self.value_sum
    }
}

pub fn observe_get_utxos_latency(
    num_utxos: usize,
    num_pages: usize,
    call_source: CallSource,
    start_ns: u64,
    end_ns: u64,
) {
    GET_UTXOS_CALL_LATENCY.with_borrow_mut(|metrics| {
        metrics
            .entry((num_pages as NumUtxoPages, call_source))
            .or_default()
            .observe_latency(start_ns, end_ns);
    });
    GET_UTXOS_RESULT_SIZE.with_borrow_mut(|metrics| {
        metrics
            .entry(call_source)
            .or_default()
            .0
            .observe_value(num_utxos as u64);
    });
}

pub fn observe_update_call_latency(num_new_utxos: usize, start_ns: u64, end_ns: u64) {
    UPDATE_CALL_LATENCY.with_borrow_mut(|metrics| {
        metrics
            .entry(num_new_utxos as NumUtxoPages)
            .or_default()
            .observe_latency(start_ns, end_ns);
    });
}

pub fn observe_sign_with_ecdsa_latency<T, E>(result: &Result<T, E>, start_ns: u64, end_ns: u64) {
    let metric_result = match result {
        Ok(_) => MetricsResult::Ok,
        Err(_) => MetricsResult::Err,
    };
    SIGN_WITH_ECDSA_LATENCY.with_borrow_mut(|metrics| {
        metrics
            .entry(metric_result)
            .or_insert(LatencyHistogram(Histogram::new(
                &BUCKETS_SIGN_WITH_ECDSA_MS,
            )))
            .observe_latency(start_ns, end_ns);
    });
}

pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

    metrics.encode_gauge(
        "stable_memory_bytes",
        ic_cdk::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
        "Size of the stable memory allocated by this canister.",
    )?;
    metrics.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister.",
    )?;

    let cycle_balance = ic_cdk::api::canister_cycle_balance() as f64;

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
            state::read_state(|s| s.pending_btc_requests.len()) as f64,
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
                    .map(|tx| tx.requests.count_retrieve_btc_requests())
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

    metrics.encode_counter(
        "ckbtc_minter_get_utxos_cache_hits",
        GET_UTXOS_CACHE_HITS.get() as f64,
        "Number of cache hits for get_utxos calls.",
    )?;

    metrics.encode_counter(
        "ckbtc_minter_get_utxos_cache_misses",
        GET_UTXOS_CACHE_MISSES.get() as f64,
        "Number of cache misses for get_utxos calls.",
    )?;

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
        state::read_state(|s| s.update_balance_accounts.len()) as f64,
        "Total number of concurrent update_balance requests.",
    )?;

    metrics.encode_gauge(
        "ckbtc_minter_concurrent_retrieve_btc_count",
        state::read_state(|s| s.retrieve_btc_accounts.len()) as f64,
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

    metrics.encode_gauge(
        "ckbtc_minter_mint_status_unknown_utxos_count",
        state::read_state(|s| s.mint_status_unknown_utxos().count()) as f64,
        "Total number of UTXOs with unknown mint status.",
    )?;

    let mut histogram_vec = metrics.histogram_vec(
        "ckbtc_minter_update_calls_latency",
        "The latency of ckBTC minter `update_balance` calls in milliseconds.",
    )?;

    UPDATE_CALL_LATENCY.with_borrow(|histograms| -> Result<(), Error> {
        for (num_new_utxos, histogram) in histograms {
            histogram_vec = histogram_vec.histogram(
                &[("num_new_utxos", &num_new_utxos.to_string())],
                histogram.0.iter(),
                histogram.0.sum() as f64,
            )?;
        }
        Ok(())
    })?;

    let mut histogram_vec = metrics.histogram_vec(
        "ckbtc_minter_get_utxos_latency",
        "The latency of ckBTC minter `get_utxos` calls in milliseconds.",
    )?;

    GET_UTXOS_CALL_LATENCY.with_borrow(|histograms| -> Result<(), Error> {
        for ((num_pages, call_source), histogram) in histograms {
            histogram_vec = histogram_vec.histogram(
                &[
                    ("num_pages", &num_pages.to_string()),
                    ("call_source", &call_source.to_string()),
                ],
                histogram.0.iter(),
                histogram.0.sum() as f64,
            )?;
        }
        Ok(())
    })?;

    let mut histogram_vec = metrics.histogram_vec(
        "ckbtc_minter_get_utxos_result_size",
        "The number of UTXOs in the result of the ckBTC minter `get_utxos` call.",
    )?;

    GET_UTXOS_RESULT_SIZE.with_borrow(|histograms| -> Result<(), Error> {
        for (call_source, histogram) in histograms {
            histogram_vec = histogram_vec.histogram(
                &[("call_source", &call_source.to_string())],
                histogram.0.iter(),
                histogram.0.sum() as f64,
            )?;
        }
        Ok(())
    })?;

    let mut histogram_vec = metrics.histogram_vec(
        "ckbtc_minter_sign_with_ecdsa_latency",
        "The latency of ckBTC minter `sign_with_ecdsa` calls in milliseconds.",
    )?;

    SIGN_WITH_ECDSA_LATENCY.with_borrow(|histograms| -> Result<(), Error> {
        for (result, histogram) in histograms {
            histogram_vec = histogram_vec.histogram(
                &[("result", result.as_str())],
                histogram.0.iter(),
                histogram.0.sum() as f64,
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
