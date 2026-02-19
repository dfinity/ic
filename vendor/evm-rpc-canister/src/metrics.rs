use std::collections::HashMap;

use crate::types::{MetricLabels, MetricValue};

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $amount:expr) => {{
        $crate::memory::UNSTABLE_METRICS.with_borrow_mut(|m| m.$metric += $amount);
    }};
}

#[macro_export]
macro_rules! add_metric_entry {
    ($metric:ident, $key:expr, $amount:expr) => {{
        $crate::memory::UNSTABLE_METRICS.with_borrow_mut(|m| {
            let amount = $amount;
            if amount != 0 {
                m.$metric
                    .entry($key)
                    .and_modify(|counter| *counter += amount)
                    .or_insert(amount);
            }
        });
    }};
}

trait EncoderExtensions {
    fn counter_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        name: &str,
        map: &HashMap<K, V>,
        help: &str,
    );
}

impl EncoderExtensions for ic_metrics_encoder::MetricsEncoder<Vec<u8>> {
    fn counter_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        name: &str,
        map: &HashMap<K, V>,
        help: &str,
    ) {
        map.iter().for_each(|(k, v)| {
            self.counter_vec(name, help)
                .and_then(|m| {
                    m.value(&k.metric_labels(), v.metric_value())?;
                    Ok(())
                })
                .unwrap_or(());
        })
    }
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

    crate::memory::UNSTABLE_METRICS.with(|m| {
        let m = m.borrow();

        w.gauge_vec("cycle_balance", "Cycle balance of this canister")?
            .value(
                &[("canister", "evmrpc")],
                ic_cdk::api::canister_cycle_balance().metric_value(),
            )?;
        w.encode_gauge(
            "evmrpc_canister_version",
            ic_cdk::api::canister_version().metric_value(),
            "Canister version",
        )?;
        w.encode_gauge(
            "stable_memory_bytes",
            ic_cdk::stable::stable_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
            "Size of the stable memory allocated by this canister.",
        )?;

        w.encode_gauge(
            "heap_memory_bytes",
            heap_memory_size_bytes() as f64,
            "Size of the heap memory allocated by this canister.",
        )?;

        w.counter_entries(
            "evmrpc_cycles_charged",
            &m.cycles_charged,
            "Number of cycles charged for RPC calls",
        );
        w.counter_entries(
            "evmrpc_requests",
            &m.requests,
            "Number of JSON-RPC requests",
        );
        w.counter_entries(
            "evmrpc_responses",
            &m.responses,
            "Number of JSON-RPC responses",
        );
        w.counter_entries(
            "evmrpc_inconsistent_responses",
            &m.inconsistent_responses,
            "Number of inconsistent RPC responses",
        );
        w.counter_entries(
            "evmrpc_err_http_outcall",
            &m.err_http_outcall,
            "Number of unsuccessful HTTP outcalls",
        );
        w.counter_entries(
            "evmrpc_err_max_response_size_exceeded",
            &m.err_max_response_size_exceeded,
            "Number of HTTP outcalls with max response size exceeded",
        );
        w.counter_entries(
            "evmrpc_err_no_consensus",
            &m.err_no_consensus,
            "Number of HTTP outcalls with consensus errors",
        );

        Ok(())
    })
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
