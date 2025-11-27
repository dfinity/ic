use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::time;
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
    NNS_UI_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub mod canister_management;
pub mod init;
pub mod pb;
pub mod root_proposals;

pub fn now_nanoseconds() -> u64 {
    if cfg!(target_arch = "wasm32") {
        time()
    } else {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get time since epoch")
            .as_nanos()
            .try_into()
            .expect("Failed to convert time to u64")
    }
}

pub fn now_seconds() -> u64 {
    Duration::from_nanos(now_nanoseconds()).as_secs()
}

fn system_time_now() -> SystemTime {
    let nanos = now_nanoseconds();
    UNIX_EPOCH + Duration::from_nanos(nanos)
}

thread_local! {
    // TODO: Move this to canister.rs. It needs to be here for now, because
    // other libs want to use this. Ideally, this would only be passed to the
    // constructor of TrackingManagementCanisterClient.
    pub static PROXIED_CANISTER_CALLS_TRACKER: RefCell<ProxiedCanisterCallsTracker> =
        RefCell::new(ProxiedCanisterCallsTracker::new(system_time_now));
}

/// Encode the metrics in a format that can be understood by Prometheus.
pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    PROXIED_CANISTER_CALLS_TRACKER.with(|proxied_canister_calls_tracker| {
        let proxied_canister_calls_tracker = proxied_canister_calls_tracker.borrow();

        let mut metric_builder = w.gauge_vec(
            "nns_root_in_flight_proxied_canister_call_max_age_seconds",
            "The age of incomplete canister calls that are being made on \
             behalf of another NNS canisters, usually NNS governance.",
        )?;
        for (key, max_age) in
            proxied_canister_calls_tracker.get_method_name_caller_callee_to_in_flight_max_age()
        {
            let (method_name, caller, callee) = key;

            metric_builder = metric_builder.value(
                &[
                    ("caller", &principal_name(caller)),
                    ("callee", &principal_name(callee.get())),
                    ("method_name", &method_name),
                ],
                max_age.as_secs_f64(),
            )?;
        }

        let mut metrics = w.gauge_vec(
            "nns_root_in_flight_proxied_canister_call_count",
            "The number of proxied canister calls that are in flight and being made \
             on behalf of another (NNS) canister.",
        )?;
        let in_flight_counts =
            proxied_canister_calls_tracker.get_method_name_caller_callee_to_in_flight_count();
        for ((method_name, caller, callee), count) in &in_flight_counts {
            metrics = metrics.value(
                &[
                    ("method_name", method_name),
                    ("caller", &principal_name(*caller)),
                    ("callee", &principal_name(callee.get())),
                ],
                *count as f64,
            )?;
        }

        // All of the following metrics are superseded (by nns_root_in_flight_proxied_canister_call_count).

        let canister_status_caller_to_in_flight_count = {
            // I am not sure if this fact is in the spec, but it is in the code.
            let min_principal_id = CanisterId::ic_00().get();

            // This is the range where method_name == "canister_status".
            let begin = (
                "canister_status".to_string(),
                min_principal_id,
                CanisterId::ic_00(),
            );
            let end = (
                "canister_status\0".to_string(),
                min_principal_id,
                CanisterId::ic_00(),
            );

            in_flight_counts
                .range(begin..end)
                .map(|((_, caller, _), count)| (*caller, *count))
                .collect::<BTreeMap<PrincipalId, u64>>()
        };

        w.encode_gauge(
            "nns_root_open_canister_status_calls_count",
            canister_status_caller_to_in_flight_count
                .values()
                .sum::<u64>() as f64,
            "Superseded by nns_root_in_flight_proxied_canister_call_count. \
             Count of open CanisterStatusCalls.",
        )?;

        let mut metrics = w.gauge_vec(
            "nns_root_open_canister_status_calls",
            "Superseded by nns_root_in_flight_proxied_canister_call_count. \
             The list of counters and canister_ids with open canister_status calls.",
        )?;
        for (canister_id, call_count) in &canister_status_caller_to_in_flight_count {
            metrics = metrics.value(
                &[("canister_id", &format!("{canister_id}"))],
                (*call_count) as f64,
            )?;
        }

        std::io::Result::Ok(())
    })?;

    Ok(())
}

fn principal_name(principal_id: PrincipalId) -> String {
    lazy_static! {
        static ref CANISTER_ID_TO_NAME: BTreeMap<CanisterId, &'static str> = btreemap! {
            CanisterId::ic_00() => "management",
            REGISTRY_CANISTER_ID => "registry",
            GOVERNANCE_CANISTER_ID => "governance",
            LEDGER_CANISTER_ID => "ledger",
            ROOT_CANISTER_ID => "root",
            CYCLES_MINTING_CANISTER_ID => "cycles_minting",
            LIFELINE_CANISTER_ID => "lifeline",
            GENESIS_TOKEN_CANISTER_ID => "genesis_token",
            IDENTITY_CANISTER_ID => "identity",
            NNS_UI_CANISTER_ID => "nns_ui",
            SNS_WASM_CANISTER_ID => "sns_wasm",
            EXCHANGE_RATE_CANISTER_ID => "exchange_rate",
        };
    }

    Some(CanisterId::unchecked_from_principal(principal_id))
        .and_then(|canister_id| CANISTER_ID_TO_NAME.get(&canister_id))
        .map(|name| format!("{name}_canister"))
        .unwrap_or_else(|| principal_id.to_string())
}

#[cfg(test)]
mod tests;
