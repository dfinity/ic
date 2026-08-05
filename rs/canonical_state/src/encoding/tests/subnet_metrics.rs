//! Cross-checks the `subnet_metrics` management canister method's
//! `consumed_cycles_total` against the canonical (certified) state encoding.

use crate::CertificationVersion;
use crate::encoding::types::SubnetMetrics as CanonicalSubnetMetrics;
use ic_replicated_state::CanisterStates;
use ic_replicated_state::metadata_state::SubnetMetrics;
use ic_test_utilities_state::new_canister_state;
use ic_test_utilities_types::ids::{canister_test_id, user_test_id};
use ic_types::NumBytes;
use ic_types_cycles::{
    CanisterCyclesCostSchedule, CompoundCycles, Cycles, Instructions, NominalCycles,
    NominalCyclesTesting,
};
use std::sync::Arc;

/// The `consumed_cycles_total` that `ExecutionEnvironment::subnet_metrics`
/// computes must equal the one that the canonical state encoding produces at
/// certification version `V29`.
///
// Keep in sync with `ExecutionEnvironment::subnet_metrics` in
// `rs/execution_environment/src/execution_environment.rs`, which carries the
// reciprocal comment.
#[test]
fn subnet_metrics_consumed_cycles_matches_v29_canonical_encoding() {
    let mut metrics = SubnetMetrics::default();
    metrics.num_canisters = 3;
    metrics.canister_state_bytes = NumBytes::new(1_234);
    metrics.update_transactions_total = 42;
    metrics.observe_consumed_cycles_by_deleted_canisters(NominalCycles::new(1_000_000_007));
    metrics.observe_consumed_cycles_http_outcalls(NominalCycles::new(2_000_000_011));

    let mut canisters = CanisterStates::default();
    for id in 1..=3_u64 {
        let mut canister = new_canister_state(
            canister_test_id(id),
            user_test_id(1).get(),
            Cycles::new(1 << 60),
            ic_base_types::NumSeconds::new(100_000),
        );
        canister
            .system_state
            .consume_cycles(CompoundCycles::<Instructions>::new(
                Cycles::new(100_000 * id as u128),
                CanisterCyclesCostSchedule::Normal,
            ));
        canisters.insert(Arc::new(canister));
    }

    // What the `subnet_metrics` handler computes.
    let handler_total = metrics.consumed_cycles_total() + canisters.total_consumed_cycles();

    // What the certified state tree reports at `V29`, recombined from its
    // `(high, low)` parts.
    let canonical = CanonicalSubnetMetrics::from((
        &metrics,
        canisters.total_consumed_cycles(),
        CertificationVersion::V29,
    ));
    let low = canonical.consumed_cycles_total.low;
    let high = canonical.consumed_cycles_total.high.unwrap();
    let canonical_total = ((high as u128) << 64) | (low as u128);

    assert_eq!(handler_total.get(), canonical_total);
    // The test would be vacuous if both were zero.
    assert!(canonical_total > 0);

    // The other three fields pass through unchanged.
    assert_eq!(canonical.num_canisters, metrics.num_canisters);
    assert_eq!(
        canonical.canister_state_bytes,
        metrics.canister_state_bytes.get()
    );
    assert_eq!(
        canonical.update_transactions_total,
        metrics.update_transactions_total
    );
}
