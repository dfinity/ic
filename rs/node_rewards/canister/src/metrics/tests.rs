use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use crate::metrics::{MetricsManager, UnixTsNanos};
use crate::pb::v1::SubnetMetricsKey;
use chrono::{Days, NaiveDate};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_cdk::call::{CallPerformFailed, CallResult, Error as CallError};
use ic_cdk_management_canister::{NodeMetrics, NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use rewards_calculation::types::NodeMetricsDailyRaw;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};

pub mod mock {
    use super::{CallResult, NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
    use crate::metrics::ManagementCanisterClient;
    use async_trait::async_trait;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub CanisterClient {}

        #[async_trait]
        impl ManagementCanisterClient for CanisterClient {
            async fn node_metrics_history(&self, args: &NodeMetricsHistoryArgs) -> CallResult<Vec<NodeMetricsHistoryRecord>>;
        }
    }
}
pub type VM = VirtualMemory<DefaultMemoryImpl>;
const ONE_DAY_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;
pub fn subnet_id(id: u64) -> ic_base_types::SubnetId {
    PrincipalId::new_subnet_test_id(id).into()
}
fn node_id(id: u64) -> ic_base_types::NodeId {
    PrincipalId::new_node_test_id(id).into()
}

impl MetricsManager<VM> {
    pub(crate) fn new_test(client: mock::MockCanisterClient) -> Self {
        Self {
            client: Box::new(client),
            subnets_metrics: RefCell::new(crate::storage::stable_btreemap_init(MemoryId::new(0))),
            last_timestamp_per_subnet: RefCell::new(crate::storage::stable_btreemap_init(
                MemoryId::new(2),
            )),
            baseline_day_per_subnet: RefCell::new(crate::storage::stable_btreemap_init(
                MemoryId::new(3),
            )),
        }
    }
}

fn add_days(date: &NaiveDate, days: u64) -> NaiveDate {
    date.checked_add_days(Days::new(days)).unwrap()
}

fn node_metrics_history_gen(days: u64) -> Vec<NodeMetricsHistoryRecord> {
    let mut result = Vec::new();
    for i in 0..days {
        result.push(NodeMetricsHistoryRecord {
            timestamp_nanos: i * ONE_DAY_NANOS,
            node_metrics: vec![],
        });
    }
    result
}

#[tokio::test]
async fn subnet_metrics_added_correctly() {
    let days = 45;
    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .return_const(Ok(node_metrics_history_gen(days)));
    let mm = MetricsManager::new_test(mock);

    let subnet_1 = subnet_id(1);

    mm.update_subnets_metrics(vec![subnet_1]).await.unwrap();
    for i in 0..days {
        let key = SubnetMetricsKey {
            timestamp_nanos: i * ONE_DAY_NANOS,
            subnet_id: Some(subnet_1.get()),
        };
        assert!(mm.subnets_metrics.borrow().get(&key).is_some());
    }
}

#[tokio::test]
async fn multiple_subnets_metrics_added_correctly() {
    let days = 30;
    let mut mock = mock::MockCanisterClient::new();

    mock.expect_node_metrics_history()
        .return_const(Ok(node_metrics_history_gen(days)));
    let mm = MetricsManager::new_test(mock);
    let subnet_1 = subnet_id(1);
    let subnet_2 = subnet_id(2);

    mm.update_subnets_metrics(vec![subnet_1, subnet_2])
        .await
        .unwrap();

    for subnet in &[subnet_1, subnet_2] {
        for i in 0..days {
            let key = SubnetMetricsKey {
                timestamp_nanos: i * ONE_DAY_NANOS,
                subnet_id: Some(subnet.get()),
            };
            assert!(
                mm.subnets_metrics.borrow().get(&key).is_some(),
                "Metrics missing for subnet {subnet:?}"
            );
        }
    }
}

#[tokio::test]
async fn partial_failures_are_handled_correctly() {
    let subnet_1 = subnet_id(1);
    let subnet_2 = subnet_id(2);
    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |subnet| {
        if SubnetId::from(PrincipalId::from(subnet.subnet_id)) == subnet_1 {
            Err(CallError::CallPerformFailed(CallPerformFailed {}))
        } else {
            Ok(node_metrics_history_gen(1))
        }
    });

    let mm = MetricsManager::new_test(mock);

    let res = mm.update_subnets_metrics(vec![subnet_1, subnet_2]).await;

    assert!(res.is_err());

    let key = SubnetMetricsKey {
        timestamp_nanos: 0,
        subnet_id: Some(subnet_1.get()),
    };
    assert!(
        mm.subnets_metrics.borrow().get(&key).is_none(),
        "Metrics should not be present for subnet 1"
    );

    let key = SubnetMetricsKey {
        timestamp_nanos: 0,
        subnet_id: Some(subnet_2.get()),
    };
    assert!(
        mm.subnets_metrics.borrow().get(&key).is_some(),
        "Metrics should be present for subnet 2"
    );
}

const MAX_TIMES: usize = 20;
type Proposed = u64;
type Failed = u64;

#[derive(Clone)]
struct NodeMetricsHistoryResponseTracker {
    current_subnet: SubnetId,
    subnets_responses: BTreeMap<UnixTsNanos, HashMap<SubnetId, Vec<NodeMetrics>>>,
}

impl NodeMetricsHistoryResponseTracker {
    pub fn new() -> Self {
        Self {
            current_subnet: subnet_id(0),
            subnets_responses: BTreeMap::new(),
        }
    }

    fn with_subnet(mut self, subnet_id: SubnetId) -> Self {
        self.current_subnet = subnet_id;
        for metrics in self.subnets_responses.values_mut() {
            metrics.insert(subnet_id, Vec::new());
        }
        self
    }

    fn add_node_metrics(
        mut self,
        node_id: NodeId,
        metrics: Vec<(NaiveDate, Vec<(Proposed, Failed)>)>,
    ) -> Self {
        for (mut from, proposed_failed) in metrics {
            for (proposed, failed) in proposed_failed {
                let entry = self
                    .subnets_responses
                    .entry(last_unix_timestamp_nanoseconds(&from))
                    .or_default();
                let entry_sub = entry.entry(self.current_subnet).or_default();

                entry_sub.push(NodeMetrics {
                    num_blocks_proposed_total: proposed,
                    num_block_failures_total: failed,
                    node_id: node_id.get().0,
                });
                from = from.succ_opt().unwrap();
            }
        }
        self
    }

    fn next(
        &self,
        response_step: usize,
        args: &NodeMetricsHistoryArgs,
    ) -> Vec<NodeMetricsHistoryRecord> {
        let mut response = Vec::new();
        let subnet_id = SubnetId::from(PrincipalId::from(args.subnet_id));

        self.subnets_responses
            .range(args.start_at_timestamp_nanos..)
            .take(response_step)
            .filter(|(_, metrics)| metrics.contains_key(&subnet_id))
            .for_each(|(ts, metrics)| {
                let node_metrics = metrics.get(&subnet_id).unwrap().clone();
                response.push(NodeMetricsHistoryRecord {
                    node_metrics,
                    timestamp_nanos: *ts,
                });
            });

        response
    }

    fn next_2_steps(&self, contract: &NodeMetricsHistoryArgs) -> Vec<NodeMetricsHistoryRecord> {
        self.next(2, contract)
    }
}

async fn _daily_metrics_correct_different_update_size(size: usize) {
    let day_start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let tracker = NodeMetricsHistoryResponseTracker::new()
        .with_subnet(subnet_id(1))
        .add_node_metrics(
            node_id(1),
            vec![(day_start, vec![(7, 5), (10, 6), (15, 6), (25, 50)])],
        )
        .add_node_metrics(node_id(2), vec![(day_start, vec![(19, 21), (32, 22)])])
        // Node 2 is redeployed to subnet 1 on day 2
        .add_node_metrics(node_id(2), vec![(add_days(&day_start, 3), vec![(10, 10)])]);

    println!("metrics stored {:?}", tracker.subnets_responses);

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .returning(move |contract| Ok(tracker.next(size, contract)));
    let mm = MetricsManager::new_test(mock);

    for _ in 0..MAX_TIMES {
        mm.update_subnets_metrics(vec![subnet_id(1)]).await.unwrap();
    }
    let daily_metrics: Vec<Vec<NodeMetricsDailyRaw>> =
        mm.metrics_by_subnet(&day_start).into_values().collect();

    println!("{:?}", daily_metrics);

    // (7, 5)
    assert_eq!(daily_metrics[0][0].num_blocks_proposed, 7);
    assert_eq!(daily_metrics[0][0].num_blocks_failed, 5);

    assert_eq!(daily_metrics[0][1].num_blocks_proposed, 19);
    assert_eq!(daily_metrics[0][1].num_blocks_failed, 21);

    let daily_metrics: Vec<Vec<NodeMetricsDailyRaw>> = mm
        .metrics_by_subnet(&day_start.succ_opt().unwrap())
        .into_values()
        .collect();

    // (10 - 7, 6 - 5) = (3, 1)
    // (32 - 19, 22 - 21) = (13, 1)
    assert_eq!(daily_metrics[0][0].num_blocks_proposed, 3);
    assert_eq!(daily_metrics[0][0].num_blocks_failed, 1);

    assert_eq!(daily_metrics[0][1].num_blocks_proposed, 13);
    assert_eq!(daily_metrics[0][1].num_blocks_failed, 1);

    let daily_metrics: Vec<Vec<NodeMetricsDailyRaw>> = mm
        .metrics_by_subnet(&add_days(&day_start, 2))
        .into_values()
        .collect();

    // (15 - 10, 6 - 6) = (5, 0)
    assert_eq!(daily_metrics[0][0].num_blocks_proposed, 5);
    assert_eq!(daily_metrics[0][0].num_blocks_failed, 0);

    let daily_metrics: Vec<Vec<NodeMetricsDailyRaw>> = mm
        .metrics_by_subnet(&add_days(&day_start, 3))
        .into_values()
        .collect();

    // (25 - 15, 50 - 6) = (10, 44)
    assert_eq!(daily_metrics[0][0].num_blocks_proposed, 10);
    assert_eq!(daily_metrics[0][0].num_blocks_failed, 44);

    assert_eq!(daily_metrics[0][1].num_blocks_proposed, 10);
    assert_eq!(daily_metrics[0][1].num_blocks_failed, 10);
}

#[tokio::test]
async fn daily_metrics_correct_different_update_size() {
    _daily_metrics_correct_different_update_size(2).await;
    _daily_metrics_correct_different_update_size(3).await;
    _daily_metrics_correct_different_update_size(4).await;
    _daily_metrics_correct_different_update_size(5).await;
}

#[tokio::test]
async fn daily_metrics_correct_2_subs() {
    let subnet_1 = subnet_id(1);
    let subnet_2 = subnet_id(2);

    let node_1 = node_id(1);
    let day_start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

    let tracker = NodeMetricsHistoryResponseTracker::new()
        .with_subnet(subnet_1)
        .add_node_metrics(node_1, vec![(day_start, vec![(1, 1), (2, 2), (3, 3)])])
        .with_subnet(subnet_2)
        .add_node_metrics(
            node_1,
            vec![(add_days(&day_start, 3), vec![(4, 4), (6, 6), (8, 8)])],
        );

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .returning(move |contract| Ok(tracker.next_2_steps(contract)));
    let mm = MetricsManager::new_test(mock);

    for _ in 0..MAX_TIMES {
        mm.update_subnets_metrics(vec![subnet_1, subnet_2])
            .await
            .unwrap();
    }

    let mut node_1_daily_metrics = Vec::new();
    for day in 0..8 {
        let daily_metrics = mm
            .metrics_by_subnet(&add_days(&day_start, day))
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .filter_map(|(sub, metrics)| {
                metrics
                    .into_iter()
                    .find(|daily_metrics| daily_metrics.node_id == node_1)
                    .map(move |metrics_node_1| (sub, metrics_node_1))
            })
            .collect::<Vec<_>>();
        node_1_daily_metrics.extend(daily_metrics);
    }

    for (day, (subnet, metrics)) in node_1_daily_metrics.into_iter().enumerate() {
        match day {
            0 => {
                assert_eq!(subnet, subnet_1);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (1, 1)
                );
            }
            1 => {
                assert_eq!(subnet, subnet_1);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (1, 1)
                );
            }
            2 => {
                assert_eq!(subnet, subnet_1);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (1, 1)
                );
            }
            3 => {
                assert_eq!(subnet, subnet_2);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (4, 4)
                );
            }
            4 => {
                assert_eq!(subnet, subnet_2);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (2, 2)
                );
            }
            _ => {
                assert_eq!(subnet, subnet_2);
                assert_eq!(
                    (metrics.num_blocks_proposed, metrics.num_blocks_failed),
                    (2, 2)
                );
            }
        }
    }
}

#[tokio::test]
async fn daily_metrics_correct_overlapping_days() {
    let subnet_1 = subnet_id(1);
    let subnet_2 = subnet_id(2);

    let node_1 = node_id(1);
    let node_2 = node_id(2);
    let day_start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();

    let tracker = NodeMetricsHistoryResponseTracker::new()
        .with_subnet(subnet_1)
        .add_node_metrics(node_1, vec![(day_start, vec![(1, 1), (2, 2), (3, 3)])])
        .with_subnet(subnet_2)
        // Node 1 redeployed to subnet 2 on day 2
        .add_node_metrics(
            node_1,
            vec![(add_days(&day_start, 2), vec![(4, 4), (6, 6), (8, 8)])],
        )
        .add_node_metrics(
            node_2,
            vec![(add_days(&day_start, 2), vec![(1, 1), (3, 3), (6, 6)])],
        );

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .returning(move |contract| Ok(tracker.next_2_steps(contract)));
    let mm = MetricsManager::new_test(mock);

    for _ in 0..MAX_TIMES {
        let _ = mm
            .update_subnets_metrics(vec![subnet_id(1), subnet_id(2)])
            .await;
    }

    let mut daily_metrics = Vec::new();
    for idx in 0..4 {
        let day = add_days(&day_start, idx);
        let metrics = mm
            .metrics_by_subnet(&day)
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .filter_map(|(sub, metrics)| {
                metrics
                    .into_iter()
                    .find(|daily_metrics| daily_metrics.node_id == node_1)
                    .map(move |metrics_node_1| (sub, day, metrics_node_1))
            })
            .collect::<Vec<_>>();
        daily_metrics.extend(metrics);
    }

    let overlapping_sub_1 = daily_metrics
        .iter()
        .find(|(sub, day, _)| sub == &subnet_1 && *day == add_days(&day_start, 2))
        .map(|(_, _, node_metrics)| node_metrics)
        .unwrap();

    assert_eq!(overlapping_sub_1.num_blocks_proposed, 1);
    assert_eq!(overlapping_sub_1.num_blocks_failed, 1);

    let overlapping_sub_2 = daily_metrics
        .iter()
        .find(|(sub, day, _)| sub == &subnet_2 && *day == add_days(&day_start, 2))
        .map(|(_, _, node_metrics)| node_metrics)
        .unwrap();

    assert_eq!(overlapping_sub_2.num_blocks_proposed, 4);
    assert_eq!(overlapping_sub_2.num_blocks_failed, 4);
}

/// The synced day must be the day every subnet has metrics for, not the day the furthest-along
/// subnet has reached.
///
/// A `node_metrics_history` call can succeed and still stop short: the management canister leaves
/// out the running (current-day) snapshot, so a subnet that has produced no block for a while
/// answers with older records than a healthy one. Reporting the furthest day would let rewards be
/// computed for days the lagging subnet contributed nothing to, on which its nodes read as
/// unassigned and are paid on an extrapolated failure rate rather than their own.
#[tokio::test]
async fn synced_day_is_the_day_every_subnet_covers() {
    let lagging = subnet_id(1);
    let healthy = subnet_id(2);

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |args| {
        let days = if SubnetId::from(PrincipalId::from(args.subnet_id)) == lagging {
            // Stalled after day 1: no snapshot has closed since, so nothing newer comes back.
            2
        } else {
            5
        };
        Ok(node_metrics_history_gen(days))
    });
    let mm = MetricsManager::new_test(mock);

    let synced_day = mm
        .update_subnets_metrics(vec![lagging, healthy])
        .await
        .unwrap();

    // node_metrics_history_gen puts day n at n * ONE_DAY_NANOS from the epoch, so the lagging
    // subnet's last record is day 1 and the healthy one's is day 4.
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    assert_eq!(
        synced_day,
        add_days(&epoch, 1),
        "the synced day must not run ahead of the lagging subnet"
    );
}

/// Once the lagging subnet catches up, the synced day advances with it — the minimum holds the day
/// back, it does not pin it down.
#[tokio::test]
async fn synced_day_advances_once_every_subnet_catches_up() {
    let subnet_1 = subnet_id(1);
    let subnet_2 = subnet_id(2);
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .return_const(Ok(node_metrics_history_gen(5)));
    let mm = MetricsManager::new_test(mock);

    // Put subnet_1 two days behind before the sync, the way a previous sync would have left it.
    mm.last_timestamp_per_subnet
        .borrow_mut()
        .insert(subnet_1.into(), 2 * ONE_DAY_NANOS);
    mm.last_timestamp_per_subnet
        .borrow_mut()
        .insert(subnet_2.into(), 4 * ONE_DAY_NANOS);
    assert_eq!(
        mm.last_day_fully_synced(&[subnet_1, subnet_2]),
        Some(add_days(&epoch, 2))
    );

    let synced_day = mm
        .update_subnets_metrics(vec![subnet_1, subnet_2])
        .await
        .unwrap();

    assert_eq!(synced_day, add_days(&epoch, 4));
}

/// A subnet with nothing stored — one created today, whose first day has not closed yet — must not
/// drag the synced day back to the epoch. Doing so would block every reward calculation
/// network-wide until that subnet's first day closed.
#[tokio::test]
async fn subnet_with_no_metrics_at_all_does_not_hold_the_synced_day_back() {
    let with_metrics = subnet_id(1);
    let brand_new = subnet_id(2);

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |args| {
        if SubnetId::from(PrincipalId::from(args.subnet_id)) == brand_new {
            Ok(vec![])
        } else {
            Ok(node_metrics_history_gen(5))
        }
    });
    let mm = MetricsManager::new_test(mock);

    let synced_day = mm
        .update_subnets_metrics(vec![with_metrics, brand_new])
        .await
        .unwrap();

    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    assert_eq!(synced_day, add_days(&epoch, 4));
    assert!(
        mm.last_timestamp_per_subnet
            .borrow()
            .get(&brand_new.into())
            .is_none(),
        "a subnet that returned no records should have no stored timestamp"
    );
    // It is credited with the day the reporting subnet reached, not skipped: that is what stops
    // the synced day advancing past it if it never reports.
    assert_eq!(
        mm.day_covered_by(brand_new),
        Some(add_days(&epoch, 4)),
        "a subnet seen for the first time should be credited with the days that predate it"
    );
}

/// With nothing stored for any subnet there is no day to report as synced. Recording the epoch
/// instead — what `unwrap_or_default` used to do — reads as a successful sync of 1970-01-01.
#[tokio::test]
async fn no_synced_day_is_recorded_when_no_subnet_has_metrics() {
    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().return_const(Ok(vec![]));
    let mm = MetricsManager::new_test(mock);

    let result = mm
        .update_subnets_metrics(vec![subnet_id(1), subnet_id(2)])
        .await;

    assert!(result.is_err(), "got {result:?}");
}

/// Being skipped for having no metrics is a state a subnet does not necessarily grow out of: one
/// that stalls before closing its first daily snapshot answers with an empty history for good,
/// because the management canister keeps that snapshot as running stats and `node_metrics_history`
/// never returns running stats. Once the subnets that do report move past the day it came in on,
/// the synced day has to stop with it — otherwise the very gap the minimum exists to close is
/// reopened for its nodes.
#[tokio::test]
async fn subnet_whose_history_stays_empty_stops_holding_the_synced_day_from_the_day_it_appeared() {
    let reporting = subnet_id(1);
    let never_reports = subnet_id(2);
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

    // The reporting subnet gets three days further along between the two syncs.
    let sync_count = AtomicUsize::new(0);
    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |args| {
        if SubnetId::from(PrincipalId::from(args.subnet_id)) == never_reports {
            return Ok(vec![]);
        }
        // Both subnets are fetched per sync, so count the reporting one only.
        let days = match sync_count.fetch_add(1, Ordering::SeqCst) {
            0 => 3,
            _ => 6,
        };
        Ok(node_metrics_history_gen(days))
    });
    let mm = MetricsManager::new_test(mock);

    let first = mm
        .update_subnets_metrics(vec![reporting, never_reports])
        .await
        .unwrap();
    assert_eq!(
        first,
        add_days(&epoch, 2),
        "on the first sync the subnet with no metrics has nothing to answer for yet"
    );

    let second = mm
        .update_subnets_metrics(vec![reporting, never_reports])
        .await
        .unwrap();
    assert_eq!(
        mm.day_covered_by(reporting),
        Some(add_days(&epoch, 5)),
        "the reporting subnet should have moved on"
    );
    assert_eq!(
        second,
        add_days(&epoch, 2),
        "the synced day must stay at the day the silent subnet appeared, not follow the other one"
    );
}

/// The baseline records where a subnet came in, so a later sync must not move it forward — that
/// would let it drift along behind the reporting subnets and never hold anything back.
#[tokio::test]
async fn baseline_of_a_subnet_without_metrics_is_not_moved_by_later_syncs() {
    let reporting = subnet_id(1);
    let never_reports = subnet_id(2);
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

    let sync_count = AtomicUsize::new(0);
    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().returning(move |args| {
        if SubnetId::from(PrincipalId::from(args.subnet_id)) == never_reports {
            return Ok(vec![]);
        }
        let days = match sync_count.fetch_add(1, Ordering::SeqCst) {
            0 => 3,
            _ => 6,
        };
        Ok(node_metrics_history_gen(days))
    });
    let mm = MetricsManager::new_test(mock);

    for _ in 0..3 {
        mm.update_subnets_metrics(vec![reporting, never_reports])
            .await
            .unwrap();
    }

    assert_eq!(mm.day_covered_by(never_reports), Some(add_days(&epoch, 2)));
}

/// A subnet that reports after having been credited with a baseline is judged on what it reported,
/// even when that is an earlier day: a subnet stalled since day D finally closes the snapshot D was
/// still running in, which is genuinely all it has.
#[tokio::test]
async fn a_reported_day_overrides_the_baseline_even_when_it_is_earlier() {
    let subnet = subnet_id(1);
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

    let mut mock = mock::MockCanisterClient::new();
    mock.expect_node_metrics_history().return_const(Ok(vec![]));
    let mm = MetricsManager::new_test(mock);

    mm.baseline_day_per_subnet
        .borrow_mut()
        .insert(subnet.into(), 5 * ONE_DAY_NANOS);
    mm.last_timestamp_per_subnet
        .borrow_mut()
        .insert(subnet.into(), 2 * ONE_DAY_NANOS);

    assert_eq!(mm.day_covered_by(subnet), Some(add_days(&epoch, 2)));
    assert_eq!(
        mm.last_day_fully_synced(&[subnet]),
        Some(add_days(&epoch, 2))
    );
}
