use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use crate::metrics::{MetricsManager, UnixTsNanos};
use crate::pb::v1::SubnetMetricsKey;
use chrono::{Days, NaiveDate};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_cdk::api::call::{CallResult, RejectionCode};
use ic_management_canister_types::{NodeMetrics, NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use rewards_calculation::types::NodeMetricsDailyRaw;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

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
            async fn node_metrics_history(&self, args: NodeMetricsHistoryArgs) -> CallResult<Vec<NodeMetricsHistoryRecord>>;
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
        .return_const(CallResult::Ok(node_metrics_history_gen(days)));
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
        .return_const(CallResult::Ok(node_metrics_history_gen(days)));
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
            CallResult::Err((RejectionCode::Unknown, "Error".to_string()))
        } else {
            CallResult::Ok(node_metrics_history_gen(1))
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
        for (_, metrics) in self.subnets_responses.iter_mut() {
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
        args: NodeMetricsHistoryArgs,
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

    fn next_2_steps(&self, contract: NodeMetricsHistoryArgs) -> Vec<NodeMetricsHistoryRecord> {
        self.next(2, contract)
    }
}

async fn _daily_metrics_correct_different_update_size(size: usize) {
    let day_start = NaiveDate::from_ymd(2025, 1, 1);
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
        .returning(move |contract| CallResult::Ok(tracker.next(size, contract)));
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
    let day_start = NaiveDate::from_ymd(2025, 1, 1);

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
        .returning(move |contract| CallResult::Ok(tracker.next_2_steps(contract)));
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
    let day_start = NaiveDate::from_ymd(2025, 1, 1);

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
        .returning(move |contract| CallResult::Ok(tracker.next_2_steps(contract)));
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
