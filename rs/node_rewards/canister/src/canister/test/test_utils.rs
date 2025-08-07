use crate::canister::NodeRewardsCanister;
use crate::metrics::MetricsManager;
use crate::storage::METRICS_MANAGER;
use ic_base_types::{NodeId, PrincipalId};
use ic_cdk::api::call::CallResult;
use ic_management_canister_types::NodeMetricsHistoryRecord;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_registry_canister_client::RegistryDataStableMemory;
use ic_registry_canister_client::{
    test_registry_data_stable_memory_impl, StableCanisterRegistryClient, StorableRegistryKey,
    StorableRegistryValue,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use rewards_calculation::rewards_calculator_results::{
    DailyResults, DayUtc, NodeProviderRewards, NodeResults, NodeStatus, RewardsCalculatorResults,
};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::style::LineText;
use tabled::Table;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    pub(crate) static STATE_TEST: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
    // Dummy value b/c we can't do direct assignment using values defined above.
    pub(crate) static CANISTER_TEST: RefCell<NodeRewardsCanister> = {
        let registry_store = Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default())));
        let metrics_manager = METRICS_MANAGER.with(|m| m.clone());

        RefCell::new(NodeRewardsCanister::new(registry_store, metrics_manager))
    };
}

test_registry_data_stable_memory_impl!(TestState, STATE_TEST);

pub(crate) fn setup_thread_local_canister_for_test() -> (Arc<FakeRegistry>, Rc<MetricsManager<VM>>)
{
    let fake_registry = Arc::new(FakeRegistry::new());
    let mut mock = crate::metrics::tests::mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .return_const(CallResult::Ok(vec![NodeMetricsHistoryRecord {
            timestamp_nanos: 0,
            node_metrics: vec![],
        }]));
    let metrics_manager = Rc::new(MetricsManager::new_test(mock));
    let canister = NodeRewardsCanister::new(
        Arc::new(StableCanisterRegistryClient::<TestState>::new(
            fake_registry.clone(),
        ))
        .clone(),
        metrics_manager.clone(),
    );
    CANISTER_TEST.with_borrow_mut(|c| *c = canister);
    (fake_registry, metrics_manager)
}

// ------------------------------------------------------------------------------------------------
// Helper functions for tabled output
// ------------------------------------------------------------------------------------------------

struct DailyProviderSummary {
    underperforming_nodes: Vec<NodeId>,
    total_rewards: Decimal,
}

/// Aggregates results across all nodes for a provider to calculate daily summaries.
/// This separates data calculation from presentation.
fn calculate_daily_summaries(
    results: &NodeProviderRewards,
) -> BTreeMap<DayUtc, DailyProviderSummary> {
    let mut summaries: BTreeMap<DayUtc, DailyProviderSummary> = BTreeMap::new();

    for NodeResults {
        node_id,
        daily_results,
        ..
    } in &results.nodes_results
    {
        for DailyResults {
            day,
            adjusted_rewards_xdr_permyriad,
            performance_multiplier_percent,
            ..
        } in daily_results
        {
            let summary = summaries.entry(*day).or_insert(DailyProviderSummary {
                underperforming_nodes: Vec::new(),
                total_rewards: dec!(0),
            });

            summary.total_rewards += adjusted_rewards_xdr_permyriad;
            if performance_multiplier_percent < &dec!(1) {
                summary.underperforming_nodes.push(*node_id);
            }
        }
    }
    summaries
}

/// Helper functions for building tables.
const NODE_HEADERS: [&'static str; 9] = [
    "Day UTC",
    "Status",
    "Subnet FR",
    "Blocks Proposed/Failed",
    "Original FR",
    "FR relative/extrapolated",
    "Performance Multiplier",
    "Base Rewards",
    "Adjusted Rewards",
];

const SUMMARY_HEADERS: [&'static str; 3] =
    ["Day UTC", "Underperforming Nodes", "Total Daily Rewards"];

pub fn tabled(results: &RewardsCalculatorResults) -> String {
    let mut all_tables = vec!["Rewards Calculator Results".to_string()];

    for (provider_id, provider_results) in &results.provider_results {
        // 1. Aggregate the daily summaries for the provider.
        let daily_summaries = calculate_daily_summaries(provider_results);

        // 2. Build and add the provider's summary table.
        all_tables.push(build_provider_summary_table(provider_id, &daily_summaries));

        // 3. Add the computation log.
        all_tables.push(provider_results.computation_log.clone());

        // 4. First, generate tables for each individual node.
        let node_tables: Vec<String> = provider_results
            .nodes_results
            .iter()
            .map(|node_results| build_node_table(&node_results.node_id, node_results))
            .collect();
        all_tables.extend(node_tables);
    }

    all_tables.join("\n\n")
}

fn build_node_table(node_id: &NodeId, node_results: &NodeResults) -> String {
    let mut builder = Builder::default();
    builder.push_record(NODE_HEADERS);

    for result in &node_results.daily_results {
        let mut row = vec![result.day.to_string()];
        let (status_cols, perf_cols) = format_row_segments(result);
        row.extend(status_cols);
        row.extend(perf_cols);
        builder.push_record(row);
    }

    let title = format!("NodeId: {}", node_id.get());
    apply_title(builder.build(), title)
}

/// Builds the summary table for a single node provider.
fn build_provider_summary_table(
    provider_id: &PrincipalId,
    summaries: &BTreeMap<DayUtc, DailyProviderSummary>,
) -> String {
    let mut builder = Builder::default();
    builder.push_record(SUMMARY_HEADERS);

    for (day, summary) in summaries {
        let node_ids: Vec<String> = summary
            .underperforming_nodes
            .iter()
            .map(|id| id.get().to_string().split('-').next().unwrap().to_string())
            .collect();

        builder.push_record([
            day.to_string(),
            node_ids.join("\n"),
            summary.total_rewards.to_string(),
        ]);
    }

    let title = format!("Overall Performance for Provider: {}", provider_id);
    apply_title(builder.build(), title)
}

/// Helper to format row data, separating status-specific and common columns.
fn format_row_segments(results: &DailyResults) -> (Vec<String>, Vec<String>) {
    let status_columns = match &results.node_status {
        NodeStatus::Assigned { node_metrics } => {
            let subnet_prefix = node_metrics.subnet_assigned.get().to_string();
            vec![
                format!("Assigned - {}", &subnet_prefix[..5]),
                node_metrics
                    .subnet_assigned_fr_percent
                    .round_dp(4)
                    .to_string(),
                format!(
                    "{}/{}",
                    node_metrics.num_blocks_proposed, node_metrics.num_blocks_failed
                ),
                node_metrics.original_fr_percent.round_dp(4).to_string(),
                node_metrics.relative_fr_percent.round_dp(4).to_string(),
            ]
        }
        NodeStatus::Unassigned {
            extrapolated_fr_percent,
        } => vec![
            "Unassigned".to_string(),
            "N/A".to_string(),
            "N/A".to_string(),
            "N/A".to_string(),
            extrapolated_fr_percent.round_dp(4).to_string(),
        ],
    };

    let performance_columns = vec![
        results.performance_multiplier_percent.to_string(),
        results.base_rewards_xdr_permyriad.to_string(),
        results.adjusted_rewards_xdr_permyriad.to_string(),
    ];

    (status_columns, performance_columns)
}

/// Applies a consistent title style to a table.
fn apply_title(mut table: Table, title: String) -> String {
    table.with(LineText::new(title, Rows::first()).offset(2));
    table.to_string()
}
