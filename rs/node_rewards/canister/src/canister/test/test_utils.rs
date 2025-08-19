use crate::canister::NodeRewardsCanister;
use crate::metrics::MetricsManager;
use crate::storage::METRICS_MANAGER;
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
    DayUtc, NodeStatus, RewardsCalculatorResults,
};
use rust_decimal::Decimal;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

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

pub fn write_rewards_to_csv(
    results: &RewardsCalculatorResults,
    output_path: &str,
) -> std::io::Result<()> {
    use std::collections::BTreeMap;

    let base_path = Path::new(output_path).join("result");
    create_dir_all(&base_path)?;

    // Write subnets_failure_rate.csv
    let subnets_path = base_path.join("subnets_failure_rate.csv");
    let mut subnets_file = csv::Writer::from_writer(File::create(&subnets_path)?);
    subnets_file.write_record(&["day", "subnet_id", "failure_rate"])?;
    for ((day, subnet_id), fr) in &results.subnets_fr {
        subnets_file.write_record(&[
            day.to_string(),
            subnet_id.to_string().split('-').next().unwrap().to_string(),
            format!("{:.4}", fr),
        ])?;
    }
    subnets_file.flush()?;

    for (np_id, provider_result) in &results.provider_results {
        let np_folder = base_path.join(format!("{}", np_id));
        create_dir_all(&np_folder)?;

        // base_rewards.csv
        let mut writer =
            csv::Writer::from_writer(File::create(np_folder.join("base_rewards.csv"))?);
        writer.write_record(&[
            "node_reward_type",
            "region",
            "monthly_xdr_permyriad",
            "daily_xdr_permyriad",
        ])?;
        for br in &provider_result.base_rewards {
            writer.write_record(&[
                format!("{:?}", br.node_reward_type),
                br.region.to_string(),
                format!("{:.4}", br.monthly),
                format!("{:.4}", br.daily),
            ])?;
        }
        writer.flush()?;

        // base_rewards_type3.csv
        let mut writer =
            csv::Writer::from_writer(File::create(np_folder.join("base_rewards_type3.csv"))?);
        writer.write_record(&["day", "region", "nodes_count", "xdr_permyriad"])?;
        for br in &provider_result.base_rewards_type3 {
            writer.write_record(&[
                br.day.to_string(),
                br.region.to_string(),
                br.nodes_count.to_string(),
                format!("{:.4}", br.value),
            ])?;
        }
        writer.flush()?;

        // nodes_results.csv
        let mut writer =
            csv::Writer::from_writer(File::create(np_folder.join("nodes_results.csv"))?);

        writer.write_record(&[
            "node_id",
            "node_reward_type",
            "region",
            "dc_id",
            "day",
            "status",
            "subnet_assigned",
            "subnet_assigned_fr",
            "num_blocks_proposed",
            "num_blocks_failed",
            "original_fr",
            "relative_fr",
            "extrapolated_fr",
            "performance_multiplier",
            "rewards_reduction",
            "base_rewards_xdr_permyriad",
            "adjusted_rewards_xdr_permyriad",
        ])?;

        for node in &provider_result.nodes_results {
            for day_result in &node.daily_results {
                let (
                    status_str,
                    subnet_assigned,
                    subnet_fr,
                    blocks_proposed,
                    blocks_failed,
                    original_fr,
                    relative_fr,
                    extrapolated_fr,
                ) = match &day_result.node_status {
                    NodeStatus::Assigned { node_metrics } => (
                        "assigned",
                        node_metrics
                            .subnet_assigned
                            .to_string()
                            .split('-')
                            .next()
                            .unwrap()
                            .to_string(),
                        format!("{:.4}", node_metrics.subnet_assigned_fr),
                        node_metrics.num_blocks_proposed.to_string(),
                        node_metrics.num_blocks_failed.to_string(),
                        format!("{:.4}", node_metrics.original_fr),
                        format!("{:.4}", node_metrics.relative_fr),
                        "".to_string(), // extrapolated_fr unused
                    ),
                    NodeStatus::Unassigned { extrapolated_fr } => (
                        "unassigned",
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        format!("{:.4}", extrapolated_fr),
                    ),
                };

                writer.write_record(&[
                    node.node_id
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap()
                        .to_string(),
                    format!("{:?}", node.node_reward_type),
                    node.region.clone(),
                    node.dc_id.clone(),
                    day_result.day.to_string(),
                    status_str.to_string(),
                    subnet_assigned,
                    subnet_fr,
                    blocks_proposed,
                    blocks_failed,
                    original_fr,
                    relative_fr,
                    extrapolated_fr,
                    format!("{:.4}", day_result.performance_multiplier),
                    format!("{:.4}", day_result.rewards_reduction),
                    format!("{:.4}", day_result.base_rewards),
                    format!("{:.4}", day_result.adjusted_rewards),
                ])?;
            }
        }
        writer.flush()?;

        // overall_rewards_per_day.csv
        let mut writer =
            csv::Writer::from_writer(File::create(np_folder.join("overall_rewards_per_day.csv"))?);
        writer.write_record(&[
            "day",
            "total_adjusted_rewards_xdr_permyriad",
            "nodes_in_registry",
            "underperforming_nodes",
        ])?;

        let mut daily_totals: BTreeMap<DayUtc, Decimal> = BTreeMap::new();
        let mut nodes_total: BTreeMap<DayUtc, usize> = BTreeMap::new();
        let mut underperforming: BTreeMap<DayUtc, Vec<String>> = BTreeMap::new();

        for node in &provider_result.nodes_results {
            for res in &node.daily_results {
                let day = res.day;
                *daily_totals.entry(day).or_default() += res.adjusted_rewards;
                *nodes_total.entry(day).or_default() += 1;

                if res.performance_multiplier < Decimal::ONE {
                    underperforming.entry(day).or_default().push(
                        node.node_id
                            .to_string()
                            .split('-')
                            .next()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }

        for (day, total) in &daily_totals {
            let nodes = underperforming
                .get(day)
                .map(|v| v.join(","))
                .unwrap_or_else(|| "".to_string());
            let nodes_in_registry = nodes_total.remove(day).unwrap_or_default().to_string();
            writer.write_record(&[
                day.to_string(),
                format!("{:.4}", total),
                nodes_in_registry,
                nodes,
            ])?;
        }
    }

    Ok(())
}
