use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use crate::metrics::MetricsManager;
use crate::registry_querier::RegistryQuerier;
use crate::storage::{NaiveDateStorable, VM};
use candid::Principal;
use chrono::{DateTime, NaiveDate};
use ic_base_types::{PrincipalId, SubnetId};
use ic_node_rewards_canister_api::RewardsCalculationAlgorithmVersion;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    DailyResults as ApiDailyResults, GetNodeProvidersRewardsCalculationRequest,
    GetNodeProvidersRewardsCalculationResponse,
};
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, GetNodeProvidersRewardsResponse, NodeProvidersRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{RewardsPerNodeProvider, calculate_rewards_v0};
use ic_stable_structures::StableCell;
use ic_types::{RegistryVersion, Time};
use rewards_calculation::AlgorithmVersion;
use rewards_calculation::performance_based_algorithm::results::{
    DailyNodeProviderRewards, DailyResults,
};
use rewards_calculation::performance_based_algorithm::{
    v1::RewardsCalculationV1, v2::RewardsCalculationV2,
};
use rewards_calculation::types::{NodeMetricsDailyRaw, RewardableNode};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::LocalKey;

#[cfg(test)]
mod test;

#[cfg(target_arch = "wasm32")]
pub fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn current_time() -> Time {
    ic_types::time::current_time()
}

/// This struct represents the API for the canister.  API methods should be implemented in
/// main.rs and defer the important work to the methods in this struct, essentially passing
/// through arguments and responses with almost no logic.
pub struct NodeRewardsCanister {
    registry_client: Arc<dyn CanisterRegistryClient>,
    metrics_manager: Rc<MetricsManager<VM>>,
    last_day_synced: &'static LocalKey<RefCell<StableCell<Option<NaiveDateStorable>, VM>>>,
}

/// Internal methods
impl NodeRewardsCanister {
    pub fn new(
        registry_client: Arc<dyn CanisterRegistryClient>,
        metrics_manager: Rc<MetricsManager<VM>>,
        last_day_synced: &'static LocalKey<RefCell<StableCell<Option<NaiveDateStorable>, VM>>>,
    ) -> Self {
        Self {
            registry_client,
            metrics_manager,
            last_day_synced,
        }
    }

    /// Gets Arc reference to RegistryClient
    pub fn get_registry_client(&self) -> Arc<dyn CanisterRegistryClient> {
        self.registry_client.clone()
    }

    /// Gets Arc reference to MetricsManager
    pub fn get_metrics_manager(&self) -> Rc<MetricsManager<VM>> {
        self.metrics_manager.clone()
    }

    // Test only methods
    pub fn get_registry_value(&self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.registry_client
            .get_value(key.as_ref(), self.registry_client.get_latest_version())
            .map_err(|e| format!("Failed to get registry value: {:?}", e))
    }

    pub fn get_last_day_synced(&self) -> Option<NaiveDate> {
        self.last_day_synced
            .with_borrow(|last_day_synced| last_day_synced.get().clone().map(|d| d.0))
    }

    pub fn set_last_day_synced(&self, last_day_synced: NaiveDate) {
        self.last_day_synced.with_borrow_mut(|cell| {
            cell.set(Some(NaiveDateStorable(last_day_synced)))
                .expect("Could not set last day synced");
        });
    }

    pub async fn schedule_registry_sync(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    ) -> Result<RegistryVersion, String> {
        let registry_client = canister.with(|canister| canister.borrow().get_registry_client());

        registry_client.sync_registry_stored().await
    }

    pub async fn schedule_metrics_sync(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    ) -> Result<(), String> {
        let (registry_client, metrics_manager) = canister.with(|canister| {
            (
                canister.borrow().get_registry_client(),
                canister.borrow().get_metrics_manager(),
            )
        });
        let registry_querier = RegistryQuerier::new(registry_client.clone());
        let version = registry_client.get_latest_version();
        let subnets_list: Vec<SubnetId> = registry_querier
            .subnets_list(version)?
            .into_iter()
            .filter(
                |subnet_id| match registry_querier.get_subnet_record(*subnet_id, version) {
                    Ok(Some(record)) if record.subnet_type() == SubnetType::CloudEngine => {
                        ic_cdk::println!(
                            "Excluding cloud engine subnet {} from metrics collection",
                            subnet_id,
                        );
                        false
                    }
                    _ => true,
                },
            )
            .collect();
        let last_day_synced: NaiveDate =
            metrics_manager.update_subnets_metrics(subnets_list).await?;
        canister.with_borrow(|canister| {
            canister.set_last_day_synced(last_day_synced);
        });

        Ok(())
    }

    fn validate_reward_period(
        &self,
        from_date: NaiveDate,
        to_date: NaiveDate,
    ) -> Result<(), String> {
        let last_day_synced = self
            .get_last_day_synced()
            .ok_or("Metrics and registry are not synced up")?;

        if last_day_synced < to_date {
            return Err("Metrics and registry are not synced up to to_date".to_string());
        }

        if from_date > to_date {
            return Err("from_date must be before to_date".to_string());
        }

        let today =
            DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
                .date_naive();

        if to_date >= today {
            return Err("to_date must be earlier than today".to_string());
        }

        Ok(())
    }

    fn calculate_rewards_for_date(
        &self,
        date: &NaiveDate,
        algorithm_version: Option<RewardsCalculationAlgorithmVersion>,
    ) -> Result<DailyResults, String> {
        // Default to currently used algorithm
        let rewards_calculator_version = algorithm_version.unwrap_or_default();

        let mut daily_results = match rewards_calculator_version.version {
            RewardsCalculationV1::VERSION => {
                RewardsCalculationV1::calculate_rewards_for_date(date, &self)
                    .map_err(|e| format!("Could not calculate rewards: {e:?}"))
            }
            RewardsCalculationV2::VERSION => {
                RewardsCalculationV2::calculate_rewards_for_date(date, &self)
                    .map_err(|e| format!("Could not calculate rewards: {e:?}"))
            }
            _ => Err(format!(
                "Rewards Calculation Version: {rewards_calculator_version:?} is not supported"
            )),
        }?;

        // Apply the temporary node provider reward reduction mandated by NNS motion
        // proposal 142724. This is applied here, at the canister boundary, rather than inside the
        // versioned reward-calculation algorithm, so the algorithm stays pure and reproducible.
        apply_node_provider_reward_reduction(&mut daily_results, date);

        Ok(daily_results)
    }
}

// ================================================================================================
// Temporary node provider reward reduction (NNS motion proposal 142724)
// ================================================================================================
//
// The motion "Follow-up on Node Provider Standards, Incident Response Readiness" mandates a 50%
// reduction of node provider rewards for a period of three months, for the node providers that
// failed to respond to both incident-response smoke tests.
//
// Design notes:
//   * The reduction is applied here, at the canister boundary, on top of the performance-based
//     adjustment, i.e. final = base * performance_multiplier * REWARD_REDUCTION_MULTIPLIER. It is
//     intentionally NOT baked into the versioned reward-calculation algorithm, so that the
//     algorithm stays pure and historically reproducible.
//   * The window is expressed as fixed UTC calendar dates. Reward calculation is deterministic
//     given the stored daily metrics, so querying any past day always returns the same result, and
//     the reduction reverts automatically at REWARD_REDUCTION_END without a further upgrade.
//   * The start and end dates are fixed UTC calendar dates chosen per NNS motion proposal 142724.

/// First day (inclusive, UTC) on which the reduction applies.
const REWARD_REDUCTION_START: (i32, u32, u32) = (2026, 7, 15);
/// First day (exclusive, UTC) on which the reduction no longer applies.
const REWARD_REDUCTION_END: (i32, u32, u32) = (2026, 10, 15);

// Node providers subject to the reduction: those that failed to respond within the 24h window in
// BOTH incident-response smoke tests (May 20 and June 13, 2026), per NNS motion proposal 142724.
// A late (>24h) response counts as a failure. Principals were taken from the node provider registry
// and cross-checked against the on-chain `list_node_providers`.
const REDUCED_NODE_PROVIDERS: &[&str] = &[
    "sqhxa-h6ili-qkwup-ohzwn-yofnm-vvnp5-kxdhg-saabw-rvua3-xp325-zqe", // 43rd Big Idea Films
    "eipr5-izbom-neyqh-s3ec2-52eww-cyfpg-qfomg-3dpwj-4pffh-34xcu-7qe", // 87m Neuron
    "2dgp4-h57n4-a4kgx-n4uun-huo3a-wbdlc-m57wd-jtkuh-g5vcc-fcbby-6qe", // 100 Count Holdings
    "ss6oe-fm7b2-b5r57-y3x74-omrz5-d5pgy-5iwtw-4aew5-aqj3l-6ydra-wqe", // Arceau NP LLC
    "mjnyf-lzqq6-s7fzb-62rqm-xzvge-5oa26-humwp-dvwxp-jxxkf-hoel7-fqe", // Bitmoon
    "sma3p-ivkif-hz7nu-ngmvq-ibnjg-nubke-zf6gh-wbnfc-2dlng-l3die-zqe", // BLP22
    "ks7ow-zvs7i-ratdk-azq34-zio2b-gbekj-qjicg-pfhp3-ovhgu-k5qql-dae", // BlockTech Ventures
    "i3cfo-s2tgu-qe5ym-wk7e6-y7ura-pptgu-kevuf-2feh7-z4enq-5hz4s-mqe", // Conic Ventures
    "w4buy-lgwzr-pccs7-huzhh-qqnws-rns75-iaoox-jolrm-xs2ra-vdu3o-2qe", // Decentralized Entities Foundation
    "7ryes-jnj73-bsyu4-lo6h7-lbxk5-x4ien-lylws-5qwzl-hxd5f-xjh3w-mqe", // Extragone SA
    "i7dto-bgkj2-xo5dx-cyrb7-zkk5y-q46eh-gz6iq-qkgyc-w4qte-scgtb-6ae", // Iancu Aurel
    "7ws2n-wqorv-vmo4m-5e222-n42c3-hk43s-ei3kp-4hpbn-xlkzo-jgv7i-tqe", // InfoObjects
    "4dibr-2alzr-h6kva-bvwn2-yqgsl-o577t-od46o-v275p-a2zov-tcw4f-eae", // Neptune Partners
    "r3yjn-kthmg-pfgmb-2fngg-5c7d7-t6kqg-wi37r-j7gy6-iee64-kjdja-jae", // Pindar Technology Limited
    "4fedi-eu6ue-nd7ts-vnof5-hzg66-hgzl7-liy5n-3otyp-h7ipw-owycg-uae", // Power Meta Corporation
    "g2ax6-jrkmb-3zuh3-jibtb-q5xoq-njrgo-5utbc-j2o7g-zfq2w-yyhky-dqe", // Wancloud limited
    "glrjs-2dbzh-owbdd-fpp5e-eweoz-nsuto-e3jmk-tl42c-wem4f-qfpfa-qqe", // Zarety
    "pa5mu-yxsey-b4yrk-bodka-dhjnm-a3nx4-w2grw-3b766-ddr6e-nupu4-pqe", // Zenith Code LLC
    "hzqcb-iiagd-4erjo-qn7rq-syqro-zztl6-cpble-atnkd-2c6bg-bxjoa-qae", // Zondax AG
];

/// Multiplier applied to the adjusted rewards of affected node providers within the window.
fn reward_reduction_multiplier() -> Decimal {
    Decimal::new(5, 1) // 0.5
}

fn reward_reduction_window() -> (NaiveDate, NaiveDate) {
    let to_date = |(y, m, d): (i32, u32, u32)| {
        NaiveDate::from_ymd_opt(y, m, d).expect("invalid reward reduction date constant")
    };
    (
        to_date(REWARD_REDUCTION_START),
        to_date(REWARD_REDUCTION_END),
    )
}

thread_local! {
    /// The affected node providers, parsed from `REDUCED_NODE_PROVIDERS` once and reused across
    /// calculations (parsing panics here on the first access if a principal is malformed).
    static REDUCED_NODE_PROVIDER_SET: BTreeSet<PrincipalId> = REDUCED_NODE_PROVIDERS
        .iter()
        .map(|p| PrincipalId::from_str(p).expect("invalid principal in REDUCED_NODE_PROVIDERS"))
        .collect();
}

/// Applies the temporary node provider reward reduction (proposal 142724) to `results` for `date`.
fn apply_node_provider_reward_reduction(results: &mut DailyResults, date: &NaiveDate) {
    let (start, end) = reward_reduction_window();
    REDUCED_NODE_PROVIDER_SET.with(|reduced| {
        reduce_provider_results(
            &mut results.provider_results,
            date,
            start,
            end,
            reduced,
            reward_reduction_multiplier(),
        );
    });
}

/// Pure implementation of the reward reduction, split out for testing.
///
/// For each affected node provider, this scales every node's adjusted rewards (which already
/// include the performance multiplier) by `multiplier`, then recomputes the provider total from
/// the scaled node values so that the per-node breakdown stays consistent with the total. Base
/// rewards are left untouched.
fn reduce_provider_results(
    provider_results: &mut BTreeMap<PrincipalId, DailyNodeProviderRewards>,
    date: &NaiveDate,
    start: NaiveDate,
    end: NaiveDate,
    reduced_providers: &BTreeSet<PrincipalId>,
    multiplier: Decimal,
) {
    if *date < start || *date >= end || reduced_providers.is_empty() {
        return;
    }

    for (provider_id, provider_rewards) in provider_results.iter_mut() {
        if !reduced_providers.contains(provider_id) {
            continue;
        }

        let mut total_adjusted = Decimal::ZERO;
        for node in provider_rewards.daily_nodes_rewards.iter_mut() {
            node.adjusted_rewards_xdr_permyriad *= multiplier;
            total_adjusted += node.adjusted_rewards_xdr_permyriad;
        }
        provider_rewards.total_adjusted_rewards_xdr_permyriad = total_adjusted
            .trunc()
            .to_u64()
            .expect("adjusted rewards should fit into u64");
    }
}

impl rewards_calculation::performance_based_algorithm::PerformanceBasedAlgorithmInputProvider
    for &NodeRewardsCanister
{
    fn get_rewards_table(&self, date: &NaiveDate) -> Result<NodeRewardsTable, String> {
        let registry_querier = RegistryQuerier::new(self.registry_client.clone());

        let version = registry_querier
            .version_for_timestamp_nanoseconds(last_unix_timestamp_nanoseconds(date))
            .ok_or_else(|| "Could not find registry version for timestamp".to_string())?;
        Ok(registry_querier.get_rewards_table(version))
    }

    fn get_daily_metrics_by_subnet(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String> {
        let metrics = self.metrics_manager.metrics_by_subnet(date);
        if metrics.is_empty() {
            return Err(format!(
                "No metrics found for day {}",
                date.format("%Y-%m-%d")
            ));
        }
        Ok(metrics)
    }

    fn get_rewardable_nodes(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let registry_client = self.get_registry_client();
        let registry_querier = RegistryQuerier::new(registry_client.clone());
        registry_querier
            .get_rewardable_nodes_per_provider(date, None)
            .map_err(|e| format!("Could not get rewardable nodes: {e:?}"))
    }
}

// Exposed API Methods
impl NodeRewardsCanister {
    pub async fn get_node_providers_monthly_xdr_rewards(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersMonthlyXdrRewardsRequest,
    ) -> GetNodeProvidersMonthlyXdrRewardsResponse {
        let registry_client = canister.with(|canister| canister.borrow().get_registry_client());

        // Main impl below
        return match inner_get_node_providers_monthly_xdr_rewards(registry_client, request).await {
            Ok((rewards, latest_version)) => GetNodeProvidersMonthlyXdrRewardsResponse {
                rewards: Some(NodeProvidersMonthlyXdrRewards {
                    rewards: rewards
                        .rewards_per_node_provider
                        .into_iter()
                        .map(|(k, v)| (k.0, v))
                        .collect(),
                    registry_version: Some(latest_version.get()),
                }),
                error: None,
            },
            Err(e) => GetNodeProvidersMonthlyXdrRewardsResponse {
                rewards: None,
                error: Some(e),
            },
        };

        async fn inner_get_node_providers_monthly_xdr_rewards(
            registry_client: Arc<dyn CanisterRegistryClient>,
            request: GetNodeProvidersMonthlyXdrRewardsRequest,
        ) -> Result<(RewardsPerNodeProvider, RegistryVersion), String> {
            registry_client.sync_registry_stored().await.map_err(|e| {
                format!(
                    "Could not sync registry store to latest version, \
                    please try again later: {:?}",
                    e
                )
            })?;

            let version = request
                .registry_version
                .map(RegistryVersion::new)
                .unwrap_or_else(|| registry_client.get_latest_version());

            let rewards_table = get_decoded_value::<NodeRewardsTable>(
                &*registry_client,
                NODE_REWARDS_TABLE_KEY,
                version,
            )
            .map_err(|e| format!("Could not find NodeRewardsTable: {e:?}"))?
            .ok_or_else(|| "Node Rewards Table was not found in the Registry".to_string())?;

            let node_operators = decoded_key_value_pairs_for_prefix::<NodeOperatorRecord>(
                &*registry_client,
                NODE_OPERATOR_RECORD_KEY_PREFIX,
                version,
            )?;

            let data_centers = decoded_key_value_pairs_for_prefix::<DataCenterRecord>(
                &*registry_client,
                DATA_CENTER_KEY_PREFIX,
                version,
            )?
            .into_iter()
            .collect();

            calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)
                .map(|rewards| (rewards, version))
        }
    }

    pub async fn get_node_providers_rewards(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsRequest,
    ) -> GetNodeProvidersRewardsResponse {
        let from_date = NaiveDate::try_from(request.from_day)?;
        let to_date = NaiveDate::try_from(request.to_day)?;
        canister.with_borrow(|c| c.validate_reward_period(from_date, to_date))?;

        let mut rewards_per_node_provider: BTreeMap<Principal, u64> = BTreeMap::new();

        let algorithm_version = request.algorithm_version.unwrap_or_default();
        for day in from_date.iter_days().take_while(|d| *d <= to_date) {
            let result_for_day = canister
                .with_borrow(|canister| {
                    canister.calculate_rewards_for_date(&day, request.algorithm_version)
                })
                .map_err(|e| format!("Could not calculate rewards: {e:?}"))?;

            for (provider_id, provider_rewards) in &result_for_day.provider_results {
                rewards_per_node_provider
                    .entry(provider_id.0)
                    .and_modify(|total| {
                        *total += provider_rewards.total_adjusted_rewards_xdr_permyriad
                    })
                    .or_insert(provider_rewards.total_adjusted_rewards_xdr_permyriad);
            }

            #[cfg(target_arch = "wasm32")]
            let _ = ic_cdk::call::Call::bounded_wait(
                ic_cdk::api::canister_self(),
                "reset_instructions",
            )
            .await
            .unwrap();
        }

        Ok(NodeProvidersRewards {
            algorithm_version,
            rewards_xdr_permyriad: rewards_per_node_provider,
        })
    }

    pub fn get_node_providers_rewards_calculation(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsCalculationRequest,
    ) -> GetNodeProvidersRewardsCalculationResponse {
        let date = NaiveDate::try_from(request.day)?;
        canister.with_borrow(|c| c.validate_reward_period(date, date))?;
        let daily_results = canister
            .with_borrow(|canister| {
                canister.calculate_rewards_for_date(&date, request.algorithm_version)
            })
            .map_err(|e| format!("Could not calculate rewards: {e:?}"))?;
        ApiDailyResults::try_from(daily_results)
    }
}

/// Get the key value pairs for a given prefix from the registry.
///
/// NOTE: This function strips the prefix, so node_operator_xyz becomes xyz.
fn decoded_key_value_pairs_for_prefix<T: prost::Message + Default>(
    registry_client: &dyn CanisterRegistryClient,
    key_prefix: &str,
    version: RegistryVersion,
) -> Result<Vec<(String, T)>, String> {
    registry_client
        .get_key_family_with_values(key_prefix, version)
        .map_err(|e| format!("Could not get values for prefix {key_prefix}: {e:?}"))?
        .into_iter()
        .map(|(k, v)| {
            T::decode(v.as_slice())
                .map_err(|e| format!("Could not decode prost Message for key {k}: {e:?}"))
                .map(|record| (k.strip_prefix(key_prefix).unwrap().to_string(), record))
        })
        .collect::<Result<Vec<_>, String>>()
}

#[cfg(test)]
mod reward_reduction_tests {
    use super::*;
    use ic_base_types::NodeId;
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use rewards_calculation::performance_based_algorithm::results::{
        DailyNodeFailureRate, DailyNodeRewards,
    };

    fn node(adjusted: Decimal) -> DailyNodeRewards {
        DailyNodeRewards {
            node_id: NodeId::from(PrincipalId::new_node_test_id(0)),
            node_reward_type: NodeRewardType::Type1,
            region: "Europe,CH".to_string(),
            dc_id: "dc1".to_string(),
            daily_node_failure_rate: DailyNodeFailureRate::NonSubnetMember {
                extrapolated_failure_rate: Decimal::ZERO,
            },
            performance_multiplier: Decimal::ONE,
            rewards_reduction: Decimal::ZERO,
            base_rewards_xdr_permyriad: adjusted,
            adjusted_rewards_xdr_permyriad: adjusted,
        }
    }

    /// Builds a provider with one node per value in `adjusted_values`, mirroring the algorithm's
    /// invariant that the provider total equals the truncated sum of the node adjusted rewards.
    fn provider_rewards(adjusted_values: &[i64]) -> DailyNodeProviderRewards {
        let daily_nodes_rewards: Vec<_> = adjusted_values
            .iter()
            .map(|v| node(Decimal::from(*v)))
            .collect();
        let total: i64 = adjusted_values.iter().sum();
        DailyNodeProviderRewards {
            total_base_rewards_xdr_permyriad: total as u64,
            total_adjusted_rewards_xdr_permyriad: total as u64,
            base_rewards: vec![],
            type3_base_rewards: vec![],
            daily_nodes_rewards,
        }
    }

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    fn reduce(
        results: &mut BTreeMap<PrincipalId, DailyNodeProviderRewards>,
        on: NaiveDate,
        reduced: &[PrincipalId],
    ) {
        reduce_provider_results(
            results,
            &on,
            d(2026, 7, 15),
            d(2026, 10, 15),
            &reduced.iter().cloned().collect(),
            Decimal::new(5, 1), // 0.5
        );
    }

    #[test]
    fn affected_provider_is_halved_within_window() {
        let affected = PrincipalId::new_node_test_id(1);
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100, 51]))]);

        reduce(&mut results, d(2026, 7, 15), &[affected]);

        let pr = &results[&affected];
        // Nodes are individually halved and the total is recomputed from the scaled nodes.
        assert_eq!(
            pr.daily_nodes_rewards[0].adjusted_rewards_xdr_permyriad,
            Decimal::from(50)
        );
        assert_eq!(
            pr.daily_nodes_rewards[1].adjusted_rewards_xdr_permyriad,
            Decimal::new(255, 1) // 25.5
        );
        // trunc(50 + 25.5) == 75; total stays consistent with the node breakdown.
        assert_eq!(pr.total_adjusted_rewards_xdr_permyriad, 75);
        // Base rewards are untouched.
        assert_eq!(pr.total_base_rewards_xdr_permyriad, 151);
    }

    #[test]
    fn unaffected_provider_is_untouched() {
        let affected = PrincipalId::new_node_test_id(1);
        let other = PrincipalId::new_node_test_id(2);
        let mut results = BTreeMap::from([(other, provider_rewards(&[100, 50]))]);

        reduce(&mut results, d(2026, 7, 15), &[affected]);

        assert_eq!(results[&other].total_adjusted_rewards_xdr_permyriad, 150);
    }

    #[test]
    fn no_reduction_before_window() {
        let affected = PrincipalId::new_node_test_id(1);
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);

        // The day before the (inclusive) start is not reduced.
        reduce(&mut results, d(2026, 7, 14), &[affected]);

        assert_eq!(results[&affected].total_adjusted_rewards_xdr_permyriad, 100);
    }

    #[test]
    fn no_reduction_on_end_date_or_after() {
        let affected = PrincipalId::new_node_test_id(1);

        // End date is exclusive.
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
        reduce(&mut results, d(2026, 10, 15), &[affected]);
        assert_eq!(results[&affected].total_adjusted_rewards_xdr_permyriad, 100);

        // A day well after the window (reproducibility: a later query still yields full rewards
        // for out-of-window days).
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
        reduce(&mut results, d(2026, 12, 1), &[affected]);
        assert_eq!(results[&affected].total_adjusted_rewards_xdr_permyriad, 100);
    }

    #[test]
    fn reduction_applies_on_start_and_last_in_window_day() {
        let affected = PrincipalId::new_node_test_id(1);

        for day in [d(2026, 7, 15), d(2026, 10, 14)] {
            let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
            reduce(&mut results, day, &[affected]);
            assert_eq!(
                results[&affected].total_adjusted_rewards_xdr_permyriad, 50,
                "expected reduction on {day}"
            );
        }
    }

    #[test]
    fn empty_reduced_set_is_noop_even_within_window() {
        let affected = PrincipalId::new_node_test_id(1);
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);

        reduce(&mut results, d(2026, 8, 1), &[]);

        assert_eq!(results[&affected].total_adjusted_rewards_xdr_permyriad, 100);
    }

    #[test]
    fn all_reduced_node_providers_parse() {
        // Fails fast in CI when REDUCED_NODE_PROVIDERS is populated with an invalid principal,
        // rather than only panicking on the first access of the thread_local initializer.
        for p in REDUCED_NODE_PROVIDERS {
            assert!(
                PrincipalId::from_str(p).is_ok(),
                "REDUCED_NODE_PROVIDERS entry is not a valid principal: {p}"
            );
        }
    }
}
