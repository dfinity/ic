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
use std::collections::BTreeMap;
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

        // Apply the temporary node provider reward reductions introduced under NNS motion
        // proposal 142724. This is applied here, at the canister boundary, rather than inside the
        // versioned reward-calculation algorithm, so the algorithm stays pure and reproducible.
        apply_node_provider_reward_reduction(&mut daily_results, date);

        Ok(daily_results)
    }
}

// ================================================================================================
// Temporary node provider reward reductions (NNS motion proposal 142724)
// ================================================================================================
//
// The motion "Follow-up on Node Provider Standards, Incident Response Readiness" (proposal 142724)
// established this mechanism: a temporary reduction of node provider rewards for the providers
// that failed to meet the incident-response standards. The motion set the mechanism, not the
// providers it applies to — each round's cohort and window are set by upgrading this canister,
// and no further motion is needed to add one. Every round therefore appends one entry to
// `REWARD_REDUCTIONS` below: a set of node providers, a fixed UTC date window, and a multiplier.
//
// Design notes:
//   * Reductions are applied here, at the canister boundary, on top of the performance-based
//     adjustment, i.e. final = base * performance_multiplier * multiplier. They are intentionally
//     NOT baked into the versioned reward-calculation algorithm, so that the algorithm stays pure
//     and historically reproducible.
//   * Each window is expressed as fixed UTC calendar dates. Reward calculation is deterministic
//     given the stored daily metrics, so querying any past day always returns the same result, and
//     each entry's reduction reverts automatically at its `end` without a further upgrade.
//   * Entries are only ever APPENDED, never edited or removed — not even once their window has
//     passed. Nothing in this canister persists computed rewards: every query recomputes the
//     requested days from the stored raw metrics using the table compiled into the running Wasm.
//     Editing or deleting a past entry therefore silently rewrites the canister's account of days
//     that have already been minted.
//   * A new entry's `start` must not predate the first day of the current, not-yet-minted reward
//     period. Governance advances its reward period past every day it has minted and never
//     recomputes those days, so a reduction reaching further back is a no-op in terms of tokens
//     while still making this table claim a penalty that was never applied.
//   * When several entries cover the same provider on the same day, the SMALLEST multiplier wins.
//     Reductions deliberately do NOT compound: a provider caught by two overlapping 50% rounds is
//     reduced to 50% on the overlapping days, not to 25%.

/// A temporary reward reduction for a cohort of node providers over a fixed UTC date window.
struct RewardReduction {
    /// First day (inclusive, UTC) on which the reduction applies.
    start: (i32, u32, u32),
    /// First day (exclusive, UTC) on which the reduction no longer applies.
    end: (i32, u32, u32),
    /// Multiplier applied to the adjusted rewards, as `(mantissa, scale)`, e.g. `(5, 1)` for 0.5.
    multiplier: (i64, u32),
    /// The node providers subject to this reduction. Principals were taken from the node provider
    /// registry and cross-checked against the on-chain `list_node_providers`.
    providers: &'static [&'static str],
}

/// The reward reductions applied so far, in the order they were introduced. Append-only; see the
/// design notes above before touching an existing entry.
const REWARD_REDUCTIONS: &[RewardReduction] = &[
    // First round: 50% for three months for the node providers that failed to respond within the
    // 24h window in BOTH incident-response smoke tests (May 20 and June 13, 2026). A late (>24h)
    // response counts as a failure.
    RewardReduction {
        start: (2026, 7, 15),
        end: (2026, 10, 15),
        multiplier: (5, 1), // 0.5
        providers: &[
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
        ],
    },
    // Second round: 50% for three months for the node providers that failed the incident-response
    // requirement in the follow-up review. Providers from the round above that have since recovered
    // are deliberately absent here, so their reduction ends with that round's window on 2026-10-15
    // and they are rewarded in full from the second half of October on. Providers in both rounds
    // are reduced continuously from 2026-07-15 to 2026-11-01 — at 50%, not 25%, on the overlapping
    // days.
    RewardReduction {
        start: (2026, 8, 1),
        end: (2026, 11, 1),
        multiplier: (5, 1), // 0.5
        providers: &[
            "2dgp4-h57n4-a4kgx-n4uun-huo3a-wbdlc-m57wd-jtkuh-g5vcc-fcbby-6qe", // 100 Count Holdings
            "sqhxa-h6ili-qkwup-ohzwn-yofnm-vvnp5-kxdhg-saabw-rvua3-xp325-zqe", // 43rd Big Idea Films
            "cp5ib-twnmx-h4dvd-isef2-tu44u-kb2ka-fise5-m4hta-hnxoq-k45mm-hqe", // ACCUSET SOLUTIONS
            "kos24-5xact-6aror-uofg2-tnvt6-dq3bk-c2c5z-jtptt-jbqvc-lmegy-qae", // Anonstake
            "ss6oe-fm7b2-b5r57-y3x74-omrz5-d5pgy-5iwtw-4aew5-aqj3l-6ydra-wqe", // Arceau NP LLC
            "mjnyf-lzqq6-s7fzb-62rqm-xzvge-5oa26-humwp-dvwxp-jxxkf-hoel7-fqe", // Bitmoon
            "ks7ow-zvs7i-ratdk-azq34-zio2b-gbekj-qjicg-pfhp3-ovhgu-k5qql-dae", // BlockTech Ventures
            "sma3p-ivkif-hz7nu-ngmvq-ibnjg-nubke-zf6gh-wbnfc-2dlng-l3die-zqe", // BLP22
            "w4buy-lgwzr-pccs7-huzhh-qqnws-rns75-iaoox-jolrm-xs2ra-vdu3o-2qe", // Decentralized Entities Foundation
            "7ryes-jnj73-bsyu4-lo6h7-lbxk5-x4ien-lylws-5qwzl-hxd5f-xjh3w-mqe", // Extragone SA
            "i7dto-bgkj2-xo5dx-cyrb7-zkk5y-q46eh-gz6iq-qkgyc-w4qte-scgtb-6ae", // Iancu Aurel
            "7ws2n-wqorv-vmo4m-5e222-n42c3-hk43s-ei3kp-4hpbn-xlkzo-jgv7i-tqe", // InfoObjects
            "izmhk-lpjum-uo4oy-lviba-yctpc-arg4b-2ywim-vgoiu-gqaj2-gskmw-2qe", // MI Servers
            "4dibr-2alzr-h6kva-bvwn2-yqgsl-o577t-od46o-v275p-a2zov-tcw4f-eae", // Neptune Partners
            "ma7dp-gz4tg-3c2wv-pgnsv-wna7u-czvhu-fpu47-t4dr6-gzxql-wr2m2-qae", // Reist Telecom AG
            "sixix-2nyqd-t2k2v-vlsyz-dssko-ls4hl-hyij4-y7mdp-ja6cj-nsmpf-yae", // Starbase
            "glrjs-2dbzh-owbdd-fpp5e-eweoz-nsuto-e3jmk-tl42c-wem4f-qfpfa-qqe", // Zarety
            "hzqcb-iiagd-4erjo-qn7rq-syqro-zztl6-cpble-atnkd-2c6bg-bxjoa-qae", // Zondax AG
        ],
    },
];

/// One reduction window and the multiplier that applies within it.
type ReductionWindow = (NaiveDate, NaiveDate, Decimal);

thread_local! {
    /// `REWARD_REDUCTIONS` indexed by node provider, parsed once and reused across calculations
    /// (parsing panics here on the first access if a constant is malformed).
    static REDUCTIONS_BY_NODE_PROVIDER: BTreeMap<PrincipalId, Vec<ReductionWindow>> =
        parse_reward_reductions(REWARD_REDUCTIONS);
}

/// Turns the `REWARD_REDUCTIONS` constants into a per-node-provider lookup table, panicking on a
/// malformed constant. A provider appearing in several rounds gets one window per round.
fn parse_reward_reductions(
    reductions: &[RewardReduction],
) -> BTreeMap<PrincipalId, Vec<ReductionWindow>> {
    let to_date = |(y, m, d): (i32, u32, u32)| {
        NaiveDate::from_ymd_opt(y, m, d).expect("invalid reward reduction date constant")
    };

    let mut by_provider: BTreeMap<PrincipalId, Vec<ReductionWindow>> = BTreeMap::new();
    for reduction in reductions {
        let (start, end) = (to_date(reduction.start), to_date(reduction.end));
        assert!(start < end, "empty reward reduction window: {start}..{end}");

        let (mantissa, scale) = reduction.multiplier;
        let multiplier = Decimal::new(mantissa, scale);
        assert!(
            multiplier > Decimal::ZERO && multiplier < Decimal::ONE,
            "reward reduction multiplier must be in (0, 1): {multiplier}"
        );

        for provider in reduction.providers {
            let provider_id =
                PrincipalId::from_str(provider).expect("invalid principal in REWARD_REDUCTIONS");
            by_provider
                .entry(provider_id)
                .or_default()
                .push((start, end, multiplier));
        }
    }
    by_provider
}

/// The multiplier to apply on `date`, given all of a provider's reduction windows: the smallest
/// multiplier among the windows containing `date`, or `None` if none of them does.
///
/// Overlapping reductions deliberately do not compound; see the design notes above.
fn effective_multiplier(windows: &[ReductionWindow], date: &NaiveDate) -> Option<Decimal> {
    windows
        .iter()
        .filter(|(start, end, _)| date >= start && date < end)
        .map(|(_, _, multiplier)| *multiplier)
        .min()
}

/// Applies the temporary node provider reward reductions to `results` for `date`.
fn apply_node_provider_reward_reduction(results: &mut DailyResults, date: &NaiveDate) {
    REDUCTIONS_BY_NODE_PROVIDER.with(|reductions| {
        reduce_provider_results(&mut results.provider_results, date, reductions);
    });
}

/// Pure implementation of the reward reduction, split out for testing.
///
/// For each affected node provider, this scales every node's adjusted rewards (which already
/// include the performance multiplier) by the multiplier effective on `date`, then recomputes the
/// provider total from the scaled node values so that the per-node breakdown stays consistent with
/// the total. Base rewards are left untouched.
fn reduce_provider_results(
    provider_results: &mut BTreeMap<PrincipalId, DailyNodeProviderRewards>,
    date: &NaiveDate,
    reductions_by_provider: &BTreeMap<PrincipalId, Vec<ReductionWindow>>,
) {
    for (provider_id, windows) in reductions_by_provider {
        let Some(multiplier) = effective_multiplier(windows, date) else {
            continue;
        };
        let Some(provider_rewards) = provider_results.get_mut(provider_id) else {
            continue;
        };

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
    use std::collections::BTreeSet;

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

    /// Applies a single 0.5 reduction over 2026-07-15..2026-10-15 to `reduced`.
    fn reduce(
        results: &mut BTreeMap<PrincipalId, DailyNodeProviderRewards>,
        on: NaiveDate,
        reduced: &[PrincipalId],
    ) {
        let windows = vec![(d(2026, 7, 15), d(2026, 10, 15), Decimal::new(5, 1))];
        let by_provider = reduced.iter().map(|p| (*p, windows.clone())).collect();
        reduce_provider_results(results, &on, &by_provider);
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
    fn overlapping_reductions_do_not_compound() {
        let affected = PrincipalId::new_node_test_id(1);
        let windows = vec![
            (d(2026, 7, 15), d(2026, 10, 15), Decimal::new(5, 1)), // 0.5
            (d(2026, 8, 1), d(2026, 11, 1), Decimal::new(5, 1)),   // 0.5
        ];
        let by_provider = BTreeMap::from([(affected, windows)]);

        // A day covered by both windows: still 0.5, not 0.25.
        let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
        reduce_provider_results(&mut results, &d(2026, 9, 1), &by_provider);
        assert_eq!(results[&affected].total_adjusted_rewards_xdr_permyriad, 50);

        // The union of the two windows is reduced, with no gap and nothing outside it.
        for (day, expected) in [
            (d(2026, 7, 14), 100), // before both
            (d(2026, 7, 15), 50),  // first window only
            (d(2026, 7, 31), 50),  // first window only
            (d(2026, 8, 1), 50),   // both
            (d(2026, 10, 14), 50), // both
            (d(2026, 10, 15), 50), // second window only (first has ended)
            (d(2026, 10, 31), 50), // second window only
            (d(2026, 11, 1), 100), // after both
        ] {
            let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
            reduce_provider_results(&mut results, &day, &by_provider);
            assert_eq!(
                results[&affected].total_adjusted_rewards_xdr_permyriad, expected,
                "unexpected reward on {day}"
            );
        }
    }

    #[test]
    fn smallest_multiplier_wins_when_windows_overlap() {
        let affected = PrincipalId::new_node_test_id(1);
        let windows = vec![
            (d(2026, 7, 15), d(2026, 10, 15), Decimal::new(5, 1)), // 0.5
            (d(2026, 8, 1), d(2026, 11, 1), Decimal::new(25, 2)),  // 0.25
        ];

        // 0.25 on the overlap (not 0.125, which is what compounding would give), and the
        // surrounding days keep their own round's multiplier.
        for (day, expected) in [
            (d(2026, 7, 20), 50),
            (d(2026, 9, 1), 25),
            (d(2026, 10, 20), 25),
        ] {
            let mut results = BTreeMap::from([(affected, provider_rewards(&[100]))]);
            reduce_provider_results(
                &mut results,
                &day,
                &BTreeMap::from([(affected, windows.clone())]),
            );
            assert_eq!(
                results[&affected].total_adjusted_rewards_xdr_permyriad, expected,
                "unexpected reward on {day}"
            );
        }
    }

    // ------------------------------------------------------------------------------------------
    // Tests against the real, compiled-in `REWARD_REDUCTIONS` table.
    // ------------------------------------------------------------------------------------------

    /// In both rounds: reduced continuously from 2026-07-15 to 2026-11-01.
    const CONTINUING_PROVIDER: &str =
        "hzqcb-iiagd-4erjo-qn7rq-syqro-zztl6-cpble-atnkd-2c6bg-bxjoa-qae"; // Zondax AG
    /// First round only: recovered, so rewarded in full again from 2026-10-15.
    const RECOVERED_PROVIDER: &str =
        "eipr5-izbom-neyqh-s3ec2-52eww-cyfpg-qfomg-3dpwj-4pffh-34xcu-7qe"; // 87m Neuron
    /// Second round only: newly added, reduced from 2026-08-01 to 2026-11-01.
    const NEWLY_ADDED_PROVIDER: &str =
        "kos24-5xact-6aror-uofg2-tnvt6-dq3bk-c2c5z-jtptt-jbqvc-lmegy-qae"; // Anonstake

    fn real_multiplier_on(provider: &str, date: NaiveDate) -> Option<Decimal> {
        let by_provider = parse_reward_reductions(REWARD_REDUCTIONS);
        let provider_id = PrincipalId::from_str(provider).unwrap();
        by_provider
            .get(&provider_id)
            .and_then(|windows| effective_multiplier(windows, &date))
    }

    #[test]
    fn all_reward_reduction_constants_are_valid() {
        // Fails fast in CI when a constant is malformed, rather than only panicking on the first
        // access of the thread_local initializer. The assertions on windows and multipliers live
        // in `parse_reward_reductions` itself.
        parse_reward_reductions(REWARD_REDUCTIONS);
    }

    #[test]
    fn continuing_provider_is_reduced_across_both_windows() {
        let half = Some(Decimal::new(5, 1));
        for day in [
            d(2026, 7, 15),
            d(2026, 7, 31),
            d(2026, 8, 1),
            d(2026, 10, 14),
            d(2026, 10, 15),
            d(2026, 10, 31),
        ] {
            assert_eq!(
                real_multiplier_on(CONTINUING_PROVIDER, day),
                half,
                "expected a 0.5 reduction on {day}"
            );
        }
        assert_eq!(
            real_multiplier_on(CONTINUING_PROVIDER, d(2026, 7, 14)),
            None
        );
        assert_eq!(
            real_multiplier_on(CONTINUING_PROVIDER, d(2026, 11, 1)),
            None
        );
    }

    #[test]
    fn recovered_provider_is_rewarded_in_full_from_mid_october() {
        let half = Some(Decimal::new(5, 1));
        assert_eq!(real_multiplier_on(RECOVERED_PROVIDER, d(2026, 8, 1)), half);
        assert_eq!(
            real_multiplier_on(RECOVERED_PROVIDER, d(2026, 10, 14)),
            half
        );

        // Not in the second round, so the reduction ends with the first round's window.
        assert_eq!(
            real_multiplier_on(RECOVERED_PROVIDER, d(2026, 10, 15)),
            None
        );
        assert_eq!(
            real_multiplier_on(RECOVERED_PROVIDER, d(2026, 10, 31)),
            None
        );
    }

    #[test]
    fn newly_added_provider_is_reduced_only_in_the_second_window() {
        let half = Some(Decimal::new(5, 1));
        assert_eq!(
            real_multiplier_on(NEWLY_ADDED_PROVIDER, d(2026, 7, 31)),
            None
        );
        assert_eq!(
            real_multiplier_on(NEWLY_ADDED_PROVIDER, d(2026, 8, 1)),
            half
        );
        assert_eq!(
            real_multiplier_on(NEWLY_ADDED_PROVIDER, d(2026, 10, 31)),
            half
        );
        assert_eq!(
            real_multiplier_on(NEWLY_ADDED_PROVIDER, d(2026, 11, 1)),
            None
        );
    }

    #[test]
    fn reward_reduction_round_membership_is_as_intended() {
        let by_provider = parse_reward_reductions(REWARD_REDUCTIONS);

        // 19 providers in the first round, 18 in the second, 13 in both.
        assert_eq!(REWARD_REDUCTIONS.len(), 2);
        assert_eq!(REWARD_REDUCTIONS[0].providers.len(), 19);
        assert_eq!(REWARD_REDUCTIONS[1].providers.len(), 18);
        let in_both = by_provider.values().filter(|w| w.len() == 2).count();
        assert_eq!(in_both, 13);
        assert_eq!(by_provider.len(), 19 + 18 - 13);

        // No round lists a provider twice.
        for reduction in REWARD_REDUCTIONS {
            let unique: BTreeSet<_> = reduction.providers.iter().collect();
            assert_eq!(
                unique.len(),
                reduction.providers.len(),
                "duplicate provider in a reward reduction round"
            );
        }
    }
}
