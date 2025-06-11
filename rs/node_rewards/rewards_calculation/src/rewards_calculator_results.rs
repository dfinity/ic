use crate::types::{
    DayEnd, NodeType, Region, RewardPeriod, RewardPeriodError, UnixTsNanos, NANOS_PER_DAY,
};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct XDRPermyriad(Decimal);

impl XDRPermyriad {
    pub fn get(&self) -> Decimal {
        self.0
    }
}
impl From<Decimal> for XDRPermyriad {
    fn from(value: Decimal) -> Self {
        XDRPermyriad(value)
    }
}

#[derive(Clone, PartialEq, Debug, Default)]

pub struct Percent(Decimal);

impl Percent {
    pub fn get(&self) -> Decimal {
        self.0
    }
}

impl From<Decimal> for Percent {
    fn from(value: Decimal) -> Self {
        Percent(value)
    }
}

#[derive(Clone, Debug, PartialEq, Hash, PartialOrd, Ord, Eq, Copy, Default)]
pub struct DayUTC(pub DayEnd);

impl DayUTC {
    pub fn unix_ts_at_day_end(&self) -> UnixTsNanos {
        self.0.get()
    }

    pub fn unix_ts_at_day_start(&self) -> UnixTsNanos {
        (self.0.get() / NANOS_PER_DAY) * NANOS_PER_DAY
    }
}
impl From<DayEnd> for DayUTC {
    fn from(value: DayEnd) -> Self {
        Self(value)
    }
}

impl From<UnixTsNanos> for DayUTC {
    fn from(value: UnixTsNanos) -> Self {
        Self(DayEnd::from(value))
    }
}

pub fn days_between(first_day: DayUTC, last_day: DayUTC) -> usize {
    (((last_day.unix_ts_at_day_end() - first_day.unix_ts_at_day_start()) / NANOS_PER_DAY) + 1)
        as usize
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeCategory {
    pub region: String,
    pub node_type: String,
}

#[derive(Clone, PartialEq, Debug)]
pub struct NodeMetricsDaily {
    pub day: DayUTC,
    pub subnet_assigned: SubnetId,
    /// Subnet Assigned Failure Rate.
    ///
    /// The failure rate of the entire subnet.
    /// Calculated as 75th percentile of the failure rate of all nodes in the subnet.
    pub subnet_assigned_fr: Percent,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
    /// Original Failure Rate.
    ///
    /// The failure rate before subnet failure rate reduction.
    /// Calculated as `blocks_failed` / (`blocks_proposed` + `blocks_failed`)
    pub original_fr: Percent,
    /// Relative Failure Rate (`RFR`).
    ///
    /// The failure rate reduced by the subnet assigned failure rate.
    /// Calculated as Max(0, `original_fr` - `subnet_assigned_fr`)
    pub relative_fr: Percent,
}

#[derive(Debug, Default)]
pub struct NodeResults {
    pub region: Region,
    pub node_type: NodeType,
    pub dc_id: String,
    pub rewardable_from: DayUTC,
    pub rewardable_to: DayUTC,
    pub rewardable_days: usize,
    pub daily_metrics: Vec<NodeMetricsDaily>,

    /// Average Relative Failure Rate (`ARFR`).
    ///
    /// Average of `RFR` for the entire reward period.
    /// None if the node is unassigned in the entire reward period
    pub avg_relative_fr: Option<Percent>,

    /// Average Extrapolated Failure Rate (`AEFR`).
    ///
    /// Failure rate average for the entire reward period
    /// - On days when the node is unassigned `ARFR` is used
    /// - On days when the node is assigned `RFR` is used
    pub avg_extrapolated_fr: Percent,

    /// Rewards reduction (`RR`).
    ///
    /// - For nodes with `AEFR` < 0.1, the rewards reduction is 0
    /// - For nodes with `AEFR` > 0.6, the rewards reduction is 0.8
    /// - For nodes with 0.1 <= `AEFR` <= 0.6, the rewards reduction is linearly interpolated between 0 and 0.8
    pub rewards_reduction: Percent,

    /// Performance multiplier (`PM`).
    ///
    /// Calculated as 1 - 'RR'
    pub performance_multiplier: Percent,
    pub base_rewards_per_month: XDRPermyriad,

    /// Base Rewards for the rewards period.
    ///
    /// Calculated as `base_rewards_per_month` / 30.4375 * `rewardable_days`
    pub base_rewards: XDRPermyriad,

    /// Adjusted rewards (`AR`).
    ///
    /// Calculated as base_rewards * `PM`
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(Debug, Default)]
pub struct RewardsCalculatorResults {
    pub results_by_node: BTreeMap<NodeId, NodeResults>,
    // [EFR]
    // Extrapolated failure rate used as replacement for days when the node is unassigned
    pub extrapolated_fr: Percent,
    /// Rewards Total
    /// The total rewards for the entire reward period computed as sum of the `AR`
    pub rewards_total: XDRPermyriad,
}

#[derive(Debug, PartialEq)]
pub enum RewardCalculatorError {
    RewardPeriodError(RewardPeriodError),
    EmptyMetrics,
    SubnetMetricsOutOfRange {
        subnet_id: SubnetId,
        day: DayUTC,
        reward_period: RewardPeriod,
    },
    DuplicateMetrics(SubnetId, DayUTC),
    ProviderNotFound(PrincipalId),
    NodeNotInRewardables(NodeId),
    RewardableNodeOutOfRange(NodeId),
}

impl From<RewardPeriodError> for RewardCalculatorError {
    fn from(err: RewardPeriodError) -> Self {
        RewardCalculatorError::RewardPeriodError(err)
    }
}

impl Error for RewardCalculatorError {}

impl fmt::Display for RewardCalculatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardCalculatorError::EmptyMetrics => {
                write!(f, "No daily_metrics_by_node")
            }
            RewardCalculatorError::SubnetMetricsOutOfRange {
                subnet_id,
                day,
                reward_period,
            } => {
                write!(
                    f,
                    "Node {} has metrics outside the reward period: timestamp: {} not in {}",
                    subnet_id,
                    day.0.get(),
                    reward_period
                )
            }
            RewardCalculatorError::DuplicateMetrics(subnet_id, day) => {
                write!(
                    f,
                    "Subnet {} has multiple metrics for the same node at ts {}",
                    subnet_id,
                    day.unix_ts_at_day_end()
                )
            }
            RewardCalculatorError::RewardPeriodError(err) => {
                write!(f, "Reward period error: {}", err)
            }
            RewardCalculatorError::ProviderNotFound(provider_id) => {
                write!(f, "Node Provider: {} not found", provider_id)
            }
            RewardCalculatorError::NodeNotInRewardables(node_id) => {
                write!(f, "Node: {} has metrics but is not rewardable", node_id)
            }
            RewardCalculatorError::RewardableNodeOutOfRange(node_id) => {
                write!(
                    f,
                    "Node: {} is not rewardable in the reward period",
                    node_id
                )
            }
        }
    }
}
