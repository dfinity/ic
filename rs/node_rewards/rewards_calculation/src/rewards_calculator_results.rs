use crate::types::{RewardPeriod, RewardPeriodError, UnixTsNanos, NANOS_PER_DAY};
use chrono::DateTime;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub type XDRPermyriad = Decimal;
pub type Percent = Decimal;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    Eq,
    Copy,
    candid::CandidType,
    candid::Deserialize,
)]
pub struct DayUTC(UnixTsNanos);

impl From<UnixTsNanos> for DayUTC {
    fn from(value: UnixTsNanos) -> Self {
        let day_end = ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1;
        Self(day_end)
    }
}

impl Default for DayUTC {
    fn default() -> Self {
        DayUTC::from(0)
    }
}

impl Display for DayUTC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dd_mm_yyyy = DateTime::from_timestamp_nanos(self.unix_ts_at_day_end() as i64)
            .naive_utc()
            .format("%d-%m-%Y")
            .to_string();

        write!(f, "{}", dd_mm_yyyy)
    }
}

impl DayUTC {
    pub fn unix_ts_at_day_end(&self) -> UnixTsNanos {
        self.0
    }

    pub fn get(&self) -> UnixTsNanos {
        self.0
    }

    pub fn unix_ts_at_day_start(&self) -> UnixTsNanos {
        (self.0 / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn next_day(&self) -> DayUTC {
        DayUTC(self.0 + NANOS_PER_DAY)
    }

    pub fn previous_day(&self) -> DayUTC {
        let ts_previous_day = self.0.checked_sub(NANOS_PER_DAY).unwrap_or_default();
        DayUTC(ts_previous_day)
    }

    pub fn days_until(&self, other: &DayUTC) -> Result<Vec<DayUTC>, String> {
        if self > other {
            return Err(format!(
                "Cannot compute days_until: {} > {}",
                self.0, other.0
            ));
        }

        let num_days = (other.0 - self.0) / NANOS_PER_DAY;
        let days_until = (0..=num_days)
            .map(|i| DayUTC(self.0 + i * NANOS_PER_DAY))
            .collect();

        Ok(days_until)
    }
}

#[derive(Clone, PartialEq, Debug, candid::CandidType, candid::Deserialize)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: SubnetId,
    pub subnet_assigned_fr: Percent,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
    /// The failure rate before subnet failure rate reduction.
    /// Calculated as `blocks_failed` / (`blocks_proposed` + `blocks_failed`)
    pub original_fr: Percent,
    /// The failure rate reduced by the subnet assigned failure rate.
    /// Calculated as Max(0, `original_fr` - `subnet_assigned_fr`)
    pub relative_fr: Percent,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub enum NodeStatus {
    Assigned { node_metrics: NodeMetricsDaily },
    Unassigned { extrapolated_fr: Percent },
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct DailyResults {
    pub node_status: NodeStatus,
    pub performance_multiplier: Percent,
    pub rewards_reduction: Percent,
    pub base_rewards: XDRPermyriad,
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeResults {
    pub node_reward_type: String,
    pub region: String,
    pub dc_id: String,
    pub daily_results: BTreeMap<DayUTC, DailyResults>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeProviderResults {
    pub rewards_total: XDRPermyriad,
    pub computation_log: String,
    pub results_by_node: BTreeMap<NodeId, NodeResults>,
}

pub struct RewardsCalculatorResults {
    pub subnets_fr: BTreeMap<(DayUTC, SubnetId), Percent>,
    pub provider_results: BTreeMap<PrincipalId, NodeProviderResults>,
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
                    subnet_id, day.0, reward_period
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
