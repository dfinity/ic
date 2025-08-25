use crate::types::{Region, RewardPeriod, RewardPeriodError, UnixTsNanos, NANOS_PER_DAY};
use chrono::{DateTime, NaiveDate};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Display;

pub type XDRPermyriad = Decimal;
pub type Percent = Decimal;

#[derive(Clone, Debug, PartialEq, Hash, PartialOrd, Ord, Eq, Copy)]
pub struct DayUtc(UnixTsNanos);

impl From<UnixTsNanos> for DayUtc {
    fn from(value: UnixTsNanos) -> Self {
        let day_end = ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1;
        Self(day_end)
    }
}

impl Serialize for DayUtc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for DayUtc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let date = NaiveDate::parse_from_str(&s, "%d-%m-%Y").map_err(serde::de::Error::custom)?;
        let unix_days = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| serde::de::Error::custom("Invalid time"))?
            .and_utc()
            .timestamp_nanos_opt()
            .unwrap();

        Ok(DayUtc::from(unix_days as u64))
    }
}

impl Default for DayUtc {
    fn default() -> Self {
        DayUtc::from(0)
    }
}

impl Display for DayUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dd_mm_yyyy = DateTime::from_timestamp_nanos(self.unix_ts_at_day_end() as i64)
            .naive_utc()
            .format("%d-%m-%Y")
            .to_string();

        write!(f, "{}", dd_mm_yyyy)
    }
}

impl DayUtc {
    pub fn unix_ts_at_day_end(&self) -> UnixTsNanos {
        self.0
    }

    pub fn get(&self) -> UnixTsNanos {
        self.0
    }

    pub fn unix_ts_at_day_start(&self) -> UnixTsNanos {
        (self.0 / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn next_day(&self) -> DayUtc {
        DayUtc(self.0 + NANOS_PER_DAY)
    }

    pub fn previous_day(&self) -> DayUtc {
        let ts_previous_day = self.0.checked_sub(NANOS_PER_DAY).unwrap_or_default();
        DayUtc(ts_previous_day)
    }

    pub fn days_until(&self, other: &DayUtc) -> Result<Vec<DayUtc>, String> {
        if self > other {
            return Err(format!(
                "Cannot compute days_until: {} > {}",
                self.0, other.0
            ));
        }

        let num_days = (other.0 - self.0) / NANOS_PER_DAY;
        let days_until = (0..=num_days)
            .map(|i| DayUtc(self.0 + i * NANOS_PER_DAY))
            .collect();

        Ok(days_until)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum NodeStatus {
    Assigned { node_metrics: NodeMetricsDaily },
    Unassigned { extrapolated_fr: Percent },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DailyResults {
    pub day: DayUtc,
    pub node_status: NodeStatus,
    pub performance_multiplier: Percent,
    pub rewards_reduction: Percent,
    pub base_rewards: XDRPermyriad,
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeResults {
    pub node_id: NodeId,
    pub node_reward_type: NodeRewardType,
    pub region: String,
    pub dc_id: String,
    pub daily_results: Vec<DailyResults>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BaseRewards {
    pub node_reward_type: NodeRewardType,
    pub region: Region,
    pub monthly: XDRPermyriad,
    pub daily: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DailyBaseRewardsType3 {
    pub day: DayUtc,
    pub region: Region,
    pub nodes_count: usize,
    pub avg_rewards: XDRPermyriad,
    pub avg_coefficient: Percent,
    pub value: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeProviderRewards {
    pub rewards_total_xdr_permyriad: u64,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<DailyBaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}

pub struct RewardsCalculatorResults {
    pub start_day: DayUtc,
    pub end_day: DayUtc,
    pub subnets_fr: BTreeMap<(DayUtc, SubnetId), Percent>,
    pub provider_results: BTreeMap<PrincipalId, NodeProviderRewards>,
}

#[derive(Debug, PartialEq)]
pub enum RewardCalculatorError {
    RewardPeriodError(RewardPeriodError),
    EmptyMetrics,
    SubnetMetricsOutOfRange {
        subnet_id: SubnetId,
        day: DayUtc,
        reward_period: RewardPeriod,
    },
    DuplicateMetrics(SubnetId, DayUtc),
    ProviderNotFound(PrincipalId),
    NodeNotInRewardables(NodeId),
    RewardableNodeOutOfRange(NodeId),
}

impl From<RewardPeriodError> for RewardCalculatorError {
    fn from(err: RewardPeriodError) -> Self {
        RewardCalculatorError::RewardPeriodError(err)
    }
}

impl std::error::Error for RewardCalculatorError {}

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
