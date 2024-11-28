use ic_base_types::PrincipalId;
use itertools::Itertools;
use rust_decimal::{prelude::Zero, Decimal};
use std::fmt;

#[derive(Clone)]
pub enum Operation {
    Sum(Vec<Decimal>),
    Avg(Vec<Decimal>),
    Subtract(Decimal, Decimal),
    Multiply(Decimal, Decimal),
    Divide(Decimal, Decimal),
    Set(Decimal),
    SumOps(Vec<Operation>),
}

impl Operation {
    fn sum(operators: &[Decimal]) -> Decimal {
        operators.iter().fold(Decimal::zero(), |acc, val| acc + val)
    }

    fn format_values<T: fmt::Display>(items: &[T], prefix: &str) -> String {
        if items.is_empty() {
            "0".to_string()
        } else {
            format!(
                "{}({})",
                prefix,
                items.iter().map(|item| format!("{}", item)).join(","),
            )
        }
    }

    fn execute(&self) -> Decimal {
        match self {
            Operation::Sum(operators) => Self::sum(operators),
            Operation::Avg(operators) => {
                Self::sum(operators) / Decimal::from(operators.len().max(1))
            }
            Operation::Subtract(o1, o2) => o1 - o2,
            Operation::Divide(o1, o2) => o1 / o2,
            Operation::Multiply(o1, o2) => o1 * o2,
            Operation::Set(o1) => *o1,
            Operation::SumOps(operations) => Self::sum(
                &operations
                    .iter()
                    .map(|operation| operation.execute())
                    .collect_vec(),
            ),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (symbol, o1, o2) = match self {
            Operation::Sum(values) => {
                return write!(f, "{}", Operation::format_values(values, "sum"))
            }
            Operation::SumOps(operations) => {
                return write!(f, "{}", Operation::format_values(operations, "sum"))
            }
            Operation::Avg(values) => {
                return write!(f, "{}", Operation::format_values(values, "avg"))
            }
            Operation::Subtract(o1, o2) => ("-", o1, o2),
            Operation::Divide(o1, o2) => ("/", o1, o2),
            Operation::Multiply(o1, o2) => ("*", o1, o2),
            Operation::Set(o1) => return write!(f, "set {}", o1),
        };
        write!(f, "{} {} {}", o1.round_dp(4), symbol, o2.round_dp(4))
    }
}

pub enum LogEntry {
    RewardsForNodeProvider(PrincipalId, u32),
    RewardMultiplierForNode(PrincipalId, Decimal),
    RewardsXDRTotal(Decimal),
    Execute {
        reason: String,
        operation: Operation,
        result: Decimal,
    },
    PerformanceBasedRewardables {
        node_type: String,
        region: String,
        count: usize,
        assigned_multipliers: Vec<Decimal>,
        unassigned_multipliers: Vec<Decimal>,
    },
    RateNotFoundInRewardTable {
        node_type: String,
        region: String,
    },
    RewardTableEntry {
        node_type: String,
        region: String,
        coeff: Decimal,
        base_rewards: Decimal,
    },
    AvgType3Rewards {
        region: String,
        rewards_avg: Decimal,
        coefficients_avg: Decimal,
        region_rewards_avg: Decimal,
    },
    UnassignedMultiplier(Decimal),
    NodeCountRewardables {
        node_type: String,
        region: String,
        count: usize,
    },
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogEntry::Execute {
                reason,
                operation,
                result,
            } => {
                write!(
                    f,
                    "ExecuteOperation | reason={}, operation={}, result={}",
                    reason,
                    operation,
                    result.round_dp(2)
                )
            }
            LogEntry::RewardsForNodeProvider(principal, node_count) => {
                write!(
                    f,
                    "Node Provider: {} rewardable nodes in period: {}",
                    principal, node_count
                )
            }
            LogEntry::RewardMultiplierForNode(principal, multiplier) => {
                write!(
                    f,
                    "Rewards Multiplier for node: {} is {}",
                    principal,
                    multiplier.round_dp(2)
                )
            }
            LogEntry::RewardsXDRTotal(rewards_xdr_total) => {
                write!(
                    f,
                    "Total rewards XDR permyriad: {}",
                    rewards_xdr_total.round_dp(2)
                )
            }
            LogEntry::RateNotFoundInRewardTable { node_type, region } => {
                write!(
                    f,
                    "RateNotFoundInRewardTable | node_type={}, region={}",
                    node_type, region
                )
            }
            LogEntry::RewardTableEntry {
                node_type,
                region,
                coeff,
                base_rewards,
            } => {
                write!(
                    f,
                    "RewardTableEntry | node_type={}, region={}, coeff={}, base_rewards={}",
                    node_type, region, coeff, base_rewards
                )
            }
            LogEntry::PerformanceBasedRewardables {
                node_type,
                region,
                count,
                assigned_multipliers: assigned_multiplier,
                unassigned_multipliers: unassigned_multiplier,
            } => {
                write!(
                    f,
                    "Region {} with type: {} | Rewardable Nodes: {} Assigned Multipliers: {:?} Unassigned Multipliers: {:?}",
                    region,
                    node_type,
                    count,
                    assigned_multiplier.iter().map(|dec| dec.round_dp(2)).collect_vec(),
                    unassigned_multiplier.iter().map(|dec| dec.round_dp(2)).collect_vec()
                )
            }
            LogEntry::AvgType3Rewards {
                region,
                rewards_avg,
                coefficients_avg,
                region_rewards_avg,
            } => {
                write!(
                    f,
                    "Avg. rewards for nodes with type: type3* in region: {} is {}\nRegion rewards average: {}\nReduction coefficient average:{}",
                    region,
                    rewards_avg.round_dp(2),
                    region_rewards_avg,
                    coefficients_avg
                )
            }
            LogEntry::UnassignedMultiplier(unassigned_multiplier) => {
                write!(
                    f,
                    "Unassigned Nodes Multiplier: {}",
                    unassigned_multiplier.round_dp(2)
                )
            }
            LogEntry::NodeCountRewardables {
                node_type,
                region,
                count,
            } => {
                write!(
                    f,
                    "Region {} with type: {} | Rewardable Nodes: {} Rewarded independently of their performance",
                    region, node_type, count
                )
            }
        }
    }
}

#[derive(Copy, Clone)]
pub enum LogLevel {
    Info,
    Debug,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

#[derive(Default)]
pub struct RewardsLog {
    entries: Vec<(LogLevel, LogEntry)>,
}

impl RewardsLog {
    pub fn add_entry(&mut self, entry: LogEntry) {
        self.entries.push((LogLevel::Info, entry));
    }

    pub fn execute(&mut self, reason: &str, operation: Operation) -> Decimal {
        let result = operation.execute();
        let entry = LogEntry::Execute {
            reason: reason.to_string(),
            operation,
            result,
        };
        self.entries.push((LogLevel::Debug, entry));
        result
    }

    pub fn get_log(&self, level: LogLevel) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(
                move |(entry_log_level, entry)| match (level, entry_log_level) {
                    (LogLevel::Info, LogLevel::Debug) => None,
                    _ => Some(format!("{}: {} ", level, entry)),
                },
            )
            .collect_vec()
    }
}
