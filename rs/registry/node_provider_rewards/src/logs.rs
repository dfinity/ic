use ic_base_types::PrincipalId;
use std::fmt::Write;

pub type RegionNodeTypeCategory = (String, String);

pub enum LogEntry {
    RateNotFoundInRewardTable {
        region: String,
        node_type: String,
        node_operator_id: PrincipalId,
    },
    NodeRewards {
        node_type: String,
        node_idx: u32,
        dc_id: String,
        rewardable_count: u32,
        rewards_xdr_permyriad: u64,
    },
    DCRewards {
        dc_id: String,
        node_type: String,
        rewardable_count: u32,
        rewards_xdr_permyriad: u64,
    },
}

impl std::fmt::Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogEntry::RateNotFoundInRewardTable {
                region,
                node_type,
                node_operator_id,
            } => {
                write!(
                    f,
                    "The Node Rewards Table does not have an entry for \
                    node type '{}' within region '{}' or parent region, defaulting to 1 xdr per month per node, for Node Operator '{}'",
                    region, node_type, node_operator_id
                )
            }
            LogEntry::NodeRewards {
                node_type,
                node_idx,
                dc_id,
                rewardable_count,
                rewards_xdr_permyriad,
            } => write!(
                f,
                "{}/{} {} node in {} DC: rewarded {}",
                node_idx, rewardable_count, node_type, dc_id, rewards_xdr_permyriad
            ),
            LogEntry::DCRewards {
                dc_id,
                node_type,
                rewardable_count,
                rewards_xdr_permyriad,
            } => write!(
                f,
                "Rewards for all {} {} nodes in {} DC: reward {}",
                rewardable_count, node_type, dc_id, rewards_xdr_permyriad
            ),
        }
    }
}

pub struct RewardsPerNodeProviderLog {
    node_provider_id: PrincipalId,
    entries: Vec<LogEntry>,
}

impl RewardsPerNodeProviderLog {
    pub fn new(node_provider_id: PrincipalId) -> Self {
        RewardsPerNodeProviderLog {
            node_provider_id,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: LogEntry) {
        println!("{}", &entry);
        self.entries.push(entry);
    }

    pub fn display_log(&self) -> String {
        self.entries.iter().fold(String::new(), |mut acc, entry| {
            writeln!(
                acc,
                "Node Provider ID: {} | {}",
                self.node_provider_id, entry
            )
            .unwrap();
            acc
        })
    }
}
