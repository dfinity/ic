use crate::retention_policy::RetentionRule;
use clap::Parser;
use ic_types::{PrincipalId, SubnetId};
use std::path::PathBuf;

#[derive(Clone)]
pub struct ClapSubnetId(pub SubnetId);

impl std::str::FromStr for ClapSubnetId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrincipalId::from_str(s)
            .map_err(|e| format!("Unable to parse subnet_id {e:?}"))
            .map(SubnetId::from)
            .map(ClapSubnetId)
    }
}

#[derive(Parser)]
pub struct BackupArgs {
    /// Path to the config file
    #[clap(long)]
    pub config_file: PathBuf,

    /// Increase the log verbosity level to DEBUG
    #[clap(long)]
    pub debug: bool,

    /// Command to execute if given, default is to do backup
    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,
}

#[derive(Parser)]
pub enum SubCommand {
    /// Run the backup process (default command, can be omitted)
    Backup,
    /// Initialize the backup config file
    Init,
    /// Upgrade the backup config file
    Upgrade,
    /// Get current replica version of a subnet
    GetReplicaVersion {
        /// The ID of the target subnet
        subnet_id: ClapSubnetId,
    },
    /// Print which cold stored states of a subnet a retention policy would delete, without
    /// deleting anything
    SimulateRetentionPolicy {
        /// The ID of the target subnet
        subnet_id: ClapSubnetId,
        /// A rule of the retention policy to simulate: keep one state every PERIOD_DAYS days,
        /// until they are older than TIME_TO_LIVE_DAYS days. Can be repeated.
        #[clap(
            long = "rule",
            value_name = "PERIOD_DAYS:TIME_TO_LIVE_DAYS",
            required = true
        )]
        rules: Vec<RetentionRule>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simulate_retention_policy_test() {
        let args = BackupArgs::try_parse_from([
            "ic-backup",
            "--config-file",
            "config.json",
            "simulate-retention-policy",
            "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe",
            "--rule",
            "1:30",
            "--rule",
            "16:182",
        ])
        .unwrap();

        let Some(SubCommand::SimulateRetentionPolicy { rules, .. }) = args.subcmd else {
            panic!("Expected the simulate-retention-policy subcommand");
        };
        assert_eq!(
            rules,
            vec![
                RetentionRule {
                    period_days: 1,
                    time_to_live_days: 30,
                },
                RetentionRule {
                    period_days: 16,
                    time_to_live_days: 182,
                },
            ]
        );
    }
}
