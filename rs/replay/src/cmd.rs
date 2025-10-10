use clap::{Parser, Subcommand};
use ic_types::{CanisterId, PrincipalId, SubnetId};
use icp_ledger::AccountIdentifier;
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
#[clap(version = "1.0")]
pub struct ReplayToolArgs {
    /// Path to Replica configuration file.
    pub config: Option<PathBuf>,

    /// Caller id that is allowed to mutate the registry canister.
    #[clap(long)]
    pub canister_caller_id: Option<CanisterId>,

    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,

    /// Subnet id of the replica, whose state we use
    #[clap(long)]
    pub subnet_id: Option<ClapSubnetId>,

    /// Data root directory; if not specified, the value from the replica config is used
    #[clap(long)]
    pub data_root: Option<PathBuf>,

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    #[clap(long)]
    /// Whether or not to skip prompts for user input.
    pub skip_prompts: bool,
}

#[derive(Clone, Subcommand)]
pub enum SubCommand {
    /// Add a new version of the replica binary to the registry.
    UpgradeSubnetToReplicaVersion(UpgradeSubnetToReplicaVersionCmd),

    /// Add registry content from external registry store to the registry
    /// canister.
    AddRegistryContent(AddRegistryContentCmd),

    /// Update registry local store with data from the registry canister.
    UpdateRegistryLocalStore,

    /// Remove all nodes from the subnet record that this node belongs to.
    /// Note that this does not remove individual node records.
    RemoveSubnetNodes,

    /// Create a recovery CUP and write it to a file.
    GetRecoveryCup(GetRecoveryCupCmd),

    /// Restore from the backup.
    RestoreFromBackup(RestoreFromBackupCmd),

    /// The replay will add a test Neuron to the Governance canister
    /// and the corresponding account in the ledger.
    WithNeuronForTests(WithNeuronCmd),

    /// The replay will add a test ledger account to the ledger canister.
    /// WARNING: This is a test-only sub-command and should only be used in
    /// tests.
    WithLedgerAccountForTests(WithLedgerAccountCmd),

    /// The replay will add a neuron and make the trusted neurons follow it.
    /// WARNING: This is a test-only sub-command and should only be used in
    /// tests.
    WithTrustedNeuronsFollowingNeuronForTests(WithTrustedNeuronsFollowingNeuronCmd),
}

#[derive(Clone, Parser)]
pub struct GetRecoveryCupCmd {
    /// State hash (in hex).
    pub state_hash: String,
    /// Height of the recovery CUP to create.
    pub height: u64,
    /// Output file
    pub output_file: PathBuf,
}

#[derive(Clone, Parser)]
pub struct UpgradeSubnetToReplicaVersionCmd {
    /// The Replica version ID.
    pub replica_version_id: String,
    /// JSON value of the replica version record.
    pub replica_version_value: String,
    /// If true, the replica version will be added and blessed in the registry
    /// before upgrading the subnet to it.
    #[clap(long)]
    pub add_and_bless_replica_version: bool,
}

#[derive(Clone, Parser)]
pub struct RestoreFromBackupCmd {
    /// Registry local store path
    pub registry_local_store_path: PathBuf,
    /// Backup spool path
    pub backup_spool_path: PathBuf,
    /// The replica version to be restored
    pub replica_version: String,
    /// Height from which the restoration should happen
    pub start_height: u64,
}

#[derive(Clone, Parser)]
pub struct RestoreFromBackup2Cmd {
    /// Registry local store path
    pub registry_local_store_path: PathBuf,
    /// Backup spool path
    pub backup_spool_path: PathBuf,
    /// The replica version to be restored
    pub replica_version: String,
    /// Height from which the restoration should happen
    pub start_height: u64,
}

#[derive(Clone, Parser)]
pub struct AddRegistryContentCmd {
    /// Path to a directory containing one file for each registry version to be
    /// inserted as initial content into the registry.
    pub registry_local_store_dir: PathBuf,

    /// Show details about which mutation keys are inserted.
    #[clap(long)]
    pub verbose: bool,

    /// Only allow mutations of the given key prefixes.
    #[clap(
        long,
        default_value = "crypto_,node_,catch_up_package_,subnet_record_,replica_version_"
    )]
    pub allowed_mutation_key_prefixes: String,
}

#[derive(Clone, Parser)]
pub struct WithLedgerAccountCmd {
    /// The account identifier that should be created with `e8s_to_mint` ICP.
    pub account_identifier: AccountIdentifier,
    /// How many e8s to mint to the account in `account_identifier`.
    pub e8s_to_mint: u64,
}

#[derive(Clone, Parser)]
pub struct WithTrustedNeuronsFollowingNeuronCmd {
    /// The neuron id of the neuron that the trusted neurons should follow.
    pub neuron_id: u64,
    /// The controller of the neuron.
    pub neuron_controller: PrincipalId,
}

#[derive(Clone, Parser)]
pub struct WithNeuronCmd {
    /// The controller of the neuron.
    pub neuron_controller: PrincipalId,
    /// How much stake the neuron will have.
    pub neuron_stake_e8s: u64,
}
