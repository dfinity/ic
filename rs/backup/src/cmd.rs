use clap::Parser;
use ic_types::SubnetId;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct BackupArgs {
    /// Main backup directory
    #[clap(long)]
    pub data_root: PathBuf,

    /// NNS controlling the subnet
    #[clap(long)]
    pub nns_url: String,

    /// Subnet id of the replica, whose state we backup
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Version of the replica runing in the subnet
    #[clap(long)]
    pub replica_version: String, // TODO: remove it

    /// Are we running against a testnet?
    #[clap(long)]
    pub testnet: bool,
}
