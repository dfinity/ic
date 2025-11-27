use clap::Parser;
use ic_backup::{
    backup_manager::BackupManager,
    cmd::{BackupArgs, SubCommand},
};
use slog::{Drain, o};
use std::{io::stdin, sync::Arc};
use tokio_util::sync::CancellationToken;

// Here is an example config file:
//
// {
//     "push_metrics": true,
//     "backup_instance": "zh1-spm34",
//     "nns_url": "https://smallXYZ.testnet.dfinity.network",
//     "nns_pem": "ic_public_key.pem",
//     "root_dir": "./backup",
//     "excluded_dirs": [
//         "backups",
//         "diverged_checkpoints",
//         "diverged_state_markers",
//         "fs_tmp",
//         "tip",
//         "tmp"
//     ],
//     "ssh_private_key": "/home/my_user/.ssh/id_ed25519_backup",
//     "hot_disk_resource_threshold_percentage": 75,
//     "cold_disk_resource_threshold_percentage": 95,
//     "slack_token": "ABCD1234",
//     "cold_storage": {
//         "cold_storage_dir": "/var/cold_storage",
//         "versions_hot": 2
//     },
//     "subnets": [
//       {
//         "subnet_id": "ziu2q-il6zl-3654z-zcdg2-nbtx3-u2ba3-7yzey-flpky-aam7n-x53ip-uqe",
//         "initial_replica_version": "2f844c50765df0833c075b7340ac5f2dd9d5dc21",
//         "nodes_syncing": 5,
//         "sync_period_secs": 1800,
//         "replay_period_secs": 7200,
//         "thread_id": 0,
//         "disable_cold_storage": false
//       },
//       {
//         "subnet_id": "qwzvq-hye2n-7o7ey-gllix-3bgyy-lfopp-q22hm-oaoez-yqtyi-qz64d-vqe",
//         "initial_replica_version": "2f844c50765df0833c075b7340ac5f2dd9d5dc21",
//         "nodes_syncing": 5,
//         "sync_period_secs": 3600,
//         "replay_period_secs": 7200,
//         "thread_id": 1,
//         "disable_cold_storage": true
//       }
//     ]
// }

#[tokio::main]
async fn main() {
    let args = BackupArgs::parse();
    let level = if args.debug {
        slog::Level::Debug
    } else {
        slog::Level::Info
    };
    let filter_fn = move |record: &slog::Record| record.level().is_at_least(level);

    // initialize a logger
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let filter = slog::Filter::new(drain, filter_fn).fuse();
    let drain = slog_async::Async::new(filter).build().fuse();
    let log = slog::Logger::root(drain, o!());

    match args.subcmd {
        Some(SubCommand::Init) => BackupManager::init(&mut stdin().lock(), log, args.config_file),
        Some(SubCommand::Upgrade) => BackupManager::upgrade(log, args.config_file),
        Some(SubCommand::GetReplicaVersion { subnet_id }) => {
            BackupManager::get_version(log, args.config_file, subnet_id.0)
        }
        _ => {
            // TODO(CON-1548): gracefully stop backup tasks on SIGTERM
            let bm = BackupManager::new(log, args, CancellationToken::new()).await;
            tokio::task::spawn_blocking(|| Arc::new(bm).do_backups())
                .await
                .expect("Backup task failed");
        }
    }
}
