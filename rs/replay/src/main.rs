//! The main function of ic-replay processes command line arguments.
use clap::Clap;
use ic_canister_client::{Agent, Sender};
use ic_config::{Config, ConfigSource};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_replay::cmd::{CliArgs, SubCommand};
use ic_replay::ingress::*;
use ic_replay::Player;
use ic_types::ReplicaVersion;
use std::convert::TryFrom;

fn main() {
    let args: CliArgs = CliArgs::parse();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    Config::run_with_temp_config(|default_config| {
        let source = ConfigSource::File(args.config);
        let cfg = Config::load_with_default(&source, default_config).unwrap_or_else(|err| {
            println!("Failed to load config:\n  {}", err);
            std::process::exit(1);
        });

        let canister_caller_id = args.canister_caller_id.unwrap_or(GOVERNANCE_CANISTER_ID);
        let subnet_id = args.subnet_id.0;

        let subcmd = &args.subcmd;
        let target_height = args.replay_until_height;

        if let Some(SubCommand::RestoreFromBackup(cmd)) = subcmd {
            rt.block_on(async {
                let mut player = Player::new_for_backup(
                    cfg,
                    ReplicaVersion::try_from(cmd.replica_version.as_str())
                        .expect("Couldn't parse the replica version"),
                    &cmd.backup_spool_path,
                    &cmd.registry_local_store_path,
                    subnet_id,
                    cmd.start_height,
                    cmd.persist_cup_heights_only,
                )
                .await
                .with_replay_target_height(target_height);
                player.restore(cmd.start_height + 1);
            });
            return;
        }
        let extra = move |player: &Player, time| {
            // Use a dummy URL here because we don't send any outgoing ingress.
            // The agent is only used to construct ingress messages.
            let agent = &Agent::new(
                url::Url::parse("http://localhost").unwrap(),
                Sender::PrincipalId(canister_caller_id.into()),
            );
            match subcmd {
                Some(SubCommand::SetRecoveryCup(cmd)) => {
                    vec![cmd_set_recovery_cup(agent, player, cmd, time).unwrap()]
                }
                Some(SubCommand::AddAndBlessReplicaVersion(cmd)) => {
                    cmd_add_and_bless_replica_version(agent, player, cmd, time).unwrap()
                }
                Some(SubCommand::AddRegistryContent(cmd)) => {
                    cmd_add_registry_content(agent, cmd, player.subnet_id, time).unwrap()
                }
                Some(SubCommand::RemoveSubnetNodes) => {
                    if let Some(msg) = cmd_remove_subnet(agent, player, time).unwrap() {
                        vec![msg]
                    } else {
                        Vec::new()
                    }
                }
                Some(SubCommand::WithNeuronForTests(cmd)) => cmd_add_neuron(time, cmd).unwrap(),
                Some(SubCommand::WithLedgerAccountForTests(cmd)) => {
                    cmd_add_ledger_account(time, cmd).unwrap()
                }
                Some(SubCommand::WithTrustedNeuronsFollowingNeuronForTests(cmd)) => {
                    cmd_make_trusted_neurons_follow_neuron(time, cmd).unwrap()
                }
                _ => Vec::new(),
            }
        };
        rt.block_on(async move {
            let player = match (subcmd.as_ref(), target_height) {
                (Some(_), Some(_)) => {
                    eprintln!("Target height cannot be used with any sub-command in disaster-recovery mode.");
                    return;
                },
                (_, target_height) => {
                    Player::new(cfg, subnet_id).await.with_replay_target_height(target_height)
                },
            };
            player.replay(extra);
            if let Some(SubCommand::UpdateRegistryLocalStore) = subcmd {
                player.update_registry_local_store()
            }
        })
    })
}
