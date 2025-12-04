//! The replay tool is to help recover a broken subnet by replaying past blocks
//! and create a checkpoint of the latest state, which can then be used to
//! create recovery CatchUpPackage. It is also used to replay the artifacts
//! stored as backup, to recover a state at any height.
//!
//! It requires the same replica config file as used on the replica. It will use
//! it to locate the relevant consensus pool, state, etc. according to the
//! config file and starts replaying past finalized block, if any of them have
//! not already been executed.
//!
//! It also supports sub-commands that allows direct modifications to canister
//! state (after all past blocks have been executed). All of them are meant to
//! help recover NNS subnet where the registry canister resides.
//!
//! Use `ic-replay --help` to find out more.

use crate::{
    cmd::{ReplayToolArgs, SubCommand},
    ingress::*,
    player::{Player, ReplayResult},
};
use ic_config::{Config, ConfigSource};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::{registry::subnet::v1::InitialNiDkgTranscriptRecord, types::v1 as pb};
use ic_types::ReplicaVersion;
use prost::Message;
use std::{cell::RefCell, convert::TryFrom, rc::Rc};

mod backup;
pub mod cmd;
pub mod ingress;
mod mocks;
pub mod player;
mod registry_helper;
mod validator;

/// Replays the past blocks and creates a checkpoint of the latest state.
/// # An example of how to set the arguments
/// ```
/// use ic_replay::cmd::ClapSubnetId;
/// use ic_replay::cmd::RestoreFromBackupCmd;
/// use ic_replay::cmd::{ReplayToolArgs, SubCommand};
/// use ic_replay::replay;
/// use std::path::PathBuf;
/// use std::str::FromStr;
///
/// let args = ReplayToolArgs {
///     subnet_id: Some(ClapSubnetId::from_str(
///         "z4uqq-mbj6v-dxsuk-7a4wc-f6vta-cv7qg-25cqh-4jwi3-heaw3-l6b33-uae",
///     )
///     .unwrap()),
///     config: Some(PathBuf::from("/path/to/ic.json5")),
///     canister_caller_id: None,
///     replay_until_height: None,
///     data_root: None,
///     subcmd: Some(SubCommand::RestoreFromBackup(RestoreFromBackupCmd {
///         registry_local_store_path: PathBuf::from("/path/to/ic_registry_local_store"),
///         backup_spool_path: PathBuf::from("/path/to/spool"),
///         replica_version: "8b91ab7c6807a6e842d9e3bb943eadfaf856e082d1094c07852aef09f8cd0c93"
///             .to_string(),
///         start_height: 0,
///     })),
///     skip_prompts: true,
/// };
/// // Once the arguments are set well, the local store and spool directories are populated;
/// // replay function could be called as follows:
/// // replay(args);
/// ```
pub fn replay(args: ReplayToolArgs) -> ReplayResult {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let result: Rc<RefCell<ReplayResult>> = Rc::new(RefCell::new(Ok(Default::default())));
    let res_clone = Rc::clone(&result);
    Config::run_with_temp_config(|default_config| {
        let subcmd = &args.subcmd;

        let source = ConfigSource::File(args.config.unwrap_or_else(|| {
            println!("Config file is required!");
            std::process::exit(1);
        }));
        let mut cfg = Config::load_with_default(&source, default_config).unwrap_or_else(|err| {
            println!("Failed to load config:\n  {err}");
            std::process::exit(1);
        });

        // Override config
        if let Some(path) = args.data_root {
            cfg.registry_client.local_store = path.join("ic_registry_local_store");
            cfg.state_manager = ic_config::state_manager::Config::new(path.join("ic_state"));
            cfg.artifact_pool.consensus_pool_path = path.join("ic_consensus_pool");
        }

        let canister_caller_id = args.canister_caller_id.unwrap_or(GOVERNANCE_CANISTER_ID);
        let subnet_id = args
            .subnet_id
            .unwrap_or_else(|| {
                println!("Subnet is required!");
                std::process::exit(1);
            })
            .0;

        let target_height = args.replay_until_height;
        if let Some(h) = target_height {
            let question = format!("The checkpoint created at height {h} ")
                + "cannot be used for deterministic state computation if it is not a CUP height.\n"
                + "Continue?";
            if !args.skip_prompts && !consent_given(&question) {
                return;
            }
        }

        if let Some(SubCommand::RestoreFromBackup(cmd)) = subcmd {
            let _enter_guard = rt.enter();

            let mut player = Player::new_for_backup(
                cfg,
                ReplicaVersion::try_from(cmd.replica_version.as_str())
                    .expect("Couldn't parse the replica version"),
                &cmd.backup_spool_path,
                &cmd.registry_local_store_path,
                subnet_id,
                cmd.start_height,
            )
            .with_replay_target_height(target_height);
            *res_clone.borrow_mut() = player.restore_from_backup(cmd.start_height + 1);
            return;
        }

        {
            let _enter_guard = rt.enter();
            let player = Player::new(cfg, subnet_id).with_replay_target_height(target_height);

            if let Some(SubCommand::GetRecoveryCup(cmd)) = subcmd {
                cmd_get_recovery_cup(&player, cmd).unwrap();
                return;
            }

            let extra = move |player: &Player, time| -> Vec<IngressWithPrinter> {
                let agent = &agent_with_principal_as_sender(&canister_caller_id.get()).unwrap();
                match subcmd {
                    Some(SubCommand::UpgradeSubnetToReplicaVersion(cmd)) => {
                        cmd_upgrade_subnet_to_replica_version(agent, player, cmd, time)
                            .unwrap()
                            .into_iter()
                            .map(|ingress| ingress.into())
                            .collect()
                    }
                    Some(SubCommand::AddRegistryContent(cmd)) => {
                        cmd_add_registry_content(agent, cmd, player.subnet_id, time)
                            .unwrap()
                            .into_iter()
                            .map(|ingress| ingress.into())
                            .collect()
                    }
                    Some(SubCommand::RemoveSubnetNodes) => {
                        if let Some(msg) = cmd_remove_subnet(agent, player, time).unwrap() {
                            vec![msg]
                                .into_iter()
                                .map(|ingress| ingress.into())
                                .collect()
                        } else {
                            Vec::new()
                        }
                    }
                    Some(SubCommand::WithNeuronForTests(cmd)) => cmd_add_neuron(time, cmd).unwrap(),
                    Some(SubCommand::WithLedgerAccountForTests(cmd)) => {
                        cmd_add_ledger_account(time, cmd)
                            .unwrap()
                            .into_iter()
                            .map(|ingress| ingress.into())
                            .collect()
                    }
                    Some(SubCommand::WithTrustedNeuronsFollowingNeuronForTests(cmd)) => {
                        cmd_make_trusted_neurons_follow_neuron(time, cmd)
                            .unwrap()
                            .into_iter()
                            // .map(|ingress| ingress.into())
                            .collect()
                    }
                    _ => Vec::new(),
                }
            };

            *res_clone.borrow_mut() = match player.replay(extra) {
                Ok(state_params) => {
                    if let Some(SubCommand::UpdateRegistryLocalStore) = subcmd {
                        player.update_registry_local_store();
                        Ok(player.get_latest_state_params(None, Vec::new()))
                    } else {
                        Ok(state_params)
                    }
                }
                err => err,
            }
        }
    });

    result.borrow().clone()
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes.
pub fn consent_given(question: &str) -> bool {
    use std::io::{Write, stdin, stdout};
    println!("{question} [Y/n] ");
    let _ = stdout().flush();
    let mut s = String::new();
    stdin().read_line(&mut s).expect("Couldn't read user input");
    matches!(s.as_str(), "\n" | "y\n" | "Y\n")
}

// Creates a recovery CUP by using the latest CUP and overriding the height and
// the state hash, intended to be used in NNS recovery on same nodes.
fn cmd_get_recovery_cup(
    player: &crate::player::Player,
    cmd: &crate::cmd::GetRecoveryCupCmd,
) -> Result<(), String> {
    use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
    use ic_types::{consensus::HasHeight, crypto::threshold_sig::ni_dkg::NiDkgTag};

    let context_time = ic_types::time::current_time();
    let time = context_time + std::time::Duration::from_secs(60);
    let state_hash = hex::decode(&cmd.state_hash).map_err(|err| format!("{err}"))?;
    let cup = player.get_highest_catch_up_package();
    let payload = cup.content.block.as_ref().payload.as_ref();
    let summary = payload.as_summary();
    let low_threshold_transcript = summary
        .dkg
        .current_transcript(&NiDkgTag::LowThreshold)
        .expect("No current low threshold transcript available")
        .clone();
    let high_threshold_transcript = summary
        .dkg
        .current_transcript(&NiDkgTag::HighThreshold)
        .expect("No current high threshold transcript available")
        .clone();
    let initial_ni_dkg_transcript_low_threshold =
        Some(InitialNiDkgTranscriptRecord::from(low_threshold_transcript));
    let initial_ni_dkg_transcript_high_threshold = Some(InitialNiDkgTranscriptRecord::from(
        high_threshold_transcript,
    ));
    let registry_version = player.get_latest_registry_version(context_time)?;
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_low_threshold,
        initial_ni_dkg_transcript_high_threshold,
        height: cmd.height,
        time: time.as_nanos_since_unix_epoch(),
        state_hash,
        registry_store_uri: None,
        ecdsa_initializations: vec![],
        chain_key_initializations: vec![],
    };

    let cup = ic_consensus_cup_utils::make_registry_cup_from_cup_contents(
        &*player.registry,
        player.subnet_id,
        cup_contents,
        registry_version,
        &player.log,
    )
    .ok_or_else(|| "couldn't create a registry CUP".to_string())?;

    println!(
        "height: {}, time: {}, state_hash: {:?}",
        cup.height(),
        cup.content.block.as_ref().context.time,
        cup.content.state_hash
    );

    let mut file =
        std::fs::File::create(&cmd.output_file).expect("Failed to open output file for write");
    let mut bytes = Vec::<u8>::new();
    let cup_proto = pb::CatchUpPackage::from(cup);
    cup_proto
        .encode(&mut bytes)
        .expect("Failed to encode protobuf");
    use std::io::Write;
    file.write_all(&bytes)
        .expect("Failed to write to output file");
    Ok(())
}
