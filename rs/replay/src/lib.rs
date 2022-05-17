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

use crate::cmd::{ReplayToolArgs, SubCommand};
use crate::ingress::*;
use crate::player::{Player, ReplayError, StateParams};

use ic_canister_client::{Agent, Sender};
use ic_config::{Config, ConfigSource};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_types::ReplicaVersion;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::rc::Rc;

mod backup;
pub mod cmd;
pub mod ingress;
pub mod player;

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
///     subnet_id: ClapSubnetId::from_str(
///         "z4uqq-mbj6v-dxsuk-7a4wc-f6vta-cv7qg-25cqh-4jwi3-heaw3-l6b33-uae",
///     )
///     .unwrap(),
///     config: PathBuf::from("/path/to/ic.json5"),
///     canister_caller_id: None,
///     replay_until_height: None,
///     subcmd: Some(SubCommand::RestoreFromBackup(RestoreFromBackupCmd {
///         registry_local_store_path: PathBuf::from("/path/to/ic_registry_local_store"),
///         backup_spool_path: PathBuf::from("/path/to/spool"),
///         replica_version: "8b91ab7c6807a6e842d9e3bb943eadfaf856e082d1094c07852aef09f8cd0c93"
///             .to_string(),
///         start_height: 0,
///     })),
/// };
/// // Once the arguments are set well, the local store and spool directories are populated;
/// // replay function could be called as follows:
/// // replay(args);
/// ```
pub fn replay(args: ReplayToolArgs) -> Result<StateParams, ReplayError> {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let result: Rc<RefCell<Result<StateParams, ReplayError>>> =
        Rc::new(RefCell::new(Ok(Default::default())));
    let res_clone = Rc::clone(&result);
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
        if let Some(h) = target_height {
            let question = format!("The checkpoint created at height {} ", h)
                + "cannot be used for deterministic state computation if it is not a CUP height.\n"
                + "Continue?";
            if !consent_given(&question) {
                return;
            }
        }

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
                )
                .await
                .with_replay_target_height(target_height);
                *res_clone.borrow_mut() = player.restore(cmd.start_height + 1);
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
                    panic!("Target height cannot be used with any sub-command in subnet-recovery mode.");
                },
                (_, target_height) => {
                    Player::new(cfg, subnet_id).await.with_replay_target_height(target_height)
                },
            };
            if let Err(e) = player.replay(extra){
                *res_clone.borrow_mut() = Err(e);
                return;
            };
            if let Some(SubCommand::UpdateRegistryLocalStore) = subcmd {
                player.update_registry_local_store()
            }
            *res_clone.borrow_mut() = player.verified_latest_state();
        })
    });
    let ret = result.borrow().clone();
    ret
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes.
pub fn consent_given(question: &str) -> bool {
    use std::io::{stdin, stdout, Write};
    println!("{} [Y/n] ", question);
    let _ = stdout().flush();
    let mut s = String::new();
    stdin().read_line(&mut s).expect("Couldn't read user input");
    matches!(s.as_str(), "\n" | "y\n" | "Y\n")
}
