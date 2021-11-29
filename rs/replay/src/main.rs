//! The main function of ic-replay processes command line arguments.
use candid::Encode;
use clap::Clap;
use ic_canister_client::{Agent, Sender};
use ic_config::{Config, ConfigSource};
use ic_crypto_sha::Sha256;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_governance::pb::v1::{
    manage_neuron::{
        claim_or_refresh::{By, MemoAndController},
        ClaimOrRefresh, Command, Follow, NeuronIdOrSubaccount,
    },
    ManageNeuron, Topic,
};
use ic_protobuf::registry::{
    replica_version::v1::ReplicaVersionRecord,
    subnet::v1::{CatchUpPackageContents, RegistryStoreUri, SubnetRecord, SubnetType},
};
use ic_registry_client::helper::subnet::get_node_ids_from_subnet_record;
use ic_registry_keys::make_subnet_record_key;
use ic_replay::{
    add_replica_version, atomic_mutate, bless_replica_version, update_catch_up_package_contents,
    update_subnet_record, Player,
};
use ic_types::{messages::SignedIngress, CanisterId, PrincipalId, ReplicaVersion, SubnetId, Time};
use ledger_canister::{AccountIdentifier, Memo, SendArgs, Subaccount, Tokens};
use prost::Message;
use std::{convert::TryFrom, path::PathBuf};
use std::{str::FromStr, time::Duration};

struct ClapSubnetId(SubnetId);

impl std::str::FromStr for ClapSubnetId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrincipalId::from_str(s)
            .map_err(|e| format!("Unable to parse subnet_id {:?}", e))
            .map(SubnetId::from)
            .map(ClapSubnetId)
    }
}

#[derive(Clap)]
#[clap(version = "1.0")]
struct CliArgs {
    /// Path to Replica configuration file.
    config: PathBuf,

    /// Caller id that is allowed to mutate the registry canister.
    #[clap(long)]
    canister_caller_id: Option<CanisterId>,

    #[clap(subcommand)]
    subcmd: Option<SubCommand>,

    /// Subnet id of the replica, whose state we use
    #[clap(long)]
    subnet_id: ClapSubnetId,
}

#[derive(Clap)]
enum SubCommand {
    /// Add a new version of the replica binary to the registry.
    AddAndBlessReplicaVersion(AddAndBlessReplicaVersionCmd),
    /// Add registry content from external registry store to the registry
    /// canister.
    AddRegistryContent(AddRegistryContentCmd),
    /// Update registry local store with data from the registry canister.
    UpdateRegistryLocalStore,
    /// Remove all nodes from the subnet record that this node belongs to.
    /// Note that this does not remove individual node records.
    RemoveSubnetNodes,
    /// Create a recovery CUP.
    SetRecoveryCup(SetRecoveryCupCmd),

    /// Restore from the backup.
    RestoreFromBackup(RestoreFromBackupCmd),

    /// The replay will stop at this height and make a checkpoint.
    ReplayUntilHeight(ReplayHeightCmd),

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

#[derive(Clap)]
struct SetRecoveryCupCmd {
    /// State hash (in hex).
    state_hash: String,
    /// Height of the recovery CUP to create.
    height: u64,
    /// Registry store URI
    registry_store_uri: Option<String>,
    /// Registry store SHA256 hash
    registry_store_sha256: Option<String>,
}

#[derive(Clap)]
struct AddAndBlessReplicaVersionCmd {
    /// The Replica version ID.
    replica_version_id: String,
    /// JSON value of the replica version record.
    replica_version_value: String,
    /// If true, the registry record of the corresponding subnet will be
    /// updated with the new replica version.
    #[clap(long)]
    update_subnet_record: bool,
}

#[derive(Clap)]
struct RestoreFromBackupCmd {
    /// Registry local store path
    registry_local_store_path: PathBuf,
    /// Backup spool path
    backup_spool_path: PathBuf,
    /// The replica version to be restored
    replica_version: String,
    /// Height from which the restoration should happen
    start_height: u64,
    /// Persist CUP states only
    #[clap(long)]
    persist_cup_heights_only: bool,
}

#[derive(Clap)]
struct AddRegistryContentCmd {
    /// Path to a directory containing one file for each registry version to be
    /// inserted as initial content into the registry.
    registry_local_store_dir: PathBuf,

    /// Show details about which mutation keys are inserted.
    #[clap(long)]
    verbose: bool,

    /// Only allow mutations of the given key prefixes.
    #[clap(
        long,
        default_value = "crypto_,node_,catch_up_package_,subnet_record_,replica_version_"
    )]
    allowed_mutation_key_prefixes: String,
}

#[derive(Clap)]
struct ReplayHeightCmd {
    /// The height until which the replay should run.
    replay_height: u64,
}

static TRUSTED_NEURONS: &[(&str, u64)] = &[
    (
        "pkjng-fnb6a-zzirr-kykal-ghbjs-ndmj2-tfoma-bzski-wtbsl-2fgbu-hae",
        16,
    ),
    (
        "ilqei-ofqjz-v7jbw-usmzf-jtdss-6mvzv-puesh-3kfga-nhr3v-zmgig-eqe",
        15,
    ),
    (
        "2q5kv-5vcol-eh2je-udy6s-j74gx-djqza-siucy-2jxyq-u5kw6-imugq-uae",
        18,
    ),
    (
        "wyzjx-3pde2-wzr4k-fblse-7hzgm-v2kkx-lcuhl-dftmv-5ywr7-gsszf-6ae",
        1_947_868_782_075_274_250,
    ),
    (
        "j2xaq-c6ph5-e4oa7-nleph-joz7b-nvv4r-if4ol-ilz7w-mzetf-jof6l-mae",
        5_091_612_375_828_828_066,
    ),
    (
        "2yjpj-uumzi-wnefi-5tum7-qt6yq-7gtxo-i4jt5-enll5-pma6q-2gild-mqe",
        12_262_067_573_992_506_876,
    ),
];

#[derive(Clap)]
struct WithLedgerAccountCmd {
    /// The account identifier that should be created with `e8s_to_mint` ICP.
    account_identifier: AccountIdentifier,
    /// How many e8s to mint to the account in `account_identifier`.
    e8s_to_mint: u64,
}

#[derive(Clap)]
struct WithTrustedNeuronsFollowingNeuronCmd {
    /// The neuron id of the neuron that the trusted neurons should follow.
    neuron_id: u64,
}

#[derive(Clap)]
struct WithNeuronCmd {
    /// The controller of the neuron.
    neuron_controller: PrincipalId,
    /// How much stake the neuron will have.
    neuron_stake_e8s: u64,
}

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

        let replay_target_height =
            if let Some(SubCommand::ReplayUntilHeight(replay_height)) = subcmd {
                Some(replay_height.replay_height)
            } else {
                None
            };

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
                .await;
                player.restore(cmd.start_height + 1).await;
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
            let player = Player::new(cfg, subnet_id)
                .await
                .with_replay_target_height(replay_target_height);
            player.replay(extra).await;
            if let Some(SubCommand::UpdateRegistryLocalStore) = subcmd {
                player.update_registry_local_store()
            }
        })
    })
}

fn make_signed_ingress(
    agent: &Agent,
    canister_id: CanisterId,
    method: &str,
    payload: Vec<u8>,
    expiry: Time,
) -> Result<SignedIngress, String> {
    let nonce = format!("{:?}", std::time::Instant::now())
        .as_bytes()
        .to_vec();
    let (http_body, _request_id) = agent
        .prepare_update_raw(&canister_id, method, payload, nonce, expiry)
        .map_err(|err| format!("Error preparing update message: {:?}", err))?;
    SignedIngress::try_from(http_body)
        .map_err(|err| format!("Error converting to SignedIngress: {:?}", err))
}

fn agent_with_principal_as_sender(principal: &PrincipalId) -> Agent {
    Agent::new(
        url::Url::parse("http://localhost").unwrap(),
        Sender::PrincipalId(*principal),
    )
}

fn cmd_add_neuron(time: Time, cmd: &WithNeuronCmd) -> Result<Vec<SignedIngress>, String> {
    let mut msgs = vec![];

    let controller = cmd.neuron_controller;
    let memo = 1234_u64;

    let subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(controller.as_slice());
        sha.write(&memo.to_be_bytes());
        sha.finish()
    });

    let neuron_account = AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount));

    let payload = Encode!(&SendArgs {
        memo: Memo(memo),
        amount: Tokens::from_e8s(cmd.neuron_stake_e8s),
        fee: Tokens::from_e8s(0),
        from_subaccount: None,
        to: neuron_account,
        created_at_time: None,
    })
    .expect("Couldn't candid-encode ledger transfer");

    let governance_agent = agent_with_principal_as_sender(&GOVERNANCE_CANISTER_ID.get());
    msgs.push(
        make_signed_ingress(
            &governance_agent,
            LEDGER_CANISTER_ID,
            "send_dfx",
            payload,
            time,
        )
        .expect("Couldn't create message to mint tokens to neuron account"),
    );

    let payload = Encode!(&ManageNeuron {
        id: None,
        neuron_id_or_subaccount: None,
        command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(By::MemoAndController(MemoAndController {
                memo,
                controller: Some(controller)
            })),
        })),
    })
    .expect("Couldn't candid-encode neuron claim");

    let user_agent = &agent_with_principal_as_sender(&cmd.neuron_controller);
    msgs.push(
        make_signed_ingress(
            user_agent,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            payload,
            time,
        )
        .expect("Couldn't create messages to claim neuron"),
    );

    Ok(msgs)
}

fn cmd_make_trusted_neurons_follow_neuron(
    time: Time,
    cmd: &WithTrustedNeuronsFollowingNeuronCmd,
) -> Result<Vec<SignedIngress>, String> {
    let mut msgs = Vec::new();

    for (principal, neuron_id) in TRUSTED_NEURONS {
        let principal = PrincipalId::from_str(*principal).expect("Invalid principal");
        let payload = Encode!(&ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                id: *neuron_id,
            })),
            command: Some(Command::Follow(Follow {
                topic: Topic::Unspecified as i32,
                followees: [NeuronId { id: cmd.neuron_id }].to_vec(),
            })),
        })
        .expect("Couldn't encode payload for manage neuron command");
        let user_agent = &agent_with_principal_as_sender(&principal);
        msgs.push(
            make_signed_ingress(
                user_agent,
                GOVERNANCE_CANISTER_ID,
                "manage_neuron",
                payload,
                time,
            )
            .expect("Couldn't create message to make trusted neurons follow test neuron"),
        );
    }
    Ok(msgs)
}

fn cmd_add_ledger_account(
    time: Time,
    cmd: &WithLedgerAccountCmd,
) -> Result<Vec<SignedIngress>, String> {
    let memo = 1234_u64;

    let payload = Encode!(&SendArgs {
        memo: Memo(memo),
        amount: Tokens::from_e8s(cmd.e8s_to_mint),
        fee: Tokens::from_e8s(0),
        from_subaccount: None,
        to: cmd.account_identifier,
        created_at_time: None,
    })
    .expect("Couldn't candid-encode ledger transfer");

    let governance_agent = agent_with_principal_as_sender(&GOVERNANCE_CANISTER_ID.get());

    Ok(vec![make_signed_ingress(
        &governance_agent,
        LEDGER_CANISTER_ID,
        "send_dfx",
        payload,
        time,
    )
    .expect(
        "Couldn't create message to mint tokens to neuron account",
    )])
}

/// Creates a recovery CUP by using the latest CUP and overriding the height and
/// the state hash.
fn cmd_set_recovery_cup(
    agent: &Agent,
    player: &Player,
    cmd: &SetRecoveryCupCmd,
    context_time: Time,
) -> Result<SignedIngress, String> {
    use ic_crypto::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTag;

    let time = context_time + Duration::from_secs(60);
    let state_hash = hex::decode(&cmd.state_hash).map_err(|err| format!("{}", err))?;
    let cup = player.get_highest_catch_up_package();
    let payload = cup.content.block.as_ref().payload.as_ref();
    let summary = payload.as_summary();
    let low_threshold_transcript = summary
        .dkg
        .current_transcript(&NiDkgTag::LowThreshold)
        .clone();
    let high_threshold_transcript = summary
        .dkg
        .current_transcript(&NiDkgTag::HighThreshold)
        .clone();
    let initial_ni_dkg_transcript_low_threshold = Some(
        initial_ni_dkg_transcript_record_from_transcript(low_threshold_transcript),
    );
    let initial_ni_dkg_transcript_high_threshold = Some(
        initial_ni_dkg_transcript_record_from_transcript(high_threshold_transcript),
    );
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_low_threshold,
        initial_ni_dkg_transcript_high_threshold,
        height: cmd.height,
        time: time.as_nanos_since_unix_epoch(),
        state_hash,
        registry_store_uri: Some(RegistryStoreUri {
            uri: cmd.registry_store_uri.clone().unwrap_or_default(),
            hash: cmd.registry_store_sha256.clone().unwrap_or_default(),
            registry_version: player.get_latest_registry_version(context_time)?.get(),
        }),
    };

    update_catch_up_package_contents(agent, player.subnet_id, cup_contents, context_time)
}

/// Creates signed ingress messages to add a new blessed replica version and
/// potentially updates the subnet record with this replica version.
fn cmd_add_and_bless_replica_version(
    agent: &Agent,
    player: &Player,
    cmd: &AddAndBlessReplicaVersionCmd,
    context_time: Time,
) -> Result<Vec<SignedIngress>, String> {
    let replica_version_id = cmd.replica_version_id.clone();
    let replica_version_record =
        serde_json::from_str::<ReplicaVersionRecord>(&cmd.replica_version_value)
            .unwrap_or_else(|err| panic!("Error parsing replica version JSON value: {:?}", err));
    let mut msgs = vec![
        add_replica_version(
            agent,
            replica_version_id.clone(),
            replica_version_record,
            context_time,
        )?,
        bless_replica_version(agent, player, replica_version_id.clone(), context_time)?,
    ];
    if cmd.update_subnet_record {
        let mut subnet_record = player.get_subnet_record(context_time + Duration::from_secs(60))?;
        subnet_record.replica_version_id = replica_version_id;
        msgs.push(update_subnet_record(
            agent,
            player.subnet_id,
            subnet_record,
            context_time,
        )?);
    }
    Ok(msgs)
}

/// Read the registry from the specified local store and send them to the
/// registry canister with slight modifications.
fn cmd_add_registry_content(
    agent: &Agent,
    cmd: &AddRegistryContentCmd,
    subnet_id: SubnetId,
    context_time: Time,
) -> Result<Vec<SignedIngress>, String> {
    let allowed_prefix: Vec<&str> = cmd.allowed_mutation_key_prefixes.split(',').collect();
    let is_allowed = |key: &str| allowed_prefix.iter().any(|p| key.starts_with(p));
    let mutate_reqs =
        ic_nns_init::read_initial_mutations_from_local_store_dir(&cmd.registry_local_store_dir);
    mutate_reqs
        .into_iter()
        .filter_map(|req| {
            let mutations = req
                .mutations
                .into_iter()
                .filter_map(|mut mutation| {
                    let key = std::str::from_utf8(&mutation.key).unwrap_or_default();
                    if is_allowed(key) {
                        // Set the subnet type flag of the child subnet to system, so that it can
                        // be spawn as a new NNS subnet. Also, unhalt it.
                        if key == make_subnet_record_key(subnet_id) {
                            let mut subnet_record = SubnetRecord::decode(mutation.value.as_slice())
                                .unwrap_or_else(|err| {
                                    panic!("Unable to decode SubnetRecord for {}: {}", key, err)
                                });
                            subnet_record.subnet_type = SubnetType::System as i32;
                            subnet_record.is_halted = false;
                            mutation.value = Vec::new();
                            subnet_record
                                .encode(&mut mutation.value)
                                .expect("encode can't fail");
                        }
                        if cmd.verbose {
                            println!(
                                "Adding registry mutation: {} key {}",
                                show_mutation_type(mutation.mutation_type),
                                key,
                            );
                        }
                        Some(mutation)
                    } else {
                        if cmd.verbose {
                            println!(
                                "Skipping registry mutation: {} key {}",
                                show_mutation_type(mutation.mutation_type),
                                key,
                            );
                        }
                        None
                    }
                })
                .collect::<Vec<_>>();
            if !mutations.is_empty() {
                Some(atomic_mutate(
                    agent,
                    REGISTRY_CANISTER_ID,
                    mutations,
                    req.preconditions,
                    context_time + Duration::from_secs(60),
                ))
            } else {
                None
            }
        })
        .collect::<Result<Vec<SignedIngress>, String>>()
}

/// Creates an ingress for removing of all nodes from a subnet.
fn cmd_remove_subnet(
    agent: &Agent,
    player: &Player,
    context_time: Time,
) -> Result<Option<SignedIngress>, String> {
    let mut subnet_record = player.get_subnet_record(context_time)?;
    let nodes = get_node_ids_from_subnet_record(&subnet_record);
    if nodes.is_empty() {
        println!("Subnet {} has empty membership", player.subnet_id);
        Ok(None)
    } else {
        println!("Removing subnet {} members: {:?}", player.subnet_id, nodes);
        subnet_record.membership = Vec::new();
        update_subnet_record(agent, player.subnet_id, subnet_record, context_time).map(Some)
    }
}

fn show_mutation_type(mutation_type: i32) -> &'static str {
    use ic_registry_transport::pb::v1::registry_mutation::Type;
    match mutation_type {
        _ if mutation_type == Type::Insert as i32 => "INSERT",
        _ if mutation_type == Type::Update as i32 => "UPDATE",
        _ if mutation_type == Type::Delete as i32 => "DELETE",
        _ if mutation_type == Type::Upsert as i32 => "UPSERT",
        _ => "UNKNOWN",
    }
}
