use crate::cmd::{
    AddRegistryContentCmd, UpgradeSubnetToReplicaVersionCmd, WithLedgerAccountCmd, WithNeuronCmd,
    WithTrustedNeuronsFollowingNeuronCmd,
};
use candid::{Encode, decode_one};
use ic_agent::{
    Agent, Identity, Signature,
    agent::{EnvelopeContent, signed::SignedUpdate},
    export::Principal,
};
use ic_nervous_system_common::ledger;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_governance_api::{
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, Topic,
    manage_neuron::{
        ClaimOrRefresh, Configure, Follow, IncreaseDissolveDelay, NeuronIdOrSubaccount,
        claim_or_refresh::{By, MemoAndController},
        configure::Operation,
    },
    manage_neuron_response,
};
use ic_protobuf::registry::{
    replica_version::v1::ReplicaVersionRecord,
    subnet::v1::{SubnetRecord, SubnetType},
};
use ic_registry_client_helpers::subnet::get_node_ids_from_subnet_record;
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_replica_version_key, make_subnet_record_key,
};
use ic_registry_transport::{
    pb::v1::{Precondition, RegistryMutation, registry_mutation},
    serialize_atomic_mutate_request,
};
use ic_types::{
    CanisterId, PrincipalId, SubnetId, Time,
    messages::{SignedIngress, SignedRequestBytes},
};
use icp_ledger::{AccountIdentifier, Memo, SendArgs, Tokens};
use prost::Message;
use std::{convert::TryFrom, str::FromStr, time::Duration};
use time::OffsetDateTime;

pub struct IngressWithPrinter {
    pub ingress: SignedIngress,
    pub print: Option<fn(Vec<u8>)>,
}

impl From<SignedIngress> for IngressWithPrinter {
    fn from(ingress: SignedIngress) -> IngressWithPrinter {
        IngressWithPrinter {
            ingress,
            print: None,
        }
    }
}

/// Behaves like the anonymous identity for the agent, i.e., does not sign messages.
/// Though, it still uses a custom PrincipalId as the sender instead of the fixed anonymous
/// principal.
struct PrincipalSender(PrincipalId);

impl Identity for PrincipalSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::from(self.0))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn sign(&self, _content: &EnvelopeContent) -> Result<Signature, String> {
        Ok(Signature {
            public_key: None,
            signature: None,
            delegations: None,
        })
    }
}

fn make_signed_ingress(
    agent: &Agent,
    canister_id: CanisterId,
    method: &str,
    payload: Vec<u8>,
    expiry: Time,
) -> Result<SignedIngress, String> {
    let SignedUpdate { signed_update, .. } = agent
        .update(&Principal::from(canister_id), method)
        .with_arg(payload)
        .expire_at(
            OffsetDateTime::from_unix_timestamp_nanos(expiry.as_nanos_since_unix_epoch().into())
                .map_err(|err| format!("Error preparing update message: {err:?}"))?,
        )
        .sign()
        .map_err(|err| format!("Error preparing update message: {err:?}"))?;

    SignedIngress::try_from(SignedRequestBytes::from(signed_update))
        .map_err(|err| format!("Error converting to SignedIngress: {err:?}"))
}

pub(crate) fn agent_with_principal_as_sender(principal: &PrincipalId) -> Result<Agent, String> {
    // Use a dummy URL here because we don't send any outgoing ingress.
    // The agent is only used to construct ingress messages.
    Agent::builder()
        .with_url("http://localhost")
        .with_identity(PrincipalSender(*principal))
        .build()
        .map_err(|err| err.to_string())
}

pub fn cmd_add_neuron(time: Time, cmd: &WithNeuronCmd) -> Result<Vec<IngressWithPrinter>, String> {
    let mut msgs = vec![];

    let controller = cmd.neuron_controller;
    let memo = 1234_u64;
    let subaccount = ledger::compute_neuron_staking_subaccount(controller, memo);

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

    let governance_agent = &agent_with_principal_as_sender(&GOVERNANCE_CANISTER_ID.get())?;
    msgs.push(IngressWithPrinter {
        ingress: make_signed_ingress(
            governance_agent,
            LEDGER_CANISTER_ID,
            "send_dfx",
            payload,
            time,
        )
        .expect("Couldn't create message to mint tokens to neuron account"),
        print: None,
    });

    let payload = Encode!(&ManageNeuronRequest {
        id: None,
        neuron_id_or_subaccount: None,
        command: Some(ManageNeuronCommandRequest::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(By::MemoAndController(MemoAndController {
                memo,
                controller: Some(controller)
            })),
        })),
    })
    .expect("Couldn't candid-encode neuron claim");

    let user_agent = &agent_with_principal_as_sender(&cmd.neuron_controller)?;
    msgs.push(IngressWithPrinter {
        ingress: make_signed_ingress(
            user_agent,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            payload,
            time,
        )
        .expect("Couldn't create messages to claim neuron"),
        print: Some(|response: Vec<u8>| {
            let v: ManageNeuronResponse =
                decode_one(&response).expect("couldn't decode canister response");
            match v.command {
                Some(manage_neuron_response::Command::ClaimOrRefresh(
                    manage_neuron_response::ClaimOrRefreshResponse {
                        refreshed_neuron_id: Some(NeuronId { id }),
                    },
                )) => {
                    println!("neuron_id={id:?}")
                }
                val => unreachable!("unexpected response: {:?}", val),
            }
        }),
    });

    Ok(msgs)
}

pub fn cmd_make_trusted_neurons_follow_neuron(
    time: Time,
    cmd: &WithTrustedNeuronsFollowingNeuronCmd,
) -> Result<Vec<SignedIngress>, String> {
    let mut msgs = Vec::new();

    let trusted_neurons: &[(&str, u64)] = &[
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

    for (principal, neuron_id) in trusted_neurons {
        let principal = PrincipalId::from_str(principal).expect("Invalid principal");
        let follow_payload = Encode!(&ManageNeuronRequest {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                id: *neuron_id,
            })),
            command: Some(ManageNeuronCommandRequest::Follow(Follow {
                topic: Topic::Unspecified as i32,
                followees: [NeuronId { id: cmd.neuron_id }].to_vec(),
            })),
        })
        .expect("Couldn't encode payload for manage neuron command");
        let user_agent = &agent_with_principal_as_sender(&principal)?;
        msgs.push(
            make_signed_ingress(
                user_agent,
                GOVERNANCE_CANISTER_ID,
                "manage_neuron",
                follow_payload,
                time,
            )
            .expect("Couldn't create message to make trusted neurons follow test neuron"),
        );
    }

    // Increase the neuron's delay
    let user_agent = &agent_with_principal_as_sender(&cmd.neuron_controller)?;
    let delay_payload = Encode!(&ManageNeuronRequest {
        id: Some(NeuronId { id: cmd.neuron_id }),
        neuron_id_or_subaccount: None,
        command: Some(ManageNeuronCommandRequest::Configure(Configure {
            operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                additional_dissolve_delay_seconds: 31560000 // one year
            }))
        })),
    })
    .expect("Couldn't encode payload for manage neuron command");
    msgs.push(
        make_signed_ingress(
            user_agent,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            delay_payload,
            time,
        )
        .expect("Couldn't create message to make trusted neurons follow test neuron"),
    );
    Ok(msgs)
}

pub fn cmd_add_ledger_account(
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

    let governance_agent = &agent_with_principal_as_sender(&GOVERNANCE_CANISTER_ID.get())?;

    Ok(vec![
        make_signed_ingress(
            governance_agent,
            LEDGER_CANISTER_ID,
            "send_dfx",
            payload,
            time,
        )
        .expect("Couldn't create message to mint tokens to neuron account"),
    ])
}

/// Creates signed ingress messages to potentially add a new blessed replica
/// version and updates the subnet record with this replica version.
pub(crate) fn cmd_upgrade_subnet_to_replica_version(
    agent: &Agent,
    player: &crate::player::Player,
    cmd: &UpgradeSubnetToReplicaVersionCmd,
    context_time: Time,
) -> Result<Vec<SignedIngress>, String> {
    let replica_version_id = cmd.replica_version_id.clone();
    let replica_version_record = cmd.replica_version_record.clone();

    let mut msgs = Vec::new();

    if cmd.add_and_bless_replica_version {
        msgs.push(add_replica_version(
            agent,
            replica_version_id.clone(),
            replica_version_record,
            context_time,
        )?);
        msgs.push(bless_replica_version(
            agent,
            player,
            replica_version_id.clone(),
            context_time,
        )?);
    }

    let mut subnet_record = player.get_subnet_record(context_time + Duration::from_secs(60))?;
    subnet_record.replica_version_id = replica_version_id;
    msgs.push(update_subnet_record(
        agent,
        player.subnet_id,
        subnet_record,
        context_time,
    )?);
    Ok(msgs)
}

/// Read the registry from the specified local store and send them to the
/// registry canister with slight modifications.
pub fn cmd_add_registry_content(
    agent: &Agent,
    cmd: &AddRegistryContentCmd,
    subnet_id: SubnetId,
    context_time: Time,
) -> Result<Vec<SignedIngress>, String> {
    let allowed_prefix: Vec<&str> = cmd.allowed_mutation_key_prefixes.split(',').collect();
    let is_allowed = |key: &str| allowed_prefix.iter().any(|p| key.starts_with(p));
    let mutate_reqs = crate::registry_helper::read_initial_mutations_from_local_store_dir(
        &cmd.registry_local_store_dir,
    );
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
                                    panic!("Unable to decode SubnetRecord for {key}: {err}")
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
pub(crate) fn cmd_remove_subnet(
    agent: &Agent,
    player: &crate::player::Player,
    context_time: Time,
) -> Result<Option<SignedIngress>, String> {
    let mut subnet_record = player.get_subnet_record(context_time)?;
    let nodes = get_node_ids_from_subnet_record(&subnet_record)
        .map_err(|err| format!("get_node_ids_from_subnet_record() failed with {err}"))?;
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

/// Applies 'mutations' to the registry.
pub fn atomic_mutate(
    agent: &Agent,
    canister_id: CanisterId,
    mutations: Vec<RegistryMutation>,
    pre_conditions: Vec<Precondition>,
    expiry: Time,
) -> Result<SignedIngress, String> {
    let payload = serialize_atomic_mutate_request(mutations, pre_conditions);

    make_signed_ingress(agent, canister_id, "atomic_mutate", payload, expiry)
}

/// Bless a new replica version by mutating the registry canister.
pub(crate) fn bless_replica_version(
    agent: &Agent,
    player: &crate::player::Player,
    replica_version_id: String,
    context_time: Time,
) -> Result<SignedIngress, String> {
    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Upsert);
    mutation.key = make_blessed_replica_versions_key().into_bytes();
    let mut blessed_versions = player.get_blessed_replica_versions(context_time)?;
    blessed_versions
        .blessed_version_ids
        .push(replica_version_id);

    let mut buf = Vec::new();
    match blessed_versions.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!("Error encoding the value to protobuf: {error:?}"),
    }
    atomic_mutate(
        agent,
        REGISTRY_CANISTER_ID,
        vec![mutation],
        vec![],
        context_time + Duration::from_secs(60),
    )
}

/// Add a new replica version by mutating the registry canister.
pub fn add_replica_version(
    agent: &Agent,
    replica_version_id: String,
    record: ReplicaVersionRecord,
    context_time: Time,
) -> Result<SignedIngress, String> {
    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_replica_version_key(replica_version_id).into_bytes();

    let mut buf = Vec::new();
    match record.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!("Error encoding the value to protobuf: {error:?}"),
    }
    atomic_mutate(
        agent,
        REGISTRY_CANISTER_ID,
        vec![mutation],
        vec![],
        context_time + Duration::from_secs(60),
    )
}

/// Update subnet record.
pub fn update_subnet_record(
    agent: &Agent,
    subnet_id: SubnetId,
    record: SubnetRecord,
    context_time: Time,
) -> Result<SignedIngress, String> {
    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Update);
    mutation.key = make_subnet_record_key(subnet_id).as_bytes().to_vec();

    let mut buf = Vec::new();
    match record.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!("Error encoding the value to protobuf: {error:?}"),
    }
    atomic_mutate(
        agent,
        REGISTRY_CANISTER_ID,
        vec![mutation],
        vec![],
        context_time + Duration::from_secs(60),
    )
}
