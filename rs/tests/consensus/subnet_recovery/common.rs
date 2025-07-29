/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes + failover nodes, with and without chain keys, with and without version upgrade)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes and on failover nodes.


Runbook::
. Deploy an IC with one "source" app subnet and one "app" app subnet (and some unassigned nodes
  in case of recovery on failover nodes).
. In case of chain keys: enable signing on the "source", create the "app" with the key, then disable
  signing on "source" and enable it on the "app" instead.
. Break (halt in case of no upgrade) the subnet.
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a node with max finalization height.
. Execute ic-replay to generate a recovery CUP.
. Optionally upgrade the subnet to a working replica.
. Submit a recovery CUP (using failover nodes and/or chain keys, if configured).
. Upload replayed state to a node.
. Unhalt the subnet.
. Ensure the subnet resumes.
. In case of chain keys: ensure that signing on the "app" is possible, and the key hasn't changed.

Success::
. "App" subnet is functional after the recovery.

end::catalog[] */

use anyhow::bail;
use candid::Principal;
use canister_test::Canister;
use ic_base_types::NodeId;
use ic_consensus_system_test_utils::{
    node::assert_node_is_unassigned,
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
    set_sandbox_env_vars,
    ssh_access::execute_bash_command,
    subnet::{
        assert_subnet_is_healthy, disable_chain_key_on_subnet, enable_chain_key_signing_on_subnet,
    },
};
use ic_consensus_threshold_sig_system_test_utils::{
    create_new_subnet_with_keys, make_key_ids_for_all_schemes, run_chain_key_signature_test,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs, StepType},
    steps::Step,
    util::DataLocation,
    NodeMetrics, Recovery, RecoveryArgs,
};
use ic_recovery::{file_sync_helper, get_node_metrics};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::{
    SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::util::*;
use ic_types::{consensus::CatchUpPackage, Height, ReplicaVersion, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::{collections::BTreeMap, convert::TryFrom};
use std::{io::Read, time::Duration};
use std::{io::Write, path::Path};
use url::Url;

const DKG_INTERVAL: u64 = 20;
const NNS_NODES: usize = 4;
const APP_NODES: usize = 4;
const UNASSIGNED_NODES: usize = 4;

const NNS_NODES_LARGE: usize = 40;
const APP_NODES_LARGE: usize = 37;
/// 40 dealings * 3 transcripts being reshared (high/local, high/remote, low/remote)
/// plus 4 to make checkpoint heights more predictable
const DKG_INTERVAL_LARGE: u64 = 124;

pub const CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Setup an IC with the given number of unassigned nodes and
/// an app subnet with the given number of nodes
fn setup(env: TestEnv, cfg: SetupConfig) {
    let key_ids = make_key_ids_for_all_schemes();

    let key_configs = key_ids
        .into_iter()
        .map(|key_id| KeyConfig {
            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            pre_signatures_to_create_in_advance: if key_id.requires_pre_signatures() {
                3
            } else {
                0
            },
            key_id,
        })
        .collect();

    let mut ic = InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.nns_nodes),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.source_nodes)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs,
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                }),
        )
        .with_unassigned_nodes(cfg.unassigned_nodes);
    if cfg.app_nodes > 0 {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.app_nodes),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");
    install_nns_and_check_progress(env.topology_snapshot());
}

struct SetupConfig {
    nns_nodes: usize,
    source_nodes: usize,
    app_nodes: usize,
    unassigned_nodes: usize,
    dkg_interval: u64,
}

pub fn setup_large_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES_LARGE,
            source_nodes: APP_NODES_LARGE,
            app_nodes: 0,
            unassigned_nodes: APP_NODES_LARGE,
            dkg_interval: DKG_INTERVAL_LARGE,
        },
    );
}

pub fn setup_same_nodes_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: 0,
            unassigned_nodes: APP_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_failover_nodes_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: 0,
            unassigned_nodes: APP_NODES + UNASSIGNED_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_same_nodes(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: APP_NODES,
            unassigned_nodes: 0,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_failover_nodes(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: APP_NODES,
            unassigned_nodes: UNASSIGNED_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

struct TestConfig {
    subnet_size: usize,
    upgrade: bool,
    chain_key: bool,
    corrupt_cup: bool,
    local_recovery: bool,
}

pub fn test_with_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: true,
            chain_key: true,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_without_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: true,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_with_chain_keys(env: TestEnv) {
    // Test the corrupt CUP case only when recovering an app subnet with chain keys without upgrade
    let corrupt_cup = env.topology_snapshot().unassigned_nodes().count() > 0;
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: true,
            corrupt_cup,
            local_recovery: false,
        },
    );
}

pub fn test_large_with_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES_LARGE,
            upgrade: false,
            chain_key: true,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_without_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_without_chain_keys_local(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: true,
        },
    );
}

fn app_subnet_recovery_test(env: TestEnv, cfg: TestConfig) {
    let logger = env.logger();

    let initial_version = get_guestos_img_version().unwrap();
    let initial_version = ReplicaVersion::try_from(initial_version).unwrap();
    info!(logger, "IC_VERSION_ID: {initial_version:?}");
    let topology_snapshot = env.topology_snapshot();

    // Choose a node from the nns subnet
    let nns_node = get_nns_node(&topology_snapshot);
    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    // The first application subnet encountered during iteration is the source subnet because it was inserted first.
    let source_subnet_id = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no source subnet")
        .subnet_id;

    let create_new_subnet = !topology_snapshot
        .subnets()
        .any(|s| s.subnet_type() == SubnetType::Application && s.subnet_id != source_subnet_id);
    assert!(cfg.chain_key >= create_new_subnet);

    let key_ids = make_key_ids_for_all_schemes();
    let chain_key_pub_keys = cfg.chain_key.then(|| {
        info!(
            logger,
            "Chain key flag set, creating key on the source subnet."
        );
        if create_new_subnet {
            info!(
                logger,
                "No app subnet found, creating a new one with the Chain keys."
            );
            enable_chain_key_on_new_subnet(
                &env,
                &nns_node,
                &nns_canister,
                source_subnet_id,
                cfg.subnet_size,
                initial_version.clone(),
                key_ids.clone(),
                &logger,
            )
        } else {
            enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                source_subnet_id,
                key_ids.clone(),
                &logger,
            )
        }
    });

    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet");
    let mut app_nodes = app_subnet.nodes();
    let app_node = app_nodes.next().expect("there is no application node");
    info!(
        logger,
        "Selected random application subnet node: {} ({:?})",
        app_node.node_id,
        app_node.get_ip_addr()
    );
    info!(logger, "app node URL: {}", app_node.get_public_url());

    info!(logger, "Ensure app subnet is functional");
    cert_state_makes_progress_with_retries(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );
    let msg = "subnet recovery works!";
    let app_can_id = store_message(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &app_node.get_public_url(),
        app_can_id,
        msg
    ));

    let subnet_id = app_subnet.subnet_id;

    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(SSH_USERNAME))
        .expect("Couldn't read public key");

    let recovery_dir = get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: nns_node.get_public_url(),
        replica_version: Some(initial_version.clone()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(SSH_USERNAME)),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: false,
    };

    let mut unassigned_nodes = env.topology_snapshot().unassigned_nodes();

    let upload_node = if let Some(node) = unassigned_nodes.next() {
        node
    } else {
        app_nodes.next().unwrap()
    };

    print_source_and_app_and_unassigned_nodes(&env, &logger, source_subnet_id);

    let unassigned_nodes_ids = env
        .topology_snapshot()
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect::<Vec<NodeId>>();

    let version_is_broken = cfg.upgrade && unassigned_nodes_ids.is_empty();
    let working_version = if version_is_broken {
        get_guestos_update_img_version().unwrap()
    } else {
        initial_version.to_string()
    };

    let subnet_args = AppSubnetRecoveryArgs {
        keep_downloaded_state: Some(cfg.chain_key),
        subnet_id,
        upgrade_version: version_is_broken
            .then(|| ReplicaVersion::try_from(working_version.clone()).unwrap()),
        upgrade_image_url: get_guestos_update_img_url().ok(),
        upgrade_image_hash: get_guestos_update_img_sha256(&env).ok(),
        replacement_nodes: Some(unassigned_nodes_ids.clone()),
        replay_until_height: None, // We will set this after breaking/halting the subnet, see below
        // If the latest CUP is corrupted we can't deploy read-only access
        pub_key: (!cfg.corrupt_cup).then_some(pub_key),
        download_method: None, // We will set this after breaking/halting the subnet, see below
        upload_method: Some(DataLocation::Remote(upload_node.get_ip_addr())),
        wait_for_cup_node: Some(upload_node.get_ip_addr()),
        chain_key_subnet_id: cfg.chain_key.then_some(source_subnet_id),
        next_step: None,
        skip: None,
    };

    info!(
        logger,
        "Starting recovery of subnet {} with {:?}",
        subnet_id.to_string(),
        &subnet_args
    );

    let mut subnet_recovery = AppSubnetRecovery::new(
        env.logger(),
        recovery_args,
        /*neuron_args=*/ None,
        subnet_args,
    );
    if cfg.upgrade {
        break_subnet(
            app_nodes,
            cfg.subnet_size,
            subnet_recovery.get_recovery_api(),
            &logger,
        );
    } else {
        halt_subnet(
            &app_node,
            subnet_id,
            subnet_recovery.get_recovery_api(),
            &logger,
        )
    }
    assert_subnet_is_broken(&app_node.get_public_url(), app_can_id, msg, true, &logger);

    let download_node = select_download_node(&app_subnet, &logger);

    if cfg.corrupt_cup {
        info!(logger, "Corrupting the latest CUP on all nodes");
        corrupt_latest_cup(&app_subnet, subnet_recovery.get_recovery_api(), &logger);
        assert_subnet_is_broken(&app_node.get_public_url(), app_can_id, msg, false, &logger);
    }

    subnet_recovery.params.download_method =
        Some(DataLocation::Remote(download_node.0.get_ip_addr()));
    subnet_recovery.params.replay_until_height = Some(download_node.1.certification_height.get());

    if cfg.local_recovery {
        info!(logger, "Performing a local node recovery");
        local_recovery(&download_node.0, subnet_recovery, &logger);
    } else {
        info!(logger, "Performing remote recovery");
        remote_recovery(&cfg, subnet_recovery, &logger);
    }

    info!(logger, "Blocking for newer registry version");
    let topology_snapshot = block_on(env.topology_snapshot().block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    print_source_and_app_and_unassigned_nodes(&env, &logger, source_subnet_id);

    let all_app_nodes: Vec<IcNodeSnapshot> = topology_snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet")
        .nodes()
        .collect();

    let mut old_unassigned_ids = unassigned_nodes_ids;
    if !old_unassigned_ids.is_empty() {
        old_unassigned_ids.sort();
        let mut assigned_nodes_ids: Vec<NodeId> = all_app_nodes.iter().map(|n| n.node_id).collect();
        assigned_nodes_ids.sort();
        assert_eq!(
            old_unassigned_ids, assigned_nodes_ids,
            "Previously unassigned nodes should now be assigned"
        );
    }

    assert_subnet_is_healthy(&all_app_nodes, working_version, app_can_id, msg, &logger);

    for node in all_app_nodes {
        let height = block_on(get_node_metrics(&logger, &node.get_ip_addr()))
            .unwrap()
            .finalization_height;
        info!(
            logger,
            "Node {} finalization height: {:?}", node.node_id, height
        );
        assert!(height > Height::from(1000));
    }

    if cfg.chain_key {
        if !create_new_subnet {
            disable_chain_key_on_subnet(
                &nns_node,
                source_subnet_id,
                &nns_canister,
                key_ids.clone(),
                &logger,
            );
            let app_keys = enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                subnet_id,
                key_ids.clone(),
                &logger,
            );
            assert_eq!(chain_key_pub_keys.clone().unwrap(), app_keys)
        }

        for (key_id, chain_key_pub_key) in chain_key_pub_keys.unwrap() {
            run_chain_key_signature_test(&nns_canister, &logger, &key_id, chain_key_pub_key);
        }
    }

    info!(
        logger,
        "Making sure unassigned nodes deleted their state..."
    );
    topology_snapshot
        .unassigned_nodes()
        .for_each(|n| assert_node_is_unassigned(&n, &logger));
}

fn remote_recovery(cfg: &TestConfig, subnet_recovery: AppSubnetRecovery, logger: &Logger) {
    for (step_type, step) in subnet_recovery {
        info!(logger, "Next step: {:?}", step_type);

        if cfg.corrupt_cup && step_type == StepType::ValidateReplayOutput {
            // Skip validating the output if the CUP is corrupt, as in this case
            // no replica will be running to compare the heights to.
            continue;
        }

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }
}

fn local_recovery(node: &IcNodeSnapshot, subnet_recovery: AppSubnetRecovery, logger: &Logger) {
    let nns_url = subnet_recovery.recovery_args.nns_url;
    let subnet_id = subnet_recovery.params.subnet_id;
    let maybe_replay_until_height = subnet_recovery
        .params
        .replay_until_height
        .map(|h| format!("--replay-until-height {h} "))
        .unwrap_or_default();
    let pub_key = subnet_recovery.params.pub_key.unwrap();
    let pub_key = pub_key.trim();
    let node_ip = node.get_ip_addr();

    let command = format!(
        r#"/opt/ic/bin/ic-recovery \
        --nns-url {nns_url} \
        --test --skip-prompts --use-local-binaries \
        app-subnet-recovery \
        --subnet-id {subnet_id} \
        {maybe_replay_until_height}\
        --pub-key "{pub_key}" \
        --download-method local \
        --upload-method local \
        --wait-for-cup-node {node_ip} \
        --skip DownloadCertifications \
        --skip MergeCertificationPools
    "#
    );

    info!(logger, "Executing local recovery command: \n{command}");
    match node.block_on_bash_script(&command) {
        Ok(ret) => info!(logger, "Finished local recovery: \n{ret}"),
        Err(err) => panic!("Local recovery failed: \n{err}"),
    }
}

/// break a subnet by breaking the replica binary on f+1 = (subnet_size - 1) / 3 +1
/// nodes taken from the given iterator.
fn break_subnet(
    subnet: Box<dyn Iterator<Item = IcNodeSnapshot>>,
    subnet_size: usize,
    recovery: &Recovery,
    logger: &Logger,
) {
    // Let's take f+1 nodes and break them.
    let f = (subnet_size - 1) / 3;
    info!(
        logger,
        "Breaking the subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = subnet.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        // simulate subnet failure by breaking the replica process, but not the orchestrator
        recovery
            .execute_ssh_command(
                "admin",
                node.get_ip_addr(),
                "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica",
            )
            .expect("couldn't run ssh command");
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Cursor {
    #[serde(alias = "__CURSOR")]
    cursor: String,
}

/// Halt the subnet and wait until the given app node reports consensus 'is halted'
fn halt_subnet(
    app_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    recovery: &Recovery,
    logger: &Logger,
) {
    info!(logger, "Breaking the app subnet by halting it");
    let s = app_node.block_on_ssh_session().unwrap();
    let message_str = execute_bash_command(
        &s,
        "journalctl -n1 -o json --output-fields='__CURSOR'".to_string(),
    )
    .expect("journal message");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");
    recovery
        .halt_subnet(subnet_id, true, &[])
        .exec()
        .expect("Failed to halt subnet.");
    ic_system_test_driver::retry_with_msg!(
        "check if consensus is halted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = execute_bash_command(
                &s,
                format!(
                    "journalctl --after-cursor='{}' | grep -c 'is halted'",
                    message.cursor
                ),
            );
            if res.is_ok_and(|r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                bail!("Did not find log entry that consensus is halted.")
            }
        }
    )
    .expect("Failed to detect broken subnet.");
}

// Corrupt the latest cup of all subnet nodes by change the CUP's replica version field.
// This will change the hash of the block, thus making the CUP non-deserializable.
fn corrupt_latest_cup(subnet: &SubnetSnapshot, recovery: &Recovery, logger: &Logger) {
    const CUP_PATH: &str = "/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb";
    const NEW_CUP_PATH: &str = "/var/lib/ic/data/cups/new_cup.pb";

    let app_node = subnet.nodes().next().unwrap();
    let session = app_node.block_on_ssh_session().unwrap();

    info!(
        logger,
        "Setting journal cursor on node {:?}",
        app_node.get_ip_addr()
    );
    let message_str = execute_bash_command(
        &session,
        "journalctl -n1 -o json --output-fields='__CURSOR'".to_string(),
    )
    .expect("journal message");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");

    info!(logger, "Reading CUP from node {:?}", app_node.get_ip_addr());
    let (mut channel, _) = session.scp_recv(Path::new(CUP_PATH)).unwrap();
    let mut bytes = Vec::new();
    channel.read_to_end(&mut bytes).unwrap();

    info!(logger, "Modifying CUP replica version");
    let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).unwrap();
    let mut cup = CatchUpPackage::try_from(&proto_cup).unwrap();
    cup.content.block.as_mut().version = ReplicaVersion::try_from("invalid_version").unwrap();
    let bytes = pb::CatchUpPackage::from(cup).encode_to_vec();

    for node in subnet.nodes() {
        info!(
            logger,
            "Uploading corrupted CUP of length {} to node {:?}",
            bytes.len(),
            node.get_ip_addr()
        );
        let session = node.block_on_ssh_session().unwrap();
        execute_bash_command(
            &session,
            format!(
                "sudo touch {}; sudo chmod a+rw {}",
                NEW_CUP_PATH, NEW_CUP_PATH
            ),
        )
        .expect("touch");
        let mut channel = session
            .scp_send(Path::new(NEW_CUP_PATH), 0o666, bytes.len() as u64, None)
            .unwrap();
        channel.write_all(&bytes).unwrap();

        info!(logger, "Restarting node {:?}", node.get_ip_addr());
        execute_bash_command(
            &session,
            format!(
                "sudo mv {} {}; sudo systemctl restart ic-replica",
                NEW_CUP_PATH, CUP_PATH
            ),
        )
        .expect("restart");
    }

    ic_system_test_driver::retry_with_msg!(
        "check if cup is corrupted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = execute_bash_command(
                &session,
                format!(
                    "journalctl --after-cursor='{}' | grep -c 'Failed to deserialize CatchUpPackage'",
                    message.cursor
                ),
            );
            if res.is_ok_and( |r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                bail!("Did not find log entry that cup is corrupted.")
            }
        }
    )
    .expect("Failed to detect broken subnet.");

    info!(logger, "Unhalting subnet");
    recovery
        .halt_subnet(subnet.subnet_id, false, &[])
        .exec()
        .expect("Failed to unhalt subnet.");
}

/// A subnet is considered to be broken if it still works in read mode,
/// but doesn't in write mode
fn assert_subnet_is_broken(
    node_url: &Url,
    can_id: Principal,
    msg: &str,
    can_read: bool,
    logger: &Logger,
) {
    if can_read {
        info!(logger, "Ensure the subnet works in read mode");
        assert!(
            can_read_msg(logger, node_url, can_id, msg),
            "Failed to read message on node: {}",
            node_url
        );
    }
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(
        cannot_store_msg(logger.clone(), node_url, can_id, msg),
        "Writing messages still successful on: {}",
        node_url
    );
}

/// Select a node with highest certification height in the given subnet snapshot
fn select_download_node(subnet: &SubnetSnapshot, logger: &Logger) -> (IcNodeSnapshot, NodeMetrics) {
    let node = subnet
        .nodes()
        .filter_map(|n| block_on(get_node_metrics(logger, &n.get_ip_addr())).map(|m| (n, m)))
        .max_by_key(|(_, metric)| metric.certification_height)
        .expect("No download node found");
    info!(
        logger,
        "Selected download node: ({}, {})",
        node.0.get_ip_addr(),
        node.1.certification_height
    );
    node
}

/// Print ID and IP of the source subnet, the first app subnet found that is not the source, and all
/// unassigned nodes.
fn print_source_and_app_and_unassigned_nodes(
    env: &TestEnv,
    logger: &Logger,
    source_subnet_id: SubnetId,
) {
    let topology_snapshot = env.topology_snapshot();

    info!(logger, "Source nodes:");
    topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == source_subnet_id)
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "S: {}, ip: {}", n.node_id, n.get_ip_addr());
        });

    info!(logger, "App nodes:");
    topology_snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "A: {}, ip: {}", n.node_id, n.get_ip_addr());
        });

    info!(logger, "Unassigned nodes:");
    topology_snapshot.unassigned_nodes().for_each(|n| {
        info!(logger, "U: {}, ip: {}", n.node_id, n.get_ip_addr());
    });
}

/// Create a chain key on the source subnet using the given NNS node, then
/// create a new subnet of the given size initialized with the chain key.
/// Disable signing on the source subnet and enable it on the new one.
/// Assert that the key stays the same regardless of whether signing
/// is enabled on the source subnet or the new one.
/// Return the public key for the given canister.
fn enable_chain_key_on_new_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    source_subnet_id: SubnetId,
    subnet_size: usize,
    replica_version: ReplicaVersion,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) -> BTreeMap<MasterPublicKeyId, Vec<u8>> {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let snapshot = env.topology_snapshot();
    let registry_version = snapshot.get_registry_version();

    info!(logger, "Enabling signing on the source subnet.");
    let source_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        source_subnet_id,
        key_ids.clone(),
        logger,
    );
    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();
    let registry_version = snapshot.get_registry_version();

    let unassigned_node_ids = snapshot
        .unassigned_nodes()
        .take(subnet_size)
        .map(|n| n.node_id)
        .collect();

    info!(logger, "Creating new subnet with keys.");
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        key_ids
            .iter()
            .cloned()
            .map(|key_id| (key_id, source_subnet_id.get()))
            .collect(),
        replica_version,
        logger,
    ));

    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();

    let app_subnet = snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet");

    app_subnet.nodes().for_each(|n| {
        n.await_status_is_healthy()
            .expect("Timeout while waiting for all nodes to be healthy");
    });

    info!(logger, "Disabling signing on the source subnet.");
    disable_chain_key_on_subnet(
        nns_node,
        source_subnet_id,
        canister,
        key_ids.clone(),
        logger,
    );
    let app_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        app_subnet.subnet_id,
        key_ids,
        logger,
    );

    assert_eq!(app_keys, source_keys);
    app_keys
}
