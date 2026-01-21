use anyhow::anyhow;
use candid::Principal;
use ic_consensus_system_test_utils::{
    rw_message::{can_read_msg, cannot_store_msg},
    ssh_access::AuthMean,
};
use ic_recovery::{
    admin_helper::AdminHelper,
    get_node_metrics,
    steps::{AdminStep, Step},
};
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR},
        test_env::{SshKeyGen, TestEnv},
        test_env_api::{
            IcNodeContainer, IcNodeSnapshot, SshSession, SubnetSnapshot, scp_send_to, secs,
        },
    },
    util::block_on,
};
use ic_types::SubnetId;
use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use std::{fmt::Debug, path::PathBuf};
use url::Url;

pub const READONLY_USERNAME: &str = "readonly";
pub const BACKUP_USERNAME: &str = "backup";

pub struct AdminAndUserKeys {
    pub ssh_admin_priv_key_path: PathBuf,
    pub admin_auth: AuthMean,
    pub ssh_user_priv_key_path: PathBuf,
    pub user_auth: AuthMean,
    pub ssh_user_pub_key_path: PathBuf,
    pub ssh_user_pub_key: String,
}

pub fn get_admin_keys_and_generate_readonly_keys(env: &TestEnv) -> AdminAndUserKeys {
    get_admin_keys_and_generate_keys_for_user(env, READONLY_USERNAME)
}

pub fn get_admin_keys_and_generate_backup_keys(env: &TestEnv) -> AdminAndUserKeys {
    get_admin_keys_and_generate_keys_for_user(env, BACKUP_USERNAME)
}

fn get_admin_keys_and_generate_keys_for_user(env: &TestEnv, username: &str) -> AdminAndUserKeys {
    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    let ssh_admin_priv_key_path = ssh_authorized_priv_keys_dir.join(SSH_USERNAME);
    let ssh_admin_priv_key = std::fs::read_to_string(&ssh_admin_priv_key_path)
        .expect("Failed to read admin SSH private key");
    let admin_auth = AuthMean::PrivateKey(ssh_admin_priv_key);

    // Generate a new keypair for the given username
    env.ssh_keygen_for_user(username)
        .unwrap_or_else(|_| panic!("ssh-keygen failed for {username} key"));
    let ssh_user_priv_key_path = ssh_authorized_priv_keys_dir.join(username);
    let ssh_user_priv_key = std::fs::read_to_string(&ssh_user_priv_key_path)
        .unwrap_or_else(|_| panic!("Failed to read {username} SSH private key"));
    let user_auth = AuthMean::PrivateKey(ssh_user_priv_key);

    let ssh_user_pub_key_path = ssh_authorized_pub_keys_dir.join(username);
    let ssh_user_pub_key = std::fs::read_to_string(&ssh_user_pub_key_path)
        .unwrap_or_else(|_| panic!("Failed to read {username} SSH public key"))
        .trim()
        .to_string();

    AdminAndUserKeys {
        ssh_admin_priv_key_path,
        admin_auth,
        ssh_user_priv_key_path,
        user_auth,
        ssh_user_pub_key_path,
        ssh_user_pub_key,
    }
}

/// Break the replica binary on the given nodes
pub fn break_nodes<T>(nodes: &[T], logger: &Logger)
where
    T: SshSession,
{
    info!(
        logger,
        "Breaking the subnet by breaking the replica binary on {} nodes...",
        nodes.len()
    );

    // Simulate subnet failure by breaking the replica process, but not the orchestrator
    let ssh_command =
        "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica";
    for node in nodes {
        let ip = node.get_host_ip().unwrap();
        info!(logger, "Breaking the replica on node with IP {ip}");

        node.block_on_bash_script(ssh_command)
            .unwrap_or_else(|_| panic!("SSH command failed on node with IP {ip}"));
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cursor {
    #[serde(alias = "__CURSOR")]
    pub cursor: String,
}

// Halt the given subnet by executing the corresponding ic-admin command through the given NNS URL.
// This function waits until it detects in the subnet node's journal that consensus is halted.
pub fn halt_subnet(
    admin_helper: &AdminHelper,
    subnet_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    keys: &[String],
    logger: &Logger,
) {
    info!(logger, "Halting subnet {subnet_id}...");
    let session = subnet_node.block_on_ssh_session().unwrap();
    let message_str = subnet_node
        .block_on_bash_script_from_session(
            &session,
            "journalctl -n1 -o json --output-fields='__CURSOR'",
        )
        .expect("Failed to get journal cursor");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");

    AdminStep {
        logger: logger.clone(),
        ic_admin_cmd: admin_helper.get_halt_subnet_command(subnet_id, true, keys),
    }
    .exec()
    .expect("Failed to halt subnet");

    ic_system_test_driver::retry_with_msg!(
        "check if consensus is halted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = subnet_node.block_on_bash_script_from_session(
                &session,
                &format!(
                    "journalctl --after-cursor='{}' | grep -c 'is halted'",
                    message.cursor
                ),
            );
            if res.is_ok_and(|r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                Err(anyhow!("Did not find log entry that consensus is halted"))
            }
        }
    )
    .expect("Failed to detect halted subnet");

    info!(logger, "Subnet {subnet_id} halted.");
}

// Unhalt the given subnet by executing the corresponding ic-admin command through the given NNS
// URL.
pub fn unhalt_subnet(
    admin_helper: &AdminHelper,
    subnet_id: SubnetId,
    keys: &[String],
    logger: &Logger,
) {
    info!(logger, "Unhalting subnet {subnet_id}...");
    AdminStep {
        logger: logger.clone(),
        ic_admin_cmd: admin_helper.get_halt_subnet_command(subnet_id, false, keys),
    }
    .exec()
    .expect("Failed to unhalt subnet");
    info!(logger, "Subnet {subnet_id} unhalted.");
}

/// A subnet is considered to be broken if it (potentially) still works in read mode, but doesn't
/// in write mode.
pub fn assert_subnet_is_broken(
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
            "Failed to read message on node: {node_url}"
        );
    }
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(
        cannot_store_msg(logger.clone(), node_url, can_id, msg),
        "Writing messages still successful on: {node_url}"
    );
}

/// Helper function to get the certification share height of a node with less boilerplate
pub fn get_node_certification_share_height(node: &IcNodeSnapshot, logger: &Logger) -> Option<u64> {
    block_on(get_node_metrics(logger, &node.get_ip_addr()))
        .map(|m| m.certification_share_height.get())
}

/// Select a node with highest certification share height in the given subnet snapshot
pub fn node_with_highest_certification_share_height(
    subnet: &SubnetSnapshot,
    logger: &Logger,
) -> (IcNodeSnapshot, u64) {
    subnet
        .nodes()
        .filter_map(|n| get_node_certification_share_height(&n, logger).map(|h| (n, h)))
        .max_by_key(|&(_, cert_height)| cert_height)
        .expect("No healthy node found")
}

/// Execute all recovery steps remotely, i.e. from the test driver
pub fn remote_recovery<Recovery, StepType>(recovery: Recovery, logger: &Logger)
where
    Recovery: IntoIterator<Item = (StepType, Box<dyn Step>)>,
    StepType: Debug,
{
    for (step_type, step) in recovery {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {step_type:?} failed: {e}"));
    }
}

// Sub-module for everything related to preparing CLI arguments for local recovery and transferring
// the relevant files to the target node
pub mod local {
    use std::{
        net::IpAddr,
        path::{Path, PathBuf},
    };

    use ic_recovery::{
        RecoveryArgs,
        app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs},
        nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs},
    };
    use ic_system_test_driver::driver::constants::SSH_USERNAME;
    use ic_types::NodeId;
    use ssh2::Session;

    use super::*;

    // Remote path where SSH keys will be uploaded
    const ADMIN_HOME: &str = "/var/lib/admin";
    // Remote path where guest launch measurements will be uploaded
    const GUEST_LAUNCH_MEASUREMENTS_REMOTE_PATH: &str =
        "/var/lib/ic/data/recovery/guest_launch_measurements.json";
    // Remote path where recovery output will be stored in case of a NNS recovery on same nodes
    pub const NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH: &str = "/var/lib/ic/data/recovery/output";

    // Macro to extract the flag name from an expression
    // It extracts the last part of the expression after the dot, replaces underscores with hyphens,
    // and prefixes it with "--"
    //
    // Example: extract_flag_name!(recovery_args.nns_url) -> "--nns-url"
    macro_rules! extract_flag_name {
        ($expr:expr) => {{
            "--".to_string()
                + &stringify!($expr)
                    .split('.')
                    .last()
                    .unwrap()
                    .replace('_', "-")
        }};
    }

    // Macro to generate CLI argument for a regular field
    //
    // Example: cli_arg!(recovery_args.nns_url) -> "--nns-url value_of_nns_url"
    macro_rules! cli_arg {
        ($expr:expr) => {{
            let flag = extract_flag_name!($expr);
            let escaped = $expr.to_string().replace(r#"""#, r#"\""#);
            format!(r#"{flag} "{}""#, escaped)
        }};
    }

    // Macro to generate CLI argument for a boolean field
    // If the boolean is true, it returns the flag, otherwise an empty string
    //
    // Example: bool_cli_arg!(recovery_args.test_mode) -> "--test-mode" if true, "" if false
    macro_rules! bool_cli_arg {
        ($expr:expr) => {{
            let flag = extract_flag_name!($expr);

            if *$expr {
                format!(r#"{flag}"#)
            } else {
                String::new()
            }
        }};
    }

    // Macro to generate CLI argument for an optional field
    // If the option is Some(value), it returns the flag with the value, otherwise an empty string
    //
    // Example: opt_cli_arg!(recovery_args.replica_version) -> "--replica-version value" if
    // Some(value), "" if None
    macro_rules! opt_cli_arg {
        ($expr:expr) => {{
            let flag = extract_flag_name!($expr);

            if let Some(value) = &$expr {
                let escaped = value.to_string().replace(r#"""#, r#"\""#);
                format!(r#"{flag} "{escaped}""#)
            } else {
                String::new()
            }
        }};
    }

    // Macro to generate CLI arguments for an optional vector field
    // If the option is Some(vec), it returns multiple flags with each value, otherwise an empty string
    //
    // Example: opt_vec_cli_arg!(subnet_recovery.params.skip) -> "--skip step1 --skip step2" if
    // Some(vec![step1, step2]), "" if None
    macro_rules! opt_vec_cli_arg {
        ($expr:expr) => {{
            let flag = extract_flag_name!($expr);

            if let Some(values) = &$expr {
                values
                    .iter()
                    .map(|value| {
                        let escaped = value.to_string().replace(r#"""#, r#"\""#);
                        format!(r#"{flag} "{escaped}""#)
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            }
        }};
    }

    // Uploads the given SSH key file to the target node at ADMIN_HOME/<ssh_user>_key and returns
    // the corresponding CLI argument, i.e. --<ssh_user>-key-file <remote_path>
    // If no key file is provided, returns an empty string
    fn upload_ssh_key_and_return_cli_arg(
        session: &Session,
        node_id: &NodeId,
        node_ip: &IpAddr,
        ssh_user: &str,
        maybe_key_file: Option<&Path>,
        logger: &Logger,
    ) -> String {
        let Some(key_file) = maybe_key_file else {
            return String::new();
        };

        info!(
            logger,
            "Copying the {ssh_user} key file to node {node_id} with IP {node_ip} ..."
        );

        let remote_path = PathBuf::from(ADMIN_HOME).join(format!("{ssh_user}_key"));
        scp_send_to(logger.clone(), session, key_file, &remote_path, 0o400);

        format!(r#"--{}-key-file "{}""#, ssh_user, remote_path.display())
    }

    // Converts `RecoveryArgs` into corresponding CLI arguments
    //
    // If `RecoveryArgs` is updated, it is important to update this function accordingly
    fn recovery_args_to_cli_args(
        session: &Session,
        node_id: &NodeId,
        node_ip: &IpAddr,
        logger: &Logger,
        recovery_args: &RecoveryArgs,
    ) -> String {
        let RecoveryArgs {
            dir: _, // ignored to choose the default directory in local recoveries
            nns_url,
            replica_version,
            admin_key_file,
            test_mode,
            skip_prompts,
            use_local_binaries,
        } = recovery_args;

        // Iterate through all fields of RecoveryArgs and generate the CLI arg for each
        let nns_url_cli = cli_arg!(nns_url);
        let replica_version_cli = opt_cli_arg!(replica_version);
        let admin_key_file_cli = upload_ssh_key_and_return_cli_arg(
            session,
            node_id,
            node_ip,
            SSH_USERNAME,
            admin_key_file.as_deref(),
            logger,
        );
        let test_mode_cli = bool_cli_arg!(test_mode);
        let skip_prompts_cli = bool_cli_arg!(skip_prompts);
        let use_local_binaries_cli = bool_cli_arg!(use_local_binaries);

        format!(
            r#"{nns_url_cli} \
            {replica_version_cli} \
            {admin_key_file_cli} \
            {test_mode_cli} \
            {skip_prompts_cli} \
            {use_local_binaries_cli}"#
        )
    }

    // Converts `AppSubnetRecovery` into corresponding CLI arguments
    //
    // If `AppSubnetRecoveryArgs` is updated, it is important to update this function accordingly
    pub fn app_subnet_recovery_local_cli_args(
        node: &IcNodeSnapshot,
        session: &Session,
        subnet_recovery: &AppSubnetRecovery,
        logger: &Logger,
    ) -> String {
        let node_id = node.node_id;
        let node_ip = node.get_ip_addr();

        let recovery_args_cli = recovery_args_to_cli_args(
            session,
            &node_id,
            &node_ip,
            logger,
            &subnet_recovery.recovery_args,
        );

        let subcommand_cli = "app-subnet-recovery";

        let AppSubnetRecoveryArgs {
            subnet_id,
            upgrade_version,
            upgrade_image_url,
            upgrade_image_hash,
            upgrade_image_launch_measurements_path,
            replacement_nodes,
            replay_until_height,
            readonly_pub_key,
            readonly_key_file,
            download_pool_node,
            download_state_method: _, // ignored to choose "local" in local recoveries, see below
            keep_downloaded_state,
            upload_method: _, // ignored to choose "local" in local recoveries, see below
            wait_for_cup_node,
            chain_key_subnet_id,
            next_step,
            skip,
        } = &subnet_recovery.params;

        // Iterate through all fields of AppSubnetRecoveryArgs and generate the CLI arg for each
        let subnet_id_cli = cli_arg!(subnet_id);
        let upgrade_version_cli = opt_cli_arg!(upgrade_version);
        let upgrade_image_url_cli = opt_cli_arg!(upgrade_image_url);
        let upgrade_image_hash_cli = opt_cli_arg!(upgrade_image_hash);
        let upgrade_image_launch_measurements_path =
            if let Some(measurements_path) = &upgrade_image_launch_measurements_path {
                scp_send_to(
                    logger.clone(),
                    session,
                    measurements_path.as_ref(),
                    &PathBuf::from(GUEST_LAUNCH_MEASUREMENTS_REMOTE_PATH),
                    0o400,
                );

                Some(GUEST_LAUNCH_MEASUREMENTS_REMOTE_PATH)
            } else {
                None
            };
        let upgrade_image_launch_measurements_path_cli =
            opt_cli_arg!(upgrade_image_launch_measurements_path);
        let replacement_nodes_cli = opt_vec_cli_arg!(replacement_nodes);
        let replay_until_height_cli = opt_cli_arg!(replay_until_height);
        let readonly_pub_key_cli = opt_cli_arg!(readonly_pub_key);
        let readonly_key_file_cli = upload_ssh_key_and_return_cli_arg(
            session,
            &node_id,
            &node_ip,
            READONLY_USERNAME,
            readonly_key_file.as_deref(),
            logger,
        );
        let download_pool_node_cli = opt_cli_arg!(download_pool_node);
        // We are doing a local recovery, so we override the download method to "local"
        let download_state_method_cli = r#"--download-state-method "local" "#.to_string();
        let keep_downloaded_state_cli = opt_cli_arg!(keep_downloaded_state);
        // We are doing a local recovery, so we override the upload method to "local"
        let upload_method_cli = r#"--upload-method "local" "#.to_string();
        let wait_for_cup_node_cli = opt_cli_arg!(wait_for_cup_node);
        let chain_key_subnet_id_cli = opt_cli_arg!(chain_key_subnet_id);
        let next_step_cli = opt_cli_arg!(next_step);
        let skip_cli = opt_vec_cli_arg!(skip);

        format!(
            r#"{recovery_args_cli} \
            {subcommand_cli} \
            {subnet_id_cli} \
            {upgrade_version_cli} \
            {upgrade_image_url_cli} \
            {upgrade_image_hash_cli} \
            {upgrade_image_launch_measurements_path_cli} \
            {replacement_nodes_cli} \
            {replay_until_height_cli} \
            {readonly_pub_key_cli} \
            {readonly_key_file_cli} \
            {download_pool_node_cli} \
            {download_state_method_cli} \
            {keep_downloaded_state_cli} \
            {upload_method_cli} \
            {wait_for_cup_node_cli} \
            {chain_key_subnet_id_cli} \
            {next_step_cli} \
            {skip_cli}"#
        )
    }

    // Converts `NNSRecoverySameNodes` into corresponding CLI arguments
    //
    // If `NNSRecoverySameNodesArgs` is updated, it is important to update this function accordingly
    pub fn nns_subnet_recovery_same_nodes_local_cli_args(
        node: &IcNodeSnapshot,
        session: &Session,
        subnet_recovery: &NNSRecoverySameNodes,
        logger: &Logger,
    ) -> String {
        let node_id = node.node_id;
        let node_ip = node.get_ip_addr();

        let recovery_args_cli = recovery_args_to_cli_args(
            session,
            &node_id,
            &node_ip,
            logger,
            &subnet_recovery.recovery_args,
        );

        let subcommand_cli = "nns-recovery-same-nodes";

        let NNSRecoverySameNodesArgs {
            subnet_id,
            upgrade_version,
            upgrade_image_url,
            upgrade_image_hash,
            upgrade_image_launch_measurements_path,
            add_and_bless_upgrade_version,
            replay_until_height,
            download_pool_node,
            admin_access_location: _, // ignored to choose "local" in local recoveries, see below
            keep_downloaded_state,
            wait_for_cup_node,
            backup_key_file,
            output_dir: _, // ignored to choose a different directory in local recoveries, see below
            next_step,
            skip,
        } = &subnet_recovery.params;

        // Iterate through all fields of NNSRecoverySameNodesArgs and generate the CLI arg for each
        let subnet_id_cli = cli_arg!(subnet_id);
        let upgrade_version_cli = opt_cli_arg!(upgrade_version);
        let upgrade_image_url_cli = opt_cli_arg!(upgrade_image_url);
        let upgrade_image_hash_cli = opt_cli_arg!(upgrade_image_hash);
        let upgrade_image_launch_measurements_path =
            if let Some(measurements_path) = &upgrade_image_launch_measurements_path {
                scp_send_to(
                    logger.clone(),
                    session,
                    measurements_path.as_ref(),
                    &PathBuf::from(GUEST_LAUNCH_MEASUREMENTS_REMOTE_PATH),
                    0o400,
                );

                Some(GUEST_LAUNCH_MEASUREMENTS_REMOTE_PATH)
            } else {
                None
            };
        let upgrade_image_launch_measurements_path_cli =
            opt_cli_arg!(upgrade_image_launch_measurements_path);
        let add_and_bless_upgrade_version_cli = opt_cli_arg!(add_and_bless_upgrade_version);
        let replay_until_height_cli = opt_cli_arg!(replay_until_height);
        let download_pool_node_cli = opt_cli_arg!(download_pool_node);
        // We are doing a local recovery, so we override the admin access location to "local"
        let admin_access_location_cli = r#"--admin-access-location "local" "#.to_string();
        let keep_downloaded_state_cli = opt_cli_arg!(keep_downloaded_state);
        let wait_for_cup_node_cli = opt_cli_arg!(wait_for_cup_node);
        let backup_key_file_cli = upload_ssh_key_and_return_cli_arg(
            session,
            &node_id,
            &node_ip,
            BACKUP_USERNAME,
            backup_key_file.as_deref(),
            logger,
        );
        // We are doing a local recovery, so we override the output directory
        let output_dir_cli = format!(r#"--output-dir "{NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH}""#);
        let next_step_cli = opt_cli_arg!(next_step);
        let skip_cli = opt_vec_cli_arg!(skip);

        format!(
            r#"{recovery_args_cli} \
            {subcommand_cli} \
            {subnet_id_cli} \
            {upgrade_version_cli} \
            {upgrade_image_url_cli} \
            {upgrade_image_hash_cli} \
            {upgrade_image_launch_measurements_path_cli} \
            {add_and_bless_upgrade_version_cli} \
            {replay_until_height_cli} \
            {download_pool_node_cli} \
            {admin_access_location_cli} \
            {keep_downloaded_state_cli} \
            {wait_for_cup_node_cli} \
            {backup_key_file_cli} \
            {output_dir_cli} \
            {next_step_cli} \
            {skip_cli}"#
        )
    }
}
