/// SSH Key Utilities
use anyhow::anyhow;
use ic_system_test_driver::{
    driver::test_env_api::{IcNodeSnapshot, SshSession as _},
    nns::{
        get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_executed, vote_execute_proposal_assert_failed,
    },
    retry_with_msg,
    util::runtime_from_url,
};

use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_types::SubnetId;
use openssh_keys::PublicKey;
use registry_canister::mutations::{
    do_update_ssh_readonly_access_for_all_unassigned_nodes::UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
    do_update_subnet::UpdateSubnetPayload,
};
use reqwest::Url;
use slog::Logger;
use ssh2::Session;
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    time::Duration,
};

// The orchestrator updates the access keys every 10 seconds. If we are lucky,
// this call succeeds at the first trial. If we are unlucky, it starts
// succeeding after 10 secs.
const SSH_ACCESS_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_ACCESS_BACKOFF: Duration = Duration::from_secs(5);

pub fn generate_key_strings() -> (String, String) {
    // Our keys are Ed25519, and not RSA. Once we figure out a direct way to encode
    // an Ed25519 private key the SSH way, we might consider switching to it.
    let rsa = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).expect("RSA keygen failed");
    use rsa::traits::PublicKeyParts;
    let e = rsa.e();
    let n = rsa.n();

    let private_key = private_key_to_pem_string(&rsa);
    let public_key = public_key_to_string(e.to_bytes_be(), n.to_bytes_be());

    (private_key, public_key)
}

fn private_key_to_pem_string(rsa: &rsa::RsaPrivateKey) -> String {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    rsa.to_pkcs1_pem(rsa::pkcs1::LineEnding::CRLF)
        .unwrap()
        .to_string()
}

fn public_key_to_string(e: Vec<u8>, n: Vec<u8>) -> String {
    let mut key = PublicKey::from_rsa(e, n);
    key.set_comment("ci@ci.ci");
    key.to_string()
}

pub enum AuthMean {
    PrivateKey(String),
    Password(String),
    None,
}

pub struct SshSession {
    pub session: Session,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            session: Session::new().unwrap(),
        }
    }
}

impl SshSession {
    pub fn login(&mut self, ip: &IpAddr, username: &str, mean: &AuthMean) -> Result<(), String> {
        let ip_str = format!("[{ip}]:22");
        let tcp = TcpStream::connect(ip_str).map_err(|err| err.to_string())?;
        self.session.set_tcp_stream(tcp);
        self.session.handshake().map_err(|err| err.to_string())?;

        match mean {
            AuthMean::PrivateKey(pk) => self
                .session
                .userauth_pubkey_memory(username, None, pk, None),
            AuthMean::Password(pw) => self.session.userauth_password(username, pw),
            AuthMean::None => self.session.userauth_agent(username),
        }
        .map_err(|err| err.to_string())
    }
}

pub fn assert_authentication_works(ip: &IpAddr, username: &str, mean: &AuthMean) {
    SshSession::default().login(ip, username, mean).unwrap();
}

pub fn assert_authentication_fails(ip: &IpAddr, username: &str, mean: &AuthMean) {
    assert!(SshSession::default().login(ip, username, mean).is_err());
}

pub fn wait_until_authentication_is_granted(
    logger: &Logger,
    ip: &IpAddr,
    username: &str,
    mean: &AuthMean,
) {
    retry_with_msg!(
        "Waiting until authentication is granted",
        logger.clone(),
        SSH_ACCESS_TIMEOUT,
        SSH_ACCESS_BACKOFF,
        || SshSession::default()
            .login(ip, username, mean)
            .map_err(|e| anyhow!(e))
    )
    .expect("Authentication failed");
}

pub fn wait_until_authentication_fails(
    logger: &Logger,
    ip: &IpAddr,
    username: &str,
    mean: &AuthMean,
) {
    retry_with_msg!(
        "Waiting until authentication fails",
        logger.clone(),
        SSH_ACCESS_TIMEOUT,
        SSH_ACCESS_BACKOFF,
        || {
            match SshSession::default().login(ip, username, mean) {
                Err(_) => Ok(()),
                Ok(_) => Err(anyhow!("Authentication still succeeds")),
            }
        }
    )
    .unwrap();
}

/// Disables the establiment of new SSH connections to the given node for the given account. This
/// is done by deleting the `authorized_keys` file in the corresponding directory.
/// Returns the SSH session used to to perform this operation, which can still be used to execute
/// further commands.
pub fn disable_ssh_access_to_node(
    logger: &Logger,
    node: &IcNodeSnapshot,
    account: &str,
    auth_mean: &AuthMean,
) -> Result<Session, String> {
    let session = node.block_on_ssh_session().map_err(|e| {
        format!(
            "Failed to establish SSH session to node {} ({:?}): {}",
            node.node_id,
            node.get_ip_addr(),
            e
        )
    })?;

    node.block_on_bash_script_from_session(
        &session,
        &format!("rm /var/lib/{account}/.ssh/authorized_keys"),
    )
    .map_err(|e| {
        format!(
            "Failed to disable {} SSH access on node {} ({:?}): {}",
            account,
            node.node_id,
            node.get_ip_addr(),
            e
        )
    })?;

    wait_until_authentication_fails(logger, &node.get_ip_addr(), account, auth_mean);

    Ok(session)
}

pub fn get_updatesubnetpayload_with_keys(
    subnet_id: SubnetId,
    readonly_keys: Option<Vec<String>>,
    backup_keys: Option<Vec<String>>,
) -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: readonly_keys,
        ssh_backup_access: backup_keys,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: Default::default(),
    }
}

pub async fn update_subnet_record(nns_url: Url, payload: UpdateSubnetPayload) {
    let r = runtime_from_url(nns_url, REGISTRY_CANISTER_ID.into());
    let gov_can = get_governance_canister(&r);

    let proposal_id =
        submit_external_proposal_with_test_id(&gov_can, NnsFunction::UpdateConfigOfSubnet, payload)
            .await;

    vote_execute_proposal_assert_executed(&gov_can, proposal_id).await;
}

pub async fn fail_to_update_subnet_record(nns_url: Url, payload: UpdateSubnetPayload) {
    let r = runtime_from_url(nns_url, REGISTRY_CANISTER_ID.into());
    let gov_can = get_governance_canister(&r);

    let proposal_id =
        submit_external_proposal_with_test_id(&gov_can, NnsFunction::UpdateConfigOfSubnet, payload)
            .await;

    vote_execute_proposal_assert_failed(&gov_can, proposal_id, "too long").await;
}

pub fn get_updatesshreadonlyaccesskeyspayload(
    readonly_keys: Vec<String>,
) -> UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
    UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
        ssh_readonly_keys: readonly_keys,
    }
}

pub async fn update_ssh_keys_for_all_unassigned_nodes(
    nns_url: Url,
    payload: UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
) {
    let r = runtime_from_url(nns_url, REGISTRY_CANISTER_ID.into());
    let gov_can = get_governance_canister(&r);

    let proposal_id = submit_external_proposal_with_test_id(
        &gov_can,
        NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes,
        payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&gov_can, proposal_id).await;
}

pub async fn fail_updating_ssh_keys_for_all_unassigned_nodes(
    nns_url: Url,
    payload: UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
) {
    let r = runtime_from_url(nns_url, REGISTRY_CANISTER_ID.into());
    let gov_can = get_governance_canister(&r);

    let proposal_id = submit_external_proposal_with_test_id(
        &gov_can,
        NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes,
        payload,
    )
    .await;

    vote_execute_proposal_assert_failed(&gov_can, proposal_id, "too long").await;
}

pub fn execute_bash_command(sess: &Session, command: String) -> Result<String, String> {
    let mut channel = sess
        .channel_session()
        .map_err(|e| format!("Failed to establish a new session channel: {e}"))?;
    channel
        .exec("bash")
        .map_err(|e| format!("Failed to execute bash: {e}"))?;
    channel
        .write_all(command.as_bytes())
        .map_err(|e| format!("Failed to write the command to the channel: {e}"))?;
    channel
        .flush()
        .map_err(|e| format!("Failed to flush the stream: {e}"))?;
    channel
        .send_eof()
        .map_err(|e| format!("Failed to send eof to the channel: {e}"))?;
    let mut out = String::new();
    channel
        .read_to_string(&mut out)
        .map_err(|e| format!("Failed to read from the channel: {e}"))?;
    let mut err_str = String::new();
    match channel.exit_status() {
        Ok(status) => match status {
            0 => Ok(out),
            _ => {
                channel
                    .stderr()
                    .read_to_string(&mut err_str)
                    .map_err(|e| format!("Failed to read stderr from the channel: {e}"))?;
                Err(format!(
                    "Error in: {command}\nErr code: {status}\nstdout: \n{out}\nstderr: \n{err_str}"
                ))
            }
        },
        Err(e) => {
            channel
                .stderr()
                .read_to_string(&mut err_str)
                .map_err(|e| format!("Failed to read stderr from the channel: {e}"))?;
            Err(format!(
                "Error in: {command}\nError: {e}\nstdout: \n{out}\nstderr: \n{err_str}"
            ))
        }
    }
}
