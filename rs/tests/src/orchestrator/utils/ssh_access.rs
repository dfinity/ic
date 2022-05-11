/// SSH Key Utilities
use crate::{
    nns::{
        get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_executed, vote_execute_proposal_assert_failed,
    },
    util::runtime_from_url,
};

use ic_fondue::ic_manager::IcEndpoint;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_types::{time::current_time, SubnetId};
use openssh_keys::PublicKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use pem::{encode, Pem};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use registry_canister::mutations::do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload;
use ssh2::Session;
use std::io::Read;
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

pub(crate) fn generate_key_strings() -> (String, String) {
    // Our keys are Ed25519, and not RSA. Once we figure out a direct way to encode
    // an Ed25519 private key the SSH way, we might consider switching to it.
    let rsa = Rsa::generate(1024).unwrap();
    let e = rsa.e();
    let n = rsa.n();

    let private_key = private_key_to_pem_string(&rsa);
    let public_key = public_key_to_string(e.to_vec(), n.to_vec());
    (private_key, public_key)
}

fn private_key_to_pem_string(rsa: &Rsa<Private>) -> String {
    let private_key = rsa.private_key_to_der().unwrap();
    let private_pem = Pem {
        tag: String::from("RSA PRIVATE KEY"),
        contents: private_key,
    };
    encode(&private_pem)
}

fn public_key_to_string(e: Vec<u8>, n: Vec<u8>) -> String {
    let mut key = PublicKey::from_rsa(e, n);
    key.set_comment("ci@ci.ci");
    key.to_string()
}

pub(crate) enum AuthMean {
    PrivateKey(String),
    Password(String),
    None,
}

pub(crate) struct SshSession {
    pub session: Session,
}

impl SshSession {
    pub fn new() -> Self {
        Self {
            session: Session::new().unwrap(),
        }
    }

    pub fn login(&mut self, ip: &IpAddr, username: &str, mean: &AuthMean) -> Result<(), String> {
        let ip_str = format!("[{}]:22", ip);
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

    pub fn scp_recv(&mut self, path: &Path, buf: &mut Vec<u8>) -> Result<usize, String> {
        let mut result = self
            .session
            .scp_recv(path)
            .map_err(|err| err.message().to_string())?;
        result.0.read_to_end(buf).map_err(|err| err.to_string())
    }
}

pub(crate) fn read_remote_file(
    ip: &IpAddr,
    username: &str,
    mean: &AuthMean,
    path: &Path,
) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut sess = SshSession::new();
    sess.login(ip, username, mean)?;
    sess.scp_recv(path, &mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

pub(crate) fn assert_authentication_works(ip: &IpAddr, username: &str, mean: &AuthMean) {
    SshSession::new().login(ip, username, mean).unwrap();
}

pub(crate) fn assert_authentication_fails(ip: &IpAddr, username: &str, mean: &AuthMean) {
    assert!(SshSession::new().login(ip, username, mean).is_err());
}

pub(crate) fn wait_until_authentication_is_granted(ip: &IpAddr, username: &str, mean: &AuthMean) {
    // The orchestrator updates the access keys every 10 seconds. If we are lucky,
    // this call succeeds at the first trial. If we are unlucky, it starts
    // succeeding after 10 secs.
    let deadline = current_time() + Duration::from_secs(30);
    loop {
        match SshSession::new().login(ip, username, mean) {
            Ok(_) => return,
            Err(e) if current_time() > deadline => panic!("Authentication failed: {}", e),
            _ => {}
        }
    }
}

pub(crate) fn wait_until_authentication_fails(ip: &IpAddr, username: &str, mean: &AuthMean) {
    // The orchestrator updates the access keys every 10 seconds. If we are lucky,
    // this call succeeds at the first trial. If we are unlucky, it starts
    // succeeding after 10 secs.
    let deadline = current_time() + Duration::from_secs(30);
    loop {
        match SshSession::new().login(ip, username, mean) {
            Err(_) => return,
            Ok(_) if current_time() > deadline => panic!("Authentication still succeeds"),
            _ => {}
        }
    }
}

pub(crate) fn get_updatesubnetpayload_with_keys(
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
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        advert_best_effort_percentage: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        max_instructions_per_message: None,
        max_instructions_per_round: None,
        max_instructions_per_install_code: None,
        features: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: readonly_keys,
        ssh_backup_access: backup_keys,
    }
}

pub(crate) async fn update_subnet_record(nns_endpoint: &IcEndpoint, payload: UpdateSubnetPayload) {
    let r = runtime_from_url(nns_endpoint.url.clone());
    let gov_can = get_governance_canister(&r);

    let proposal_id =
        submit_external_proposal_with_test_id(&gov_can, NnsFunction::UpdateConfigOfSubnet, payload)
            .await;

    vote_execute_proposal_assert_executed(&gov_can, proposal_id).await;
}

pub(crate) async fn fail_to_update_subnet_record(
    nns_endpoint: &IcEndpoint,
    payload: UpdateSubnetPayload,
) {
    let r = runtime_from_url(nns_endpoint.url.clone());
    let gov_can = get_governance_canister(&r);

    let proposal_id =
        submit_external_proposal_with_test_id(&gov_can, NnsFunction::UpdateConfigOfSubnet, payload)
            .await;

    vote_execute_proposal_assert_failed(&gov_can, proposal_id, "too long").await;
}

pub(crate) fn get_updateunassignednodespayload(
    readonly_keys: Option<Vec<String>>,
) -> UpdateUnassignedNodesConfigPayload {
    UpdateUnassignedNodesConfigPayload {
        ssh_readonly_access: readonly_keys,
        replica_version: None,
    }
}

pub(crate) async fn update_ssh_keys_for_all_unassigned_nodes(
    nns_endpoint: &IcEndpoint,
    payload: UpdateUnassignedNodesConfigPayload,
) {
    let r = runtime_from_url(nns_endpoint.url.clone());
    let gov_can = get_governance_canister(&r);

    let proposal_id = submit_external_proposal_with_test_id(
        &gov_can,
        NnsFunction::UpdateUnassignedNodesConfig,
        payload,
    )
    .await;

    vote_execute_proposal_assert_executed(&gov_can, proposal_id).await;
}

pub(crate) async fn fail_updating_ssh_keys_for_all_unassigned_nodes(
    nns_endpoint: &IcEndpoint,
    payload: UpdateUnassignedNodesConfigPayload,
) {
    let r = runtime_from_url(nns_endpoint.url.clone());
    let gov_can = get_governance_canister(&r);

    let proposal_id = submit_external_proposal_with_test_id(
        &gov_can,
        NnsFunction::UpdateUnassignedNodesConfig,
        payload,
    )
    .await;

    vote_execute_proposal_assert_failed(&gov_can, proposal_id, "too long").await;
}
