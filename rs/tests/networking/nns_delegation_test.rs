/* tag::catalog[]
Title:: NNS Delegation Tests

Goal:: Test the behavior NNS Delegations.

Runbook::
. Set up two subnets with one fast node each, send some request to them, and inspect the
  returned delegations.
. Depending on the values of `ENV_DEPS__GUESTOS_DISK_IMG_VERSION` and `ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION`
  environment variables we might upgrade the application subnet to a different version than the NNS subnet.
  Currently we run two scenarios (this is defined in the BUILD.bazel file):
  . Both subnets are running the branch version and no subnet is upgraded
  . Both subnets are initiated with the NNS mainnet version and then the Application subnet is upgraded to the
    branch version. This ensures that we can still fetch the delegations from the NNS subnet when it runs a
    different replica version when our replica's.

Success::
. NNS subnet doesn't attach any delegations to the responses.
. Application subnets refresh delegations once in a while.
. Responses to `api/v2/subnet/{subnet_id}/read_state` have valid delegations with canister ranges in the flat format.
. Responses to `api/v3/subnet/{subnet_id}/read_state` have valid delegations without any canister ranges.
. Responses to `api/v2/canister/{canister_id}/read_state` have valid delegations with canister ranges in the flat format.
. Responses to `api/v3/canister/{canister_id}/read_state` have valid delegations with canister ranges in the tree format.
. Responses to `api/v3/canister/{canister_id}/call` have valid delegations with canister ranges in the flat format.
. Responses to `api/v4/canister/{canister_id}/call` have valid delegations with canister ranges in the tree format.
. For `api/v2/canister/{canister_id}/query` we pass valid delegations with canister ranges in the flat format to the canister.
. For `api/v3/canister/{canister_id}/query` we pass valid delegations with canister ranges in the tree format to the canister.
 */
use std::{
    borrow::Cow,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use candid::{CandidType, Encode};
use ic_agent::{
    Agent, Identity,
    agent::{Envelope, EnvelopeContent},
};
use ic_certification::verify_delegation_certificate;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress,
    upgrade::{
        assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
    },
};
use ic_crypto_tree_hash::{LabeledTree, lookup_path};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::{HasIcPrepDir, TestEnv},
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SubnetSnapshot,
            get_guestos_img_version, get_guestos_update_img_sha256, get_guestos_update_img_url,
            get_guestos_update_img_version,
        },
    },
    systest,
    util::{block_on, get_identity, get_nns_node},
};
use ic_types::{
    CanisterId, Height, PrincipalId, SubnetId,
    messages::{
        Blob, Certificate, CertificateDelegation, CertificateDelegationFormat,
        HttpQueryResponseReply, HttpReadStateResponse, NodeSignature,
    },
};
use ic_utils::interfaces::ManagementCanister;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use slog::info;
use time::OffsetDateTime;

const CERTIFIED_VAR_WAT: &str = r#"
;; A canister serving a certified variable
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
  (import "ic0" "data_certificate_size" (func $data_certificate_size (result i32)))
  (import "ic0" "data_certificate_copy"
      (func $data_certificate_copy (param i32 i32 i32)))

  (func $certificate
    (local $size i32)
    (local.set $size (call $data_certificate_size))
    (i32.store (i32.const 0) (local.get $size))
    (call $data_certificate_copy
      (i32.const 0)
      (i32.const 0)
      (local.get $size))
    (call $msg_reply_data_append
      (i32.const 0)
      (local.get $size))
    (call $msg_reply))

  (memory $memory 1)
  (export "memory" (memory $memory))
  (export "canister_update certificate_as_update" (func $certificate))
  (export "canister_query certificate" (func $certificate))
)
"#;

/// How long to wait between subsequent nns delegation fetch requests.
const RETRY_DELAY: tokio::time::Duration = tokio::time::Duration::from_secs(60);

const DKG_LENGTH: Height = Height::new(9);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System).with_dkg_interval_length(DKG_LENGTH),
        )
        .add_subnet(
            Subnet::fast_single_node(SubnetType::Application).with_dkg_interval_length(DKG_LENGTH),
        )
        .setup_and_start(&env)
        .expect("Should be able to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    info!(
        env.logger(),
        "Installing certified variables canister on the Application subnet"
    );
    let (_subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let agent = node.build_default_agent();
    let management_canister = ManagementCanister::create(&agent);
    let wasm = wat::parse_str(CERTIFIED_VAR_WAT).expect("Failed to parse certified variables WAT");

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        management_canister
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(node.effective_canister_id())
            .call_and_wait()
            .await
            .expect("Failed to create the certified variables canister");

        management_canister
            .install_code(&node.effective_canister_id().0, &wasm)
            .call_and_wait()
            .await
            .expect("Failed to install the certified variables canister");
    });

    upgrade_application_subnet_if_necessary(&env);
}

fn nns_delegation_on_nns_test(env: TestEnv) {
    block_on(nns_delegation_test(env, SubnetType::System))
}

fn nns_delegation_on_app_subnet_test(env: TestEnv) {
    block_on(nns_delegation_test(env, SubnetType::Application))
}

async fn nns_delegation_test(env: TestEnv, subnet_type: SubnetType) {
    let (_subnet, node) = get_subnet_and_node(&env, subnet_type);

    let agent = node.build_default_agent_async().await;
    info!(env.logger(), "Fetching an initial NNS delegation");
    let maybe_initial_delegation_timestamp =
        get_nns_delegation_timestamp(&agent, node.effective_canister_id()).await;

    if subnet_type == SubnetType::System {
        assert!(
            maybe_initial_delegation_timestamp.is_none(),
            "There shouldn't be delegation on the NNS subnet"
        );

        // We can return, there is nothing more to be checked.
        return;
    }

    let initial_delegation_timestamp = maybe_initial_delegation_timestamp
        .expect("Non-NNS subnet should return an NNS delegation with the response");
    let initial_delegation_time = SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_nanos(
            initial_delegation_timestamp,
        ))
        .unwrap();

    info!(
        env.logger(),
        "Waiting for a new NNS delegation. Note: it could take up to 10 minutes."
    );
    loop {
        let new_delegation_timestamp =
            get_nns_delegation_timestamp(&agent, node.effective_canister_id())
                .await
                .expect("Non-NNS subnet should return an NNS delegation with the response");
        assert!(
            new_delegation_timestamp >= initial_delegation_timestamp,
            "Timestamps should be (not necessarily strictly) increasing. \
            New delegation timestamp: {new_delegation_timestamp}, \
            initial delegation timestamp: {initial_delegation_timestamp}",
        );

        if new_delegation_timestamp == initial_delegation_timestamp {
            info!(
                env.logger(),
                "The subnet is still using the old nns delegation, which is roughly {}s old. \
                Retrying in {} seconds.",
                SystemTime::now()
                    .duration_since(initial_delegation_time)
                    .unwrap()
                    .as_secs(),
                RETRY_DELAY.as_secs(),
            );
            tokio::time::sleep(RETRY_DELAY).await;
        } else {
            info!(
                env.logger(),
                "The subnet is using a new nns delegation. Success.",
            );

            break;
        }
    }
}

async fn get_nns_delegation_timestamp(
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> Option<u64> {
    let delegation = agent
        .read_state_raw(vec![vec!["time".into()]], effective_canister_id.into())
        .await
        .expect("The node is up and running and should respond to the request")
        .delegation?;

    let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
        .expect("Should return a certificate which can be deserialized");
    let tree = LabeledTree::try_from(parsed_delegation.tree)
        .expect("Should return a state tree which can be parsed");

    let timestamp: &Vec<u8> =
        match lookup_path(&tree, &[b"time"]).expect("Every delegation has a '/time' path") {
            LabeledTree::Leaf(value) => value,
            LabeledTree::SubTree(_) => panic!("Not a leaf"),
        };

    Some(leb128::read::unsigned(&mut std::io::Cursor::new(timestamp)).unwrap())
}

/// Responses to `api/v2/subnet/{subnet_id}/read_state` have valid delegations with canister ranges in the flat format.
fn subnet_read_state_v2_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!("api/v2/subnet/{}/read_state", subnet.subnet_id),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        None,
        CertificateDelegationFormat::Flat,
    );
}

/// Responses to `api/v3/subnet/{subnet_id}/read_state` have valid delegations with canister ranges in the flat format.
fn subnet_read_state_v3_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!("api/v3/subnet/{}/read_state", subnet.subnet_id),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        None,
        CertificateDelegationFormat::Pruned,
    );
}

/// Responses to `api/v2/canister/{canister_id}/read_state` have valid delegations with canister ranges in the flat format.
fn canister_read_state_v2_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!(
            "api/v2/canister/{}/read_state",
            node.effective_canister_id()
        ),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Flat,
    );
}

/// Responses to `api/v3/canister/{canister_id}/read_state` have valid delegations with canister ranges in the flat format.
fn canister_read_state_v3_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!(
            "api/v3/canister/{}/read_state",
            node.effective_canister_id()
        ),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Tree,
    );
}

/// Responses to `api/v3/canister/aaaaa-aa/read_state` have valid delegations without canister ranges.
fn canister_read_state_v3_management_canister_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!("api/v3/canister/{}/read_state", CanisterId::ic_00()),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        None,
        CertificateDelegationFormat::Pruned,
    );
}

#[derive(Deserialize)]
struct SyncCallResponse {
    #[allow(dead_code)]
    status: String,
    certificate: Blob,
}

/// Responses to `api/v3/canister/{canister_id}/call` have valid delegations with canister ranges in the flat format.
fn call_v3_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: SyncCallResponse = block_on(send(
        &node,
        format!("api/v3/canister/{}/call", node.effective_canister_id()),
        sign_envelope(&call_content(node.effective_canister_id())),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Flat,
    );
}

/// Responses to `api/v4/canister/{canister_id}/call` have valid delegations with canister ranges in the flat format.
fn call_v4_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: SyncCallResponse = block_on(send(
        &node,
        format!("api/v4/canister/{}/call", node.effective_canister_id()),
        sign_envelope(&call_content(node.effective_canister_id())),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Tree,
    );
}

/// Responses to `api/v4/canister/{canister_id}/call` targeting the management canister
/// have valid delegations without canister ranges.
fn call_v4_management_canister_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let expiration = OffsetDateTime::now_utc() + Duration::from_secs(3 * 60);

    #[derive(CandidType)]
    struct Arg {
        canister_id: PrincipalId,
    }
    // This update call is a no-op because the canister is already started, but at least
    // the call doesn't fail.
    let call_content = EnvelopeContent::Call {
        ingress_expiry: expiration.unix_timestamp_nanos() as u64,
        sender: get_identity().sender().unwrap(),
        canister_id: CanisterId::ic_00().into(),
        method_name: String::from("start_canister"),
        arg: Encode!(&Arg {
            canister_id: node.effective_canister_id()
        })
        .unwrap(),
        nonce: None,
    };

    let response: SyncCallResponse = block_on(send(
        &node,
        format!("api/v4/canister/{}/call", node.effective_canister_id()),
        sign_envelope(&call_content),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Tree,
    );
}

#[derive(Deserialize)]
struct QueryResponse {
    reply: HttpQueryResponseReply,
    #[allow(dead_code)]
    signatures: Vec<NodeSignature>,
}

/// For `api/v2/canister/{canister_id}/query` we pass valid delegations with
/// canister ranges in the flat format to the canister.
fn query_v2_passes_correct_delegation_to_canister(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let arg = vec![];

    let response: QueryResponse = block_on(send(
        &node,
        format!("api/v2/canister/{}/query", node.effective_canister_id()),
        sign_envelope(&query_content(node.effective_canister_id(), arg)),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.reply.arg).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Flat,
    );
}

/// For `api/v3/canister/{canister_id}/query` we pass valid delegations with
/// canister ranges in the tree format to the canister.
fn query_v3_passes_correct_delegation_to_canister(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let arg = vec![];

    let response: QueryResponse = block_on(send(
        &node,
        format!("api/v3/canister/{}/query", node.effective_canister_id()),
        sign_envelope(&query_content(node.effective_canister_id(), arg)),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.reply.arg).unwrap();

    validate_delegation(
        &env,
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(node.effective_canister_id()),
        CertificateDelegationFormat::Tree,
    );
}

/// Run query tests several times sequentially to check that we don't return incorrect cached response.
fn interlaced_v2_and_v3_query_requests(env: TestEnv) {
    for _ in 0..10 {
        query_v2_passes_correct_delegation_to_canister(env.clone());
        query_v3_passes_correct_delegation_to_canister(env.clone());
    }
}

fn read_state_content() -> EnvelopeContent {
    let expiration = OffsetDateTime::now_utc() + Duration::from_secs(3 * 60);
    EnvelopeContent::ReadState {
        ingress_expiry: expiration.unix_timestamp_nanos() as u64,
        sender: get_identity().sender().unwrap(),
        paths: vec![],
    }
}

fn call_content(canister_id: PrincipalId) -> EnvelopeContent {
    let expiration = OffsetDateTime::now_utc() + Duration::from_secs(3 * 60);
    EnvelopeContent::Call {
        ingress_expiry: expiration.unix_timestamp_nanos() as u64,
        sender: get_identity().sender().unwrap(),
        canister_id: canister_id.into(),
        method_name: String::from("certificate_as_update"),
        arg: vec![],
        nonce: None,
    }
}

fn query_content(canister_id: PrincipalId, arg: Vec<u8>) -> EnvelopeContent {
    let expiration = OffsetDateTime::now_utc() + Duration::from_secs(3 * 60);
    EnvelopeContent::Query {
        ingress_expiry: expiration.unix_timestamp_nanos() as u64,
        sender: get_identity().sender().unwrap(),
        canister_id: canister_id.into(),
        method_name: String::from("certificate"),
        arg,
        nonce: None,
    }
}

fn sign_envelope(content: &EnvelopeContent) -> Vec<u8> {
    let signature = get_identity().sign(content).unwrap();

    let envelope = Envelope {
        content: Cow::Borrowed(content),
        sender_pubkey: signature.public_key,
        sender_sig: signature.signature,
        sender_delegation: signature.delegations,
    };

    let mut serialized_bytes = Vec::new();
    let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
    serializer.self_describe().unwrap();
    envelope.serialize(&mut serializer).unwrap();

    serialized_bytes
}

fn validate_delegation(
    env: &TestEnv,
    delegation: &CertificateDelegation,
    subnet_id: SubnetId,
    effective_canister_id: Option<PrincipalId>,
    expected_delegation_format: CertificateDelegationFormat,
) {
    let nns_public_key = env.prep_dir("").unwrap().root_public_key().unwrap();
    verify_delegation_certificate(
        &delegation.certificate,
        &subnet_id,
        &parse_threshold_sig_key_from_der(&nns_public_key).unwrap(),
        effective_canister_id
            .map(CanisterId::unchecked_from_principal)
            .as_ref(),
        /*use_signature_cache=*/ false,
    )
    .expect("Should receive a valid delegation certificate: {err:?}");

    let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
        .expect("Should return a certificate which can be deserialized");
    let tree = LabeledTree::try_from(parsed_delegation.tree)
        .expect("Should return a state tree which can be parsed");

    match lookup_path(&tree, &[b"time"]).expect("Every delegation has a '/time' path") {
        LabeledTree::Leaf(_value) => (),
        LabeledTree::SubTree(_) => panic!("Not a leaf"),
    };

    let flat_canister_ranges = lookup_path(
        &tree,
        &[b"subnet", subnet_id.get_ref().as_ref(), b"canister_ranges"],
    )
    .map(|tree| match tree {
        LabeledTree::Leaf(value) => value,
        LabeledTree::SubTree(_) => panic!("Not a leaf"),
    });

    let tree_canister_ranges =
        lookup_path(&tree, &[b"canister_ranges", subnet_id.get_ref().as_ref()]).map(|tree| {
            match tree {
                LabeledTree::Leaf(_) => panic!("Not a subtree"),
                LabeledTree::SubTree(sub_tree) => sub_tree,
            }
        });

    match (
        expected_delegation_format,
        flat_canister_ranges,
        tree_canister_ranges,
    ) {
        (CertificateDelegationFormat::Pruned, None, None) => (),
        (CertificateDelegationFormat::Tree, None, Some(_)) => (),
        (CertificateDelegationFormat::Flat, Some(_), None) => (),
        (CertificateDelegationFormat::Pruned, Some(_), _) => {
            panic!("Should not have any canister ranges")
        }
        (CertificateDelegationFormat::Pruned, _, Some(_)) => {
            panic!("Should not have any canister ranges")
        }
        (CertificateDelegationFormat::Flat, None, _) => panic!("Flat canister ranges not found"),
        (CertificateDelegationFormat::Tree, _, None) => panic!("Tree canister ranges not found"),
        (CertificateDelegationFormat::Tree, Some(_), _) => {
            panic!("Should not have the flat canister ranges")
        }
        (CertificateDelegationFormat::Flat, _, Some(_)) => {
            panic!("Should not have the tree canister ranges")
        }
    }
}

fn get_subnet_and_node(env: &TestEnv, subnet_type: SubnetType) -> (SubnetSnapshot, IcNodeSnapshot) {
    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == subnet_type)
        .expect("There is at least one subnet of each type");
    let node = subnet
        .nodes()
        .next()
        .expect("There is at least one node on each subnet");

    (subnet, node)
}

async fn send<A>(node: &IcNodeSnapshot, endpoint: String, body: Vec<u8>) -> A
where
    A: serde::de::DeserializeOwned,
{
    const RETRIES: usize = 20;
    const SLEEP_DURATION: Duration = Duration::from_secs(3);

    for i in 0..RETRIES {
        match try_send(node, endpoint.clone(), body.clone()).await {
            Ok(response) => return response,
            Err(err) => println!("Attempt #{i}: {err}"),
        }

        tokio::time::sleep(SLEEP_DURATION).await;
    }

    panic!("Failed to send request after {RETRIES} attempts");
}

async fn try_send<A>(node: &IcNodeSnapshot, endpoint: String, body: Vec<u8>) -> Result<A, String>
where
    A: serde::de::DeserializeOwned,
{
    let response = reqwest::Client::new()
        .post(format!("http://[{}]:8080/{}", node.get_ip_addr(), endpoint))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Request failed: {err}"))?;

    let status = response.status();
    let response = response
        .bytes()
        .await
        .map_err(|err| format!("Request failed: {err}"))?;

    if status != StatusCode::OK {
        return Err(format!(
            "Request failed. Status: {status}. Response: {response:?}",
        ));
    }

    serde_cbor::from_slice(&response)
        .map_err(|err| format!("Failed to deserialize response: {err:?}. Response: {response:?}",))
}

fn upgrade_application_subnet_if_necessary(env: &TestEnv) {
    let (subnet, node) = get_subnet_and_node(env, SubnetType::Application);
    let nns_node = get_nns_node(&env.topology_snapshot());

    let initial_version = get_guestos_img_version();
    let target_version = get_guestos_update_img_version();

    if initial_version == target_version {
        info!(env.logger(), "No need to upgrade the application subnet");
        return;
    }

    info!(
        env.logger(),
        "Upgrade the application subnet from {initial_version:?} to {target_version:?} to test the protocol \
        compatibility between subnets running different replica versions."
    );

    let sha256 = get_guestos_update_img_sha256();
    let upgrade_url = get_guestos_update_img_url();

    block_on(bless_replica_version(
        &nns_node,
        &target_version,
        &env.logger(),
        sha256,
        /*guest_launch_measurements=*/ None,
        vec![upgrade_url.to_string()],
    ));

    block_on(deploy_guestos_to_all_subnet_nodes(
        &nns_node,
        &target_version,
        subnet.subnet_id,
    ));

    assert_assigned_replica_version(&node, &target_version, env.logger());
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        // We potentially upgrade the app subnet in the setup which could take several minutes
        .with_overall_timeout(std::time::Duration::from_secs(25 * 60))
        .with_timeout_per_test(std::time::Duration::from_secs(15 * 60))
        .add_test(systest!(nns_delegation_on_nns_test))
        .add_test(systest!(nns_delegation_on_app_subnet_test))
        .add_test(systest!(canister_read_state_v2_returns_correct_delegation))
        .add_test(systest!(canister_read_state_v3_returns_correct_delegation))
        .add_test(systest!(
            canister_read_state_v3_management_canister_returns_correct_delegation
        ))
        .add_test(systest!(subnet_read_state_v2_returns_correct_delegation))
        .add_test(systest!(subnet_read_state_v3_returns_correct_delegation))
        // note: the v2 call endpoint doesn't return an NNS delegation, so there is nothing to test
        .add_test(systest!(call_v3_returns_correct_delegation))
        .add_test(systest!(call_v4_returns_correct_delegation))
        .add_test(systest!(
            call_v4_management_canister_returns_correct_delegation
        ))
        .add_test(systest!(query_v2_passes_correct_delegation_to_canister))
        .add_test(systest!(query_v3_passes_correct_delegation_to_canister))
        .add_test(systest!(interlaced_v2_and_v3_query_requests))
        .execute_from_args()
}
