use std::{
    borrow::Cow,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use ic_agent::{
    agent::{Envelope, EnvelopeContent},
    Agent, Identity,
};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_crypto_tree_hash::{lookup_path, LabeledTree};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SubnetSnapshot,
        },
    },
    systest,
    util::{block_on, get_identity, UniversalCanister},
};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation, HttpReadStateResponse},
    PrincipalId, SubnetId,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use slog::info;
use time::OffsetDateTime;

/// How long to wait between subsequent nns delegation fetch requests.
const RETRY_DELAY: tokio::time::Duration = tokio::time::Duration::from_secs(60);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("Should be able to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    let (_subnet, node) = get_subnet_and_node(&env, SubnetType::Application);
    let agent = node.build_default_agent();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let _canister = UniversalCanister::new_with_params_with_retries(
            &agent,
            node.effective_canister_id(),
            /*compute_allocation= */ None,
            /*cycles= */ None,
            /*pages= */ None,
            &env.logger(),
        )
        .await;
    });
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
            New delegation timestamp: {}, \
            initial delegation timestamp: {}",
            new_delegation_timestamp,
            initial_delegation_timestamp,
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

    let timestamp: Vec<u8> =
        match lookup_path(&tree, &[b"time"]).expect("Every delegation has a '/time' path") {
            LabeledTree::Leaf(value) => value.clone(),
            LabeledTree::SubTree(_) => panic!("Not a leaf"),
        };

    Some(leb128::read::unsigned(&mut std::io::Cursor::new(&timestamp)).unwrap())
}

fn subnet_read_state_v2_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: HttpReadStateResponse = block_on(send(
        &node,
        format!("api/v2/subnet/{}/read_state", subnet.subnet_id),
        sign_envelope(&read_state_content()),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(CanisterRangesFormat::Flat),
    );
}

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
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(CanisterRangesFormat::Flat),
    );
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct SyncCallResponse {
    status: String,
    certificate: Blob,
}

fn call_v3_returns_correct_delegation(env: TestEnv) {
    let (subnet, node) = get_subnet_and_node(&env, SubnetType::Application);

    let response: SyncCallResponse = block_on(send(
        &node,
        format!("api/v3/canister/{}/call", node.effective_canister_id()),
        sign_envelope(&call_content(node.effective_canister_id())),
    ));
    let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();

    validate_delegation(
        &certificate
            .delegation
            .expect("Should have an NNS delegation attached"),
        subnet.subnet_id,
        Some(CanisterRangesFormat::Flat),
    );
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
        method_name: String::from("update"),
        arg: vec![],
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

enum CanisterRangesFormat {
    Flat,
    #[allow(dead_code)]
    Tree,
}

fn validate_delegation(
    delegation: &CertificateDelegation,
    subnet_id: SubnetId,
    canister_ranges_format: Option<CanisterRangesFormat>,
) {
    let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
        .expect("Should return a certificate which can be deserialized");
    let tree = LabeledTree::try_from(parsed_delegation.tree)
        .expect("Should return a state tree which can be parsed");

    match lookup_path(&tree, &[b"time"]).expect("Every delegation has a '/time' path") {
        LabeledTree::Leaf(value) => value.clone(),
        LabeledTree::SubTree(_) => panic!("Not a leaf"),
    };

    let flat_canister_ranges = lookup_path(
        &tree,
        &[b"subnet", subnet_id.get_ref().as_ref(), b"canister_ranges"],
    )
    .map(|tree| match tree {
        LabeledTree::Leaf(value) => value.clone(),
        LabeledTree::SubTree(_) => panic!("Not a leaf"),
    });

    let tree_canister_ranges =
        lookup_path(&tree, &[b"canister_ranges", subnet_id.get_ref().as_ref()]).map(|tree| {
            match tree {
                LabeledTree::Leaf(_) => panic!("Not a subtree"),
                LabeledTree::SubTree(sub_tree) => sub_tree.clone(),
            }
        });

    match (
        canister_ranges_format,
        flat_canister_ranges,
        tree_canister_ranges,
    ) {
        (None, None, None) => (),
        (Some(CanisterRangesFormat::Tree), None, Some(_)) => (),
        (Some(CanisterRangesFormat::Flat), Some(_), None) => (),
        (None, Some(_), _) => panic!("Should not have any canister ranges"),
        (None, _, Some(_)) => panic!("Should not have any canister ranges"),
        (Some(CanisterRangesFormat::Flat), None, _) => panic!("Flat canister ranges not found"),
        (Some(CanisterRangesFormat::Tree), _, None) => panic!("Tree canister ranges not found"),
        (Some(CanisterRangesFormat::Tree), Some(_), _) => {
            panic!("Should not have the flat canister ranges")
        }
        (Some(CanisterRangesFormat::Flat), _, Some(_)) => {
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
        .map_err(|err| format!("Request failed: {err}"))?
        .to_vec();

    if status != StatusCode::OK {
        return Err(format!(
            "Request failed. Status: {status}. Response: {}",
            String::from_utf8_lossy(&response)
        ));
    }

    serde_cbor::from_slice(&response)
        .map_err(|err| format!("Failed to deserialize response: {err}"))
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(std::time::Duration::from_secs(15 * 60))
        .add_test(systest!(nns_delegation_on_nns_test))
        .add_test(systest!(nns_delegation_on_app_subnet_test))
        .add_test(systest!(canister_read_state_v2_returns_correct_delegation))
        .add_test(systest!(subnet_read_state_v2_returns_correct_delegation))
        .add_test(systest!(call_v3_returns_correct_delegation))
        .execute_from_args()
}
