/* tag::catalog[]
Title:: Read State Request Tests

Goal:: Test the behavior of the read_state endpoint according to its sepcification.

Runbook::
. Set up two subnets with one fast node each

Success::
. read_state of the empty path returns the time
. The /time path returns the time
. The /subnet path returns
    . public key and canister ranges for all subnets
    . public keys of nodes on the subnet
    . no public keys of nodes on other subnets
. Malformed status requests are rejected
. Status requests for non-existant reqeusts contain an absence proof
. read_state of invalid paths are rejected
. A canister's public metadata sections can be read by
    . The canister controller
    . The anonymous identity
    . An Identity that isn't the canister controller
. A canister's private metadata sections can only be read by the canister controller.

end::catalog[] */

use anyhow::Result;
use assert_matches::assert_matches;
use canister_test::{Canister, Wasm};
use ic_agent::hash_tree::Label;
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{lookup_value, Agent, AgentError, Certificate, Identity};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::{
    agent_with_identity, agent_with_identity_mapping, block_on, get_identity,
    random_ed25519_identity, runtime_from_url,
};
use ic_system_test_driver::{
    driver::{
        boundary_node::{BoundaryNode, BoundaryNodeVm},
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot},
    },
    systest,
};
use ic_types::CanisterId;
use slog::info;
use wabt_tests::with_custom_sections;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

/// Sets up a testnet with
/// 1. System subnet with a single node
/// 2. Application subnet with a single node
/// 3. Boundary node
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    env.get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap()
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

fn get_first_app_node(env: &TestEnv) -> IcNodeSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("There should be at least one subnet for every subnet type")
        .nodes()
        .next()
        .expect("Every subnet should have at least one node")
}

async fn build_agent_with_identity(env: &TestEnv, identity: impl Identity + 'static) -> Agent {
    let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
    let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
    let url = boundary_node_vm.get_public_url();
    if boundary_node_vm.uses_dns() {
        agent_with_identity(url.as_ref(), identity).await.unwrap()
    } else {
        agent_with_identity_mapping(url.as_ref(), Some(boundary_node_vm.ipv6().into()), identity)
            .await
            .unwrap()
    }
}

/// Call "read_state" with the given paths and the basic identity
fn read_state(env: &TestEnv, paths: Vec<Vec<Label<Vec<u8>>>>) -> Result<Certificate, AgentError> {
    read_state_with_identity(env, paths, get_identity())
}

/// Call "read_state" with the given paths and identity
fn read_state_with_identity(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    identity: impl Identity + 'static,
) -> Result<Certificate, AgentError> {
    let node = get_first_app_node(env);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            let agent = build_agent_with_identity(env, identity).await;
            agent
                .read_state_raw(paths, node.effective_canister_id().into())
                .await
        })
}

fn is_http_4xx(status_code: u16) -> bool {
    (400..=499).contains(&status_code)
}

fn test_empty_paths_return_time(env: TestEnv) {
    let cert = read_state(&env, vec![]).unwrap();
    let mut value = lookup_value(&cert, vec!["time".as_bytes()]).unwrap();
    let time = leb128::read::unsigned(&mut value).unwrap();
    assert!(time > 0);
}

fn test_time_path_returns_time(env: TestEnv) {
    let path = vec!["time".into()];
    let paths = vec![path.clone()];
    let cert = read_state(&env, paths).unwrap();
    let mut value = lookup_value(&cert, path).unwrap();
    let time = leb128::read::unsigned(&mut value).unwrap();
    assert!(time > 0);
}

fn test_subnet_path(env: TestEnv) {
    let nns_subnet = env.topology_snapshot().root_subnet();
    let nns_subnet_id = nns_subnet.subnet_id;
    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_id != nns_subnet_id)
        .unwrap();
    let app_subnet_id = app_subnet.subnet_id;

    let cert = read_state(&env, vec![vec!["subnet".into()]]).unwrap();

    // Should contain public key and canister ranges for all subnets
    for subnet_id in [nns_subnet_id, app_subnet_id] {
        for path in ["public_key".as_bytes(), "canister_ranges".as_bytes()] {
            let value = lookup_value(
                &cert,
                vec!["subnet".as_bytes(), subnet_id.get_ref().as_slice(), path],
            )
            .unwrap();
            assert!(!value.is_empty());
        }
    }

    // Should not contain public keys of nodes on other subnets
    for node in nns_subnet.nodes() {
        let node_id = node.node_id;
        let value = lookup_value(
            &cert,
            vec![
                "subnet".as_bytes(),
                nns_subnet_id.get_ref().as_slice(),
                "node".as_bytes(),
                node_id.get_ref().as_slice(),
                "public_key".as_bytes(),
            ],
        );
        assert_matches!(value, Err(AgentError::LookupPathAbsent(_)));
    }

    // Should contain public keys of nodes on the subnet
    for node in app_subnet.nodes() {
        let node_id = node.node_id;
        let value = lookup_value(
            &cert,
            vec![
                "subnet".as_bytes(),
                app_subnet_id.get_ref().as_slice(),
                "node".as_bytes(),
                node_id.get_ref().as_slice(),
                "public_key".as_bytes(),
            ],
        )
        .unwrap();
        assert!(!value.is_empty());
    }
}

fn test_invalid_request_rejected(env: TestEnv) {
    for request in ["", "foo"] {
        let cert = read_state(&env, vec![vec!["request_status".into(), request.into()]]);
        assert_matches!(
            cert, Err(AgentError::HttpError(payload))
            if is_http_4xx(payload.status)
        );
    }
}

fn test_absent_request(env: TestEnv) {
    for request in [&[0; 32], &[8; 32], &[255; 32]] {
        let cert = read_state(&env, vec![vec!["request_status".into(), request.into()]]).unwrap();
        let value = lookup_value(
            &cert,
            vec!["request_status".as_bytes(), request, "status".as_bytes()],
        );
        assert_matches!(value, Err(AgentError::LookupPathAbsent(_)));
    }
}

fn test_invalid_path_rejected(env: TestEnv) {
    for request in ["", "foo"] {
        let cert = read_state(&env, vec![vec![request.into()]]);
        assert_matches!(cert, Err(AgentError::HttpError(payload)) if is_http_4xx(payload.status));
    }
}

/// Create a wasm with custom metadata sections
fn wasm_with_custom_sections(sections: Vec<(Vec<u8>, Vec<u8>)>) -> Wasm {
    Wasm::from_bytes(with_custom_sections(sections))
}

/// Look up the value of the given metadata section for the given canister
fn lookup_metadata(
    env: &TestEnv,
    canister_id: &CanisterId,
    metadata_section: &[u8],
    identity: impl Identity + 'static,
) -> Result<Vec<u8>, AgentError> {
    info!(
        env.logger(),
        "Reading canister metadata section \"{}\"",
        String::from_utf8_lossy(metadata_section)
    );
    let cid_slice = canister_id.get_ref().as_slice();
    let path: Vec<Label<Vec<u8>>> = vec![
        "canister".into(),
        cid_slice.into(),
        "metadata".into(),
        metadata_section.into(),
    ];
    let cert = read_state_with_identity(env, vec![path.clone()], identity)?;
    lookup_value(&cert, path).map(|s| s.to_vec())
}

fn test_metadata(env: TestEnv) {
    let node = get_first_app_node(&env);
    let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
    let mut canister: Canister<'_> =
        block_on(runtime.create_canister_max_cycles_with_retries()).unwrap();
    let canister_id = canister.canister_id();

    let metadata_sections = vec![
        // ASCII
        (b"test".to_vec(), b"test 1".to_vec()),
        // Non-ASCII UTF-8
        (b"\x0e2\x028\x0a1".to_vec(), b"test 2".to_vec()),
        ("☃️".as_bytes().to_vec(), b"test 3".to_vec()),
        // Empty blob
        (vec![], b"test 4".to_vec()),
        // ASCII string with spaces
        (
            b"metadata section name with spaces".to_vec(),
            b"test 5".to_vec(),
        ),
    ];

    // Create a wasm with public metadata sections
    let wasm_public = wasm_with_custom_sections(
        metadata_sections
            .iter()
            .cloned()
            .map(|(section_name, content)| {
                ([b"icp:public ".to_vec(), section_name].concat(), content)
            })
            .collect(),
    );

    // Create a wasm with private metadata sections
    let wasm_private = wasm_with_custom_sections(
        metadata_sections
            .iter()
            .cloned()
            .map(|(section_name, content)| {
                ([b"icp:private ".to_vec(), section_name].concat(), content)
            })
            .collect(),
    );

    // Install the wasm with public metadata sections first
    block_on(wasm_public.install_with_retries_onto_canister(&mut canister, None, None)).unwrap();

    // Invalid utf-8 bytes in metadata reqeust
    let cert = lookup_metadata(&env, &canister_id, &[0xff, 0xfe, 0xfd], get_identity());
    assert_matches!(cert, Err(AgentError::HttpError(payload)) if is_http_4xx(payload.status));

    // Non-existing metadata section
    let value = lookup_metadata(&env, &canister_id, "foo".as_bytes(), get_identity());
    assert_matches!(value, Err(AgentError::LookupPathAbsent(_)));

    // Existing sections
    for (section_name, expected_content) in &metadata_sections {
        // Controller identity
        let value = lookup_metadata(&env, &canister_id, section_name, get_identity()).unwrap();
        assert_eq!(&value, expected_content);

        // Anonymous identity
        let value = lookup_metadata(&env, &canister_id, section_name, AnonymousIdentity).unwrap();
        assert_eq!(&value, expected_content);

        // Non-controller identity
        let value =
            lookup_metadata(&env, &canister_id, section_name, random_ed25519_identity()).unwrap();
        assert_eq!(&value, expected_content);
    }

    // Now install the wasm with private metadata sections
    block_on(wasm_private.install_with_retries_onto_canister(&mut canister, None, None)).unwrap();

    // Existing private sections should only be readable by canister controller
    for (section_name, expected_content) in &metadata_sections {
        // Controller identity
        let value = lookup_metadata(&env, &canister_id, section_name, get_identity()).unwrap();
        assert_eq!(&value, expected_content);

        // Anonymous identity
        let res = lookup_metadata(&env, &canister_id, section_name, AnonymousIdentity);
        assert_matches!(res, Err(AgentError::HttpError(payload)) if is_http_4xx(payload.status));

        // Non-controller identity
        let res = lookup_metadata(&env, &canister_id, section_name, random_ed25519_identity());
        assert_matches!(res, Err(AgentError::HttpError(payload)) if is_http_4xx(payload.status));
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_empty_paths_return_time))
        .add_test(systest!(test_time_path_returns_time))
        .add_test(systest!(test_subnet_path))
        .add_test(systest!(test_invalid_request_rejected))
        .add_test(systest!(test_absent_request))
        .add_test(systest!(test_invalid_path_rejected))
        .add_test(systest!(test_metadata))
        .execute_from_args()?;
    Ok(())
}
