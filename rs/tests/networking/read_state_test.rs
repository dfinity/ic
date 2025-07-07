/* tag::catalog[]
Title:: Read State Request Tests

Goal:: Test the behavior of the read_state endpoint according to its specification.

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
. Status requests for non-existent requests contain an absence proof
. read_state requests of invalid paths are rejected
. A canister's public metadata sections can be read by
    . The canister controller
    . The anonymous identity
    . An Identity that isn't the canister controller
. A canister's private metadata sections can only be read by the canister controller.
. Requests for the paths /canister/C/module_hash and /canister/C/controllers succeed for
  both empty and non-empty canisters (with zero, one, and two controllers) and return correct values:
    . module_hash is absent for empty canisters;
    . module_hash is a blob for non-empty canisters;
    . controllers are always present for existing canisters and consist of a list of principals
. Read state requests for the full paths /request_status/R/status and /request_status/R/reply succeed
. Read state requests for the path /request_status/R are rejected with 403 if signed by a different
  principal than who made the original request with request ID R;
. Read state requests for two paths /request_status/R and /request_status/S with two different request
  IDs R and S are rejected with 400 (while requesting each of the two paths in isolation would succeed);

end::catalog[] */

use std::collections::BTreeSet;

use anyhow::Result;
use assert_matches::assert_matches;
use candid::{Encode, Principal};
use canister_test::{Canister, Wasm};
use ic_agent::agent::CallResponse;
use ic_agent::hash_tree::Label;
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{lookup_value, Agent, AgentError, Certificate, Identity, RequestId};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_message::ForwardParams;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::{
    agent_with_identity, block_on, get_identity, random_ed25519_identity, runtime_from_url,
    MessageCanister,
};
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot},
    },
    systest,
};
use ic_types::{CanisterId, PrincipalId};
use slog::info;

/// Encodes an unsigned integer into leb128.
fn enc_leb128(x: usize) -> Vec<u8> {
    let mut buf = [0; 1024];
    let mut writable = &mut buf[..];
    let n =
        leb128::write::unsigned(&mut writable, x.try_into().unwrap()).expect("Should write number");
    buf[..n].to_vec()
}

fn add_custom_section(mut n: Vec<u8>, mut c: Vec<u8>) -> Vec<u8> {
    let mut ret = vec![0x00];
    ret.append(&mut enc_leb128(
        enc_leb128(n.len()).len() + n.len() + c.len(),
    ));
    ret.append(&mut enc_leb128(n.len()));
    ret.append(&mut n);
    ret.append(&mut c);
    ret
}

/// Creates a valid WASM binary with the provided custom sections.
fn with_custom_sections(cs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut ret = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for nc in cs {
        ret.append(&mut add_custom_section(nc.0, nc.1));
    }
    ret
}

/// Sets up a testnet with
/// 1. System subnet with a single node
/// 2. Application subnet with a single node
/// 3. Boundary node
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    for api_bn in env.topology_snapshot().api_boundary_nodes() {
        api_bn
            .await_status_is_healthy()
            .expect("API boundary node did not come up healthy.");
    }
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
    // get an agent for the API boundary node
    let api_bn = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .expect("There should be at least one API boundary node");
    let url = api_bn.get_public_url();

    agent_with_identity(url.as_ref(), identity).await.unwrap()
}

/// Call "read_state" with the given paths and the basic identity on the first Application subnet
fn read_state(env: &TestEnv, paths: Vec<Vec<Label<Vec<u8>>>>) -> Result<Certificate, AgentError> {
    read_state_with_identity(env, paths, get_identity())
}

/// Call "read_state" with the given paths and identity on the first Application subnet
fn read_state_with_identity(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    identity: impl Identity + 'static,
) -> Result<Certificate, AgentError> {
    let node = get_first_app_node(env);
    read_state_with_identity_and_canister_id(env, paths, identity, node.effective_canister_id())
}

/// Call "read_state" with the given paths and canister ID for the default identity
fn read_state_with_canister_id(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    effective_canister_id: CanisterId,
) -> Result<Certificate, AgentError> {
    read_state_with_identity_and_canister_id(
        env,
        paths,
        get_identity(),
        effective_canister_id.get(),
    )
}

/// Call "read_state" with the given paths, identity and canister ID
fn read_state_with_identity_and_canister_id(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    identity: impl Identity + 'static,
    effective_canister_id: PrincipalId,
) -> Result<Certificate, AgentError> {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            let agent = build_agent_with_identity(env, identity).await;
            agent
                .read_state_raw(paths, effective_canister_id.into())
                .await
        })
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

    // Query the `/subnet` enpoint of the app subnet
    let path = vec!["subnet".into()];
    let cert = read_state(&env, vec![path]).unwrap();

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

    // Should not contain public keys of nodes on other subnets (the NNS)
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

    // Should contain public keys of nodes on the current subnet (the App subnet)
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
    for invalid_request_id in ["", "foo"] {
        let path = vec!["request_status".into(), invalid_request_id.into()];
        let cert = read_state(&env, vec![path]);
        assert_matches!(
            cert, Err(AgentError::HttpError(payload))
            if payload.status == 400
        );
    }
}

fn test_absent_request(env: TestEnv) {
    for absent_request_id in [&[0; 32], &[8; 32], &[255; 32]] {
        let path = vec!["request_status".into(), absent_request_id.into()];
        let cert = read_state(&env, vec![path]).unwrap();
        let value = lookup_value(
            &cert,
            vec![
                "request_status".as_bytes(),
                absent_request_id,
                "status".as_bytes(),
            ],
        );
        assert_matches!(value, Err(AgentError::LookupPathAbsent(_)));
    }
}

fn test_invalid_path_rejected(env: TestEnv) {
    for invalid_path in ["", "foo"] {
        let path = vec![invalid_path.into()];
        let cert = read_state(&env, vec![path]);
        assert_matches!(cert, Err(AgentError::HttpError(payload)) if payload.status == 404);
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

fn test_metadata_path(env: TestEnv) {
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

    // Invalid utf-8 bytes in metadata request
    let cert = lookup_metadata(&env, &canister_id, &[0xff, 0xfe, 0xfd], get_identity());
    assert_matches!(cert, Err(AgentError::HttpError(payload)) if payload.status == 400);

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
        assert_matches!(res, Err(AgentError::HttpError(payload)) if payload.status == 403);

        // Non-controller identity
        let res = lookup_metadata(&env, &canister_id, section_name, random_ed25519_identity());
        assert_matches!(res, Err(AgentError::HttpError(payload)) if payload.status == 403);
    }
}

fn test_canister_path(env: TestEnv) {
    let identities = [
        PrincipalId::from(get_identity().sender().unwrap()),
        PrincipalId::from(random_ed25519_identity().sender().unwrap()),
    ];

    let node = get_first_app_node(&env);
    let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());

    // Create an empty canister
    let empty_canister: Canister<'_> =
        block_on(runtime.create_canister_max_cycles_with_retries()).unwrap();

    // Create a canister with some installed WASM
    let mut installed_canister: Canister<'_> =
        block_on(runtime.create_canister_max_cycles_with_retries()).unwrap();
    let wasm = wasm_with_custom_sections(vec![]);
    block_on(wasm.install_with_retries_onto_canister(&mut installed_canister, None, None)).unwrap();

    // Test /module_hash and /controllers paths by setting canister controllers to:
    // 1. [default_identity, random_identity]
    // 2. [default_identity]
    // 3. []
    // Identities must be ordered such that the default identity (the one sending updates/requests)
    // is removed last. Otherwise, it would fail to remove itself as the last controller.
    for i in [2, 1, 0] {
        let controllers = identities[..i].to_vec();

        // Test `module_hash` and `controllers` endpoints for both canisters
        test_module_hash_and_controllers(&env, &empty_canister, controllers.clone(), |res| {
            // Empty canister should not have a module hash
            matches!(res, Err(AgentError::LookupPathAbsent(_)))
        });
        test_module_hash_and_controllers(&env, &installed_canister, controllers, |res| {
            // Installed canister should have a module hash
            !res.unwrap().is_empty()
        });
    }
}

fn test_module_hash_and_controllers<F>(
    env: &TestEnv,
    canister: &Canister<'_>,
    controllers: Vec<PrincipalId>,
    assert_module_hash: F,
) where
    F: FnOnce(Result<&[u8], AgentError>) -> bool,
{
    let canister_id = canister.canister_id();
    info!(
        env.logger(),
        "Setting controllers of {} to {:?}", canister_id, controllers
    );
    block_on(canister.set_controllers(controllers.clone())).unwrap();

    let module_hash_path = vec![
        "canister".into(),
        canister_id.get_ref().as_slice().into(),
        "module_hash".into(),
    ];
    let cert =
        read_state_with_canister_id(env, vec![module_hash_path.clone()], canister_id).unwrap();
    let value = lookup_value(&cert, module_hash_path);
    assert!(assert_module_hash(value));

    let controllers_path = vec![
        "canister".into(),
        canister_id.get_ref().as_slice().into(),
        "controllers".into(),
    ];
    let cert =
        read_state_with_canister_id(env, vec![controllers_path.clone()], canister_id).unwrap();
    let value = lookup_value(&cert, controllers_path).unwrap();
    let controllers_read_state: Vec<PrincipalId> =
        serde_cbor::from_slice(value).expect("Failed to decode CBOR");

    // The returned controllers should be equal to what we set them to
    assert_eq!(controllers_read_state.len(), controllers.len());
    assert_eq!(
        BTreeSet::from_iter(controllers_read_state),
        BTreeSet::from_iter(controllers)
    );
}

/// Make an update call by forwarding a "raw_rand" request through the message canister
fn make_update_call(agent: &Agent, canister_id: &Principal) -> (RequestId, Vec<u8>) {
    let update = agent
        .update(canister_id, "forward")
        .with_arg(
            Encode!(&ForwardParams {
                receiver: Principal::management_canister(),
                method: "raw_rand".to_string(),
                cycles: u64::MAX.into(),
                payload: Encode!().unwrap(),
            })
            .unwrap(),
        )
        .sign()
        .unwrap();

    let request_id = update.request_id;
    let CallResponse::Response(result) =
        block_on(agent.update_signed(*canister_id, update.signed_update)).unwrap()
    else {
        panic!("Failed to get response");
    };

    (request_id, result)
}

fn test_request_path(env: TestEnv) {
    let node = get_first_app_node(&env);
    let effective_canister_id = node.effective_canister_id();
    let agent = node.build_default_agent();

    let canister_id = block_on(async {
        let mcan = MessageCanister::new_with_cycles(&agent, effective_canister_id, u128::MAX).await;
        mcan.canister_id()
    });

    let (request_id, result) = make_update_call(&agent, &canister_id);

    // Status should be "replied"
    let status_path = vec![
        "request_status".into(),
        (*request_id).into(),
        "status".into(),
    ];
    let cert = read_state(&env, vec![status_path.clone()]).unwrap();
    let value = lookup_value(&cert, status_path).unwrap();
    assert_eq!(
        String::from("replied"),
        String::from_utf8(value.to_vec()).unwrap()
    );

    let reply_path = vec![
        "request_status".into(),
        (*request_id).into(),
        "reply".into(),
    ];
    let cert = read_state(&env, vec![reply_path.clone()]).unwrap();
    let value = lookup_value(&cert, reply_path).unwrap();
    // Sanity check that at least 32 bytes were returned
    assert!(value.len() > 32);
    assert_eq!(value.to_vec(), result);
}

fn test_request_path_access(env: TestEnv) {
    let node = get_first_app_node(&env);
    let effective_canister_id = node.effective_canister_id();
    let agent = node.build_default_agent();

    let canister_id = block_on(async {
        let mcan = MessageCanister::new_with_cycles(&agent, effective_canister_id, u128::MAX).await;
        mcan.canister_id()
    });

    let (request_id1, _) = make_update_call(&agent, &canister_id);
    let (request_id2, _) = make_update_call(&agent, &canister_id);

    for request_id in [request_id1, request_id2] {
        let paths = vec![vec!["request_status".into(), (*request_id).into()]];

        // Lookup should succeed for default identity
        let result = read_state_with_identity(&env, paths.clone(), get_identity());
        assert!(result.is_ok());

        // Lookup should fail for identity that didn't make the request
        let result = read_state_with_identity(&env, paths, random_ed25519_identity());
        assert_matches!(result, Err(AgentError::HttpError(payload)) if payload.status == 403);
    }

    let (request_id2, _) = make_update_call(&agent, &canister_id);
    // Reading both requests at the same time should fail
    let paths = vec![
        vec!["request_status".into(), (*request_id1).into()],
        vec!["request_status".into(), (*request_id2).into()],
    ];
    let result = read_state_with_identity(&env, paths.clone(), get_identity());
    assert_matches!(result, Err(AgentError::HttpError(payload)) if payload.status == 400);
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
        .add_test(systest!(test_metadata_path))
        .add_test(systest!(test_canister_path))
        .add_test(systest!(test_request_path))
        .add_test(systest!(test_request_path_access))
        .execute_from_args()?;
    Ok(())
}
