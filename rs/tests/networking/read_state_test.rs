/* tag::catalog[]
Title:: Read State Request Tests

Goal:: Test the behavior of the read_state endpoint according to its specification.

Runbook::
. Set up two subnets with one fast node each and an api boundary node

Success::
. /api/{v2,v3}/{subnet,canister}/.../read_state of the empty path returns the time
. The /time path returns the time at /api/{v2,v3}/{subnet,canister}/.../read_state
. /api/{v2,v3}/{subnet,canister}/.../read_state of the /subnet path returns
    . public key and canister ranges for all subnets
    . public keys of nodes on the subnet
    . no public keys of nodes on other subnets
. Malformed status requests are rejected by /api/{v2,v3}/canister/.../read_state
. Status requests for non-existent requests contain an absence proof by /api/{v2,v3}/canister/.../read_state
. /api/{v2,v3}/canister/.../read_state requests of invalid paths are rejected
. A canister's public metadata sections can be read by
    . The canister controller
    . The anonymous identity
    . An Identity that isn't the canister controller
  at /api/{v2,v3}/canister/.../read_state endpoints.
. A canister's private metadata sections can only be read by the canister controller.
. /api/{v2,v3}/canister/.../read_state requests for the paths /canister/C/module_hash and /canister/C/controllers succeed for
  both empty and non-empty canisters (with zero, one, and two controllers) and return correct values:
    . module_hash is absent for empty canisters;
    . module_hash is a blob for non-empty canisters;
    . controllers are always present for existing canisters and consist of a list of principals
. /api/{v2,v3}/canister/.../read_state requests for the full paths /request_status/R/status and /request_status/R/reply succeed
. /api/{v2,v3}/canister/.../read_state requests for the path /request_status/R are rejected with 403 if signed by a different
  principal than who made the original request with request ID R;
. /api/{v2,v3}/canister/.../read_state requests for two paths /request_status/R and /request_status/S with two different request
  IDs R and S are rejected with 400 (while requesting each of the two paths in isolation would succeed);
. Read state requests at `/api/{v2,v3}/subnet/{subnet_id}/read_state` for the path `/canister_ranges/{subnet_id}`
  succeed and return a correct list of canister ranges assigned to the subnet.
. Read state requests at `/api/{v2,v3}/canister/{canister_id}/read_state` for the path `/canister_ranges/{subnet_id}`
  should fail because the path is disallowed.
end::catalog[] */

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::panic;
use std::time::Duration;

use anyhow::Result;
use assert_matches::assert_matches;
use candid::{Encode, Principal};
use canister_test::{Canister, CanisterInstallMode, Wasm};
use ic_agent::agent::{CallResponse, Envelope, EnvelopeContent};
use ic_agent::agent_error::HttpErrorPayload;
use ic_agent::hash_tree::{Label, LookupResult, SubtreeLookupResult};
use ic_agent::identity::AnonymousIdentity;
use ic_agent::{Agent, AgentError, Certificate, Identity, RequestId, lookup_value};
use ic_certification::{verify_certificate, verify_certificate_for_subnet_read_state};
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_http_endpoints_public::read_state;
use ic_message::ForwardParams;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::test_env::HasIcPrepDir;
use ic_system_test_driver::driver::test_env_api::SubnetSnapshot;
use ic_system_test_driver::util::{
    MessageCanister, block_on, get_identity, random_ed25519_identity, runtime_from_url,
};
use ic_system_test_driver::{
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot},
    },
    systest,
};
use ic_types::messages::{Blob, HttpReadStateResponse};
use ic_types::{CanisterId, PrincipalId};
use reqwest::StatusCode;
use serde::Serialize;
use slog::info;
use time::OffsetDateTime;
use url::Url;

/// Encodes an unsigned integer into its binary representation using `leb128`.
fn enc_leb128(x: usize) -> Vec<u8> {
    let mut buf = [0; 1024];
    let mut writable = &mut buf[..];
    let num_bytes =
        leb128::write::unsigned(&mut writable, x.try_into().unwrap()).expect("Should write number");
    buf[..num_bytes].to_vec()
}

struct CustomSection {
    name: Vec<u8>,
    content: Vec<u8>,
}

/// Encodes a WASM custom section with a given name and content into its binary representation,
/// following the WebAssembly standard: https://webassembly.github.io/spec/core/binary/modules.html#custom-section
fn encode_custom_section(custom_section: CustomSection) -> Vec<u8> {
    let mut name = custom_section.name;
    let mut content = custom_section.content;
    let mut name_len_leb128 = enc_leb128(name.len());
    let mut section_len_leb128 = enc_leb128(name_len_leb128.len() + name.len() + content.len());
    let mut buf = vec![0x00]; // Custom sections have the id 0.
    buf.append(&mut section_len_leb128);
    buf.append(&mut name_len_leb128);
    buf.append(&mut name);
    buf.append(&mut content);
    buf
}

/// Creates a valid WASM binary with the provided custom sections.
fn wasm_with_custom_sections(custom_sections: Vec<CustomSection>) -> Wasm {
    // We start with the trivial WASM represented as `(module)` in the WebAssembly textual representation (WAT)
    let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // and append the binary representations of the individual custom sections
    // (which are self-contained and can thus be simply appended).
    for custom_section in custom_sections {
        buf.append(&mut encode_custom_section(custom_section));
    }
    Wasm::from_bytes(buf)
}

/// Sets up a testnet with
/// 1. System subnet with a single node
/// 2. Application subnet with a single node
/// 3. Boundary node
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
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
    get_first_app_subnet(env)
        .nodes()
        .next()
        .expect("Every subnet should have at least one node")
}

fn get_first_app_subnet(env: &TestEnv) -> SubnetSnapshot {
    get_both_app_subnets(env).0
}

fn get_both_app_subnets(env: &TestEnv) -> (SubnetSnapshot, SubnetSnapshot) {
    let app_subnets: Vec<_> = env
        .topology_snapshot()
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect();

    assert_eq!(
        app_subnets.len(),
        2,
        "There should be exactly two Application subnets"
    );

    (app_subnets[0].clone(), app_subnets[1].clone())
}

/// Call "read_state" with the given paths and the basic identity on the first Application subnet
fn read_state(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    endpoint: Endpoint,
) -> Result<Certificate, AgentError> {
    read_state_with_identity(env, paths, endpoint, get_identity())
}

/// Call "read_state" with the given paths and the identity on the first Application subnet
fn read_state_with_identity(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    endpoint: Endpoint,
    identity: impl Identity,
) -> Result<Certificate, AgentError> {
    let principal_id = match &endpoint {
        Endpoint::CanisterReadState(_version) => get_first_app_node(env).effective_canister_id(),
        Endpoint::SubnetReadState(_version) => get_first_app_subnet(env).subnet_id.get(),
    };

    read_state_with_identity_and_principal_id(env, paths, endpoint, identity, principal_id)
}

fn read_state_with_identity_and_principal_id(
    env: &TestEnv,
    paths: Vec<Vec<Label<Vec<u8>>>>,
    endpoint: Endpoint,
    identity: impl Identity,
    principal_id: PrincipalId,
) -> Result<Certificate, AgentError> {
    let subnet = get_first_app_subnet(env);
    let node = get_first_app_node(env);
    let api_boundary_node = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .expect("There should be at least one API boundary node");

    let node_url = match endpoint {
        Endpoint::CanisterReadState(read_state::canister::Version::V2)
        | Endpoint::SubnetReadState(read_state::subnet::Version::V2) => {
            api_boundary_node.get_public_url()
        }
        // TODO(CON-1586): switch to api_boundary_node once the endpoints are
        // allowlisted by the boundary nodes.
        Endpoint::CanisterReadState(read_state::canister::Version::V3)
        | Endpoint::SubnetReadState(read_state::subnet::Version::V3) => node.get_public_url(),
    };

    let certificate = endpoint.read_state(node_url, paths, principal_id, identity)?;

    let nns_public_key =
        parse_threshold_sig_key_from_der(&env.prep_dir("").unwrap().root_public_key().unwrap())
            .unwrap();

    match endpoint {
        Endpoint::CanisterReadState(_version) => {
            verify_certificate(
                &certificate,
                &CanisterId::unchecked_from_principal(principal_id),
                &nns_public_key,
            )
            .unwrap();
        }
        Endpoint::SubnetReadState(_version) => {
            verify_certificate_for_subnet_read_state(
                &certificate,
                &subnet.subnet_id,
                &nns_public_key,
            )
            .unwrap();
        }
    };

    let certificate: Certificate = serde_cbor::from_slice(&certificate).unwrap();

    Ok(certificate)
}

fn test_empty_paths_return_time(env: TestEnv, endpoint: Endpoint) {
    let cert = read_state(&env, vec![], endpoint).expect("Valid request");
    let mut value = lookup_value(&cert, vec!["time".as_bytes()]).unwrap();
    let time = leb128::read::unsigned(&mut value).unwrap();
    assert!(time > 0);
}

fn test_time_path_returns_time(env: TestEnv, endpoint: Endpoint) {
    let path = vec!["time".into()];
    let paths = vec![path.clone()];
    let cert = read_state(&env, paths, endpoint).expect("Valid request");
    let mut value = lookup_value(&cert, path).unwrap();
    let time = leb128::read::unsigned(&mut value).unwrap();
    assert!(time > 0);
}

fn test_subnet_path(env: TestEnv, endpoint: Endpoint) {
    let nns_subnet = env.topology_snapshot().root_subnet();
    let nns_subnet_id = nns_subnet.subnet_id;
    let (app_subnet, other_app_subnet) = get_both_app_subnets(&env);
    let app_subnet_id = app_subnet.subnet_id;

    // Query the `/subnet` enpoint of the app subnet
    let path = vec!["subnet".into()];
    let cert = read_state(&env, vec![path], endpoint).expect("Valid request");

    for subnet_id in [nns_subnet_id, app_subnet_id] {
        let value = lookup_value(
            &cert,
            vec![
                "subnet".as_bytes(),
                subnet_id.get_ref().as_slice(),
                "public_key".as_bytes(),
            ],
        )
        .expect("Should contain public key for all subnets");
        assert!(!value.is_empty());
    }

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
        assert_matches!(
            value,
            Err(AgentError::LookupPathAbsent(_)),
            "Should not contain public keys of nodes on other subnets (the NNS)"
        );
    }

    for node in other_app_subnet.nodes() {
        let node_id = node.node_id;
        let value = lookup_value(
            &cert,
            vec![
                "subnet".as_bytes(),
                other_app_subnet.subnet_id.get_ref().as_slice(),
                "node".as_bytes(),
                node_id.get_ref().as_slice(),
                "public_key".as_bytes(),
            ],
        );
        assert_matches!(
            value,
            Err(AgentError::LookupPathAbsent(_) | AgentError::LookupPathUnknown(_)),
            "Should not contain public keys of nodes on other subnets (the App subnet)"
        );
    }

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
        .expect("Should contain public keys of nodes on the current subnet (the App subnet)");
        assert!(!value.is_empty());
    }
}

fn test_invalid_request_rejected(env: TestEnv, endpoint: Endpoint) {
    for invalid_request_id in ["", "foo"] {
        let path = vec!["request_status".into(), invalid_request_id.into()];
        let error = read_state(&env, vec![path], endpoint).expect_err("Invalid request");
        match endpoint {
            Endpoint::CanisterReadState(_version) => {
                assert_matches!(
                    error,
                    AgentError::HttpError(error) if error.status == StatusCode::BAD_REQUEST.as_u16(),
                    "Invalid request id"
                )
            }
            Endpoint::SubnetReadState(_version) => {
                assert_matches!(
                    error,
                    AgentError::HttpError(error) if error.status == StatusCode::NOT_FOUND.as_u16(),
                    "request_status is not allowed on subnet read_state endpoint"
                )
            }
        }
    }
}

fn test_absent_request(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
    for absent_request_id in [&[0; 32], &[8; 32], &[255; 32]] {
        let path = vec!["request_status".into(), absent_request_id.into()];
        let cert = read_state(&env, vec![path], endpoint).expect("Valid request");
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

// The paths `/` (root), `/<>` (empty label), and `/<foo>` are invalid.
fn test_invalid_path_rejected(env: TestEnv, endpoint: Endpoint) {
    for invalid_path in [vec![], vec!["".into()], vec!["foo".into()]] {
        let error =
            read_state(&env, vec![invalid_path.clone()], endpoint).expect_err("Invalid request");
        assert_matches!(
            error,
            AgentError::HttpError(error) if error.status == StatusCode::NOT_FOUND.as_u16(),
            "{invalid_path:?} is not allowed"
        )
    }
}

/// Look up the value of the given metadata section for the given canister
fn lookup_metadata(
    env: &TestEnv,
    canister_id: &CanisterId,
    metadata_section: &[u8],
    identity: impl Identity + 'static,
    endpoint: Endpoint,
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
    let cert = read_state_with_identity_and_principal_id(
        env,
        vec![path.clone()],
        endpoint,
        identity,
        canister_id.get(),
    )?;
    lookup_value(&cert, path).map(|s| s.to_vec())
}

// The following system test is included here because it requires ability to craft an invalid custom section name
// using `wasm_with_custom_sections`.
fn test_non_utf8_metadata(env: TestEnv) {
    let node = get_first_app_node(&env);
    let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
    let mut canister: Canister<'_> =
        block_on(runtime.create_canister_max_cycles_with_retries()).unwrap();

    let non_utf8_vec = b"\xe2\x28\xa1".to_vec();
    assert!(String::from_utf8(non_utf8_vec.clone()).is_err());

    let custom_section = CustomSection {
        name: non_utf8_vec,
        content: b"test".to_vec(),
    };

    // Create a wasm with non UTF-8 custom section name.
    let wasm = wasm_with_custom_sections(vec![custom_section]);

    // Installing the wasm fails
    let err = block_on(wasm.install_onto_canister(
        &mut canister,
        CanisterInstallMode::Install,
        None,
        None,
    ))
    .unwrap_err();
    assert!(err.contains("Canister's Wasm module is not valid"));
}

fn test_metadata_path(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
    let node = get_first_app_node(&env);
    let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
    let mut canister: Canister<'_> =
        block_on(runtime.create_canister_max_cycles_with_retries()).unwrap();
    let canister_id = canister.canister_id();

    let non_ascii_vec = "☃️".as_bytes().to_vec();
    let non_ascii_str = String::from_utf8(non_ascii_vec.clone()).unwrap();
    assert!(!non_ascii_str.is_ascii());

    let metadata_sections = vec![
        // ASCII
        (b"test".to_vec(), b"test 1".to_vec()),
        // Non-ASCII UTF-8
        (non_ascii_vec, b"test 2".to_vec()),
        // Empty blob
        (vec![], b"test 3".to_vec()),
        // ASCII string with spaces
        (
            b"metadata section name with spaces".to_vec(),
            b"test 4".to_vec(),
        ),
    ];

    // Create a wasm with public metadata sections
    let wasm_public = wasm_with_custom_sections(
        metadata_sections
            .iter()
            .cloned()
            .map(|(section_name, content)| CustomSection {
                name: [b"icp:public ".to_vec(), section_name].concat(),
                content,
            })
            .collect(),
    );

    // Create a wasm with private metadata sections
    let wasm_private = wasm_with_custom_sections(
        metadata_sections
            .iter()
            .cloned()
            .map(|(section_name, content)| CustomSection {
                name: [b"icp:private ".to_vec(), section_name].concat(),
                content,
            })
            .collect(),
    );

    // Install the wasm with public metadata sections first
    block_on(wasm_public.install_with_retries_onto_canister(&mut canister, None, None)).unwrap();

    // Invalid utf-8 bytes in metadata request
    let non_utf8 = [0xff, 0xfe, 0xfd];
    assert!(String::from_utf8(non_utf8.to_vec()).is_err());
    let cert = lookup_metadata(&env, &canister_id, &non_utf8, get_identity(), endpoint);
    assert_matches!(cert, Err(AgentError::HttpError(payload)) if payload.status == 400);

    // Non-existing metadata section
    let value = lookup_metadata(
        &env,
        &canister_id,
        "foo".as_bytes(),
        get_identity(),
        endpoint,
    );
    assert_matches!(value, Err(AgentError::LookupPathAbsent(_)));

    // Existing sections
    for (section_name, expected_content) in &metadata_sections {
        // Controller identity
        let value =
            lookup_metadata(&env, &canister_id, section_name, get_identity(), endpoint).unwrap();
        assert_eq!(&value, expected_content);

        // Anonymous identity
        let value = lookup_metadata(
            &env,
            &canister_id,
            section_name,
            AnonymousIdentity,
            endpoint,
        )
        .unwrap();
        assert_eq!(&value, expected_content);

        // Non-controller identity
        let value = lookup_metadata(
            &env,
            &canister_id,
            section_name,
            random_ed25519_identity(),
            endpoint,
        )
        .unwrap();
        assert_eq!(&value, expected_content);
    }

    // Now install the wasm with private metadata sections
    block_on(wasm_private.install_with_retries_onto_canister(&mut canister, None, None)).unwrap();

    // Existing private sections should only be readable by canister controller
    for (section_name, expected_content) in &metadata_sections {
        // Controller identity
        let value =
            lookup_metadata(&env, &canister_id, section_name, get_identity(), endpoint).unwrap();
        assert_eq!(&value, expected_content);

        // Anonymous identity
        let res = lookup_metadata(
            &env,
            &canister_id,
            section_name,
            AnonymousIdentity,
            endpoint,
        );
        assert_matches!(res, Err(AgentError::HttpError(payload)) if payload.status == 403);

        // Non-controller identity
        let res = lookup_metadata(
            &env,
            &canister_id,
            section_name,
            random_ed25519_identity(),
            endpoint,
        );
        assert_matches!(res, Err(AgentError::HttpError(payload)) if payload.status == 403);
    }
}

fn test_canister_path(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
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
    let expected_module_hash = wasm.sha256_hash();
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
        test_module_hash_and_controllers(
            &env,
            endpoint,
            &empty_canister,
            controllers.clone(),
            |res| {
                // Empty canister should not have a module hash
                matches!(res, Err(AgentError::LookupPathAbsent(_)))
            },
        );
        test_module_hash_and_controllers(&env, endpoint, &installed_canister, controllers, |res| {
            // Installed canister should have a module hash
            res.unwrap() == expected_module_hash
        });
    }
}

fn test_module_hash_and_controllers<F>(
    env: &TestEnv,
    endpoint: Endpoint,
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
    let cert = read_state_with_identity_and_principal_id(
        env,
        vec![module_hash_path.clone()],
        endpoint,
        get_identity(),
        canister_id.get(),
    )
    .unwrap();
    let value = lookup_value(&cert, module_hash_path);
    assert!(assert_module_hash(value));

    let controllers_path = vec![
        "canister".into(),
        canister_id.get_ref().as_slice().into(),
        "controllers".into(),
    ];
    let cert = read_state_with_identity_and_principal_id(
        env,
        vec![controllers_path.clone()],
        endpoint,
        get_identity(),
        canister_id.get(),
    )
    .unwrap();
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
                cycles: 0,
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

fn test_request_path(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
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
    let cert = read_state(&env, vec![status_path.clone()], endpoint).unwrap();
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
    let cert = read_state(&env, vec![reply_path.clone()], endpoint).unwrap();
    let value = lookup_value(&cert, reply_path).unwrap();
    // Sanity check that at least 32 bytes were returned
    assert!(value.len() > 32);
    assert_eq!(value.to_vec(), result);
}

fn test_request_path_access(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
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
        let result = read_state_with_identity(&env, paths.clone(), endpoint, get_identity());
        assert!(result.is_ok());

        // Lookup should fail for identity that didn't make the request
        let result = read_state_with_identity(&env, paths, endpoint, random_ed25519_identity());
        assert_matches!(result, Err(AgentError::HttpError(payload)) if payload.status == 403);
    }

    // Reading both requests (to the same canister) at the same time should fail
    let paths = vec![
        vec!["request_status".into(), (*request_id1).into()],
        vec!["request_status".into(), (*request_id2).into()],
    ];
    let result = read_state_with_identity(&env, paths.clone(), endpoint, get_identity());
    assert_matches!(result, Err(AgentError::HttpError(payload)) if payload.status == 400);

    // Reading both requests (to different canisters) at the same time should fail
    let another_canister_id = block_on(async {
        let mcan = MessageCanister::new_with_cycles(&agent, effective_canister_id, u128::MAX).await;
        mcan.canister_id()
    });
    let (request_id2, _) = make_update_call(&agent, &another_canister_id);
    let paths = vec![
        vec!["request_status".into(), (*request_id1).into()],
        vec!["request_status".into(), (*request_id2).into()],
    ];
    let result = read_state_with_identity(&env, paths.clone(), endpoint, get_identity());
    assert_matches!(result, Err(AgentError::HttpError(payload)) if payload.status == 400);
}

/// Queries the `api/{v2,v3}/canister/{canister_id}/read_state` endpoint for the canister ranges,
/// and makes sure the requests fails.
fn test_canister_canister_ranges_paths(env: TestEnv, version: read_state::canister::Version) {
    let endpoint = Endpoint::CanisterReadState(version);
    let subnet = get_first_app_subnet(&env);

    let path: Vec<Label<Vec<u8>>> = vec![
        "canister_ranges".into(),
        subnet.subnet_id.get_ref().as_slice().into(),
    ];

    let err = read_state(&env, vec![path.clone()], endpoint).expect_err(
        "/canister_ranges path should not be fetchable from \
        the /api/v2/canister/<canister_id>/read_state endpoint",
    );

    assert_matches!(err, AgentError::HttpError(payload) if payload.status == 404);
}

/// Queries the `api/{v2,v3}/subnet/{subnet_id}/read_state` endpoint for the canister ranges.
/// and compares the result with the canister ranges obtained from the registry.
fn test_subnet_canister_ranges_paths(env: TestEnv, version: read_state::subnet::Version) {
    let endpoint = Endpoint::SubnetReadState(version);
    let subnet = get_first_app_subnet(&env);

    let path: Vec<Label<Vec<u8>>> = vec![
        "canister_ranges".into(),
        subnet.subnet_id.get_ref().as_slice().into(),
    ];

    let cert = read_state(&env, vec![path.clone()], endpoint).expect("Failed to read state");

    validate_canister_ranges(&subnet, &path, &cert);
}

/// Checks that requesting the deprecated canister ranges path (/subnet/{subnet_id}/canister_ranges)
/// doesn't work on the v3 endpoints, except when subnet_id == nns_subnet_id.
fn test_deprecated_subnet_canister_ranges_paths(env: TestEnv, endpoint: Endpoint) {
    let should_accept_deprecated_canister_ranges_path = match endpoint {
        Endpoint::CanisterReadState(read_state::canister::Version::V2)
        | Endpoint::SubnetReadState(read_state::subnet::Version::V2) => true,
        Endpoint::CanisterReadState(read_state::canister::Version::V3)
        | Endpoint::SubnetReadState(read_state::subnet::Version::V3) => false,
    };

    let app_subnet = get_first_app_subnet(&env);
    let app_subnet_id_label = Label::<Vec<u8>>::from(app_subnet.subnet_id.get_ref().as_slice());
    let deprecated_canister_ranges_for_app_subnet_path: Vec<Label<Vec<u8>>> = vec![
        "subnet".into(),
        app_subnet_id_label.clone(),
        "canister_ranges".into(),
    ];

    let nns_subnet = env.topology_snapshot().root_subnet();
    let nns_subnet_id_label = Label::<Vec<u8>>::from(nns_subnet.subnet_id.get_ref().as_slice());
    let deprecated_canister_ranges_for_nns_path: Vec<Label<Vec<u8>>> = vec![
        "subnet".into(),
        nns_subnet_id_label.clone(),
        "canister_ranges".into(),
    ];

    let response = read_state(
        &env,
        vec![deprecated_canister_ranges_for_app_subnet_path.clone()],
        endpoint,
    );

    if should_accept_deprecated_canister_ranges_path {
        let certificate = response.expect(
            "The old endpoints should correctly handle the request with the deprecated paths",
        );
        assert!(
            lookup_value(
                &certificate,
                deprecated_canister_ranges_for_app_subnet_path.clone()
            )
            .is_ok(),
            "The certificate should contain the deprecated canister ranges"
        );
    } else {
        let err = response.expect_err("The new endpoints should not accept the deprecated paths");
        assert_matches!(err, AgentError::HttpError(payload) if payload.status == StatusCode::NOT_FOUND.as_u16());
    }

    let certificate = read_state(
        &env,
        vec![deprecated_canister_ranges_for_nns_path.clone()],
        endpoint,
    )
    .expect("Requesting the deprecated canister ranges for the nns subnet is always allowed");
    assert!(
        lookup_value(
            &certificate,
            deprecated_canister_ranges_for_nns_path.clone()
        )
        .is_ok(),
        "The certificate should contain the deprecated canister \
        ranges because we are requesting the nns subnet"
    );

    for (path, check_app, check_nns) in [
        (vec!["subnet".into()], true, true),
        (vec!["subnet".into(), app_subnet_id_label], true, false),
        (vec!["subnet".into(), nns_subnet_id_label], false, true),
    ] {
        let certificate = read_state(&env, vec![path.clone()], endpoint)
            .expect("Requesting the {path:?} subtree is valid");

        if check_app {
            let deprecated_app_subnet_ranges = lookup_value(
                &certificate,
                deprecated_canister_ranges_for_app_subnet_path.clone(),
            );
            if should_accept_deprecated_canister_ranges_path {
                assert!(
                    deprecated_app_subnet_ranges.is_ok(),
                    "The certificate should contain the deprecated canister ranges \
                    for the app subnet"
                );
            } else {
                let err = deprecated_app_subnet_ranges.expect_err(
                    "The new endpoints should purge the deprecated paths \
                    for the app subnet",
                );
                assert_matches!(
                    err,
                    AgentError::LookupPathUnknown(_),
                    "The path {deprecated_canister_ranges_for_app_subnet_path:?} should have \
                    been purged from the certificate"
                );
            }
        }

        if check_nns {
            assert!(
                lookup_value(
                    &certificate,
                    deprecated_canister_ranges_for_nns_path.clone()
                )
                .is_ok(),
                "The certificate should contain the deprecated canister \
                ranges because we are requesting the nns subnet"
            );
        }
    }
}

fn validate_canister_ranges(
    subnet: &SubnetSnapshot,
    path: &Vec<Label<Vec<u8>>>,
    cert: &Certificate,
) {
    let SubtreeLookupResult::Found(subtree) = cert.tree.lookup_subtree(path) else {
        panic!("State tree does not contain canister ranges subtree");
    };

    let mut canister_ranges_from_state_tree = Vec::new();
    for path in subtree.list_paths() {
        let LookupResult::Found(value) = subtree.lookup_path(&path) else {
            panic!("State tree doesn't contain the requested path: {path:?}");
        };
        let ranges: Vec<(PrincipalId, PrincipalId)> =
            serde_cbor::from_slice(value).expect("Failed to deserialize a canister ranges leaf");

        canister_ranges_from_state_tree.extend(ranges.into_iter().map(|(start, end)| {
            CanisterIdRange {
                start: CanisterId::try_from_principal_id(start).unwrap(),
                end: CanisterId::try_from_principal_id(end).unwrap(),
            }
        }));
    }
    canister_ranges_from_state_tree.sort();

    let mut canister_ranges_from_registry = subnet.subnet_canister_ranges();
    canister_ranges_from_registry.sort();

    assert_eq!(
        canister_ranges_from_registry,
        canister_ranges_from_state_tree
    );
}

#[derive(Copy, Clone, Debug)]
enum Endpoint {
    CanisterReadState(read_state::canister::Version),
    SubnetReadState(read_state::subnet::Version),
}

impl Endpoint {
    fn url(&self, base: Url, principal_id: PrincipalId) -> Url {
        match self {
            Endpoint::CanisterReadState(read_state::canister::Version::V2) => {
                base.join(&format!("/api/v2/canister/{principal_id}/read_state"))
            }
            Endpoint::CanisterReadState(read_state::canister::Version::V3) => {
                base.join(&format!("/api/v3/canister/{principal_id}/read_state"))
            }
            Endpoint::SubnetReadState(read_state::subnet::Version::V2) => {
                base.join(&format!("/api/v2/subnet/{principal_id}/read_state"))
            }
            Endpoint::SubnetReadState(read_state::subnet::Version::V3) => {
                base.join(&format!("/api/v3/subnet/{principal_id}/read_state"))
            }
        }
        .unwrap()
    }

    fn read_state(
        &self,
        base: Url,
        paths: Vec<Vec<Label<Vec<u8>>>>,
        principal_id: PrincipalId,
        identity: impl Identity,
    ) -> Result<Blob, AgentError> {
        let expiration = OffsetDateTime::now_utc() + Duration::from_secs(3 * 60);
        let content = EnvelopeContent::ReadState {
            ingress_expiry: expiration.unix_timestamp_nanos() as u64,
            sender: identity.sender().unwrap(),
            paths,
        };

        let signature = identity.sign(&content).unwrap();

        let envelope = Envelope {
            content: Cow::Borrowed(&content),
            sender_pubkey: signature.public_key,
            sender_sig: signature.signature,
            sender_delegation: signature.delegations,
        };

        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe().unwrap();
        envelope.serialize(&mut serializer).unwrap();

        let response: HttpReadStateResponse =
            block_on(try_send(self.url(base, principal_id), serialized_bytes))?;

        Ok(response.certificate)
    }
}

async fn try_send<A>(url: Url, body: Vec<u8>) -> Result<A, AgentError>
where
    A: serde::de::DeserializeOwned,
{
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Request failed: {err:?}"))
        .unwrap();

    let status = response.status();
    let response = response
        .bytes()
        .await
        .map_err(|err| format!("Request failed: {err:?}"))
        .unwrap();

    if status != StatusCode::OK {
        return Err(AgentError::HttpError(HttpErrorPayload {
            status: status.as_u16(),
            content_type: None,
            content: response.to_vec(),
        }));
    }

    Ok(serde_cbor::from_slice(&response)
        .map_err(|err| format!("Failed to deserialize response: {err:?}. Response: {response:?}"))
        .unwrap())
}

macro_rules! systest_all_variants {
    ($group: expr, $function_name:path) => {
        $group = $group.add_test(systest!($function_name; Endpoint::CanisterReadState(read_state::canister::Version::V2)));
        $group = $group.add_test(systest!($function_name; Endpoint::CanisterReadState(read_state::canister::Version::V3)));
        $group = $group.add_test(systest!($function_name; Endpoint::SubnetReadState(read_state::subnet::Version::V2)));
        $group = $group.add_test(systest!($function_name; Endpoint::SubnetReadState(read_state::subnet::Version::V3)));
    };
}

fn main() -> Result<()> {
    let mut parallel_group = SystemTestSubGroup::new()
        .add_test(systest!(test_non_utf8_metadata))
        .add_test(systest!(test_subnet_canister_ranges_paths; read_state::subnet::Version::V2))
        .add_test(systest!(test_subnet_canister_ranges_paths; read_state::subnet::Version::V3))
        .add_test(systest!(test_canister_canister_ranges_paths; read_state::canister::Version::V2))
        .add_test(systest!(test_canister_canister_ranges_paths; read_state::canister::Version::V3))
        // Only /api/{v2,v3}/canister/read_state endpoints are tested because paths with
        // /request_status prefix are not supported by /api/{v2,v3}/subnet/read_state
        .add_test(systest!(test_request_path; read_state::canister::Version::V2))
        .add_test(systest!(test_request_path; read_state::canister::Version::V3))
        // Only /api/{v2,v3}/canister/read_state endpoints are tested because paths with
        // /request_status prefix are not supported by /api/{v2,v3}/subnet/read_state
        .add_test(systest!(test_request_path_access; read_state::canister::Version::V2))
        .add_test(systest!(test_request_path_access; read_state::canister::Version::V3))
        // Only /api/{v2,v3}/canister/read_state endpoints are tested because paths with
        // /request_status prefix are not supported by /api/{v2,v3}/subnet/read_state
        .add_test(systest!(test_absent_request; read_state::canister::Version::V2))
        .add_test(systest!(test_absent_request; read_state::canister::Version::V3))
        // Only /api/{v2,v3}/canister/read_state endpoints are tested because paths with
        // /canister prefix are not supported by /api/{v2,v3}/subnet/read_state
        .add_test(systest!(test_canister_path; read_state::canister::Version::V2))
        .add_test(systest!(test_canister_path; read_state::canister::Version::V3))
        // Only /api/{v2,v3}/canister/read_state endpoints are tested because paths with
        // /canister prefix are not supported by /api/{v2,v3}/subnet/read_state
        .add_test(systest!(test_metadata_path; read_state::canister::Version::V2))
        .add_test(systest!(test_metadata_path; read_state::canister::Version::V3));

    systest_all_variants!(parallel_group, test_empty_paths_return_time);
    systest_all_variants!(parallel_group, test_time_path_returns_time);
    systest_all_variants!(parallel_group, test_subnet_path);
    systest_all_variants!(parallel_group, test_invalid_request_rejected);
    systest_all_variants!(parallel_group, test_invalid_path_rejected);
    systest_all_variants!(parallel_group, test_deprecated_subnet_canister_ranges_paths);

    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(parallel_group)
        .execute_from_args()?;
    Ok(())
}
