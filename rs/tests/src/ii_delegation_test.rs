use std::time::Duration;

use candid::Principal;
use ic_agent::Identity;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::util::delegations::*;
use ic_system_test_driver::util::{
    agent_with_identity, assert_canister_counter_with_retries, block_on, random_ed25519_identity,
};
use ic_types::messages::{Blob, HttpQueryResponse};
use ic_universal_canister::wasm;
use slog::info;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let non_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ii_canister_id =
        non_nns_node.create_and_install_canister_with_arg(INTERNET_IDENTITY_WASM, None);
    info!(
        log,
        "II canister with id={ii_canister_id} installed on subnet with id={}",
        non_nns_node.subnet_id().unwrap()
    );
    let app_node = env.get_first_healthy_application_node_snapshot();
    let counter_canister_id =
        app_node.create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        log,
        "Counter canister with id={counter_canister_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let app_agent = app_node.build_default_agent();
    let ucan_id = block_on(install_universal_canister(
        &app_agent,
        app_node.effective_canister_id(),
    ));
    // We use universal canister to verify the identity of the caller for query and update calls performed with delegation.
    info!(
        log,
        "Universal canister with id={ucan_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let user_identity = random_ed25519_identity();
    let pubkey = user_identity.public_key().unwrap();
    let non_nns_agent = block_on(agent_with_identity(
        non_nns_node.get_public_url().as_str(),
        user_identity,
    ))
    .unwrap();
    block_on(register_user(
        &non_nns_agent,
        pubkey,
        ii_canister_id,
        USER_NUMBER_OFFSET,
    ));
    info!(log, "User registered");
    let delegation_identity = random_ed25519_identity();
    let delegation_pubkey = delegation_identity.public_key().unwrap();
    let frontend_hostname = format!("https://{}.ic0.app", counter_canister_id.to_text());
    let (signed_delegation, ii_derived_public_key) = block_on(create_delegation(
        &non_nns_agent,
        delegation_pubkey,
        ii_canister_id,
        frontend_hostname,
        USER_NUMBER_OFFSET,
    ));
    info!(log, "Delegation received");
    let app_agent_with_delegation = AgentWithDelegation {
        node_url: app_node.get_public_url(),
        pubkey: ii_derived_public_key.clone(),
        signed_delegation,
        delegation_identity: &delegation_identity,
        polling_timeout: UPDATE_POLLING_TIMEOUT,
    };
    info!(
        log,
        "Making an update call on counter canister with delegation (increment counter)"
    );
    let _ = block_on(app_agent_with_delegation.update(&counter_canister_id, "write", Blob(vec![])));
    info!(
        log,
        "Making a query call on counter canister with delegation (read counter)"
    );
    let query_response =
        block_on(app_agent_with_delegation.query(&counter_canister_id, "read", Blob(vec![])));
    match query_response {
        HttpQueryResponse::Replied { .. } => (),
        HttpQueryResponse::Rejected {
            error_code,
            reject_message,
            ..
        } => panic!("Query call was rejected: code={error_code}, message={reject_message}"),
    }
    info!(log, "Asserting canister counter has value=1");
    let app_agent = app_node.build_default_agent();
    block_on(assert_canister_counter_with_retries(
        &log,
        &app_agent,
        &counter_canister_id,
        vec![],
        1,
        10,
        Duration::from_secs(1),
    ));
    let expected_principal = Principal::self_authenticating(&ii_derived_public_key);
    info!(
        log,
        "Expected principal {} of the caller", expected_principal
    );
    info!(log, "Asserting caller identity of the query call");
    let observed_principal = {
        let response: HttpQueryResponse = block_on(app_agent_with_delegation.query(
            &ucan_id,
            "query",
            Blob(wasm().caller().append_and_reply().build()),
        ));
        let principal = match response {
            HttpQueryResponse::Replied { reply } => Principal::from_slice(reply.arg.as_ref()),
            HttpQueryResponse::Rejected { reject_message, .. } => {
                panic!("Query call was rejected: {reject_message}")
            }
        };
        principal
    };
    assert_eq!(expected_principal, observed_principal);
    info!(log, "Asserting caller identity of the update call");
    let observed_principal = {
        let response = block_on(app_agent_with_delegation.update_and_wait(
            &ucan_id,
            "update",
            Blob(wasm().caller().append_and_reply().build()),
        ))
        .unwrap();
        Principal::from_slice(response.as_ref())
    };
    assert_eq!(expected_principal, observed_principal);
}
