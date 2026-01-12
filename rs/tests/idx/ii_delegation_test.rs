use anyhow::Result;
use candid::Principal;
use ic_agent::Identity;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::async_systest;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::util::delegations::*;
use ic_system_test_driver::util::{
    agent_with_identity, assert_canister_counter_with_retries, random_ed25519_identity,
};
use ic_types::messages::{Blob, HttpQueryResponse};
use ic_universal_canister::wasm;
use slog::info;
use std::env;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(async_systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
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

pub async fn test(env: TestEnv) {
    let log = env.logger();
    let non_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ii_canister_id = non_nns_node
        .create_and_install_canister_with_arg(
            &env::var("II_WASM_PATH").expect("II_WASM_PATH not set"),
            None,
        )
        .await;
    info!(
        log,
        "II canister with id={ii_canister_id} installed on subnet with id={}",
        non_nns_node.subnet_id().unwrap()
    );
    let app_node = env.get_first_healthy_application_node_snapshot();
    let counter_canister_id = app_node
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None)
        .await;
    info!(
        log,
        "Counter canister with id={counter_canister_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let app_agent = app_node.build_default_agent_async().await;
    let ucan_id = install_universal_canister(&app_agent, app_node.effective_canister_id()).await;
    // We use universal canister to verify the identity of the caller for query and update calls performed with delegation.
    info!(
        log,
        "Universal canister with id={ucan_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let user_identity = random_ed25519_identity();
    let pubkey = user_identity.public_key().unwrap();
    let non_nns_agent = agent_with_identity(non_nns_node.get_public_url().as_str(), user_identity)
        .await
        .unwrap();
    register_user(&non_nns_agent, pubkey, ii_canister_id, USER_NUMBER_OFFSET).await;
    info!(log, "User registered");
    let delegation_identity = random_ed25519_identity();
    let delegation_pubkey = delegation_identity.public_key().unwrap();
    let frontend_hostname = format!("https://{}.ic0.app", counter_canister_id.to_text());
    let (signed_delegation, ii_derived_public_key) = create_delegation(
        &non_nns_agent,
        delegation_pubkey,
        ii_canister_id,
        frontend_hostname,
        USER_NUMBER_OFFSET,
    )
    .await;
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
    let _ = app_agent_with_delegation
        .update(&counter_canister_id, "write", Blob(vec![]))
        .await;
    info!(
        log,
        "Making a query call on counter canister with delegation (read counter)"
    );
    let query_response = app_agent_with_delegation
        .query(&counter_canister_id, "read", Blob(vec![]))
        .await;
    match query_response {
        HttpQueryResponse::Replied { .. } => (),
        HttpQueryResponse::Rejected {
            error_code,
            reject_message,
            ..
        } => panic!("Query call was rejected: code={error_code}, message={reject_message}"),
    }
    info!(log, "Asserting canister counter has value=1");
    let app_agent = app_node.build_default_agent_async().await;
    assert_canister_counter_with_retries(
        &log,
        &app_agent,
        &counter_canister_id,
        vec![],
        1,
        10,
        Duration::from_secs(1),
    )
    .await;
    let expected_principal = Principal::self_authenticating(&ii_derived_public_key);
    info!(
        log,
        "Expected principal {} of the caller", expected_principal
    );
    info!(log, "Asserting caller identity of the query call");
    let observed_principal = {
        let response: HttpQueryResponse = app_agent_with_delegation
            .query(
                &ucan_id,
                "query",
                Blob(wasm().caller().append_and_reply().build()),
            )
            .await;
        match response {
            HttpQueryResponse::Replied { reply } => Principal::from_slice(reply.arg.as_ref()),
            HttpQueryResponse::Rejected { reject_message, .. } => {
                panic!("Query call was rejected: {reject_message}")
            }
        }
    };
    assert_eq!(expected_principal, observed_principal);
    info!(log, "Asserting caller identity of the update call");
    let observed_principal = {
        let response = app_agent_with_delegation
            .update_and_wait(
                &ucan_id,
                "update",
                Blob(wasm().caller().append_and_reply().build()),
            )
            .await
            .unwrap();
        Principal::from_slice(response.as_ref())
    };
    assert_eq!(expected_principal, observed_principal);
}
