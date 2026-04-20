/* tag::catalog[]
Title:: Canister signatures from CloudEngine subnets are rejected.

Goal:: Verify that a canister signature delegation originating from a
CloudEngine subnet is rejected when used to authenticate a call to a canister
on an Application subnet.

Runbook::
0. Set up an IC with one System (NNS) subnet, one CloudEngine subnet, and one
   Application subnet.
1. Install Internet Identity on the CloudEngine subnet.
2. Install a universal canister on the Application subnet.
3. Register a user on II and obtain a delegation (canister signature).
4. Use the delegation to make a query call to the universal canister on the
   Application subnet.
5. Verify that the query is rejected because the delegation certificate
   originates from a CloudEngine subnet.
6. Sanity-check that a normal (non-delegation) query to the same canister
   succeeds.

Success::
The delegation-authenticated query is rejected with an error referencing the
unacceptable source subnet, and the normal query succeeds.

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use ic_agent::Identity;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::delegations::*;
use ic_system_test_driver::util::{
    agent_with_identity, block_on, expiry_time, random_ed25519_identity, sign_query,
};
use ic_types::Time;
use ic_types::messages::{Blob, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery};
use ic_universal_canister::wasm;
use reqwest::Client;
use slog::info;
use std::env;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System) // NNS
        .add_fast_single_node_subnet(SubnetType::CloudEngine) // II lives here
        .add_fast_single_node_subnet(SubnetType::Application) // target canister
        .with_api_boundary_nodes_playnet(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();
    block_on(async move {
        let cloud_node = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            0,
        );
        let app_node = env.get_first_healthy_application_node_snapshot();

        // Install II on the cloud engine subnet
        info!(logger, "Installing II on CloudEngine subnet...");
        let ii_canister_id = cloud_node.create_and_install_canister_with_arg(
            &env::var("II_BACKEND_WASM_PATH").expect("II_BACKEND_WASM_PATH not set"),
            Some(build_internet_identity_backend_install_arg()),
        );
        info!(
            logger,
            "II installed on CloudEngine subnet {} with id {}",
            cloud_node.subnet_id().unwrap(),
            ii_canister_id,
        );

        // Install the universal canister on the app subnet
        info!(
            logger,
            "Installing universal canister on Application subnet..."
        );
        let app_agent = app_node.build_default_agent_async().await;
        let universal_canister =
            install_universal_canister(&app_agent, app_node.effective_canister_id()).await;
        info!(
            logger,
            "Universal canister {universal_canister} installed on Application subnet {}",
            app_node.subnet_id().unwrap()
        );

        // Register on II
        info!(logger, "Registering user on II...");
        let user_identity = random_ed25519_identity();
        let pubkey = user_identity.public_key().unwrap();
        let cloud_agent = agent_with_identity(cloud_node.get_public_url().as_str(), user_identity)
            .await
            .unwrap();
        register_user(&cloud_agent, pubkey, ii_canister_id, USER_NUMBER_OFFSET).await;
        info!(logger, "User registered.");

        // Obtain a delegation from II
        info!(logger, "Creating delegation from II on CloudEngine...");
        let delegation_identity = random_ed25519_identity();
        let delegation_pubkey = delegation_identity.public_key().unwrap();
        let frontend_hostname = format!("https://{}.ic0.app", universal_canister.to_text());
        let (signed_delegation, ii_derived_public_key) = create_delegation(
            &cloud_agent,
            delegation_pubkey,
            ii_canister_id,
            frontend_hostname,
            USER_NUMBER_OFFSET,
        )
        .await;

        info!(
            logger,
            "Querying Application subnet UC with CloudEngine delegation (should be rejected)..."
        );

        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(universal_canister.as_slice().to_vec()),
                method_name: "query".to_string(),
                arg: Blob(wasm().reply_data(b"hello").build()),
                sender: Blob(
                    Principal::self_authenticating(ii_derived_public_key.clone().into_vec())
                        .as_slice()
                        .to_vec(),
                ),
                ingress_expiry: expiry_time().as_nanos() as u64,
                nonce: None,
                sender_info: None,
            },
        };
        let signature = sign_query(&content, &delegation_identity);
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: Some(vec![ic_types::messages::SignedDelegation::new(
                ic_types::messages::Delegation::new(
                    signed_delegation.delegation.pubkey.clone(),
                    Time::from_nanos_since_unix_epoch(signed_delegation.delegation.expiration),
                ),
                signed_delegation.signature.clone(),
            )]),
            sender_pubkey: Some(Blob(ii_derived_public_key.clone().into_vec())),
            sender_sig: Some(Blob(signature.signature.unwrap())),
        };
        let body = serde_cbor::ser::to_vec(&envelope).unwrap();

        let client = Client::new();
        let response = client
            .post(format!(
                "{}api/v2/canister/{}/query",
                app_node.get_public_url().as_str(),
                universal_canister
            ))
            .header("Content-Type", "application/cbor")
            .body(body)
            .send()
            .await
            .unwrap();

        let status = response.status();
        let response_body = response.text().await.unwrap();
        info!(
            logger,
            "Query response: status={status}, body={response_body}"
        );
        assert!(
            !status.is_success(),
            "Expected query to be rejected due to CloudEngine canister signature, \
             but got success status {status}"
        );
        assert!(
            response_body.contains("certificate verification failed: the source subnet"),
            "Missing expected error text",
        );
        assert!(
            response_body.contains("is not trusted for delegations"),
            "Missing expected error text",
        );

        // Check that a query without delegations works
        info!(
            logger,
            "Sanity check: querying UC without delegation (should succeed)..."
        );
        let normal_response = app_agent
            .query(&universal_canister, "query")
            .with_arg(wasm().reply_data(b"hello").build())
            .call()
            .await;
        assert!(
            normal_response.is_ok(),
            "Normal (non-delegation) query should succeed, got: {normal_response:?}"
        );
        info!(logger, "Sanity check passed. All assertions passed.");
    });
}
