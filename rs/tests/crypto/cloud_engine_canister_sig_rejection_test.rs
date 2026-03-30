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
use ic_system_test_driver::util::{agent_with_identity, block_on, random_ed25519_identity};
use ic_types::messages::{Blob, HttpQueryResponse};
use ic_universal_canister::wasm;
use slog::info;
use std::env;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System) // NNS
        .add_fast_single_node_subnet(SubnetType::CloudEngine) // II lives here
        .add_fast_single_node_subnet(SubnetType::Application) // target canister
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
        // ── Locate nodes ───────────────────────────────────────────────
        let ce_node = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            0,
        );
        let app_node = env.get_first_healthy_application_node_snapshot();

        // ── Install II on the CloudEngine subnet ───────────────────────
        info!(logger, "Installing II on CloudEngine subnet...");
        let ii_canister_id = ce_node.create_and_install_canister_with_arg(
            &env::var("II_BACKEND_WASM_PATH").expect("II_BACKEND_WASM_PATH not set"),
            Some(build_internet_identity_backend_install_arg()),
        );
        info!(
            logger,
            "II canister {ii_canister_id} installed on CloudEngine subnet {}",
            ce_node.subnet_id().unwrap()
        );

        // ── Install universal canister on Application subnet ───────────
        info!(
            logger,
            "Installing universal canister on Application subnet..."
        );
        let app_agent = app_node.build_default_agent_async().await;
        let uc_id = install_universal_canister(&app_agent, app_node.effective_canister_id()).await;
        info!(
            logger,
            "Universal canister {uc_id} installed on Application subnet {}",
            app_node.subnet_id().unwrap()
        );

        // ── Register a user on II ──────────────────────────────────────
        info!(logger, "Registering user on II...");
        let user_identity = random_ed25519_identity();
        let pubkey = user_identity.public_key().unwrap();
        let ce_agent = agent_with_identity(ce_node.get_public_url().as_str(), user_identity)
            .await
            .unwrap();
        register_user(&ce_agent, pubkey, ii_canister_id, USER_NUMBER_OFFSET).await;
        info!(logger, "User registered.");

        // ── Obtain a delegation (canister signature) from II ───────────
        info!(logger, "Creating delegation from II on CloudEngine...");
        let delegation_identity = random_ed25519_identity();
        let delegation_pubkey = delegation_identity.public_key().unwrap();
        let frontend_hostname = format!("https://{}.ic0.app", uc_id.to_text());
        let (signed_delegation, ii_derived_public_key) = create_delegation(
            &ce_agent,
            delegation_pubkey,
            ii_canister_id,
            frontend_hostname,
            USER_NUMBER_OFFSET,
        )
        .await;
        info!(logger, "Delegation received.");

        // ── Query the Application subnet UC with the delegation ────────
        info!(
            logger,
            "Querying Application subnet UC with CloudEngine delegation (should be rejected)..."
        );
        let agent_with_delegation = AgentWithDelegation {
            node_url: app_node.get_public_url(),
            pubkey: ii_derived_public_key,
            signed_delegation,
            delegation_identity: &delegation_identity,
            polling_timeout: UPDATE_POLLING_TIMEOUT,
        };

        let response = agent_with_delegation
            .query(&uc_id, "query", Blob(wasm().reply_data(b"hello").build()))
            .await;

        match response {
            HttpQueryResponse::Rejected { reject_message, .. } => {
                info!(logger, "Query correctly rejected: {reject_message}");
                assert!(
                    reject_message.contains("source subnet cannot be used for delegations")
                        || reject_message.contains("certificate verification failed"),
                    "Expected rejection to mention unacceptable source subnet, got: {reject_message}"
                );
            }
            HttpQueryResponse::Replied { .. } => {
                panic!(
                    "Expected query to be rejected due to CloudEngine canister signature, \
                     but it succeeded"
                );
            }
        }

        // ── Sanity check: normal query (no delegation) succeeds ────────
        info!(
            logger,
            "Sanity check: querying UC without delegation (should succeed)..."
        );
        let normal_response = app_agent
            .query(&uc_id, "query")
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
