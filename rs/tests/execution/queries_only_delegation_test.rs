/* tag::catalog[]
end::catalog[] */

//! System test for queries-only delegation permissions on the management
//! canister.
//!
//! When a caller authenticates via a delegation chain that carries
//! `permissions = queries`, the ingress validator rejects every request
//! sent to the `/call` endpoint. This test iterates over every method of
//! the management canister and verifies that a call to `aaaaa-aa` is
//! rejected with a `400 Bad Request` whose body identifies the
//! queries-only restriction.

use anyhow::Result;
use ic_agent::AgentError;
use ic_agent::Identity;
use ic_agent::agent::agent_error::HttpErrorPayload;
use ic_agent::export::Principal;
use ic_agent::identity::{DelegatedIdentity, Delegation, DelegationPermissions, SignedDelegation};
use ic_management_canister_types_private::{IC_00, Method as Ic00Method};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    agent_with_identity, block_on, expiry_time, random_ed25519_identity,
};
use slog::info;
use strum::IntoEnumIterator;

// Substring of the validator error emitted by
// `RequestValidationError::UpdateCallNotPermittedByDelegation` (see
// `rs/validator/ingress_message/src/lib.rs`). Matching this string, rather
// than a generic prefix like "Update calls are not permitted", verifies
// that the rejection is specifically due to the queries-only delegation
// restriction and not some other reason (e.g. a bad signature or expired
// ingress).
const UPDATE_REJECTED_MSG: &str =
    "a delegation restricts the sender to query calls (permissions = \"queries\")";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(
            management_canister_calls_rejected_with_queries_only_delegation
        ))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn management_canister_calls_rejected_with_queries_only_delegation(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    block_on(async move {
        // Root identity of the delegation chain — this is the principal the
        // ingress is authenticated as.
        let sender = random_ed25519_identity();
        let sender_pubkey_der = sender.public_key().expect("sender has a public key");

        // Session key the sender delegates to, restricted to queries only.
        let session = random_ed25519_identity();
        let session_pubkey_der = session.public_key().expect("session has a public key");

        // Delegation from sender → session with permissions = queries.
        let delegation = Delegation {
            pubkey: session_pubkey_der,
            expiration: expiry_time().as_nanos() as u64,
            targets: None,
            permissions: Some(DelegationPermissions::Queries),
        };
        let signature = sender
            .sign_arbitrary(&delegation.signable())
            .expect("sender signs the delegation")
            .signature
            .expect("delegation signature bytes");
        let signed_delegation = SignedDelegation {
            delegation,
            signature,
        };

        let identity = DelegatedIdentity::new_unchecked(
            sender_pubkey_der,
            Box::new(session),
            vec![signed_delegation],
        );
        let agent = agent_with_identity(node.get_public_url().as_str(), identity)
            .await
            .expect("build agent with a queries-only DelegatedIdentity");

        let ic_00: Principal = IC_00.get().0;
        for method in Ic00Method::iter() {
            let method_name = method.to_string();
            let outcome = agent
                .update(&ic_00, &method_name)
                .with_arg(vec![])
                .call_and_wait()
                .await;
            info!(logger, "method={} outcome={:?}", method_name, outcome);

            match outcome {
                Err(AgentError::HttpError(HttpErrorPayload {
                    status, content, ..
                })) => {
                    assert_eq!(
                        status, 400,
                        "management canister method {method_name} expected HTTP 400, got {status}"
                    );
                    let body = String::from_utf8_lossy(&content);
                    assert!(
                        body.contains(UPDATE_REJECTED_MSG),
                        "management canister method {method_name} expected body to contain {:?}, got: {}",
                        UPDATE_REJECTED_MSG,
                        body,
                    );
                }
                other => panic!(
                    "management canister method {method_name} expected 400 HttpError, got {other:?}"
                ),
            }
        }
    });
}
