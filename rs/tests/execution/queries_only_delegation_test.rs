/* tag::catalog[]
end::catalog[] */

//! System test for queries-only delegation permissions on the management
//! canister.
//!
//! When a caller authenticates via a delegation chain that carries
//! `permissions = queries`, the ingress validator rejects every request
//! sent to the `/call` endpoint. This test iterates over every method of
//! the management canister and verifies that a call to `aaaaa-aa` is
//! rejected with a `400 Bad Request` whose body mentions the delegation
//! restriction.

use anyhow::Result;
use ic_agent::Identity;
use ic_management_canister_types_private::Method as Ic00Method;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, expiry_time, random_ed25519_identity};
use ic_types::CanisterId;
use ic_types::crypto::Signable;
use ic_types::messages::{
    Blob, Delegation, DelegationPermissions, HttpCallContent, HttpCanisterUpdate,
    HttpRequestEnvelope, MessageId, SignedDelegation,
};
use ic_types::time::Time;
use reqwest::StatusCode;
use slog::info;
use strum::IntoEnumIterator;

// Substring of the validator error emitted by
// `RequestValidationError::UpdateCallNotPermittedByDelegation` (defined in
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
        let node_url = node.get_public_url();
        let client = reqwest::Client::new();

        // Root identity of the delegation chain — this is the principal that
        // shows up as `sender` on the ingress.
        let sender = random_ed25519_identity();
        let sender_pubkey_der = sender.public_key().expect("sender has a public key");
        let sender_principal = sender.sender().expect("sender principal");

        // Session key the sender delegates to, restricted to queries only.
        let session = random_ed25519_identity();
        let session_pubkey_der = session.public_key().expect("session has a public key");

        // The delegation covers all outgoing requests in this test; use a
        // uniform ingress-expiry / delegation-expiration so both the
        // delegation and the requests are valid concurrently.
        let expiry_ns = expiry_time().as_nanos() as u64;
        let expiration = Time::from_nanos_since_unix_epoch(expiry_ns);

        let delegation = Delegation::new(session_pubkey_der, expiration)
            .with_permissions(DelegationPermissions::Queries);
        let delegation_sig_bytes = sender
            .sign_arbitrary(&delegation.as_signed_bytes())
            .expect("sender signs delegation")
            .signature
            .expect("delegation signature bytes");
        let signed_delegation = SignedDelegation::new(delegation, delegation_sig_bytes);

        let url = format!("{}api/v2/canister/{}/call", node_url, CanisterId::ic_00());

        for method in Ic00Method::iter() {
            let content = HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(CanisterId::ic_00().get().to_vec()),
                    method_name: method.to_string(),
                    // The request is rejected during validation before the
                    // replica ever looks at these bytes, so an empty payload
                    // is enough.
                    arg: Blob(vec![]),
                    sender: Blob(sender_principal.as_slice().to_vec()),
                    ingress_expiry: expiry_ns,
                    nonce: None,
                    sender_info: None,
                },
            };
            let message_id = MessageId::from(content.representation_independent_hash());
            let session_sig_bytes = session
                .sign_arbitrary(&message_id.as_signed_bytes())
                .expect("session signs request id")
                .signature
                .expect("session signature bytes");

            let envelope = HttpRequestEnvelope {
                content,
                sender_pubkey: Some(Blob(sender_pubkey_der.clone())),
                sender_sig: Some(Blob(session_sig_bytes)),
                sender_delegation: Some(vec![signed_delegation.clone()]),
            };
            let body = serde_cbor::to_vec(&envelope).expect("serialize envelope");

            let response = client
                .post(&url)
                .header("Content-Type", "application/cbor")
                .body(body)
                .send()
                .await
                .expect("HTTP POST failed");
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            info!(
                logger,
                "method={} status={} body={:?}", method, status, body_text
            );

            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "management canister method {} expected 400, got {}: {}",
                method,
                status,
                body_text
            );
            assert!(
                body_text.contains(UPDATE_REJECTED_MSG),
                "management canister method {} expected body to contain {:?}, got: {}",
                method,
                UPDATE_REJECTED_MSG,
                body_text
            );
        }
    });
}
