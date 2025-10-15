/* tag::catalog[]
Title:: Input deduplication test.

Goal:: Test update call deduplication by sending two identical update call requests and asserting that only one was executed.


end::catalog[] */
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
};
use ic_system_test_driver::util::{UniversalCanister, block_on};
use ic_types::messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope};
use ic_universal_canister::wasm;
use reqwest::StatusCode;
use std::time::{Duration, SystemTime};

pub fn input_deduplication_test(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let node_url = node.get_public_url();
    let agent = node.build_default_agent();
    let logger = env.logger();

    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            let client = reqwest::Client::new();

            let canister_id = canister.canister_id();
            let ingress_expiry = expiry_time().as_nanos() as u64;

            // Update call body growing stable memory by 1 page.
            let update_body = |nonce: u64| {
                let envelope = HttpRequestEnvelope {
                    content: HttpCallContent::Call {
                        update: HttpCanisterUpdate {
                            canister_id: Blob(canister_id.as_slice().to_vec()),
                            method_name: "update".to_string(),
                            arg: Blob(wasm().stable_grow(1).reply().build()),
                            sender: Blob(vec![4]), // the anonymous user.
                            ingress_expiry,
                            nonce: Some(nonce.to_le_bytes().into()),
                        },
                    },
                    sender_delegation: None,
                    sender_pubkey: None,
                    sender_sig: None,
                };
                serde_cbor::ser::to_vec(&envelope).unwrap()
            };

            // The following two requests with the same nonce are identical and thus deduplicated.
            let res = client
                .post(format!("{node_url}api/v2/canister/{canister_id}/call"))
                .header("Content-Type", "application/cbor")
                .body(update_body(42))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::ACCEPTED);

            let res = client
                .post(format!("{node_url}api/v2/canister/{canister_id}/call"))
                .header("Content-Type", "application/cbor")
                .body(update_body(42))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::ACCEPTED);

            // The following request has a different nonce and thus is executed.
            let res = client
                .post(format!("{node_url}api/v2/canister/{canister_id}/call"))
                .header("Content-Type", "application/cbor")
                .body(update_body(43))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::ACCEPTED);

            // Only two update calls (one submitted with nonce 42 and one submitted with nonce 43)
            // are executed and thus stable memory grows to 2 pages.
            let res = canister
                .update(
                    wasm()
                        .stable_size()
                        .int_to_blob()
                        .append_and_reply()
                        .build(),
                )
                .await
                .unwrap();
            assert_eq!(res, 2_u32.to_le_bytes());
        }
    });
}

fn expiry_time() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(60)
}
