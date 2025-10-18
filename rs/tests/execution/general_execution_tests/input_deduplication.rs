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

            let stable_size = || async {
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
                u32::from_le_bytes(res.try_into().unwrap())
            };

            // Stable memory size is initially 1 page.
            assert_eq!(stable_size().await, 1);

            // Update call body growing stable memory by 1 page.
            // The ingress expiry is equal in all update call bodies
            // so that they can be deduplicated;
            // only the nonce can vary.
            let canister_id = canister.canister_id();
            let ingress_expiry = expiry_time().as_nanos() as u64;
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

            let submit_update_call = |body: Vec<u8>| async {
                let res = client
                    .post(format!("{node_url}api/v2/canister/{canister_id}/call"))
                    .header("Content-Type", "application/cbor")
                    .body(body)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::ACCEPTED);
            };

            // The following two update calls with the same nonce are identical and thus deduplicated.
            for _ in 0..2 {
                submit_update_call(update_body(42)).await;
            }

            // The following update call has a different nonce and thus it is executed separately.
            submit_update_call(update_body(43)).await;

            // Synchronization call: we assume that the previous calls have been executed
            // (in the same round as the synchronization call or in previous rounds)
            // once the result of the "synchronization" call is available.
            canister.update(wasm().reply().build()).await.unwrap();

            // Only two update calls (one submitted with nonce 42 and one submitted with nonce 43)
            // are executed and thus stable memory grows from 1 page to 3 pages.
            assert_eq!(stable_size().await, 3);
        }
    });
}

/// Returns the ingress expiry used by IC agent:
/// 3 minutes into the future from now.
fn expiry_time() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(3 * 60)
}
