/* tag::catalog[]
Title:: Malicious input test.

Goal:: Test the robustness of the replica by sending invalid requests to its HTTP endpoint.


end::catalog[] */
use crate::util;
use ic_base_types::CanisterId;
use ic_fondue::ic_manager::IcHandle;
use ic_types::messages::{
    Blob, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope, HttpSubmitContent,
    HttpUserQuery,
};
use rand::RngCore;
use reqwest::StatusCode;
use std::time::{Duration, SystemTime};

const ENDPOINTS: &[&str; 3] = &["call", "query", "read_state"];

pub fn test(handle: IcHandle, ctx: &fondue::pot::Context) {
    test_invalid_content_type(&handle, ctx);
    test_invalid_get_requests(&handle, ctx);
    test_garbage_payload(&handle, ctx);
    test_valid_query_followed_by_garbage(&handle, ctx);
    test_valid_update_followed_by_garbage(&handle, ctx);
}

// Endpoints reject requests without the "application/cbor" content type.
fn test_invalid_content_type(handle: &IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let client = reqwest::blocking::Client::new();
    let endpoint = util::get_random_node_endpoint(handle, &mut rng);
    util::block_on(endpoint.assert_ready(ctx));
    let canister_id = CanisterId::from_u64(123456789);
    for e in ENDPOINTS {
        // Specifying a bogus content type should result in a 415.
        let res = client
            .post(&format!(
                "{}api/v2/canister/{}/{}",
                endpoint.url, canister_id, e
            ))
            .header("Content-Type", "application/abc")
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Not specifying a content type should also result in a 400.
        let res = client
            .post(&format!("{}{}", endpoint.url, e))
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

// Endpoints reject get requests.
fn test_invalid_get_requests(handle: &IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let endpoint = util::get_random_node_endpoint(handle, &mut rng);
    util::block_on(endpoint.assert_ready(ctx));
    let client = reqwest::blocking::Client::new();

    let canister_id = CanisterId::from_u64(123456789);
    for e in ENDPOINTS {
        let res = client
            .get(&format!(
                "{}api/v2/canister/{}/{}",
                endpoint.url, canister_id, e
            ))
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

// Endpoints reject garbage payloads.
fn test_garbage_payload(handle: &IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let endpoint = util::get_random_node_endpoint(handle, &mut rng);
    util::block_on(endpoint.assert_ready(ctx));
    let client = reqwest::blocking::Client::new();

    let garbage_payload = {
        let mut p = [0u8; 100];
        // Fill the payload with random bytes.
        rng.fill_bytes(&mut p);
        p.to_vec()
    };

    let canister_id = CanisterId::from_u64(123456789);
    for e in ENDPOINTS {
        let res = client
            .post(&format!(
                "{}api/v2/canister/{}/{}",
                endpoint.url, canister_id, e
            ))
            .header("Content-Type", "application/cbor")
            .body(garbage_payload.clone())
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

fn test_valid_query_followed_by_garbage(handle: &IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let endpoint = util::get_random_node_endpoint(handle, &mut rng);
    util::block_on(endpoint.assert_ready(ctx));
    let client = reqwest::blocking::Client::new();

    let canister_id = CanisterId::from_u64(123456789);
    // Create a valid query request.
    let envelope = HttpRequestEnvelope {
        content: HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "query".to_string(),
                arg: Blob(vec![]),
                sender: Blob(vec![4]), // the anonymous user.
                ingress_expiry: expiry_time().as_nanos() as u64,
                nonce: None,
            },
        },
        sender_delegation: None,
        sender_pubkey: None,
        sender_sig: None,
    };
    let mut body = serde_cbor::ser::to_vec(&envelope).unwrap();

    // Append some garbage to the valid request.
    let garbage_payload = {
        let mut p = [0u8; 100];
        // Fill the payload with random bytes.
        rng.fill_bytes(&mut p);
        p.to_vec()
    };
    body.extend(garbage_payload);

    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/query",
            endpoint.url, canister_id
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

fn test_valid_update_followed_by_garbage(handle: &IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let endpoint = util::get_random_node_endpoint(handle, &mut rng);
    util::block_on(endpoint.assert_ready(ctx));
    let client = reqwest::blocking::Client::new();

    let canister_id = CanisterId::from_u64(123456789);
    // Create a valid update request.
    let envelope = HttpRequestEnvelope {
        content: HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "update".to_string(),
                arg: Blob(vec![]),
                sender: Blob(vec![4]), // the anonymous user.
                ingress_expiry: expiry_time().as_nanos() as u64,
                nonce: None,
            },
        },
        sender_delegation: None,
        sender_pubkey: None,
        sender_sig: None,
    };
    let mut body = serde_cbor::ser::to_vec(&envelope).unwrap();

    // Append some garbage to the valid request.
    let garbage_payload = {
        let mut p = [0u8; 100];
        // Fill the payload with random bytes.
        rng.fill_bytes(&mut p);
        p.to_vec()
    };
    body.extend(garbage_payload);

    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            endpoint.url, canister_id
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

fn expiry_time() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(60)
}
