/* tag::catalog[]
Title:: Malicious input test.

Goal:: Test the robustness of the replica by sending invalid requests to its HTTP endpoint.


end::catalog[] */
use ic_base_types::CanisterId;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
};
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery,
};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use reqwest::StatusCode;
use std::time::{Duration, SystemTime};

const RND_SEED: u64 = 42;

const ENDPOINTS: &[&str; 3] = &["call", "query", "read_state"];

pub fn malicious_input_test(env: TestEnv) {
    test_invalid_content_type(env.clone());
    test_invalid_get_requests(env.clone());
    test_garbage_payload(env.clone());
    test_valid_query_followed_by_garbage(env.clone());
    test_valid_update_followed_by_garbage(env);
}

// Endpoints reject requests without the "application/cbor" content type.
fn test_invalid_content_type(env: TestEnv) {
    let node_url = env.get_first_healthy_node_snapshot().get_public_url();
    let client = reqwest::blocking::Client::new();
    let canister_id = CanisterId::from_u64(123456789);
    for e in ENDPOINTS {
        // Specifying a bogus content type should result in a 415.
        let res = client
            .post(format!("{node_url}api/v2/canister/{canister_id}/{e}"))
            .header("Content-Type", "application/abc")
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Not specifying a content type should also result in a 400.
        let res = client
            .post(format!("{node_url}api/v2/canister/{canister_id}/{e}"))
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

// Endpoints reject get requests.
fn test_invalid_get_requests(env: TestEnv) {
    let node_url = env.get_first_healthy_node_snapshot().get_public_url();
    let client = reqwest::blocking::Client::new();

    let canister_id = CanisterId::from_u64(123456789);
    for e in ENDPOINTS {
        let res = client
            .get(format!("{node_url}api/v2/canister/{canister_id}/{e}"))
            .header("Content-Type", "application/cbor")
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

// Endpoints reject garbage payloads.
fn test_garbage_payload(env: TestEnv) {
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    let node_url = env.get_first_healthy_node_snapshot().get_public_url();
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
            .post(format!("{node_url}api/v2/canister/{canister_id}/{e}"))
            .header("Content-Type", "application/cbor")
            .body(garbage_payload.clone())
            .send()
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

fn test_valid_query_followed_by_garbage(env: TestEnv) {
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    let node_url = env.get_first_healthy_node_snapshot().get_public_url();
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
        .post(format!("{node_url}api/v2/canister/{canister_id}/query"))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

fn test_valid_update_followed_by_garbage(env: TestEnv) {
    let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    let node_url = env.get_first_healthy_node_snapshot().get_public_url();
    let client = reqwest::blocking::Client::new();

    let canister_id = CanisterId::from_u64(123456789);
    // Create a valid update request.
    let envelope = HttpRequestEnvelope {
        content: HttpCallContent::Call {
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
        .post(format!("{node_url}api/v2/canister/{canister_id}/call"))
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
