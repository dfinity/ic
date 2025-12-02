use super::*;
use candid::{decode_args, encode_args};
use canister_test::Project;
use lazy_static::lazy_static;
use pocket_ic::{PocketIcBuilder, common::rest::InstanceHttpGatewayConfig};
use std::fs;

lazy_static! {
    static ref TEST_WASM: Vec<u8> = {
        let features = [];
        Project::cargo_bin_maybe_from_env("test-canister", &features).bytes()
    };
}

// This test data was taken from production by calling get_build_metadata, and
// has been inspected by hand.
const SAMPLE_SIGNED_REPLY: &[u8] = include_bytes!("../signed_reply.cbor");

#[tokio::test]
async fn test_call_canister() {
    // Step 1: Prepare the world.

    // Step 1.1: Create an instance of ICP to operate in.
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let pocket_ic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_http_gateway(http_gateway_config)
        .build_async()
        .await;

    // Step 1.2: Install "Hello, world!" canister.
    let callee_canister_id = pocket_ic.create_canister().await;
    pocket_ic.add_cycles(callee_canister_id, u128::MAX).await;
    pocket_ic
        .install_canister(
            callee_canister_id,
            TEST_WASM.clone(),
            encode_args(()).unwrap(),
            None,
        )
        .await;

    // Step 1.3: Create object that code under test needs (to call canister), to
    // wit, an Agent.
    pocket_ic.auto_progress().await;
    let agent_url = pocket_ic.url().unwrap();
    let agent = Agent::builder().with_url(agent_url).build().unwrap();
    agent.fetch_root_key().await.unwrap();

    // Step 2: Call the code under test.

    fs::write("arg.can", encode_args(()).unwrap()).unwrap();
    let mut stdout = vec![];
    CallCanister {
        callee: callee_canister_id,
        method: "get_build_metadata".to_string(),
        arg_path: "arg.can".to_string(),
    }
    .execute(agent.clone(), &mut stdout)
    .await;

    // Step 3: Verify results.

    let SignedCanisterReply {
        callee_principal_id,
        certificate,
    } = serde_cbor::from_slice(&stdout).unwrap();

    assert_eq!(callee_principal_id, callee_canister_id);

    agent.verify(&certificate, callee_principal_id).unwrap();

    let request_status = RequestStatus::try_from_tree(certificate.tree).unwrap();
    assert_eq!(&request_status.status, "replied", "{request_status:#?}");
    let reply = decode_args::<(String,)>(&request_status.reply).unwrap().0;
    for key_word in ["profile", "compiler_version", "crate_name"] {
        assert!(reply.contains(key_word), "{reply:?}");
    }
}

#[tokio::test]
async fn test_load_from_file() {
    // Step 1: Prepare the world.

    // Create an input file, by essentially copying ../signed_reply.cbor.
    let mut signed_reply = tempfile::NamedTempFile::new().unwrap();
    signed_reply.write_all(SAMPLE_SIGNED_REPLY).unwrap();

    let a_very_long_time = Duration::from_secs(365_250 * 500 * 24 * 60 * 60);
    let agent = Agent::builder()
        .with_url(PRODUCTION_AGENT_URL.to_string())
        .with_ingress_expiry(a_very_long_time)
        .build()
        .unwrap();

    // Step 2: Call the code under test.
    let mut stdout = vec![];
    LoadFromFile {
        signed_reply_path: signed_reply.path().to_str().unwrap().to_string(),
    }
    // Agent URL is not actually used in this test, so we can just use the
    // production value.
    .execute(agent, &mut stdout)
    .await;

    // Step 3: Verify results.
    let reply = hex::decode(&stdout).unwrap();
    let reply = candid::decode_args::<(String,)>(&reply)
        // This is the main assertion. What this is saying is that the output
        // can be Candid decoded.
        .unwrap_or_else(|err| {
            // Convert reply into a hexidecimal string.
            let reply = reply
                .into_iter()
                .map(|element| format!("{:02X}", element))
                .collect::<Vec<String>>()
                .join("");

            panic!("{}: {}", err, reply);
        })
        .0;
    assert!(reply.starts_with("profile: "), "{reply:?}");
}
