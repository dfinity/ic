use candid::{CandidType, Deserialize};
use test_fixtures::Setup;

#[tokio::test]
async fn should_make_json_rpc_request() {
    let setup = Setup::new("json_rpc_canister").await;

    let result = setup
        .canister()
        .update_call::<_, u64>("make_json_rpc_request", ())
        .await;

    assert!(result > 0);
}

#[tokio::test]
async fn should_make_batch_json_rpc_request() {
    let setup = Setup::new("json_rpc_canister").await;

    let result = setup
        .canister()
        .update_call::<_, SlotInfo>("make_batch_json_rpc_request", ())
        .await;

    assert!(result.slot > 0);
    assert_eq!(result.leader.len(), 44);
}

#[derive(CandidType, Deserialize)]
struct SlotInfo {
    slot: u64,
    leader: String,
}
