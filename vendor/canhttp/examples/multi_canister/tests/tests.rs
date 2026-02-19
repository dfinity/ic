use test_fixtures::Setup;
use uuid::Uuid;

#[tokio::test]
async fn should_make_parallel_http_requests() {
    let setup = Setup::new("multi_canister").await;

    let http_request_results = setup
        .canister()
        .update_call::<_, Vec<String>>("make_parallel_http_requests", ())
        .await;

    for uuid in http_request_results {
        assert!(Uuid::parse_str(uuid.as_str()).is_ok());
    }
}
