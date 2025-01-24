use ic_sns_testing::pocket_ic::bootstrap_nns;
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_sns_testing_pocket_ic() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    bootstrap_nns(&pocket_ic).await;
}
