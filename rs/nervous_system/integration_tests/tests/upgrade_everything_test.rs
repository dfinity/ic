use ic_sns_wasm::pb::v1::SnsCanisterType;
mod sns_upgrade_test_utils;
use sns_upgrade_test_utils::test_sns_upgrade;

#[tokio::test]
async fn test_upgrade_everything() {
    test_sns_upgrade(vec![
        SnsCanisterType::Root,
        SnsCanisterType::Governance,
        SnsCanisterType::Swap,
        SnsCanisterType::Index,
        SnsCanisterType::Ledger,
        SnsCanisterType::Archive,
    ])
    .await;
}
