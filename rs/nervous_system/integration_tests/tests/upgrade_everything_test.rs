use ic_sns_wasm::pb::v1::SnsCanisterType;
mod sns_upgrade_test_utils;
use sns_upgrade_test_utils::test_sns_upgrade;

#[tokio::test]
async fn test_upgrade_everything_auto() {
    let automatically_advance_target_version = true;
    test_sns_upgrade(
        vec![
            SnsCanisterType::Root,
            SnsCanisterType::Governance,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
            SnsCanisterType::Ledger,
            SnsCanisterType::Archive,
        ],
        automatically_advance_target_version,
    )
    .await;
}

#[tokio::test]
async fn test_upgrade_everything_no_auto() {
    let automatically_advance_target_version = false;
    test_sns_upgrade(
        vec![
            SnsCanisterType::Root,
            SnsCanisterType::Governance,
            SnsCanisterType::Swap,
            SnsCanisterType::Index,
            SnsCanisterType::Ledger,
            SnsCanisterType::Archive,
        ],
        automatically_advance_target_version,
    )
    .await;
}
