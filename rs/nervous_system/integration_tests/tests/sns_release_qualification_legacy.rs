//! Legacy upgrade release-qualification tests

use ic_sns_wasm::pb::v1::SnsCanisterType;

mod sns_upgrade_test_utils_legacy;
use sns_upgrade_test_utils_legacy::test_sns_upgrade_legacy;

#[tokio::test]
async fn test_upgrade_swap() {
    test_sns_upgrade_legacy(vec![SnsCanisterType::Swap]).await;
}

#[tokio::test]
async fn test_upgrade_sns_gov_root() {
    test_sns_upgrade_legacy(vec![SnsCanisterType::Root, SnsCanisterType::Governance]).await;
}

#[tokio::test]
async fn test_upgrade_upgrade_sns_gov_root() {
    test_sns_upgrade_legacy(vec![SnsCanisterType::Governance, SnsCanisterType::Root]).await;
}
