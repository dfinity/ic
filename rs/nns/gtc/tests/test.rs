use canister_test::{Canister, Runtime};
use dfn_candid::candid;
use ic_nns_gtc::init::GenesisTokenCanisterInitPayloadBuilder;
use ic_nns_gtc::pb::v1::Gtc;
use ic_nns_gtc_accounts::{ECT_ACCOUNTS, SEED_ROUND_ACCOUNTS};
use ic_nns_test_utils::itest_helpers::{
    maybe_upgrade_to_self, set_up_genesis_token_canister, UpgradeTestingScenario,
};
use ic_nns_test_utils_macros::parameterized_upgrades;

// This tests examples shown in README
async fn test_gtc(gtc: &Canister<'_>) {
    let total: u32 = gtc.query_("total", candid, ()).await.unwrap();
    assert_eq!(total, 160561922);

    let len: u16 = gtc.query_("len", candid, ()).await.unwrap();
    assert_eq!(len, 375);

    let balance: u32 = gtc
        .query_(
            "balance",
            candid,
            ("006b572cd1af263c1f6c7c4d74f9260cd308c937",),
        )
        .await
        .unwrap();
    assert_eq!(balance, 756);

    let balance: u32 = gtc
        .query_(
            "balance",
            candid,
            ("6d9bd871135894e872df9db1e5a07cb5102297e8",),
        )
        .await
        .unwrap();
    assert_eq!(balance, 81778);
}

/// Run `test_gtc` before and after an upgrade to confirm that `test_gtc` passes
/// on both an initialized GTC and an upgraded GTC
#[parameterized_upgrades]
async fn test_gtc_before_and_after_upgrade(
    runtime: &Runtime,
    upgrade_scenario: UpgradeTestingScenario,
) {
    let mut gtc = set_up_genesis_token_canister(runtime, get_gtc_init_payload()).await;
    test_gtc(&gtc).await;
    maybe_upgrade_to_self(&mut gtc, upgrade_scenario).await;
    test_gtc(&gtc).await;
}

fn get_gtc_init_payload() -> Gtc {
    let mut payload_builder = GenesisTokenCanisterInitPayloadBuilder::new();
    payload_builder.sr_months_to_release = Some(48);
    payload_builder.ect_months_to_release = Some(12);
    payload_builder.add_sr_neurons(SEED_ROUND_ACCOUNTS);
    payload_builder.add_ect_neurons(ECT_ACCOUNTS);
    payload_builder.build()
}
