pub mod common;

use common::{TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets};
use ic_types::CanisterId;
use messaging_test::Call;
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::ProptestConfig;

#[test]
fn test_canister_can_be_stopped_with_hanging_call_on_stalled_subnet() {
    let (subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn bla(
    #[strategy(arb_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default()))]
    setup: TestSubnetSetup,

    #[strategy(proptest::collection::vec(arb_call(CallConfig {
        receivers: #setup.canisters,
        ..CallConfig::default()
    }), 20))]
    calls: Vec<Call>,
) {
    let (subnet1, subnet2, _) = setup.into_parts();

    assert!(false);
}
