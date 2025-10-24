pub mod common;

use common::{TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets};
use ic_types::CanisterId;
use messaging_test::Call;
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::ProptestConfig;

#[test]
fn test_canister_can_be_stopped_with_hanging_call_on_stalled_subnet() {
    let (mut subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());

    // A call to be sent as ingress to `subnet1`,
    // which then makes a best-effort call to `subnet2`.
    let call = Call {
        receiver: subnet1.canisters()[0],
        call_bytes: 345,
        reply_bytes: 567,
        timeout_secs: None,
        downstream_calls: vec![Call {
            receiver: subnet2.canisters()[0],
            call_bytes: 678,
            reply_bytes: 543,
            timeout_secs: Some(10),
            downstream_calls: vec![],
        }],
    };
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
