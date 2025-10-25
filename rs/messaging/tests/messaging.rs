pub mod common;

use assert_matches::assert_matches;
use common::{TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets, two_test_subnets};
use ic_error_types::RejectCode;
use ic_management_canister_types_private::CanisterStatusType;
use ic_types::{
    CanisterId, PrincipalId,
    ingress::{IngressState, IngressStatus},
    messages::StreamMessage,
};
use messaging_test::{Call, Response};
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::ProptestConfig;

#[test]
fn test_canister_can_be_stopped_with_hanging_call_on_stalled_subnet() {
    let (subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());

    let canister1 = subnet1.principal_canister();
    let canister2 = subnet2.principal_canister();

    // A call sent to `subnet1` as ingress, which then makes a best-effort call to `subnet2`.
    let msg_id = subnet1
        .submit_call(Call {
            receiver: canister1,
            downstream_calls: vec![Call {
                receiver: canister2,
                timeout_secs: Some(10),
                ..Call::default()
            }],
            ..Call::default()
        })
        .unwrap();

    // Two rounds should be enough to route the message to `subnet2`.
    subnet1.execute_round();
    subnet1.execute_round();
    // Put `canister1` into `Stopping` state.
    subnet1.env.stop_canister_non_blocking(canister1);
    subnet1.execute_round();
    // Advance time and execute another round; this should time out the downstream call
    // and allow the ingress to conclude.
    subnet1
        .env
        .advance_time(std::time::Duration::from_secs(100));
    subnet1.execute_round();

    // The downstream call was timed out...
    assert_matches!(
        subnet1.try_get_response(&msg_id),
        Ok(Response::Success {
            downstream_responses,
            ..
        }) if matches!(downstream_responses[..], [Response::AsyncReject {
            reject_code: RejectCode::SysUnknown as u32,
            ..
        }])
    );
    // ...and the canister was stopped.
    assert_matches!(
        subnet1.canister_status(&canister1),
        Some(CanisterStatusType::Stopped)
    );
    /*




        // Two rounds should be enough to route the message into the stream to `subnet2`.
        subnet1.execute_round();
        subnet1.execute_round();
        assert_matches!(
            subnet1
                .stream_snapshot(subnet2.id())
                .map(|(_, msgs)| msgs)
                .as_deref(),
            Some([StreamMessage::Request(_)])
        );

        // Put `canister1` into `Stopping` state.
        subnet1.env.stop_canister_non_blocking(canister1);
        subnet1.execute_round();

        // Advance time and execute another round; this should time out the downstream call
        // and allow the ingress to conclude.
        subnet1
            .env
            .advance_time(std::time::Duration::from_secs(100));
        subnet1.execute_round();

        assert_matches!(
            subnet1.try_get_response(&msg_id),
            Ok(Response::Success { .. })
        );
        assert_matches!(
            subnet1.canister_status(&canister1),
            Some(CanisterStatusType::Stopped)
        );
    */
}

/*
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
*/
