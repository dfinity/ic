pub mod common;

use assert_matches::assert_matches;
use common::{TestSubnet, TestSubnetConfig, TestSubnetSetup, arb_test_subnets, two_test_subnets};
use ic_types::{
    CanisterId, PrincipalId,
    ingress::{IngressState, IngressStatus},
    messages::StreamMessage,
};
use messaging_test::Call;
use messaging_test_utils::{CallConfig, arb_call};
use proptest::prelude::ProptestConfig;

#[test]
fn test_canister_can_be_stopped_with_hanging_call_on_stalled_subnet() {
    let (mut subnet1, subnet2) =
        two_test_subnets(TestSubnetConfig::default(), TestSubnetConfig::default());

    let [canister1] = subnet1.canisters()[..] else {
        unreachable!()
    };
    let [canister2] = subnet2.canisters()[..] else {
        unreachable!()
    };

    // A call sent to `subnet1` as ingress, which then best-effort call to `subnet2`.
    let call = Call {
        receiver: canister1,
        downstream_calls: vec![Call {
            receiver: canister2,
            timeout_secs: Some(10),
            ..Call::default()
        }],
        ..Call::default()
    };
    /*
    subnet1
        .pulse(Call {
            receiver: canister1,
            downstream_calls: vec![Call {
                receiver: canister2,
                timeout_secs: Some(10),
                ..Call::default()
            }],
            ..Call::default()
        })
        .unwrap();
    */

    let (receiver, payload) = messaging_test_utils::to_encoded_ingress(call);
    let msg_id = subnet1
        .env
        .submit_ingress_as(PrincipalId::new_anonymous(), receiver, "pulse", payload)
        .unwrap();
    subnet1.execute_round();
    let status = subnet1.env.ingress_status(&msg_id);
    assert!(false, "{:#?}", status);

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
    let msg_id = subnet1.env.stop_canister_non_blocking(canister1);
    subnet1.execute_round();

    // Advance time and execute another round; this should time out the downstream call
    // and allow the ingress to conclude.
    subnet1
        .env
        .advance_time(std::time::Duration::from_secs(100));
    subnet1.execute_round();

    let status = subnet1.env.ingress_status(&msg_id);
    let IngressStatus::Known { receiver, .. } = status else {
        unreachable!();
    };
    let receiver = CanisterId::unchecked_from_principal(receiver);
    assert!(false, "{:#?}\n\n{:#?}", status, receiver);

    //subnet1.update_submitted_pulses();
    */

    /*
    pub fn stop_canister_non_blocking(&self, canister_id: CanisterId) -> MessageId {

    // Tick for up to `shutdown_phase_max_rounds` times on the local subnet only
    // or until the local canister has stopped.
    for _ in 0..shutdown_phase_max_rounds {
        match subnets.local_env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            } => return subnets.check_canister_traps(),
            _ => {
                subnets.local_env.tick();
                subnets
                    .local_env
                    .advance_time(std::time::Duration::from_secs(1));
            }
        }
    }
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
