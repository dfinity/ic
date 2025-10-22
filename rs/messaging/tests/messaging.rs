pub mod common;

use common::{KB, MB, TestSubnetsConfig, two_test_subnets};
use messaging_test::Call;

#[test]
fn gradius() {
    let (mut local_subnet, _remote_subnet) = two_test_subnets(TestSubnetsConfig {
        local_canisters_count: 2,
        remote_canisters_count: 1,
        ..TestSubnetsConfig::default()
    });

    let canisters = local_subnet.canisters();

    let call = Call {
        receiver: canisters[0],
        call_bytes: 2 * KB,
        reply_bytes: 1 * MB,
        timeout_secs: None,
        downstream_calls: vec![],
    };

    local_subnet.pulse(call).unwrap();

    let call = Call {
        receiver: canisters[1],
        call_bytes: 1 * MB,
        reply_bytes: 10 * KB,
        timeout_secs: None,
        downstream_calls: vec![Call {
            receiver: canisters[1],
            //call_bytes: 2 * MB,
            call_bytes: 1 * KB,
            reply_bytes: 5 * KB,
            timeout_secs: None,
            downstream_calls: vec![Call {
                receiver: canisters[0],
                call_bytes: 10 * KB,
                reply_bytes: 100 * KB,
                timeout_secs: Some(60),
                downstream_calls: vec![],
            }],
        }],
    };

    local_subnet.pulse(call).unwrap();

    println!("{:#?}", local_subnet.pulses());
    local_subnet.execute_round();
    local_subnet.execute_round();
    local_subnet.execute_round();
    local_subnet.execute_round();

    local_subnet.update_submitted_pulses();

    println!("{:#?}", local_subnet.pulses());
}
