pub mod common;

use common::{KB, MB, TestSubnet};
use ic_state_machine_tests::two_subnets_simple;
use ic_types::Cycles;
use messaging_test::{Call, Message, Reply, Response, decode_reply, encode_message};

#[test]
fn gradius() {
    let (local_env, remote_env) = two_subnets_simple();
    let mut local_subnet = TestSubnet::new(local_env, 2);

    let canisters = local_subnet.canisters();

    let msg = Message {
        call_index: 0,
        reply_bytes: 1 * MB,
        downstream_calls: vec![],
    };

    local_subnet.pulse(canisters[0], msg).unwrap();

    let msg = Message {
        call_index: 0,
        reply_bytes: 10 * KB,
        downstream_calls: vec![Call {
            receiver: canisters[1],
            //call_bytes: 2 * MB,
            call_bytes: 2 * MB - 1000,
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

    local_subnet.pulse(canisters[0], msg).unwrap();

    println!("{:#?}", local_subnet.pulses());
    local_subnet.execute_round();
    local_subnet.execute_round();
    local_subnet.execute_round();
    local_subnet.execute_round();

    local_subnet.update_submitted_pulses();

    println!("{:#?}", local_subnet.pulses());
}
