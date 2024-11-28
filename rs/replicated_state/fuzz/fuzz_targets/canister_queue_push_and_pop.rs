#![no_main]
use arbitrary::Arbitrary;
use ic_replicated_state::canister_state::queues::message_pool::ArbitraryVec;
use ic_replicated_state::canister_state::queues::message_pool::QUEUE_BOUND;
use ic_replicated_state::canister_state::queues::message_pool::{
    InboundReference, Kind, OutboundReference,
};
use ic_replicated_state::canister_state::queues::queue::{InputQueue, OutputQueue};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct ArbQueue {
    inbound: ArbitraryVec<InboundReference>,
    outbound: ArbitraryVec<OutboundReference>,
}

fuzz_target!(|arb_queue: ArbQueue| {
    let mut references = arb_queue.inbound.0;

    if !references.is_empty() {
        let mut queue = InputQueue::new(QUEUE_BOUND);

        for reference in references.iter() {
            match reference {
                reference if reference.kind() == Kind::Request => {
                    queue.push_request(*reference);
                }
                reference => {
                    queue.try_reserve_response_slot().unwrap();
                    queue.push_response(*reference);
                }
            }
            assert_eq!(Ok(()), queue.check_invariants());
        }

        while let Some(r) = queue.peek() {
            let reference = references.pop_front();
            assert_eq!(reference, Some(r));
            assert_eq!(reference, queue.pop());
        }

        assert!(references.is_empty());
    }

    let mut references = arb_queue.outbound.0;

    if !references.is_empty() {
        let mut queue = OutputQueue::new(QUEUE_BOUND);

        for reference in references.iter() {
            match reference {
                reference if reference.kind() == Kind::Request => {
                    queue.push_request(*reference);
                }
                reference => {
                    queue.try_reserve_response_slot().unwrap();
                    queue.push_response(*reference);
                }
            }
            assert_eq!(Ok(()), queue.check_invariants());
        }

        while let Some(r) = queue.peek() {
            let reference = references.pop_front();
            assert_eq!(reference, Some(r));
            assert_eq!(reference, queue.pop());
        }

        assert!(references.is_empty());
    }
});
