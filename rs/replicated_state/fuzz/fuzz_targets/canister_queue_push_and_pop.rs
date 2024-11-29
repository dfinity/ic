#![no_main]
use ic_replicated_state::canister_state::queues::message_pool::{
    Class, InboundReference, Kind, OutboundReference, Reference,
};

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use ic_replicated_state::canister_state::queues::queue::{InputQueue, OutputQueue};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

#[derive(Debug)]
struct ArbQueue {
    inbound: VecDeque<InboundReference>,
    outbound: VecDeque<OutboundReference>,
}

const QUEUE_BOUND: usize = 5000;

impl<'a> Arbitrary<'a> for ArbQueue {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        if u.is_empty() {
            return Ok(ArbQueue {
                inbound: VecDeque::new(),
                outbound: VecDeque::new(),
            });
        }

        let range: usize = u.int_in_range(1..=QUEUE_BOUND).unwrap();
        let inbound: VecDeque<InboundReference> = (0..range)
            .map(|g| g as u64)
            .map(|g| {
                *u.choose(&[
                    Reference::new(Class::BestEffort, Kind::Request, g),
                    Reference::new(Class::BestEffort, Kind::Response, g),
                    Reference::new(Class::GuaranteedResponse, Kind::Request, g),
                    Reference::new(Class::GuaranteedResponse, Kind::Response, g),
                ])
                .unwrap()
            })
            .collect();

        let range: usize = u.int_in_range(1..=QUEUE_BOUND).unwrap();
        let outbound: VecDeque<OutboundReference> = (0..range)
            .map(|g| g as u64)
            .map(|g| {
                *u.choose(&[
                    Reference::new(Class::BestEffort, Kind::Request, g),
                    Reference::new(Class::BestEffort, Kind::Response, g),
                    Reference::new(Class::GuaranteedResponse, Kind::Request, g),
                    Reference::new(Class::GuaranteedResponse, Kind::Response, g),
                ])
                .unwrap()
            })
            .collect();

        Ok(ArbQueue { inbound, outbound })
    }
}

fuzz_target!(|arb_queue: ArbQueue| {
    let mut references = arb_queue.inbound;

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

    let mut references = arb_queue.outbound;

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
