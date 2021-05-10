mod queue;

use crate::StateError;
use ic_interfaces::messages::CanisterInputMessage;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    xnet::{QueueId, SessionId},
    CanisterId, QueueIndex,
};
use queue::{IngressQueue, InputQueue, OutputQueue};
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

pub const DEFAULT_QUEUE_CAPACITY: usize = 500;

/// "None" queue index used internally by Message Routing for reject responses
/// generated e.g. when a request cannot be inducted due to a full input queue
/// (and enqueuing the response into the output queue might also fail).
pub const QUEUE_INDEX_NONE: QueueIndex = QueueIndex::new(std::u64::MAX);

/// Wrapper around the induction pool (ingress and input queues); a priority
/// queue used for round-robin scheduling of senders when consuming input
/// messages; and output queues.
///
/// Responsible for queue lifetime management, fair scheduling of inputs across
/// sender canisters and queue backpressure.
///
/// Encapsulates the `InductionPool` component described in the spec. The reason
/// for bundling together the induction pool and output queues is to reliably
/// implement backpressure via queue reservations for response messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterQueues {
    /// Queue of ingress (user) messages.
    ingress_queue: IngressQueue,

    /// Per-sender input (canister-to-canister message) queues.
    input_queues: BTreeMap<CanisterId, InputQueue>,

    /// FIFO queue of sender canister IDs ensuring round-robin consumption of
    /// input messages. Only senders with non-empty queues are scheduled.
    input_schedule: VecDeque<CanisterId>,

    /// Per-receiver output (canister-to-canister message) queues.
    output_queues: BTreeMap<CanisterId, OutputQueue>,
}

impl CanisterQueues {
    /// Pushes an ingress message into the induction pool.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.ingress_queue.push(msg)
    }

    /// Pops the next ingress message from `ingress_queue`.
    fn pop_ingress(&mut self) -> Option<Ingress> {
        self.ingress_queue.pop()
    }

    pub(crate) fn output_queues_mut(&mut self) -> &mut BTreeMap<CanisterId, OutputQueue> {
        &mut self.output_queues
    }

    /// See IngressQueue::filter_messages() for documentation
    pub fn filter_ingress_messages<F>(&mut self, filter: F)
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.ingress_queue.filter_messages(filter);
    }

    /// Pushes a canister-to-canister message into the induction pool.
    ///
    /// If the message is a `Request` this will also reserve a slot in the
    /// corresponding output queue for the eventual response.
    ///
    /// If the message is a `Response` the protocol will have already reserved
    /// space for it, so the push cannot fail due to the input queue being
    /// full.
    ///
    /// # Errors
    ///
    /// Returns a `StateError` along with the provided message:
    ///
    ///  * `QueueFull` if pushing a `Request` and the corresponding input or
    ///    output queues are full.
    ///
    ///  * `QueueFull` if pushing a `Response` and the receiving canister is not
    ///  expecting one.
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let sender = msg.sender();
        let input_queue = match msg {
            RequestOrResponse::Request(_) => {
                let (input_queue, output_queue) = self.get_or_insert_queues(&sender);
                if let Err(e) = input_queue.check_has_slot() {
                    return Err((e, msg));
                }
                if let Err(e) = output_queue.reserve_slot() {
                    return Err((e, msg));
                }
                input_queue
            }
            RequestOrResponse::Response(_) => match self.input_queues.get_mut(&sender) {
                Some(queue) => queue,
                None => return Err((StateError::QueueFull { capacity: 0 }, msg)),
            },
        };
        input_queue.push(index, msg)?;

        // Add sender canister ID to the input schedule queue if it isn't already there.
        // Sender was not scheduled iff its input queue was empty before the push (i.e.
        // queue size is 1 after the push).
        if input_queue.num_messages() == 1 {
            self.input_schedule.push_back(sender);
        }
        Ok(())
    }

    /// Pops the next canister-to-canister message from `input_queues`.
    ///
    /// Note: We pop senders from the head of `input_schedule` and insert them
    /// to the back, which allows us to handle messages from different
    /// originators in a round-robin fashion.
    fn pop_canister_input(&mut self) -> Option<RequestOrResponse> {
        if let Some(sender) = self.input_schedule.pop_front() {
            // Get the message queue of this canister.
            let input_queue = self.input_queues.get_mut(&sender).unwrap();
            let msg = input_queue.pop().unwrap();
            // If the queue still isn't empty, re-add sender canister ID to the end of the
            // input schedule queue.
            if input_queue.num_messages() != 0 {
                self.input_schedule.push_back(sender);
            }

            return Some(msg);
        }

        None
    }

    /// Returns `true` if `ingress_queue` or at least one of the `input_queues`
    /// is not empty; `false` otherwise.
    pub fn has_input(&self) -> bool {
        !self.ingress_queue.is_empty()
            || self
                .input_queues
                .iter()
                .any(|(_, queue)| queue.num_messages() > 0)
    }

    /// Returns `true` if at least one output queue is not empty; false
    /// otherwise.
    pub fn has_output(&self) -> bool {
        self.output_queues
            .iter()
            .any(|(_, queue)| queue.num_messages() > 0)
    }

    /// Extracts the next inter-canister or ingress message (in that order).
    /// If no inter-canister messages are available in the induction pool, we
    /// pop the next ingress message.
    pub fn pop_input(&mut self) -> Option<CanisterInputMessage> {
        // Return the next inter-canister message if one exists.
        if let Some(msg) = self.pop_canister_input() {
            return Some(match msg {
                RequestOrResponse::Request(msg) => CanisterInputMessage::Request(msg),
                RequestOrResponse::Response(msg) => CanisterInputMessage::Response(msg),
            });
        }
        self.pop_ingress().map(CanisterInputMessage::Ingress)
    }

    /// Pushes a `Request` type message into the relevant output queue. Also
    /// reserves a slot for the eventual response on the matching input queue.
    ///
    /// # Errors
    ///
    /// Returns a `QueueFull` error along with the provided message if either
    /// the output queue or the matching input queue is full.
    pub fn push_output_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        let (input_queue, output_queue) = self.get_or_insert_queues(&msg.receiver);

        if let Err(e) = output_queue.check_has_slot() {
            return Err((e, msg));
        }
        if let Err(e) = input_queue.reserve_slot() {
            return Err((e, msg));
        }

        output_queue.push_request(msg)
    }

    /// Pushes a `Response` type message into the relevant output queue. The
    /// protocol should have already reserved a slot, so this cannot fail.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_output_response(&mut self, msg: Response) {
        let receiver = &msg.originator;
        // As long as we are not garbage collecting output queues, we are guaranteed
        // that an output queue should exist for pushing responses because one would
        // have been created when the request (that triggered this response) was
        // inducted into the induction pool.
        self.output_queues
            .get_mut(receiver)
            .unwrap()
            .push_response(msg);
    }

    /// Returns an iterator that consumes all output messages.
    pub fn output_into_iter<'a>(
        &'a mut self,
        owner: CanisterId,
    ) -> impl std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)> + 'a {
        self.output_queues
            .iter_mut()
            // Flat map output queues to their contents (prepended with a `QueueId`).
            .flat_map(move |(receiver, queue)| {
                let queue_id = QueueId {
                    dst_canister: *receiver,
                    src_canister: owner,
                    session_id: SessionId::from(0),
                };
                // Zip repeated `queue_id` with message iterator (the output queue).
                std::iter::repeat(queue_id).zip(queue)
            })
            // Remap to a flat tuple.
            .map(|(queue_id, (queue_index, msg))| {
                assert_eq!(queue_id.src_canister, msg.sender());
                (queue_id, queue_index, msg)
            })
    }

    fn get_or_insert_queues(
        &mut self,
        canister_id: &CanisterId,
    ) -> (&mut InputQueue, &mut OutputQueue) {
        let input_queue = self
            .input_queues
            .entry(*canister_id)
            .or_insert_with(|| InputQueue::new(DEFAULT_QUEUE_CAPACITY));
        let output_queue = self
            .output_queues
            .entry(*canister_id)
            .or_insert_with(|| OutputQueue::new(DEFAULT_QUEUE_CAPACITY));
        (input_queue, output_queue)
    }
}

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        Self {
            ingress_queue: (&item.ingress_queue).into(),
            input_queues: item
                .input_queues
                .iter()
                .map(|(canid, input_queue)| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(input_queue.into()),
                })
                .collect(),
            input_schedule: item
                .input_schedule
                .iter()
                .map(|canid| pb_types::CanisterId::from(*canid))
                .collect(),
            output_queues: item
                .output_queues
                .iter()
                .map(|(canid, output_queue)| pb_queues::QueueEntry {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    queue: Some(output_queue.into()),
                })
                .collect(),
        }
    }
}

impl TryFrom<pb_queues::CanisterQueues> for CanisterQueues {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_queues::CanisterQueues) -> Result<Self, Self::Error> {
        if item.input_queues.len() != item.input_queues.len() {
            return Err(ProxyDecodeError::Other(format!(
                "CanisterQueues: Mismatched input ({}) and output ({}) queue lengths",
                item.input_queues.len(),
                item.output_queues.len()
            )));
        }
        if let Some((ie, oe)) = item
            .input_queues
            .iter()
            .zip(item.output_queues.iter())
            .find(|(ie, oe)| ie.canister_id != oe.canister_id)
        {
            return Err(ProxyDecodeError::Other(format!(
                "Mismatched input {:?} and output {:?} queue entries",
                ie.canister_id, oe.canister_id
            )));
        }

        let mut input_queues = BTreeMap::<CanisterId, InputQueue>::new();
        for entry in item.input_queues {
            let can_id =
                try_from_option_field(entry.canister_id, "CanisterQueues::input_queues::K")?;
            let iq = try_from_option_field(entry.queue, "CanisterQueues::input_queues::V")?;
            input_queues.insert(can_id, iq);
        }

        let mut output_queues = BTreeMap::<CanisterId, OutputQueue>::new();
        for entry in item.output_queues {
            let can_id =
                try_from_option_field(entry.canister_id, "CanisterQueues::output_queues::K")?;

            let oq = try_from_option_field(entry.queue, "CanisterQueues::output_queues::V")?;
            output_queues.insert(can_id, oq);
        }

        let mut input_schedule = VecDeque::new();
        for can_id in item.input_schedule.into_iter() {
            let c = CanisterId::try_from(can_id)?;
            input_schedule.push_back(c);
        }

        Ok(Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            input_schedule,
            input_queues,
            output_queues,
        })
    }
}

pub mod testing {
    use super::CanisterQueues;
    use ic_types::{messages::RequestOrResponse, CanisterId, QueueIndex};

    /// Exposes public testing-only `CanisterQueues` methods to be used in other
    /// crates' unit tests.
    pub trait CanisterQueuesTesting {
        /// Returns the number of messages in `ingress_queue`.
        fn ingress_queue_size(&self) -> usize;

        /// Pops the next message from the output queue associated with
        /// `dst_canister`. Returned `QueueIndex` values are sequential across
        /// successful calls.
        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)>;

        /// Returns the number of output queues, empty or not.
        fn output_queues_len(&self) -> usize;

        /// Returns the total number of messages in the output queues.
        fn output_message_count(&self) -> usize;
    }

    impl CanisterQueuesTesting for CanisterQueues {
        fn ingress_queue_size(&self) -> usize {
            self.ingress_queue.size()
        }

        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)> {
            match self.output_queues.get_mut(dst_canister) {
                None => None,
                Some(canister_out_queue) => canister_out_queue.pop(),
            }
        }

        fn output_queues_len(&self) -> usize {
            self.output_queues.len()
        }

        fn output_message_count(&self) -> usize {
            self.output_queues
                .iter()
                .map(|(_, q)| q.num_messages())
                .sum()
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::CanisterInputMessage;
    use super::*;
    use ic_test_utilities::types::{
        ids::{canister_test_id, message_test_id, user_test_id},
        messages::{RequestBuilder, ResponseBuilder},
    };
    use ic_types::time::current_time_and_expiry_time;

    #[test]
    // Can push one request to the output queues.
    fn can_push_output_request() {
        let this = canister_test_id(13);
        let mut queues = CanisterQueues::default();
        queues
            .push_output_request(RequestBuilder::default().sender(this).build())
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "alled `Option::unwrap()` on a `None` value")]
    // Cannot push response to output queues without pushing an input request first.
    fn cannot_push_output_response_without_input_request() {
        let this = canister_test_id(13);
        let mut queues = CanisterQueues::default();
        queues.push_output_response(ResponseBuilder::default().respondent(this).build());
    }

    #[test]
    fn enqueuing_unexpected_response_does_not_panic() {
        let other = canister_test_id(14);
        let this = canister_test_id(13);
        let mut queues = CanisterQueues::default();
        // Enqueue a request to create a queue for `other`.
        queues
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .sender(other)
                    .receiver(this)
                    .build()
                    .into(),
            )
            .unwrap();
        // Now `other` sends an unexpected `Response`.  We should return an error not
        // panic.
        queues
            .push_input(
                QUEUE_INDEX_NONE,
                ResponseBuilder::default()
                    .respondent(other)
                    .originator(this)
                    .build()
                    .into(),
            )
            .unwrap_err();
    }

    #[test]
    // Can push response to output queues after pushing input request.
    fn can_push_output_response_after_input_request() {
        let this = canister_test_id(13);
        let other = canister_test_id(14);
        let mut queues = CanisterQueues::default();
        queues
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .sender(other)
                    .receiver(this)
                    .build()
                    .into(),
            )
            .unwrap();
        queues.push_output_response(
            ResponseBuilder::default()
                .respondent(this)
                .originator(other)
                .build(),
        );
    }

    #[test]
    // Can push one request to the induction pool.
    fn can_push_input_request() {
        let this = canister_test_id(13);
        let mut queues = CanisterQueues::default();
        queues
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default().receiver(this).build().into(),
            )
            .unwrap();
    }

    #[test]
    // Cannot push response to the induction pool without pushing output request
    // first.
    fn cannot_push_input_response_without_output_request() {
        let this = canister_test_id(13);
        let mut queues = CanisterQueues::default();
        queues
            .push_input(
                QueueIndex::from(0),
                ResponseBuilder::default().originator(this).build().into(),
            )
            .unwrap_err();
    }

    #[test]
    // Can push response to input queues after pushing request to output queues.
    fn can_push_input_response_after_output_request() {
        let this = canister_test_id(13);
        let other = canister_test_id(14);
        let mut queues = CanisterQueues::default();
        queues
            .push_output_request(
                RequestBuilder::default()
                    .sender(this)
                    .receiver(other)
                    .build(),
            )
            .unwrap();
        queues
            .push_input(
                QueueIndex::from(0),
                ResponseBuilder::default()
                    .respondent(other)
                    .originator(this)
                    .build()
                    .into(),
            )
            .unwrap();
    }

    #[test]
    // Enqueues 10 ingress messages and pops them.
    fn test_message_picking_ingress_only() {
        let this = canister_test_id(13);

        let mut queues = CanisterQueues::default();
        assert!(queues.pop_input().is_none());

        for i in 0..10 {
            queues.push_ingress(Ingress {
                source: user_test_id(77),
                receiver: this,
                method_name: String::from("test"),
                method_payload: vec![i as u8],
                message_id: message_test_id(555),
                expiry_time: current_time_and_expiry_time().1,
            });
        }

        let mut expected_byte = 0;
        while queues.has_input() {
            match queues.pop_input().expect("could not pop a message") {
                CanisterInputMessage::Ingress(msg) => {
                    assert_eq!(msg.method_payload, vec![expected_byte])
                }
                msg => panic!("unexpected message popped: {:?}", msg),
            }
            expected_byte += 1;
        }
        assert_eq!(10, expected_byte);

        assert!(queues.pop_input().is_none());
    }

    #[test]
    // Enqueues 3 requests for the same canister and consumes them.
    fn test_message_picking_round_robin_on_one_queue() {
        let this = canister_test_id(13);
        let other = canister_test_id(14);

        let mut queues = CanisterQueues::default();
        assert!(queues.pop_input().is_none());

        let list = vec![(0, other), (1, other), (2, other)];
        for (ix, id) in list.iter() {
            queues
                .push_input(
                    QueueIndex::from(*ix),
                    RequestBuilder::default()
                        .sender(*id)
                        .receiver(this)
                        .build()
                        .into(),
                )
                .expect("could not push");
        }

        for _ in 0..list.len() {
            match queues.pop_input().expect("could not pop a message") {
                CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other),
                msg => panic!("unexpected message popped: {:?}", msg),
            }
        }

        assert!(!queues.has_input());
        assert!(queues.pop_input().is_none());
    }

    #[test]
    // Enqueues 3 requests and 1 response, then pops them and verifies the expected
    // order.
    fn test_message_picking_round_robin() {
        let this = canister_test_id(13);
        let other_1 = canister_test_id(1);
        let other_2 = canister_test_id(2);
        let other_3 = canister_test_id(3);

        let mut queues = CanisterQueues::default();
        assert!(queues.pop_input().is_none());

        for (ix, id) in &[(0, other_1), (1, other_1), (0, other_3)] {
            queues
                .push_input(
                    QueueIndex::from(*ix),
                    RequestBuilder::default()
                        .sender(*id)
                        .receiver(this)
                        .build()
                        .into(),
                )
                .expect("could not push");
        }

        queues
            .push_output_request(
                RequestBuilder::default()
                    .sender(this)
                    .receiver(other_2)
                    .build(),
            )
            .unwrap();
        // This succeeds because we pushed a request to other_2 to the output_queue
        // above which reserved a slot for the expected response here.
        queues
            .push_input(
                QueueIndex::from(0),
                ResponseBuilder::default()
                    .respondent(other_2)
                    .originator(this)
                    .build()
                    .into(),
            )
            .expect("could not push");

        queues.push_ingress(Ingress {
            source: user_test_id(77),
            receiver: this,
            method_name: String::from("test"),
            method_payload: Vec::new(),
            message_id: message_test_id(555),
            expiry_time: current_time_and_expiry_time().1,
        });

        /* POPPING */

        // Pop request from other_1
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_1),
            msg => panic!("unexpected message popped: {:?}", msg),
        }

        // Pop request from other_3
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_3),
            msg => panic!("unexpected message popped: {:?}", msg),
        }

        // Pop response from other_2
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Response(msg) => assert_eq!(msg.respondent, other_2),
            msg => panic!("unexpected message popped: {:?}", msg),
        }

        // Pop request from other_1
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Request(msg) => assert_eq!(msg.sender, other_1),
            msg => panic!("unexpected message popped: {:?}", msg),
        }

        // Pop last ingress msg
        match queues.pop_input().expect("could not pop a message") {
            CanisterInputMessage::Ingress(msg) => assert_eq!(msg.source, user_test_id(77)),
            msg => panic!("unexpected message popped: {:?}", msg),
        }

        assert!(!queues.has_input());
        assert!(queues.pop_input().is_none());
    }

    #[test]
    // Enqueues 4 input requests across 3 canisters and consumes them, ensuring
    // correct round-robin scheduling.
    fn test_input_scheduling() {
        let this = canister_test_id(13);
        let other_1 = canister_test_id(1);
        let other_2 = canister_test_id(2);
        let other_3 = canister_test_id(3);

        let mut queues = CanisterQueues::default();
        assert_eq!(false, queues.has_input());

        let push_input_from = |queues: &mut CanisterQueues, sender: &CanisterId, index: u64| {
            queues
                .push_input(
                    QueueIndex::from(index),
                    RequestBuilder::default()
                        .sender(*sender)
                        .receiver(this)
                        .build()
                        .into(),
                )
                .expect("could not push");
        };

        let assert_schedule = |queues: &CanisterQueues, expected_schedule: &[&CanisterId]| {
            let schedule: Vec<&CanisterId> = queues.input_schedule.iter().collect();
            assert_eq!(expected_schedule, schedule.as_slice());
        };

        let assert_sender = |sender: &CanisterId, message: CanisterInputMessage| match message {
            CanisterInputMessage::Request(req) => assert_eq!(*sender, req.sender),
            _ => unreachable!(),
        };

        push_input_from(&mut queues, &other_1, 0);
        assert_schedule(&queues, &[&other_1]);

        push_input_from(&mut queues, &other_2, 0);
        assert_schedule(&queues, &[&other_1, &other_2]);

        push_input_from(&mut queues, &other_1, 1);
        assert_schedule(&queues, &[&other_1, &other_2]);

        push_input_from(&mut queues, &other_3, 0);
        assert_schedule(&queues, &[&other_1, &other_2, &other_3]);

        assert_sender(&other_1, queues.pop_input().unwrap());
        assert_schedule(&queues, &[&other_2, &other_3, &other_1]);

        assert_sender(&other_2, queues.pop_input().unwrap());
        assert_schedule(&queues, &[&other_3, &other_1]);

        assert_sender(&other_3, queues.pop_input().unwrap());
        assert_schedule(&queues, &[&other_1]);

        assert_sender(&other_1, queues.pop_input().unwrap());
        assert_schedule(&queues, &[]);

        assert_eq!(false, queues.has_input());
    }

    #[test]
    // Enqueues 6 output requests across 3 canisters and consumes them.
    fn test_output_into_iter() {
        let this = canister_test_id(13);
        let other_1 = canister_test_id(1);
        let other_2 = canister_test_id(2);
        let other_3 = canister_test_id(3);

        let canister_id = canister_test_id(1);
        let mut queues = CanisterQueues::default();
        assert_eq!(0, queues.output_into_iter(canister_id).count());

        let destinations = vec![other_1, other_2, other_1, other_3, other_2, other_1];
        for (i, id) in destinations.iter().enumerate() {
            queues
                .push_output_request(
                    RequestBuilder::default()
                        .sender(this)
                        .receiver(*id)
                        .method_payload(vec![i as u8])
                        .build(),
                )
                .expect("could not push");
        }

        let expected = vec![
            (&other_1, 0, 0),
            (&other_1, 1, 2),
            (&other_1, 2, 5),
            (&other_2, 0, 1),
            (&other_2, 1, 4),
            (&other_3, 0, 3),
        ];
        assert_eq!(
            expected.len(),
            queues.clone().output_into_iter(this).count()
        );

        for (i, (qid, idx, msg)) in queues.output_into_iter(this).enumerate() {
            assert_eq!(this, qid.src_canister);
            assert_eq!(*expected[i].0, qid.dst_canister);
            assert_eq!(expected[i].1, idx.get());
            match msg {
                RequestOrResponse::Request(msg) => {
                    assert_eq!(vec![expected[i].2], msg.method_payload)
                }
                msg => panic!("unexpected message popped: {:?}", msg),
            }
        }

        assert_eq!(0, queues.output_into_iter(canister_id).count());
    }
}
