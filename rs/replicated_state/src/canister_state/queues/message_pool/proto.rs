use super::*;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::queues::v1 as pb_queues;

impl<T> TryFrom<u64> for Reference<T>
where
    T: ToContext,
{
    type Error = ProxyDecodeError;
    fn try_from(item: u64) -> Result<Self, Self::Error> {
        let id = Id(item);
        if id.context() == T::context() {
            Ok(Reference(item, PhantomData))
        } else {
            Err(ProxyDecodeError::Other(format!(
                "Mismatched reference context: {item}"
            )))
        }
    }
}

impl<T> From<&Reference<T>> for u64 {
    fn from(item: &Reference<T>) -> Self {
        item.0
    }
}

impl From<CallbackReference> for pb_queues::canister_queues::CallbackReference {
    fn from(item: CallbackReference) -> Self {
        Self {
            id: item.0.0,
            callback_id: item.1.get(),
        }
    }
}

impl TryFrom<pb_queues::canister_queues::CallbackReference> for CallbackReference {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_queues::canister_queues::CallbackReference) -> Result<Self, Self::Error> {
        let reference = Reference(item.id, PhantomData);
        if reference.is_inbound_best_effort_response() {
            Ok(CallbackReference(reference, item.callback_id.into()))
        } else {
            Err(ProxyDecodeError::Other(
                "Not an inbound best-effort response".to_string(),
            ))
        }
    }
}

impl From<&MessagePool> for pb_queues::MessagePool {
    fn from(item: &MessagePool) -> Self {
        use pb_queues::message_pool::*;

        Self {
            messages: item
                .messages
                .iter()
                .map(|(id, message)| Entry {
                    id: id.0,
                    message: Some(message.into()),
                })
                .collect(),
            outbound_guaranteed_request_deadlines: item
                .outbound_guaranteed_request_deadlines
                .iter()
                .map(|(id, deadline)| MessageDeadline {
                    deadline_seconds: deadline.as_secs_since_unix_epoch(),
                    id: id.0,
                })
                .collect(),
            message_id_generator: item.message_id_generator,
        }
    }
}

impl TryFrom<pb_queues::MessagePool> for MessagePool {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_queues::MessagePool) -> Result<Self, Self::Error> {
        let message_count = item.messages.len();

        let messages: MutableIntMap<_, _> = item
            .messages
            .into_iter()
            .map(|entry| {
                let id = Id(entry.id);
                let message = try_from_option_field(entry.message, "MessagePool::Entry::message")?;
                Ok((id, message))
            })
            .collect::<Result<_, Self::Error>>()?;
        if messages.len() != message_count {
            return Err(ProxyDecodeError::Other("Duplicate Id".to_string()));
        }
        let message_stats = Self::calculate_message_stats(&messages);

        let outbound_guaranteed_request_deadlines = item
            .outbound_guaranteed_request_deadlines
            .into_iter()
            .map(|entry| {
                let id = Id(entry.id);
                let deadline = CoarseTime::from_secs_since_unix_epoch(entry.deadline_seconds);
                (id, deadline)
            })
            .collect();

        let (deadline_queue, size_queue) =
            Self::calculate_priority_queues(&messages, &outbound_guaranteed_request_deadlines);

        let res = Self {
            messages,
            outbound_guaranteed_request_deadlines,
            message_stats,
            deadline_queue,
            size_queue,
            message_id_generator: item.message_id_generator,
        };

        // Ensure that we've built a valid `MessagePool`.
        res.check_invariants().map_err(ProxyDecodeError::Other)?;

        Ok(res)
    }
}
