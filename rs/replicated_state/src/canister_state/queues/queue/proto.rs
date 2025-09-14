use super::*;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::ingress::v1 as pb_ingress;
use ic_protobuf::state::queues::v1 as pb_queues;

impl<T> From<&CanisterQueue<T>> for pb_queues::CanisterQueue {
    fn from(item: &CanisterQueue<T>) -> Self {
        Self {
            queue: item.queue.iter().map(Into::into).collect(),
            capacity: item.capacity as u64,
            response_slots: item.response_slots as u64,
        }
    }
}

impl<T> TryFrom<pb_queues::CanisterQueue> for CanisterQueue<T>
where
    Reference<T>: TryFrom<u64, Error = ProxyDecodeError>,
{
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::CanisterQueue) -> Result<Self, Self::Error> {
        let queue: VecDeque<Reference<T>> = item
            .queue
            .into_iter()
            .map(Reference::<T>::try_from)
            .collect::<Result<_, _>>()?;
        let request_slots = queue
            .iter()
            .filter(|reference| reference.kind() == Kind::Request)
            .count();

        let res = Self {
            queue,
            capacity: super::super::DEFAULT_QUEUE_CAPACITY,
            request_slots,
            response_slots: item.response_slots as usize,
            marker: std::marker::PhantomData,
        };

        res.check_invariants()
            .map(|_| res)
            .map_err(ProxyDecodeError::Other)
    }
}

impl From<&IngressQueue> for Vec<pb_ingress::Ingress> {
    fn from(item: &IngressQueue) -> Self {
        // When serializing the IngressQueue, we iterate over
        // `schedule` and persist the queues in that order.
        item.schedule
            .iter()
            .flat_map(|canister_id| {
                item.queues
                    .get(canister_id)
                    .unwrap()
                    .iter()
                    .map(|v| pb_ingress::Ingress::from(&(**v)))
            })
            .collect()
    }
}

impl TryFrom<Vec<pb_ingress::Ingress>> for IngressQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: Vec<pb_ingress::Ingress>) -> Result<Self, Self::Error> {
        let mut res = Self::default();

        for ingress_pb in item {
            // Because the contents of `Self::queues` were serialized in `Self::schedule`
            // order, pushing the messages in that same order will implicitly reconstruct
            // `Self::schedule`.
            res.push(ingress_pb.try_into()?);
        }

        Ok(res)
    }
}
