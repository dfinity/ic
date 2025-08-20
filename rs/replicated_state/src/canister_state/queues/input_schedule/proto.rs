use super::*;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::queues::v1::canister_queues::NextInputQueue;
use ic_protobuf::types::v1 as pb_types;

impl From<&InputSchedule> for (i32, Vec<pb_types::CanisterId>, Vec<pb_types::CanisterId>) {
    fn from(item: &InputSchedule) -> Self {
        let next_input_source = NextInputQueue::from(&item.next_input_source).into();
        let local_sender_schedule = item
            .local_sender_schedule
            .iter()
            .map(|sender| pb_types::CanisterId::from(*sender))
            .collect();
        let remote_sender_schedule = item
            .remote_sender_schedule
            .iter()
            .map(|sender| pb_types::CanisterId::from(*sender))
            .collect();
        (
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
        )
    }
}

impl TryFrom<(i32, Vec<pb_types::CanisterId>, Vec<pb_types::CanisterId>)> for InputSchedule {
    type Error = ProxyDecodeError;
    fn try_from(
        (next_input_source, local_sender_schedule, remote_sender_schedule): (
            i32,
            Vec<pb_types::CanisterId>,
            Vec<pb_types::CanisterId>,
        ),
    ) -> Result<Self, Self::Error> {
        let next_input_source =
            InputSource::from(NextInputQueue::try_from(next_input_source).unwrap_or_default());

        let local_sender_schedule = local_sender_schedule
            .into_iter()
            .map(CanisterId::try_from)
            .collect::<Result<VecDeque<_>, _>>()?;
        let remote_sender_schedule = remote_sender_schedule
            .into_iter()
            .map(CanisterId::try_from)
            .collect::<Result<VecDeque<_>, _>>()?;
        let scheduled_senders = local_sender_schedule
            .iter()
            .cloned()
            .chain(remote_sender_schedule.iter().cloned())
            .collect();

        Ok(InputSchedule {
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
            scheduled_senders,
        })
    }
}
