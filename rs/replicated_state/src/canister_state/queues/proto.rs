use super::refunds::{RefundPool, RefundPoolMetrics};
use super::*;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::queues::v1::Refunds;
use ic_protobuf::state::queues::v1::canister_queues::CanisterQueuePair;
use ic_protobuf::types::v1 as pb_types;
use ic_types::messages::Refund;

impl From<&CanisterQueues> for pb_queues::CanisterQueues {
    fn from(item: &CanisterQueues) -> Self {
        fn callback_references_to_proto(
            callback_references: &MutableIntMap<message_pool::InboundReference, CallbackId>,
        ) -> Vec<pb_queues::canister_queues::CallbackReference> {
            callback_references
                .iter()
                .map(|(&id, &callback_id)| message_pool::CallbackReference(id, callback_id).into())
                .collect()
        }

        let (next_input_source, local_sender_schedule, remote_sender_schedule) =
            (&item.input_schedule).into();

        Self {
            ingress_queue: (&item.ingress_queue).into(),
            canister_queues: item
                .canister_queues
                .iter()
                .map(|(canid, (iq, oq))| CanisterQueuePair {
                    canister_id: Some(pb_types::CanisterId::from(*canid)),
                    input_queue: Some((&**iq).into()),
                    output_queue: Some((&**oq).into()),
                })
                .collect(),
            pool: if item.store.pool != MessagePool::default() {
                Some((&item.store.pool).into())
            } else {
                None
            },
            expired_callbacks: callback_references_to_proto(&item.store.expired_callbacks),
            shed_responses: callback_references_to_proto(&item.store.shed_responses),
            next_input_source,
            local_sender_schedule,
            remote_sender_schedule,
            guaranteed_response_memory_reservations: item
                .queue_stats
                .guaranteed_response_memory_reservations
                as u64,
        }
    }
}

impl TryFrom<(pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics)> for CanisterQueues {
    type Error = ProxyDecodeError;
    fn try_from(
        (item, metrics): (pb_queues::CanisterQueues, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
        let pool = MessagePool::try_from(item.pool.unwrap_or_default())?;

        fn callback_references_try_from_proto(
            callback_references: Vec<pb_queues::canister_queues::CallbackReference>,
        ) -> Result<MutableIntMap<message_pool::InboundReference, CallbackId>, ProxyDecodeError>
        {
            callback_references
                .into_iter()
                .map(|cr_proto| {
                    let cr = message_pool::CallbackReference::try_from(cr_proto)?;
                    Ok((cr.0, cr.1))
                })
                .collect()
        }
        let expired_callbacks = callback_references_try_from_proto(item.expired_callbacks)?;
        let shed_responses = callback_references_try_from_proto(item.shed_responses)?;

        let mut enqueued_pool_messages = BTreeSet::new();
        let canister_queues = item
            .canister_queues
            .into_iter()
            .map(|qp| {
                let canister_id: CanisterId =
                    try_from_option_field(qp.canister_id, "CanisterQueuePair::canister_id")?;
                let iq: InputQueue =
                    try_from_option_field(qp.input_queue, "CanisterQueuePair::input_queue")?;
                let oq: OutputQueue =
                    try_from_option_field(qp.output_queue, "CanisterQueuePair::output_queue")?;

                iq.iter().for_each(|&reference| {
                    if pool.get(reference).is_some()
                        && !enqueued_pool_messages.insert(SomeReference::Inbound(reference))
                    {
                        metrics.observe_broken_soft_invariant(format!(
                            "CanisterQueues: {reference:?} enqueued more than once"
                        ));
                    }
                });
                oq.iter().for_each(|&reference| {
                    if pool.get(reference).is_some()
                        && !enqueued_pool_messages.insert(SomeReference::Outbound(reference))
                    {
                        metrics.observe_broken_soft_invariant(format!(
                            "CanisterQueues: {reference:?} enqueued more than once"
                        ));
                    }
                });

                Ok((canister_id, (Arc::new(iq), Arc::new(oq))))
            })
            .collect::<Result<_, Self::Error>>()?;

        if enqueued_pool_messages.len() != pool.len() {
            metrics.observe_broken_soft_invariant(format!(
                "CanisterQueues: Pool holds {} messages, but only {} of them are enqueued",
                pool.len(),
                enqueued_pool_messages.len()
            ));
        }

        let queue_stats = Self::calculate_queue_stats(
            &canister_queues,
            item.guaranteed_response_memory_reservations as usize,
        );

        let input_schedule = InputSchedule::try_from((
            item.next_input_source,
            item.local_sender_schedule,
            item.remote_sender_schedule,
        ))?;

        let store = MessageStoreImpl {
            pool,
            expired_callbacks,
            shed_responses,
        };
        let callbacks_with_enqueued_response = store
            .callbacks_with_enqueued_response(&canister_queues)
            .map_err(ProxyDecodeError::Other)?;

        let queues = Self {
            ingress_queue: IngressQueue::try_from(item.ingress_queue)?,
            canister_queues,
            store,
            queue_stats,
            input_schedule,
            callbacks_with_enqueued_response,
        };

        // Safe to pretend that all senders are remote, as the validation logic allows
        // for deleted local canisters (which would be categorized as remote).
        if let Err(msg) = queues.schedules_ok(&|_| InputQueueType::RemoteSubnet) {
            metrics.observe_broken_soft_invariant(msg);
        }
        queues.test_invariants().map_err(ProxyDecodeError::Other)?;

        Ok(queues)
    }
}

impl From<&RefundPool> for pb_queues::Refunds {
    fn from(item: &RefundPool) -> Self {
        let metrics = item.metrics();
        Refunds {
            refunds: item.iter().map(|refund| refund.into()).collect(),
            // Left unset if no refund was ever pushed, so that a pristine pool
            // serializes to an empty proto (and is thus omitted from the checkpoint).
            metrics: (metrics != RefundPoolMetrics::default()).then(|| metrics.into()),
        }
    }
}

impl From<RefundPoolMetrics> for pb_queues::RefundPoolMetrics {
    fn from(item: RefundPoolMetrics) -> Self {
        Self {
            pushed_refunds: item.pushed_refunds,
            pushed_cycles: Some(item.pushed_cycles.into()),
        }
    }
}

impl TryFrom<pb_queues::RefundPoolMetrics> for RefundPoolMetrics {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::RefundPoolMetrics) -> Result<Self, Self::Error> {
        Ok(Self {
            pushed_refunds: item.pushed_refunds,
            pushed_cycles: try_from_option_field(
                item.pushed_cycles,
                "RefundPoolMetrics::pushed_cycles",
            )?,
        })
    }
}

impl TryFrom<(pb_queues::Refunds, &dyn CheckpointLoadingMetrics)> for RefundPool {
    type Error = ProxyDecodeError;

    fn try_from(
        (item, metrics): (pb_queues::Refunds, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
        let mut pool = RefundPool::new();
        for refund in item.refunds {
            let pool_size_before = pool.len();

            let refund = Refund::try_from(refund)?;
            pool.add(refund.recipient(), refund.amount());

            if pool.len() <= pool_size_before {
                metrics.observe_broken_soft_invariant(format!(
                    "RefundPool: Duplicate recipient ({}) or zero amount ({})",
                    refund.recipient(),
                    refund.amount()
                ));
            }
        }

        // The metrics cover all refunds ever pushed, including those already merged
        // into the refunds loaded above, so take them as persisted.
        if let Some(metrics) = item.metrics {
            pool.set_metrics(metrics.try_into()?);
        }

        Ok(pool)
    }
}
