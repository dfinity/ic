use super::*;
use ic_protobuf::registry::subnet::v1::CanisterCyclesCostSchedule as CanisterCyclesCostScheduleProto;
use ic_protobuf::state::system_metadata::v1::ThresholdSignatureAgreementsEntry;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    registry::subnet::v1 as pb_subnet,
    state::{
        canister_state_bits::v1::{ConsumedCyclesByUseCase, CyclesUseCase as pbCyclesUseCase},
        ingress::v1 as pb_ingress,
        queues::v1 as pb_queues,
        system_metadata::v1::{self as pb_metadata},
    },
    types::v1 as pb_types,
};

impl From<&NetworkTopology> for pb_metadata::NetworkTopology {
    fn from(item: &NetworkTopology) -> Self {
        Self {
            subnets: item
                .subnets
                .iter()
                .map(|(subnet_id, subnet_topology)| pb_metadata::SubnetsEntry {
                    subnet_id: Some(subnet_id_into_protobuf(*subnet_id)),
                    subnet_topology: Some(subnet_topology.into()),
                })
                .collect(),
            routing_table: Some(item.routing_table.as_ref().into()),
            nns_subnet_id: Some(subnet_id_into_protobuf(item.nns_subnet_id)),
            canister_migrations: Some(item.canister_migrations.as_ref().into()),
            bitcoin_testnet_canister_ids: match item.bitcoin_testnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
            bitcoin_mainnet_canister_ids: match item.bitcoin_mainnet_canister_id {
                Some(c) => vec![pb_types::CanisterId::from(c)],
                None => vec![],
            },
            chain_key_enabled_subnets: item
                .chain_key_enabled_subnets
                .iter()
                .map(|(key_id, subnet_ids)| {
                    let subnet_ids = subnet_ids
                        .iter()
                        .map(|id| subnet_id_into_protobuf(*id))
                        .collect();
                    pb_metadata::ChainKeySubnetEntry {
                        key_id: Some(key_id.into()),
                        subnet_ids,
                    }
                })
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::NetworkTopology> for NetworkTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::NetworkTopology) -> Result<Self, Self::Error> {
        let mut subnets = BTreeMap::new();
        for entry in item.subnets {
            subnets.insert(
                subnet_id_try_from_protobuf(try_from_option_field(
                    entry.subnet_id,
                    "NetworkTopology::subnets::K",
                )?)?,
                try_from_option_field(entry.subnet_topology, "NetworkTopology::subnets::V")?,
            );
        }

        let nns_subnet_id = subnet_id_try_from_protobuf(try_from_option_field(
            item.nns_subnet_id,
            "NetworkTopology::nns_subnet_id",
        )?)?;

        let mut chain_key_enabled_subnets = BTreeMap::new();
        for entry in item.chain_key_enabled_subnets {
            let mut subnet_ids = vec![];
            for subnet_id in entry.subnet_ids {
                subnet_ids.push(subnet_id_try_from_protobuf(subnet_id)?);
            }
            chain_key_enabled_subnets.insert(
                try_from_option_field(entry.key_id, "ChainKeySubnetEntry::key_id")?,
                subnet_ids,
            );
        }

        let bitcoin_testnet_canister_id = match item.bitcoin_testnet_canister_ids.first() {
            Some(canister) => Some(CanisterId::try_from(canister.clone())?),
            None => None,
        };

        let bitcoin_mainnet_canister_id = match item.bitcoin_mainnet_canister_ids.first() {
            Some(canister) => Some(CanisterId::try_from(canister.clone())?),
            None => None,
        };

        Ok(Self {
            subnets,
            routing_table: try_from_option_field(
                item.routing_table,
                "NetworkTopology::routing_table",
            )
            .map(Arc::new)?,
            // `None` value needs to be allowed here because all the existing states don't have this field yet.
            canister_migrations: item
                .canister_migrations
                .map(CanisterMigrations::try_from)
                .transpose()?
                .unwrap_or_default()
                .into(),
            nns_subnet_id,
            chain_key_enabled_subnets,
            bitcoin_testnet_canister_id,
            bitcoin_mainnet_canister_id,
        })
    }
}

impl From<&SubnetTopology> for pb_metadata::SubnetTopology {
    fn from(item: &SubnetTopology) -> Self {
        Self {
            public_key: item.public_key.clone(),
            nodes: item
                .nodes
                .iter()
                .map(|node_id| pb_metadata::SubnetTopologyEntry {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                })
                .collect(),
            subnet_type: i32::from(item.subnet_type),
            subnet_features: Some(pb_subnet::SubnetFeatures::from(item.subnet_features)),
            chain_keys_held: item.chain_keys_held.iter().map(|k| k.into()).collect(),
            canister_cycles_cost_schedule: i32::from(CanisterCyclesCostScheduleProto::from(
                item.cost_schedule,
            )),
        }
    }
}

impl TryFrom<pb_metadata::SubnetTopology> for SubnetTopology {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetTopology) -> Result<Self, Self::Error> {
        let mut nodes = BTreeSet::<NodeId>::new();
        for entry in item.nodes {
            nodes.insert(node_id_try_from_option(entry.node_id)?);
        }

        let mut chain_keys_held = BTreeSet::new();
        for key in item.chain_keys_held {
            chain_keys_held.insert(MasterPublicKeyId::try_from(key)?);
        }
        let cost_schedule = CanisterCyclesCostSchedule::from(
            CanisterCyclesCostScheduleProto::try_from(item.canister_cycles_cost_schedule).map_err(
                |e| ProxyDecodeError::ValueOutOfRange {
                    typ: "CanisterCyclesCostSchedule",
                    err: format!(
                        "Failed to convert CanisterCyclesCostSchedule type for SubnetTopology: {e:?}"
                    ),
                },
            )?,
        );

        Ok(Self {
            public_key: item.public_key,
            nodes,
            // It is fine to use an arbitrary value here. We always reset the
            // field before we actually use it. We pick the value of least
            // privilege just to be sure.
            subnet_type: SubnetType::try_from(item.subnet_type).unwrap_or(SubnetType::Application),
            subnet_features: item
                .subnet_features
                .map(SubnetFeatures::from)
                .unwrap_or_default(),
            chain_keys_held,
            cost_schedule,
        })
    }
}

impl From<&SubnetMetrics> for pb_metadata::SubnetMetrics {
    fn from(item: &SubnetMetrics) -> Self {
        Self {
            consumed_cycles_by_deleted_canisters: Some(
                (&item.consumed_cycles_by_deleted_canisters).into(),
            ),
            consumed_cycles_http_outcalls: Some((&item.consumed_cycles_http_outcalls).into()),
            consumed_cycles_ecdsa_outcalls: Some((&item.consumed_cycles_ecdsa_outcalls).into()),
            threshold_signature_agreements: item
                .threshold_signature_agreements
                .iter()
                .map(|(key_id, &count)| ThresholdSignatureAgreementsEntry {
                    key_id: Some(key_id.into()),
                    count,
                })
                .collect(),
            consumed_cycles_by_use_case: item
                .consumed_cycles_by_use_case
                .clone()
                .into_iter()
                .map(|(use_case, cycles)| ConsumedCyclesByUseCase {
                    use_case: pbCyclesUseCase::from(use_case).into(),
                    cycles: Some((&cycles).into()),
                })
                .collect(),
            num_canisters: Some(item.num_canisters),
            canister_state_bytes: Some(item.canister_state_bytes.get()),
            update_transactions_total: Some(item.update_transactions_total),
        }
    }
}

impl TryFrom<pb_metadata::SubnetMetrics> for SubnetMetrics {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_metadata::SubnetMetrics) -> Result<Self, Self::Error> {
        let mut consumed_cycles_by_use_case = BTreeMap::new();
        for x in item.consumed_cycles_by_use_case.into_iter() {
            consumed_cycles_by_use_case.insert(
                CyclesUseCase::try_from(pbCyclesUseCase::try_from(x.use_case).map_err(|_| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "CyclesUseCase",
                        err: format!("Unexpected value of cycles use case: {}", x.use_case),
                    }
                })?)?,
                NominalCycles::try_from(x.cycles.unwrap_or_default()).unwrap_or_default(),
            );
        }
        let mut threshold_signature_agreements = BTreeMap::new();
        for x in item.threshold_signature_agreements.into_iter() {
            threshold_signature_agreements.insert(
                try_from_option_field(
                    x.key_id,
                    "SubnetMetrics::threshold_signature_agreements:key_id",
                )?,
                x.count,
            );
        }
        Ok(Self {
            consumed_cycles_by_deleted_canisters: try_from_option_field(
                item.consumed_cycles_by_deleted_canisters,
                "SubnetMetrics::consumed_cycles_by_deleted_canisters",
            )?,
            consumed_cycles_http_outcalls: try_from_option_field(
                item.consumed_cycles_http_outcalls,
                "SubnetMetrics::consumed_cycles_http_outcalls",
            )
            .unwrap_or_else(|_| NominalCycles::from(0_u128)),
            consumed_cycles_ecdsa_outcalls: try_from_option_field(
                item.consumed_cycles_ecdsa_outcalls,
                "SubnetMetrics::consumed_cycles_ecdsa_outcalls",
            )
            .unwrap_or_else(|_| NominalCycles::from(0_u128)),
            threshold_signature_agreements,
            consumed_cycles_by_use_case,
            num_canisters: try_from_option_field(
                item.num_canisters,
                "SubnetMetrics::num_canisters",
            )?,
            canister_state_bytes: try_from_option_field(
                item.canister_state_bytes,
                "SubnetMetrics::canister_state_bytes",
            )?,
            update_transactions_total: try_from_option_field(
                item.update_transactions_total,
                "SubnetMetrics::update_transactions_total",
            )?,
        })
    }
}

impl From<&SystemMetadata> for pb_metadata::SystemMetadata {
    fn from(item: &SystemMetadata) -> Self {
        // We do not store the subnet type when we serialize SystemMetadata. We rely on
        // `load_checkpoint()` to properly set this value.
        Self {
            own_subnet_id: Some(subnet_id_into_protobuf(item.own_subnet_id)),
            canister_allocation_ranges: Some(item.canister_allocation_ranges.clone().into()),
            last_generated_canister_id: item.last_generated_canister_id.map(Into::into),
            prev_state_hash: item
                .prev_state_hash
                .clone()
                .map(|prev_hash| prev_hash.get().0),
            batch_time_nanos: item.batch_time.as_nanos_since_unix_epoch(),
            streams: item
                .streams
                .iter()
                .map(|(subnet_id, stream)| pb_queues::StreamEntry {
                    subnet_id: Some(subnet_id_into_protobuf(*subnet_id)),
                    subnet_stream: Some(stream.into()),
                })
                .collect(),
            network_topology: Some((&item.network_topology).into()),
            subnet_call_context_manager: Some((&item.subnet_call_context_manager).into()),
            state_sync_version: item.state_sync_version as u32,
            certification_version: item.certification_version as u32,
            heap_delta_estimate: item.heap_delta_estimate.get(),
            own_subnet_features: Some(item.own_subnet_features.into()),
            subnet_metrics: Some((&item.subnet_metrics).into()),
            bitcoin_get_successors_follow_up_responses: item
                .bitcoin_get_successors_follow_up_responses
                .clone()
                .into_iter()
                .map(
                    |(sender, payloads)| pb_metadata::BitcoinGetSuccessorsFollowUpResponses {
                        sender: Some(sender.into()),
                        payloads,
                    },
                )
                .collect(),
            node_public_keys: item
                .node_public_keys
                .iter()
                .map(|(node_id, public_key)| pb_metadata::NodePublicKeyEntry {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                    public_key: public_key.clone(),
                })
                .collect(),
            api_boundary_nodes: item
                .api_boundary_nodes
                .iter()
                .map(
                    |(node_id, api_boundary_node_entry)| pb_metadata::ApiBoundaryNodeEntry {
                        node_id: Some(node_id_into_protobuf(*node_id)),
                        domain: api_boundary_node_entry.domain.clone(),
                        ipv4_address: api_boundary_node_entry.ipv4_address.clone(),
                        ipv6_address: api_boundary_node_entry.ipv6_address.clone(),
                        pubkey: api_boundary_node_entry.pubkey.clone(),
                    },
                )
                .collect(),
            blockmaker_metrics_time_series: Some((&item.blockmaker_metrics_time_series).into()),
            canister_cycles_cost_schedule: i32::from(CanisterCyclesCostScheduleProto::from(
                item.cost_schedule,
            )),
        }
    }
}

/// Decodes a `SystemMetadata` proto. The metrics are provided as a side-channel
/// for recording errors without being forced to return `Err(_)`.
impl TryFrom<(pb_metadata::SystemMetadata, &dyn CheckpointLoadingMetrics)> for SystemMetadata {
    type Error = ProxyDecodeError;

    fn try_from(
        (item, metrics): (pb_metadata::SystemMetadata, &dyn CheckpointLoadingMetrics),
    ) -> Result<Self, Self::Error> {
        let mut streams = BTreeMap::<SubnetId, Stream>::new();
        for entry in item.streams {
            streams.insert(
                subnet_id_try_from_protobuf(try_from_option_field(
                    entry.subnet_id,
                    "SystemMetadata::streams::K",
                )?)?,
                try_from_option_field(entry.subnet_stream, "SystemMetadata::streams::V")?,
            );
        }

        let canister_allocation_ranges: CanisterIdRanges = match item.canister_allocation_ranges {
            Some(canister_allocation_ranges) => canister_allocation_ranges.try_into()?,
            None => Default::default(),
        };
        let last_generated_canister_id = item
            .last_generated_canister_id
            .map(TryInto::try_into)
            .transpose()?;
        // Validate that `last_generated_canister_id` (if not `None`) is within the
        // first `canister_allocation_ranges` range.
        if let Some(last_generated_canister_id) = last_generated_canister_id {
            match canister_allocation_ranges.iter().next() {
                Some(first_allocation_range)
                    if first_allocation_range.contains(&last_generated_canister_id) => {}
                _ => {
                    return Err(ProxyDecodeError::Other(format!(
                        "SystemMetadata::last_generated_canister_id ({last_generated_canister_id}) not in the first SystemMetadata::canister_allocation_ranges range ({canister_allocation_ranges:?})"
                    )));
                }
            }
        }

        let mut bitcoin_get_successors_follow_up_responses = BTreeMap::new();
        for response in item.bitcoin_get_successors_follow_up_responses {
            let sender_pb: pb_types::CanisterId = try_from_option_field(
                response.sender,
                "BitcoinGetSuccessorsFollowUpResponses::sender",
            )?;

            let sender = CanisterId::try_from(sender_pb)?;

            bitcoin_get_successors_follow_up_responses.insert(sender, response.payloads);
        }

        let batch_time = Time::from_nanos_since_unix_epoch(item.batch_time_nanos);

        let mut node_public_keys = BTreeMap::<NodeId, Vec<u8>>::new();
        for entry in item.node_public_keys {
            node_public_keys.insert(node_id_try_from_option(entry.node_id)?, entry.public_key);
        }

        let mut api_boundary_nodes = BTreeMap::<NodeId, ApiBoundaryNodeEntry>::new();
        for entry in item.api_boundary_nodes {
            api_boundary_nodes.insert(
                node_id_try_from_option(entry.node_id)?,
                ApiBoundaryNodeEntry {
                    domain: entry.domain,
                    ipv4_address: entry.ipv4_address,
                    ipv6_address: entry.ipv6_address,
                    pubkey: entry.pubkey,
                },
            );
        }

        let cost_schedule = CanisterCyclesCostSchedule::from(
            CanisterCyclesCostScheduleProto::try_from(item.canister_cycles_cost_schedule)
                .unwrap_or(CanisterCyclesCostScheduleProto::Normal),
        );

        Ok(Self {
            own_subnet_id: subnet_id_try_from_protobuf(try_from_option_field(
                item.own_subnet_id,
                "SystemMetadata::own_subnet_id",
            )?)?,
            // WARNING! Setting to the default value which can be incorrect. We do not store the
            // actual value when we serialize SystemMetadata. We rely on `load_checkpoint()` to
            // properly set this value.
            own_subnet_type: SubnetType::default(),
            own_subnet_features: item.own_subnet_features.unwrap_or_default().into(),
            node_public_keys,
            api_boundary_nodes,
            // Note: `load_checkpoint()` will set this to the contents of `split_marker.pbuf`,
            // when present.
            split_from: None,
            canister_allocation_ranges,
            last_generated_canister_id,
            prev_state_hash: item.prev_state_hash.map(|b| CryptoHash(b).into()),
            batch_time,
            // Ingress history is persisted separately. We rely on `load_checkpoint()` to
            // properly set this value.
            ingress_history: Default::default(),
            streams: Arc::new(streams),
            network_topology: try_from_option_field(
                item.network_topology,
                "SystemMetadata::network_topology",
            )?,
            state_sync_version: item
                .state_sync_version
                .try_into()
                .map_err(|_| ProxyDecodeError::UnknownStateSyncVersion(item.state_sync_version))?,
            certification_version: item.certification_version.try_into().map_err(|_| {
                ProxyDecodeError::UnknownCertificationVersion(item.certification_version)
            })?,
            subnet_call_context_manager: match item.subnet_call_context_manager {
                Some(manager) => SubnetCallContextManager::try_from((batch_time, manager))?,
                None => Default::default(),
            },

            heap_delta_estimate: NumBytes::from(item.heap_delta_estimate),
            subnet_metrics: match item.subnet_metrics {
                Some(subnet_metrics) => subnet_metrics.try_into()?,
                None => SubnetMetrics::default(),
            },
            expected_compiled_wasms: BTreeSet::new(),
            bitcoin_get_successors_follow_up_responses,
            blockmaker_metrics_time_series: match item.blockmaker_metrics_time_series {
                Some(blockmaker_metrics) => (blockmaker_metrics, metrics).try_into()?,
                None => BlockmakerMetricsTimeSeries::default(),
            },
            unflushed_checkpoint_ops: Default::default(),
            cost_schedule,
        })
    }
}

impl From<&Stream> for pb_queues::Stream {
    fn from(item: &Stream) -> Self {
        let reject_signals = item
            .reject_signals()
            .iter()
            .map(|signal| pb_queues::RejectSignal {
                reason: pb_queues::RejectReason::from(signal.reason).into(),
                index: signal.index.get(),
            })
            .collect();
        Self {
            messages_begin: item.messages.begin().get(),
            messages: item
                .messages
                .iter()
                .map(|(_, message)| message.into())
                .collect(),
            signals_end: item.signals_end.get(),
            reject_signals,
            reverse_stream_flags: Some(pb_queues::StreamFlags {
                deprecated_responses_only: item.reverse_stream_flags.deprecated_responses_only,
            }),
        }
    }
}

impl TryFrom<pb_queues::Stream> for Stream {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_queues::Stream) -> Result<Self, Self::Error> {
        let mut messages = StreamIndexedQueue::with_begin(item.messages_begin.into());
        for message in item.messages {
            messages.push(message.try_into()?);
        }
        let guaranteed_response_counts = Self::calculate_guaranteed_response_counts(&messages);
        let messages_size_bytes = Self::calculate_size_bytes(&messages);

        let signals_end = item.signals_end.into();
        let reject_signals = item
            .reject_signals
            .iter()
            .map(|signal| {
                Ok(RejectSignal {
                    reason: pb_queues::RejectReason::try_from(signal.reason)
                        .map_err(|err| ProxyDecodeError::Other(err.to_string()))?
                        .try_into()?,
                    index: signal.index.into(),
                })
            })
            .collect::<Result<VecDeque<_>, ProxyDecodeError>>()?;

        // Check reject signals are sorted and below `signals_end`.
        let iter = reject_signals.iter().map(|signal| signal.index);
        for (index, next_index) in iter
            .clone()
            .zip(iter.skip(1).chain(std::iter::once(item.signals_end.into())))
        {
            if index >= next_index {
                return Err(ProxyDecodeError::Other(format!(
                    "reject signals not strictly sorted, received [{index:?}, {next_index:?}]",
                )));
            }
        }

        Ok(Self {
            messages,
            signals_end,
            reject_signals,
            messages_size_bytes,
            reverse_stream_flags: item
                .reverse_stream_flags
                .map(|flags| StreamFlags {
                    deprecated_responses_only: flags.deprecated_responses_only,
                })
                .unwrap_or_default(),
            guaranteed_response_counts,
        })
    }
}

impl From<&IngressHistoryState> for pb_ingress::IngressHistoryState {
    fn from(item: &IngressHistoryState) -> Self {
        let statuses = item
            .statuses()
            .map(|(message_id, status)| pb_ingress::IngressStatusEntry {
                message_id: message_id.as_bytes().to_vec(),
                status: Some(status.into()),
            })
            .collect();
        let pruning_times = item
            .pruning_times()
            .map(|(time, messages)| pb_ingress::PruningEntry {
                time_nanos: time.as_nanos_since_unix_epoch(),
                messages: messages.iter().map(|m| m.as_bytes().to_vec()).collect(),
            })
            .collect();

        debug_assert_eq!(
            IngressHistoryState::compute_memory_usage(&item.statuses),
            item.memory_usage
        );

        pb_ingress::IngressHistoryState {
            statuses,
            pruning_times,
            next_terminal_time: item.next_terminal_time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_ingress::IngressHistoryState> for IngressHistoryState {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::IngressHistoryState) -> Result<Self, Self::Error> {
        let mut statuses = BTreeMap::<MessageId, Arc<IngressStatus>>::new();
        let mut pruning_times = BTreeMap::<Time, BTreeSet<MessageId>>::new();

        for entry in item.statuses {
            let msg_id = entry.message_id.as_slice().try_into()?;
            let ingres_status = try_from_option_field(entry.status, "IngressStatusEntry::status")?;

            statuses.insert(msg_id, Arc::new(ingres_status));
        }

        for entry in item.pruning_times {
            let time = Time::from_nanos_since_unix_epoch(entry.time_nanos);
            let messages = entry
                .messages
                .iter()
                .map(|message_id| message_id.as_slice().try_into())
                .collect::<Result<BTreeSet<_>, _>>()?;

            pruning_times.insert(time, messages);
        }

        let memory_usage = IngressHistoryState::compute_memory_usage(&statuses);

        Ok(IngressHistoryState {
            statuses: Arc::new(statuses),
            pruning_times: Arc::new(pruning_times),
            next_terminal_time: Time::from_nanos_since_unix_epoch(item.next_terminal_time),
            memory_usage,
        })
    }
}

impl From<&BlockmakerStatsMap> for pb_metadata::BlockmakerStatsMap {
    fn from(item: &BlockmakerStatsMap) -> Self {
        Self {
            node_stats: item
                .node_stats
                .iter()
                .map(|(node_id, stats)| pb_metadata::NodeBlockmakerStats {
                    node_id: Some(node_id_into_protobuf(*node_id)),
                    blocks_proposed_total: stats.blocks_proposed_total,
                    blocks_not_proposed_total: stats.blocks_not_proposed_total,
                })
                .collect::<Vec<_>>(),
            blocks_proposed_total: item.subnet_stats.blocks_proposed_total,
            blocks_not_proposed_total: item.subnet_stats.blocks_not_proposed_total,
        }
    }
}

impl From<&BlockmakerMetricsTimeSeries> for pb_metadata::BlockmakerMetricsTimeSeries {
    fn from(item: &BlockmakerMetricsTimeSeries) -> Self {
        Self {
            time_stamp_map: item
                .0
                .iter()
                .map(|(time, map)| (time.as_nanos_since_unix_epoch(), map.into()))
                .collect(),
        }
    }
}

impl TryFrom<pb_metadata::BlockmakerStatsMap> for BlockmakerStatsMap {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_metadata::BlockmakerStatsMap) -> Result<Self, Self::Error> {
        Ok(Self {
            node_stats: item
                .node_stats
                .into_iter()
                .map(|e| {
                    Ok((
                        node_id_try_from_option(e.node_id)?,
                        BlockmakerStats {
                            blocks_proposed_total: e.blocks_proposed_total,
                            blocks_not_proposed_total: e.blocks_not_proposed_total,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Self::Error>>()?,
            subnet_stats: BlockmakerStats {
                blocks_proposed_total: item.blocks_proposed_total,
                blocks_not_proposed_total: item.blocks_not_proposed_total,
            },
        })
    }
}

/// Decodes a `BlockmakerMetricsTimeSeries` proto. The metrics are provided as a
/// side-channel for recording errors and stats without being forced to return
/// `Err(_)`.
impl
    TryFrom<(
        pb_metadata::BlockmakerMetricsTimeSeries,
        &dyn CheckpointLoadingMetrics,
    )> for BlockmakerMetricsTimeSeries
{
    type Error = ProxyDecodeError;

    fn try_from(
        (item, metrics): (
            pb_metadata::BlockmakerMetricsTimeSeries,
            &dyn CheckpointLoadingMetrics,
        ),
    ) -> Result<Self, Self::Error> {
        let time_series = Self(
            item.time_stamp_map
                .into_iter()
                .map(|(time_nanos, blockmaker_stats_map)| {
                    Ok((
                        Time::from_nanos_since_unix_epoch(time_nanos),
                        blockmaker_stats_map.try_into()?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, Self::Error>>()?,
        );

        if let Err(err) = time_series.check_soft_invariants() {
            metrics.observe_broken_soft_invariant(err);
        }

        Ok(time_series)
    }
}
