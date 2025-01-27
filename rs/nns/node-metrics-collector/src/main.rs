use candid::{CandidType, Decode, Encode, Principal};
use futures::FutureExt;
use ic_base_types::PrincipalId;
use ic_cdk_macros::*;
use ic_management_canister_types::{
    NodeMetrics, NodeMetricsHistoryArgs, NodeMetricsHistoryResponse,
};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use serde::Deserialize;
use std::borrow::Cow;
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type TimestampNanos = u64;
type NodeMetricsStoredKey = (TimestampNanos, Principal);
#[derive(Clone, Debug, CandidType, Deserialize)]
struct NodeMetricsStored(Vec<NodeMetrics>);

// Management canisters updates node metrics every day
const DAY_SECONDS: u64 = 60 * 60 * 24;
const HR_BUFFER: u64 = 60 * 60;

const MAX_VALUE_SIZE_BYTES_NODE_METRICS: u32 = Principal::MAX_LENGTH_IN_BYTES as u32 + 2 * 64;

impl Storable for NodeMetricsStored {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        // This size supports subnets with max 200 nodes
        max_size: MAX_VALUE_SIZE_BYTES_NODE_METRICS * 200,
        is_fixed_size: false,
    };
}

thread_local! {
    pub static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
    RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static NODES_METRICS: RefCell<StableBTreeMap<NodeMetricsStoredKey, NodeMetricsStored, Memory>> =
      RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
    ));
}

/// Fetch metrics
///
/// Calls to the node_metrics_history endpoint of the management canister for all the subnets
/// to get updated metrics since refresh_ts.
async fn fetch_metrics(
    subnets: Vec<PrincipalId>,
    refresh_ts: TimestampNanos,
) -> anyhow::Result<Vec<(PrincipalId, Vec<NodeMetricsHistoryResponse>)>> {
    let mut subnets_node_metrics = Vec::new();

    for subnet_id in subnets {
        let contract = NodeMetricsHistoryArgs {
            subnet_id,
            start_at_timestamp_nanos: refresh_ts,
        };

        let node_metrics =
            ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryResponse>,)>(
                candid::Principal::management_canister(),
                "node_metrics_history",
                (contract,),
                0_u128,
            )
                .map(move |result| {
                    result
                        .map_err(|(code, msg)| {
                            anyhow::anyhow!(
                        "Error when calling management canister for subnet {}:\n Code:{:?}\nMsg:{}",
                        subnet_id,
                        code,
                        msg
                    )
                        })
                        .map(|(node_metrics,)| (subnet_id, node_metrics))
                });

        subnets_node_metrics.push(node_metrics);
    }

    let updated_metrics = futures::future::try_join_all(subnets_node_metrics).await?;

    for (subnet, node_metrics) in &updated_metrics {
        ic_cdk::println!(
            "Fetched {} new metrics for subnet: {}",
            node_metrics.len(),
            subnet
        );
    }

    Ok(updated_metrics)
}

/// Fetch subnets
///
/// Fetch subnets from the registry canister
async fn fetch_subnets() -> anyhow::Result<Vec<PrincipalId>> {
    let (registry_subnets, _): (SubnetListRecord, _) =
        ic_nns_common::registry::get_value(make_subnet_list_record_key().as_bytes(), None).await?;
    let subnets = registry_subnets
        .subnets
        .into_iter()
        .map(|subnet_id: Vec<u8>| PrincipalId::try_from(subnet_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(subnets)
}

/// Update node metrics
async fn sync_node_metrics() {
    let latest_metrics_ts = NODES_METRICS.with_borrow(|nodes_metrics| {
        nodes_metrics
            .last_key_value()
            .map(|((ts, _), _)| ts)
            .unwrap_or(0)
    });
    let refresh_ts = latest_metrics_ts + 1;
    let subnets = match fetch_subnets().await {
        Ok(subnets) => subnets,
        Err(e) => {
            ic_cdk::println!("Error fetching subnets: {}", e);
            return;
        }
    };
    ic_cdk::println!(
        "Updating node metrics for {} subnets: Latest timestamp persisted: {}  Refreshing metrics from timestamp {}",
        subnets.len(),
        latest_metrics_ts,
        refresh_ts
    );

    let subnet_metrics: Vec<(PrincipalId, Vec<NodeMetricsHistoryResponse>)> =
        match fetch_metrics(subnets, refresh_ts).await {
            Ok(subnets) => subnets,
            Err(e) => {
                ic_cdk::println!("Error fetching metrics: {}", e);
                return;
            }
        };

    NODES_METRICS.with_borrow_mut(|nodes_metrics| {
        for (subnet_id, history) in subnet_metrics {
            for history_response in history {
                nodes_metrics.insert(
                    (history_response.timestamp_nanos, subnet_id.0),
                    NodeMetricsStored(history_response.node_metrics),
                );
            }
        }
    });

    ic_cdk::println!("Successfully updated trustworthy node metrics");
}

fn setup_update_timers() {
    ic_cdk_timers::set_timer(
        std::time::Duration::from_secs(
            DAY_SECONDS + HR_BUFFER - (ic_cdk::api::time() / 1_000_000_000) % DAY_SECONDS,
        ),
        || {
            ic_cdk::spawn(sync_node_metrics());
            ic_cdk_timers::set_timer_interval(
                std::time::Duration::from_secs(DAY_SECONDS),
                || ic_cdk::spawn(sync_node_metrics()),
            );
        },
    );
}

#[init]
fn init() {
    ic_cdk_timers::set_timer(
        std::time::Duration::from_secs(0),
        || {
            ic_cdk::spawn(sync_node_metrics());
            setup_update_timers();
        },
    );
}

#[post_upgrade]
fn post_upgrade() {
    setup_update_timers();
}

#[query]
fn node_metrics_history(args: NodeMetricsHistoryArgs) -> Vec<NodeMetricsHistoryResponse> {
    NODES_METRICS.with_borrow(|nodes_metrics| {
        let mut node_metrics = Vec::new();
        for ((ts, subnet_id), node_metrics_stored) in
            nodes_metrics.range((args.start_at_timestamp_nanos, args.subnet_id.0)..)
        {
            if subnet_id == args.subnet_id.0 {
                node_metrics.push(NodeMetricsHistoryResponse {
                    timestamp_nanos: ts,
                    node_metrics: node_metrics_stored.0,
                });
            }
        }
        node_metrics
    })
}

fn main() {}
