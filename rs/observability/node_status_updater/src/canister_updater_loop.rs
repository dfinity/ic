use std::sync::Arc;

use crossbeam::select;
use crossbeam_channel::Receiver;
use ic_agent::export::Principal;
use obs_canister_clients::node_status_canister_client::{NodeStatus, NodeStatusCanister};
use prometheus_http_query::Client;
use service_discovery::IcServiceDiscovery;
use slog::{info, warn};

pub fn canister_updater_loop(
    log: slog::Logger,
    _discovery: Arc<dyn IcServiceDiscovery>,
    shutdown_signal: Receiver<()>,
    update_signal_recv: Receiver<()>,
    canister: NodeStatusCanister,
    rt: tokio::runtime::Handle,
    prom_client: Client,
) -> impl FnMut() {
    move || loop {
        let prom_response: Vec<NodeStatus> = match rt.block_on(
            prom_client
                .query("up{ ic_node=~\".+\", job=\"node_exporter\" }")
                .get(),
        ) {
            Ok(response) => response
                .data()
                .as_vector()
                .unwrap_or_default()
                .iter()
                .map(|entry| NodeStatus {
                    node_id: Principal::from_text(entry.metric().get("ic_node").unwrap()).unwrap(),
                    status: entry.sample().value() > 0.0,
                    subnet_id: entry
                        .metric()
                        .get("ic_subnet")
                        .map(|subnet_id| Principal::from_text(subnet_id).unwrap()),
                })
                .collect(),
            Err(err) => {
                warn!(log, "Failed to query Prometheus: {:?}", err);
                Vec::new()
            }
        };

        let present_nodes = match rt.block_on(canister.get_node_status(false)) {
            Ok(node_status) => node_status,
            Err(err) => {
                warn!(
                    log,
                    "Failed to query node statuses from canister: {:?}", err
                );
                vec![]
            }
        };

        let mut diff = vec![];

        for node in prom_response.iter() {
            if !present_nodes.contains(node) {
                diff.push(node.clone());
            }
        }

        info!(log, "Updating node status"; "prom_response_nodes" => prom_response.len(), "diff" => diff.len());

        if diff.is_empty() {
            info!(log, "No node status updates");
        } else {
            match rt.block_on(canister.update_node_statuses(diff)) {
                Ok(_) => {
                    info!(log, "Successfully updated node status");
                }
                Err(err) => {
                    warn!(log, "Failed to update node status: {:?}", err);
                }
            };
        }

        select! {
            recv(shutdown_signal) -> _ => {
                    info!(log, "Received shutdown signal in canister_updater_loop");
                    break;
                },
            recv(update_signal_recv) -> _ => continue,
        };
    }
}
