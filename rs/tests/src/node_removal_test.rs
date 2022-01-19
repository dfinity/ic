/* tag::catalog[]
Title:: Node Removal Test

Goal:: Test whether a node removal from subnet operation triggered via NNS registry mutation results in removal
from subnet record in registry and then from P2P.

Runbook::
. Set up a system subnet using a node operator
. Install the NNS canisters (registry one is key here).
. Invoke the remove node registry mutation using the same node operator as in step one.
. Validate P2P metrics show that the node is removed.


Success:: Metric successfully published indicating node removal from P2P.

Coverage::
. Registry remove node from subnet mutation with proper node operator occurs.
. P2P refreshes registry and reacts to registry change my removing node.

Remark::
. As further components support node removal, this test can be expanded to validate those behaviors.


end::catalog[] */
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcManager,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;
use std::time::{Duration, Instant};
use url::Url;

use crate::nns::NnsExt;

pub fn config() -> InternetComputer {
    // Set dkg interval height low so consensus membership version can update
    // quickly.
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(3))
            .add_nodes(2),
    )
}

pub fn test(man: IcManager, ctx: &ic_fondue::pot::Context) {
    let handle = man.handle();
    let api_endpoints: Vec<Url> = handle
        .public_api_endpoints
        .iter()
        .map(|ep| ep.metrics_url.clone().unwrap())
        .collect();
    info!(ctx.logger, "{:?}", api_endpoints);
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let node_ids = ctx.initial_node_ids(&handle);
    info!(ctx.logger, "Removing {:?}", node_ids[0]);
    ctx.remove_nodes(&handle, vec![node_ids[0]].as_ref());
    info!(ctx.logger, "Node removed from registry");

    // Verify that subnet membership has been updated via Consensus
    let mut subnet_membership_update = false;
    while !subnet_membership_update {
        std::thread::sleep(Duration::from_secs(10));
        for endpoint in api_endpoints.clone() {
            let registry_version =
                get_int_counter_metric("consensus_membership_registry_version", &endpoint);
            info!(
                ctx.logger,
                "consensus membership registry version: {:?}", registry_version
            );
            if registry_version == 2 {
                subnet_membership_update = true;
            }
        }
    }

    // Once it has been updated, we must wait for P2P registry to be refreshed.
    const TIMEOUT: Duration = Duration::from_secs(180);
    const DELAY: Duration = Duration::from_secs(20);
    std::thread::sleep(DELAY);
    let start = Instant::now();
    let all_removed = loop {
        // Since we removed 1 node from a subnet of 2, we expect to see both of the
        // nodes to have a nodes_removed metric of 1. This metric should be a total
        // of 2 then which indicates both nodes have observed the removal of the
        // node.
        let all_removed = api_endpoints
            .iter()
            .all(|e| get_int_counter_metric("p2p_nodes_removed", e) == 1);
        if all_removed {
            break true;
        } else if start.elapsed() < TIMEOUT {
            std::thread::sleep(DELAY);
        } else {
            break false;
        }
    };

    assert!(
        all_removed,
        "Not all nodes observed node removal within timeout!"
    );
}

fn get_int_counter_metric(metric_name: &str, api_endpoint: &Url) -> i32 {
    let body = reqwest::blocking::get(api_endpoint.clone())
        .unwrap()
        .text()
        .unwrap();
    let metric: Vec<&str> = body
        .lines()
        .filter_map(|line| {
            if line.starts_with(metric_name) {
                let split_metric: Vec<&str> = line.split(metric_name).collect();
                Some(split_metric[1].trim())
            } else {
                None
            }
        })
        .collect();
    metric[0].parse::<i32>().unwrap()
}
