use ic_protobuf::registry::{
    node::v1::connection_endpoint, node::v1::NodeRecord, subnet::v1::SubnetRecord,
};
use ic_registry_keys::{make_node_record_key, make_subnet_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{NodeId, PrincipalId, SubnetId};
use prost::Message;
use reqwest::Url;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task;

mod lib;

/// Returns the list of nodes assigned to the specified subnet_id.
async fn get_nodes(
    registry_canister: &Arc<RegistryCanister>,
    subnet_id: SubnetId,
) -> Vec<(NodeId, NodeRecord)> {
    let (subnet_record, version) = registry_canister
        .get_value(make_subnet_record_key(subnet_id).as_bytes().to_vec(), None)
        .await
        .expect("failed to fetch the list of nodes");

    let subnet = SubnetRecord::decode(&subnet_record[..]).expect("failed to decode subnet record");

    let futures: Vec<_> = subnet
        .membership
        .into_iter()
        .map(|n| {
            let registry_canister = Arc::clone(registry_canister);
            task::spawn(async move {
                let node_id = NodeId::from(PrincipalId::try_from(&n[..]).unwrap());
                let (node_record_bytes, _) = registry_canister
                    .get_value(
                        make_node_record_key(node_id).as_bytes().to_vec(),
                        Some(version),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("failed to get node record {}: {}", node_id, e));
                let record = NodeRecord::decode(&node_record_bytes[..]).unwrap_or_else(|e| {
                    panic!("failed to deserialize node record {}: {}", node_id, e)
                });
                (node_id, record)
            })
        })
        .collect();

    let mut results = Vec::new();
    for f in futures {
        results.push(f.await.unwrap());
    }
    results
}

fn http_url(n: &NodeRecord) -> Url {
    let c = n.http.as_ref().unwrap();
    // Parse IP address (using IpAddr::parse())
    let ip_addr = c.ip_addr.parse().unwrap();
    // Default protocol is HTTP, unless HTTPS is specified.
    let scheme =
        if n.http.as_ref().unwrap().protocol == connection_endpoint::Protocol::Http1Tls13 as i32 {
            "https"
        } else {
            "http"
        };
    Url::parse(
        format!(
            "{}://{}",
            scheme,
            SocketAddr::new(ip_addr, u16::try_from(c.port).unwrap())
        )
        .as_str(),
    )
    .unwrap()
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} [REGISTRY_URL] [SUBNET_ID]", args[0]);
        std::process::exit(1);
    }

    let registry_url = Url::parse(&args[1][..])
        .unwrap_or_else(|e| panic!("failed to parse registry url {}: {}", args[1], e));

    let subnet_id = SubnetId::from(
        PrincipalId::from_str(&args[2][..])
            .unwrap_or_else(|e| panic!("failed to parse subnet id {}: {}", args[2], e)),
    );

    let registry_canister = Arc::new(RegistryCanister::new(vec![registry_url]));

    println!("Fetching the list of nodes on subnet {}...", subnet_id);

    let node_records = get_nodes(&registry_canister, subnet_id).await;
    println!("Found {} node(s)", node_records.len());
    for (i, (id, record)) in node_records.iter().enumerate() {
        println!("  {:2}. {} ({})", i + 1, id, http_url(record));
    }

    println!("\nDetecting the latest CUP...");

    let tasks = node_records.into_iter().map(|(node_id, node)| {
        task::spawn(async move { (node_id, lib::get_catchup_content(&http_url(&node)).await) })
    });

    let mut latest_height = 0;
    let mut latest = None;

    for t in tasks {
        let (node_id, content) = t.await.unwrap();
        match content {
            Err(err) => {
                println!(" ✘ [{}]: {}", node_id, err);
            }
            Ok(None) => {
                println!(" ? [{}]: no cup yet", node_id);
            }
            Ok(Some(content)) => {
                let h = content.block.unwrap().height;
                let s = hex::encode(&content.state_hash[..]);

                println!(" ✔ [{}]: height = {}, state_hash: {}", node_id, h, s);
                if h > latest_height {
                    latest_height = h;
                    latest = Some((node_id, s));
                }
            }
        }
    }

    if let Some((node, hash)) = latest {
        println!();
        println!("Latest state:");
        println!("{:>10}: {}", "HEIGHT", latest_height);
        println!("{:>10}: {}", "HASH", hash);
        println!("{:>10}: {}", "NODE", node);
    }
}
