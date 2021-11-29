//! Prometheus Service discovery

use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fs,
    future::Future,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    result::Result,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::time;

use ecs::SetTo;
use elastic_common_schema as ecs;
use ic_protobuf::registry::node::v1::ConnectionEndpoint as pbConnectionEndpoint;
use ic_registry_client::{
    client::{RegistryClient, RegistryClientError, RegistryVersion},
    helper::{
        node::{NodeId, NodeRegistry, SubnetId},
        subnet::{SubnetListRegistry, SubnetRegistry},
    },
};
use ic_types::registry::connection_endpoint::{
    ConnectionEndpoint, ConnectionEndpointTryFromProtoError,
};

use crate::{config, metrics};

#[derive(Error, Debug, strum::IntoStaticStr)]
pub(crate) enum ServiceDiscoveryError {
    #[error("registry failed invariant check: {source}")]
    RegistryInvariantFailed {
        #[from]
        source: RegistryInvariantError,
    },

    #[error("I/O error: {source}")]
    IO {
        #[from]
        source: std::io::Error,
    },

    #[error("serialization error: {source}")]
    JsonSerializationFailed {
        #[from]
        source: serde_json::Error,
    },

    #[error("failed to write to {destination:?}: {source}")]
    FilePersistenceFailed {
        source: tempfile::PersistError,
        destination: PathBuf,
    },
}

/// Errors indicating a registry invariant check failed. See
/// https://docs.google.com/document/d/137Xr74mHKRuFfjnKmkCBSvMJ1XTrTy6c7OyPNGKaovk/edit#
/// for details.
#[derive(Error, Debug, strum::IntoStaticStr)]
pub(crate) enum RegistryInvariantError {
    #[error("failed to fetch subnet list from registry {registry_version}: {source}")]
    GetSubnetsFailed {
        source: RegistryClientError,
        registry_version: RegistryVersion,
    },

    #[error("no subnets in registry at {registry_version}")]
    NoSubnetsInRegistry { registry_version: RegistryVersion },

    #[error("failed to fetch node ID list for subnet {subnet_id} from registry {registry_version}: {source}")]
    GetNodeIdsFailed {
        subnet_id: SubnetId,
        source: RegistryClientError,
        registry_version: RegistryVersion,
    },

    #[error("subnet {subnet_id} has no nodes at {registry_version}")]
    SubnetHasNoNodes {
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    },

    #[error("failed to get transport info for node {node_id} from registry {registry_version}: {source}")]
    GetTransportInfoFailed {
        node_id: NodeId,
        registry_version: RegistryVersion,
        source: RegistryClientError,
    },

    #[error("node {node_id} has no transport info at registry {registry_version}")]
    NodeHasNoTransportInfo {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },

    #[error("failed to get endpoint for subnet {subnet_id} node {node_id}")]
    NoConnectionEndpoint {
        subnet_id: SubnetId,
        node_id: NodeId,
        registry_version: RegistryVersion,
    },

    #[error("failed to parse {node_id} proto endpoint {connection_endpoint:?}: {source}")]
    ConnectionEndpointParseFailed {
        source: ConnectionEndpointTryFromProtoError,
        node_id: NodeId,
        connection_endpoint: pbConnectionEndpoint,
        registry_version: RegistryVersion,
    },

    #[error("metrics connection endpoint for {node_id} has 0.0.0.0 addr at {registry_version}")]
    ConnectionEndpointIsAllBalls {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
}

/// Additional label/value pairs for Prometheus to add to the job. Can be
/// arbitrary strings as long as they follow the requirements at
/// https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels.
// Need btreemap for consistently order serialization of labels. This is
// required for testing output in unit tests
type Labels = BTreeMap<String, String>;

#[derive(Serialize, Deserialize, Debug, Default)]
struct PrometheusNodeRecord {
    targets: Vec<String>, // targets: ["ip:port"]
    labels: Labels,       // labels: { k: v, k : v}
}

// Default labels
const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";

/// Returns all the subnets and the nodes they contain.
fn get_ic_topology(
    registry_client: &Arc<impl RegistryClient>,
    registry_version: RegistryVersion,
    extra_labels: Labels,
) -> Result<Vec<PrometheusNodeRecord>, RegistryInvariantError> {
    let mut prometheus_service_discovery: Vec<PrometheusNodeRecord> = Vec::new();

    // Fetch all subnet IDs, propogate errors
    let subnet_ids = registry_client
        .get_subnet_ids(registry_version)
        .map_err(|source| RegistryInvariantError::GetSubnetsFailed {
            source,
            registry_version,
        })?
        .unwrap_or_default();

    // No subnets is a problem
    if subnet_ids.is_empty() {
        return Err(RegistryInvariantError::NoSubnetsInRegistry { registry_version });
    }

    for subnet_id in subnet_ids {
        // Fetch all node IDs for this subnet, propagate errors
        let node_ids = registry_client
            .get_node_ids_on_subnet(subnet_id, registry_version)
            .map_err(|source| RegistryInvariantError::GetNodeIdsFailed {
                source,
                subnet_id,
                registry_version,
            })?
            .unwrap_or_default();

        if node_ids.is_empty() {
            return Err(RegistryInvariantError::SubnetHasNoNodes {
                subnet_id,
                registry_version,
            });
        }

        for node_id in node_ids {
            let node_record = registry_client
                .get_transport_info(node_id, registry_version)
                .map_err(|source| RegistryInvariantError::GetTransportInfoFailed {
                    node_id,
                    registry_version,
                    source,
                })?
                .ok_or(RegistryInvariantError::NodeHasNoTransportInfo {
                    node_id,
                    registry_version,
                })?;

            let connection_endpoint =
                ConnectionEndpoint::try_from(node_record.prometheus_metrics_http.clone().ok_or(
                    RegistryInvariantError::NoConnectionEndpoint {
                        subnet_id,
                        node_id,
                        registry_version,
                    },
                )?)
                .map_err(|source| {
                    RegistryInvariantError::ConnectionEndpointParseFailed {
                        source,
                        node_id,
                        connection_endpoint: node_record.prometheus_metrics_http.clone().unwrap(),
                        registry_version,
                    }
                })?;

            let mut addr = SocketAddr::from(&connection_endpoint);

            // If prometheus_metrics_http is not set fallback to http.
            if addr.ip().is_unspecified() {
                let connection_endpoint =
                    ConnectionEndpoint::try_from(node_record.http.clone().ok_or(
                        RegistryInvariantError::NoConnectionEndpoint {
                            subnet_id,
                            node_id,
                            registry_version,
                        },
                    )?)
                    .map_err(|source| {
                        RegistryInvariantError::ConnectionEndpointParseFailed {
                            source,
                            node_id,
                            connection_endpoint: node_record.http.unwrap(),
                            registry_version,
                        }
                    })?;

                addr = SocketAddr::from(&connection_endpoint);
                addr.set_port(9090);
            }

            // Seen bogus registry entries where the connection endpoint exists
            // but is 0.0.0.0
            if addr.ip().is_unspecified() {
                return Err(RegistryInvariantError::ConnectionEndpointIsAllBalls {
                    node_id,
                    registry_version,
                });
            }

            let node_endpoint_string = addr.to_string();

            let mut labels: Labels = Default::default();
            labels.insert(IC_SUBNET.to_string(), subnet_id.to_string());
            labels.insert(IC_NODE.to_string(), node_id.to_string());
            labels.extend(extra_labels.clone().into_iter());

            prometheus_service_discovery.push(PrometheusNodeRecord {
                targets: vec![node_endpoint_string],
                labels,
            });
        }
    }
    Ok(prometheus_service_discovery)
}

/// Atomically write `node_records` in JSON format to `destination` file.
fn write_file<P: AsRef<Path>>(
    node_records: &[PrometheusNodeRecord],
    destination: P,
    mode: u32,
) -> Result<(), ServiceDiscoveryError> {
    let mut temp_dump_file = NamedTempFile::new_in(
        destination
            .as_ref()
            .parent()
            .unwrap_or_else(|| Path::new("/")),
    )
    .map_err(|source| ServiceDiscoveryError::IO { source })?;

    serde_json::to_writer_pretty(&temp_dump_file, &node_records)
        .map_err(|source| ServiceDiscoveryError::JsonSerializationFailed { source })?;

    temp_dump_file
        .as_file_mut()
        .sync_data()
        .map_err(|source| ServiceDiscoveryError::IO { source })?;

    temp_dump_file.persist(&destination).map_err(|source| {
        ServiceDiscoveryError::FilePersistenceFailed {
            source,
            destination: destination.as_ref().into(),
        }
    })?;

    let mut permissions = fs::metadata(&destination)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(&destination, permissions)?;

    Ok(())
}

// Periodically monitor the registry for changes. Translate and write the
// registry content changes to prometheus service discovery file.
pub(crate) async fn service_discovery<F>(
    config: Arc<config::Config>,
    registry_client: Arc<impl RegistryClient>,
    log: Logger,
    metrics: Arc<metrics::Metrics>,
    graceful: F,
) where
    F: Future<Output = ()>,
{
    let mut graceful = Box::pin(graceful);
    let mut interval = time::interval(config.discover_every);

    let mut extra_labels: Labels = Default::default();
    extra_labels.insert(IC_NAME.to_string(), config.ic_name.clone());

    loop {
        let mut event_timer = ecs::Timer::start();

        let registry_version = registry_client.get_latest_version();

        let result = get_ic_topology(&registry_client, registry_version, extra_labels.clone())
            .map_err(ServiceDiscoveryError::from)
            .and_then(|node_records| {
                write_file(
                    &node_records,
                    &config.service_discovery_file,
                    config.service_discovery_file_mode,
                )
            });

        let mut canonical_event = ecs::Event::new(ecs::Kind::Event);
        canonical_event.event.set(ecs::Category::Database);
        canonical_event.event.set(ecs::Type::Access);

        let metric_status_value = match &result {
            Ok(_) => {
                metrics
                    .ic_topology_registry_version
                    .set(registry_version.get() as i64);
                canonical_event.event.set(ecs::Outcome::Success);

                "success"
            }
            Err(error) => {
                canonical_event.event.set(ecs::Outcome::Failure);
                let ecs_error = ecs::error_fields::Error {
                    message: Some(error.to_string()),
                    ..Default::default()
                };
                canonical_event.error = Some(ecs_error);

                error.into()
            }
        };

        let mut ic_registry_map = BTreeMap::new();
        ic_registry_map.insert("version".into(), registry_version.get().into());
        let mut ic_map = BTreeMap::new();
        ic_map.insert("registry".into(), ic_registry_map.into());
        if !ic_map.is_empty() {
            canonical_event.extra_values.insert("IC", ic_map.into());
        }

        info!(log, ""; &canonical_event);

        event_timer.finish();
        canonical_event.event.set(&event_timer);

        metrics
            .ic_service_discovery_duration_seconds
            .with_label_values(&[metric_status_value])
            .observe(event_timer.elapsed_secs());

        loop {
            // Wait for the next interval, or a graceful shutdown signal
            tokio::select! {
                _ = graceful.as_mut() => {
                    info!(&log, "Graceful shutdown");
                    return;
                },
                _ = interval.tick() => {}
            }

            // Wait if the registry version hasn't changed and the last run was a
            // successful.
            if registry_client.get_latest_version() == registry_version && result.is_ok() {
                metrics.ic_service_discovery_skipped_total.inc();
                continue;
            }

            // Back to the outer loop to update the topology
            break;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ic_registry_client::client::RegistryClientImpl;
    use ic_test_utilities::p2p::test_group_set_registry;
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};

    #[tokio::test]
    async fn test_service_discovery() {
        let expected_json_str = r#"[
  {
    "targets": [
      "127.0.0.1:9090"
    ],
    "labels": {
      "ic": "sodium",
      "ic_node": "0",
      "ic_subnet": "0"
    }
  },
  {
    "targets": [
      "127.0.0.1:9090"
    ],
    "labels": {
      "ic": "sodium",
      "ic_node": "1",
      "ic_subnet": "0"
    }
  },
  {
    "targets": [
      "127.0.0.1:9090"
    ],
    "labels": {
      "ic": "sodium",
      "ic_node": "2",
      "ic_subnet": "0"
    }
  }
]"#;

        let num_nodes = 3;

        let mut extra_labels: Labels = Default::default();
        extra_labels.insert("ic".to_string(), "sodium".to_string());

        // Build the registry for the test
        let mut node_port_allocation = Vec::new();
        for _i in 0..num_nodes {
            node_port_allocation.push(8080);
        }
        let data_provider =
            test_group_set_registry(subnet_test_id(0), Arc::new(node_port_allocation));
        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
        registry_client.fetch_and_start_polling().unwrap();

        let registry_version = registry_client.get_latest_version();
        let node_records =
            get_ic_topology(&registry_client, registry_version, extra_labels).unwrap();
        assert_eq!(node_records.len(), num_nodes);

        let mut discovery_file_content = serde_json::to_string_pretty(&node_records).unwrap();
        println!("{}", discovery_file_content);
        for i in 0..num_nodes {
            discovery_file_content =
                discovery_file_content.replace(&node_test_id(i as u64).to_string(), &i.to_string());
        }
        discovery_file_content =
            discovery_file_content.replace(&subnet_test_id(0).to_string(), &0.to_string());
        println!("{}", discovery_file_content);
        assert_eq!(discovery_file_content, expected_json_str.to_string());
    }
}
