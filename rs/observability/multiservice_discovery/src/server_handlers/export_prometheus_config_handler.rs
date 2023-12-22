use std::{collections::BTreeMap, sync::Arc};

use service_discovery::{
    job_types::{JobType, NodeOS},
    jobs::Job,
    IcServiceDiscovery,
};
use tokio::sync::Mutex;
use warp::reply::Reply;

use crate::definition::Definition;
use multiservice_discovery_shared::{
    builders::prometheus_config_structure::{map_target_group, PrometheusStaticConfig},
    contracts::TargetDto,
};

use super::WebResult;

pub struct ExportDefinitionConfigBinding {
    pub definitions: Arc<Mutex<Vec<Definition>>>,
}

pub async fn export_prometheus_config(
    binding: ExportDefinitionConfigBinding,
) -> WebResult<impl Reply> {
    let definitions = binding.definitions.lock().await;

    let all_jobs = [
        JobType::Replica,
        JobType::Orchestrator,
        JobType::NodeExporter(NodeOS::Guest),
        JobType::NodeExporter(NodeOS::Host),
        JobType::MetricsProxy,
    ];

    let mut total_targets: Vec<TargetDto> = vec![];

    for def in definitions.iter() {
        for job_type in all_jobs {
            let targets = match def.ic_discovery.get_target_groups(job_type) {
                Ok(targets) => targets,
                Err(_) => continue,
            };

            for target in targets {
                if let Some(entry) = total_targets
                    .iter_mut()
                    .find(|t| t.node_id == target.node_id)
                {
                    entry.jobs.push(job_type);
                } else {
                    let mut mapped = Into::<TargetDto>::into(&target);
                    mapped.ic_name = def.name.clone();
                    total_targets.push(TargetDto {
                        jobs: vec![job_type],
                        ..mapped
                    });
                }
            }
        }
    }

    let mut total_set = map_target_group(total_targets.into_iter().collect());

    definitions.iter().for_each(|def| {
        def.boundary_nodes.iter().for_each(|bn| {
            // Boundary nodes do not get the metrics-proxy installed.
            if bn.job_type == JobType::MetricsProxy {
                return;
            }

            // If this boundary node is under the test environment,
            // and the job is Node Exporter, then skip adding this
            // target altogether.
            if bn
                .custom_labels
                .iter()
                .any(|(k, v)| k.as_str() == "env" && v.as_str() == "test")
                && bn.job_type == JobType::NodeExporter(NodeOS::Host)
            {
                return;
            }

            let binding = Job::all();
            let job = binding.iter().find(|j| j._type == bn.job_type).unwrap();

            total_set.insert(PrometheusStaticConfig {
                targets: bn
                    .targets
                    .clone()
                    .iter()
                    .map(|g| {
                        let mut g = *g;
                        g.set_port(job.port);
                        format!("http://{}/{}", g, job.endpoint.trim_start_matches('/'),)
                    })
                    .collect(),
                labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("ic".to_string(), def.name.clone());
                    labels.insert("name".to_string(), bn.name.clone());
                    labels.extend(bn.custom_labels.clone());
                    labels.insert("job".to_string(), bn.job_type.to_string());
                    labels
                },
            });
        })
    });

    let prom_config = serde_json::to_string_pretty(&total_set).unwrap();

    Ok(warp::reply::with_status(
        prom_config,
        warp::http::StatusCode::OK,
    ))
}
