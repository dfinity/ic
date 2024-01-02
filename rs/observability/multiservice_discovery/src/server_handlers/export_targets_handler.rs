use std::{collections::BTreeMap, sync::Arc};

use ic_types::{NodeId, PrincipalId};
use service_discovery::{
    job_types::{JobType, NodeOS},
    IcServiceDiscovery,
};
use warp::reply::Reply;

use crate::definition::Definition;

use super::WebResult;
use multiservice_discovery_shared::contracts::target::{map_to_target_dto, TargetDto};
use tokio::sync::Mutex;

pub struct ExportTargetsBinding {
    pub definitions: Arc<Mutex<Vec<Definition>>>,
}

pub async fn export_targets(binding: ExportTargetsBinding) -> WebResult<impl Reply> {
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

            targets.iter().for_each(|target_group| {
                if let Some(target) = total_targets
                    .iter_mut()
                    .find(|t| t.node_id == target_group.node_id)
                {
                    target.jobs.push(job_type);
                } else {
                    total_targets.push(map_to_target_dto(
                        target_group,
                        job_type,
                        BTreeMap::new(),
                        target_group.node_id.to_string(),
                        def.name.clone(),
                    ));
                }
            });
        }

        def.boundary_nodes.iter().for_each(|bn| {
            if bn
                .custom_labels
                .iter()
                .any(|(k, v)| k.as_str() == "env" && v.as_str() == "test")
                && bn.job_type == JobType::NodeExporter(NodeOS::Host)
            {
                return;
            }
            total_targets.push(TargetDto {
                name: bn.name.clone(),
                node_id: NodeId::from(PrincipalId::new_anonymous()),
                jobs: vec![bn.job_type],
                custom_labels: bn.custom_labels.clone(),
                targets: bn.targets.clone(),
                dc_id: "".to_string(),
                ic_name: def.name.clone(),
                node_provider_id: PrincipalId::new_anonymous(),
                operator_id: PrincipalId::new_anonymous(),
                subnet_id: None,
            });
        });
    }

    let prom_config = serde_json::to_string_pretty(&total_targets).unwrap();

    Ok(warp::reply::with_status(
        prom_config,
        warp::http::StatusCode::OK,
    ))
}
