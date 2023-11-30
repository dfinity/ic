use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use k8s_openapi::api::core::v1::{
    Container, PersistentVolumeClaimVolumeSource, Pod, PodSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DeleteParams, ListParams, ObjectList, ObjectMeta, PostParams};
use kube::Api;
use tracing::*;

pub async fn create_pod(
    api: &Api<Pod>,
    name: &str,
    image: &str,
    init_command: Vec<&str>,
    command: Vec<&str>,
    volume: Option<(&str, &str)>,
    owner: OwnerReference,
) -> Result<Pod> {
    if api.get(name).await.is_ok() {
        return Err(anyhow!("Pod {} already exists!", name));
    }

    let (mut volumes, mut volume_mounts) = (None, None);
    if let Some((volume_name, volume_mount)) = volume {
        let vol = Volume {
            name: volume_name.to_string(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: volume_name.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let volmount = VolumeMount {
            name: volume_name.to_string(),
            mount_path: volume_mount.to_string(),
            ..Default::default()
        };
        volumes = Some(vec![vol]);
        volume_mounts = Some(vec![volmount]);
    }

    let init_ctr = match init_command.is_empty() {
        true => None,
        false => Some(vec![Container {
            name: "init".to_string(),
            image: Some(image.to_string()),
            command: Some(init_command.iter().map(|s| s.to_string()).collect()),
            volume_mounts: volume_mounts.clone(),
            ..Default::default()
        }]),
    };
    let ctr = Container {
        name: "main".to_string(),
        image: Some(image.to_string()),
        command: Some(command.iter().map(|s| s.to_string()).collect()),
        volume_mounts,
        ..Default::default()
    };
    let podspec = PodSpec {
        init_containers: init_ctr,
        containers: vec![ctr],
        volumes,
        ..Default::default()
    };

    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: vec![owner].into(),
            ..Default::default()
        },
        spec: Some(podspec),
        ..Default::default()
    };

    let pod = api.create(&PostParams::default(), &pod).await?;

    Ok(pod)
}

pub async fn delete_pod(api: &Api<Pod>, name: &str) -> Result<()> {
    info!("Deleting pod {}", name);
    api.delete(name, &DeleteParams::default()).await?;
    Ok(())
}

pub async fn get_pod(api: &Api<Pod>, name: &str) -> Result<Pod> {
    info!("Getting pod {}", name);
    Ok(api.get(name).await?)
}

pub async fn get_pods(
    api: &Api<Pod>,
    labels: Option<BTreeMap<String, String>>,
) -> Result<ObjectList<Pod>> {
    let label_selector = labels
        .map(|ls| {
            ls.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<String>>()
                .join(",")
        })
        .unwrap_or("".to_string());
    let lp = ListParams::default().labels(&label_selector);
    Ok(api.list(&lp).await?)
}
