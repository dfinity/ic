use anyhow::{anyhow, Result};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, PersistentVolumeClaimVolumeSource, PodSpec, PodTemplateSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{ObjectMeta, PostParams};
use kube::Api;
use tracing::*;

pub async fn create_job(
    api: &Api<Job>,
    name: &str,
    image: &str,
    command: Vec<&str>,
    volume: Option<(&str, &str)>,
    owner: OwnerReference,
) -> Result<Job> {
    info!("Creating job {}", name);
    if api.get(name).await.is_ok() {
        return Err(anyhow!("Job {} already exists!", name));
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

    let ctr = Container {
        name: "main".to_string(),
        image: Some(image.to_string()),
        command: Some(command.iter().map(|s| s.to_string()).collect()),
        volume_mounts,
        ..Default::default()
    };
    let podspec = PodSpec {
        containers: vec![ctr],
        restart_policy: Some("OnFailure".to_string()),
        volumes,
        ..Default::default()
    };
    let jobspec = JobSpec {
        template: PodTemplateSpec {
            metadata: Some(ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            }),
            spec: Some(podspec),
        },
        ..Default::default()
    };

    let job = Job {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: vec![owner].into(),
            ..Default::default()
        },
        spec: Some(jobspec),
        ..Default::default()
    };

    let job = api.create(&PostParams::default(), &job).await?;
    info!("Creating job {} complete", name);

    Ok(job)
}
