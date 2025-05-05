use anyhow::{anyhow, Result};
use backon::{ConstantBuilder, Retryable};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, HostPathVolumeSource, PodSpec, PodTemplateSpec, ResourceRequirements, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client};
use tracing::*;

pub async fn create_job(
    name: &str,
    image: &str,
    command: Vec<&str>,
    args: Vec<&str>,
    hostpath: Option<&str>,
    owner: OwnerReference,
    labels: Option<Vec<(String, String)>>,
    node_name: Option<String>,
) -> Result<Job> {
    let client = Client::try_default().await?;
    let api = Api::namespaced(client, "tnets");

    info!("Creating job {}", name);
    if api.get(name).await.is_ok() {
        return Err(anyhow!("Job {} already exists!", name));
    }

    let volume_name = "hostpath";
    let mount_path = "/tnet";
    let (mut volumes, mut volume_mounts) = (None, None);
    if let Some(hostpath) = hostpath {
        let vol = Volume {
            name: "hostpath".to_string(),
            host_path: Some(HostPathVolumeSource {
                path: hostpath.to_string(),
                type_: "DirectoryOrCreate".to_string().into(),
            }),
            ..Default::default()
        };
        let volmount: VolumeMount = VolumeMount {
            name: volume_name.to_string(),
            mount_path: mount_path.to_string(),
            ..Default::default()
        };
        volumes = Some(vec![vol]);
        volume_mounts = Some(vec![volmount]);
    };

    let ctr = Container {
        name: "main".to_string(),
        image: Some(image.to_string()),
        command: Some(command.iter().map(|s| s.to_string()).collect()),
        args: Some(args.iter().map(|s| s.to_string()).collect()),
        resources: Some(ResourceRequirements {
            requests: Some(
                [
                    ("cpu".to_string(), Quantity("0.5".to_string())),
                    ("memory".to_string(), Quantity("256Mi".to_string())),
                ]
                .iter()
                .cloned()
                .collect(),
            ),
            ..Default::default()
        }),
        volume_mounts,
        ..Default::default()
    };
    let podspec = PodSpec {
        containers: vec![ctr],
        restart_policy: Some("OnFailure".to_string()),
        scheduler_name: Some("koord-scheduler".to_string()),
        node_selector: node_name.map(|node_name| {
            [("kubernetes.io/hostname".to_string(), node_name)]
                .iter()
                .cloned()
                .collect()
        }),
        volumes,
        ..Default::default()
    };
    let jobspec = JobSpec {
        template: PodTemplateSpec {
            metadata: Some(ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(
                    [("kubevirt.io/job".to_string(), name.to_string())]
                        .iter()
                        .cloned()
                        .chain(labels.clone().unwrap_or_default().into_iter())
                        .collect(),
                ),
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
            labels: Some(
                [("kubevirt.io/job".to_string(), name.to_string())]
                    .iter()
                    .cloned()
                    .chain(labels.unwrap_or_default().into_iter())
                    .collect(),
            ),
            ..Default::default()
        },
        spec: Some(jobspec),
        ..Default::default()
    };

    let job = (|| async { api.create(&PostParams::default(), &job).await })
        .retry(
            &ConstantBuilder::default()
                .with_max_times(2)
                .with_delay(std::time::Duration::from_secs(1)),
        )
        .await?;
    info!("Creating job {} complete", name);

    Ok(job)
}

pub async fn wait_for_job_completion(name: &str) -> Result<()> {
    let client = Client::try_default().await?;
    let api: Api<Job> = Api::namespaced(client, "tnets");

    let job_status = (|| async {
        let job = api.get(name).await?;
        let status = job.status.clone().unwrap_or_default();
        if status.succeeded.is_some() {
            return Ok(status);
        }
        Err(anyhow!("Job {} not yet completed", name))
    })
    .retry(
        &ConstantBuilder::default()
            .with_max_times(30)
            .with_delay(std::time::Duration::from_secs(3)),
    )
    .await?;
    debug!("Job {} status: {:?}", name, job_status);

    Ok(())
}
