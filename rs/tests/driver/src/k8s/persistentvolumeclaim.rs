use std::collections::BTreeMap;

use anyhow::Result;
use k8s_openapi::api::core::v1::{
    PersistentVolumeClaim, PersistentVolumeClaimSpec, ResourceRequirements,
    TypedLocalObjectReference,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{ObjectMeta, PostParams};
use kube::Api;
use tracing::*;

pub async fn create_pvc(
    api: &Api<PersistentVolumeClaim>,
    name: &str,
    size: &str,
    volume_mode: Option<String>,
    storage_class_name: Option<String>,
    data_source: Option<TypedLocalObjectReference>,
    owner: OwnerReference,
) -> Result<PersistentVolumeClaim> {
    info!("Creating persistent volume claim {}", name);
    let pvc = PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: vec![owner].into(),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(ResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_string(),
                    Quantity(size.to_string()),
                )])),
                ..Default::default()
            }),
            data_source,
            storage_class_name,
            volume_mode,
            ..Default::default()
        }),
        ..Default::default()
    };
    let pvc = api.create(&PostParams::default(), &pvc).await?;
    info!("Creating persistent volume claim {} complete", name);

    Ok(pvc)
}
