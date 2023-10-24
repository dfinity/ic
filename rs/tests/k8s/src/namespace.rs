use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{DeleteParams, ListParams, ObjectList, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{Api, ResourceExt};
use tracing::*;

pub async fn create_namespace(
    api: &Api<Namespace>,
    name: &str,
    labels: Option<BTreeMap<String, String>>,
) -> Result<Namespace> {
    info!("Creating namespace {}", name);
    if api.get(name).await.is_ok() {
        return Err(anyhow!("Namespace {} already exists!", name));
    }

    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels,
            ..Default::default()
        },
        ..Default::default()
    };
    let ns = api.create(&PostParams::default(), &ns).await?;
    info!("Creating namespace {} complete", name);

    Ok(ns)
}

pub async fn get_namespace(api: &Api<Namespace>, name: &str) -> Result<Namespace> {
    Ok(api.get(name).await?)
}

pub async fn get_namespaces(
    api: &Api<Namespace>,
    labels: Option<BTreeMap<String, String>>,
) -> Result<ObjectList<Namespace>> {
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

pub async fn delete_namespace(api: &Api<Namespace>, name: &str) -> Result<()> {
    info!("Deleting namespace {}", name);
    api.delete(name, &DeleteParams::default()).await?;
    Ok(())
}
