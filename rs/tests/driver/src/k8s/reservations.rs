use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use backon::ConstantBuilder;
use backon::Retryable;
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::{
    api::{DynamicObject, GroupVersionKind},
    Api, Client,
};
use tracing::*;

static RESERVATION_TEMPLATE: &str = r#"
apiVersion: scheduling.koordinator.sh/v1alpha1
kind: Reservation
metadata:
  name: {name}
  namespace: tnets
spec:
  allocateOnce: false
  template:
    metadata:
      namespace: tnets
      labels:
        tnet.internetcomputer.org/name: {tnet_name}
    spec:
      affinity:
        podAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: tnet.internetcomputer.org/name
                      operator: In
                      values:
                        - {tnet_name}
                topologyKey: "kubernetes.io/hostname"
      containers:
        - command: ["tail", "-f", "/dev/null"]
          image: alpine:latest
          name: reservation
          resources:
            requests:
              cpu: {cpu}
              memory: {memory}
      schedulerName: koord-scheduler # use koord-scheduler
  owners:
    - object:
        name: {name}-test
        namespace: tnets
    - labelSelector:
        matchLabels:
          kubevirt.io/vm: {vm_name}
  ttl: 1h
"#;

pub async fn create_reservation(
    name: String,
    vm_name: String,
    tnet_name: String,
    ttl: Option<String>,
    requests: Option<(String, String)>,
) -> Result<String> {
    let client = Client::try_default().await?;
    let gvk = GroupVersionKind::gvk("scheduling.koordinator.sh", "v1alpha1", "Reservation");
    let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
    let api = Api::<DynamicObject>::all_with(client.clone(), &ar);

    info!("Creating reservation {}", name);
    let (cpu, memory) = requests.unwrap_or((String::from("0.5"), String::from("256Mi")));
    let yaml = RESERVATION_TEMPLATE
        .replace("{name}", name.as_str())
        .replace("{vm_name}", &vm_name)
        .replace("{tnet_name}", &tnet_name)
        .replace("{cpu}", &cpu)
        .replace("{memory}", &memory)
        .replace("{ttl}", &ttl.unwrap_or(String::from("1h")));
    debug!("YAML: {}", yaml);

    let data: DynamicObject = serde_yaml::from_str(&yaml)?;
    let response = api
        .patch(
            &name,
            &PatchParams::apply("system-driver"),
            &Patch::Apply(data),
        )
        .await?;
    debug!("Creating reservation response: {:?}", response);
    info!("Creating reservation {} complete", name);

    let node_name = (|| async {
        let r: DynamicObject = api.get(&name).await?;
        r.data
            .get("status")
            .and_then(|status| status.get("nodeName"))
            .and_then(|node_name| node_name.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow!("Node name not found"))
    })
    .retry(
        &ConstantBuilder::default()
            .with_max_times(60)
            .with_delay(Duration::from_secs(3)),
    )
    .await?;

    Ok(node_name)
}

pub async fn delete_reservation(name: &str) -> Result<()> {
    info!("Deleting reservation {}", name);

    let client = Client::try_default().await?;
    let gvk = GroupVersionKind::gvk("scheduling.koordinator.sh", "v1alpha1", "Reservation");
    let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
    let api = Api::<DynamicObject>::all_with(client.clone(), &ar);
    api.delete(name, &DeleteParams::default()).await?;

    Ok(())
}
