use crate::k8s::config::*;
use anyhow::Result;
use backon::{ExponentialBuilder, Retryable};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DynamicObject, Patch, PatchParams};
use kube::{Api, Client};
use std::convert::AsRef;
use strum_macros::AsRefStr;
use tracing::*;

static NODE_TEMPLATE: &str = r#"
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  labels:
    kubevirt.io/vm: {name}
    tnet.internetcomputer.org/name: {tnet}
  name: {name}
spec:
  running: {running}
  template:
    metadata:
      annotations:
        "container.apparmor.security.beta.kubernetes.io/compute": unconfined
      labels:
        kubevirt.io/vm: {name}
        kubevirt.io/network: passt
    spec:
      domain:
        cpu:
          cores: {cpus}
        firmware:
          bootloader:
            efi:
              secureBoot: false
        devices:
          disks:
            - name: disk0
              disk:
                bus: virtio
            - name: disk1
              disk:
                bus: scsi
              serial: "config"
          interfaces:
          - name: default
            passt: {}
            ports:
              - port: 22
              - port: 80
              - port: 443
              - port: 2497
              - port: 4100
              - port: 7070
              - port: 8080
              - port: 9090
              - port: 9091
              - port: 9100
              - port: 19100
              - port: 19531
        resources:
          requests:
            memory: {memory}Ki
      networks:
      - name: default
        pod: {}
      volumes:
        - dataVolume:
            name: "{name}-guestos"
          name: disk0
        - dataVolume:
            name: "{name}-config"
          name: disk1
"#;

pub async fn create_vm(
    api: &Api<DynamicObject>,
    name: &str,
    cpus: &str,
    memory: &str,
    running: bool,
    owner: OwnerReference,
) -> Result<()> {
    info!("Creating virtual machine {}", name);
    let yaml = NODE_TEMPLATE
        .replace("{name}", name)
        .replace("{tnet}", &owner.name)
        .replace("{running}", &running.to_string())
        .replace("{memory}", memory)
        .replace("{cpus}", cpus);
    let mut data: DynamicObject = serde_yaml::from_str(&yaml)?;
    data.metadata.owner_references = vec![owner].into();
    let response = api
        .patch(
            name,
            &PatchParams::apply("system-driver"),
            &Patch::Apply(data),
        )
        .await?;
    debug!("Creating virtual machine response: {:?}", response);
    info!("Creating virtual machine {} complete", name);
    Ok(())
}

#[derive(Debug, AsRefStr)]
enum Action {
    #[strum(serialize = "start")]
    Start,
    #[strum(serialize = "restart")]
    Restart,
    #[strum(serialize = "stop")]
    Stop,
    Delete,
}

pub async fn start_vm(name: &str) -> Result<String> {
    action_vm(name, Action::Start).await
}

pub async fn restart_vm(name: &str) -> Result<String> {
    action_vm(name, Action::Restart).await
}

pub async fn stop_vm(name: &str) -> Result<String> {
    action_vm(name, Action::Stop).await
}

pub async fn delete_vm(name: &str) -> Result<String> {
    action_vm(name, Action::Delete).await
}

async fn action_vm(name: &str, action: Action) -> Result<String> {
    let client = Client::try_default().await?;

    Ok((|| async {
        client
            .request_text(match action {
                Action::Start | Action::Stop | Action::Restart => http::Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/apis/subresources.kubevirt.io/v1/namespaces/{}/virtualmachines/{}/{}",
                        *TNET_NAMESPACE,
                        name,
                        action.as_ref(),
                    ))
                    .body("{}".as_bytes().to_vec())
                    .unwrap(),
                Action::Delete => http::Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/apis/kubevirt.io/v1/namespaces/{}/virtualmachines/{}",
                        *TNET_NAMESPACE, name
                    ))
                    .body("{}".as_bytes().to_vec())
                    .unwrap(),
            })
            .await
            .or_else(|e| match e {
                kube::Error::Api(error_response) if error_response.reason == "Conflict" => {
                    kube::Result::Ok(Default::default())
                }
                _ => kube::Result::Err(e),
            })
    })
    .retry(&ExponentialBuilder::default())
    .await?)
}
