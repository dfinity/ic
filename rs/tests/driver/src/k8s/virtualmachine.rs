use crate::driver::resource::ImageType;
use crate::k8s::config::*;
use anyhow::Result;
use backon::{ExponentialBuilder, Retryable};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DynamicObject, Patch, PatchParams};
use kube::{Api, Client};
use std::convert::AsRef;
use std::net::{Ipv4Addr, Ipv6Addr};
use strum_macros::AsRefStr;
use tracing::*;

static UVM_TEMPLATE: &str = r#"
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
        "cni.projectcalico.org/ipAddrs": "[\"{ipv4}\", \"{ipv6}\"]"
      labels:
        kubevirt.io/vm: {name}
    spec:
      schedulerName: koord-scheduler
      domain:
        cpu:
          cores: {cpus}
          model: host-passthrough
        firmware:
          bootloader:
            efi:
              secureBoot: false
        devices:
          autoattachSerialConsole: true
          logSerialConsole: true
          disks:
            - name: disk0
              disk:
                bus: virtio
            - name: cloudinitdisk
              disk:
                bus: virtio
          interfaces:
          - name: default
            binding:
              name: passt
        resources:
          overcommitGuestOverhead: true
          requests:
            memory: {memory_request}Ki
        memory:
          guest: {memory}Ki
      networks:
      - name: default
        pod: {}
      volumes:
        - hostDisk:
            type: Disk
            path: /srv/tnet/{name}/disk.img
          name: disk0
        - name: cloudinitdisk
          cloudInitNoCloud:
            userData: |
              #cloud-config
              mounts:
                - ["/dev/sda", "/config", "vfat", "dmask=000,fmask=0111,user,nofail", 0, 0]
              users:
                - name: admin
                  sudo: ALL=(ALL) NOPASSWD:ALL
                  groups: docker
                  no_user_group: true
                  shell: /bin/bash
                  ssh-authorized-keys:
                    - {pub_key}
              write_files:
                - path: /etc/systemd/system/activate.service
                  permissions: '0755'
                  content: |
                      [Unit]
                      Description=Activate Script
                      Requires=docker.service
                      After=docker.service

                      [Service]
                      Type=simple
                      ExecStart=bash /config/activate
                      Restart=no

                      [Install]
                      WantedBy=multi-user.target
              runcmd:
                - systemctl daemon-reload
                - systemctl enable --now activate
"#;

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
        "cni.projectcalico.org/ipAddrs": "[\"{ipv4}\", \"{ipv6}\"]"
      labels:
        kubevirt.io/vm: {name}
    spec:
      nodeSelector:
        kubernetes.io/hostname: {node}
      schedulerName: koord-scheduler
      domain:
        cpu:
          cores: {cpus}
          model: host-passthrough
        firmware:
          bootloader:
            efi:
              secureBoot: false
        devices:
          autoattachSerialConsole: true
          logSerialConsole: true
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
            binding:
              name: passt
        resources:
          overcommitGuestOverhead: true
          requests:
            memory: {memory_request}Ki
        memory:
          guest: {memory}Ki
      networks:
      - name: default
        pod: {}
      volumes:
        - hostDisk:
            type: Disk
            path: /srv/tnet/{name}/disk.img
          name: disk0
        - hostDisk:
            type: Disk
            path: /srv/tnet/{name}/config_disk.img
          name: disk1
"#;

pub async fn create_vm(
    api: &Api<DynamicObject>,
    name: &str,
    cpus: &str,
    memory: &str,
    memory_request: &str,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    running: bool,
    owner: OwnerReference,
    access_key: Option<String>,
    vm_type: ImageType,
    node: Option<String>,
) -> Result<()> {
    info!("Creating virtual machine {}", name);
    let template = match vm_type {
        ImageType::IcOsImage => NODE_TEMPLATE.to_string(),
        _ => UVM_TEMPLATE.replace("{pub_key}", &access_key.unwrap()),
    };
    let yaml = template
        .replace("{name}", name)
        .replace("{tnet}", &owner.name)
        .replace("{running}", &running.to_string())
        .replace("{memory}", memory)
        .replace("{memory_request}", memory_request)
        .replace("{cpus}", cpus)
        .replace("{ipv4}", &ipv4.to_string())
        .replace("{ipv6}", &ipv6.to_string())
        .replace("{node}", &node.unwrap_or_default());
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
#[strum(serialize_all = "lowercase")]
enum Action {
    Start,
    Restart,
    Stop,
    Delete,
    #[strum(serialize = "stop")]
    Destroy,
}

pub async fn start_vm(name: &str) -> Result<()> {
    action_vm(name, Action::Start).await
}

pub async fn restart_vm(name: &str) -> Result<()> {
    action_vm(name, Action::Restart).await
}

pub async fn stop_vm(name: &str) -> Result<()> {
    action_vm(name, Action::Stop).await
}

pub async fn delete_vm(name: &str) -> Result<()> {
    action_vm(name, Action::Delete).await
}

pub async fn destroy_vm(name: &str) -> Result<()> {
    action_vm(name, Action::Destroy).await
}

async fn action_vm(name: &str, action: Action) -> Result<()> {
    let client = Client::try_default().await?;

    (|| async {
        client
            .request_text(match action {
                Action::Start | Action::Stop | Action::Restart | Action::Destroy => {
                    http::Request::builder()
                        .method("PUT")
                        .uri(format!(
                            "/apis/subresources.kubevirt.io/v1/namespaces/{}/virtualmachines/{}/{}",
                            *TNET_NAMESPACE,
                            name,
                            action.as_ref(),
                        ))
                        .body(
                            (if matches!(action, Action::Destroy) {
                                "{\"gracePeriod\": 0}"
                            } else {
                                "{}"
                            })
                            .as_bytes()
                            .to_vec(),
                        )
                        .unwrap()
                }
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
    .await?;
    Ok(())
}

pub async fn add_volume(name: &str, volume_name: &str) -> Result<()> {
    let client = Client::try_default().await?;

    (|| async {
        client
            .request_text(
                http::Request::builder()
                        .method("PUT")
                        .uri(format!(
                            "/apis/subresources.kubevirt.io/v1/namespaces/{}/virtualmachines/{}/addvolume",
                            *TNET_NAMESPACE,
                            name,
                        ))
                        .body(serde_json::to_vec(&serde_json::json!({
                          "disk": {
                            "disk": {
                              "bus": "scsi"
                            },
                            "serial": volume_name,
                          },
                          "name": format!("disk-{volume_name}"),
                          "volumeSource": {
                            "dataVolume": {
                              "name": format!("{name}-{volume_name}")
                            },
                          }
                        })).unwrap()).unwrap(),
                        )
            .await
            .or_else(|e| match e {
                kube::Error::Api(error_response) if error_response.reason == "Conflict" => {
                    kube::Result::Ok(Default::default())
                }
                _ => kube::Result::Err(e),
            })
    })
    .retry(&ExponentialBuilder::default())
    .await?;
    Ok(())
}
