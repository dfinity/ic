use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::DynamicObject;
use kube::api::{Patch, PatchParams};
use kube::Api;
use tracing::*;

use crate::event::*;
use crate::pod::get_pods;
use crate::tnet::K8sClient;
use crate::tnet::{TNet, TNode};

static VM_PVC_TEMPLATE: &str = r#"
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
        "cni.projectcalico.org/ipAddrs": '["{ipv6}"]'
        "container.apparmor.security.beta.kubernetes.io/compute": unconfined
      labels:
        kubevirt.io/vm: {name}
        kubevirt.io/network: passt
    spec:
      domain:
        cpu:
          cores: 32
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
              - port: 4100
              - port: 2497
              - port: 8080
              - port: 9090
              - port: 9100
        resources:
          requests:
            memory: 64Gi
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

static VM_HOST_DISK_TEMPLATE: &str = r#"
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: {name}
  tnet.internetcomputer.org/name: {tnet}
spec:
  running: true
  template:
    metadata:
      annotations:
        "cni.projectcalico.org/ipAddrs": '["{ipv6}"]'
        "container.apparmor.security.beta.kubernetes.io/compute": "unconfined"
      labels:
        kubevirt.io/network: passt
        kubevirt.io/vm: {name}
    spec:
      nodeSelector:
        kubernetes.io/hostname: {nodename}
      domain:
        cpu:
          cores: 32
        devices:
          disks:
          - disk:
              bus: virtio
            name: host-disk-guestos
          - disk:
              bus: scsi
            name: host-disk-config
            serial: config
          interfaces:
          - name: default
            passt: {}
            ports:
            - port: 22
            - port: 4100
            - port: 2497
            - port: 8080
            - port: 9090
            - port: 9100
        firmware:
          bootloader:
            efi:
              secureBoot: false
        machine:
          type: q35
        resources:
          requests:
            memory: 64Gi
      networks:
      - name: default
        pod: {}
      volumes:
      - hostDisk:
          path: /tnet/{tnet}/{name}-guestos.img
          type: Disk
        name: host-disk-guestos
      - hostDisk:
          path: /tnet/{tnet}/{name}-config.img
          type: Disk
        name: host-disk-config
"#;

static VMI_SETUP_TEMPLATE: &str = r#"
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstance
metadata:
  name: {vmi_name}
  labels:
    kubevirt.io/vm: {vm_name}
    tnet.internetcomputer.org/name: {tnet}
spec:
  terminationGracePeriodSeconds: 30
  domain:
    cpu:
      cores: 32
    resources:
      requests:
        memory: 64G
    devices:
      disks:
      - name: containerdisk
        disk:
          bus: virtio
      - name: host-disk-guestos
        disk:
          bus: virtio
      - name: host-disk-config
        disk:
          bus: virtio
      - disk:
          bus: virtio
        name: cloudinitdisk
  volumes:
  - name: containerdisk
    containerDisk:
      image: kubevirt/fedora-cloud-container-disk-demo:v0.36.4
  - hostDisk:
      capacity: 52Gi
      path: /tnet/{tnet}/{vm_name}-guestos.img
      type: DiskOrCreate
    name: host-disk-guestos
  - hostDisk:
      capacity: 12Mi
      path: /tnet/{tnet}/{vm_name}-config.img
      type: DiskOrCreate
    name: host-disk-config
  - name: cloudinitdisk
    cloudInitNoCloud:
      userData: |-
        #cloud-config
        password: fedora
        chpasswd: { expire: False }
        runcmd:
          - set -exuo pipefail
          - |
            # write guestos disk image to /dev/sdb
            curl -O {url_image}
            tar -xzOf disk-img.tar.gz | sudo dd of=/dev/vdb bs=1M status=progress
          - |
            # write config disk image to /dev/sdc
            curl -o config.img {url_config}
            sudo dd if=config.img of=/dev/vdc bs=1M status=progress
          - sudo poweroff
"#;

pub async fn prepare_host_vm(k8s_client: &K8sClient, node: &TNode, tnet: &TNet) -> Result<()> {
    let vm_name: String = node.name.as_ref().unwrap().to_string();
    let vmi_name: String = format!("{}-disk-setup", &node.name.as_ref().unwrap());
    let ipv6_addr: String = node.ipv6_addr.unwrap().to_string();
    let url_image: String = tnet.image_url.clone();
    let url_config: String = node.config_url.as_ref().unwrap().to_string();

    info!("Preparing disks for virtual machine {}", &vm_name);
    let yaml = VMI_SETUP_TEMPLATE
        .replace("{vm_name}", &vm_name)
        .replace("{vmi_name}", &vmi_name)
        .replace("{tnet}", &TNet::owner_config_map_name(tnet.index.unwrap()))
        .replace("{ipv6}", &ipv6_addr)
        .replace("{url_image}", &url_image)
        .replace("{url_config}", &url_config);

    let mut data: DynamicObject = serde_yaml::from_str(&yaml)?;
    data.metadata.owner_references = vec![tnet.owner_reference()].into();
    let response = k8s_client
        .api_vmi
        .patch(
            &vmi_name,
            &PatchParams::apply("system-driver"),
            &Patch::Apply(data),
        )
        .await?;
    debug!("Creating virtual machine instance response: {:?}", response);

    Ok(())
}

pub async fn create_host_vm(k8s_client: &K8sClient, node: &TNode, tnet: &TNet) -> Result<()> {
    let vm_name: String = node.name.as_ref().unwrap().to_string();
    let vmi_name: String = format!("{}-disk-setup", &node.name.as_ref().unwrap());

    wait_for_event(
        k8s_client.client.clone(),
        &tnet.namespace,
        "Signaled Deletion",
        "VirtualMachineInstance",
        &vmi_name,
        600,
    )
    .await
    .unwrap_or_else(|_| {
        error!(
            "Timeout waiting for VirtualMachineInstance {} to create local image disks",
            &vmi_name
        );
        std::process::exit(124);
    });
    info!("Preparing disks for virtual machine {} complete", &vm_name);

    let labels = Some(BTreeMap::from([(
        "kubevirt.io/vm".to_string(),
        vm_name.to_string(),
    )]));
    let pods = get_pods(&k8s_client.api_pod, labels).await?;
    if pods.items.is_empty() {
        return Err(anyhow!("No setup vmi found!"));
    } else if pods.items.len() > 1 {
        return Err(anyhow!("Multiple setup vmis found!"));
    }
    let nodename = pods.items[0]
        .metadata
        .labels
        .as_ref()
        .unwrap()
        .get("kubevirt.io/nodeName")
        .unwrap();

    info!("Creating virtual machine {}", &vm_name);
    let yaml = VM_HOST_DISK_TEMPLATE
        .replace("{nodename}", nodename)
        .replace("{name}", &vm_name)
        .replace("{tnet}", &TNet::owner_config_map_name(tnet.index.unwrap()))
        .replace("{ipv6}", &node.ipv6_addr.as_ref().unwrap().to_string());
    let mut data: DynamicObject = serde_yaml::from_str(&yaml)?;
    data.metadata.owner_references = vec![tnet.owner_reference()].into();
    let response = &k8s_client
        .api_vm
        .patch(
            &vm_name,
            &PatchParams::apply("system-driver"),
            &Patch::Apply(data),
        )
        .await?;
    debug!("Creating virtual machine response: {:?}", response);
    info!("Creating virtual machine {} complete", vm_name);

    Ok(())
}

pub async fn create_vm(
    api: &Api<DynamicObject>,
    name: &str,
    ipv6: &str,
    running: bool,
    owner: OwnerReference,
) -> Result<()> {
    info!("Creating virtual machine {}", name);
    let yaml = VM_PVC_TEMPLATE
        .replace("{name}", name)
        .replace("{tnet}", &owner.name)
        .replace("{running}", &running.to_string())
        .replace("{ipv6}", ipv6);
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
