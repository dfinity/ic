use rand::seq::SliceRandom;
use regex::Regex;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use url::Url;

use anyhow::Result;
use backon::Retryable;
use backon::{ConstantBuilder, ExponentialBuilder};
use k8s_openapi::api::core::v1::{
    ConfigMap, PersistentVolumeClaim, Pod, Secret, Service, TypedLocalObjectReference,
};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use k8s_openapi::chrono::DateTime;
use k8s_openapi::chrono::Duration;
use k8s_openapi::chrono::Utc;
use kube::api::{DeleteParams, PostParams};
use kube::core::ObjectMeta;
use kube::ResourceExt;
use kube::{
    api::{Api, DynamicObject, GroupVersionKind},
    Client,
};
use serde::{Deserialize, Serialize};
use tokio;
use tracing::*;

use crate::driver::farm::{
    Certificate, CreateVmRequest, DnsRecord, DnsRecordType, ImageLocation, PlaynetCertificate,
    VMCreateResponse, VmSpec,
};
use crate::driver::resource::ImageType;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::k8s::config::*;
use crate::k8s::datavolume::*;
use crate::k8s::persistentvolumeclaim::*;
use crate::k8s::virtualmachine::*;

const PLAYNET_POOL_SIZE: usize = 33;

#[allow(dead_code)]
pub struct K8sClient {
    pub(crate) api_dv: Api<DynamicObject>,
    pub(crate) api_vm: Api<DynamicObject>,
    pub(crate) api_vmi: Api<DynamicObject>,
    pub(crate) api_ipreservation: Api<DynamicObject>,
    pub(crate) api_pvc: Api<PersistentVolumeClaim>,
    pub(crate) api_pod: Api<Pod>,
    pub(crate) api_svc: Api<Service>,
    pub(crate) api_ingress: Api<Ingress>,
}

impl K8sClient {
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;
        let api_pod: Api<Pod> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        let api_pvc: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        let api_svc: Api<Service> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        let api_ingress: Api<Ingress> = Api::namespaced(client.clone(), &TNET_NAMESPACE);

        let gvk = GroupVersionKind::gvk("cdi.kubevirt.io", "v1beta1", "DataVolume");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_dv = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachine");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vm = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachineInstance");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vmi = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        let gvk = GroupVersionKind::gvk("crd.projectcalico.org", "v1", "IPReservation");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_ipreservation = Api::<DynamicObject>::all_with(client.clone(), &ar);

        Ok(Self {
            api_dv,
            api_vm,
            api_vmi,
            api_pvc,
            api_pod,
            api_svc,
            api_ingress,
            api_ipreservation,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TNode {
    pub node_id: Option<String>,
    pub name: Option<String>,
    pub ipv6_addr: Option<Ipv6Addr>,
    pub config_url: Option<String>,
    owner: ConfigMap,
}

impl TNode {
    fn owner_reference(&self) -> OwnerReference {
        OwnerReference {
            api_version: k8s_openapi::api_version(&self.owner).to_owned(),
            kind: k8s_openapi::kind(&self.owner).to_owned(),
            name: self
                .owner
                .metadata
                .name
                .clone()
                .expect("should have a name"),
            uid: self.owner.metadata.uid.clone().expect("should have uid"),
            ..Default::default()
        }
    }

    pub async fn deploy_config_image(
        &self,
        image_name: &str,
        dv_name: &str,
        content_type: DataVolumeContentType,
    ) -> Result<()> {
        let client = Client::try_default().await?;
        let gvk = GroupVersionKind::gvk("cdi.kubevirt.io", "v1beta1", "DataVolume");
        let (ar, _) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api = Api::<DynamicObject>::namespaced_with(client, &TNET_NAMESPACE, &ar);

        let dvname = format!("{}-{}", self.name.clone().unwrap(), dv_name);
        let source = DvSource::url(format!(
            "{}/{}",
            self.config_url.clone().unwrap(),
            image_name
        ));
        let dvinfo = DvInfo::new(&dvname, source, content_type, "512Mi");
        info!("Creating DV {}", dvname);
        create_datavolume(&api, &dvinfo, self.owner_reference()).await?;
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        start_vm(&self.name.clone().expect("name missing")).await
    }

    pub async fn stop(&self) -> Result<()> {
        stop_vm(&self.name.clone().expect("name missing")).await
    }

    pub async fn add_volume(&self, name: &str) -> Result<()> {
        add_volume(&self.name.clone().expect("name missing"), name).await
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct TNet {
    pub group_name: String,
    pub unique_name: Option<String>,
    pub version: String,
    pub image_url: String,
    pub config_url: Option<String>,
    pub access_key: Option<String>,
    pub nodes: Vec<TNode>,
    pub owner: ConfigMap,
    terminate_time: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub logger: Option<Logger>,
}

impl TestEnvAttribute for TNet {
    fn attribute_name() -> String {
        "tnet".to_string()
    }
}

impl TNet {
    pub fn new(group_name: &str) -> Result<Self> {
        Self {
            group_name: group_name.to_string(),
            ..Default::default()
        }
        .ttl(Duration::minutes(90))
    }

    pub fn from_env(env: &TestEnv) -> Self {
        let log = env.logger();
        let mut tnet = Self::read_attribute(env);
        tnet.logger = Some(log);
        tnet
    }

    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        if self.image_url.is_empty() {
            self.image_url = format!(
                "{}/ic/{}/guest-os/disk-img-dev/disk-img.tar.zst",
                *TNET_CDN_URL, self.version
            );
        }
        self
    }

    pub fn image_url(mut self, url: &str) -> Self {
        self.image_url = url.to_string();
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Result<Self> {
        self.terminate_time = Some(
            k8s_openapi::chrono::Utc::now()
                .checked_add_signed(ttl)
                .ok_or(anyhow::anyhow!("failed to set terminate time"))?,
        );
        Ok(self)
    }

    fn owner_reference(&self) -> OwnerReference {
        OwnerReference {
            api_version: k8s_openapi::api_version(&self.owner).to_owned(),
            kind: k8s_openapi::kind(&self.owner).to_owned(),
            name: self
                .owner
                .metadata
                .name
                .clone()
                .expect("should have a name"),
            uid: self.owner.metadata.uid.clone().expect("should have uid"),
            ..Default::default()
        }
    }

    pub async fn create(&mut self) -> Result<&Self> {
        let client = Client::try_default().await?;
        let config_map_api = Api::<ConfigMap>::namespaced(client.clone(), &TNET_NAMESPACE);

        debug!("Creating owner configmap");
        let config_map = (|| async {
            config_map_api
                .create(
                    &PostParams::default(),
                    &ConfigMap {
                        metadata: ObjectMeta {
                            generate_name: format!("{}-", self.group_name).into(),
                            labels: [(TNET_NAME_LABEL.to_string(), self.group_name.clone())]
                                .into_iter()
                                .chain(TNET_STATIC_LABELS.clone().into_iter())
                                .collect::<BTreeMap<String, String>>()
                                .into(),
                            annotations: [(
                                TNET_TERMINATE_TIME_ANNOTATION.to_string(),
                                self.terminate_time
                                    .expect("Terminate time missing")
                                    .to_rfc3339_opts(
                                        k8s_openapi::chrono::SecondsFormat::Secs,
                                        true,
                                    ),
                            )]
                            .into_iter()
                            .collect::<BTreeMap<String, String>>()
                            .into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .await
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        debug!("Tnet owner: {}", config_map.name_any());
        self.unique_name.clone_from(&config_map.metadata.name);
        self.owner = config_map;
        self.config_url = Some(format!(
            "{}/{}/{}",
            *TNET_CONFIG_URL,
            *TNET_BUCKET,
            self.unique_name.clone().unwrap(),
        ));
        Ok(self)
    }

    pub async fn delete(self) -> Result<()> {
        let client = Client::try_default().await?;
        let api: Api<ConfigMap> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        api.delete(
            &self.unique_name.clone().expect("missing unique name"),
            &Default::default(),
        )
        .await?;
        Ok(())
    }

    pub async fn deploy_guestos_image(&self) -> Result<()> {
        let image_name = &format!("{}-image-guestos", self.owner.name_any());
        self.deploy_image(image_name, &self.image_url).await?;
        Ok(())
    }

    pub async fn deploy_boundary_image(&self, url: Url) -> Result<()> {
        let image_name = &format!("{}-image-boundaryos", self.owner.name_any());
        self.deploy_image(image_name, url.as_str()).await?;
        Ok(())
    }

    async fn deploy_image(&self, name: &str, url: &str) -> Result<()> {
        let client = Client::try_default().await?;
        let gvk = GroupVersionKind::gvk("cdi.kubevirt.io", "v1beta1", "DataVolume");
        let (ar, _) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_dv = Api::<DynamicObject>::namespaced_with(client, &TNET_NAMESPACE, &ar);

        let source = DvSource::url(url.into());
        let dvinfo = DvInfo::new(name, source, DataVolumeContentType::Archive, "50Gi");
        info!("Creating DV {} from {}", name, url);
        create_datavolume(&api_dv, &dvinfo, self.owner_reference()).await?;
        // wait for the datavolume to be ready
        tokio::time::timeout(tokio::time::Duration::from_secs(300), async {
            while (|| async {
                api_dv
                    .get(name)
                    .await
                    .map(|r| r.data["status"]["phase"] != "Succeeded")
            })
            .retry(&ExponentialBuilder::default())
            .await?
            {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
            anyhow::Ok(())
        })
        .await??;

        Ok(())
    }

    pub async fn vm_create(
        &mut self,
        vm_req: CreateVmRequest,
        vm_type: ImageType,
    ) -> Result<VMCreateResponse> {
        let k8s_client = &K8sClient::new().await?;
        let vm_name = format!(
            "{}-{}",
            self.unique_name.clone().expect("no unique name"),
            match vm_type {
                ImageType::IcOsImage => self.nodes.len().to_string(),
                ImageType::UniversalImage | ImageType::PrometheusImage =>
                    format!("{}-{}", self.nodes.len(), vm_req.name),
            }
        );
        let pvc_name = format!("{}-guestos", vm_name.clone());
        let data_source = Some(TypedLocalObjectReference {
            api_group: None,
            kind: "PersistentVolumeClaim".to_string(),
            name: match vm_req.primary_image {
                ImageLocation::PersistentVolumeClaim { name } => name,
                _ => unimplemented!(),
            },
        });

        create_pvc(
            &k8s_client.api_pvc,
            &pvc_name,
            "100Gi",
            None,
            None,
            data_source,
            self.owner_reference(),
        )
        .await?;

        let mut ipam_pod: Pod = serde_yaml::from_str(&format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  containers:
    - name: nginx
      image: registry.k8s.io/pause:3.8
    "#,
            name = vm_name,
        ))?;
        ipam_pod.metadata.owner_references = vec![self.owner_reference()].into();

        (|| async {
            k8s_client
                .api_pod
                .create(&PostParams::default(), &ipam_pod)
                .await
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        let (ipv4, ipv6) = (|| async {
            k8s_client
                .api_pod
                .get(&vm_name)
                .await
                .map_err(|e| anyhow::anyhow!(e))
                .and_then(|s| s.status.ok_or_else(|| anyhow::anyhow!("missing spec")))
                .and_then(|s| s.pod_ips.ok_or_else(|| anyhow::anyhow!("missing podIPs")))
                .and_then(|ips| {
                    ips.iter()
                        .map(|ip| {
                            ip.ip
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("no ip"))
                                .and_then(|ip| {
                                    Ipv4Addr::from_str(ip).map_err(|e| anyhow::anyhow!(e))
                                })
                        })
                        .find_map(|r| r.ok())
                        .ok_or_else(|| anyhow::anyhow!("missing ipv4 address"))
                        .and_then(|ipv4| {
                            ips.iter()
                                .map(|ip| {
                                    ip.ip
                                        .as_ref()
                                        .ok_or_else(|| anyhow::anyhow!("no ip"))
                                        .and_then(|ip| {
                                            Ipv6Addr::from_str(ip).map_err(|e| anyhow::anyhow!(e))
                                        })
                                })
                                .find_map(|r| r.ok().map(|ipv6| (ipv4, ipv6)))
                                .ok_or_else(|| anyhow::anyhow!("missing ipv6 address"))
                        })
                })
        })
        .retry(
            &ConstantBuilder::default()
                .with_max_times(60)
                .with_delay(std::time::Duration::from_secs(1)),
        )
        .await?;

        let mut ip_reservation: DynamicObject = serde_yaml::from_str(&format!(
            r#"
apiVersion: crd.projectcalico.org/v1
kind: IPReservation
metadata:
  name: {name}
spec:
  reservedCIDRs:
    - {ipv4}
    - {ipv6}
    "#,
            name = vm_name,
        ))?;
        ip_reservation.metadata.owner_references = vec![self.owner_reference()].into();

        (|| async {
            k8s_client
                .api_ipreservation
                .create(&PostParams::default(), &ip_reservation)
                .await
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        (|| async {
            k8s_client
                .api_pod
                .delete(&vm_name, &DeleteParams::default())
                .await
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        create_vm(
            &k8s_client.api_vm,
            &vm_name.clone(),
            &vm_req.vcpus.to_string(),
            &vm_req.memory_kibibytes.to_string(),
            ipv4,
            ipv6,
            false,
            self.owner_reference(),
            self.access_key.clone(),
            vm_type.clone(),
        )
        .await?;

        let mut svc: Service = serde_yaml::from_str(&format!(
            r#"
apiVersion: v1
kind: Service
metadata:
  name: {name}
spec:
  ipFamilyPolicy: PreferDualStack
  ipFamilies:
  - IPv6
  - IPv4
  ports:
    - port: 22
      name: ssh
    - port: 80
      name: http
    - port: 443
      name: https
    - port: 2497
      name: port-2497
    - port: 3000
      name: grafana
    - port: 4100
      name: port-4100
      protocol: UDP
    - port: 4444
      name: port-4444
    - port: 7070
      name: port-7070
    - port: 8080
      name: port-8080
    - port: 8100
      name: port-8100
    - port: 8101
      name: port-8101
    - port: 8102
      name: port-8102
    - port: 8103
      name: port-8103
    - port: 8104
      name: port-8104
    - port: 8105
      name: port-8105
    - port: 8106
      name: port-8106
    - port: 8107
      name: port-8107
    - port: 8108
      name: port-8108
    - port: 8109
      name: port-8109
    - port: 8110
      name: port-8110
    - port: 8111
      name: port-8111
    - port: 9091
      name: port-9091
    - port: 9100
      name: prometheus-node-exporter
    - port: 9090
      name: prometheus
    - port: 19100
      name: port-19100
    - port: 19531
      name: port-19531
    - port: 20443
      name: port-20443
  selector:
    kubevirt.io/vm: {name}
  type: ClusterIP
    "#,
            name = vm_name,
        ))?;
        svc.metadata.owner_references = vec![self.owner_reference()].into();

        (|| async {
            k8s_client
                .api_svc
                .create(&PostParams::default(), &svc)
                .await
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        if vm_type == ImageType::PrometheusImage {
            let mut ingress: Ingress = serde_yaml::from_str(&format!(
                r#"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {name}
  labels:
    app: nginx
spec:
  ingressClassName: nginx
  rules:
    - host: grafana-{name}.{suffix}
      http:
        paths:
          - backend:
              service:
                name: {svc_name}
                port:
                  number: 3000
            path: /
            pathType: Prefix
    - host: prometheus-{name}.{suffix}
      http:
        paths:
          - backend:
              service:
                name: {svc_name}
                port:
                  number: 9090
            path: /
            pathType: Prefix
  tls:
    - secretName: tnets-wildcard-tls
      hosts:
        - "*.tnets.{suffix}"
"#,
                name = self.unique_name.clone().expect("missing unique name"),
                svc_name = vm_name,
                suffix = *TNET_DNS_SUFFIX,
            ))?;
            ingress.metadata.owner_references = vec![self.owner_reference()].into();

            (|| async {
                k8s_client
                    .api_ingress
                    .create(&PostParams::default(), &ingress)
                    .await
            })
            .retry(&ExponentialBuilder::default())
            .await?;
        }

        self.nodes.push(TNode {
            node_id: vm_req.name.clone().into(),
            name: vm_name.clone().into(),
            ipv6_addr: ipv6.into(),
            config_url: format!("{}/{}", self.config_url.clone().unwrap(), vm_name.clone()).into(),
            owner: self.owner.clone(),
        });

        Ok(VMCreateResponse {
            ipv4: ipv4.into(),
            ipv6,
            mac6: "00:11:22:33:44:55".to_string(),
            hostname: vm_name,
            spec: VmSpec {
                v_cpus: vm_req.vcpus.get(),
                memory_ki_b: vm_req.memory_kibibytes.get(),
            },
        })
    }

    pub async fn start(&self) -> Result<()> {
        for node in self.nodes.iter() {
            node.start().await?;
        }
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for node in self.nodes.iter() {
            node.stop().await?;
        }
        Ok(())
    }

    pub async fn acquire_playnet_certificate(&self) -> Result<PlaynetCertificate> {
        let client = Client::try_default().await?;
        let config_map_api = Api::<ConfigMap>::namespaced(client.clone(), &TNET_NAMESPACE);

        let playnet_prefix = format!("{}-playnet-", self.unique_name.clone().unwrap());
        let config_map = (|| async {
            let existing_playnets = config_map_api
                .list(&Default::default())
                .await?
                .items
                .into_iter()
                .filter(|cm| {
                    cm.metadata
                        .labels
                        .as_ref()
                        .map(|l| l.contains_key(TNET_PLAYNET_LABEL))
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();

            if let Some(playnet) = existing_playnets.iter().find(|cm| {
                cm.metadata
                    .owner_references
                    .as_ref()
                    .expect("should have owner references")
                    .iter()
                    .any(|o| o.name == self.group_name)
            }) {
                slog::info!(
                    self.logger.as_ref().unwrap(),
                    "Using existing playnet: {}",
                    playnet.name_any()
                );
                return Ok(playnet.clone());
            }

            if existing_playnets.len() >= PLAYNET_POOL_SIZE {
                return Err(anyhow::anyhow!("Playnet pool is full"));
            }

            let random_number = *(1..=PLAYNET_POOL_SIZE)
                .filter(|n| {
                    !existing_playnets.iter().any(|cm| {
                        cm.metadata
                            .labels
                            .clone()
                            .expect("should have labels")
                            .get(TNET_PLAYNET_LABEL)
                            .unwrap()
                            == n.to_string().as_str()
                    })
                })
                .collect::<Vec<_>>()
                .choose_multiple(&mut rand::thread_rng(), 1)
                .next()
                .expect("should be able to choose one playnet");
            config_map_api
                .create(
                    &PostParams::default(),
                    &ConfigMap {
                        metadata: ObjectMeta {
                            name: format!("{}{}", playnet_prefix, random_number).into(),
                            labels: [(TNET_PLAYNET_LABEL.to_string(), random_number.to_string())]
                                .into_iter()
                                .collect::<BTreeMap<String, String>>()
                                .into(),
                            owner_references: vec![self.owner_reference()].into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| anyhow::anyhow!(e))
        })
        .retry(&ExponentialBuilder::default())
        .await?;

        let playnet_id = config_map
            .name_any()
            .strip_prefix(&playnet_prefix)
            .unwrap()
            .to_string();

        slog::info!(self.logger.as_ref().unwrap(), "Using playnet {playnet_id}");

        let secret_api = Api::<Secret>::namespaced(client.clone(), &TNET_NAMESPACE);
        let playnet_secret = secret_api.get(TNET_PLAYNET_SECRET).await?;

        let playnet = playnet_secret
            .metadata
            .annotations
            .expect("must have annotations")
            .get("cert-manager.io/alt-names")
            .expect("should have cert-manager.io/alt-names annotation")
            .split(',')
            .find(|n| {
                Regex::new(&format!(r"^ic0*{playnet_id}\..+\.dfinity\.network$"))
                    .unwrap()
                    .is_match(n)
            })
            .unwrap()
            .to_string();

        let priv_key_pem = String::from_utf8(
            playnet_secret
                .data
                .as_ref()
                .and_then(|d| d.clone().remove("tls.key"))
                .map(|d| d.0)
                .expect("missing tls.key"),
        )
        .expect("should be able to convert priv key pem");

        let cert_pem = String::from_utf8(
            playnet_secret
                .data
                .and_then(|d| d.clone().remove("tls.crt"))
                .map(|d| d.0)
                .expect("missing tls.crt"),
        )
        .expect("should be able to convert cert pem");

        Ok(PlaynetCertificate {
            playnet,
            cert: Certificate {
                priv_key_pem,
                chain_pem: cert_pem.clone(),
                cert_pem,
            },
        })
    }

    pub async fn create_playnet_dns_records(&self, dns_records: Vec<DnsRecord>) -> Result<String> {
        let client = Client::try_default().await?;
        let api_svc: Api<Service> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        for dns_record in dns_records {
            for record in dns_record.records {
                let mut svc: Service = serde_yaml::from_str(&format!(
                    r#"
kind: Service
apiVersion: v1
metadata:
  generateName: {generate_name_prefix}-
  annotations:
    external-dns.alpha.kubernetes.io/hostname: "{hostname}"
spec:
  type: ExternalName
  externalName: "{external_name}"
            "#,
                    generate_name_prefix = self.unique_name.clone().unwrap(),
                    hostname = dns_record.name,
                    external_name = record,
                ))?;
                if dns_record.record_type == DnsRecordType::AAAA {
                    if let Some(annotations) = svc.metadata.annotations.as_mut() {
                        annotations.insert(
                            "external-dns.alpha.kubernetes.io/target".to_string(),
                            record,
                        );
                    }
                    if let Some(spec) = svc.spec.as_mut() {
                        spec.external_name = "notimportant".to_string().into();
                    }
                }
                svc.metadata.owner_references = vec![self.owner_reference()].into();

                (|| async { api_svc.create(&PostParams::default(), &svc).await })
                    .retry(&ExponentialBuilder::default())
                    .await?;
            }
        }
        Ok("".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tnet_new() {
        let tnet = TNet::new("testnet").expect("should create a testnet");
        assert_eq!(tnet.group_name, "testnet");
        assert_eq!(tnet.version, "");
        assert_eq!(tnet.image_url, "");
        assert_eq!(tnet.config_url, None);
    }

    #[tokio::test]
    async fn test_tnet_version() {
        let tnet = TNet::new("testnet")
            .expect("should create a testnet")
            .version("1.0.0");
        assert_eq!(tnet.version, "1.0.0");
        assert_eq!(
            tnet.image_url,
            "https://download.dfinity.systems/ic/1.0.0/guest-os/disk-img-dev/disk-img.tar.zst"
        );
    }
}
