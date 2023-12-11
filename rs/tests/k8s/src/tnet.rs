use std::collections::BTreeMap;
use std::env::var;
use std::net::Ipv6Addr;
use std::path::Path;

use backon::ExponentialBuilder;
use backon::Retryable;

use anyhow::{anyhow, Result};
use cidr::Ipv6Cidr;
use k8s_openapi::api::core::v1::{
    ConfigMap, PersistentVolumeClaim, Pod, TypedLocalObjectReference,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use k8s_openapi::chrono::DateTime;
use k8s_openapi::chrono::Duration;
use k8s_openapi::chrono::Utc;
use kube::api::{ListParams, PostParams};
use kube::core::ObjectMeta;
use kube::Error;
use kube::ResourceExt;
use kube::{
    api::{Api, DynamicObject, GroupVersionKind},
    Client,
};
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use reqwest::Body;
use tokio;
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::*;

use crate::datavolume::*;
use crate::persistentvolumeclaim::*;
use crate::pod::*;
use crate::prep::*;
use crate::virtualmachine::*;

pub static TNET_IPV6: Lazy<String> =
    Lazy::new(|| var("TNET_IPV6").unwrap_or("fda6:8d22:43e1:fda6".to_string()));
static TNET_CDN_URL: Lazy<String> =
    Lazy::new(|| var("TNET_CDN_URL").unwrap_or("https://download.dfinity.systems".to_string()));
static TNET_CONFIG_URL: Lazy<String> = Lazy::new(|| {
    var("TNET_CONFIG_URL").unwrap_or("https://objects.sf1-idx1.dfinity.network".to_string())
});
static TNET_BUCKET: Lazy<String> = Lazy::new(|| {
    var("TNET_BUCKET").unwrap_or("tnet-config-5f1a0cb6-fdf2-4ca8-b816-9b9c2ffa1669".to_string())
});
static TNET_NAMESPACE: Lazy<String> =
    Lazy::new(|| var("TNET_NAMESPACE").unwrap_or("tnets".to_string()));

static TNET_STATIC_LABELS: Lazy<BTreeMap<String, String>> =
    Lazy::new(|| BTreeMap::from([("app".to_string(), "tnet".to_string())]));

static TNET_INDEX_LABEL: &str = "tnet.internetcomputer.org/index";
static TNET_NAME_LABEL: &str = "tnet.internetcomputer.org/name";
static TNET_TERMINATE_TIME_ANNOTATION: &str = "tnet.internetcomputer.org/terminate-time";

pub struct K8sClient {
    pub(crate) api_dv: Api<DynamicObject>,
    pub(crate) api_vm: Api<DynamicObject>,
    pub(crate) api_vmi: Api<DynamicObject>,
    pub(crate) api_pvc: Api<PersistentVolumeClaim>,
    pub(crate) api_pod: Api<Pod>,
}

impl K8sClient {
    pub async fn new(client: Client) -> Result<Self> {
        let api_pod: Api<Pod> = Api::namespaced(client.clone(), &TNET_NAMESPACE);
        let api_pvc: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &TNET_NAMESPACE);

        let gvk = GroupVersionKind::gvk("cdi.kubevirt.io", "v1beta1", "DataVolume");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_dv = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachine");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vm = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachineInstance");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vmi = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);

        Ok(Self {
            api_dv,
            api_vm,
            api_vmi,
            api_pvc,
            api_pod,
        })
    }
}

#[derive(Default, Clone, Debug)]
pub struct TNode {
    pub name: Option<String>,
    pub ipv6_addr: Option<Ipv6Addr>,
    pub config_url: Option<String>,
}

#[derive(Default)]
pub struct TNet {
    name: String,
    version: String,
    init: bool,
    use_zero_version: bool,
    pub(crate) image_url: String,
    ipv6_net: Option<Ipv6Cidr>,
    config_url: Option<String>,
    pub(crate) index: Option<u32>,
    pub nns_nodes: Vec<TNode>,
    pub app_nodes: Vec<TNode>,
    k8s: Option<K8sClient>,
    owner: ConfigMap,
    terminate_time: DateTime<Utc>,
}

impl TNet {
    pub fn new(name: &str) -> Result<Self> {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
        .ttl(Duration::days(1))
    }

    pub fn owner_config_map_name(idx: u32) -> String {
        format!("tnet-{}", idx)
    }

    pub fn owner_reference(&self) -> OwnerReference {
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

    fn get_tnet_index(cm: &ConfigMap) -> Result<u32> {
        Ok(cm
            .metadata
            .labels
            .as_ref()
            .unwrap()
            .get(TNET_INDEX_LABEL)
            .unwrap_or(&"-".to_string())
            .parse()?)
    }

    pub async fn delete(idx: u32) -> Result<()> {
        let client = Client::try_default().await?;
        let api: Api<ConfigMap> = Api::namespaced(client.clone(), &TNET_NAMESPACE);

        api.delete(&Self::owner_config_map_name(idx), &Default::default())
            .await?;
        Ok(())
    }

    pub async fn list() -> Result<Vec<(String, String)>> {
        let client = Client::try_default().await?;
        let api: Api<ConfigMap> = Api::namespaced(client.clone(), &TNET_NAMESPACE);

        let label_selector = TNET_STATIC_LABELS
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join(",");

        Ok(api
            .list(&ListParams::default().labels(&label_selector))
            .await?
            .iter()
            .map(|cm| {
                (
                    cm.name_any(),
                    cm.metadata.labels.as_ref().expect("should have labels")[TNET_NAME_LABEL]
                        .clone(),
                )
            })
            .collect::<Vec<(String, String)>>())
    }

    async fn vm_action(name: &str, action: &str) -> kube::Result<String> {
        let client = Client::try_default().await?;
        client
            .request_text(
                http::Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/apis/subresources.kubevirt.io/v1/namespaces/{}/virtualmachines/{}/{}",
                        *TNET_NAMESPACE, name, action,
                    ))
                    .body("{}".as_bytes().to_vec())
                    .unwrap(),
            )
            .await
            .or_else(|e| match e {
                Error::Api(error_response) if error_response.reason == "Conflict" => {
                    kube::Result::Ok(Default::default())
                }
                _ => kube::Result::Err(e),
            })
    }

    async fn vms_action(index: u32, action: &str) -> Result<()> {
        let tnet = Self::owner_config_map_name(index);
        let client = Client::try_default().await?;

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachine");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vm = Api::<DynamicObject>::namespaced_with(client.clone(), &TNET_NAMESPACE, &ar);
        let vms = api_vm
            .list(&ListParams {
                label_selector: format!("{}={}", TNET_NAME_LABEL, tnet).into(),
                ..Default::default()
            })
            .await?;

        futures::future::try_join_all(vms.into_iter().map(|vm| {
            let name = vm.name_any();
            async move { Self::vm_action(&name, action).await }
        }))
        .await?;

        Ok(())
    }

    pub async fn start(index: u32) -> Result<()> {
        Self::vms_action(index, "start").await
    }

    pub async fn stop(index: u32) -> Result<()> {
        Self::vms_action(index, "stop").await
    }

    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self.image_url = format!(
            "{}/ic/{}/guest-os/disk-img-dev/disk-img.tar.gz",
            *TNET_CDN_URL, self.version
        );
        self
    }

    pub fn image_url(mut self, url: &str) -> Self {
        self.image_url = url.to_string();
        self
    }

    pub fn init(mut self, init: bool) -> Self {
        self.init = init;

        self
    }

    pub fn use_zero_version(mut self, use_zero_version: bool) -> Self {
        self.use_zero_version = use_zero_version;

        self
    }

    pub fn topology(mut self, nns_count: usize, app_count: usize) -> Self {
        self.nns_nodes = vec![Default::default(); nns_count];
        self.app_nodes = vec![Default::default(); app_count];
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Result<Self> {
        self.terminate_time = k8s_openapi::chrono::Utc::now()
            .checked_add_signed(ttl)
            .ok_or(anyhow::anyhow!("failed to set terminate time"))?;
        Ok(self)
    }

    pub async fn upload<P: AsRef<Path> + std::fmt::Display + Clone>(
        path: P,
        uri: &str,
    ) -> Result<()> {
        Self::upload_url(
            path,
            &format!("{}/{}/{}", *TNET_CONFIG_URL, *TNET_BUCKET, uri),
        )
        .await
    }

    async fn upload_url<P: AsRef<Path> + std::fmt::Display + Clone>(
        path: P,
        url: &str,
    ) -> Result<()> {
        let client = reqwest::Client::new();

        info!("Uploading {} to {}", path.clone(), url);
        let file = tokio::fs::File::open(path.clone()).await?;
        let res = client
            .put(url)
            .body({
                let stream = FramedRead::new(file, BytesCodec::new());
                Body::wrap_stream(stream)
            })
            .send()
            .await?;
        debug!("Upload's put response: {:?}", res);
        if res.status().as_u16() != 200 {
            return Err(anyhow!("Failed to upload {} to {}", path.clone(), url));
        }

        Ok(())
    }

    async fn upload_config(&self) -> Result<()> {
        for (count, node) in self
            .nns_nodes
            .iter()
            .chain(self.app_nodes.iter())
            .enumerate()
        {
            Self::upload_url(
                format!("out/bootstrap-{}.img", count),
                &node.config_url.clone().unwrap(),
            )
            .await?;
        }
        Self::upload_url(
            "out/init.tar",
            &format!("{}/init.tar", self.config_url.clone().unwrap()),
        )
        .await?;

        Ok(())
    }

    fn autoconfigure(&mut self) -> &Self {
        let index = self.index.expect("should have an index");
        self.config_url = Some(format!(
            "{}/{}/{}/tnet-{}",
            *TNET_CONFIG_URL, *TNET_BUCKET, self.version, index
        ));
        self.ipv6_net = Some(format!("{}:{:x}::/80", *TNET_IPV6, index).parse().unwrap());

        let mut count = 0;
        let mut iter = self.ipv6_net.unwrap().iter();
        iter.next(); // skip network address
        self.nns_nodes.iter_mut().for_each(|node| {
            node.name = Some(format!("{}-nns-{}", self.owner.name_any(), count));
            node.config_url = Some(format!(
                "{}/{}.img",
                self.config_url.clone().unwrap(),
                node.name.clone().unwrap()
            ));
            node.ipv6_addr = Some(iter.next().unwrap().address());
            count += 1;
        });
        let mut count = 0;
        self.app_nodes.iter_mut().for_each(|node| {
            node.name = Some(format!("{}-app-{}", self.owner.name_any(), count));
            node.config_url = Some(format!(
                "{}/{}.img",
                self.config_url.clone().unwrap(),
                node.name.clone().unwrap()
            ));
            node.ipv6_addr = Some(iter.next().unwrap().address());
            count += 1;
        });

        debug!("Index: {}", index);
        debug!("NNS Nodes: {:?}", self.nns_nodes);
        debug!("APP Nodes: {:?}", self.app_nodes);

        self
    }

    async fn tnet_owner(&mut self) -> Result<()> {
        let client = Client::try_default().await?;
        let config_map_api = Api::<ConfigMap>::namespaced(client.clone(), &TNET_NAMESPACE);

        debug!("Allocating namespace");
        let config_map = (|| async {
            let tnet_name = self.name.clone();
            let mut rng = rand::thread_rng();

            let tnet_idx = (0..65536)
                .collect::<Vec<u32>>()
                .choose(&mut rng)
                .unwrap()
                .to_owned();
            config_map_api
                .create(
                    &PostParams::default(),
                    &ConfigMap {
                        metadata: ObjectMeta {
                            name: format!("tnet-{}", tnet_idx).into(),
                            labels: [
                                (TNET_NAME_LABEL.to_string(), tnet_name),
                                (TNET_INDEX_LABEL.to_string(), tnet_idx.to_string()),
                            ]
                            .into_iter()
                            .chain(TNET_STATIC_LABELS.clone().into_iter())
                            .collect::<BTreeMap<String, String>>()
                            .into(),
                            annotations: [(
                                TNET_TERMINATE_TIME_ANNOTATION.to_string(),
                                self.terminate_time.to_rfc3339_opts(
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

        self.k8s = Some(K8sClient::new(client.clone()).await?);
        self.index = Self::get_tnet_index(&config_map)?.into();
        self.owner = config_map;
        self.autoconfigure();

        Ok(())
    }

    pub async fn create(&mut self) -> Result<&Self> {
        self.tnet_owner().await?;
        let k8s_client = &self.k8s.as_ref().unwrap();

        // tnet guestos image
        let tnet_image = &format!("{}-image-guestos", self.owner.name_any());
        let source = DvSource::url(self.image_url.clone());
        let dvinfo = DvInfo::new(tnet_image, source, "archive", "32Gi");
        info!("Creating DV {} from {}", tnet_image, self.image_url);
        create_datavolume(&k8s_client.api_dv, &dvinfo, self.owner_reference()).await?;

        // generate and upload node config images
        let dv_info_name = format!("{}-config-init", self.owner.name_any());
        if self.init {
            generate_config(
                &self.version,
                self.use_zero_version,
                &self.nns_nodes,
                &self.app_nodes,
            )?;
            self.upload_config().await?;

            // tnet-config-init for nns init
            let config_url = format!("{}/init.tar", self.config_url.clone().unwrap());
            let source = DvSource::url(config_url);
            let dvinfo = DvInfo::new(&dv_info_name, source, "archive", "128Mi");
            create_datavolume(&k8s_client.api_dv, &dvinfo, self.owner_reference()).await?;

            // nns-config and app-config images
            for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
                let dvname = format!("{}-config", node.name.clone().unwrap());
                let source = DvSource::url(node.config_url.clone().unwrap());
                let dvinfo = DvInfo::new(&dvname, source, "kubevirt", "12Mi");
                create_datavolume(&k8s_client.api_dv, &dvinfo, self.owner_reference()).await?;
            }
        }

        tokio::time::timeout(tokio::time::Duration::from_secs(100), async {
            while (|| async {
                self.k8s
                    .as_ref()
                    .unwrap()
                    .api_dv
                    .get(tnet_image)
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

        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            let pvc_name = format!("{}-guestos", node.name.clone().unwrap());
            let data_source = Some(TypedLocalObjectReference {
                api_group: None,
                kind: "PersistentVolumeClaim".to_string(),
                name: tnet_image.to_string(),
            });
            create_pvc(
                &k8s_client.api_pvc,
                &pvc_name,
                "32Gi",
                None,
                None,
                data_source,
                self.owner_reference(),
            )
            .await?;
        }

        // create virtual machines
        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            create_vm(
                &self.k8s.as_ref().unwrap().api_vm,
                &node.name.clone().unwrap(),
                &node.ipv6_addr.unwrap().to_string(),
                self.init,
                self.owner_reference(),
            )
            .await?;
        }

        let nns_ips = self
            .nns_nodes
            .iter()
            .map(|node| node.ipv6_addr.unwrap().to_string())
            .collect::<Vec<String>>()
            .join(" ");

        // initialize nns
        if self.init {
            create_pod(
                &k8s_client.api_pod,
                &format!("{}-operator", self.owner.name_any()),
                "ubuntu:20.04",
                vec![
                    "/usr/bin/bash",
                    "-c",
                    &format!(
                        r#"
                        set -eEuo pipefail

                        if [ -e /mnt/ic-nns-init.complete ]; then
                          echo NNS already initialized, nothing to do
                          exit 0
                        fi

                        apt update && apt install -y parallel wget iputils-ping libssl1.1="1.1.1f-1ubuntu2"
                        gunzip /mnt/*.gz /mnt/canisters/*.gz || true
                        chmod u+x /mnt/ic-nns-init

                        timeout 10m bash -c 'until parallel -u ping -c1 -W1 ::: {} >/dev/null;
                        do
                          echo Waiting for NNS nodes to come up...
                          sleep 5
                        done'

                        echo NNS nodes seem to be up...
                        echo Giving them 2 minutes to settle...
                        sleep 120
                        echo Initiliazing NNS nodes...
                        /mnt/ic-nns-init --url 'http://[{}]:8080' \
                          --registry-local-store-dir /mnt/ic_registry_local_store \
                          --wasm-dir /mnt/canisters --http2-only 2>&1 | tee /mnt/ic-nns-init.log
                        touch /mnt/ic-nns-init.complete
                        "#,
                        nns_ips, self.nns_nodes[0].ipv6_addr.unwrap()
                    ),
                ],
                vec![
                    "/usr/bin/bash",
                    "-c",
                    "tail -f /dev/null",
                ],
                Some((&dv_info_name, "/mnt")),
                self.owner_reference(),
            )
            .await?;
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tnet_new() {
        let tnet = TNet::new("testnet").expect("should create a testnet");
        assert_eq!(tnet.name, "testnet");
        assert_eq!(tnet.version, "");
        assert!(!tnet.use_zero_version);
        assert_eq!(tnet.image_url, "");
        assert_eq!(tnet.ipv6_net, None);
        assert_eq!(tnet.config_url, None);
        assert_eq!(tnet.index, None);
    }

    #[tokio::test]
    async fn test_tnet_version() {
        let tnet = TNet::new("testnet")
            .expect("should create a testnet")
            .version("1.0.0");
        assert_eq!(tnet.version, "1.0.0");
        assert_eq!(
            tnet.image_url,
            "https://download.dfinity.systems/ic/1.0.0/guest-os/disk-img-dev/disk-img.tar.gz"
        );
    }

    #[tokio::test]
    async fn test_tnet_topology() {
        let tnet = TNet::new("testnet")
            .expect("should create a testnet")
            .topology(2, 3);
        assert_eq!(tnet.nns_nodes.len(), 2);
        assert_eq!(tnet.app_nodes.len(), 3);
    }

    #[tokio::test]
    async fn test_tnet_owner() {
        // TODO:
    }
}
