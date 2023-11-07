use std::collections::{BTreeMap, HashSet};
use std::env::var;
use std::net::Ipv6Addr;

use anyhow::{anyhow, Result};
use cidr::Ipv6Cidr;
use k8s_openapi::api::core::v1::{
    Namespace, PersistentVolumeClaim, Pod, TypedLocalObjectReference,
};
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
use crate::event::*;
use crate::namespace::*;
use crate::persistentvolumeclaim::*;
use crate::pod::*;
use crate::prep::*;
use crate::virtualmachine::*;

pub static TNET_IPV6: Lazy<String> =
    Lazy::new(|| var("TNET_IPV6").unwrap_or("fda6:8d22:43e1:fda6".to_string()));
static CDN_URL: Lazy<String> =
    Lazy::new(|| var("CDN_URL").unwrap_or("https://download.dfinity.systems".to_string()));
static CONFIG_URL: Lazy<String> = Lazy::new(|| {
    var("CONFIG_URL").unwrap_or("https://objects.sf1-idx1.dfinity.network".to_string())
});
static BUCKET: Lazy<String> = Lazy::new(|| {
    var("BUCKET").unwrap_or("tnet-config-5f1a0cb6-fdf2-4ca8-b816-9b9c2ffa1669".to_string())
});

pub struct K8sClient {
    pub(crate) client: Client,
    pub(crate) api_dv: Api<DynamicObject>,
    pub(crate) api_vm: Api<DynamicObject>,
    pub(crate) api_vmi: Api<DynamicObject>,
    pub(crate) api_pvc: Api<PersistentVolumeClaim>,
    pub(crate) api_pod: Api<Pod>,
}

impl K8sClient {
    pub async fn new(client: Client, namespace: &str) -> Result<Self> {
        let api_pod: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let api_pvc: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);

        let gvk = GroupVersionKind::gvk("cdi.kubevirt.io", "v1beta1", "DataVolume");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_dv = Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachine");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vm = Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &ar);

        let gvk = GroupVersionKind::gvk("kubevirt.io", "v1", "VirtualMachineInstance");
        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api_vmi = Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &ar);

        Ok(Self {
            client,
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
    pub(crate) name: Option<String>,
    pub(crate) ipv6_addr: Option<Ipv6Addr>,
    pub(crate) config_url: Option<String>,
}

#[derive(Default)]
pub struct TNet {
    name: String,
    version: String,
    use_zero_version: bool,
    pub(crate) image_url: String,
    ipv6_net: Option<Ipv6Cidr>,
    config_url: Option<String>,
    index: Option<u32>,
    pub(crate) namespace: Option<String>,
    nns_nodes: Vec<TNode>,
    app_nodes: Vec<TNode>,
    k8s: Option<K8sClient>,
}

impl TNet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub async fn delete(name: Option<String>, namespace: Option<String>) -> Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Namespace> = Api::all(client.clone());

        if let Some(name) = name {
            let labels = Some(BTreeMap::from([("tnet".to_string(), name.to_string())]));
            let namespaces = get_namespaces(&api, labels).await?;

            if namespaces.items.is_empty() {
                return Err(anyhow!("No testnet '{}' found!", name));
            } else if namespaces.items.len() > 1 {
                return Err(anyhow!("Multiple testnets '{}' found!", name));
            }

            let namespace = namespaces.items[0].name_any();
            delete_namespace(&api, &namespace).await?;
        } else if let Some(namespace) = namespace {
            delete_namespace(&api, &namespace).await?;
        } else {
            return Err(anyhow!("name or namespace expected!"));
        }

        Ok(())
    }

    pub async fn list() -> Result<Vec<(String, String)>> {
        let client = Client::try_default().await?;
        let api: Api<Namespace> = Api::all(client.clone());

        let labels = Some(BTreeMap::from([("app".to_string(), "tnet".to_string())]));
        Ok(get_namespaces(&api, labels)
            .await?
            .iter()
            .map(|ns| {
                (
                    ns.name_any(),
                    ns.metadata
                        .labels
                        .as_ref()
                        .unwrap()
                        .get("tnet")
                        .unwrap_or(&"-".to_string())
                        .into(),
                )
            })
            .collect::<Vec<(String, String)>>())
    }

    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self.image_url = format!(
            "{}/ic/{}/guest-os/disk-img-dev/disk-img.tar.gz",
            *CDN_URL, self.version
        );
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

    async fn upload_config(&self) -> Result<()> {
        let client = reqwest::Client::new();

        for (count, node) in self
            .nns_nodes
            .iter()
            .chain(self.app_nodes.iter())
            .enumerate()
        {
            info!(
                "Uploading bootstrap-{}.img to {}",
                count,
                node.config_url.clone().unwrap()
            );
            let file = tokio::fs::File::open(format!("out/bootstrap-{}.img", count)).await?;
            let res = client
                .put(node.config_url.clone().unwrap())
                .body({
                    let stream = FramedRead::new(file, BytesCodec::new());
                    Body::wrap_stream(stream)
                })
                .send()
                .await?;
            debug!("Upload's put response: {:?}", res);
            if res.status().as_u16() != 200 {
                return Err(anyhow!(
                    "Failed to upload bootstrap-{}.img to {}",
                    count,
                    node.config_url.clone().unwrap()
                ));
            }
        }

        let file = tokio::fs::File::open("out/init.tar").await?;
        let res = client
            .put(format!("{}/init.tar", self.config_url.clone().unwrap()))
            .body({
                let stream = FramedRead::new(file, BytesCodec::new());
                Body::wrap_stream(stream)
            })
            .send()
            .await?;
        debug!("Response: {:?}", res);
        if res.status().as_u16() != 200 {
            return Err(anyhow!(
                "Failed to upload init.tar to {}",
                self.config_url.clone().unwrap()
            ));
        }

        Ok(())
    }

    fn autoconfigure(&mut self, index: u32) -> &Self {
        self.index = Some(index);
        self.namespace = Some(format!("tnet-{}", index));
        self.config_url = Some(format!(
            "{}/{}/{}/tnet-{}",
            *CONFIG_URL, *BUCKET, self.version, index
        ));
        self.ipv6_net = Some(format!("{}:{:x}::/80", *TNET_IPV6, index).parse().unwrap());

        let mut count = 0;
        let mut iter = self.ipv6_net.unwrap().iter();
        iter.next(); // skip network address
        self.nns_nodes.iter_mut().for_each(|node| {
            node.name = Some(format!("nns-{}", count));
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
            node.name = Some(format!("app-{}", count));
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

    async fn allocate_namespace(&mut self) -> Result<String> {
        let client = Client::try_default().await?;
        let api_ns = Api::all(client.clone());

        debug!("Allocating namespace");
        // get indexes of used testnet namespaces
        let labels = Some(BTreeMap::from([("app".to_string(), "tnet".to_string())]));
        let used_ns_list = get_namespaces(&api_ns, labels).await?;
        let used_ns_idx_list = used_ns_list
            .items
            .iter()
            .map(|ns| {
                ns.labels()
                    .get("index")
                    .unwrap_or(&"0".to_string())
                    .parse::<u32>()
                    .unwrap()
            })
            .collect::<HashSet<u32>>();

        // choose a random unused index
        let ns_idx_list = (0..65536)
            .filter(|idx| !used_ns_idx_list.contains(idx))
            .collect::<Vec<u32>>();
        let mut rng = rand::thread_rng();
        let mut generate_random_index = || -> u32 {
            let ns_idx = ns_idx_list.choose(&mut rng).unwrap().to_owned();
            ns_idx
        };

        let mut ns_idx = 0;
        let mut ns_name = "".to_string();
        for _ in 0..10 {
            ns_idx = generate_random_index();
            ns_name = format!("tnet-{}", ns_idx);
            let labels = Some(BTreeMap::from([
                ("app".to_string(), "tnet".to_string()),
                ("tnet".to_string(), self.name.clone()),
                ("index".to_string(), ns_idx.to_string()),
            ]));
            if create_namespace(&api_ns, &ns_name, labels).await.is_ok() {
                break;
            }
        }

        self.autoconfigure(ns_idx);
        self.k8s = Some(K8sClient::new(client, &ns_name).await?);

        Ok(ns_name)
    }

    pub async fn create(&mut self) -> Result<&Self> {
        let ns_name = self.allocate_namespace().await?;
        let k8s_client = &self.k8s.as_ref().unwrap();

        // tnet guestos image
        let tnet_image = "tnet-image-guestos";
        let source = DvSource::url(self.image_url.clone());
        let dvinfo = DvInfo::new(tnet_image, source, "archive", "32Gi");
        info!("Creating DV {} from {}", tnet_image, self.image_url);
        create_datavolume(&k8s_client.api_dv, &dvinfo).await?;

        // generate and upload node config images
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
        let dvinfo = DvInfo::new("tnet-config-init", source, "archive", "128Mi");
        create_datavolume(&k8s_client.api_dv, &dvinfo).await?;

        // nns-config and app-config images
        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            let dvname = format!("{}-config", node.name.clone().unwrap());
            let source = DvSource::url(node.config_url.clone().unwrap());
            let dvinfo = DvInfo::new(&dvname, source, "kubevirt", "12Mi");
            create_datavolume(&k8s_client.api_dv, &dvinfo).await?;
        }

        wait_for_event(
            self.k8s.as_ref().unwrap().client.clone(),
            "Import Successful",
            "PersistentVolumeClaim",
            tnet_image,
            &ns_name,
            180,
        )
        .await
        .unwrap_or_else(|_| {
            error!(
                "Timeout waiting for import of PersistentVolumeClaim {}",
                tnet_image.to_string()
            );
            std::process::exit(124);
        });

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
            )
            .await?;
        }

        // create virtual machines
        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            create_vm(
                &self.k8s.as_ref().unwrap().api_vm,
                &node.name.clone().unwrap(),
                &node.ipv6_addr.unwrap().to_string(),
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
        create_pod(
            &k8s_client.api_pod,
            "tnet-operator",
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
            Some(("tnet-config-init", "/mnt")),
        )
        .await?;

        Ok(self)
    }

    pub async fn create_local(&mut self) -> Result<&Self> {
        self.allocate_namespace().await?;
        let k8s_client = &self.k8s.as_ref().unwrap();

        // generate and upload node config images
        generate_config(
            &self.version,
            self.use_zero_version,
            &self.nns_nodes,
            &self.app_nodes,
        )?;
        self.upload_config().await?;

        // create virtual machines
        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            prepare_host_vm(self.k8s.as_ref().unwrap(), node, self).await?;
        }

        for node in self.nns_nodes.iter().chain(self.app_nodes.iter()) {
            create_host_vm(self.k8s.as_ref().unwrap(), node, self).await?;
        }

        let config_url = format!("{}/init.tar", self.config_url.clone().unwrap());
        let nns_ips = self
            .nns_nodes
            .iter()
            .map(|node| node.ipv6_addr.unwrap().to_string())
            .collect::<Vec<String>>()
            .join(" ");

        // initialize nns
        // TODO: save init state somehere (host-based pvc)
        create_pod(
            &k8s_client.api_pod,
            "tnet-operator",
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
                    pushd /mnt
                    wget {}
                    tar -xf init.tar
                    popd
                    gunzip /mnt/*.gz /mnt/canisters/*.gz || true
                    chmod u+x /mnt/ic-nns-init

                    timeout 10m bash -c 'until parallel -u ping -c1 -W1 ::: {} >/dev/null;
                    do
                      echo Waiting for NNS nodes to come up...
                      sleep 5
                    done'

                    echo NNS nodes seem to be up...
                    sleep 30
                    echo Initiliazing NNS nodes...
                    /mnt/ic-nns-init --url 'http://[{}]:8080' \
                      --registry-local-store-dir /mnt/ic_registry_local_store \
                      --wasm-dir /mnt/canisters --http2-only 2>&1 | tee /mnt/ic-nns-init.log
                    touch /mnt/ic-nns-init.complete
                    "#,
                    config_url, nns_ips, self.nns_nodes[0].ipv6_addr.unwrap()
                ),
            ],
            vec![
                "/usr/bin/bash",
                "-c",
                "tail -f /dev/null",
            ],
            None,
        )
        .await?;

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tnet_new() {
        let tnet = TNet::new("testnet");
        assert_eq!(tnet.name, "testnet");
        assert_eq!(tnet.version, "");
        assert!(!tnet.use_zero_version);
        assert_eq!(tnet.image_url, "");
        assert_eq!(tnet.ipv6_net, None);
        assert_eq!(tnet.config_url, None);
        assert_eq!(tnet.index, None);
        assert_eq!(tnet.namespace, None);
    }

    #[tokio::test]
    async fn test_tnet_version() {
        let tnet = TNet::new("testnet").version("1.0.0");
        assert_eq!(tnet.version, "1.0.0");
        assert_eq!(
            tnet.image_url,
            "https://download.dfinity.systems/ic/1.0.0/guest-os/disk-img-dev/disk-img.tar.gz"
        );
    }

    #[tokio::test]
    async fn test_tnet_topology() {
        let tnet = TNet::new("testnet").topology(2, 3);
        assert_eq!(tnet.nns_nodes.len(), 2);
        assert_eq!(tnet.app_nodes.len(), 3);
    }

    #[tokio::test]
    async fn test_allocate_namespace() {
        // TODO:
    }
}
