use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use ic_types::PrincipalId;
use serde::Serialize;
use slog::info;
use url::Url;

use crate::driver::test_env_api::{HasIcName, HasTopologySnapshot, IcNodeContainer};

use super::{
    ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources},
    resource::{DiskImage, ImageType},
    test_env::TestEnv,
    universal_vm::UniversalVm,
};

// Default labels
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
const ADDRESS: &str = "address";
const JOB: &str = "job";
const IS_API_BN: &str = "is_api_bn";
const IS_MALICIOUS: &str = "is_mallicious";
const IC: &str = "ic";

const DEFAULT_VECTOR_VM_IMG_SHA256: &str =
    "3af874174d48f5c9a59c9bc54dd73cbfc65b17b952fbacd7611ee07d19de369b";

const ELASTICSEARCH_URL: &str = "https://elasticsearch.testnet.dfinity.network";
const ELASTICSEARCH_INDEX: &str = "testnet-vector-push";
fn get_default_vector_vm_img_url() -> Url {
    format!("http://download.proxy-global.dfinity.network:8080/farm/vector-vm/{DEFAULT_VECTOR_VM_IMG_SHA256}/x86_64-linux/vector-vm.img.zst").parse().unwrap()
}

fn get_sinks_toml() -> String {
    format!(
        r#"
[sinks.elastic]
type = "elasticsearch"
inputs = ["to_json"]
endpoints = ["{ELASTICSEARCH_URL}"]
mode = "bulk"
compression = "gzip"
id_key = "__CURSOR"

  [sinks.elastic.bulk]
  index = "{ELASTICSEARCH_INDEX}-%Y-%m-%d"

  [sinks.elastic.buffer]
  type = "disk"
  max_size = 268435488 # 256 MB least we can have
  when_full = "block"
    
"#
    )
}

fn get_general_transforms_toml() -> String {
    format!(
        r#"
[transforms.to_json]
type = "remap"
inputs = [ "*-transforms" ]
source = """
message_parsed = parse_json!(del(.message))

. = merge(., message_parsed )

if .MESSAGE == null {{
  .MESSAGE = ""
}}

if is_json(string!(.MESSAGE)) {{
  parsed_message = parse_json!(string!(del(.MESSAGE)))
  v = get!(parsed_message, ["log_entry"])
  if v != null {{
    .MESSAGE = v.message
    .PRIORITY = v.level
    .utc_time = v.utc_time
    .crate_ = v.crate_
    .module = v.module
  }}
}}

.timestamp = from_unix_timestamp!(to_int(del(.__REALTIME_TIMESTAMP)) * 1000, unit: "nanoseconds")
"""
"#
    )
}

pub struct VectorVm {
    universal_vm: UniversalVm,
}

impl VectorVm {
    pub fn new() -> Self {
        Self {
            universal_vm: UniversalVm::new("VectorVm".to_string())
                .with_primary_image(DiskImage {
                    image_type: ImageType::VectorImage,
                    url: get_default_vector_vm_img_url(),
                    sha256: DEFAULT_VECTOR_VM_IMG_SHA256.to_string(),
                })
                .with_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(2)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(16780000)), // 16GiB
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(1)), // Logs are pushed to elastic
                }),
        }
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.universal_vm = self.universal_vm.with_vm_resources(vm_resources);
        self
    }

    pub fn start(&self, env: &TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();

        info!(logger, "Spawning vector vm for log fetching.");

        // self.universal_vm.clone().start(env)?;

        info!(logger, "Spawned vector vm.");
        Ok(())
    }

    pub fn sync_targets(&self, env: &TestEnv) -> anyhow::Result<()> {
        let log = env.logger();
        info!(log, "Syncing vector targets.");
        let snapshot = env.topology_snapshot();

        let mut sources = BTreeMap::new();
        let mut transforms = BTreeMap::new();

        let nodes = snapshot
            .subnets()
            .map(|s| s.nodes())
            .flatten()
            .chain(snapshot.unassigned_nodes())
            .chain(snapshot.api_boundary_nodes());

        for node in nodes {
            let node_id = node.node_id.get();
            let ip = node.get_ip_addr();

            let source = VectorSource::new(node_id, ip);
            let source_key = format!("{}-source", node_id);

            let labels = [
                (IC_NODE, node_id.to_string()),
                (ADDRESS, ip.to_string()),
                // We don't have host os in these tests so this is the only job.
                // It is here to keep consistency between mainnet and testnet logs.
                (JOB, "node_exporter".to_string()),
                (IS_API_BN, node.is_api_boundary_node().to_string()),
                (IS_MALICIOUS, node.is_malicious().to_string()),
                (IC, snapshot.ic_name()),
            ]
            .into_iter()
            .chain(match node.subnet_id() {
                None => vec![],
                Some(s) => vec![(IC_SUBNET, s.get().to_string())],
            })
            .map(|(key, val)| (key.to_string(), val))
            .collect();

            let transform = VectorTransform::new(source_key.clone(), labels);
            let transform_key = format!("{}-transform", node_id);

            sources.insert(source_key, source);
            transforms.insert(transform_key, transform);
        }

        let vector_local_dir = env.get_path("vector");
        info!(log, "Writing vector config to {vector_local_dir:?}");
        std::fs::create_dir_all(&vector_local_dir).map_err(anyhow::Error::from)?;

        std::fs::write(
            vector_local_dir.join("general_transforms.toml"),
            get_general_transforms_toml(),
        )
        .map_err(anyhow::Error::from)?;
        std::fs::write(vector_local_dir.join("sinks.toml"), get_sinks_toml())
            .map_err(anyhow::Error::from)?;

        let mut generated_config = BTreeMap::new();
        generated_config.insert(
            "sources".to_string(),
            serde_json::to_value(&sources).unwrap(),
        );
        generated_config.insert(
            "transforms".to_string(),
            serde_json::to_value(&transforms).unwrap(),
        );

        std::fs::write(
            vector_local_dir.join("generated_config.json"),
            serde_json::to_string_pretty(&generated_config).unwrap(),
        )
        .map_err(anyhow::Error::from)?;

        Ok(())
    }
}

#[derive(Serialize)]
struct VectorSource {
    #[serde(rename = "type")]
    _type: String,
    command: Vec<String>,
    mode: String,
    streaming: VectorStreaming,
}

impl VectorSource {
    pub fn new(node_id: PrincipalId, ip: IpAddr) -> Self {
        let socket = SocketAddr::new(ip, 19531);

        let command = vec![
            "/log-fetcher",
            "--url",
            &format!("http://{}/entries?follow", socket),
            "--name",
            &format!("{}-node_exporter", node_id),
            "--cursor-path",
            &format!("/data/{}-node_exporter/checkpoint.txt", node_id),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            _type: "exec".to_string(),
            command,
            mode: "streaming".to_string(),
            streaming: VectorStreaming {
                respawn_on_exit: true,
            },
        }
    }
}

#[derive(Serialize)]
struct VectorStreaming {
    respawn_on_exit: bool,
}

#[derive(Serialize)]
struct VectorTransform {
    #[serde(rename = "type")]
    _type: String,
    inputs: Vec<String>,
    source: String,
}

impl VectorTransform {
    pub fn new(input_key: String, labels: BTreeMap<String, String>) -> Self {
        Self {
            _type: "remap".to_string(),
            inputs: vec![input_key],
            source: labels
                .into_iter()
                // Might be dangerous as the tag value is coming from an outside source and
                // is not escaped.
                .map(|(k, v)| format!(".{} = \"{}\"", k, v))
                .collect::<Vec<String>>()
                .join("\n"),
        }
    }
}
