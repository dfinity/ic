use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use ic_types::PrincipalId;
use serde::{Deserialize, Serialize};
use slog::{info, warn};

use crate::{
    driver::{
        log_events::LogEvent,
        prometheus_vm::{SCP_RETRY_BACKOFF, SCP_RETRY_TIMEOUT},
        test_env::TestEnvAttribute,
        test_env_api::{HasTopologySnapshot, IcNodeContainer, SshSession},
        test_setup::GroupSetup,
        universal_vm::UniversalVms,
    },
    retry_with_msg,
};

use super::{
    ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources},
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

const ELASTICSEARCH_URL: &str = "https://elasticsearch.testnet.dfinity.network";
const ELASTICSEARCH_INDEX: &str = "testnet-vector-push";

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
# Colleting all the logs for debugging
[sinks.local_file]
type = "file"
inputs = [ "*-transform" ]
path = "/etc/vector/config/debug.log"
     [sinks.local_file.encoding]
     codec = "json"

[transforms.to_json]
type = "remap"
inputs = [ "*-transform" ]
source = """
message_parsed = parse_json!(del(.message))

. = merge!(., message_parsed)

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

.timestamp = from_unix_timestamp!(to_int!(del(.__REALTIME_TIMESTAMP)) * 1000, unit: "nanoseconds")
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
            universal_vm: UniversalVm::new("vector".to_string())
                .with_config_img(
                    std::env::var("VECTOR_VM_PATH")
                        .expect("VECTOR_VM_PATH not set")
                        .into(),
                )
                .with_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(2)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(16780000)), // 16GiB
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(30)),
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

        self.universal_vm.start(env)?;

        info!(logger, "Spawned vector vm");
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

        let infra_group_name = GroupSetup::read_attribute(&env).infra_group_name;
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
                (IC, infra_group_name.clone()),
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

        let deployed_prometheus_vm = env
            .get_deployed_universal_vm(&self.universal_vm.name)
            .unwrap();
        let session = deployed_prometheus_vm
            .block_on_ssh_session()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to setup SSH session to {} because: {e:?}!",
                    self.universal_vm.name
                )
            });

        for file in vector_local_dir.read_dir().map_err(anyhow::Error::from)? {
            let file = match file {
                Ok(f) => f,
                Err(e) => {
                    warn!(log, "Failed to read an entry in vector local dir {:?}", e);
                    continue;
                }
            };

            let from = file.path();
            let to = Path::new("/etc/vector/config").join(file.path().file_name().unwrap());
            let size = std::fs::metadata(&from).unwrap().len();
            retry_with_msg!(
                format!("scp {from:?} to {}:{to:?}", self.universal_vm.name),
                env.logger(),
                SCP_RETRY_TIMEOUT,
                SCP_RETRY_BACKOFF,
                || {
                    let mut remote_file = session.scp_send(&to, 0o644, size, None)?;
                    let mut from_file = File::open(&from)?;
                    std::io::copy(&mut from_file, &mut remote_file)?;
                    Ok(())
                }
            )
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to scp {from:?} to {}:{to:?} because: {e:?}!",
                    self.universal_vm.name
                )
            });
        }

        touch_spawn_file(&session)?;

        emit_kibana_url_event(&log, &infra_group_name);

        info!(log, "Vector targets sync complete.");

        Ok(())
    }
}

fn touch_spawn_file(session: &ssh2::Session) -> anyhow::Result<()> {
    let mut channel = session.channel_session()?;
    channel.exec("touch /etc/vector/config/spawn_vector")?;
    channel.flush()?;
    channel.send_eof()?;
    let mut _stdout = Vec::new();
    channel.read_to_end(&mut _stdout)?;
    channel.wait_close()?;

    channel
        .exit_signal()
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

fn emit_kibana_url_event(log: &slog::Logger, network_name: &str) {
    #[derive(Serialize, Deserialize)]
    pub struct KibanaUrl {
        message: String,
        url: String,
    }

    let event = LogEvent::new(
        "kibana_url_created_new_event".to_string(),
        KibanaUrl {
            message: "Pulled replica logs will appear in Kibana".to_string(),
            url: format!("https://kibana.testnet.dfinity.network/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-5h,to:now%2B5h))&_a=(columns:!(MESSAGE,ic_subnet,ic_node),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,field:ic,index:testnet-vector-push,key:ic,negate:!f,params:(query:{network_name}),type:phrase),query:(match_phrase:(ic:{network_name})))),hideChart:!f,index:testnet-vector-push,interval:auto,query:(language:kuery,query:''),sort:!(!(timestamp,desc)))")
        }
    );

    event.emit_log(log);
}

#[derive(Serialize)]
struct VectorSource {
    #[serde(rename = "type")]
    _type: String,
    command: Vec<String>,
    mode: String,
    streaming: VectorStreaming,
    include_stderr: bool,
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
            include_stderr: false,
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
