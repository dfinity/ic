use std::{
    collections::BTreeMap,
    fs::File,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
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
const IS_MALICIOUS: &str = "is_malicious";
const IC: &str = "ic";

const ELASTICSEARCH_URL: &str = "https://elasticsearch.testnet.dfinity.network";
const ELASTICSEARCH_INDEX: &str = "testnet-vector-push";

const VECTOR_TOML: &[u8] = include_bytes!("../../assets/vector.toml");

fn get_vector_toml() -> String {
    String::from_utf8(VECTOR_TOML.to_vec()).unwrap()
}

pub struct VectorVm {
    universal_vm: UniversalVm,
    sources: BTreeMap<String, VectorSource>,
    transforms: BTreeMap<String, VectorTransform>,
    container_running: bool,
}

impl Default for VectorVm {
    fn default() -> Self {
        Self::new()
    }
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
            sources: BTreeMap::new(),
            transforms: BTreeMap::new(),
            container_running: false,
        }
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.universal_vm = self.universal_vm.with_vm_resources(vm_resources);
        self
    }

    pub fn with_required_host_features(mut self, required_host_features: Vec<HostFeature>) -> Self {
        self.universal_vm = self
            .universal_vm
            .with_required_host_features(required_host_features);
        self
    }

    pub fn start(&self, env: &TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();

        info!(logger, "Spawning vector vm for log fetching.");

        self.universal_vm.start(env)?;

        info!(logger, "Spawned vector vm");
        Ok(())
    }

    pub fn add_custom_target(
        &mut self,
        target_id: String,
        ip: IpAddr,
        labels: Option<BTreeMap<String, String>>,
    ) {
        let source = VectorSource::new(target_id.clone(), ip);
        let source_key = format!("{}-source", target_id);

        let mut extended_labels = labels.unwrap_or_default();
        extended_labels.extend([
            (IC_NODE.to_string(), target_id.clone()),
            (ADDRESS.to_string(), ip.to_string()),
        ]);

        let transform = VectorTransform::new(source_key.clone(), extended_labels);

        self.sources.insert(source_key, source);
        self.transforms
            .insert(format!("{}-transform", target_id), transform);
    }

    pub fn sync_targets(&mut self, env: &TestEnv) -> anyhow::Result<()> {
        let log = env.logger();
        info!(log, "Syncing vector targets.");
        let snapshot = env.topology_snapshot();

        let nodes = snapshot
            .subnets()
            .flat_map(|s| s.nodes())
            .chain(snapshot.unassigned_nodes())
            .chain(snapshot.api_boundary_nodes());

        for node in nodes {
            let node_id = node.node_id.get();
            let ip = node.get_ip_addr();

            let labels = [
                // We don't have host os in these tests so this is the only job.
                // It is here to keep consistency between mainnet and testnet logs.
                (JOB, "node_exporter".to_string()),
                (IS_API_BN, node.is_api_boundary_node().to_string()),
                (IS_MALICIOUS, node.is_malicious().to_string()),
            ]
            .into_iter()
            .chain(match node.subnet_id() {
                None => vec![],
                Some(s) => vec![(IC_SUBNET, s.get().to_string())],
            })
            .map(|(key, val)| (key.to_string(), val))
            .collect();

            self.add_custom_target(node_id.to_string(), ip, Some(labels));
        }

        // For all targets add an IC label
        let infra_group_name = GroupSetup::read_attribute(env).infra_group_name;
        for transform in self.transforms.values_mut() {
            transform
                .labels
                .insert(IC.to_string(), infra_group_name.clone());
        }

        let vector_local_dir = env.get_path("vector");
        info!(log, "Writing vector config to {vector_local_dir:?}");
        std::fs::create_dir_all(&vector_local_dir).map_err(anyhow::Error::from)?;

        std::fs::write(vector_local_dir.join("vector.toml"), get_vector_toml())
            .map_err(anyhow::Error::from)?;

        let mut generated_config = BTreeMap::new();
        generated_config.insert(
            "sources".to_string(),
            serde_json::to_value(&self.sources).unwrap(),
        );
        generated_config.insert(
            "transforms".to_string(),
            serde_json::to_value(&self.transforms).unwrap(),
        );

        std::fs::write(
            vector_local_dir.join("generated_config.json"),
            serde_json::to_string_pretty(&generated_config).unwrap(),
        )
        .map_err(anyhow::Error::from)?;

        let deployed_vm = env
            .get_deployed_universal_vm(&self.universal_vm.name)
            .unwrap();
        let session = deployed_vm.block_on_ssh_session().unwrap_or_else(|e| {
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

        if !self.container_running {
            info!(log, "Issuing command to run vector container.");
            deployed_vm
                .block_on_bash_script_from_session(
                    &session,
                    &format!(
                        r#"
docker run -d --name vector \
    -v /etc/vector/config:/etc/vector/config \
    --network host \
    --entrypoint vector \
    -e ELASTICSEARCH_URL="{ELASTICSEARCH_URL}" \
    -e ELASTICSEARCH_INDEX="{ELASTICSEARCH_INDEX}" \
    vector-with-log-fetcher:image \
    -w --config-dir /etc/vector/config
        "#,
                    ),
                )
                .expect("Failed to start docker container for vector");
            emit_kibana_url_event(&log, &infra_group_name);

            self.container_running = true;
        }

        info!(log, "Vector targets sync complete.");

        Ok(())
    }
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
    pub fn new(target_id: String, ip: IpAddr) -> Self {
        let socket = SocketAddr::new(ip, 19531);

        let command = [
            "/log-fetcher",
            "--url",
            &format!("http://{}/entries?follow", socket),
            "--name",
            &format!("{}-node_exporter", target_id),
            "--cursor-path",
            &format!("/data/{}-node_exporter/checkpoint.txt", target_id),
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

struct VectorTransform {
    _type: String,
    inputs: Vec<String>,
    labels: BTreeMap<String, String>,
}

impl VectorTransform {
    pub fn new(input_key: String, labels: BTreeMap<String, String>) -> Self {
        Self {
            _type: "remap".to_string(),
            inputs: vec![input_key],
            labels,
        }
    }

    fn calculate_source(&self) -> String {
        self.labels
            .iter()
            // Might be dangerous as the tag value is coming from an outside source and
            // is not escaped.
            .map(|(k, v)| format!(".{} = \"{}\"", k, v))
            .collect::<Vec<String>>()
            .join("\n")
    }
}

impl Serialize for VectorTransform {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("VectorTransform", 3)?;
        s.serialize_field("type", &self._type)?;
        s.serialize_field("inputs", &self.inputs)?;
        s.serialize_field("source", &self.calculate_source())?;
        s.end()
    }
}
