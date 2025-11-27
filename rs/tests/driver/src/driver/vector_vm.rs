use std::{
    collections::BTreeMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use slog::{Logger, debug, info, warn};

use crate::driver::{
    farm::HostFeature,
    log_events::LogEvent,
    nested::HasNestedVms,
    test_env::TestEnvAttribute,
    test_env_api::{HasTopologySnapshot, HasVmName, IcNodeContainer, SshSession, scp_send_to},
    test_setup::GroupSetup,
    universal_vm::UniversalVms,
};

use super::{
    ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources},
    test_env::TestEnv,
    test_env_api::get_dependency_path,
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
    container_running: bool,
    config_hash: u64,
    start_time: DateTime<Utc>,
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
                .with_config_img(get_dependency_path(
                    std::env::var("VECTOR_VM_PATH").expect("VECTOR_VM_PATH not set"),
                ))
                .with_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(2)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(16780000)), // 16GiB
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(30)),
                }),
            container_running: false,
            config_hash: 0,
            start_time: Utc::now(),
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

    pub fn with_start_time(mut self, time: DateTime<Utc>) -> Self {
        self.start_time = time;
        self
    }

    pub fn start(&self, env: &TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();

        info!(logger, "Spawning vector vm for log fetching.");

        self.universal_vm.start(env)?;

        info!(logger, "Spawned vector vm");
        Ok(())
    }

    fn hash_updated(&mut self, content: &str, logger: &Logger) -> bool {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);

        let new_hash = hasher.finish();

        if new_hash != self.config_hash {
            debug!(
                logger,
                "Vector targets hash changed from {} to {new_hash}", self.config_hash
            );

            self.config_hash = new_hash;
            return true;
        }

        false
    }

    pub fn sync_with_vector(&mut self, env: &TestEnv) -> anyhow::Result<()> {
        let mut sources = BTreeMap::new();
        let mut transforms = BTreeMap::new();

        let log = env.logger();
        info!(log, "Syncing vector targets.");

        match env.safe_topology_snapshot() {
            Err(e) => warn!(
                log,
                "Skipping adding IC nodes as vector targets for now because could not fetch topology snapshot because: {e:?}"
            ),
            Ok(snapshot) => {
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

                    add_vector_target(
                        &mut sources,
                        &mut transforms,
                        node_id.to_string(),
                        ip,
                        Some(labels),
                    );
                }
            }
        }

        for vm in env.get_all_nested_vms()? {
            let vm_name = vm.vm_name();
            let network = match vm.get_nested_network() {
                Ok(network) => network,
                Err(e) => {
                    warn!(
                        log,
                        "Skipping adding vector target for {vm_name} because: {e:?}"
                    );
                    continue;
                }
            };

            for (job, ip) in [
                ("node_exporter", network.guest_ip),
                ("host_node_exporter", network.host_ip),
            ] {
                add_vector_target(
                    &mut sources,
                    &mut transforms,
                    format!("{vm_name}-{job}"),
                    ip.into(),
                    Some(
                        [("job", job)]
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                    ),
                )
            }
        }

        // Extend with custom targets
        let custom_targets = env.get_custom_vector_targets();
        for (key, val) in custom_targets {
            add_vector_target(&mut sources, &mut transforms, key, val.ip, val.labels);
        }

        if sources.is_empty() && transforms.is_empty() {
            info!(
                log,
                "Still no targets found. Skipping running vector container."
            );
            return Ok(());
        }

        // For all targets add an IC label
        let infra_group_name = GroupSetup::read_attribute(env).infra_group_name;
        for transform in transforms.values_mut() {
            transform
                .labels
                .insert(IC.to_string(), infra_group_name.clone());
        }

        let vector_local_dir = env.get_path("vector").join("generated");
        info!(log, "Writing vector config to {vector_local_dir:?}");
        std::fs::create_dir_all(&vector_local_dir).map_err(anyhow::Error::from)?;

        let mut generated_config = BTreeMap::new();
        generated_config.insert(
            "sources".to_string(),
            serde_json::to_value(&sources).unwrap(),
        );
        generated_config.insert(
            "transforms".to_string(),
            serde_json::to_value(&transforms).unwrap(),
        );

        let generated_content = serde_json::to_string_pretty(&generated_config).unwrap();

        if !self.hash_updated(&generated_content, &log) {
            debug!(log, "Skipping updating vector targets.");
            return Ok(());
        }

        std::fs::write(
            vector_local_dir.join("generated_config.json"),
            &generated_content,
        )
        .map_err(anyhow::Error::from)?;

        std::fs::write(vector_local_dir.join("vector.toml"), get_vector_toml())
            .map_err(anyhow::Error::from)?;

        let deployed_vm = env.get_deployed_universal_vm("vector").unwrap();
        let session = deployed_vm
            .block_on_ssh_session()
            .unwrap_or_else(|e| panic!("Failed to setup SSH session to vector because: {e:?}!",));

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
            scp_send_to(env.logger(), &session, &from, &to, 0o644);
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
                .unwrap();
            self.container_running = true;

            emit_kibana_url_event(&log, &infra_group_name, &self.start_time);
        }

        info!(log, "Vector targets sync complete.");

        Ok(())
    }
}

fn emit_kibana_url_event(log: &slog::Logger, network_name: &str, start_time: &DateTime<Utc>) {
    #[derive(Serialize, Deserialize)]
    pub struct KibanaUrl {
        message: String,
        url: String,
    }

    let fmt = |dt: &DateTime<Utc>| dt.format("'%Y-%m-%dT%H:%M:%S%.3fZ'").to_string();

    let event = LogEvent::new(
        "kibana_url_created_event".to_string(),
        KibanaUrl {
            message: "Pulled replica logs will appear in Kibana".to_string(),
            url: format!(
                "https://kibana.testnet.dfinity.network/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:{},to:now))&_a=(columns:!(MESSAGE,ic_subnet,ic_node),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,field:ic,index:testnet-vector-push,key:ic,negate:!f,params:(query:{network_name}),type:phrase),query:(match_phrase:(ic:{network_name})))),hideChart:!f,index:testnet-vector-push,interval:auto,query:(language:kuery,query:''),sort:!(!(timestamp,desc)))",
                fmt(start_time)
            ),
        },
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
            &format!("http://{socket}/entries?follow"),
            "--name",
            &format!("{target_id}-node_exporter"),
            "--cursor-path",
            &format!("/data/{target_id}-node_exporter/checkpoint.txt"),
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
            .map(|(k, v)| format!(".{k} = \"{v}\""))
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

fn add_vector_target(
    sources: &mut BTreeMap<String, VectorSource>,
    transforms: &mut BTreeMap<String, VectorTransform>,
    target_id: String,
    ip: IpAddr,
    labels: Option<BTreeMap<String, String>>,
) {
    let source = VectorSource::new(target_id.clone(), ip);
    let source_key = format!("{target_id}-source");

    let mut extended_labels = labels.unwrap_or_default();
    extended_labels.extend([
        (IC_NODE.to_string(), target_id.clone()),
        (ADDRESS.to_string(), ip.to_string()),
    ]);

    let transform = VectorTransform::new(source_key.clone(), extended_labels);

    sources.insert(source_key, source);
    transforms.insert(format!("{target_id}-transform"), transform);
}

pub trait HasVectorTargets {
    // Adds a custom vector target for scraping logs.
    // The target has to have systemd-journal-gatewayd open on port 19531.
    fn add_custom_vector_target(
        &self,
        target_id: String,
        ip: IpAddr,
        labels: Option<BTreeMap<String, String>>,
    ) -> anyhow::Result<()>;
}

impl HasVectorTargets for TestEnv {
    fn add_custom_vector_target(
        &self,
        target_id: String,
        ip: IpAddr,
        labels: Option<BTreeMap<String, String>>,
    ) -> anyhow::Result<()> {
        let mut custom_targets = self.get_custom_vector_targets();

        custom_targets.insert(target_id, CustomTarget { ip, labels });

        custom_targets.write_attribute(self);
        Ok(())
    }
}

impl TestEnv {
    fn get_custom_vector_targets(&self) -> BTreeMap<String, CustomTarget> {
        // Get current targets, if any
        CustomVectorTargets::try_read_attribute(self).unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize)]
struct CustomTarget {
    ip: IpAddr,
    labels: Option<BTreeMap<String, String>>,
}

type CustomVectorTargets = BTreeMap<String, CustomTarget>;
impl TestEnvAttribute for CustomVectorTargets {
    fn attribute_name() -> String {
        "vector_custom_targets.json".to_string()
    }
}
