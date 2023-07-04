use std::{
    collections::HashMap,
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use slog::{debug, info};

use crate::driver::{
    constants::SSH_USERNAME,
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmAllocationStrategy, VmResources},
    log_events,
    resource::{DiskImage, ImageType},
    test_env::TestEnv,
    test_env_api::{
        retry, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SshSession, TopologySnapshot,
    },
    test_setup::GroupSetup,
    universal_vm::{UniversalVm, UniversalVms},
};
use crate::driver::{
    farm::{DnsRecord, DnsRecordType},
    test_env::TestEnvAttribute,
    test_env_api::{CreateDnsRecords, HasDependencies},
};

const PROMETHEUS_VM_NAME: &str = "prometheus";

/// The SHA-256 hash of the Prometheus VM disk image.
/// The latest hash can be retrieved by downloading the SHA256SUMS file from:
/// https://hydra.dfinity.systems/job/dfinity-ci-build/farm/universal-vm.img-prometheus.x86_64-linux/latest
///
/// Please also keep this in sync with the PROMETHEUS_VM_DISK_IMG_SHA256 variable in:
/// /scalability/common/farm.py.
const DEFAULT_PROMETHEUS_VM_IMG_SHA256: &str =
    "d5f181da1f8a426f60f4f7d0dcea27b9f017c8bc4001733d0c7c009a7caa4011";

fn get_default_prometheus_vm_img_url() -> String {
    format!("http://download.proxy-global.dfinity.network:8080/farm/prometheus-vm/{DEFAULT_PROMETHEUS_VM_IMG_SHA256}/x86_64-linux/prometheus-vm.img.zst")
}

const PROMETHEUS_DATA_DIR_TARBALL: &str = "prometheus-data-dir.tar.zst";

const PROMETHEUS_CONFIG_DIR_NAME: &str = "prometheus";

const PROMETHEUS_SCRAPING_TARGETS_DIR: &str = "/etc/prometheus";

const REPLICA_METRICS_PORT: u16 = 9090;
const ORCHESTRATOR_METRICS_PORT: u16 = 9091;
const NODE_EXPORTER_METRICS_PORT: u16 = 9100;

const PROMETHEUS_DOMAIN_NAME: &str = "prometheus";
const GRAFANA_DOMAIN_NAME: &str = "grafana";

pub const SCP_RETRY_TIMEOUT: Duration = Duration::from_secs(60);
pub const SCP_RETRY_BACKOFF: Duration = Duration::from_secs(5);
// Be mindful when modifying this constant, as the event can be consumed by other parties.
const PROMETHEUS_VM_CREATED_EVENT_NAME: &str = "prometheus_vm_created_event";
const GRAFANA_INSTANCE_CREATED_EVENT_NAME: &str = "grafana_instance_created_event";
const IC_PROGRESS_CLOCK_CREATED_EVENT_NAME: &str = "ic_progress_clock_created_event";

pub struct PrometheusVm {
    universal_vm: UniversalVm,
    scrape_interval: Duration,
}

impl Default for PrometheusVm {
    fn default() -> Self {
        PrometheusVm::new(PROMETHEUS_VM_NAME.to_string())
    }
}

impl PrometheusVm {
    pub fn new(name: String) -> Self {
        PrometheusVm {
            universal_vm: UniversalVm::new(name)
                .with_primary_image(DiskImage {
                    image_type: ImageType::RawImage,
                    url: Url::parse(&get_default_prometheus_vm_img_url())
                        .expect("should not fail!"),
                    sha256: String::from(DEFAULT_PROMETHEUS_VM_IMG_SHA256),
                })
                .with_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(2)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(16780000)), // 16GiB
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(100)),
                }),
            scrape_interval: Duration::from_secs(10),
        }
    }

    pub fn with_scrape_interval(mut self, scrape_interval: Duration) -> Self {
        self.scrape_interval = scrape_interval;
        self
    }

    pub fn with_vm_resources(mut self, vm_resources: VmResources) -> Self {
        self.universal_vm = self.universal_vm.with_vm_resources(vm_resources);
        self
    }

    pub fn with_vm_allocation(mut self, vm_allocation: VmAllocationStrategy) -> Self {
        self.universal_vm = self.universal_vm.with_vm_allocation(vm_allocation);
        self
    }

    pub fn with_required_host_features(mut self, required_host_features: Vec<HostFeature>) -> Self {
        self.universal_vm = self
            .universal_vm
            .with_required_host_features(required_host_features);
        self
    }

    pub fn enable_ipv4(mut self) -> Self {
        self.universal_vm.has_ipv4 = true;
        self
    }

    pub fn start(&self, env: &TestEnv) -> Result<()> {
        // Create a config directory containing the prometheus.yml configuration file.
        let vm_name = String::from(PROMETHEUS_VM_NAME);
        let log = env.logger();
        let config_dir = env
            .single_activate_script_config_dir(
                &vm_name,
                &format!(
                    r#"#!/bin/sh
mkdir -p -m 755 {PROMETHEUS_SCRAPING_TARGETS_DIR}
for name in replica orchestrator node_exporter; do
  echo '[]' > "{PROMETHEUS_SCRAPING_TARGETS_DIR}/$name.json"
done
chown -R {SSH_USERNAME}:users {PROMETHEUS_SCRAPING_TARGETS_DIR}
"#
                ),
            )
            .unwrap();
        let grafana_dashboards_src = env.get_dependency_path("rs/tests/dashboards");
        let grafana_dashboards_dst = config_dir.join("grafana").join("dashboards");
        debug!(log, "Copying Grafana dashboards from {grafana_dashboards_src:?} to {grafana_dashboards_dst:?} ...");
        TestEnv::shell_copy_with_deref(grafana_dashboards_src, grafana_dashboards_dst).unwrap();
        write_prometheus_config_dir(config_dir.clone(), self.scrape_interval).unwrap();

        self.universal_vm
            .clone()
            .with_config_dir(config_dir)
            .start(env)?;

        // Log the Prometheus URL so users can browse to it while the test is running.
        let deployed_prometheus_vm = env.get_deployed_universal_vm(&vm_name).unwrap();
        let prometheus_vm = deployed_prometheus_vm.get_vm().unwrap();
        let ipv6 = prometheus_vm.ipv6.to_string();
        let suffix = env.create_dns_records(vec![
            DnsRecord {
                name: PROMETHEUS_DOMAIN_NAME.to_string(),
                record_type: DnsRecordType::AAAA,
                records: vec![ipv6.clone()],
            },
            DnsRecord {
                name: GRAFANA_DOMAIN_NAME.to_string(),
                record_type: DnsRecordType::AAAA,
                records: vec![ipv6],
            },
        ]);
        let prometheus_fqdn = format!("{PROMETHEUS_DOMAIN_NAME}.{suffix}");
        let grafana_fqdn = format!("{GRAFANA_DOMAIN_NAME}.{suffix}");
        let prometheus_message = format!("Prometheus Web UI at http://{prometheus_fqdn}");
        let grafana_message = format!("Grafana at http://{grafana_fqdn}");
        let ic_progress_clock_message = format!(
            "IC Progress Clock at http://{grafana_fqdn}/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now"
        );
        emit_event(&log, &prometheus_message, PROMETHEUS_VM_CREATED_EVENT_NAME);
        emit_event(&log, &grafana_message, GRAFANA_INSTANCE_CREATED_EVENT_NAME);
        emit_event(
            &log,
            &ic_progress_clock_message,
            IC_PROGRESS_CLOCK_CREATED_EVENT_NAME,
        );
        Ok(())
    }
}

/// The Prometheus trait allows starting a Prometheus VM,
/// configuring its scraping targets based on the latest IC topology
/// and finally downloading its data directory.
pub trait HasPrometheus {
    /// Retrieves a topology snapshot, converts it into p8s scraping target
    /// JSON files and scps them to the prometheus VM.
    fn sync_prometheus_config_with_topology(&self);

    /// Downloads prometheus' data directory to the test artifacts
    /// such that we can run a local p8s on that later.
    ///
    /// Return early if no prometheus_vm has been setup.
    /// This allows this function to be used in a finalizer where no prometheus
    /// server has been setup.
    fn download_prometheus_data_dir_if_exists(&self);
}

impl HasPrometheus for TestEnv {
    fn sync_prometheus_config_with_topology(&self) {
        let vm_name = PROMETHEUS_VM_NAME.to_string();
        // Write the scraping target JSON files to the local prometheus config directory.
        let topology_snapshot = self.topology_snapshot();
        let prometheus_config_dir = self.get_universal_vm_config_dir(&vm_name);
        let group_setup = GroupSetup::read_attribute(self);
        sync_prometheus_config_dir(
            prometheus_config_dir.clone(),
            group_setup.farm_group_name,
            topology_snapshot,
        )
        .expect("Failed to synchronise prometheus config with the latest IC topology!");

        // Setup an SSH session to the prometheus VM which we'll use to scp the JSON files.
        let deployed_prometheus_vm = self.get_deployed_universal_vm(&vm_name).unwrap();
        let session = deployed_prometheus_vm
            .block_on_ssh_session()
            .unwrap_or_else(|e| panic!("Failed to setup SSH session to {vm_name} because: {e:?}!"));

        // scp the scraping target JSON files to prometheus VM.
        for name in &["replica", "orchestrator", "node_exporter"] {
            let from_pathbuf = prometheus_config_dir.join(name).with_extension("json");
            let from = from_pathbuf.as_path();
            let to = &Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR)
                .join(name)
                .with_extension("json");
            let size = fs::metadata(from).unwrap().len();

            retry(self.logger(), SCP_RETRY_TIMEOUT, SCP_RETRY_BACKOFF, || {
                let mut remote_file = session.scp_send(to, 0o644, size, None)?;
                let mut from_file = File::open(from)?;
                std::io::copy(&mut from_file, &mut remote_file)?;
                Ok(())
            })
            .unwrap_or_else(|e| {
                panic!("Failed to scp {from:?} to {vm_name}:{to:?} because: {e:?}!")
            });
        }
    }

    fn download_prometheus_data_dir_if_exists(&self) {
        // Return early without failing if no prometheus VM has been deployed.
        // This allows this function to be called unconditionally when finalizing.
        let vm_name = String::from(PROMETHEUS_VM_NAME);
        let deployed_prometheus_vm = match self.get_deployed_universal_vm(&vm_name) {
            Err(_) => return,
            Ok(deployed_prometheus_vm) => deployed_prometheus_vm,
        };

        // Log what we're about to do.
        let log = self.logger();
        let tarball = PathBuf::from(PROMETHEUS_DATA_DIR_TARBALL);
        let prometheus_vm_dir = self.get_deployed_universal_vm_dir(&vm_name);
        let destination = prometheus_vm_dir.join(tarball.clone());
        info!(
            log,
            "Downloading prometheus data directory to {destination:?} ..."
        );

        // First create a tarball of the p8s data directory.
        let tarball_full_path = PathBuf::from("/home").join(SSH_USERNAME).join(tarball);
        // Note that p8s is configured with --enable-feature=memory-snapshot-on-shutdown.
        // This causes p8s to snapshot its memory to its data directory on shutdown.
        // This means we can remove most of the contents of the wal directory
        // from the tarball saving significant space.
        let create_tarball_script = &format!(
            r#"
set -e
sudo systemctl stop prometheus.service
sudo tar -cf "{tarball_full_path:?}" \
    --sparse \
    --use-compress-program="zstd --threads=0 -10" \
    -C /var/lib/prometheus .
    "#,
        );
        let session = deployed_prometheus_vm
            .block_on_ssh_session()
            .expect("Failed to setup SSH session to {vm_name}");
        deployed_prometheus_vm
            .block_on_bash_script_from_session(&session, create_tarball_script)
            .expect("Failed to create tarball of prometheus data directory");

        // scp the tarball to the local test environment.
        let (mut remote_tarball, _) = session
            .scp_recv(&tarball_full_path)
            .expect("Failed to scp the tarball of the prometheus data directory {vm_name}:{tarball_full_path:?}");
        let mut destination_file = File::create(&destination).unwrap_or_else(|e| {
            panic!("Failed to open destination {destination:?} because: {e:?}")
        });
        std::io::copy(&mut remote_tarball, &mut destination_file).expect(
            "Failed to write the tarball of prometheus data directory {vm_name}:{tarball_full_path:?} to {destination:?}",
        );
    }
}

#[derive(Serialize)]
struct PrometheusStaticConfig {
    targets: Vec<String>,
    labels: HashMap<String, String>,
}

fn write_prometheus_config_dir(config_dir: PathBuf, scrape_interval: Duration) -> Result<()> {
    let prometheus_config_dir = config_dir.join(PROMETHEUS_CONFIG_DIR_NAME);
    fs::create_dir_all(prometheus_config_dir.clone())?;

    let replica_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join("replica.json");
    let orchestrator_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join("orchestrator.json");
    let node_exporter_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join("node_exporter.json");
    let scrape_interval_str: String = format!("{}s", scrape_interval.as_secs());
    let prometheus_config = json!({
        "global": {"scrape_interval": scrape_interval_str},
        "scrape_configs": [
            {"job_name": "replica", "file_sd_configs": [{"files": [replica_scraping_targets_path]}]},
            {"job_name": "orchestrator", "file_sd_configs": [{"files": [orchestrator_scraping_targets_path]}]},
            {
                "job_name": "node_exporter",
                "file_sd_configs": [{"files": [node_exporter_scraping_targets_path]}],
                "scheme": "https",
                "tls_config": {"insecure_skip_verify": true},
            },
        ],
    });
    let prometheus_config_path = prometheus_config_dir.join("prometheus.yml");
    let prometheus_config_file = File::create(prometheus_config_path)?;
    serde_json::to_writer(prometheus_config_file, &prometheus_config)?;
    Ok(())
}

fn sync_prometheus_config_dir(
    prometheus_config_dir: PathBuf,
    group_name: String,
    topology_snapshot: TopologySnapshot,
) -> Result<()> {
    let mut replica_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
    let mut orchestrator_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
    let mut node_exporter_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
    for subnet in topology_snapshot.subnets() {
        for node in subnet.nodes() {
            let labels: HashMap<String, String> = [
                ("ic".to_string(), group_name.clone()),
                ("ic_node".to_string(), node.node_id.to_string()),
                ("ic_subnet".to_string(), subnet.subnet_id.to_string()),
            ]
            .iter()
            .cloned()
            .collect();
            replica_p8s_static_configs.push(PrometheusStaticConfig {
                targets: vec![scraping_target_url(&node, REPLICA_METRICS_PORT)],
                labels: labels.clone(),
            });
            orchestrator_p8s_static_configs.push(PrometheusStaticConfig {
                targets: vec![scraping_target_url(&node, ORCHESTRATOR_METRICS_PORT)],
                labels: labels.clone(),
            });
            node_exporter_p8s_static_configs.push(PrometheusStaticConfig {
                targets: vec![scraping_target_url(&node, NODE_EXPORTER_METRICS_PORT)],
                labels,
            });
        }
    }
    for node in topology_snapshot.unassigned_nodes() {
        let labels: HashMap<String, String> = [
            ("ic".to_string(), group_name.clone()),
            ("ic_node".to_string(), node.node_id.to_string()),
        ]
        .iter()
        .cloned()
        .collect();
        orchestrator_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![scraping_target_url(&node, ORCHESTRATOR_METRICS_PORT)],
            labels: labels.clone(),
        });
        node_exporter_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![scraping_target_url(&node, NODE_EXPORTER_METRICS_PORT)],
            labels,
        });
    }
    for (name, p8s_static_configs) in &[
        ("replica", replica_p8s_static_configs),
        ("orchestrator", orchestrator_p8s_static_configs),
        ("node_exporter", node_exporter_p8s_static_configs),
    ] {
        ::serde_json::to_writer(
            &File::create(prometheus_config_dir.join(name).with_extension("json"))?,
            &p8s_static_configs,
        )?;
    }
    Ok(())
}

fn scraping_target_url(node: &IcNodeSnapshot, port: u16) -> String {
    format!("[{:?}]:{:?}", node.get_ip_addr(), port)
}

fn emit_event(log: &slog::Logger, message: &str, event_name: &str) {
    let event = log_events::LogEvent::new(event_name.to_string(), message.to_string());
    event.emit_log(log);
}
