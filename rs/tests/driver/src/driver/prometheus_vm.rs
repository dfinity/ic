use std::{
    collections::HashMap,
    fs::{self, File},
    net::Ipv6Addr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::Result;
use maplit::hashmap;
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use slog::{debug, info, warn, Logger};

use crate::driver::{
    constants::SSH_USERNAME,
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmAllocationStrategy, VmResources},
    log_events,
    resource::{DiskImage, ImageType},
    test_env::TestEnv,
    test_env_api::{
        HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, RetrieveIpv4Addr, SshSession,
        TopologySnapshot,
    },
    test_setup::{GroupSetup, InfraProvider},
    universal_vm::{UniversalVm, UniversalVms},
};
use crate::driver::{
    farm::{DnsRecord, DnsRecordType},
    test_env::TestEnvAttribute,
    test_env_api::CreateDnsRecords,
};
use crate::k8s::config::TNET_DNS_SUFFIX;
use crate::k8s::tnet::TNet;
use crate::retry_with_msg;

use super::boundary_node::BoundaryNodeVm;

const PROMETHEUS_VM_NAME: &str = "prometheus";

/// The SHA-256 hash of the Prometheus VM disk image.
/// The latest hash can be retrieved by downloading the SHA256SUMS file from:
/// https://hydra-int.dfinity.systems/job/dfinity-ci-build/farm/universal-vm.img-prometheus.x86_64-linux/latest
const DEFAULT_PROMETHEUS_VM_IMG_SHA256: &str =
    "4c288cebafb59e6c6b1611475cef1f4963aec61b6af798dd47d8c5264af15b8f";

fn get_default_prometheus_vm_img_url() -> String {
    format!("http://download.proxy-global.dfinity.network:8080/farm/prometheus-vm/{DEFAULT_PROMETHEUS_VM_IMG_SHA256}/x86_64-linux/prometheus-vm.img.zst")
}

const PROMETHEUS_DATA_DIR_TARBALL: &str = "prometheus-data-dir.tar.zst";

const PROMETHEUS_CONFIG_DIR_NAME: &str = "prometheus";

const PROMETHEUS_SCRAPING_TARGETS_DIR: &str = "/etc/prometheus";

const REPLICA_METRICS_PORT: u16 = 9090;
const ORCHESTRATOR_METRICS_PORT: u16 = 9091;
const NODE_EXPORTER_METRICS_PORT: u16 = 9100;
const IC_BOUNDARY_METRICS_PORT: u16 = 9324;

const PROMETHEUS_DOMAIN_NAME: &str = "prometheus";
const GRAFANA_DOMAIN_NAME: &str = "grafana";

pub const SCP_RETRY_TIMEOUT: Duration = Duration::from_secs(60);
pub const SCP_RETRY_BACKOFF: Duration = Duration::from_secs(5);
// Be mindful when modifying this constant, as the event can be consumed by other parties.
const PROMETHEUS_VM_CREATED_EVENT_NAME: &str = "prometheus_vm_created_event";
const GRAFANA_INSTANCE_CREATED_EVENT_NAME: &str = "grafana_instance_created_event";
const IC_PROGRESS_CLOCK_CREATED_EVENT_NAME: &str = "ic_progress_clock_created_event";

const REPLICA_PROMETHEUS_TARGET: &str = "replica.json";
const ORCHESTRATOR_PROMETHEUS_TARGET: &str = "orchestrator.json";
const NODE_EXPORTER_PROMETHEUS_TARGET: &str = "node_exporter.json";
const LEDGER_CANISTER_PROMETHEUS_TARGET: &str = "ledger_canister.json";
const BITCOIN_MAINNET_CANISTER_PROMETHEUS_TARGET: &str = "bitcoin_mainnet_canister.json";
const BITCOIN_TESTNET_CANISTER_PROMETHEUS_TARGET: &str = "bitcoin_testnet_canister.json";
const BITCOIN_WATCHDOG_MAINNET_CANISTER_PROMETHEUS_TARGET: &str =
    "bitcoin_watchdog_mainnet_canister.json";
const BITCOIN_WATCHDOG_TESTNET_CANISTER_PROMETHEUS_TARGET: &str =
    "bitcoin_watchdog_testnet_canister.json";
const BN_PROMETHEUS_TARGET: &str = "boundary_nodes.json";
const BN_EXPORTER_PROMETHEUS_TARGET: &str = "boundary_nodes_exporter.json";
const IC_BOUNDARY_PROMETHEUS_TARGET: &str = "ic_boundary.json";
const GRAFANA_DASHBOARDS: &str = "grafana_dashboards";

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
                    image_type: ImageType::PrometheusImage,
                    url: Url::parse(&get_default_prometheus_vm_img_url())
                        .expect("should not fail!"),
                    sha256: String::from(DEFAULT_PROMETHEUS_VM_IMG_SHA256),
                })
                .with_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(2)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(16780000)), // 16GiB
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(100)),
                })
                .enable_ipv4(),
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

    pub fn disable_ipv4(mut self) -> Self {
        self.universal_vm.has_ipv4 = false;
        self
    }

    /// Expects the layout of directory to be like:
    /// ```
    /// root
    /// ├── folder1
    /// │   ├── kustomization.yaml
    /// │   ├── dashboard1.json
    /// │   └── dashboard2.json
    /// ├── folder2
    /// │   ├── dashboard3.json
    /// │   ├── dashboard4.json
    /// │   ├── kustomization.yaml
    /// ...
    /// ```
    ///
    /// This process automatically discovers all `*.json` files, which are interpreted as Grafana dashboards. It then copies these files to a destination, where they will be sent to the Prometheus VM for use with the testnets. The expected name of the dashboards directory is determined by reading the `commonAnnotations.k8s-sidecar-target-directory` path from the `kustomize.yaml` file. This value specifies the location where the dashboards should be placed so that the links don't get broken.
    fn transform_dashboards_root_dir(logger: Logger, destination: &Path) -> Result<()> {
        let dashboards_root = PathBuf::from_str(&std::env::var("IC_DASHBOARDS_DIR")?)?;

        for directory in dashboards_root.read_dir().map_err(|e| {
            anyhow::anyhow!(
                "Failed to read contents of `{}`: {:?}",
                dashboards_root.display(),
                e
            )
        })? {
            let entry = directory?;
            if !entry.path().is_dir() {
                continue;
            }

            let maybe_kustomization = entry
                .path()
                .read_dir()?
                .filter_map(|f| f.ok())
                .find(|f| f.file_name().eq("kustomization.yaml"));

            let dashboard_dir = match maybe_kustomization {
                Some(file) => {
                    let parsed: serde_yaml::Value =
                        serde_yaml::from_str(&std::fs::read_to_string(file.path()).unwrap())?;

                    parsed
                        .get("commonAnnotations")
                        .ok_or(anyhow::anyhow!(
                            "Unexpected yaml schema for kustomization.yaml"
                        ))?
                        .get("k8s-sidecar-target-directory")
                        .ok_or(anyhow::anyhow!(
                            "Unexpected yaml schema for kustomization.yaml"
                        ))?
                        .as_str()
                        .ok_or(anyhow::anyhow!("Expected string for the name of directory"))?
                        .to_string()
                }
                None => entry.file_name().to_string_lossy().to_string(),
            };
            let dashboard_dir = destination.join(dashboard_dir);

            std::fs::create_dir_all(&dashboard_dir)?;
            info!(
                logger,
                "Created dir for dashboards: {}",
                dashboard_dir.display()
            );

            for maybe_file in entry.path().read_dir()? {
                let file = maybe_file?;

                if !file.path().is_file() && file.path().extension().is_none() {
                    continue;
                }

                // Safe because of previous check
                let path = file.path();
                let extension = path.extension().unwrap();

                // Dashboards are json files
                if extension != "json" {
                    continue;
                }

                let file_name = file.file_name();
                let file_name = file_name.as_os_str().to_str().unwrap();

                let destination_path = dashboard_dir.join(file_name);

                std::fs::copy(file.path(), destination_path)?;
                info!(logger, "Copying `{}` dashboard...", file_name);
            }
        }

        Ok(())
    }

    pub fn start(&self, env: &TestEnv) -> Result<()> {
        // Create a config directory containing the prometheus.yml configuration file.
        let vm_name = &self.universal_vm.name;
        let log = env.logger();
        let config_dir = env
            .single_activate_script_config_dir(
                vm_name,
                &format!(
                    r#"#!/bin/sh
mkdir -p -m 755 {PROMETHEUS_SCRAPING_TARGETS_DIR}
for name in replica orchestrator node_exporter; do
  echo '[]' > "{PROMETHEUS_SCRAPING_TARGETS_DIR}/$name.json"
done

mkdir -p /config/grafana/dashboards

if uname -a | grep -q Ubuntu; then
  # k8s
  chmod g+s /etc/prometheus
  cp -f /config/prometheus/prometheus.yml /etc/prometheus/prometheus.yml
  cp -R /config/grafana/dashboards /var/lib/grafana/
  chown -R grafana:grafana /var/lib/grafana/dashboards
  chown -R {SSH_USERNAME}:prometheus /etc/prometheus
  systemctl reload prometheus
else
  # farm
  chown -R {SSH_USERNAME}:users {PROMETHEUS_SCRAPING_TARGETS_DIR}
fi
"#
                ),
            )
            .unwrap();

        let grafana_dashboards_dst = config_dir.join("grafana").join("dashboards");
        std::fs::create_dir_all(&grafana_dashboards_dst).unwrap();
        let grafana_dashboards_src = env.get_path(GRAFANA_DASHBOARDS);
        if let Err(e) = Self::transform_dashboards_root_dir(log.clone(), &grafana_dashboards_src) {
            warn!(
                log,
                "Failed to sync k8s dashboards to grafana. Error: {}",
                e.to_string()
            )
        } else {
            debug!(log, "Copying Grafana dashboards from {grafana_dashboards_src:?} to {grafana_dashboards_dst:?} ...");
            TestEnv::shell_copy_with_deref(grafana_dashboards_src, grafana_dashboards_dst).unwrap();
        }

        write_prometheus_config_dir(config_dir.clone(), self.scrape_interval).unwrap();

        self.universal_vm
            .clone()
            .with_config_dir(config_dir)
            .start(env)?;

        let (prometheus_fqdn, grafana_fqdn) = match InfraProvider::read_attribute(env) {
            InfraProvider::Farm => {
                // Log the Prometheus URL so users can browse to it while the test is running.
                let deployed_prometheus_vm = env.get_deployed_universal_vm(vm_name).unwrap();
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
                if self.universal_vm.has_ipv4 {
                    let ipv4 = deployed_prometheus_vm.block_on_ipv4()?.to_string();
                    env.create_dns_records(vec![
                        DnsRecord {
                            name: PROMETHEUS_DOMAIN_NAME.to_string(),
                            record_type: DnsRecordType::A,
                            records: vec![ipv4.clone()],
                        },
                        DnsRecord {
                            name: GRAFANA_DOMAIN_NAME.to_string(),
                            record_type: DnsRecordType::A,
                            records: vec![ipv4],
                        },
                    ]);
                }
                (
                    format!("{PROMETHEUS_DOMAIN_NAME}.{suffix}"),
                    format!("{GRAFANA_DOMAIN_NAME}.{suffix}"),
                )
            }
            InfraProvider::K8s => {
                let tnet = TNet::read_attribute(env);
                (
                    format!(
                        "prometheus-{}.{}",
                        tnet.unique_name.clone().expect("no unique name"),
                        *TNET_DNS_SUFFIX
                    ),
                    format!(
                        "grafana-{}.{}",
                        tnet.unique_name.clone().expect("no unique name"),
                        *TNET_DNS_SUFFIX
                    ),
                )
            }
        };
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
    fn sync_with_prometheus(&self);

    /// Retrieves a topology snapshot by name, converts it into p8s scraping target
    /// JSON files and scps them to the prometheus VM. If `playnet_url` is specified, add a
    /// scraping target for NNS canisters (currently only the ICP ledger) to the prometheus VM.
    fn sync_with_prometheus_by_name(&self, name: &str, playnet_url: Option<String>);

    /// Downloads prometheus' data directory to the test artifacts
    /// such that we can run a local p8s on that later.
    ///
    /// Return early if no prometheus_vm has been setup.
    /// This allows this function to be used in a finalizer where no prometheus
    /// server has been setup.
    fn download_prometheus_data_dir_if_exists(&self);

    /// Get the playnet URL of the boundary node with the given name.
    fn get_playnet_url(&self, boundary_node_name: &str) -> Option<String>;
}

impl HasPrometheus for TestEnv {
    fn get_playnet_url(&self, boundary_node_name: &str) -> Option<String> {
        self.get_deployed_boundary_node(boundary_node_name)
            .ok()
            .and_then(|bn| bn.get_snapshot().ok()?.get_playnet())
    }

    fn sync_with_prometheus(&self) {
        self.sync_with_prometheus_by_name("", None)
    }

    fn sync_with_prometheus_by_name(&self, name: &str, mut playnet_url: Option<String>) {
        if InfraProvider::read_attribute(self) == InfraProvider::K8s {
            playnet_url = None;
        }

        let vm_name = PROMETHEUS_VM_NAME.to_string();
        // Write the scraping target JSON files to the local prometheus config directory.
        let prometheus_config_dir = self.get_universal_vm_config_dir(&vm_name);
        let group_name = GroupSetup::read_attribute(self).infra_group_name;
        sync_prometheus_config_dir(
            prometheus_config_dir.clone(),
            group_name.clone(),
            self.topology_snapshot_by_name(name),
            &playnet_url,
        )
        .expect("Failed to synchronize prometheus config with the latest IC topology!");
        sync_prometheus_config_dir_with_boundary_nodes(
            self,
            prometheus_config_dir.clone(),
            group_name,
        )
        .expect("Failed to synchronize prometheus config with the last deployments of the boundary nodes");
        // Setup an SSH session to the prometheus VM which we'll use to scp the JSON files.
        let deployed_prometheus_vm = self.get_deployed_universal_vm(&vm_name).unwrap();
        let session = deployed_prometheus_vm
            .block_on_ssh_session()
            .unwrap_or_else(|e| panic!("Failed to setup SSH session to {vm_name} because: {e:?}!"));
        // scp the scraping target JSON files to prometheus VM.
        let mut target_json_files = vec![
            REPLICA_PROMETHEUS_TARGET,
            ORCHESTRATOR_PROMETHEUS_TARGET,
            NODE_EXPORTER_PROMETHEUS_TARGET,
            BN_PROMETHEUS_TARGET,
            BN_EXPORTER_PROMETHEUS_TARGET,
            IC_BOUNDARY_PROMETHEUS_TARGET,
        ];
        if playnet_url.is_some() {
            target_json_files.push(LEDGER_CANISTER_PROMETHEUS_TARGET);
            target_json_files.push(BITCOIN_MAINNET_CANISTER_PROMETHEUS_TARGET);
            target_json_files.push(BITCOIN_TESTNET_CANISTER_PROMETHEUS_TARGET);
            target_json_files.push(BITCOIN_WATCHDOG_MAINNET_CANISTER_PROMETHEUS_TARGET);
            target_json_files.push(BITCOIN_WATCHDOG_TESTNET_CANISTER_PROMETHEUS_TARGET);
        }
        for file in &target_json_files {
            let from = prometheus_config_dir.join(file);
            let to = Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(file);
            let size = fs::metadata(&from).unwrap().len();
            retry_with_msg!(
                format!("scp {from:?} to {vm_name}:{to:?}"),
                self.logger(),
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

    let boundary_nodes_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(BN_PROMETHEUS_TARGET);
    let boundary_nodes_exporter_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(BN_EXPORTER_PROMETHEUS_TARGET);
    let ic_boundary_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(IC_BOUNDARY_PROMETHEUS_TARGET);
    let replica_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(REPLICA_PROMETHEUS_TARGET);
    let orchestrator_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(ORCHESTRATOR_PROMETHEUS_TARGET);
    let node_exporter_scraping_targets_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(NODE_EXPORTER_PROMETHEUS_TARGET);
    let ledger_canister_scraping_target_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(LEDGER_CANISTER_PROMETHEUS_TARGET);
    let bitcoin_mainnet_canister_scraping_target_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(BITCOIN_MAINNET_CANISTER_PROMETHEUS_TARGET);
    let bitcoin_testnet_canister_scraping_target_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR).join(BITCOIN_TESTNET_CANISTER_PROMETHEUS_TARGET);
    let bitcoin_watchdog_mainnet_canister_scraping_target_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR)
            .join(BITCOIN_WATCHDOG_MAINNET_CANISTER_PROMETHEUS_TARGET);
    let bitcoin_watchdog_testnet_canister_scraping_target_path =
        Path::new(PROMETHEUS_SCRAPING_TARGETS_DIR)
            .join(BITCOIN_WATCHDOG_TESTNET_CANISTER_PROMETHEUS_TARGET);
    let scrape_interval_str: String = format!("{}s", scrape_interval.as_secs());
    let prometheus_config = json!({
        "global": {"scrape_interval": scrape_interval_str},
        "scrape_configs": [
            {
                "job_name": "boundary_nodes",
                "file_sd_configs": [{"files": [boundary_nodes_scraping_targets_path]}],
            },
            {
                "job_name": "boundary_nodes_exporter",
                "file_sd_configs": [{"files": [boundary_nodes_exporter_scraping_targets_path]}],
            },
            {
                "job_name": "ic_boundary",
                "file_sd_configs": [{"files": [ic_boundary_scraping_targets_path]}],
            },
            {"job_name": "replica", "file_sd_configs": [{"files": [replica_scraping_targets_path]}]},
            {"job_name": "orchestrator", "file_sd_configs": [{"files": [orchestrator_scraping_targets_path]}]},
            {
                "job_name": "node_exporter",
                "file_sd_configs": [{"files": [node_exporter_scraping_targets_path]}],
                "scheme": "https",
                "tls_config": {"insecure_skip_verify": true},
            },
            {
                "job_name": "ledger-canister",
                "honor_timestamps": true,
                "metrics_path": "/metrics",
                "scheme": "https",
                "follow_redirects": true,
                "enable_http2": true,
                "file_sd_configs": [{"files": [ledger_canister_scraping_target_path]}],
            },
            {
                "job_name": "bitcoin-mainnet-canister",
                "honor_timestamps": true,
                "metrics_path": "/metrics",
                "scheme": "https",
                "follow_redirects": true,
                "enable_http2": true,
                "file_sd_configs": [{"files": [bitcoin_mainnet_canister_scraping_target_path]}],
            },
            {
                "job_name": "bitcoin-testnet-canister",
                "honor_timestamps": true,
                "metrics_path": "/metrics",
                "scheme": "https",
                "follow_redirects": true,
                "enable_http2": true,
                "file_sd_configs": [{"files": [bitcoin_testnet_canister_scraping_target_path]}],
            },
            {
                "job_name": "bitcoin-watchdog-mainnet-canister",
                "honor_timestamps": true,
                "metrics_path": "/metrics",
                "scheme": "https",
                "follow_redirects": true,
                "enable_http2": true,
                "file_sd_configs": [{"files": [bitcoin_watchdog_mainnet_canister_scraping_target_path]}],
            },
            {
                "job_name": "bitcoin-watchdog-testnet-canister",
                "honor_timestamps": true,
                "metrics_path": "/metrics",
                "scheme": "https",
                "follow_redirects": true,
                "enable_http2": true,
                "file_sd_configs": [{"files": [bitcoin_watchdog_testnet_canister_scraping_target_path]}],
            },
        ],
    });
    let prometheus_config_path = prometheus_config_dir.join("prometheus.yml");
    let prometheus_config_file = File::create(prometheus_config_path)?;
    serde_json::to_writer(prometheus_config_file, &prometheus_config)?;
    Ok(())
}

fn sync_prometheus_config_dir_with_boundary_nodes(
    env: &TestEnv,
    prometheus_config_dir: PathBuf,
    group_name: String,
) -> Result<()> {
    let mut boundary_nodes_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
    let mut boundary_nodes_exporter_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();

    let bns: Vec<(String, Ipv6Addr)> = env
        .get_deployed_boundary_nodes()
        .into_iter()
        .map(|bn| {
            let vm = bn.get_vm().unwrap();
            (vm.hostname, vm.ipv6)
        })
        .collect();

    for (name, ipv6) in bns.iter() {
        let labels: HashMap<String, String> = [
            ("ic".to_string(), group_name.clone()),
            ("ic_boundary_node".to_string(), name.to_string()),
        ]
        .iter()
        .cloned()
        .collect();
        boundary_nodes_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![format!("[{:?}]:{:?}", ipv6, IC_BOUNDARY_METRICS_PORT)],
            labels: labels.clone(),
        });
        boundary_nodes_exporter_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![format!("[{:?}]:{:?}", ipv6, NODE_EXPORTER_METRICS_PORT)],
            labels: labels.clone(),
        });
    }
    for (name, p8s_static_configs) in &[
        (BN_PROMETHEUS_TARGET, boundary_nodes_p8s_static_configs),
        (
            BN_EXPORTER_PROMETHEUS_TARGET,
            boundary_nodes_exporter_p8s_static_configs,
        ),
    ] {
        ::serde_json::to_writer(
            &File::create(prometheus_config_dir.join(name))?,
            &p8s_static_configs,
        )?;
    }
    Ok(())
}

fn sync_prometheus_config_dir(
    prometheus_config_dir: PathBuf,
    group_name: String,
    topology_snapshot: TopologySnapshot,
    playnet_url: &Option<String>,
) -> Result<()> {
    let mut replica_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
    let mut ic_boundary_p8s_static_configs: Vec<PrometheusStaticConfig> = Vec::new();
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

    for node in topology_snapshot.api_boundary_nodes() {
        let labels: HashMap<String, String> = [
            ("ic".to_string(), group_name.clone()),
            ("ic_node".to_string(), node.node_id.to_string()),
            ("ic_api_bn".to_string(), "1".to_string()),
        ]
        .iter()
        .cloned()
        .collect();
        orchestrator_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![scraping_target_url(&node, ORCHESTRATOR_METRICS_PORT)],
            labels: labels.clone(),
        });
        ic_boundary_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![scraping_target_url(&node, IC_BOUNDARY_METRICS_PORT)],
            labels: labels.clone(),
        });
        node_exporter_p8s_static_configs.push(PrometheusStaticConfig {
            targets: vec![scraping_target_url(&node, NODE_EXPORTER_METRICS_PORT)],
            labels,
        });
    }

    if let Some(playnet_url) = playnet_url {
        // ICP ledger canister
        serde_json::to_writer(
            &File::create(prometheus_config_dir.join(LEDGER_CANISTER_PROMETHEUS_TARGET))?,
            &vec![PrometheusStaticConfig {
                targets: vec![format!("ryjl3-tyaaa-aaaaa-aaaba-cai.raw.{}", playnet_url)],
                labels: hashmap! {"ic".to_string() => group_name.clone(), "token".to_string() => "icp".to_string()},
            }],
        )?;
        // Bitcoin canisters
        for (prometheus_target, canister_id) in [
            (
                BITCOIN_MAINNET_CANISTER_PROMETHEUS_TARGET,
                "ghsi2-tqaaa-aaaan-aaaca-cai",
            ),
            (
                BITCOIN_TESTNET_CANISTER_PROMETHEUS_TARGET,
                "g4xu7-jiaaa-aaaan-aaaaq-cai",
            ),
            (
                BITCOIN_WATCHDOG_MAINNET_CANISTER_PROMETHEUS_TARGET,
                "gatoo-6iaaa-aaaan-aaacq-cai",
            ),
            (
                BITCOIN_WATCHDOG_TESTNET_CANISTER_PROMETHEUS_TARGET,
                "gjqfs-iaaaa-aaaan-aaada-cai",
            ),
        ] {
            serde_json::to_writer(
                &File::create(prometheus_config_dir.join(prometheus_target))?,
                &vec![PrometheusStaticConfig {
                    targets: vec![format!("{canister_id}.raw.{playnet_url}")],
                    labels: hashmap! {"ic".to_string() => group_name.clone()},
                }],
            )?;
        }
    }
    for (name, p8s_static_configs) in &[
        (REPLICA_PROMETHEUS_TARGET, replica_p8s_static_configs),
        (
            IC_BOUNDARY_PROMETHEUS_TARGET,
            ic_boundary_p8s_static_configs,
        ),
        (
            ORCHESTRATOR_PROMETHEUS_TARGET,
            orchestrator_p8s_static_configs,
        ),
        (
            NODE_EXPORTER_PROMETHEUS_TARGET,
            node_exporter_p8s_static_configs,
        ),
    ] {
        ::serde_json::to_writer(
            &File::create(prometheus_config_dir.join(name))?,
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
