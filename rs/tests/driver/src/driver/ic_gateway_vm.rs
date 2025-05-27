use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use slog::info;
use std::path::Path;
use url::Url;

use crate::driver::{
    farm::{DnsRecord, DnsRecordType, PlaynetCertificate, VMCreateResponse},
    log_events,
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{
        get_dependency_path, AcquirePlaynetCertificate, CreatePlaynetDnsRecords,
        HasTopologySnapshot, HasVmName, SshSession,
    },
    test_setup::InfraProvider,
    universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
};

// Constants
pub const IC_GATEWAY_VM_NAME: &str = "ic-gateway";
const IC_GATEWAY_VM_FILE: &str = "vm.json";
const IMAGE_PATH: &str = "rs/tests/ic_gateway_uvm_config_image.zst";
const IC_GATEWAY_VMS_DIR: &str = "ic_gateway_vms";
const PLAYNET_FILE: &str = "playnet.json";
const BN_AAAA_RECORDS_CREATED_EVENT_NAME: &str = "bn_aaaa_records_created_event";

/// Represents an IC HTTP Gateway VM, it is a wrapper around Farm's Universal VM.
#[derive(Debug)]
pub struct IcGatewayVm {
    universal_vm: UniversalVm,
}

/// Represents a deployed IC HTTP Gateway VM.
#[derive(Debug)]
pub struct DeployedIcGatewayVm {
    deployed_universal_vm: DeployedUniversalVm,
    https_url: Option<Url>,
}

impl DeployedIcGatewayVm {
    pub fn https_url(&self) -> Option<Url> {
        self.https_url.clone()
    }

    /// Retrieves the underlying VM.
    pub fn get_vm(&self, env: &TestEnv) -> Result<VMCreateResponse> {
        let vm_path = Path::new(IC_GATEWAY_VMS_DIR)
            .join(self.deployed_universal_vm.vm_name())
            .join(IC_GATEWAY_VM_FILE);
        env.read_json_object(&vm_path)
            .with_context(|| format!("Failed to read VM data from {}", vm_path.display()))
    }
}

impl Default for IcGatewayVm {
    fn default() -> Self {
        Self::new(IC_GATEWAY_VM_NAME)
    }
}

impl IcGatewayVm {
    /// Creates a new IC Gateway VM with the specified name.
    pub fn new(name: &str) -> Self {
        let universal_vm = super::universal_vm::UniversalVm::new(name.to_string())
            .with_config_img(get_dependency_path(IMAGE_PATH));
        Self { universal_vm }
    }

    /// Starts the IC Gateway VM, configuring DNS and certificates.
    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let logger = env.logger();
        info!(logger, "Starting IC Gateway VM: {}", self.universal_vm.name);

        // Start the underlying universal VM
        self.universal_vm.start(env)?;
        let deployed_universal_vm = env.get_deployed_universal_vm(&self.universal_vm.name)?;

        // Get IPv6 address and API node URLs
        let uvm_ipv6 = deployed_universal_vm.get_vm()?.ipv6.to_string();
        let api_nodes_urls = self.get_api_nodes_urls(env)?;

        // Handle playnet configuration and DNS records
        let playnet = self.load_or_create_playnet(env, &uvm_ipv6)?;
        let bn_fqdn = playnet.playnet_cert.playnet.clone();
        self.configure_dns_records(env, &playnet, &bn_fqdn)?;

        // Emit log event for AAAA records
        emit_bn_aaaa_records_event(&logger, &bn_fqdn, playnet.aaaa_records.clone());

        // Save playnet configuration and start the gateway
        let playnet_url = Url::parse(&format!("https://{}", bn_fqdn))?;
        env.write_deployed_ic_gateway(&self.universal_vm.name, playnet_url.clone())?;
        env.write_json_object(PLAYNET_FILE, &playnet)?;
        self.start_gateway_container(&deployed_universal_vm, &playnet, &api_nodes_urls)?;

        info!(
            logger,
            "IC Gateway started successfully with URL: {}", playnet_url
        );

        Ok(())
    }

    /// Retrieves API boundary node URLs from the topology.
    fn get_api_nodes_urls(&self, env: &TestEnv) -> Result<String> {
        env.topology_snapshot()
            .api_boundary_nodes()
            .map(|node| format!("https://[{}]", node.get_ip_addr()))
            .reduce(|acc, url| format!("{},{}", acc, url))
            .ok_or_else(|| anyhow!("No API boundary nodes found in topology"))
    }

    /// Loads existing playnet configuration or creates a new one.
    fn load_or_create_playnet(&self, env: &TestEnv, uvm_ipv6: &str) -> Result<Playnet> {
        let logger = env.logger();
        let playnet_file = env.get_json_path(PLAYNET_FILE);

        let mut playnet = if playnet_file.exists() {
            let playnet: Playnet = env.read_json_object(PLAYNET_FILE)?;
            info!(
                logger,
                "Using existing playnet: {}", playnet.playnet_cert.playnet
            );
            playnet
        } else {
            let playnet_cert = env.acquire_playnet_certificate();
            info!(logger, "Acquired new playnet: {}", playnet_cert.playnet);
            Playnet {
                playnet_cert,
                aaaa_records: vec![],
                a_records: vec![],
            }
        };

        playnet.aaaa_records.push(uvm_ipv6.to_string());
        Ok(playnet)
    }

    /// Configures DNS records based on infrastructure provider.
    fn configure_dns_records(&self, env: &TestEnv, playnet: &Playnet, bn_fqdn: &str) -> Result<()> {
        let records = match InfraProvider::read_attribute(env) {
            InfraProvider::Farm => vec![
                DnsRecord {
                    name: "".to_string(),
                    record_type: DnsRecordType::AAAA,
                    records: playnet.aaaa_records.clone(),
                },
                DnsRecord {
                    name: "*".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.to_string()],
                },
                DnsRecord {
                    name: "*.raw".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.to_string()],
                },
            ],
            _ => vec![
                DnsRecord {
                    name: bn_fqdn.to_string(),
                    record_type: DnsRecordType::AAAA,
                    records: playnet.aaaa_records.clone(),
                },
                DnsRecord {
                    name: format!("{}.{}", "*", bn_fqdn),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.to_string()],
                },
                DnsRecord {
                    name: format!("{}.{}", "*.raw", bn_fqdn),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.to_string()],
                },
            ],
        };

        env.create_playnet_dns_records(records);

        Ok(())
    }

    /// Starts the IC Gateway docker container.
    fn start_gateway_container(
        &self,
        deployed_universal_vm: &DeployedUniversalVm,
        playnet: &Playnet,
        api_nodes_urls: &str,
    ) -> Result<()> {
        let bash_script = format!(
            r#"
# Prepare certificates and private key
mkdir /tmp/certs
cd /tmp/certs
printf "%b" "{cert}" > cert.pem
printf "%b" "{cert_chain}" >> cert.pem
printf "%b" "{key}" > cert.key

# Prepare config file
cat <<EOF > ic-gateway.env
IC_URL={ic_url}
DOMAIN={domain}
NETWORK_HTTP_CLIENT_INSECURE_BYPASS_TLS_VERIFICATION=true
IC_UNSAFE_ROOT_KEY_FETCH=true
LISTEN_TLS=[::]:443
CERT_PROVIDER_DIR=/certs
EOF

# Load the docker image from the tarball
docker load -i /config/ic_gatewayd.tar

# Start ic-gateway service in the background
docker run --name=ic-gateway -d \
  -v /tmp/certs:/certs \
  --network host \
  --env-file ic-gateway.env \
  ic_gatewayd:image

# Wait for the service to become ready.
# Readiness is defined when some API boundary node used by ic-gateway responds with HTTP 200 to /api/v2/status.

URL="https://{domain}/api/v2/status"
TOTAL_TIMEOUT=80
REQUEST_TIMEOUT=2
RETRY_INTERVAL=5

start_time=$(date +%s)
echo "Waiting for ic-gateway to become ready..."

while true; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))

  http_code=$(curl --silent --output /dev/null --write-out "%{{http_code}}" \
                    --max-time "${{REQUEST_TIMEOUT}}" "$URL")

  if [ "$http_code" -eq 200 ]; then
    echo "ic-gateway is ready to serve traffic"
    exit 0
  fi

  if [ "$elapsed" -ge "${{TOTAL_TIMEOUT}}" ]; then
    echo "ic-gateway did not become ready within ${{TOTAL_TIMEOUT}}s"
    exit 1
  fi

  echo "ic-gateway not ready yet (status: $http_code). Retrying in ${{RETRY_INTERVAL}}s..."
  sleep "$RETRY_INTERVAL"
done
"#,
            key = playnet.playnet_cert.cert.priv_key_pem,
            cert = playnet.playnet_cert.cert.cert_pem,
            cert_chain = playnet.playnet_cert.cert.chain_pem,
            ic_url = api_nodes_urls,
            domain = playnet.playnet_cert.playnet
        );

        deployed_universal_vm.block_on_bash_script(&bash_script)?;
        Ok(())
    }
}

/// Playnet configuration structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Playnet {
    playnet_cert: PlaynetCertificate,
    aaaa_records: Vec<String>,
    a_records: Vec<String>,
}

/// Emits a log event for boundary node AAAA records.
pub fn emit_bn_aaaa_records_event(log: &slog::Logger, bn_fqdn: &str, aaaa_records: Vec<String>) {
    #[derive(Deserialize, Serialize)]
    struct BoundaryNodeAAAARecords {
        url: String,
        aaaa_records: Vec<String>,
    }

    let event = log_events::LogEvent::new(
        BN_AAAA_RECORDS_CREATED_EVENT_NAME.to_string(),
        BoundaryNodeAAAARecords {
            url: bn_fqdn.to_string(),
            aaaa_records,
        },
    );
    event.emit_log(log);
}

/// Trait for interacting with IC Gateway VMs in a test environment.
pub trait HasIcGatewayVm {
    fn get_deployed_ic_gateway(&self, name: &str) -> Result<DeployedIcGatewayVm>;
    fn write_deployed_ic_gateway(&self, name: &str, playnet: Url) -> Result<()>;
}

impl HasIcGatewayVm for TestEnv {
    fn get_deployed_ic_gateway(&self, name: &str) -> Result<DeployedIcGatewayVm> {
        let ic_gateway_dir = Path::new(IC_GATEWAY_VMS_DIR).join(name);
        let ic_gateway_abs_dir = self.get_path(&ic_gateway_dir);

        if !ic_gateway_abs_dir.is_dir() {
            bail!(
                "Deployed IC Gateway VM '{}' not found at {}",
                name,
                ic_gateway_abs_dir.display()
            );
        }

        let playnet_path = ic_gateway_abs_dir.join(PLAYNET_FILE);
        let playnet: Url = self
            .read_json_object(&playnet_path)
            .with_context(|| format!("Failed to read playnet file: {}", playnet_path.display()))?;

        let https_url = playnet.scheme().eq("https").then(|| playnet.clone());
        let deployed_universal_vm = self
            .get_deployed_universal_vm(name)
            .context("Failed to retrieve deployed universal VM")?;

        Ok(DeployedIcGatewayVm {
            deployed_universal_vm,
            https_url,
        })
    }

    fn write_deployed_ic_gateway(&self, name: &str, playnet: Url) -> Result<()> {
        let file_path = Path::new(IC_GATEWAY_VMS_DIR).join(name).join(PLAYNET_FILE);
        self.write_json_object(&file_path, &playnet)
    }
}
