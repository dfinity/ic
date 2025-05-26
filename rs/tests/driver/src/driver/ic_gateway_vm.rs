use std::path::{Path, PathBuf};

use slog::info;
use url::Url;

use super::{
    test_env::TestEnv,
    test_env_api::get_dependency_path,
    universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
};
use crate::driver::test_env_api::{HasTopologySnapshot, SshSession};
use crate::driver::{
    farm::{DnsRecord, DnsRecordType, PlaynetCertificate},
    log_events,
    test_env_api::{AcquirePlaynetCertificate, CreatePlaynetDnsRecords},
    test_setup::InfraProvider,
};
use crate::driver::{test_env::TestEnvAttribute};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const IC_GATEWAY_VM_NAME: &str = "ic-gateway";
pub const IMAGE_PATH: &str = "rs/tests/ic_gateway_uvm_config_image.zst";
pub const IC_GATEWAY_VMS_DIR: &str = "ic_gateway_vms";
const PLAYNET_FILE: &str = "playnet.json";

// Be mindful when modifying this constant, as the event can be consumed by other parties.
const BN_AAAA_RECORDS_CREATED_EVENT_NAME: &str = "bn_aaaa_records_created_event";

pub struct IcGatewayVm {
    universal_vm: UniversalVm,
}

#[derive(Debug)]
pub struct DeployedIcGatewayVm {
    deployed_universal_vm: DeployedUniversalVm,
    https_url: Option<Url>,
}

impl DeployedIcGatewayVm {
    pub fn https_url(&self) -> Option<Url> {
        self.https_url.clone()
    }
}

impl Default for IcGatewayVm {
    fn default() -> Self {
        IcGatewayVm::new(IC_GATEWAY_VM_NAME)
    }
}

impl IcGatewayVm {
    pub fn new(name: &str) -> Self {
        let universal_vm =
            UniversalVm::new(name.to_string()).with_config_img(get_dependency_path(IMAGE_PATH));

        Self { universal_vm }
    }

    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let logger = env.logger();

        self.universal_vm.start(&env)?;

        let deployed_universal_vm = env.get_deployed_universal_vm(&self.universal_vm.name)?;

        let uvm_ipv6 = deployed_universal_vm.get_vm()?.ipv6.to_string();

        // At least one API node is required for ic-gateway
        let api_nodes_urls = env
            .topology_snapshot()
            .api_boundary_nodes()
            .map(|node| format!("https://[{}]", node.get_ip_addr()))
            // fold urls into one string prepending commas
            .reduce(|acc, url| format!("{},{}", acc, url))
            .ok_or_else(|| anyhow!("No API boundary nodes found in topology"))?;

        info!(
            &logger,
            "API boundary nodes in topology: {:?}", api_nodes_urls
        );

        // Acquire a playnet certificate and provision an AAAA record pointing
        // ic{ix}.farm.dfinity.systems to the IPv6 address of the BN.
        let playnet_file = env.get_json_path(PLAYNET_FILE);
        let mut playnet: Playnet = if playnet_file.exists() {
            let playnet: Playnet = env.read_json_object(PLAYNET_FILE)?;
            info!(
                &logger,
                "Using existing playnet: {}", playnet.playnet_cert.playnet
            );
            playnet
        } else {
            let playnet_cert = env.acquire_playnet_certificate();
            info!(&logger, "Acquired playnet: {}", playnet_cert.playnet);
            Playnet {
                playnet_cert,
                aaaa_records: vec![],
                a_records: vec![],
            }
        };

        let bn_fqdn = playnet.playnet_cert.playnet.clone();

        playnet.aaaa_records.push(uvm_ipv6.clone());

        if InfraProvider::read_attribute(env) == InfraProvider::Farm {
            env.create_playnet_dns_records(vec![
                DnsRecord {
                    name: "".to_string(),
                    record_type: DnsRecordType::AAAA,
                    records: playnet.aaaa_records.clone(),
                },
                DnsRecord {
                    name: "*".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
                DnsRecord {
                    name: "*.raw".to_string(),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
            ]);
        } else {
            env.create_playnet_dns_records(vec![
                DnsRecord {
                    name: bn_fqdn.clone(),
                    record_type: DnsRecordType::AAAA,
                    records: playnet.aaaa_records.clone(),
                },
                DnsRecord {
                    name: format!("{}.{}", "*", bn_fqdn),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
                DnsRecord {
                    name: format!("{}.{}", "*.raw", bn_fqdn),
                    record_type: DnsRecordType::CNAME,
                    records: vec![bn_fqdn.clone()],
                },
            ]);
        }
        // TODO: The AAAA record is incorrect for k8s, but leaving it like this for now just for compatibility.
        // Emit a json log event, to be consumed by log post-processing tools.
        emit_bn_aaaa_records_event(&logger, &bn_fqdn, playnet.aaaa_records.clone());

        let playnet_url = Url::parse(&format!("https://{}", playnet.playnet_cert.playnet))?;
        env.write_deployed_ic_gateway(&self.universal_vm.name, playnet_url)?;
        env.write_json_object(PLAYNET_FILE, &playnet)?;

        let start_ic_gateway = deployed_universal_vm.block_on_bash_script(&format!(
            r#"
mkdir /tmp/certs
cd /tmp/certs
printf "%b" "{cert}" > cert.pem
printf "%b" "{cert_chain}" >> cert.pem
printf "%b" "{key}" > cert.key

cat <<EOF > ic-gateway.env
IC_URL={ic_url}
DOMAIN={domain}
NETWORK_HTTP_CLIENT_INSECURE_BYPASS_TLS_VERIFICATION=true
IC_UNSAFE_ROOT_KEY_FETCH=true
LISTEN_TLS=[::]:443
CERT_PROVIDER_DIR=/certs
EOF

docker load -i /config/ic_gatewayd.tar

docker run --name=ic-gateway -d \
  -v /tmp/certs:/certs \
  --network host \
  --env-file ic-gateway.env \
  ic_gatewayd:image
"#,
            key = playnet.playnet_cert.cert.priv_key_pem,
            cert = playnet.playnet_cert.cert.cert_pem,
            cert_chain = playnet.playnet_cert.cert.chain_pem,
            ic_url = api_nodes_urls,
            domain = playnet.playnet_cert.playnet
        ))?;

        info!(&logger, "Start ic-gateway result {start_ic_gateway}");

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Playnet {
    playnet_cert: PlaynetCertificate,
    aaaa_records: Vec<String>,
    a_records: Vec<String>,
}

pub fn emit_bn_aaaa_records_event(log: &slog::Logger, bn_fqdn: &str, aaaa_records: Vec<String>) {
    #[derive(Deserialize, Serialize)]
    pub struct BoundaryNodeAAAARecords {
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

pub trait HasIcGatewayVm {
    fn get_deployed_ic_gateway(&self, name: &str) -> Result<DeployedIcGatewayVm>;

    fn write_deployed_ic_gateway(&self, name: &str, playnet: Url) -> Result<()>;
}

impl HasIcGatewayVm for TestEnv {
    fn get_deployed_ic_gateway(&self, name: &str) -> Result<DeployedIcGatewayVm> {
        let ic_gateway_rel_dir = Path::new(IC_GATEWAY_VMS_DIR).join(name);
        let ic_gateway_abs_dir = self.get_path(ic_gateway_rel_dir);

        if !ic_gateway_abs_dir.is_dir() {
            bail!(
                "Deployed ic-gateway with name `{}` not found",
                ic_gateway_abs_dir.display()
            );
        }

        let playnet_path = ic_gateway_abs_dir.join(PLAYNET_FILE);

        let playnet: Url = self
            .read_json_object(&playnet_path)
            .with_context(|| format!("Failed to read `{}`", playnet_path.display()))?;

        let https_url = if playnet.scheme() == "https" {
            Some(playnet.clone())
        } else {
            None
        };

        let deployed_universal_vm = self
            .get_deployed_universal_vm(name)
            .context("Failed to get deployed universal VM")?;

        Ok(DeployedIcGatewayVm {
            deployed_universal_vm,
            https_url,
        })
    }

    fn write_deployed_ic_gateway(&self, name: &str, playnet: Url) -> Result<()> {
        let file_path: PathBuf = Path::new(IC_GATEWAY_VMS_DIR).join(name).join(PLAYNET_FILE);

        self.write_json_object(file_path, &playnet)
    }
}
