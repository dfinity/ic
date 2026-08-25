use anyhow::{Context, Result, anyhow, bail};
use http::{Method, StatusCode};
use rcgen::{CertificateParams, KeyPair};
use reqwest::{Client, Request};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::EncodePrivateKey};
use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::net::lookup_host;
use url::Url;

use crate::{
    driver::{
        farm::{
            Certificate, DemoCertificate, DnsRecord, DnsRecordType, HostFeature, PlaynetCertificate,
        },
        local_backend::{IN_GROUP_DOMAIN_SUFFIX, LocalBackend},
        log_events,
        resource::AllocatedVm,
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{
            AcquireDemoCertificate, AcquirePlaynetCertificate, CreateDnsRecords,
            CreatePlaynetDnsRecords, HasPublicApiUrl, HasTestEnv, HasTopologySnapshot,
            IcNodeSnapshot, RetrieveIpv4Addr, SshSession, get_dependency_path_from_env,
        },
        test_setup::{GroupSetup, SystemTestBackend},
        universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
    },
    retry_with_msg_async,
    util::block_on,
};

// Constants
pub const IC_GATEWAY_VM_NAME: &str = "ic-gateway";
const IC_GATEWAY_VM_FILE: &str = "vm.json";
const IC_GATEWAY_VMS_DIR: &str = "ic_gateway_vms";
const PLAYNET_URL_FILE: &str = "playnet_url.json";
const IC_GATEWAY_AAAA_RECORDS_CREATED_EVENT_NAME: &str = "ic_gateway_aaaa_records_created_event";
const IC_GATEWAY_A_RECORDS_CREATED_EVENT_NAME: &str = "ic_gateway_a_records_created_event";
const READY_TIMEOUT: Duration = Duration::from_secs(360);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// The dev root CA: the certificate authority that every *dev* IC-OS image
/// already trusts, loaded ready to sign with.
///
/// `ic-os/{guestos,hostos}/context/Dockerfile` installs
/// `ic-os/components/networking/dev-certs/canister_http_test_ca.cert` into
/// `/usr/local/share/ca-certificates` and runs `update-ca-certificates` — in the
/// `output_dev` stage only, so a production image trusts nothing extra. Its
/// private key is checked in beside it, which is how a test can serve HTTPS that
/// a node accepts without any node-side configuration; `canister_http` and
/// `ckbtc` already rely on this, and its `README.md` documents the use.
///
/// The certificate and the key reach us as runfiles, provided to the local
/// backend's variant of every system test by `_local_only_deps` in
/// `rs/tests/system_tests.bzl`. Reading either on the Farm backend would panic,
/// and must not happen: Farm uses a playnet certificate.
struct DevRootCa {
    /// PEM of the checked-in CA certificate, exactly as it sits in the images'
    /// trust store. This is what the gateway serves as its chain and what a
    /// driver-side client adds as a trust anchor.
    cert_pem: String,
    /// The same CA as an `rcgen` issuer.
    cert: rcgen::Certificate,
    key: KeyPair,
}

/// The PEM of the dev root CA certificate. See [`DevRootCa`].
fn dev_root_ca_cert_pem() -> Result<String> {
    let path = get_dependency_path_from_env("ENV_DEPS__DEV_ROOT_CA_CERT_PATH");
    fs::read_to_string(&path).with_context(|| {
        format!(
            "reading the dev root CA certificate from {}",
            path.display()
        )
    })
}

/// Loads the dev root CA so `rcgen` can issue certificates from it.
fn dev_root_ca() -> Result<DevRootCa> {
    let cert_pem = dev_root_ca_cert_pem()?;
    let key_path = get_dependency_path_from_env("ENV_DEPS__DEV_ROOT_CA_KEY_PATH");
    let key_pkcs1_pem = fs::read_to_string(&key_path)
        .with_context(|| format!("reading the dev root CA key from {}", key_path.display()))?;

    // The checked-in key is PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`), which
    // `rcgen` loads only under its `aws_lc_rs` backend; under `ring` it takes
    // PKCS#8 only. Which of the two is compiled in is not ours to decide: both
    // features are on, and `rcgen` prefers `aws_lc_rs` when they are — but only
    // because `rustls-acme` happens to enable it, four crates away (see
    // `cargo tree -i rcgen -e features`). Re-encoding to PKCS#8 works under either
    // backend, so it does not matter if that ever changes; relying on the feature
    // would turn an unrelated dependency edit into a runtime failure in every
    // local gateway test.
    let key_pkcs8_pem = RsaPrivateKey::from_pkcs1_pem(&key_pkcs1_pem)
        .context("parsing the dev root CA key as PKCS#1")?
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .context("re-encoding the dev root CA key as PKCS#8")?;
    let key = KeyPair::from_pem(&key_pkcs8_pem).context("loading the dev root CA key")?;

    // `from_ca_cert_pem` extracts what is needed to act as an issuer, of which
    // `signed_by` uses one thing: the subject name, which becomes the leaf's
    // issuer. (It carries the CA's subject key identifier across too, but that
    // reaches the leaf as an authority key identifier only when
    // `use_authority_key_identifier_extension` is set, and `CertificateParams::new`
    // leaves it false — the leaf's only extension is its SAN.) `self_signed` then
    // re-signs the CA merely to obtain an `rcgen::Certificate` to pass as that
    // issuer; the result is not the checked-in certificate byte for byte and is
    // never served. What makes the chain verify is the issuer name plus the
    // signature, both of which are the real CA's.
    let cert = CertificateParams::from_ca_cert_pem(&cert_pem)
        .context("parsing the dev root CA certificate")?
        .self_signed(&key)
        .context("loading the dev root CA certificate as an issuer")?;

    Ok(DevRootCa {
        cert_pem,
        cert,
        key,
    })
}

/// Represents an IC HTTP Gateway VM, it is a wrapper around Farm's Universal VM.
#[derive(Debug)]
pub struct IcGatewayVm {
    universal_vm: UniversalVm,
    enp2s0_config: Option<String>,
}

/// Represents a deployed IC HTTP Gateway VM.
#[derive(Debug)]
pub struct DeployedIcGatewayVm {
    env: TestEnv,
    vm: AllocatedVm,
    https_url: Url,
}

impl DeployedIcGatewayVm {
    pub fn get_public_url(&self) -> Url {
        self.https_url.clone()
    }

    /// Retrieves the underlying VM.
    pub fn get_vm(&self) -> AllocatedVm {
        self.vm.clone()
    }

    /// Returns a custom DNS resolution override for reaching the gateway at the
    /// given `url`, if one is needed for the active system-test backend.
    ///
    /// On the [`SystemTestBackend::Local`] backend the gateway's domain is
    /// `<name>.ic.net`, which the group's `dnsmasq` resolves for the *VMs* — but
    /// not for the driver, which sits in the group's network namespace yet reads
    /// the host's `/etc/resolv.conf`, whose nameserver is unreachable from there.
    /// Nor does `dnsmasq` answer for the per-canister subdomains
    /// `<canister_id>.<name>.ic.net`, since it is served a hosts file, which has
    /// no wildcards. A driver-side client therefore has to resolve the requested
    /// host itself. This returns `(host, [vm_ipv6]:443)` for the host of `url`,
    /// to be passed to `reqwest`'s `.resolve(host, addr)`.
    ///
    /// Note that `resolve` overrides only the *exact* host passed to it (it does
    /// *not* apply to subdomains), so the host of the actual request URL — e.g.
    /// `<canister_id>.<name>.ic.net` — must be used, not the apex domain. On the
    /// [`SystemTestBackend::Farm`] backend DNS resolves the gateway domain, so no
    /// override is needed and `None` is returned.
    ///
    /// The certificate needs no equivalent workaround: see
    /// [`Self::root_certificate`].
    pub fn resolve_override_for_url(&self, url: &Url) -> Option<(String, SocketAddr)> {
        match SystemTestBackend::read_attribute(&self.env) {
            SystemTestBackend::Local => {
                let host = url.host_str()?.to_string();
                Some((host, SocketAddr::new(IpAddr::V6(self.vm.ipv6), 443)))
            }
            SystemTestBackend::Farm => None,
        }
    }

    /// The extra trust anchor a client needs in order to verify the gateway's
    /// TLS certificate, if any.
    ///
    /// On the [`SystemTestBackend::Local`] backend the certificate is issued by
    /// the dev root CA (see [`DevRootCa`]) rather than by a public one, so a
    /// driver-side client has to add that CA to its roots:
    /// `builder.add_root_certificate(cert)`. `reqwest` *adds* it to the
    /// platform's roots rather than replacing them, so the client keeps trusting
    /// everything it trusted before. On [`SystemTestBackend::Farm`] the playnet
    /// certificate chains to a public CA and `None` is returned.
    ///
    /// This covers the gateway only. Clients that dial an API boundary node
    /// directly still need `danger_accept_invalid_certs`, and for a different
    /// reason: `IcNodeSnapshot::get_public_url` hands them an IP-literal URL, which
    /// no name in the node's certificate can match. (Whether that certificate has a
    /// CA at all depends on the test — under `with_api_boundary_nodes_playnet` it
    /// is issued by `LocalApiBoundaryNodesPlaynet`'s ephemeral CA, and otherwise the
    /// node self-signs it via `generate_ic_boundary_tls_cert`.)
    pub fn root_certificate(&self) -> Result<Option<reqwest::Certificate>> {
        match SystemTestBackend::read_attribute(&self.env) {
            SystemTestBackend::Local => {
                let cert_pem = dev_root_ca_cert_pem()?;
                let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes())
                    .context("parsing the dev root CA certificate as a trust anchor")?;
                Ok(Some(cert))
            }
            SystemTestBackend::Farm => Ok(None),
        }
    }
}

impl HasTestEnv for DeployedIcGatewayVm {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl SshSession for DeployedIcGatewayVm {
    fn get_host_ip(&self) -> Result<IpAddr> {
        Ok(self.get_vm().ipv6.into())
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
        let universal_vm = UniversalVm::new(name.to_string())
            .with_config_img(get_dependency_path_from_env(
                "IC_GATEWAY_UVM_CONFIG_IMAGE_PATH",
            ))
            .enable_ipv4();
        Self {
            universal_vm,
            enp2s0_config: None,
        }
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

    pub fn with_ipv4_config(mut self, address: &str, gateway: &str) -> Self {
        self.enp2s0_config = Some(format!(
            "\
[Match]
Name=enp2s0

[Network]
Address={address}
Gateway={gateway}"
        ));
        self
    }

    /// Starts the IC Gateway VM, configuring DNS and certificates.
    pub fn start(&self, env: &TestEnv) -> Result<()> {
        let logger = env.logger();
        info!(logger, "Starting IC Gateway VM: {}", self.universal_vm.name);

        // Start the underlying universal VM
        self.universal_vm.start(env)?;
        let deployed_vm = env.get_deployed_universal_vm(&self.universal_vm.name)?;
        let allocated_vm = deployed_vm.get_vm()?;

        let vm_ipv6: Ipv6Addr = allocated_vm.ipv6;

        let vm_ipv4: Option<Ipv4Addr> = if self.universal_vm.has_ipv4 {
            let session = deployed_vm.block_on_ssh_session()?;
            if let Some(enp2s0_config) = self.enp2s0_config.as_ref() {
                info!(
                    logger,
                    "Configuring enp2s0 network interface for VM: {}", self.universal_vm.name
                );
                let _out = deployed_vm.block_on_bash_script_from_session(
                    &session,
                    &format!(
                        "\
set -e
sudo mkdir -p /run/systemd/network
echo '{enp2s0_config}' | sudo tee /run/systemd/network/00-enp2s0.network > /dev/null
sudo networkctl reload
sudo networkctl reconfigure enp2s0
                "
                    ),
                )?;
            }
            let ipv4 = deployed_vm.block_on_ipv4_from_session(&session)?;
            Some(ipv4)
        } else {
            None
        };

        let backend = SystemTestBackend::read_attribute(env);
        let demo_domain_env = std::env::var("DEMO_DOMAIN").ok().filter(|s| !s.is_empty());

        let (ic_gateway_fqdn, cert, aaaa_records, a_records) = match backend {
            SystemTestBackend::Local => {
                // The Local backend has no playnet service, so issue the
                // certificate from the dev root CA and register the domain with
                // the group's own `dnsmasq`.
                let playnet = self.load_or_create_local_playnet(env, vm_ipv6, vm_ipv4)?;
                let fqdn = playnet.playnet_cert.playnet.clone();
                self.configure_dns_records(env, &playnet, &fqdn)?;
                (
                    fqdn,
                    playnet.playnet_cert.cert.clone(),
                    playnet.aaaa_records.clone(),
                    playnet.a_records.clone(),
                )
            }
            SystemTestBackend::Farm => {
                if let Some(demo_domain) = demo_domain_env {
                    let demo =
                        self.load_or_create_demo_domain(env, &demo_domain, vm_ipv6, vm_ipv4)?;
                    let fqdn = demo.demo_cert.domain.clone();
                    self.configure_demo_domain_dns_records(env, &demo, &fqdn)?;
                    (
                        fqdn,
                        demo.demo_cert.cert.clone(),
                        demo.aaaa_records.clone(),
                        demo.a_records.clone(),
                    )
                } else {
                    let playnet = self.load_or_create_playnet(env, vm_ipv6, vm_ipv4)?;
                    let fqdn = playnet.playnet_cert.playnet.clone();
                    self.configure_dns_records(env, &playnet, &fqdn)?;
                    (
                        fqdn,
                        playnet.playnet_cert.cert.clone(),
                        playnet.aaaa_records.clone(),
                        playnet.a_records.clone(),
                    )
                }
            }
        };

        // Emit log events for A and AAAA records
        emit_ic_gateway_records_event(&logger, &ic_gateway_fqdn, &aaaa_records, &a_records);

        // Save playnet configuration and start the gateway
        let playnet_url = Url::parse(&format!("https://{ic_gateway_fqdn}"))?;
        env.write_deployed_ic_gateway(&self.universal_vm.name, &playnet_url, &allocated_vm)?;
        let api_nodes: Vec<IcNodeSnapshot> = env.topology_snapshot().api_boundary_nodes().collect();
        info!(
            logger,
            "Waiting for all API boundary nodes to become healthy ..."
        );
        let api_nodes_urls: Vec<String> = api_nodes
            .iter()
            .map(|node| {
                let url = node.get_public_url().to_string();
                node.await_status_is_healthy()
                    .unwrap_or_else(|_| panic!("Expect {url} to be healthy!"));
                url
            })
            .collect();
        self.start_gateway_container(&deployed_vm, &ic_gateway_fqdn, &cert, api_nodes_urls)?;

        // Wait for the service to become ready.
        // Readiness is defined when some API boundary node used by ic-gateway responds with HTTP 200 to /api/v2/status.
        let health_url = playnet_url.join("/api/v2/status")?;
        let msg = format!(
            "await_status_is_healthy of {} with url {}",
            self.universal_vm.name,
            health_url.as_str()
        );
        // The driver does not use the group's `dnsmasq` as its resolver — it is in
        // the group's network namespace but reads the host's `/etc/resolv.conf`,
        // whose nameserver is unreachable from there — so on the Local backend it
        // has to resolve the gateway domain itself. The certificate needs no such
        // workaround: it is issued by the dev root CA, which is added as a trust
        // anchor rather than skipping verification altogether.
        let (resolve, root_cert) = match backend {
            SystemTestBackend::Local => {
                let resolve = Some((
                    ic_gateway_fqdn.clone(),
                    SocketAddr::new(IpAddr::V6(vm_ipv6), 443),
                ));
                let cert = reqwest::Certificate::from_pem(dev_root_ca_cert_pem()?.as_bytes())
                    .context("parsing the dev root CA certificate as a trust anchor")?;
                (resolve, Some(cert))
            }
            SystemTestBackend::Farm => (None, None),
        };
        block_on(await_status_is_healthy(
            &env.logger(),
            health_url,
            msg,
            resolve,
            root_cert,
        ))
    }

    /// Loads existing playnet configuration or creates a new one.
    fn load_or_create_playnet(
        &self,
        env: &TestEnv,
        uvm_ipv6: Ipv6Addr,
        uvm_ipv4: Option<Ipv4Addr>,
    ) -> Result<Playnet> {
        let logger = env.logger();
        let mut playnet = if Playnet::attribute_exists(env) {
            let playnet: Playnet = Playnet::read_attribute(env);
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

        playnet.aaaa_records.push(uvm_ipv6);
        if let Some(ipv4) = uvm_ipv4 {
            playnet.a_records.push(ipv4);
        }

        // Write/overwrite file
        playnet.write_attribute(env);

        Ok(playnet)
    }

    /// Loads existing configuration or, on the Local backend, issues a
    /// certificate for a deterministic in-group domain from the dev root CA.
    ///
    /// The Local backend has no playnet TLS service. Signing with the CA that
    /// every dev IC-OS image already trusts (see [`DevRootCa`]), rather than
    /// self-signing, means a *node* can reach the gateway over HTTPS with no
    /// node-side configuration — which is what lets a nested node register
    /// through the gateway exactly as it does on Farm.
    ///
    /// The certificate covers the apex domain and both the `*.<domain>` and
    /// `*.raw.<domain>` wildcards, matching the records the Farm path creates, so
    /// the gateway can also serve canister subdomains. Only the apex is
    /// registered with the group's `dnsmasq` though (see
    /// [`Self::configure_dns_records`]), so a subdomain still has to be resolved
    /// by the client -- see [`DeployedIcGatewayVm::resolve_override_for_url`].
    fn load_or_create_local_playnet(
        &self,
        env: &TestEnv,
        uvm_ipv6: Ipv6Addr,
        uvm_ipv4: Option<Ipv4Addr>,
    ) -> Result<Playnet> {
        let logger = env.logger();
        let mut playnet = if Playnet::attribute_exists(env) {
            let playnet: Playnet = Playnet::read_attribute(env);
            info!(
                logger,
                "Using existing local domain: {}", playnet.playnet_cert.playnet
            );
            playnet
        } else {
            let domain = format!("{}.{IN_GROUP_DOMAIN_SUFFIX}", self.universal_vm.name);
            let ca = dev_root_ca()?;
            let key = KeyPair::generate().context("generating the gateway certificate key")?;
            let cert = CertificateParams::new(vec![
                domain.clone(),
                format!("*.{domain}"),
                // A wildcard matches a single label, so the canonical raw hosts
                // `<canister id>.raw.{domain}` -- which the Farm path gives their
                // own `*.raw` CNAME -- need a SAN of their own.
                format!("*.raw.{domain}"),
            ])
            .context("building the gateway certificate parameters")?
            .signed_by(&key, &ca.cert, &ca.key)
            .context("signing the gateway certificate")?;
            let certificate = Certificate {
                priv_key_pem: key.serialize_pem(),
                cert_pem: cert.pem(),
                // Appended to the served `cert.pem` by `start_gateway_container`.
                // A client that trusts this CA does not actually need it — the leaf
                // is issued by the root directly, so there is no intermediate to
                // supply, and RFC 8446 4.4.2 lets the root be omitted — but it
                // keeps the served chain self-describing when debugging a handshake,
                // and mirrors the shape of Farm's playnet chain.
                chain_pem: ca.cert_pem,
            };
            info!(
                logger,
                "Issued a certificate for local domain {domain} from the dev root CA"
            );
            Playnet {
                playnet_cert: PlaynetCertificate {
                    playnet: domain,
                    cert: certificate,
                },
                aaaa_records: vec![],
                a_records: vec![],
            }
        };

        playnet.aaaa_records.push(uvm_ipv6);
        if let Some(ipv4) = uvm_ipv4 {
            playnet.a_records.push(ipv4);
        }

        // Write/overwrite file
        playnet.write_attribute(env);

        Ok(playnet)
    }

    /// Configures DNS records based on the system-test backend.
    fn configure_dns_records(
        &self,
        env: &TestEnv,
        playnet: &Playnet,
        ic_gateway_fqdn: &str,
    ) -> Result<()> {
        let mut records = match SystemTestBackend::read_attribute(env) {
            SystemTestBackend::Local => {
                // The group's `dnsmasq` is the local replacement for Farm's
                // playnet DNS. Only the apex is registered, because dnsmasq's
                // `--addn-hosts` file is a hosts file and so has no wildcards.
                // Driver-side clients cope by resolving the exact request host
                // themselves, see
                // `DeployedIcGatewayVm::resolve_override_for_url`. Clients *inside*
                // a VM cannot: `prometheus_vm` writes `<canister id>.raw.<domain>`
                // scrape targets that the Prometheus VM resolves through this
                // dnsmasq, and those have never resolved on this backend — the
                // domain was an equally unresolvable `.local` name before. Fixing
                // it means `--address=/<domain>/<addr>` on dnsmasq's command line,
                // which `SIGHUP` does not re-read, so it would have to be known at
                // `start_dnsmasq` time or cost a restart.
                let group_name = GroupSetup::read_attribute(env).infra_group_name;
                let backend = LocalBackend::from_test_env(env)?;
                let addrs = playnet
                    .aaaa_records
                    .iter()
                    .map(|addr| IpAddr::V6(*addr))
                    .chain(playnet.a_records.iter().map(|addr| IpAddr::V4(*addr)));
                for addr in addrs {
                    backend.add_dns_record(&group_name, ic_gateway_fqdn, addr)?;
                }
                return Ok(());
            }
            SystemTestBackend::Farm => {
                vec![
                    DnsRecord {
                        name: "".to_string(),
                        record_type: DnsRecordType::AAAA,
                        records: playnet.aaaa_records.iter().map(|r| r.to_string()).collect(),
                    },
                    DnsRecord {
                        name: "*".to_string(),
                        record_type: DnsRecordType::CNAME,
                        records: vec![ic_gateway_fqdn.to_string()],
                    },
                    DnsRecord {
                        name: "*.raw".to_string(),
                        record_type: DnsRecordType::CNAME,
                        records: vec![ic_gateway_fqdn.to_string()],
                    },
                ]
            }
        };

        if !playnet.a_records.is_empty() {
            records.push(DnsRecord {
                name: "".to_string(),
                record_type: DnsRecordType::A,
                records: playnet.a_records.iter().map(|r| r.to_string()).collect(),
            })
        }

        let base_domain = env.create_playnet_dns_records(records);

        // Wait for DNS propagation by checking a random subdomain
        block_on(await_dns_propagation(&env.logger(), &base_domain))?;

        Ok(())
    }

    /// Starts the IC Gateway docker container.
    fn start_gateway_container(
        &self,
        deployed_universal_vm: &DeployedUniversalVm,
        domain: &str,
        cert: &Certificate,
        api_nodes_urls: Vec<String>,
    ) -> Result<()> {
        let api_nodes_urls = (!api_nodes_urls.is_empty())
            .then(|| api_nodes_urls.join(","))
            .ok_or_else(|| anyhow!("IC Gateway can't start without API boundary nodes"))?;

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
METRICS_LISTEN=[::]:9325
LOG_STDOUT=true
LOG_STDOUT_JSON=true
LOG_LEVEL=info
# For logging each request enable this
# LOG_REQUESTS=true
EOF

# Load the docker image from the tarball
docker load -i /config/ic_gatewayd.tar

# Start ic-gateway service in the background
docker run --name=ic-gateway -d \
  -v /tmp/certs:/certs \
  --network host \
  --env-file ic-gateway.env \
  --log-driver=journald \
  ic_gatewayd:image
"#,
            key = cert.priv_key_pem,
            cert = cert.cert_pem,
            cert_chain = cert.chain_pem,
            ic_url = api_nodes_urls,
            domain = domain,
        );

        deployed_universal_vm.block_on_bash_script(&bash_script)?;
        Ok(())
    }

    /// Loads existing demo-domain configuration or creates a new one by acquiring a
    /// demo certificate for the given `domain`.
    fn load_or_create_demo_domain(
        &self,
        env: &TestEnv,
        domain: &str,
        uvm_ipv6: Ipv6Addr,
        uvm_ipv4: Option<Ipv4Addr>,
    ) -> Result<DemoDomain> {
        let logger = env.logger();
        let mut demo = if DemoDomain::attribute_exists(env) {
            let demo: DemoDomain = DemoDomain::read_attribute(env);
            info!(
                logger,
                "Using existing demo domain: {}", demo.demo_cert.domain
            );
            demo
        } else {
            let demo_cert = env.acquire_demo_certificate(domain);
            info!(logger, "Acquired new demo domain: {}", demo_cert.domain);
            DemoDomain {
                domain: domain.to_string(),
                demo_cert,
                aaaa_records: vec![],
                a_records: vec![],
            }
        };

        demo.aaaa_records.push(uvm_ipv6);
        if let Some(ipv4) = uvm_ipv4 {
            demo.a_records.push(ipv4);
        }

        // Write/overwrite file
        demo.write_attribute(env);

        Ok(demo)
    }

    /// Configures DNS records for the demo-domain flow based on the system-test backend.
    fn configure_demo_domain_dns_records(
        &self,
        env: &TestEnv,
        demo: &DemoDomain,
        ic_gateway_fqdn: &str,
    ) -> Result<()> {
        let mut records = match SystemTestBackend::read_attribute(env) {
            SystemTestBackend::Farm => {
                vec![
                    DnsRecord {
                        name: "".to_string(),
                        record_type: DnsRecordType::AAAA,
                        records: demo.aaaa_records.iter().map(|r| r.to_string()).collect(),
                    },
                    DnsRecord {
                        name: "*".to_string(),
                        record_type: DnsRecordType::CNAME,
                        records: vec![ic_gateway_fqdn.to_string()],
                    },
                    DnsRecord {
                        name: "*.raw".to_string(),
                        record_type: DnsRecordType::CNAME,
                        records: vec![ic_gateway_fqdn.to_string()],
                    },
                ]
            }
            SystemTestBackend::Local => {
                slog::warn!(
                    env.logger(),
                    "LocalBackend: skipping configure_demo_domain_dns_records (no playnet)"
                );
                vec![]
            }
        };

        if !demo.a_records.is_empty() {
            records.push(DnsRecord {
                name: "".to_string(),
                record_type: DnsRecordType::A,
                records: demo.a_records.iter().map(|r| r.to_string()).collect(),
            })
        }

        let base_domain = env.create_demo_dns_records(&demo.domain, records);

        // Wait for DNS propagation by checking a random subdomain
        block_on(await_dns_propagation(&env.logger(), &base_domain))?;

        Ok(())
    }
}

/// Playnet configuration structure.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Playnet {
    pub playnet_cert: PlaynetCertificate,
    pub aaaa_records: Vec<Ipv6Addr>,
    pub a_records: Vec<Ipv4Addr>,
}

impl TestEnvAttribute for Playnet {
    fn attribute_name() -> String {
        String::from("playnet")
    }
}

/// Demo-domain configuration structure, analogous to [`Playnet`] but backed by a
/// [`DemoCertificate`] for a caller-supplied domain.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DemoDomain {
    pub domain: String,
    pub demo_cert: DemoCertificate,
    pub aaaa_records: Vec<Ipv6Addr>,
    pub a_records: Vec<Ipv4Addr>,
}

impl TestEnvAttribute for DemoDomain {
    fn attribute_name() -> String {
        String::from("demo_domain")
    }
}

/// Emits log events for IC gateway A and AAAA records.
fn emit_ic_gateway_records_event(
    log: &slog::Logger,
    ic_gateway_fqdn: &str,
    aaaa_records: &[Ipv6Addr],
    a_records: &[Ipv4Addr],
) {
    #[derive(Deserialize, Serialize)]
    struct IcGatewayARecords {
        url: String,
        a_records: Vec<Ipv4Addr>,
    }

    #[derive(Deserialize, Serialize)]
    struct IcGatewayAAAARecords {
        url: String,
        aaaa_records: Vec<Ipv6Addr>,
    }

    let event_a_record = log_events::LogEvent::new(
        IC_GATEWAY_A_RECORDS_CREATED_EVENT_NAME.to_string(),
        IcGatewayARecords {
            url: ic_gateway_fqdn.to_string(),
            a_records: a_records.to_vec(),
        },
    );
    event_a_record.emit_log(log);

    let event_aaaa_record = log_events::LogEvent::new(
        IC_GATEWAY_AAAA_RECORDS_CREATED_EVENT_NAME.to_string(),
        IcGatewayAAAARecords {
            url: ic_gateway_fqdn.to_string(),
            aaaa_records: aaaa_records.to_vec(),
        },
    );
    event_aaaa_record.emit_log(log);
}

/// Trait for interacting with IC Gateway VMs in a test environment.
pub trait HasIcGatewayVm {
    fn get_deployed_ic_gateway(&self, name: &str) -> Result<DeployedIcGatewayVm>;
    fn get_deployed_ic_gateways(&self) -> Result<Vec<DeployedIcGatewayVm>>;
    fn write_deployed_ic_gateway(
        &self,
        name: &str,
        playnet: &Url,
        allocated_vm: &AllocatedVm,
    ) -> Result<()>;
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

        let playnet_url_path = ic_gateway_abs_dir.join(PLAYNET_URL_FILE);
        let playnet_url: Url = self.read_json_object(&playnet_url_path).with_context(|| {
            format!(
                "Failed to read playnet URL file: {}",
                playnet_url_path.display()
            )
        })?;

        let https_url = playnet_url
            .scheme()
            .eq("https")
            .then(|| playnet_url.clone())
            .context("Expected a TLS URL")?;

        let uvm = self
            .get_deployed_universal_vm(name)
            .context("Failed to retrieve deployed universal VM")?;
        let env = uvm.test_env();
        let vm = uvm.get_vm()?;

        Ok(DeployedIcGatewayVm { env, vm, https_url })
    }

    fn get_deployed_ic_gateways(&self) -> Result<Vec<DeployedIcGatewayVm>> {
        let path = self.get_path(IC_GATEWAY_VMS_DIR);

        // no deployed vms
        if !path.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&path)?;

        let mut gateways = Vec::new();

        for entry_result in entries {
            let entry = entry_result?;
            if entry.path().is_dir() {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                let vm = self.get_deployed_ic_gateway(&dir_name)?;
                gateways.push(vm);
            }
        }

        Ok(gateways)
    }

    fn write_deployed_ic_gateway(
        &self,
        name: &str,
        playnet_url: &Url,
        allocated_vm: &AllocatedVm,
    ) -> Result<()> {
        let path = Path::new(IC_GATEWAY_VMS_DIR).join(name);
        self.write_json_object(path.join(PLAYNET_URL_FILE), playnet_url)?;
        self.write_json_object(path.join(IC_GATEWAY_VM_FILE), allocated_vm)
    }
}

/// Checks if DNS propagation is complete by testing resolution of a random subdomain.
/// This leverages the wildcard DNS records to verify that the domain is properly propagated.
async fn await_dns_propagation(logger: &Logger, base_domain: &str) -> Result<()> {
    use rand::{Rng, distributions::Alphanumeric};

    info!(
        logger,
        "Waiting for DNS propagation of wildcard records for domain: {}", base_domain
    );

    let msg = format!("DNS propagation check for domain {base_domain}");
    retry_with_msg_async!(&msg, logger, READY_TIMEOUT, RETRY_INTERVAL, || async {
        // Generate a random subdomain to test the wildcard record
        let random_subdomain: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();

        let test_domain = format!("{random_subdomain}.{base_domain}");

        match lookup_host(&format!("{test_domain}:443")).await {
            Ok(mut addrs) => {
                if addrs.next().is_some() {
                    info!(
                        logger,
                        "DNS propagation confirmed: {} resolves correctly", test_domain
                    );
                    Ok(())
                } else {
                    bail!("DNS lookup returned no addresses for {}", test_domain)
                }
            }
            Err(e) => {
                bail!("DNS lookup failed for {}: {}", test_domain, e)
            }
        }
    })
    .await
}

async fn await_status_is_healthy(
    logger: &Logger,
    url: Url,
    msg: String,
    resolve: Option<(String, SocketAddr)>,
    root_cert: Option<reqwest::Certificate>,
) -> Result<()> {
    info!(logger, "Waiting for IcGatewayVm to become healthy ...");

    let request = Request::new(Method::GET, url);
    retry_with_msg_async!(&msg, logger, READY_TIMEOUT, RETRY_INTERVAL, || async {
        let mut builder = Client::builder();
        // On the Local backend the driver cannot resolve the gateway domain, so
        // point it at the VM directly, and trust the CA that issued the
        // certificate.
        if let Some((domain, addr)) = resolve.as_ref() {
            builder = builder.resolve(domain, *addr);
        }
        if let Some(cert) = root_cert.as_ref() {
            builder = builder.add_root_certificate(cert.clone());
        }
        let client = builder.build()?;
        let response = client
            .execute(request.try_clone().unwrap())
            .await
            .context("failed to execute request")?;
        if response.status() == StatusCode::OK {
            return Ok(());
        }
        bail!("ic-gateway not ready yet ...")
    })
    .await
}
