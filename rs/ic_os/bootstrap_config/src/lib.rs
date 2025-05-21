use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;

/// Configuration options for bootstrap image/tar creation
#[derive(Default, Debug, Clone)]
pub struct BootstrapOptions {
    /// Path to the serialized GuestOS config object
    pub guestos_config: Option<PathBuf>,

    /// Path to the NNS public key file
    pub nns_public_key: Option<PathBuf>,

    /// Path to the Node Operator private key PEM
    pub node_operator_private_key: Option<PathBuf>,

    /// Path to directory with SSH authorized keys for specific user accounts
    #[cfg(feature = "dev")]
    pub accounts_ssh_authorized_keys: Option<PathBuf>,

    /// Path to injected crypto state directory
    pub ic_crypto: Option<PathBuf>,

    /// Path to injected state directory
    pub ic_state: Option<PathBuf>,

    /// Path to injected initial registry state directory
    pub ic_registry_local_store: Option<PathBuf>,

    /// IPv6 address with netmask (e.g., "dead:beef::1/64")
    pub ipv6_address: Option<String>,

    /// Default IPv6 gateway
    pub ipv6_gateway: Option<String>,

    /// IPv4 address with prefix length (e.g., "18.208.190.35/28")
    pub ipv4_address: Option<String>,

    /// Default IPv4 gateway
    pub ipv4_gateway: Option<String>,

    /// Domain name to assign to the guest
    pub domain: Option<String>,

    /// Node reward type for determining node rewards
    pub node_reward_type: Option<String>,

    /// Hostname for the host (used in logging)
    pub hostname: Option<String>,

    /// Logging hosts to use
    pub elasticsearch_hosts: Vec<String>,

    /// Tags for Filebeat
    pub elasticsearch_tags: Vec<String>,

    /// URL of NNS nodes for sign up or registry access
    pub nns_urls: Vec<String>,

    /// Backup retention time in seconds
    pub backup_retention_time: Option<u64>,

    /// Backup purging interval in seconds
    pub backup_purging_interval: Option<u64>,

    /// Malicious behavior JSON object (for testing)
    pub malicious_behavior: Option<String>,

    /// Query stats epoch length in seconds (for testing)
    pub query_stats_epoch_length: Option<u64>,

    /// IP address of a running bitcoind instance (for testing)
    pub bitcoind_addr: Option<String>,

    /// IP address of a running Jaeger Collector instance (for testing)
    pub jaeger_addr: Option<String>,

    /// URL of the socks proxy to use (for testing)
    pub socks_proxy: Option<String>,
}

/// Generate network configuration content from config.
///
/// The config must be valid.
fn generate_network_conf(config: &BootstrapOptions) -> Result<String> {
    let mut network_conf = String::new();

    if let Some(ipv6_address) = &config.ipv6_address {
        writeln!(network_conf, "ipv6_address={ipv6_address}")?;
    }

    if let Some(ipv6_gateway) = &config.ipv6_gateway {
        writeln!(network_conf, "ipv6_gateway={ipv6_gateway}")?;
    }

    writeln!(
        network_conf,
        "hostname={}",
        valid_hostname_or_error(config)?
    )?;

    if let Some(ipv4_address) = &config.ipv4_address {
        writeln!(network_conf, "ipv4_address={ipv4_address}")?;
    }

    if let Some(ipv4_gateway) = &config.ipv4_gateway {
        writeln!(network_conf, "ipv4_gateway={ipv4_gateway}")?;
    }

    if let Some(domain) = &config.domain {
        writeln!(network_conf, "domain={domain}")?;
    }

    Ok(network_conf)
}

fn valid_hostname_or_error(bootstrap_options: &BootstrapOptions) -> Result<&str> {
    let Some(hostname) = bootstrap_options.hostname.as_ref() else {
        bail!("Hostname is required");
    };

    let pattern = Regex::new(r"^[a-zA-Z][a-zA-Z0-9]*(-[a-zA-Z0-9]+)*$").unwrap();
    if hostname.is_empty() || !pattern.is_match(hostname) {
        bail!("Invalid hostname: '{hostname}'");
    }

    Ok(hostname)
}

/// Build a bootstrap tar file with the given configuration
fn build_bootstrap_tar(out_file: &Path, config: &BootstrapOptions) -> Result<()> {
    // Create temporary directory for bootstrap files
    let bootstrap_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    // Copy files to the temporary directory
    if let Some(guestos_config) = &config.guestos_config {
        fs::copy(guestos_config, bootstrap_dir.path().join("config.json"))
            .context("Failed to copy guestos config")?;
    }

    if let Some(nns_public_key) = &config.nns_public_key {
        fs::copy(
            nns_public_key,
            bootstrap_dir.path().join("nns_public_key.pem"),
        )
        .context("Failed to copy NNS public key")?;
    }

    if let Some(node_operator_private_key) = &config.node_operator_private_key {
        fs::copy(
            node_operator_private_key,
            bootstrap_dir.path().join("node_operator_private_key.pem"),
        )
        .context("Failed to copy node operator private key")?;
    }

    #[cfg(feature = "dev")]
    if let Some(accounts_ssh_authorized_keys) = &config.accounts_ssh_authorized_keys {
        let target_dir = bootstrap_dir.path().join("accounts_ssh_authorized_keys");
        copy_dir_recursively(accounts_ssh_authorized_keys, &target_dir)
            .context("Failed to copy SSH authorized keys")?;
    }

    if let Some(ic_crypto) = &config.ic_crypto {
        copy_dir_recursively(ic_crypto, &bootstrap_dir.path().join("ic_crypto"))
            .context("Failed to copy IC crypto directory")?;
    }

    if let Some(ic_state) = &config.ic_state {
        if ic_state.exists() {
            copy_dir_recursively(ic_state, &bootstrap_dir.path().join("ic_state"))
                .context("Failed to copy IC state directory")?;
        }
    }

    if let Some(ic_registry_local_store) = &config.ic_registry_local_store {
        copy_dir_recursively(
            ic_registry_local_store,
            &bootstrap_dir.path().join("ic_registry_local_store"),
        )
        .context("Failed to copy registry local store")?;
    }

    // Create network.conf
    fs::write(
        bootstrap_dir.path().join("network.conf"),
        generate_network_conf(config)?,
    )
    .context("Failed to write network.conf")?;

    // Create reward.conf if node_reward_type is set
    if let Some(node_reward_type) = &config.node_reward_type {
        fs::write(
            bootstrap_dir.path().join("reward.conf"),
            format!("node_reward_type={node_reward_type}\n"),
        )
        .context("Failed to write reward.conf")?;
    }

    // Create filebeat.conf if elasticsearch_hosts is set
    if !config.elasticsearch_hosts.is_empty() {
        let space_separated_hosts = config.elasticsearch_hosts.join(" ");
        let mut filebeat_config = File::create(bootstrap_dir.path().join("filebeat.conf"))
            .context("Failed to create filebeat.conf")?;

        writeln!(
            filebeat_config,
            "elasticsearch_hosts={space_separated_hosts}"
        )?;
        if !&config.elasticsearch_tags.is_empty() {
            let space_separated_tags = config.elasticsearch_tags.join(" ");
            writeln!(filebeat_config, "elasticsearch_tags={space_separated_tags}")?;
        }
    }

    // Create nns.conf if nns_urls are available
    if !config.nns_urls.is_empty() {
        let comma_separated_urls = config.nns_urls.join(",");
        fs::write(
            bootstrap_dir.path().join("nns.conf"),
            format!("nns_url={comma_separated_urls}\n"),
        )
        .context("Failed to write nns.conf")?;
    }

    // Create backup.conf if backup settings are set
    if let Some(backup_retention_time) = config.backup_retention_time {
        let mut backup_conf = File::create(&bootstrap_dir.path().join("backup.conf"))
            .context("Failed to create backup.conf")?;

        writeln!(
            backup_conf,
            "backup_retention_time_secs={backup_retention_time}"
        )?;

        if let Some(backup_purging_interval) = config.backup_purging_interval {
            writeln!(
                backup_conf,
                "backup_puging_interval_secs={backup_purging_interval}"
            )?;
        }
    }

    // Create malicious_behavior.conf if malicious_behavior is set
    if let Some(malicious_behavior) = &config.malicious_behavior {
        fs::write(
            bootstrap_dir.path().join("malicious_behavior.conf"),
            format!("malicious_behavior={malicious_behavior}\n"),
        )
        .context("Failed to write malicious_behavior.conf")?;
    }

    // Create query_stats.conf if query_stats_epoch_length is set
    if let Some(query_stats_epoch_length) = config.query_stats_epoch_length {
        fs::write(
            bootstrap_dir.path().join("query_stats.conf"),
            format!("query_stats_epoch_length={query_stats_epoch_length}\n"),
        )
        .context("Failed to write query_stats.conf")?;
    }

    // Create bitcoind_addr.conf if bitcoind_addr is set
    if let Some(bitcoind_addr) = &config.bitcoind_addr {
        fs::write(
            bootstrap_dir.path().join("bitcoind_addr.conf"),
            format!("bitcoind_addr={bitcoind_addr}\n"),
        )
        .context("Failed to write bitcoind_addr.conf")?;
    }

    // Create jaeger_addr.conf if jaeger_addr is set
    if let Some(jaeger_addr) = &config.jaeger_addr {
        fs::write(
            bootstrap_dir.path().join("jaeger_addr.conf"),
            format!("jaeger_addr=http://{jaeger_addr}\n"),
        )
        .context("Failed to write jaeger_addr.conf")?;
    }

    // Create socks_proxy.conf if socks_proxy is set
    if let Some(socks_proxy) = &config.socks_proxy {
        fs::write(
            bootstrap_dir.path().join("socks_proxy.conf"),
            format!("socks_proxy={socks_proxy}\n"),
        )
        .context("Failed to write socks_proxy.conf")?;
    }

    // Create tar file
    let status = Command::new("tar")
        .arg("cf")
        .arg(out_file)
        .arg("--sort=name")
        .arg("--owner=root:0")
        .arg("--group=root:0")
        .arg("--mtime=UTC 1970-01-01 00:00:00")
        .arg("-C")
        .arg(bootstrap_dir.path())
        .arg(".")
        .status()
        .context("Failed to execute tar command")?;

    if !status.success() {
        bail!("Failed to create tar file: {status}");
    }

    Ok(())
}

/// Build a bootstrap disk image with the given configuration
pub fn build_bootstrap_config_image(out_file: &Path, config: &BootstrapOptions) -> Result<()> {
    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    // Create bootstrap tar
    let tar_path = tmp_dir.path().join("ic-bootstrap.tar");
    build_bootstrap_tar(&tar_path, config)?;

    let tar_size = fs::metadata(&tar_path)
        .context("Failed to get tar file metadata")?
        .len();

    // Calculate the disk image size (2 * tar_size + 1MB)
    let image_size = 2 * tar_size + 1_048_576;

    // Create an empty file of the calculated size
    let file = File::create(out_file).context("Failed to create output file")?;
    file.set_len(image_size)
        .context("Failed to set output file size")?;

    // Format the disk image as FAT
    let status = Command::new("mkfs.vfat")
        .arg("-n")
        .arg("CONFIG")
        .arg(out_file)
        .status()
        .context("Failed to execute mkfs.vfat command")?;

    if !status.success() {
        bail!("Failed to format disk image: {status}");
    }

    // Copy the tar file to the disk image
    let status = Command::new("mcopy")
        .arg("-i")
        .arg(out_file)
        .arg("-o")
        .arg(&tar_path)
        .arg("::")
        .status()
        .context("Failed to execute mcopy command")?;

    if !status.success() {
        bail!("Failed to copy tar to disk image: {status}");
    }

    Ok(())
}

fn copy_dir_recursively(src: &Path, dst: &Path) -> Result<()> {
    if !Command::new("cp")
        .arg("-r")
        .arg(src)
        .arg(dst)
        .status()
        .context(format!(
            "Failed to copy {} to {}",
            src.display(),
            dst.display()
        ))?
        .success()
    {
        bail!("Failed to copy {} to {}", src.display(), dst.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_hostname() {
        fn is_valid_hostname(hostname: &str) -> bool {
            let mut config = BootstrapOptions::default();
            config.hostname = Some(hostname.to_string());
            valid_hostname_or_error(&config).is_ok()
        }

        // Valid hostnames
        assert!(is_valid_hostname("hostname"));
        assert!(is_valid_hostname("hostname123"));
        assert!(is_valid_hostname("hostname-part2"));
        assert!(is_valid_hostname("h-1-2-3"));

        // Invalid hostnames
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("123hostname"));
        assert!(!is_valid_hostname("hostname-"));
        assert!(!is_valid_hostname("-hostname"));
        assert!(!is_valid_hostname("hostname_invalid"));
        assert!(!is_valid_hostname("hostname with spaces"));
    }

    #[test]
    fn test_build_bootstrap_tar_fails_with_default_options() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let out_file = tmp_dir.path().join("bootstrap.tar");

        let config = BootstrapOptions::default();

        assert!(build_bootstrap_tar(&out_file, &config).is_err());
    }

    #[test]
    fn test_build_bootstrap_tar() -> Result<()> {
        // Create a temporary directory for the test
        let tmp_dir = tempfile::tempdir()?;
        let out_file = tmp_dir.path().join("bootstrap.tar");

        // Create a minimal valid configuration
        let mut config = BootstrapOptions::default();
        config.hostname = Some("testhostname".to_string());
        config.ipv6_address = Some("2001:db8::1/64".to_string());

        // Create a test file to be included in the tar
        let test_config_path = tmp_dir.path().join("test_config.json");
        fs::write(&test_config_path, r#"{"test": "value"}"#)?;
        config.guestos_config = Some(test_config_path);

        // Build the tar file
        build_bootstrap_tar(&out_file, &config)?;

        // Extract the tar file to verify contents
        let extract_dir = tmp_dir.path().join("extract");
        fs::create_dir(&extract_dir)?;

        let status = Command::new("tar")
            .arg("xf")
            .arg(&out_file)
            .arg("-C")
            .arg(&extract_dir)
            .status()?;
        assert!(status.success());

        // Verify network.conf contents
        let network_conf = fs::read_to_string(extract_dir.join("network.conf"))?;
        assert_eq!(
            network_conf,
            "ipv6_address=2001:db8::1/64\n\
             hostname=testhostname\n"
        );

        // Verify config.json contents
        let config_json = fs::read_to_string(extract_dir.join("config.json"))?;
        assert_eq!(config_json, r#"{"test": "value"}"#);

        Ok(())
    }

    #[test]
    fn test_build_bootstrap_tar_with_all_options() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        let out_file = tmp_dir.path().join("bootstrap.tar");

        // Create test files and directories
        let test_files_dir = tmp_dir.path().join("test_files");
        fs::create_dir(&test_files_dir)?;

        let config_path = test_files_dir.join("config.json");
        fs::write(&config_path, r#"{"test": "config"}"#)?;

        let nns_key_path = test_files_dir.join("nns.pem");
        fs::write(&nns_key_path, "test_nns_key")?;

        let node_key_path = test_files_dir.join("node.pem");
        fs::write(&node_key_path, "test_node_key")?;

        let ssh_keys_dir = test_files_dir.join("ssh_keys");
        fs::create_dir(&ssh_keys_dir)?;
        fs::write(ssh_keys_dir.join("key1"), "ssh_key1")?;

        let crypto_dir = test_files_dir.join("crypto");
        fs::create_dir(&crypto_dir)?;
        fs::write(crypto_dir.join("test"), "crypto_data")?;

        let state_dir = test_files_dir.join("state");
        fs::create_dir(&state_dir)?;
        fs::write(state_dir.join("test"), "state_data")?;

        let registry_dir = test_files_dir.join("registry");
        fs::create_dir(&registry_dir)?;
        fs::write(registry_dir.join("test"), "registry_data")?;

        // Create full configuration
        let config = BootstrapOptions {
            hostname: Some("fulltest".to_string()),
            guestos_config: Some(config_path),
            nns_public_key: Some(nns_key_path),
            node_operator_private_key: Some(node_key_path),
            #[cfg(feature = "dev")]
            accounts_ssh_authorized_keys: Some(ssh_keys_dir),
            ic_crypto: Some(crypto_dir),
            ic_state: Some(state_dir),
            ic_registry_local_store: Some(registry_dir),
            ipv6_address: Some("2001:db8::1/64".to_string()),
            ipv6_gateway: Some("2001:db8::ff".to_string()),
            ipv4_address: Some("192.168.1.1/24".to_string()),
            ipv4_gateway: Some("192.168.1.254".to_string()),
            domain: Some("test.domain".to_string()),
            node_reward_type: Some("test_reward".to_string()),
            elasticsearch_hosts: vec!["host1".to_string(), "host2".to_string()],
            elasticsearch_tags: vec!["tag1".to_string(), "tag2".to_string()],
            nns_urls: vec!["url1".to_string(), "url2".to_string()],
            backup_retention_time: Some(3600),
            backup_purging_interval: Some(300),
            malicious_behavior: Some(r#"{"type": "test"}"#.to_string()),
            query_stats_epoch_length: Some(60),
            bitcoind_addr: Some("127.0.0.1:8332".to_string()),
            jaeger_addr: Some("127.0.0.1:14250".to_string()),
            socks_proxy: Some("socks5://127.0.0.1:1080".to_string()),
        };

        // Build and extract tar
        build_bootstrap_tar(&out_file, &config)?;
        let extract_dir = tmp_dir.path().join("extract");
        fs::create_dir(&extract_dir)?;
        Command::new("tar")
            .arg("xf")
            .arg(&out_file)
            .arg("-C")
            .arg(&extract_dir)
            .status()?;

        // Verify all files
        assert_eq!(
            fs::read_to_string(extract_dir.join("config.json"))?,
            r#"{"test": "config"}"#
        );
        assert_eq!(
            fs::read_to_string(extract_dir.join("nns_public_key.pem"))?,
            "test_nns_key"
        );
        assert_eq!(
            fs::read_to_string(extract_dir.join("node_operator_private_key.pem"))?,
            "test_node_key"
        );

        let network_conf = fs::read_to_string(extract_dir.join("network.conf"))?;
        assert!(network_conf.contains("hostname=fulltest\n"));
        assert!(network_conf.contains("ipv6_address=2001:db8::1/64\n"));
        assert!(network_conf.contains("ipv6_gateway=2001:db8::ff\n"));
        assert!(network_conf.contains("ipv4_address=192.168.1.1/24\n"));
        assert!(network_conf.contains("ipv4_gateway=192.168.1.254\n"));
        assert!(network_conf.contains("domain=test.domain\n"));

        assert_eq!(
            fs::read_to_string(extract_dir.join("reward.conf"))?,
            "node_reward_type=test_reward\n"
        );

        let filebeat_conf = fs::read_to_string(extract_dir.join("filebeat.conf"))?;
        assert!(filebeat_conf.contains("elasticsearch_hosts=host1 host2\n"));
        assert!(filebeat_conf.contains("elasticsearch_tags=tag1 tag2\n"));

        assert_eq!(
            fs::read_to_string(extract_dir.join("nns.conf"))?,
            "nns_url=url1,url2\n"
        );

        let backup_conf = fs::read_to_string(extract_dir.join("backup.conf"))?;
        assert!(backup_conf.contains("backup_retention_time_secs=3600\n"));
        assert!(backup_conf.contains("backup_puging_interval_secs=300\n"));

        assert_eq!(
            fs::read_to_string(extract_dir.join("malicious_behavior.conf"))?,
            "malicious_behavior={\"type\": \"test\"}\n"
        );

        assert_eq!(
            fs::read_to_string(extract_dir.join("query_stats.conf"))?,
            "query_stats_epoch_length=60\n"
        );

        assert_eq!(
            fs::read_to_string(extract_dir.join("bitcoind_addr.conf"))?,
            "bitcoind_addr=127.0.0.1:8332\n"
        );

        assert_eq!(
            fs::read_to_string(extract_dir.join("jaeger_addr.conf"))?,
            "jaeger_addr=http://127.0.0.1:14250\n"
        );

        assert_eq!(
            fs::read_to_string(extract_dir.join("socks_proxy.conf"))?,
            "socks_proxy=socks5://127.0.0.1:1080\n"
        );

        Ok(())
    }
}
