use anyhow::{bail, Context, Result};
use askama::Template;
use clap::Parser;
use config::guestos_bootstrap_image::BootstrapOptions;
use config::guestos_config::generate_guestos_config;
use config::{serialize_and_write_config, DEFAULT_HOSTOS_CONFIG_OBJECT_PATH};
use config_types::{GuestOSConfig, HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant};
use ic_metrics_tool::{Metric, MetricsWriter};
use macaddr::MacAddr6;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Generate the GuestOS VM configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct GenerateGuestVmConfigArgs {
    /// Specify the config media image file
    #[arg(short, long, default_value = "/run/ic-node/config.img")]
    media: PathBuf,

    /// Specify the output configuration file
    #[arg(short, long, default_value = "/var/lib/libvirt/guestos.xml")]
    output: PathBuf,

    /// Path to the input HostOS config file
    #[arg(short, long, default_value = DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)]
    config: PathBuf,
}

/// Generate the GuestOS VM configuration by assembling the bootstrap config media image
/// and creating the libvirt XML configuration file.
pub fn generate_guest_vm_config(args: GenerateGuestVmConfigArgs) -> Result<()> {
    let metrics_writer = MetricsWriter::new(PathBuf::from(
        "/run/node_exporter/collector_textfile/hostos_generate_guestos_config.prom",
    ));

    run(args, &metrics_writer, restorecon)
}

fn run(
    args: GenerateGuestVmConfigArgs,
    metrics_writer: &MetricsWriter,
    // We pass a functor to allow mocking in tests.
    restorecon: impl Fn(&Path) -> Result<()>,
) -> Result<()> {
    let hostos_config: HostOSConfig = serde_json::from_reader(
        File::open(&args.config).context("Failed to open HostOS config file")?,
    )
    .context("Failed to parse HostOS config file")?;

    assemble_config_media(&hostos_config, &args.media)
        .context("Failed to assemble config media")?;

    if args.output.exists() {
        metrics_writer.write_metrics(&[Metric::with_annotation(
            "hostos_generate_guestos_config",
            0.0,
            "HostOS generate GuestOS config",
        )])?;

        bail!(
            "GuestOS configuration file already exists: {}",
            args.output.display()
        );
    }

    let output_path = &args.output;

    // Create parent directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    File::create(output_path)
        .context("Failed to create output file")?
        .write_all(generate_vm_config(&hostos_config, &args.media)?.as_bytes())
        .context("Failed to write output file")?;

    // Restore SELinux security context
    if let Some(parent) = output_path.parent() {
        restorecon(parent)?
    }

    println!(
        "Generating GuestOS configuration file: {}",
        output_path.display(),
    );

    metrics_writer.write_metrics(&[Metric::with_annotation(
        "hostos_generate_guestos_config",
        1.0,
        "HostOS generate GuestOS config",
    )])?;

    Ok(())
}

fn assemble_config_media(hostos_config: &HostOSConfig, media_path: &Path) -> Result<()> {
    let guestos_config_file = tempfile::NamedTempFile::new()?;
    let guestos_config =
        generate_guestos_config(hostos_config).context("Failed to generate GuestOS config")?;
    serialize_and_write_config(guestos_config_file.path(), &guestos_config).with_context(|| {
        format!(
            "Failed to write GuestOS config to {}",
            guestos_config_file.path().display()
        )
    })?;

    let bootstrap_options =
        make_bootstrap_options(hostos_config, guestos_config, guestos_config_file.path())?;

    bootstrap_options.build_bootstrap_config_image(media_path)?;

    println!(
        "Assembling config media for GuestOS: {}",
        media_path.display()
    );

    Ok(())
}

fn make_bootstrap_options(
    hostos_config: &HostOSConfig,
    guestos_config: GuestOSConfig,
    guestos_config_path: &Path,
) -> Result<BootstrapOptions> {
    let mut bootstrap_options = BootstrapOptions {
        guestos_config: Some(guestos_config_path.to_path_buf()),
        ..Default::default()
    };

    #[cfg(feature = "dev")]
    if hostos_config.icos_settings.use_ssh_authorized_keys {
        bootstrap_options.accounts_ssh_authorized_keys =
            Some(PathBuf::from("/boot/config/ssh_authorized_keys"));
    }

    if hostos_config.icos_settings.use_nns_public_key {
        bootstrap_options.nns_public_key = Some(PathBuf::from("/boot/config/nns_public_key.pem"));
    }

    if hostos_config.icos_settings.use_node_operator_private_key {
        bootstrap_options.node_operator_private_key =
            Some(PathBuf::from("/boot/config/node_operator_private_key.pem"));
    }

    let guestos_ipv6_config = match guestos_config.network_settings.ipv6_config {
        Ipv6Config::Fixed(ip_config) => ip_config,
        _ => bail!(
            "Expected GuestOS IPv6 address to be fixed but was {:?}",
            guestos_config.network_settings.ipv6_config
        ),
    };
    bootstrap_options.ipv6_address = Some(guestos_ipv6_config.address);
    bootstrap_options.ipv6_gateway = Some(guestos_ipv6_config.gateway.to_string());

    if let Some(ipv4_config) = &hostos_config.network_settings.ipv4_config {
        bootstrap_options.ipv4_address = Some(format!(
            "{}/{}",
            ipv4_config.address, ipv4_config.prefix_length
        ));
        bootstrap_options.ipv4_gateway = Some(ipv4_config.gateway.to_string());
    }

    if let Some(domain) = &hostos_config.network_settings.domain_name {
        bootstrap_options.domain = Some(domain.clone());
    }

    if let Some(node_reward_type) = &hostos_config.icos_settings.node_reward_type {
        bootstrap_options.node_reward_type = Some(node_reward_type.clone());
    }

    let hostname = format!(
        "guest-{}",
        hostos_config
            .icos_settings
            .mgmt_mac
            .to_string()
            .replace(":", "")
    );
    bootstrap_options.hostname = Some(hostname);

    bootstrap_options.nns_urls = hostos_config
        .icos_settings
        .nns_urls
        .iter()
        .map(|url| url.to_string())
        .collect();

    Ok(bootstrap_options)
}

/// Generate the GuestOS VM libvirt XML configuration and return it as String.
fn generate_vm_config(config: &HostOSConfig, media_path: &Path) -> Result<String> {
    // If you get a compile error pointing at #[derive(Template)], there is likely a syntax error in
    // the template.
    #[derive(Template)]
    #[template(path = "guestos_vm_template.xml")]
    pub struct GuestOSTemplateProps<'a> {
        pub cpu_domain: &'a str,
        pub vm_memory: u32,
        pub nr_of_vcpus: u32,
        pub mac_address: MacAddr6,
        pub config_media: &'a str,
    }

    let mac_address = calculate_deterministic_mac(
        &config.icos_settings.mgmt_mac,
        config.icos_settings.deployment_environment,
        IpVariant::V6,
        NodeType::GuestOS,
    );

    let cpu_domain = if config.hostos_settings.vm_cpu == "qemu" {
        "qemu"
    } else {
        "kvm"
    };

    GuestOSTemplateProps {
        cpu_domain,
        vm_memory: config.hostos_settings.vm_memory,
        nr_of_vcpus: config.hostos_settings.vm_nr_of_vcpus,
        mac_address,
        config_media: &media_path.display().to_string(),
    }
    .render()
    .context("Failed to render GuestOS VM XML template")
}

fn restorecon(path: &Path) -> Result<()> {
    Command::new("restorecon")
        .arg("-R")
        .arg(path)
        .status()?
        .success()
        .then_some(())
        .context("Failed to run restorecon")
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSConfig, HostOSSettings, ICOSSettings,
        Ipv4Config, Ipv6Config, Logging, NetworkSettings,
    };
    use goldenfile::Mint;
    use std::env;
    use std::os::unix::prelude::MetadataExt;
    use std::path::Path;
    use tempfile::tempdir;

    fn create_test_hostos_config() -> HostOSConfig {
        HostOSConfig {
            config_version: "1.0".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::ffff".parse().unwrap(),
                }),
                ipv4_config: Some(Ipv4Config {
                    address: "192.168.1.2".parse().unwrap(),
                    gateway: "192.168.1.1".parse().unwrap(),
                    prefix_length: 24,
                }),
                domain_name: Some("test.domain".to_string()),
            },
            icos_settings: ICOSSettings {
                node_reward_type: Some("type3.1".to_string()),
                mgmt_mac: "00:11:22:33:44:55".parse().unwrap(),
                deployment_environment: DeploymentEnvironment::Testnet,
                logging: Logging {
                    elasticsearch_hosts: None,
                    elasticsearch_tags: None,
                },
                use_nns_public_key: false,
                nns_urls: vec![url::Url::parse("https://example.com").unwrap()],
                use_node_operator_private_key: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            hostos_settings: HostOSSettings {
                vm_memory: 490,
                vm_cpu: "qemu".to_string(),
                vm_nr_of_vcpus: 56,
                verbose: false,
            },
            guestos_settings: Default::default(),
        }
    }

    fn mock_restorecon(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[test]
    fn test_make_bootstrap_options() {
        let mut config = create_test_hostos_config();
        config.icos_settings.use_nns_public_key = true;
        config.icos_settings.use_ssh_authorized_keys = true;
        config.icos_settings.use_node_operator_private_key = true;

        let guestos_config = generate_guestos_config(&config).unwrap();

        let options =
            make_bootstrap_options(&config, guestos_config, Path::new("/tmp/test")).unwrap();

        assert_eq!(
            options,
            BootstrapOptions {
                ipv6_address: Some("2001:db8::6801:aeff:fe1a:9bb/64".to_string()),
                ipv6_gateway: Some("2001:db8::ffff".to_string()),
                ipv4_address: Some("192.168.1.2/24".to_string()),
                ipv4_gateway: Some("192.168.1.1".to_string()),
                domain: Some("test.domain".to_string()),
                node_reward_type: Some("type3.1".to_string()),
                hostname: Some("guest-001122334455".to_string()),
                nns_urls: vec!["https://example.com/".to_string()],
                guestos_config: Some(PathBuf::from("/tmp/test")),
                nns_public_key: Some(PathBuf::from("/boot/config/nns_public_key.pem")),
                node_operator_private_key: Some(PathBuf::from(
                    "/boot/config/node_operator_private_key.pem"
                )),
                accounts_ssh_authorized_keys: Some(PathBuf::from(
                    "/boot/config/ssh_authorized_keys"
                )),
                ..Default::default()
            }
        );
    }

    fn goldenfiles_path() -> PathBuf {
        let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("golden");
        path
    }

    #[test]
    fn test_generate_vm_config_qemu() {
        let mut mint = Mint::new(goldenfiles_path());
        let mut config = create_test_hostos_config();

        config.hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: "qemu".to_string(),
            vm_nr_of_vcpus: 56,
            verbose: true,
        };

        let vm_config = generate_vm_config(&config, Path::new("/tmp/config.img")).unwrap();

        fs::write(
            mint.new_goldenpath("guestos_vm_qemu.xml").unwrap(),
            vm_config,
        )
        .unwrap();
    }

    #[test]
    fn test_generate_vm_config_kvm() {
        let mut mint = Mint::new(goldenfiles_path());
        let mut config = create_test_hostos_config();
        config.hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: "kvm".to_string(),
            vm_nr_of_vcpus: 56,
            verbose: false,
        };

        let vm_config = generate_vm_config(&config, Path::new("/tmp/config.img")).unwrap();

        fs::write(
            mint.new_goldenpath("guestos_vm_kvm.xml").unwrap(),
            vm_config,
        )
        .unwrap();
    }

    #[test]
    fn test_run_success() {
        let temp_dir = tempdir().unwrap();
        let hostos_config_path = temp_dir.path().join("hostos.json");
        let media_path = temp_dir.path().join("config.img");
        let output_path = temp_dir.path().join("guestos.xml");
        let metrics_path = temp_dir.path().join("metrics.prom");

        serialize_and_write_config(&hostos_config_path, &create_test_hostos_config()).unwrap();

        let args = GenerateGuestVmConfigArgs {
            media: media_path.clone(),
            output: output_path.clone(),
            config: hostos_config_path.clone(),
        };

        let result = run(
            args,
            &MetricsWriter::new(metrics_path.clone()),
            mock_restorecon,
        );
        assert!(result.is_ok(), "{result:?}");

        assert_eq!(
            fs::read_to_string(metrics_path).unwrap(),
            "# HELP hostos_generate_guestos_config HostOS generate GuestOS config\n\
             # TYPE hostos_generate_guestos_config counter\n\
             hostos_generate_guestos_config 1\n"
        );

        assert!(media_path.metadata().unwrap().size() > 0);
        assert!(output_path.metadata().unwrap().size() > 0);
    }

    #[test]
    fn test_run_existing_output_file() {
        let temp_dir = tempdir().unwrap();
        let hostos_config_path = temp_dir.path().join("hostos.json");
        let media_path = temp_dir.path().join("config.img");
        let output_path = temp_dir.path().join("guestos.xml");
        let metrics_path = temp_dir.path().join("metrics.prom");

        serialize_and_write_config(&hostos_config_path, &create_test_hostos_config()).unwrap();

        // Create the output file so it already exists
        fs::write(&output_path, "test").unwrap();

        let args = GenerateGuestVmConfigArgs {
            media: media_path,
            output: output_path,
            config: hostos_config_path,
        };

        let result_err = run(
            args,
            &MetricsWriter::new(metrics_path.clone()),
            mock_restorecon,
        )
        .unwrap_err();

        assert!(
            result_err.to_string().contains("already exists"),
            "{result_err:?}"
        );

        assert_eq!(
            fs::read_to_string(metrics_path).unwrap(),
            "# HELP hostos_generate_guestos_config HostOS generate GuestOS config\n\
             # TYPE hostos_generate_guestos_config counter\n\
             hostos_generate_guestos_config 0\n"
        )
    }
}
