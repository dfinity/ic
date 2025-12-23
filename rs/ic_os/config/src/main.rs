use anyhow::Result;
use clap::{Parser, Subcommand};
use config::guestos::bootstrap_ic_node::populate_nns_public_key;
use config::guestos::{bootstrap_ic_node::bootstrap_ic_node, generate_ic_config};
use config::serialize_and_write_config;
use config::setupos::config_ini::{ConfigIniSettings, get_config_ini_settings};
use config::setupos::deployment_json::{VmResources, get_deployment_settings};
use config_types::*;
use macaddr::MacAddr6;
use network::resolve_mgmt_mac;
use regex::Regex;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Creates SetupOSConfig object
    CreateSetuposConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH, value_name = "config.ini")]
        config_ini_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH, value_name = "deployment.json")]
        deployment_json_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, value_name = "config.json")]
        setupos_config_json_path: PathBuf,
    },
    /// Creates HostOSConfig object from existing SetupOS config.json file
    GenerateHostosConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, value_name = "config.json")]
        setupos_config_json_path: PathBuf,
        #[arg(long, default_value = config::DEFAULT_SETUPOS_HOSTOS_CONFIG_OBJECT_PATH, value_name = "config-hostos.json")]
        hostos_config_json_path: PathBuf,
    },
    /// Bootstrap IC Node from a bootstrap package
    BootstrapICNode {
        #[arg(long, default_value = config::DEFAULT_BOOTSTRAP_DIR, value_name = "bootstrap_dir")]
        bootstrap_dir: PathBuf,
    },
    /// Generate IC configuration from template and guestos config
    GenerateICConfig {
        #[arg(long, default_value = config::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, value_name = "config-guestos.json")]
        guestos_config_json_path: PathBuf,
        #[arg(long, default_value = config::DEFAULT_IC_JSON5_OUTPUT_PATH, value_name = "ic.json5")]
        output_path: PathBuf,
    },
    PopulateNnsPublicKey {
        #[arg(long, default_value = config::DEFAULT_BOOTSTRAP_DIR, value_name = "bootstrap_dir")]
        bootstrap_dir: PathBuf,
    },
}

#[derive(Parser)]
#[command()]
struct ConfigArgs {
    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    let opts = ConfigArgs::parse();

    match opts.command {
        Some(Commands::CreateSetuposConfig {
            config_ini_path,
            deployment_json_path,
            setupos_config_json_path,
        }) => {
            // get config.ini settings
            let ConfigIniSettings {
                ipv6_prefix,
                ipv6_prefix_length,
                ipv6_gateway,
                ipv4_address,
                ipv4_gateway,
                ipv4_prefix_length,
                domain_name,
                verbose,
                node_reward_type,
                enable_trusted_execution_environment,
            } = get_config_ini_settings(&config_ini_path)?;

            // get deployment.json variables
            let deployment_json_settings = get_deployment_settings(&deployment_json_path)?;

            // create NetworkSettings
            let deterministic_config = DeterministicIpv6Config {
                prefix: ipv6_prefix,
                prefix_length: ipv6_prefix_length,
                gateway: ipv6_gateway,
            };

            let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length) {
                (Some(address), Some(gateway), Some(prefix_length)) => Some(Ipv4Config {
                    address,
                    gateway,
                    prefix_length,
                }),
                (None, None, None) => None,
                _ => {
                    println!(
                        "Warning: Partial IPv4 configuration provided. All parameters are required for IPv4 configuration."
                    );
                    None
                }
            };

            let network_settings = NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(deterministic_config),
                ipv4_config,
                domain_name,
            };

            let mgmt_mac =
                resolve_mgmt_mac(deployment_json_settings.deployment.mgmt_mac.as_deref())?;

            if let Some(ref node_reward_type) = node_reward_type {
                let node_reward_type_pattern = Regex::new(r"^type[0-9]+(\.[0-9])?$")?;
                if !node_reward_type_pattern.is_match(node_reward_type) {
                    anyhow::bail!(
                        "Invalid node_reward_type '{}'. It must match the pattern ^type[0-9]+(\\.[0-9])?$",
                        node_reward_type
                    );
                }
            } else {
                println!("Node reward type is not set. Skipping validation.");
            }

            let use_node_operator_private_key =
                Path::new("/config/node_operator_private_key.pem").exists();
            let use_ssh_authorized_keys = Path::new("/config/ssh_authorized_keys").exists();

            let setupos_config = assemble_setupos_config(
                node_reward_type,
                mgmt_mac,
                deployment_json_settings.deployment.deployment_environment,
                &deployment_json_settings.nns.urls,
                deployment_json_settings.dev_vm_resources,
                enable_trusted_execution_environment,
                use_node_operator_private_key,
                use_ssh_authorized_keys,
                verbose,
                network_settings,
            );

            // SetupOSConfig is safe to log; it does not contain any secret material
            println!("SetupOSConfig: {setupos_config:?}");

            let setupos_config_json_path = Path::new(&setupos_config_json_path);
            serialize_and_write_config(setupos_config_json_path, &setupos_config)?;

            println!(
                "SetupOSConfig has been written to {}",
                setupos_config_json_path.display()
            );

            Ok(())
        }
        Some(Commands::GenerateHostosConfig {
            setupos_config_json_path,
            hostos_config_json_path,
        }) => {
            let setupos_config_json_path = Path::new(&setupos_config_json_path);

            let setupos_config: SetupOSConfig =
                config::deserialize_config(setupos_config_json_path)?;

            let hostos_config = HostOSConfig {
                config_version: setupos_config.config_version,
                network_settings: setupos_config.network_settings,
                icos_settings: setupos_config.icos_settings,
                hostos_settings: setupos_config.hostos_settings,
                guestos_settings: setupos_config.guestos_settings,
            };

            let hostos_config_json_path = Path::new(&hostos_config_json_path);
            serialize_and_write_config(hostos_config_json_path, &hostos_config)?;

            println!(
                "HostOSConfig has been written to {}",
                hostos_config_json_path.display()
            );

            Ok(())
        }
        Some(Commands::BootstrapICNode { bootstrap_dir }) => {
            println!("Bootstrap IC Node from: {}", bootstrap_dir.display());
            bootstrap_ic_node(&bootstrap_dir)
        }
        Some(Commands::PopulateNnsPublicKey { bootstrap_dir }) => {
            println!("Populating NNS key from: {}", bootstrap_dir.display());
            populate_nns_public_key(&bootstrap_dir)
        }
        Some(Commands::GenerateICConfig {
            guestos_config_json_path,
            output_path,
        }) => {
            println!("Generating IC configuration");
            let guestos_config: GuestOSConfig =
                config::deserialize_config(&guestos_config_json_path)?;

            generate_ic_config::generate_ic_config(&guestos_config, &output_path)
        }
        None => {
            println!("No command provided. Use --help for usage information.");
            Ok(())
        }
    }
}

pub fn assemble_setupos_config(
    node_reward_type: Option<String>,
    mgmt_mac: MacAddr6,
    deployment_environment: DeploymentEnvironment,
    nns_urls: &[Url],
    dev_vm_resources: VmResources,
    enable_trusted_execution_environment: bool,
    use_node_operator_private_key: bool,
    use_ssh_authorized_keys: bool,
    verbose: bool,
    network_settings: NetworkSettings,
) -> SetupOSConfig {
    let icos_settings = ICOSSettings {
        node_reward_type,
        mgmt_mac,
        deployment_environment,
        nns_urls: nns_urls.to_vec(),
        use_node_operator_private_key,
        enable_trusted_execution_environment,
        use_ssh_authorized_keys,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    let setupos_settings = SetupOSSettings;

    let hostos_settings = HostOSSettings {
        verbose,
        hostos_dev_settings: HostOSDevSettings {
            vm_memory: dev_vm_resources.memory,
            vm_cpu: dev_vm_resources.cpu,
            vm_nr_of_vcpus: dev_vm_resources.nr_of_vcpus,
        },
    };

    let guestos_settings = GuestOSSettings::default();

    SetupOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings,
        icos_settings,
        setupos_settings,
        hostos_settings,
        guestos_settings,
    }
}
