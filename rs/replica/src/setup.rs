use crate::args::ReplicaArgs;
use clap::Parser;
use ic_config::{crypto::CryptoConfig, Config, ConfigSource, SAMPLE_CONFIG};
use ic_crypto::CryptoComponent;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{fatal, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::types::v1 as pb;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::subnet::{SubnetListRegistry, SubnetRegistry};
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    consensus::catchup::CatchUpPackage, NodeId, RegistryVersion, ReplicaVersion, SubnetId,
};
use std::{env, path::PathBuf, sync::Arc};

/// Parse command-line args into `ReplicaArgs`
pub fn parse_args() -> Result<ReplicaArgs, clap::Error> {
    let args_result = ReplicaArgs::try_parse_from(env::args());

    args_result.map(|args| {
        if args.print_sample_config {
            print!("{}", SAMPLE_CONFIG);
            std::process::exit(0);
        }
        args
    })
}

/// Set the Replica version passed in via command-line
pub fn set_replica_version(args: &Result<ReplicaArgs, clap::Error>, logger: &ReplicaLogger) {
    match args {
        Ok(args) => {
            info!(
                logger,
                "Setting replica version to: {}",
                args.replica_version.as_ref()
            );
            if ReplicaVersion::set_default_version(args.replica_version.clone()).is_err() {
                warn!(
                    logger,
                    "Failed to set replica version, defaulting to: {}",
                    ReplicaVersion::default().as_ref()
                );
            }
        }
        Err(_) => (),
    }
}

/// Parse the catch-up package given via command-line args (if one was given)
pub fn get_catch_up_package(
    replica_args: &Result<ReplicaArgs, clap::Error>,
    logger: &ReplicaLogger,
) -> Option<pb::CatchUpPackage> {
    match replica_args {
        Ok(args) => Some(
            pb::CatchUpPackage::read_from_file(args.catch_up_package.clone()?)
                .map_err(|e| panic!("Failed to load CUP at startup {:?}", e))
                .unwrap(),
        ),
        Err(_) => {
            info!(
                logger,
                "No catch-up package was given via a command-line arg"
            );
            None
        }
    }
}

/// Return the subnet ID of the given node
///
/// First attempts to look up the node's subnet ID in the registry.
///
/// Panic if this fails after some retries. The orchestrator should
/// never have booted a replica if our node ID is not assigned to a subntwork
/// yet.
pub fn get_subnet_id(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
    cup: Option<&CatchUpPackage>,
    logger: &ReplicaLogger,
) -> SubnetId {
    let mut tries = 0;
    loop {
        // If given, use the CUP's registry version else use the latest registry version
        let registry_version = cup
            .as_ref()
            .map(|cup| cup.content.registry_version())
            .unwrap_or_else(|| registry_client.get_latest_version());

        let subnet_ids = registry_client
            .get_subnet_ids(registry_version)
            .ok()
            .flatten()
            .unwrap_or_default();
        info!(logger, "Found subnets {:?}", subnet_ids);

        for subnet_id in subnet_ids {
            let node_ids = registry_client
                .get_node_ids_on_subnet(subnet_id, registry_version)
                .ok()
                .flatten()
                .unwrap_or_default();

            info!(
                logger,
                "Found subnet {} with nodes {:?}", subnet_id, node_ids
            );

            if node_ids.contains(&node_id) {
                return subnet_id;
            }
        }

        tries += 1;
        if tries > 10 {
            panic!(
                "Failed to find a subnet for node {} at registry version {}",
                node_id, registry_version
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Return the subnet type of the given subnet.
pub fn get_subnet_type(
    logger: &ReplicaLogger,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry: &dyn RegistryClient,
) -> SubnetType {
    loop {
        match registry.get_subnet_record(subnet_id, registry_version) {
            Ok(subnet_record) => {
                break match subnet_record {
                    Some(record) => match SubnetType::try_from(record.subnet_type) {
                        Ok(subnet_type) => {
                            info!(
                                logger,
                                "{{subnet_record: Registry subnet record {:?}, subnet_id: {}}}",
                                record,
                                subnet_id
                            );
                            subnet_type
                        }
                        Err(e) => fatal!(logger, "Could not parse SubnetType: {}", e),
                    },
                    // This can only happen if the registry is corrupted, so better to crash.
                    None => fatal!(
                        logger,
                        "Failed to find a subnet record for subnet: {} in the registry.",
                        subnet_id
                    ),
                };
            }
            Err(err) => {
                warn!(
                    logger,
                    "Unable to read the subnet record: {}\nTrying again...",
                    err.to_string(),
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Return the source from which to derive the Replica's config
pub fn get_config_source(replica_args: &Result<ReplicaArgs, clap::Error>) -> ConfigSource {
    match replica_args {
        Ok(args) => ConfigSource::from(args),
        Err(_) => {
            let args: Vec<String> = env::args().collect();
            get_config_source_or_abort(&args)
        }
    }
}

pub fn setup_crypto_registry(
    config: &Config,
    tokio_runtime_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    logger: ReplicaLogger,
) -> (std::sync::Arc<RegistryClientImpl>, CryptoComponent) {
    let data_provider = Arc::new(LocalStoreImpl::new(
        config.registry_client.local_store.clone(),
    ));

    let registry = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(metrics_registry),
    ));

    // The registry must be initialized before setting up the crypto component
    if let Err(e) = registry.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    }

    // TODO(RPL-49): pass in registry_client
    let crypto = setup_crypto_provider(
        &config.crypto,
        tokio_runtime_handle,
        Arc::clone(&registry) as Arc<dyn RegistryClient>,
        logger,
        metrics_registry,
    );

    (registry, crypto)
}

fn get_config_source_or_abort(args: &[String]) -> ConfigSource {
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).skip(1).collect();

    match &arg_refs[..] {
        [] => {
            let path = PathBuf::from("./ic.json5");
            if path.exists() {
                ConfigSource::File(path)
            } else {
                ConfigSource::Default
            }
        }
        ["-"] => ConfigSource::StdIn,
        ["--help"] => abort_print_usage(args),
        ["--sample-config"] => {
            print!("{}", SAMPLE_CONFIG);
            std::process::exit(0);
        }
        [arg] if arg.starts_with("--config=") => {
            ConfigSource::Literal(arg["--config=".len()..].to_string())
        }
        [filename] => ConfigSource::File(PathBuf::from(filename)),
        ["--config", literal] => ConfigSource::Literal((*literal).to_string()),
        _ => abort_print_usage(args),
    }
}

fn abort_print_usage(cmdline_args: &[String]) -> ! {
    eprint!(
        r#"Usage: {0} [OPTIONS] [CONFIG_FILE]
Start an Internet Computer replica with the specified CONFIG_FILE.

When CONFIG_FILE is -, read the config from standard input.

Options:
  --config LITERAL   read the config from LITERAL
  --sample-config    print a sample config and exit
  --sample-registry  print a sample 4 node registry bootstrap config and exit
  --help             display this help and exit

Examples:
  {0}                                 Read the config from the default location.
  {0} ic.toml                         Read the config from ic.toml.
  {0} -                               Read the config from stdin.
  {0} --config '{{http_handler: ..}}' Read the config from the string literal.
"#,
        cmdline_args[0]
    );
    std::process::exit(1);
}

/// Setup a crypto provider provided a `CryptoConfig`, a
/// `RegistryClient`, a `ReplicaLogger`, and a `MetricsRegistry`.
///
/// # Panics
///
/// Panics when no root directory for the cryptography storage can be
/// created.
pub fn setup_crypto_provider(
    config: &CryptoConfig,
    tokio_runtime_handle: tokio::runtime::Handle,
    registry: Arc<dyn RegistryClient>,
    replica_logger: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
) -> CryptoComponent {
    CryptoConfig::check_dir_has_required_permissions(&config.crypto_root).unwrap();
    CryptoComponent::new(
        config,
        Some(tokio_runtime_handle),
        registry,
        replica_logger,
        Some(metrics_registry),
    )
}
