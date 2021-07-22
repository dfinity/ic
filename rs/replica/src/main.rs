//! Replica -- Internet Computer

use ic_base_server::shutdown_signal;
use ic_config::registry_client::DataProviderConfig;
use ic_config::{subnet_config::SubnetConfigs, Config};
use ic_crypto_sha256::Sha256;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::registry::{LocalStoreCertifiedTimeReader, RegistryClient};
use ic_logger::info;
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replica::{args::ReplicaArgs, setup};
use ic_transport::transport::create_transport;
use ic_types::{replica_version::REPLICA_BINARY_HASH, PrincipalId, SubnetId};
use ic_utils::ic_features::*;
use nix::unistd::{setpgid, Pid};
use static_assertions::assert_eq_size;
use std::env;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{runtime, task};

#[cfg(target_os = "linux")]
mod jemalloc_metrics;

// On mac jemalloc causes lmdb to segfault
#[cfg(target_os = "linux")]
use jemallocator::Jemalloc;
#[cfg(target_os = "linux")]
#[global_allocator]
#[cfg(target_os = "linux")]
static ALLOC: Jemalloc = Jemalloc;

use ic_registry_common::local_store::LocalStoreImpl;
#[cfg(feature = "profiler")]
use pprof::{protos::Message, ProfilerGuard};
#[cfg(feature = "profiler")]
use regex::Regex;
#[cfg(feature = "profiler")]
use std::fs::File;
#[cfg(feature = "profiler")]
use std::io::Write;

fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));
}

/// Determine sha256 hash of the current replica binary
///
/// Returns tuple (path of the replica binary, hex encoded sha256 of binary)
fn get_replica_binary_hash() -> std::result::Result<(PathBuf, String), String> {
    let mut hasher = Sha256::new();
    let replica_binary_path = env::current_exe()
        .map_err(|e| format!("Failed to determine replica binary path: {:?}", e))?;

    let mut binary_file = std::fs::File::open(&replica_binary_path)
        .map_err(|e| format!("Failed to open replica binary to calculate hash: {:?}", e))?;

    std::io::copy(&mut binary_file, &mut hasher)
        .map_err(|e| format!("Failed to calculate hash for replica binary: {:?}", e))?;

    Ok((replica_binary_path, hex::encode(hasher.finish())))
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}

async fn run() -> io::Result<()> {
    // We do not support 32 bits architectures and probably never will.
    assert_eq_size!(usize, u64);

    // At this point we need to setup a new process group. This is
    // done to ensure all our children processes belong to the same
    // process group (as policy wise in production we restrict setpgid
    // for the children of this process). We do not want a new
    // terminal or control group (we still want to be under the same
    // systemd control group in the future). Thus we do not declare
    // this process as a session leader.
    if let Err(err) = setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
        eprintln!("Failed to setup a new process group for replica.");
        // This is a generic exit error. At this point sandboxing is
        // not turned on so we can do a simple exit with cleanup.
        return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
    }

    #[cfg(feature = "profiler")]
    let guard = pprof::ProfilerGuard::new(100).unwrap();
    // Setup temp directory for the configuration.
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .unwrap();

    // Before setup of execution, we disable SIGPIPEs. In particular,
    // we install the corresponding signal handler. We are setting up
    // a series of socket based IPC connections for communication with
    // the sandboxed processes (crypto and runtime), and we require
    // extensive and particular stateful error handling. We MAY NOT
    // depend on the default Rust startup setup.
    //
    // Even if until now SIGPIPE signals are not handled by the
    // current Rust version, there is an ongoing discussion for
    // providing a default behavior to ensure POSIX/UNIX
    // compatibility,
    // cf. https://github.com/rust-lang/rust/issues/62569.
    //
    // In our case we want to handle EPIPE failures only with the
    // processes we establish IPC communication with and manage. Any
    // default SIGPIPE handling is undesirable. (We do not build a CLI
    // tool here, where the default C handling is sometimes helpful.)
    //
    // Note: This is done for darwin builds mainly as we [should]
    // always hopefully establish connections with MSG_NOSIGNAL on
    // linux. Recall that MSG_NOSIGNAL is setup *per write and read*.
    // And SO_NOSIGPIPE is kernel dependent (>2.2) and has spotty
    // support. (And thus both options lead to sporadic problems
    // commonly if we simply depend on them.)
    let _sigpipe_handler =
        signal(SignalKind::pipe()).expect("failed to install SIGPIPE signal handler");

    // Parse command-line args
    let replica_args = setup::parse_args();
    if let Err(e) = &replica_args {
        eprintln!("Failed to parse command line arguments: {}", e.message);
    }

    let config_source = setup::get_config_source(&replica_args);
    let config = Config::load_with_tmpdir(config_source, tmpdir.path().to_path_buf());

    let (logger, _async_log_guard) = setup::get_replica_logger(&config);

    let optional_nns_key_path = match &replica_args {
        Ok(ReplicaArgs {
            nns_public_key_file: Some(path_buf),
            ..
        }) => Some(path_buf.as_path()),
        _ => None,
    };

    let metrics_registry = MetricsRegistry::global();

    #[cfg(target_os = "linux")]
    metrics_registry.register(jemalloc_metrics::JemallocMetrics::new());

    let (registry, crypto) = setup::setup_crypto_registry(
        config.clone(),
        Some(&metrics_registry),
        optional_nns_key_path,
        logger.clone(),
        |_crypto, _data_provider| (),
    );

    let node_id = crypto.get_node_id();
    let cup_with_proto = setup::get_catch_up_package(&replica_args, &logger);
    setup::set_replica_version(&replica_args, &logger);
    let subnet_id = match &replica_args {
        Ok(args) => {
            if let Some(subnet) = args.force_subnet.as_ref() {
                SubnetId::from(
                    PrincipalId::from_str(subnet)
                        .expect("Failed to parse subnet ID given as --force-subnet"),
                )
            } else {
                setup::get_subnet_id(
                    node_id,
                    registry.as_ref(),
                    cup_with_proto
                        .as_ref()
                        .map(|cup_with_proto| &cup_with_proto.cup),
                    &logger,
                )
                .await
            }
        }
        Err(_) => {
            setup::get_subnet_id(
                node_id,
                registry.as_ref(),
                cup_with_proto
                    .as_ref()
                    .map(|cup_with_proto| &cup_with_proto.cup),
                &logger,
            )
            .await
        }
    };

    let subnet_type = setup::get_subnet_type(
        &*registry,
        subnet_id,
        registry.get_latest_version(),
        &logger,
    )
    .await;

    let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);
    // Any change to these lines should be mirrored in the file
    // `rs/replay/src/lib.rs` so that the replica and the replay tool of the same
    // version have an identical behavior wrt. CoW.
    if subnet_config.cow_memory_manager_config.enabled {
        cow_state_feature::enable(cow_state_feature::cow_state);
    } else {
        cow_state_feature::disable(cow_state_feature::cow_state);
    }

    // Read the root subnet id from registry
    let root_subnet_id = registry
        .get_root_subnet_id(
            cup_with_proto
                .as_ref()
                .map(|cup| cup.cup.content.registry_version())
                .unwrap_or_else(|| registry.get_latest_version()),
        )
        .expect("cannot read from registry")
        .expect("cannot find root subnet id");

    // Set node_id and subnet_id in the logging context
    let mut context = logger.get_context();
    context.node_id = format!("{}", node_id.get());
    context.subnet_id = format!("{}", subnet_id.get());
    let logger = logger.with_new_context(context);

    info!(logger, "Replica Started");
    info!(logger, "Running in subnetwork {:?}", subnet_id);
    if let Ok((path, hash)) = get_replica_binary_hash() {
        info!(logger, "Running replica binary: {:?} {}", path, hash);
        let _ = REPLICA_BINARY_HASH.set(hash);
    }

    if replica_args.is_err() {
        info!(logger, "Warning: unlabeled command-line args are deprecated! Please use the flags/labels defined by ReplicaArgs");
    }

    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    setup::create_consensus_pool_dir(&config);

    let crypto = Arc::new(crypto);
    let _metrics = MetricsRuntimeImpl::new(
        tokio::runtime::Handle::current(),
        config.metrics.clone(),
        metrics_registry.clone(),
        registry.clone(),
        Arc::clone(&crypto) as Arc<dyn TlsHandshake + Send + Sync>,
        &logger.inner_logger.root,
    );

    let registry_certified_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>> =
        if let Some(DataProviderConfig::LocalStore(path)) =
            config.registry_client.data_provider.clone()
        {
            Some(Arc::new(LocalStoreImpl::new(path)))
        } else {
            None
        };

    // Transport already implement its own actor-like light interface.
    let transport = create_transport(
        node_id,
        config.transport.clone(),
        registry.get_latest_version(),
        metrics_registry.clone(),
        Arc::clone(&crypto) as Arc<dyn TlsHandshake + Send + Sync>,
        runtime::Handle::current(),
        logger.clone(),
    );
    let (
        crypto,
        state_manager,
        query_handler,
        mut p2p_runner,
        p2p_event_handler,
        consensus_pool_cache,
        ingress_message_filter,
        _xnet_endpoint,
    ) = ic_replica::setup_p2p::construct_p2p_stack(
        logger.clone(),
        config.clone(),
        subnet_config,
        node_id,
        subnet_id,
        subnet_type,
        registry.clone(),
        crypto,
        metrics_registry.clone(),
        transport,
        cup_with_proto,
        registry_certified_time_reader,
    )?;

    p2p_runner.run();

    let malicious_behaviour = &config.malicious_behaviour;

    task::spawn(ic_http_handler::start_server(
        metrics_registry.clone(),
        config.http_handler.clone(),
        p2p_event_handler,
        query_handler,
        state_manager,
        registry,
        crypto,
        subnet_id,
        root_subnet_id,
        logger.clone(),
        consensus_pool_cache,
        ingress_message_filter,
        subnet_type,
        malicious_behaviour.malicious_flags.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(5000)).await;

    if config.malicious_behaviour.maliciously_seg_fault() {
        tokio::spawn(async move {
            loop {
                // Exit roughly every 8 seconds.
                tokio::time::sleep(Duration::from_millis(500)).await;
                let r: u8 = rand::random();
                if r % 16 == 0 {
                    // Exit immediately without cleaning up.
                    unsafe {
                        libc::_exit(1);
                    }
                }
            }
        });
    }

    shutdown_signal(logger.inner_logger.root.clone()).await;

    #[cfg(feature = "profiler")]
    finalize_report(&guard);
    // Ensure cleanup of the temporary directory is triggered; error
    // otherwise.
    tmpdir.close()?;
    info!(logger, "IC Replica Terminated");
    // Ensure we join any threads etc.
    std::mem::drop(p2p_runner);
    Ok(())
}

#[cfg(feature = "profiler")]
fn frames_post_processor() -> impl Fn(&mut pprof::Frames) {
    let thread_rename = [
        (Regex::new(r"^rocksdb:bg\d*$").unwrap(), "rocksdb:bg"),
        (Regex::new(r"^rocksdb:low\d*$").unwrap(), "rocksdb:low"),
        (Regex::new(r"^rocksdb:high\d*$").unwrap(), "rocksdb:high"),
        (Regex::new(r"^snap sender\d*$").unwrap(), "snap-sender"),
        (Regex::new(r"^apply-\d*$").unwrap(), "apply"),
        (Regex::new(r"^future-poller-\d*$").unwrap(), "future-poller"),
    ];

    move |frames| {
        for (regex, name) in thread_rename.iter() {
            if regex.is_match(&frames.thread_name) {
                frames.thread_name = name.to_string();
            }
        }
    }
}

#[cfg(feature = "profiler")]
fn finalize_report(guard: &ProfilerGuard) {
    if let Ok(report) = guard.report().build() {
        println!("report: {}", &report);

        let file = File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();

        let mut file = File::create("profile.pb").unwrap();
        let profile = report.pprof().unwrap();

        let mut content = Vec::new();
        profile.encode(&mut content).unwrap();
        file.write_all(&content).unwrap();

        println!("report: {}", &report);
    };

    if let Ok(report) = guard
        .report()
        .frames_post_processor(frames_post_processor())
        .build()
    {
        let file = File::create("flamegraph_simple.svg").unwrap();
        report.flamegraph(file).unwrap();
    }
}
