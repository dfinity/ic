//! Replica -- Internet Computer

use ic_async_utils::{abort_on_panic, shutdown_signal};
use ic_config::Config;
use ic_crypto_sha::Sha256;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_logger::{info, new_replica_logger_from_config};
use ic_metrics::MetricsRegistry;
use ic_onchain_observability_server::spawn_onchain_observability_grpc_server_and_register_metrics;
use ic_replica::setup;
use ic_sys::PAGE_SIZE;
use ic_types::consensus::CatchUpPackage;
use ic_types::{replica_version::REPLICA_BINARY_HASH, PrincipalId, ReplicaVersion, SubnetId};
use nix::unistd::{setpgid, Pid};
use static_assertions::assert_eq_size;
use std::{env, fs, io, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::signal::unix::{signal, SignalKind};

#[cfg(target_os = "linux")]
mod jemalloc_metrics;

// On mac jemalloc causes lmdb to segfault
#[cfg(target_os = "linux")]
use jemallocator::Jemalloc;
#[cfg(target_os = "linux")]
#[global_allocator]
#[cfg(target_os = "linux")]
static ALLOC: Jemalloc = Jemalloc;

#[cfg(feature = "profiler")]
use pprof::{protos::Message, ProfilerGuard};
#[cfg(feature = "profiler")]
use regex::Regex;
#[cfg(feature = "profiler")]
use std::fs::File;
#[cfg(feature = "profiler")]
use std::io::Write;

/// Determine sha256 hash of the current replica binary
///
/// Returns tuple (path of the replica binary, hex encoded sha256 of binary)
fn get_replica_binary_hash() -> Result<(PathBuf, String), String> {
    let mut hasher = Sha256::new();
    let replica_binary_path = env::current_exe()
        .map_err(|e| format!("Failed to determine replica binary path: {:?}", e))?;

    let mut binary_file = fs::File::open(&replica_binary_path)
        .map_err(|e| format!("Failed to open replica binary to calculate hash: {:?}", e))?;

    io::copy(&mut binary_file, &mut hasher)
        .map_err(|e| format!("Failed to calculate hash for replica binary: {:?}", e))?;

    Ok((replica_binary_path, hex::encode(hasher.finish())))
}

fn main() -> io::Result<()> {
    // We do not support 32 bits architectures and probably never will.
    assert_eq_size!(usize, u64);
    // Ensure that the hardcoded constant matches the OS page size.
    assert_eq!(ic_sys::sysconf_page_size(), PAGE_SIZE);

    // Produce a thread dump and exit if this is a child process created for this
    // purpose.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    ic_backtrace::init();

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
        return Err(io::Error::new(io::ErrorKind::Other, err));
    }

    #[cfg(feature = "profiler")]
    let guard = pprof::ProfilerGuard::new(100).unwrap();

    // We create 3 separate Tokio runtimes. The main one is for the most important
    // IC operations (e.g. transport). Then the `http` is for serving user requests.
    // This is also crucial because IC upgrades go through this code path.
    // The 3rd one is for XNet.
    // In a bug-free system with quotas in place we would use just a single runtime.
    // We do have 3 currently as risk management measure. We don't want to risk
    // a potential bug (e.g. blocking some thread) in one component to yield the
    // Tokio scheduler irresponsive and block progress on other components.
    let rt_main = tokio::runtime::Runtime::new().unwrap();
    // Runtime used for serving user requests.
    let http_rt_worker_threads = std::cmp::max(num_cpus::get() / 2, 1);
    let rt_http = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(http_rt_worker_threads)
        .thread_name("HTTP_Thread".to_string())
        .enable_all()
        .build()
        .unwrap();

    let xnet_rt_worker_threads = std::cmp::max(num_cpus::get() / 4, 1);
    let rt_xnet = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(xnet_rt_worker_threads)
        .thread_name("XNet_Thread".to_string())
        .enable_all()
        .build()
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
    let sigpipe_handler = rt_main.block_on(async {
        signal(SignalKind::pipe()).expect("failed to install SIGPIPE signal handler")
    });
    // Parse command-line args
    let replica_args = setup::parse_args();
    if let Err(e) = &replica_args {
        e.print().expect("Failed to print CLI argument error.");
    }

    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let config_source = setup::get_config_source(&replica_args);
    // Setup temp directory for the configuration.
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .unwrap();
    let config = Config::load_with_tmpdir(config_source, tmpdir.path().to_path_buf());

    let (logger, async_log_guard) = new_replica_logger_from_config(&config.logger);
    let metrics_registry = MetricsRegistry::global();
    #[cfg(target_os = "linux")]
    metrics_registry.register(jemalloc_metrics::JemallocMetrics::new());

    let cup = setup::get_catch_up_package(&replica_args, &logger)
        .as_ref()
        .map(|c| CatchUpPackage::try_from(c).expect("deserializing CUP failed"));

    // Set the replica verison and report as metric
    setup::set_replica_version(&replica_args, &logger);
    {
        let g = metrics_registry.int_gauge_vec(
            "ic_replica_info",
            "version info for the internet computer replica running.",
            &["ic_active_version", "ic_replica_binary_hash"],
        );
        g.with_label_values(&[
            ReplicaVersion::default().as_ref(),
            &get_replica_binary_hash()
                .map(|x| x.1)
                .unwrap_or_else(|_| "na".to_string()),
        ])
        .set(1);
    }

    let (registry, crypto) = setup::setup_crypto_registry(
        &config,
        rt_main.handle().clone(),
        &metrics_registry,
        logger.clone(),
    );

    let node_id = crypto.get_node_id();

    let subnet_id = match &replica_args {
        Ok(args) => {
            if let Some(subnet) = args.force_subnet.as_ref() {
                SubnetId::from(
                    PrincipalId::from_str(subnet)
                        .expect("Failed to parse subnet ID given as --force-subnet"),
                )
            } else {
                setup::get_subnet_id(node_id, registry.as_ref(), cup.as_ref(), &logger)
            }
        }
        Err(_) => setup::get_subnet_id(node_id, registry.as_ref(), cup.as_ref(), &logger),
    };

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

    let crypto = Arc::new(crypto);
    let _metrics_endpoint = MetricsHttpEndpoint::new(
        rt_http.handle().clone(),
        config.metrics.clone(),
        metrics_registry.clone(),
        registry.clone(),
        Arc::clone(&crypto) as Arc<dyn TlsHandshake + Send + Sync>,
        &logger.inner_logger.root,
    );

    info!(logger, "Constructing IC stack");
    let (_, _, _p2p_thread_joiner, _, _xnet_endpoint) =
        ic_replica::setup_ic_stack::construct_ic_stack(
            &logger,
            &metrics_registry,
            rt_main.handle().clone(),
            rt_http.handle().clone(),
            rt_xnet.handle().clone(),
            config.clone(),
            node_id,
            subnet_id,
            registry,
            crypto,
            cup,
        )?;

    info!(logger, "Constructed IC stack");

    // TODO(NET-1366) - remove this flag once confident that starting gRPC is stable
    if config
        .adapters_config
        .onchain_observability_enable_grpc_server
    {
        // Spawns a new grpc server in a new task. This will continue to run until the Runtime shuts down.
        spawn_onchain_observability_grpc_server_and_register_metrics(
            metrics_registry,
            rt_main.handle().clone(),
            config
                .adapters_config
                .onchain_observability_uds_metrics_path,
        );
    }

    std::thread::sleep(Duration::from_millis(5000));

    if config.malicious_behaviour.maliciously_seg_fault() {
        rt_main.spawn(async move {
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

    let save_logger = logger.clone();
    rt_main.block_on(async move {
        let _drop_async_log_guard = async_log_guard;
        let _drop_sigpipe_handler = sigpipe_handler;
        info!(logger, "IC Replica Running");
        // Blocking on `SIGINT` or `SIGTERM`.
        shutdown_signal(logger.inner_logger.root.clone()).await
    });
    info!(save_logger, "IC Replica Terminating");

    #[cfg(feature = "profiler")]
    finalize_report(&guard);
    // Ensure cleanup of the temporary directory is triggered; error
    // otherwise.
    tmpdir.close()?;
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
        println!("report: {:?}", &report);

        let file = File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();

        let mut file = File::create("profile.pb").unwrap();
        let profile = report.pprof().unwrap();

        let mut content = Vec::new();
        profile.encode(&mut content).unwrap();
        file.write_all(&content).unwrap();

        println!("report: {:?}", &report);
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
