#[macro_use(slog_o)]
extern crate slog;
#[macro_use]
extern crate slog_scope;

// #[macro_use]
// extern crate tokio;
use byte_unit::Byte;
use chrono::Utc;
use clap::{arg_enum, value_t, App, Arg};
use slog::Drain;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::Duration,
};

use std::{convert::TryFrom, net::SocketAddrV4};

mod canister;
mod chart;
mod collector;
mod content_length;
mod engine;
mod message;
mod metrics;
mod plan;
mod stats;

use ic_canister_client::{
    ed25519_public_key_to_der, HttpClient, HttpClientConfig, Sender as AgentSender,
};
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_test_identity::{get_pair, TEST_IDENTITY_KEYPAIR, TEST_IDENTITY_KEYPAIR_HARD_CODED};
use ic_types::{messages::Blob, CanisterId, PrincipalId, UserId};
use stats::Summary;

#[cfg(build = "debug")]
fn get_logger() -> slog::Logger {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!())
}
#[cfg(not(build = "debug"))]
fn get_logger() -> slog::Logger {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    slog::Logger::root(
        slog_term::FullFormat::new(plain)
            .build()
            .filter_level(slog::Level::Info)
            .fuse(),
        slog_o!(),
    )
}

fn write_output_json(filename: &str, summaries: &[Summary]) -> io::Result<()> {
    use std::fs::File;

    let file = PathBuf::from(filename);
    serde_json::to_writer(&File::create(file)?, summaries)?;
    Ok(())
}

arg_enum! {
    #[derive(Clone, Copy, Debug)]
    pub enum RequestType {
        // Needs to expose "read"
        QueryCounter,
        // Needs to expose "write"
        UpdateCounter,
        // Needs to expose "change_state", "expand_state", and "read_state"
        StateSyncA,
        // Needs to expose "init_array", "query_and_update", and "compute_sum"
        CowSafetyA,
        // Needs to expose the method that matches --canister-method-name
        Update,
        // Needs to expose the method that matches --canister-method-name
        Query,
    }
}

arg_enum! {
    #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    pub enum ChartSize {
        None,
        Small,
        Medium,
        Large,
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("IC workload generator")
        .author("DFINITY team <team@dfinity.org>")
        .about("The workload generator generate calls at a given rps (-r), for a period of time (-n)")
        .arg(
            Arg::with_name("URL")
                .required(true)
                .help("URLs to send requests to. A comma-separated list of URLs including port and protocol, e.g. \"http://localhost:8080,http://8.8.8.8:8080\". Load is evenly distributed on these."),
        )
        .arg(
            Arg::with_name("nonce")
                .long("nonce")
                .takes_value(true)
                .help("Nonce to use for update requests"),
        )
        .arg(
            Arg::with_name("duration")
                .short("n")
                .default_value("600")
                .takes_value(true)
                .help("The number of seconds to run(in seconds)."),
        )
        .arg(
            Arg::with_name("rps")
                .short("r")
                .required(true)
                .takes_value(true)
                .help("Requests per second to generate. Accepts fractional values, e.g. 1.5 rps."),
        )
        .arg(
            Arg::with_name("evaluate-max-rps")
                .long("evaluate-max-rps")
                .help("If specified, enables the max rps evaluation\
                       mode. The --rps argument is used as an initial\
                       upper estimate. The estimation process iterates\
                       down starting from --rps, and tries to locate\
                       the actual max rps currently possible.")
        )
        .arg(
            Arg::with_name("canister-id")
                .long("canister-id")
                .takes_value(true)
                .help("Canister ID, in text format (xxxxx-xxx), of a pre-installed canister. When absent, a canister must be installed instead")
        )
        .arg(
            Arg::with_name("canister")
                .long("canister")
                .takes_value(true)
                .conflicts_with("canister-id")
                .help("Path to the canister code. Needs to match selected --method."),
        )
        .arg(
            Arg::with_name("install-endpoint")
                .long("install-endpoint")
                .takes_value(true)
                .help("Path to the canister code. Needs to expose \"read\" for queries and \"write\" for updates."),
        )
        .arg(
            Arg::with_name("prometheus-port")
                .short("pport")
                .takes_value(true)
                .help("Export prometheus metrics on given port"),
        )
        .arg(
            Arg::with_name("method")
                .short("m")
                .possible_values(&RequestType::variants())
                .case_insensitive(true)
                .default_value("QueryCounter")
                .help("What method to issue"),
        )
        .arg(
            Arg::with_name("call-method")
                .long("call-method")
                .takes_value(true)
                .help("The name of the canister method to call. It works only with --method=Update and --method=Query")
        )
        .arg(
            Arg::with_name("updates")
                .short("u")
                .conflicts_with("method")
                .help("Issue counter update calls (alias for --method QueryCounter)"),
        )
        .arg(
            Arg::with_name("no-status-check")
                .long("no-status-check")
                .help("Do not check status endpoints of replicas"),
        )
        .arg(
            Arg::with_name("payload-size")
                .long("payload-size")
                .takes_value(true)
                .help("Size of the ingress canister calls (both updates and queries). The content will be all zeros. Format: <number><suffix>, with suffix any of B, KB, KiB, MB, GiB, GB. The 'B' is always optional.")
        )
        .arg(
            Arg::with_name("payload")
                .long("payload")
                .takes_value(true)
                .help("Hex string of the bytes that will be sent as input to the canister method")
        )
        .arg(
            Arg::with_name("chart-size")
                .long("chart-size")
                .takes_value(true)
                .case_insensitive(true)
                .default_value("None")
                .possible_values(&ChartSize::variants())
                .help("Size of chart to render"),
        )
        .arg(
            Arg::with_name("summary-file")
                .long("summary-file")
                .value_name("FILE")
                .takes_value(true)
                .help("Filename to output the summary of the run, in JSON format. File will be created if not present."),
        )
        .arg(
            Arg::with_name("periodic-output")
                .long("periodic-output")
                .takes_value(false)
                .help("Periodically print output instead of using a progress bar."),
        )
        .arg(
            Arg::with_name("principal-id")
                .long("principal-id")
                .takes_value(true)
                .help("If specified, this, base32 encoding of the principal id, is used for sending request to the IC."),
        )
        .arg(
            Arg::with_name("pem-file")
                .long("pem-file")
                .takes_value(true)
                .help("If specified, use the given pem-file instead of the default principal's pem file."),
        )
        .arg(
            Arg::with_name("http2-only")
                .long("http2-only")
                .default_value("false")
                .takes_value(true)
                .help("If specified, sets this option when building the hyper http client."),
        )
        .arg(
            Arg::with_name("pool-max-idle-per-host")
                .long("pool-max-idle-per-host")
                .default_value("20000")
                .takes_value(true)
                .help("If specified, sets this option when building the hyper http client."),
        )
        .arg(
            Arg::with_name("pool-idle-timeout-secs")
                .long("pool-idle-timeout-secs")
                .takes_value(true)
                .help("If specified, sets this option when building the hyper http client."),
        )

        .get_matches();

    if !cfg!(target_os = "windows") {
        let output = Command::new("sh")
            .arg("-c")
            .arg("ulimit -n")
            .output()
            .expect("failed to execute process");
        let output = String::from_utf8_lossy(&output.stdout).replace("\n", "");
        if let Ok(num) = output.parse::<usize>() {
            // This is a somewhat arbitrary limit :-)
            if num < 4096 {
                let url = "https://askubuntu.com/questions/162229/how-do-i-increase-the-open-files-limit-for-a-non-root-user";
                println!(
                    "⚠️  Number of open file descriptors is low on your platform: {} - This might limit the workload generator's ability to open enough sockets to drive its load. To increase, see: {}",
                    num, url
                );
            }
        }
    };

    let url: Vec<_> = matches
        .value_of("URL")
        .unwrap()
        .split(',')
        .map(ToString::to_string)
        .collect();

    let install_endpoint;
    let install_endpoint = match matches.value_of("install-endpoint") {
        Some(endpoint) => {
            install_endpoint = endpoint.split(',').map(ToString::to_string).collect();
            &install_endpoint
        }
        None => &url,
    };

    let duration = matches
        .value_of("duration")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let rps = matches.value_of("rps").unwrap().parse::<usize>().unwrap();

    let evaluate_max_rps = matches.is_present("evaluate-max-rps");

    let principal_id = matches
        .value_of("principal-id")
        .map(|x| PrincipalId::from_str(x).unwrap());

    let nonce: String = match matches.value_of("nonce") {
        Some(s) => s.to_string(),
        None => {
            let s = Utc::now().to_string();
            debug!("Nonce not given, using {:?}", s);
            s
        }
    };

    let log = get_logger();
    let _guard = slog_scope::set_global_logger(log);

    let periodic_output = matches.is_present("periodic-output");

    let call_payload_size = Byte::from_str(
        matches
            .value_of("payload-size")
            .unwrap_or("0")
            .trim()
            .to_string(),
    )
    .expect("Could not parse the value of --payload-size");

    let call_payload = hex::decode(matches.value_of("payload").unwrap_or("").to_string())
        .expect("Payload must be in hex format");

    if call_payload_size.get_bytes() > 0 && !call_payload.is_empty() {
        assert_eq!(
            call_payload_size.get_bytes(),
            call_payload.len() as u128,
            "Both --payload-size and --payload are given and they are inconsistent",
        );
    }

    let mut metrics_runtime = match matches.value_of("prometheus-port") {
        Some(prometheus_port) => {
            let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
            let logger =
                slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!());
            let port = prometheus_port
                .parse::<u16>()
                .expect("Expected u16 for port value");
            let config = MetricsConfig {
                exporter: Exporter::Http(
                    SocketAddrV4::new("0.0.0.0".parse().expect("can't fail"), port).into(),
                ),
            };
            Some(ic_metrics_exporter::MetricsRuntimeImpl::new_insecure(
                tokio::runtime::Handle::current(),
                config,
                ic_metrics::MetricsRegistry::global(),
                &logger,
            ))
        }
        None => {
            println!("⚠️  Printed rates are completion rates, not rates at which requests are issued. Recommending to use Prometheus metrics (-p) to verify rate at which workload generator issues requests");
            None
        }
    };

    let mut exit_code_success = true;

    let mut http_client_config = HttpClientConfig::default();
    if let Some(val) = matches.value_of("http2-only") {
        http_client_config.http2_only = val.parse::<bool>().unwrap();
    }
    if let Some(val) = matches.value_of("pool-max-idle-per-host") {
        http_client_config.pool_max_idle_per_host = val.parse::<usize>().unwrap();
    }
    if let Some(val) = matches.value_of("pool-idle-timeout-secs") {
        http_client_config.pool_idle_timeout =
            Some(Duration::from_secs(val.parse::<u64>().unwrap()));
    }

    let http_client = HttpClient::new();
    let (sender, pubkey_bytes) = match principal_id {
        None => (
            AgentSender::from_keypair(&TEST_IDENTITY_KEYPAIR),
            TEST_IDENTITY_KEYPAIR.public.to_bytes(),
        ),
        Some(_principal_id) => match matches.value_of("pem-file") {
            Some(f) => {
                let pem_file = fs::read_to_string(f).unwrap();
                let keypair: ed25519_dalek::Keypair = { get_pair(Some(&pem_file)) };
                (
                    AgentSender::from_keypair(&keypair),
                    keypair.public.to_bytes(),
                )
            }
            None => (
                AgentSender::from_keypair(&TEST_IDENTITY_KEYPAIR_HARD_CODED),
                TEST_IDENTITY_KEYPAIR_HARD_CODED.public.to_bytes(),
            ),
        },
    };
    let sender_field = Blob(
        UserId::from(PrincipalId::new_self_authenticating(
            &ed25519_public_key_to_der(pubkey_bytes.to_vec()),
        ))
        .get()
        .into_vec(),
    );

    slog_scope::scope(
        &slog_scope::logger().new(slog_o!("scope" => "1")),
        || async {
            let request_type = if matches.is_present("updates") {
                RequestType::UpdateCounter
            } else {
                value_t!(matches, "method", RequestType).unwrap_or_else(|e| e.exit())
            };
            let canister_method_name = matches.value_of("call-method").unwrap_or("").to_string();
            match request_type {
                RequestType::Update | RequestType::Query => {
                    assert!(
                        !canister_method_name.is_empty(),
                        "Specify the canister method name to call using --call-method."
                    );
                }
                _ => {}
            }
            let eng = engine::Engine::new(sender.clone(), sender_field, &url, http_client_config);

            if !matches.is_present("no-status-check") {
                eng.wait_for_all_agents_to_be_healthy().await;
            }

            // use id of install canister if no id specified
            let canister_id = if let Some(s) = matches.value_of("canister-id") {
                CanisterId::try_from(PrincipalId::from_str(s).unwrap_or_else(|_| {
                    panic!("Illegal value for option --canister-id: '{}'", s);
                }))
                .unwrap()
            } else {
                let wasm_file_path = matches.value_of_os("canister").map(Path::new);
                canister::setup_canister(http_client, sender, install_endpoint, wasm_file_path)
                    .await
                    .unwrap_or_else(|err| {
                        panic!("Failed to create canister: {}", err);
                    })
            };

            let chart_size =
                value_t!(matches, "chart-size", ChartSize).unwrap_or_else(|e| e.exit());

            // Hold all summaries so we can serialize them later if needed
            let mut summaries: Vec<Summary> = Vec::new();

            // Make sure to save the guard, see documentation for more information
            println!(
                "Running {:?} rps for {} seconds, req_type = {}, evaluate_max_rps = {}",
                rps,
                duration,
                request_type.to_string(),
                evaluate_max_rps,
            );

            let facts = if evaluate_max_rps {
                eng.evaluate_max_rps(
                    rps,
                    request_type,
                    canister_method_name,
                    duration,
                    nonce.clone(),
                    call_payload_size,
                    call_payload,
                    &canister_id,
                    periodic_output,
                )
                .await
            } else {
                eng.execute_rps(
                    rps,
                    request_type,
                    canister_method_name,
                    duration,
                    nonce.clone(),
                    call_payload_size,
                    call_payload,
                    &canister_id,
                    periodic_output,
                )
                .await
            };

            // Drop the engine with the hope that all client connections will be closed.
            // Sometimes we may end up in situation where all file decriptors
            // are consumed by the number of connections. We need a more
            // sustainable solution where the file decriptors
            // are not a bottleneck.
            std::mem::drop(eng);
            let summary = Summary::from_facts(&facts);
            summaries.push(summary.clone());
            println!("{}", summary.with_chart_size(chart_size));

            if let Some(metrics) = metrics_runtime.take() {
                std::mem::drop(metrics);
            }

            if let Some(filename) = matches.value_of("summary-file") {
                if let Err(e) = write_output_json(filename, &summaries) {
                    println!(
                        "Error while writing the summaries to file {}: {}",
                        filename, e
                    );
                    exit_code_success = false;
                }
            }

            // TODO: delete a canister after the run, when Agent gets a
            // delete_canister function
        },
    )
    .await;

    std::process::exit(if exit_code_success { 0 } else { 1 });
}
