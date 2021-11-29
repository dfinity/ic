//! IC Prober is a blackbox exporter that allows blackbox probing of HTTP and IC
//! endpoints.
//!
//! Exposed APIs:
//!
//! * `/probe/{name}[?<probe_parameters>]`
//!   - Executes the probe identified by name, with the provided parameters
//!     (specific to each probe, see module documentation).
//! * `/metrics`
//!   - Exposes the prober's own metrics, encoded in plaintext.

use ic_metrics::MetricsRegistry;
use slog::{slog_o, Drain, Logger};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

mod metrics;
mod probe;
mod prober;

const DEFAULT_PORT: u16 = 2198;

#[tokio::main]
async fn main() {
    let log = get_logger();

    let args: Vec<String> = env::args().collect();
    let port = get_port_or_abort(&args);

    let address = SocketAddr::new(IpAddr::from_str("::1").unwrap(), port);
    let registry = MetricsRegistry::global();

    abort_on_panic();

    let prober = prober::Prober::new(address, registry, log);
    prober.run();
}

fn get_logger() -> Logger {
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog_o!())
}

fn get_port_or_abort(args: &[String]) -> u16 {
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).skip(1).collect();
    fn parse_port(port: &str) -> u16 {
        port.parse::<u16>()
            .unwrap_or_else(|_| panic!("Port number should be an u16, got {}", port))
    }

    match &arg_refs[..] {
        [] => DEFAULT_PORT,

        ["--port", port] => parse_port(port),
        [arg] if arg.starts_with("--port=") => parse_port(&arg["--port=".len()..]),

        _ => abort_and_print_usage(args),
    }
}

fn abort_and_print_usage(args: &[String]) -> ! {
    eprint!(
        r#"Usage: {0} [--port <port>]

Starts an IC Prober listening on the specified port (default {1}).
"#,
        args[0], DEFAULT_PORT
    );
    std::process::exit(1);
}

fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));
}
