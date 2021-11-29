use fondue::pot::execution::Config as ExecConfig;
use fondue::pot::Config as PotConfig;
use ic_fondue::ic_manager::{IcEndpoint, IcManagerSettings, IcSubnet, RuntimeDescriptor};
use ic_registry_subnet_type::SubnetType;
use ic_types::{PrincipalId, SubnetId};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use url::Url;

impl Options {
    /// Creates a [fondue::pot::Config] according to the command line options
    /// captured in [Option] and a given default [fondue::pot::Config].
    pub fn modify_fondue_pot_config(&self, cfg: PotConfig) -> PotConfig {
        PotConfig {
            rng_seed: self.fondue_seed.unwrap_or(cfg.rng_seed),
            ready_timeout: self.fondue_ready_timeout.unwrap_or(cfg.ready_timeout),
            level: cfg.level.max(verbosity_to_log_level(self.fondue_log_level)),
            log_target: self.fondue_log_target.clone().or(cfg.log_target),
        }
    }

    /// Creates a [fondue::pot::execution::Config] according to the command line
    /// options captured in [Option] and a given default
    /// [fondue::pot::execution::Config].
    pub fn modify_fondue_exec_config(
        &self,
        cfg: ExecConfig<IcManagerSettings>,
    ) -> ExecConfig<IcManagerSettings> {
        ExecConfig {
            pot_timeout: self.pot_timeout.unwrap_or(cfg.pot_timeout),
            filter: Some(self.get_fondue_filter()),
            jobs: self.jobs.unwrap_or(cfg.jobs),
            pot_config: self.modify_fondue_pot_config(cfg.pot_config),
            man_config: self.modify_ic_manager_settings(cfg.man_config),
        }
    }

    /// Creates a `ic_fondue::ic_manager::IcManager::ManConfig` in a similar
    /// fashion to the other two "modify" functions in this impl.
    pub fn modify_ic_manager_settings(&self, settings: IcManagerSettings) -> IcManagerSettings {
        IcManagerSettings {
            tee_replica_logs_base_dir: self
                .tee_replica_logs_base_dir
                .clone()
                .map(|mut p| {
                    // Create a subdirectory inside of the base directory to ensure that old logs
                    // will not get overwritten.
                    p.push(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string());
                    p
                })
                .or(settings.tee_replica_logs_base_dir),
            existing_endpoints: if let Some(urls) = &self.endpoint_urls {
                let mut endpoints = Vec::new();
                for info in urls.split(',') {
                    let parts: Vec<&str> = info.split('/').collect();
                    let subnet_type = parts[0];
                    let subnet_id = SubnetId::from(
                        PrincipalId::from_str(parts[1])
                            .expect("cannot parse subnet id as principal"),
                    );
                    let subnet_addr = parts[2];
                    endpoints.push(IcEndpoint {
                        runtime_descriptor: RuntimeDescriptor::Unknown,
                        url: Url::parse(&format!("http://{}", subnet_addr)).unwrap(),
                        is_root_subnet: subnet_type == "nns",
                        subnet: Some(IcSubnet {
                            id: subnet_id,
                            type_of: if subnet_type == "nns" {
                                SubnetType::System
                            } else {
                                SubnetType::Application
                            },
                        }),
                        metrics_url: None,
                        started_at: Instant::now(),
                        ssh_key_pairs: vec![],
                    })
                }
                Some(endpoints)
            } else {
                None
            },
        }
    }

    fn get_fondue_filter(&self) -> fondue::pot::Filter {
        fondue::pot::Filter {
            select: self.filters.clone().unwrap_or_else(|| "".to_string()),
            skip_filter: self.skip.clone(),
        }
    }
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "system-tests", about = "Runs the our system-tests")]
pub struct Options {
    #[structopt(
        long = "seed",
        help = r#"
Uses the specified seed for starting up the RNG;
This is important to pay attention to if you want to reproduce a run."#
    )]
    pub fondue_seed: Option<u64>,

    #[structopt(
        long = "ready-timeout",
        parse(try_from_str = parse_duration),
        help = "How much time should we wait for the replicas to be ready for interaction"
    )]
    pub fondue_ready_timeout: Option<Duration>,

    #[structopt(
        short = "v",
        parse(from_occurrences),
        help = r#"
Verbosity control. Using -v makes the tests a little chatty while
 -vv makes them really chatty!"#
    )]
    pub fondue_log_level: u64,

    #[structopt(
        long = "fondue-logs",
        parse(from_os_str),
        help = "Saves the framework logs to a file. See 'tee-replica-logs-base-dir' for saving the replica logs."
    )]
    pub fondue_log_target: Option<PathBuf>,

    #[structopt(
        long = "tee-replica-logs-base-dir",
        parse(from_os_str),
        help = "Saves the logs of every replica to a dedicated file, unique for corresponding pot and channel."
    )]
    pub tee_replica_logs_base_dir: Option<PathBuf>,

    #[structopt(
        long = "endpoint-urls",
        help = "If specified, execute eligible system tests against a running IC."
    )]
    pub endpoint_urls: Option<String>,

    #[structopt(
        long = "timeout",
        parse(try_from_str = parse_duration),
        help = "How much time should each test take before being killed"
    )]
    pub pot_timeout: Option<Duration>,

    #[structopt(long = "jobs", help = "How many fondue jobs should we run in parallel")]
    pub jobs: Option<usize>,

    #[structopt(
        long = "pots",
        help = "Run only pots containing the given string in their names"
    )]
    pub pot_filter: Option<String>,

    #[structopt(long = "skip", help = "Skip any tests that match this filter")]
    pub skip: Option<String>,

    #[structopt(long_help = "Run any tests that contain this filter in their name")]
    pub filters: Option<String>,

    #[structopt(
        long = "runtime-stats",
        parse(from_os_str),
        help = "If set, specifies where to write runtime statistics collected during tests execution"
    )]
    pub runtime_stats_file: Option<PathBuf>,

    #[structopt(
        long = "experimental",
        help = "Include 'experimetnal' (vm-based) pots."
    )]
    pub experimental: bool,
}

fn verbosity_to_log_level(v: u64) -> slog::Level {
    if v == 0 {
        slog::Level::Info
    } else if v == 1 {
        slog::Level::Debug
    } else {
        slog::Level::Trace
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|e| format!("Can't parse u64: {:?}", e))
}

fn parse_duration(dur: &str) -> Result<Duration, String> {
    if let Some(dur) = dur.strip_suffix("ms") {
        Ok(Duration::from_millis(parse_u64(dur)?))
    } else if let Some(dur) = dur.strip_suffix('s') {
        Ok(Duration::from_secs(parse_u64(dur)?))
    } else if let Some(dur) = dur.strip_suffix('m') {
        Ok(Duration::from_secs(60 * parse_u64(dur)?))
    } else {
        Err("Can't parse duration unit. Try 4000ms, 4s or 4m".to_string())
    }
}
