use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    middleware::Next,
    response::IntoResponse,
};
use dashmap::DashMap;
use http::Request;
use moka::sync::{Cache, CacheBuilder};
use prometheus::{
    register_histogram_with_registry, register_int_gauge_vec_with_registry, Histogram, IntGaugeVec,
    Registry,
};
use ratelimit::Ratelimiter;
use tracing::{debug, error, info, warn};

use crate::{
    cli::BouncerConfig,
    routes::{ErrorCause, RateLimitCause},
    socket::TcpConnectInfo,
};

// Common firewall backend operations required by the bouncer
#[async_trait]
pub trait Firewall: Send + Sync {
    // Apply a list of IPs to be banned.
    // Firewall should decide by itself how to do it since it's very implementation-dependent.
    // E.g. it can maintain its own blocklist, compare it with the provided one and decide which ones to add/remove
    async fn apply(&self, decisions: Vec<Decision>) -> Result<(), Error>;
}

// Ban decision for a single IP
#[derive(Copy, Clone)]
pub struct Decision {
    pub ip: IpAddr,
    pub when: Instant,
    // Length can be used by a firewall implementation to do TTL (e.g. nftables sets)
    pub length: Duration,
}

struct Bucket {
    limiter: Ratelimiter,
}

struct Metrics {
    decisions: IntGaugeVec,
    fw_latency: Histogram,
}

pub struct Bouncer {
    firewall: Arc<dyn Firewall>,
    buckets: Cache<IpAddr, Arc<Bucket>>,
    decisions: DashMap<IpAddr, Decision>,
    ban_time: Duration,
    burst_size: u64,
    refill_interval: Duration,
    // Generations are used to track changes to `decisions` and to apply firewall only when needed
    gen_current: AtomicU64,
    gen_applied: AtomicU64,
    metrics: Metrics,
}

impl Bouncer {
    fn new(
        rate_per_second: u32,
        burst_size: u64,
        ban_time: Duration,
        max_buckets: u64,
        bucket_expiry: Duration,
        firewall: Arc<dyn Firewall>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        if rate_per_second == 0 {
            return Err(anyhow!("rate_per_second should be > 0"));
        }

        if burst_size < rate_per_second as u64 {
            return Err(anyhow!("burst_size should be >= rate_per_second"));
        }

        let buckets = CacheBuilder::new(max_buckets)
            // Expire buckets when they're not queried for some time, this bounds memory usage
            .time_to_idle(bucket_expiry)
            .build();

        let metrics = Metrics {
            decisions: register_int_gauge_vec_with_registry!(
                "bouncer_decisions",
                "Current active number of banned IPs partitioned by IP family",
                &["family"],
                registry
            )?,

            fw_latency: register_histogram_with_registry!(
                "bouncer_fw_latency",
                "Time it takes to apply firewall rules in seconds",
                registry,
            )?,
        };

        Ok(Self {
            burst_size,
            firewall,
            buckets,
            decisions: DashMap::new(),
            ban_time,
            refill_interval: Duration::from_secs(1).checked_div(rate_per_second).unwrap(),
            gen_current: AtomicU64::new(0),
            gen_applied: AtomicU64::new(0),
            metrics,
        })
    }

    fn new_bucket(&self) -> Arc<Bucket> {
        Arc::new(Bucket {
            limiter: Ratelimiter::builder(1, self.refill_interval)
                .max_tokens(self.burst_size)
                .initial_available(self.burst_size)
                .build()
                .unwrap(),
        })
    }

    // Increment the generation to indicate that we need to apply
    fn mark_update(&self) {
        self.gen_current.fetch_add(1, Ordering::SeqCst);
    }

    // Counts the request against a bucket and returns if it should be allowed or not
    fn acquire_token(&self, ip: IpAddr) -> bool {
        // Check if the IP is already banned
        if self.decisions.contains_key(&ip) {
            return false;
        }

        // Get bucket or create a new one
        // Moka guarantees that concurrent requests for the same key would lead to only a single one value created
        let bucket = self.buckets.get_with(ip, || self.new_bucket());

        // Try to acquire a token
        if bucket.limiter.try_wait().is_ok() {
            return true;
        }

        warn!("Bouncer: banning {ip}");

        self.decisions.insert(
            ip,
            Decision {
                ip,
                when: Instant::now(),
                length: self.ban_time,
            },
        );

        self.mark_update();
        false
    }

    // Release the IPs that are due
    fn process_releases(&self, now: Instant) {
        // Collect IPs to be released
        let to_release = self
            .decisions
            .iter()
            .filter_map(|x| (now.duration_since(x.when) > x.length).then_some(x.ip))
            .collect::<Vec<_>>();

        if to_release.is_empty() {
            return;
        }

        info!("Bouncer: releasing {} IPs", to_release.len());
        debug!("Bouncer: releasing: {:?}", to_release);

        // Remove the released decisions & compact the map
        for ip in to_release {
            self.decisions.remove(&ip);
        }
        self.decisions.shrink_to_fit();

        self.mark_update();
    }

    // Apply active decisions to the firewall
    async fn apply(&self) -> Result<(), Error> {
        let mut v4: usize = 0;

        // Collect active decisions
        let decisions = self
            .decisions
            .iter()
            .map(|x| {
                // Count v4 for metrics
                if x.ip.is_ipv4() {
                    v4 += 1;
                }

                x.to_owned()
            })
            .collect::<Vec<_>>();

        let count = decisions.len();
        info!("Bouncer: applying {count} active decisions",);

        // Apply the changes to the firewall
        let start = Instant::now();
        self.firewall.apply(decisions).await?;

        // Record metrics
        self.metrics
            .fw_latency
            .observe(start.elapsed().as_secs_f64());
        self.metrics
            .decisions
            .with_label_values(&["IPv4"])
            .set(v4 as i64);
        self.metrics
            .decisions
            .with_label_values(&["IPv6"])
            .set((count - v4) as i64);

        Ok(())
    }

    async fn run(&self, apply_interval: Duration) {
        let mut interval = tokio::time::interval(apply_interval);

        warn!(
            "Bouncer: periodic task with interval {}s started",
            apply_interval.as_secs()
        );

        loop {
            let now = interval.tick().await;
            self.process_releases(now.into_std());

            // Apply updates only if the generations are different.
            // This allows us to bother firewall only when there are changes.
            let gen_current = self.gen_current.load(Ordering::SeqCst);
            if gen_current != self.gen_applied.load(Ordering::SeqCst) {
                if let Err(e) = self.apply().await {
                    error!("Bouncer: unable to apply firewall: {e}");
                    continue;
                };

                // Store the current generation only when we've successfully applies the changes
                self.gen_applied.store(gen_current, Ordering::SeqCst);
            }
        }
    }
}

pub fn setup(cli: &BouncerConfig, registry: &Registry) -> Result<Arc<Bouncer>, Error> {
    let executor = Arc::new(exec::Executor::new(
        cli.bouncer_sudo,
        cli.bouncer_sudo_path.clone(),
        cli.bouncer_nft_path.clone(),
    ));

    let firewall = Arc::new(
        firewall::NftablesFw::new(
            cli.bouncer_v4_table.clone(),
            cli.bouncer_v4_set.clone(),
            cli.bouncer_v6_table.clone(),
            cli.bouncer_v6_set.clone(),
            executor,
        )
        .context("unable to create firewall")?,
    );

    let bouncer = Arc::new(
        Bouncer::new(
            cli.bouncer_ratelimit,
            cli.bouncer_burst_size,
            Duration::from_secs(cli.bouncer_ban_seconds),
            cli.bouncer_max_buckets,
            Duration::from_secs(cli.bouncer_bucket_ttl),
            firewall,
            registry,
        )
        .context("unable to create bouncer")?,
    );

    // Start background task
    let bouncer_task = bouncer.clone();
    let interval = Duration::from_secs(cli.bouncer_apply_interval);
    tokio::spawn(async move {
        bouncer_task.clone().run(interval).await;
    });

    Ok(bouncer)
}

pub async fn middleware(
    State(bouncer): State<Arc<Bouncer>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ErrorCause> {
    // Attempt to extract client's IP from the request
    let ip = request
        .extensions()
        .get::<ConnectInfo<TcpConnectInfo>>()
        .map(|x| (x.0).0)
        .or(request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|x| x.0))
        .map(|x| x.ip());

    if let Some(v) = ip {
        if !bouncer.acquire_token(v) {
            return Err(ErrorCause::RateLimited(RateLimitCause::Bouncer));
        }
    } else {
        // This should not really happen ever, unless somebody enables bouncer when running with Unix socket.
        // Maybe we should check that and forbid or add IP extraction using X-Real-IP & friends headers.
        return Err(ErrorCause::Other("Unable to extract client's IP".into()));
    }

    Ok(next.run(request).await)
}

mod exec;
mod firewall;
#[cfg(test)]
mod test;
