use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Error, bail};
use async_trait::async_trait;
use axum::{body::Body, extract::State, middleware::Next, response::IntoResponse};
use dashmap::DashMap;
use http::Request;
use ic_bn_lib::prometheus::{
    Histogram, IntGaugeVec, Registry, register_histogram_with_registry,
    register_int_gauge_vec_with_registry,
};
use ic_bn_lib_common::types::http::ConnInfo;
use tracing::{debug, error, info, warn};

use crate::{
    cli,
    errors::{ErrorCause, RateLimitCause},
    rate_limiting::sharded::ShardedRatelimiter,
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

struct Metrics {
    decisions: IntGaugeVec,
    fw_latency: Histogram,
}

pub struct Bouncer {
    firewall: Arc<dyn Firewall>,
    shards: ShardedRatelimiter<IpAddr>,
    decisions: DashMap<IpAddr, Decision>,
    ban_time: Duration,
    // Generations are used to track changes to `decisions` and to apply firewall only when needed
    gen_current: AtomicU64,
    gen_applied: AtomicU64,
    metrics: Metrics,
}

impl Bouncer {
    fn new(
        rate_per_second: u32,
        burst_size: u32,
        ban_time: Duration,
        max_shards: u64,
        shard_tti: Duration,
        firewall: Arc<dyn Firewall>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        if rate_per_second == 0 {
            bail!("rate_per_second should be > 0");
        }

        if burst_size < rate_per_second {
            bail!("burst_size should be >= rate_per_second");
        }

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
            firewall,
            shards: ShardedRatelimiter::new(
                rate_per_second,
                burst_size,
                Duration::from_secs(1),
                shard_tti,
                max_shards,
            ),
            decisions: DashMap::new(),
            ban_time,
            gen_current: AtomicU64::new(0),
            gen_applied: AtomicU64::new(0),
            metrics,
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

        if self.shards.acquire(ip) {
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

pub fn setup(cli: &cli::Bouncer, registry: &Registry) -> Result<Arc<Bouncer>, Error> {
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
            cli.bouncer_ban_time,
            cli.bouncer_max_buckets,
            cli.bouncer_bucket_ttl,
            firewall,
            registry,
        )
        .context("unable to create bouncer")?,
    );

    // Start background task
    let bouncer_task = bouncer.clone();
    let interval = cli.bouncer_apply_interval;
    tokio::spawn(async move {
        bouncer_task.clone().run(interval).await;
    });

    Ok(bouncer)
}

pub async fn middleware(
    State(bouncer): State<Arc<Bouncer>>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    // Attempt to extract client's IP from the request
    let ip = request
        .extensions()
        .get::<Arc<ConnInfo>>()
        .map(|x| x.remote_addr.ip());

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
mod test {
    use std::str::FromStr;

    use dashmap::DashSet;

    use super::*;

    struct MockFirewall(DashSet<IpAddr>);

    #[async_trait]
    impl Firewall for MockFirewall {
        async fn apply(&self, decisions: Vec<Decision>) -> Result<(), Error> {
            self.0.clear();
            decisions.into_iter().for_each(|x| {
                self.0.insert(x.ip);
            });
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_bouncer() {
        let fw = Arc::new(MockFirewall(DashSet::new()));

        let bouncer = Bouncer::new(
            10,
            15,
            Duration::from_secs(100),
            100,
            Duration::from_secs(10),
            fw.clone(),
            &Registry::new(),
        )
        .unwrap();

        let ip1 = IpAddr::from_str("1.1.1.1").unwrap();
        let ip2 = IpAddr::from_str("2.2.2.2").unwrap();

        // Check that first 15 reqs for ip1 are allowed (burst)
        for _ in 0..15 {
            assert!(bouncer.acquire_token(ip1));
        }

        // Check that next one is denied
        assert!(!bouncer.acquire_token(ip1));

        // Make sure it's added to firewall
        assert!(bouncer.apply().await.is_ok());
        assert!(fw.0.contains(&ip1));

        // Check that first 15 reqs for ip2 are allowed even if ip1 is blocked
        for _ in 0..15 {
            assert!(bouncer.acquire_token(ip2));
        }

        // Check that next one is denied
        assert!(!bouncer.acquire_token(ip2));

        // Make sure it's added to firewall and we still have ip1 there
        assert!(bouncer.apply().await.is_ok());
        assert!(fw.0.contains(&ip1));
        assert!(fw.0.contains(&ip2));

        // Jump 150s into the future and check that both IPs are expired
        let now = Instant::now()
            .checked_add(Duration::from_secs(150))
            .unwrap();
        bouncer.process_releases(now);
        assert!(bouncer.apply().await.is_ok());
        assert!(fw.0.is_empty());
    }
}
