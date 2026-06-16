//! Stress-test driver for the local 4-node subnet (dev/local-net).
//!
//! Deploys N universal canisters via `provisional_create_canister_with_cycles`
//! and then hammers the subnet with compute and memory load, reporting how it
//! holds up. Drives the public endpoint with the in-repo `ic-canister-client`
//! Agent, so it needs no dfx / external SDK.
//!
//! Run with:
//!   cargo run -p ic-canister-client --example hammer --release -- http://localhost:8080
//!
//! Env knobs: HAMMER_CANISTERS (default 6), HAMMER_SECS (per throughput/compute
//! phase, default 15), HAMMER_CONCURRENCY (default 48).

use ic_canister_client::{Agent, Sender};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, IC_00, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs,
};
use ic_types::{CanisterId, PrincipalId};
use ic_universal_canister::{get_universal_canister_wasm, wasm};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const MIB: u32 = 1024 * 1024;
// A canister id that lives in this subnet's allocation range (see DEPLOY.md);
// used only to route `provisional_create_canister_with_cycles`.
const ROUTING_CANISTER_ID: &str = "bnz7o-iuaaa-aaaaa-qaaaa-cai";

static NONCE: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> Vec<u8> {
    NONCE.fetch_add(1, Ordering::Relaxed).to_le_bytes().to_vec()
}

#[derive(Default)]
struct Stats {
    ok: AtomicU64,
    err: AtomicU64,
    lat_sum_ms: AtomicU64,
    lat_max_ms: AtomicU64,
    err_classes: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    fn record(&self, started: Instant, result: &Result<Option<Vec<u8>>, String>) {
        let ms = started.elapsed().as_millis() as u64;
        self.lat_sum_ms.fetch_add(ms, Ordering::Relaxed);
        self.lat_max_ms.fetch_max(ms, Ordering::Relaxed);
        match result {
            Ok(_) => {
                self.ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.err.fetch_add(1, Ordering::Relaxed);
                // Collapse to a short class so the histogram stays readable.
                let class: String = e.split_whitespace().take(10).collect::<Vec<_>>().join(" ");
                let class: String = class.chars().take(120).collect();
                *self.err_classes.lock().unwrap().entry(class).or_insert(0) += 1;
            }
        }
    }

    fn report(&self, label: &str, wall: Duration) {
        let ok = self.ok.load(Ordering::Relaxed);
        let err = self.err.load(Ordering::Relaxed);
        let total = ok + err;
        let avg = if total > 0 {
            self.lat_sum_ms.load(Ordering::Relaxed) / total
        } else {
            0
        };
        let rps = ok as f64 / wall.as_secs_f64().max(0.001);
        println!(
            "\n── {label} ──\n  ok={ok} err={err}  throughput={rps:.1} ok/s  \
             latency avg={avg}ms max={}ms  (wall {:.1}s)",
            self.lat_max_ms.load(Ordering::Relaxed),
            wall.as_secs_f64()
        );
        let classes = self.err_classes.lock().unwrap();
        if !classes.is_empty() {
            println!("  error classes:");
            for (c, n) in classes.iter() {
                println!("    [{n:>5}] {c}");
            }
        }
    }
}

async fn update(
    agent: &Agent,
    canister: &CanisterId,
    payload: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    agent
        .execute_update(canister, canister, "update", payload, next_nonce())
        .await
}

/// Create + install a universal canister; optionally pre-grow its stable memory.
async fn deploy_one(
    agent: &Agent,
    routing_id: &CanisterId,
    pre_grow_pages: u32,
) -> Result<CanisterId, String> {
    let args = ProvisionalCreateCanisterWithCyclesArgs::new(
        Some(1_000_000_000_000_000_u128), // 1 Pcycle, never freezes
        None,
    );
    let reply = agent
        .execute_update(
            routing_id,
            &IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            args.encode(),
            next_nonce(),
        )
        .await?
        .ok_or("provisional_create: empty reply")?;
    let canister_id = CanisterIdRecord::decode(&reply)
        .map_err(|e| format!("decode CanisterIdRecord: {e}"))?
        .get_canister_id();

    agent
        .install_canister(InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            get_universal_canister_wasm(),
            vec![],
        ))
        .await?;

    if pre_grow_pages > 0 {
        update(agent, &canister_id, wasm().stable_grow(pre_grow_pages).reply().build()).await?;
    }
    Ok(canister_id)
}

/// Run `make_payload` against the canister pool from `concurrency` workers until
/// `dur` elapses.
async fn storm(
    agent: Arc<Agent>,
    canisters: Arc<Vec<CanisterId>>,
    concurrency: usize,
    dur: Duration,
    make_payload: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
) -> Stats {
    let stats = Arc::new(Stats::default());
    let deadline = Instant::now() + dur;
    let rr = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let agent = agent.clone();
        let canisters = canisters.clone();
        let stats = stats.clone();
        let rr = rr.clone();
        let make_payload = make_payload.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let idx = rr.fetch_add(1, Ordering::Relaxed) as usize % canisters.len();
                let canister = canisters[idx];
                let payload = make_payload();
                let started = Instant::now();
                let res = update(&agent, &canister, payload).await;
                stats.record(started, &res);
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Arc::try_unwrap(stats).unwrap_or_default()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let num_canisters: usize = std::env::var("HAMMER_CANISTERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let secs: u64 = std::env::var("HAMMER_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let concurrency: usize = std::env::var("HAMMER_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(48);

    let agent = Arc::new(Agent::new(
        Url::parse(&url).expect("bad url"),
        Sender::Anonymous,
    ));
    let routing_id =
        CanisterId::unchecked_from_principal(PrincipalId::from_str(ROUTING_CANISTER_ID).unwrap());

    println!("== hammer ==");
    println!("target={url} canisters={num_canisters} phase_secs={secs} concurrency={concurrency}");

    // ---- Deploy ----
    println!("\n[1/5] deploying {num_canisters} universal canisters (pre-grow 32 MiB stable each)...");
    let t0 = Instant::now();
    let mut canisters = Vec::new();
    for i in 0..num_canisters {
        match deploy_one(&agent, &routing_id, 512).await {
            Ok(id) => {
                println!("  + canister {i} = {id}");
                canisters.push(id);
            }
            Err(e) => println!("  ! deploy {i} failed: {e}"),
        }
    }
    if canisters.is_empty() {
        eprintln!("no canisters deployed; aborting");
        std::process::exit(1);
    }
    println!("  deployed {} canisters in {:.1}s", canisters.len(), t0.elapsed().as_secs_f64());
    let canisters = Arc::new(canisters);

    // ---- Phase A: ingress/throughput storm (near-empty updates) ----
    println!("\n[2/5] THROUGHPUT storm: empty update calls, {concurrency} concurrent, {secs}s");
    let t = Instant::now();
    let stats = storm(
        agent.clone(),
        canisters.clone(),
        concurrency,
        Duration::from_secs(secs),
        Arc::new(|| wasm().reply().build()),
    )
    .await;
    stats.report("THROUGHPUT (empty updates)", t.elapsed());

    // ---- Phase B: compute storm (8 MiB stable fill per call, within dirty limit) ----
    println!("\n[3/5] COMPUTE storm: 8 MiB stable_fill per call, {concurrency} concurrent, {secs}s");
    let t = Instant::now();
    let stats = storm(
        agent.clone(),
        canisters.clone(),
        concurrency,
        Duration::from_secs(secs),
        Arc::new(|| wasm().stable_fill(0, 0x61, 8 * MIB).reply().build()),
    )
    .await;
    stats.report("COMPUTE (8 MiB fill)", t.elapsed());

    // ---- Phase C: per-message dirty-page limit (expect traps) ----
    println!("\n[4/5] DIRTY-LIMIT probe: 48 MiB dirty in one message (limit is 32 MiB) x16");
    let probe = Stats::default();
    for _ in 0..16 {
        let c = canisters[0];
        let p = wasm().stable_grow(1024).stable_fill(0, 0x62, 48 * MIB).reply().build();
        let started = Instant::now();
        let res = update(&agent, &c, p).await;
        probe.record(started, &res);
    }
    probe.report("DIRTY-LIMIT (48 MiB/msg)", Duration::from_secs(1));

    // ---- Phase D: grow stable memory toward the 512 MiB subnet cap ----
    println!("\n[5/5] MEMORY-GROWTH storm: grow 16 MiB + fill per call across all canisters until rejected");
    let grow = Arc::new(Stats::default());
    let total_mib = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for &c in canisters.iter() {
        let agent = agent.clone();
        let grow = grow.clone();
        let total_mib = total_mib.clone();
        handles.push(tokio::spawn(async move {
            // Hard cap iterations so a misbehaving run can't loop forever.
            for _ in 0..64 {
                let p = wasm().stable_grow(256).stable_fill(0, 0x63, 16 * MIB).reply().build();
                let started = Instant::now();
                let res = update(&agent, &c, p).await;
                let ok = res.is_ok();
                grow.record(started, &res);
                if ok {
                    total_mib.fetch_add(16, Ordering::Relaxed);
                } else {
                    break; // first rejection for this canister: stop growing it
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    grow.report("MEMORY-GROWTH", Duration::from_secs(1));
    println!(
        "  approx stable memory successfully grown across subnet: ~{} MiB",
        total_mib.load(Ordering::Relaxed)
    );

    println!("\n== done ==");
}
