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
use ic_universal_canister::{call_args, get_universal_canister_wasm, wasm};
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
                let class: String = e.split_whitespace().take(60).collect::<Vec<_>>().join(" ");
                let class: String = class.chars().take(400).collect();
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

/// Build a payload that, executed by the ingress-target canister, makes it call
/// canisters[start+1], which calls canisters[start+2], ... `depth` hops deep
/// around the canister ring; the innermost canister replies and the replies
/// propagate back. Generates ~2*depth inter-canister messages per ingress
/// (depth requests + depth responses), with `depth` outstanding callbacks at
/// peak (each holding a guaranteed-response memory reservation).
fn chain_payload(canisters: &[CanisterId], start: usize, depth: usize) -> Vec<u8> {
    let k = canisters.len();
    let mut inner = wasm().reply().build(); // innermost callee just replies
    for h in (1..=depth).rev() {
        let callee = canisters[(start + h) % k].get().as_slice().to_vec();
        inner = wasm()
            .call_simple(callee, "update", call_args().other_side(inner))
            .build();
    }
    inner
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
    is_query: bool,
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
                let res = if is_query {
                    agent.execute_query(&canister, "query", payload).await
                } else {
                    update(&agent, &canister, payload).await
                };
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
    // probe mode: skip the throughput/compute/growth storms, run only the
    // per-message dirty-page-limit probe (Phase C).
    let probe_only = std::env::var("HAMMER_MODE").map(|m| m == "probe").unwrap_or(false);
    // read mode: populate canisters with large state, then read-heavy updates on
    // all-but-one and read-heavy queries on the last; plus a read-limit probe.
    let read_mode = std::env::var("HAMMER_MODE").map(|m| m == "read").unwrap_or(false);
    // heap mode: the heap-memory (Wasm) analogue of the stable-memory tests
    // (compute/dirty-limit/read). Heap has no per-execution dirty/accessed cap
    // (the 32 MiB limits are stable-only), so a single message can touch
    // arbitrarily large heap.
    let heap_mode = std::env::var("HAMMER_MODE").map(|m| m == "heap").unwrap_or(false);
    // calls mode: thrash inter-canister communication — each ingress triggers a
    // chain of canister-to-canister update calls `HAMMER_CALL_DEPTH` hops deep.
    let calls_mode = std::env::var("HAMMER_MODE").map(|m| m == "calls").unwrap_or(false);
    let call_depth: usize = std::env::var("HAMMER_CALL_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    // heapread mode: large heap-memory reads pulling lots of distinct state into
    // RAM. Each canister holds a 96 MiB heap global (built via append, small
    // transient); reads use queries (heap reads via update would OOM because
    // get_global_data copies the global to the stack, permanently growing heap).
    let heapread_mode = std::env::var("HAMMER_MODE").map(|m| m == "heapread").unwrap_or(false);

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

    if calls_mode {
        // ---- Inter-canister call thrash ----
        // Each ingress makes the target canister start a `call_depth`-hop chain
        // of update calls around the canister ring. With C concurrent ingresses
        // there are up to C*call_depth outstanding inter-canister calls at peak.
        let cans = canisters.clone();
        let ctr = Arc::new(AtomicU64::new(0));
        let mk: Arc<dyn Fn() -> Vec<u8> + Send + Sync> = {
            let cans = cans.clone();
            Arc::new(move || {
                let n = ctr.fetch_add(1, Ordering::Relaxed) as usize;
                chain_payload(&cans, n % cans.len(), call_depth)
            })
        };
        println!(
            "\n[calls] inter-canister call storm ({secs}s): {call_depth}-hop chains, {concurrency} concurrent ingresses across {} canisters",
            canisters.len()
        );
        println!("  (~{} inter-canister messages per ingress; up to {} outstanding calls at peak)", 2 * call_depth, concurrency * call_depth);
        let t = Instant::now();
        let stats = storm(
            agent.clone(),
            canisters.clone(),
            concurrency,
            Duration::from_secs(secs),
            mk,
            false,
        )
        .await;
        stats.report(&format!("INTER-CANISTER CALLS ({call_depth}-hop chains)"), t.elapsed());

        println!("\n== done ==");
        return;
    }

    if read_mode {
        // Populate each canister with ~120 MiB of real stable data (written in
        // <=24 MiB chunks to respect the 32 MiB per-message dirty limit).
        const BIG_MIB: u32 = 128;
        let chunk: u32 = 24 * MIB;
        let pages: u32 = (BIG_MIB * MIB) / 65536; // 64 KiB Wasm pages
        println!("\n[read] populating {} canisters to ~{BIG_MIB} MiB stable each...", canisters.len());
        let _ = pages; // grow incrementally below instead of one big grow
        let grow_pages = chunk / 65536; // pages per 24 MiB step
        for (i, c) in canisters.iter().enumerate() {
            let (mut off, mut werr) = (0u32, 0u32);
            // Grow + fill one 24 MiB window at a time: a single 128 MiB grow can
            // be rejected, but small incremental grows reliably build the state.
            while off + chunk <= BIG_MIB * MIB {
                let p = wasm().stable_grow(grow_pages).stable_fill(off, 0x40 + i as u32, chunk).reply().build();
                if update(&agent, c, p).await.is_err() {
                    werr += 1;
                }
                off += chunk;
            }
            println!("  canister {i} = {c} populated ({werr} write errors)");
        }
        println!("[read] waiting ~25s for a checkpoint to flush state to disk...");
        tokio::time::sleep(Duration::from_secs(25)).await;

        // Read 24 MiB (< 32 MiB accessed limit) per call, cycling the offset
        // window across the populated range.
        let off_ctr = Arc::new(AtomicU64::new(0));
        let mk: Arc<dyn Fn() -> Vec<u8> + Send + Sync> = {
            let off_ctr = off_ctr.clone();
            let windows = ((BIG_MIB * MIB) / chunk) as u64; // cycle across the FULL state
            Arc::new(move || {
                let n = off_ctr.fetch_add(1, Ordering::Relaxed);
                let off = ((n % windows) as u32) * chunk;
                wasm().stable_read(off, chunk).reply().build()
            })
        };
        let all_cans = Arc::new(canisters.as_ref().clone());
        println!(
            "\n[read] read storm ({secs}s): 24 MiB stable_read/call — QUERIES across all {} canisters (cycling full range)",
            all_cans.len()
        );
        let t = Instant::now();
        let qs = storm(agent.clone(), all_cans, concurrency, Duration::from_secs(secs), mk.clone(), true).await;
        qs.report("READ-QUERY (24 MiB stable_read, all canisters)", t.elapsed());

        // Read-limit probe: access 48 MiB in one execution (> 32 MiB accessed
        // limit) -> expect a trap, for both update and query.
        println!("\n[read] read-limit probe: 48 MiB stable_read in one execution (accessed limit 32 MiB)");
        let ru = update(&agent, &canisters[0], wasm().stable_read(0, 48 * MIB).reply().build()).await;
        println!(
            "  update read 48 MiB: {}",
            if ru.is_ok() { "OK (no limit!)".to_string() } else { format!("TRAP {}", ru.as_ref().err().unwrap().chars().take(220).collect::<String>()) }
        );
        let rq = agent
            .execute_query(&canisters[canisters.len() - 1], "query", wasm().stable_read(0, 48 * MIB).reply().build())
            .await;
        println!(
            "  query  read 48 MiB: {}",
            if rq.is_ok() { "OK (no limit!)".to_string() } else { format!("TRAP {}", rq.as_ref().err().unwrap().chars().take(220).collect::<String>()) }
        );

        println!("\n== done ==");
        return;
    }

    if heapread_mode {
        // Build a large heap global per canister via append (24 MiB chunks, so
        // the transient heap stays small and all 3 globals fit under the cap).
        const BIG_MIB: u32 = 96;
        let chunk: u32 = 24 * MIB;
        let appends = (BIG_MIB * MIB) / chunk;
        println!("\n[heapread] populating {} canisters with a {BIG_MIB} MiB heap global...", canisters.len());
        for (i, c) in canisters.iter().enumerate() {
            let mut ok = true;
            for _ in 0..appends {
                if update(&agent, c, wasm().push_equal_bytes(0x41 + i as u32, chunk).append_to_global_data().reply().build()).await.is_err() {
                    ok = false;
                }
            }
            println!("  canister {i} = {c}: {}", if ok { "populated" } else { "PARTIAL/FAILED" });
        }
        println!("[heapread] waiting ~25s for a checkpoint to flush state to disk...");
        tokio::time::sleep(Duration::from_secs(25)).await;

        // Read the full 96 MiB global per call via queries on ALL canisters.
        // (Heap reads via update OOM: the get_global_data stack copy permanently
        // grows the heap. Queries discard it.) This pulls ~3x96 MiB of distinct
        // heap state into the page cache.
        println!(
            "\n[heapread] heap-read QUERY storm ({secs}s): get_global_data ({BIG_MIB} MiB) on all {} canisters, {concurrency} concurrent",
            canisters.len()
        );
        let t = Instant::now();
        let qs = storm(
            agent.clone(),
            canisters.clone(),
            concurrency,
            Duration::from_secs(secs),
            Arc::new(|| wasm().get_global_data().reply().build()),
            true,
        )
        .await;
        qs.report("HEAP-READ-QUERY (96 MiB/read)", t.elapsed());
        println!("\n== done ==");
        return;
    }

    if heap_mode {
        // ---- Heap per-message write probe ----
        // Stable memory traps a single message that dirties/accesses > 32 MiB;
        // heap (Wasm) memory has no such per-message cap. push_equal_bytes(b, n)
        // pushes n bytes onto the data stack, dirtying n bytes of heap.
        println!("\n[heap] per-message heap-write probe (stable's per-msg limit is 32 MiB; heap has none)");
        for sz in [24u32, 48, 96] {
            let r = update(&agent, &canisters[0], wasm().push_equal_bytes(0x61, sz * MIB).reply().build()).await;
            println!(
                "  push {sz} MiB onto heap in ONE message: {}",
                if r.is_ok() { "OK".to_string() } else { format!("TRAP {}", r.as_ref().err().unwrap().chars().take(200).collect::<String>()) }
            );
        }

        // ---- Heap-write storm (analogue of the COMPUTE storm) ----
        let upd_cans = Arc::new(canisters[..canisters.len() - 1].to_vec());
        println!("\n[heap] heap-write storm ({secs}s): 8 MiB heap write/call on {} canisters", upd_cans.len());
        let t = Instant::now();
        let ws = storm(
            agent.clone(),
            upd_cans.clone(),
            concurrency,
            Duration::from_secs(secs),
            Arc::new(|| wasm().push_equal_bytes(0x61, 8 * MIB).reply().build()),
            false,
        )
        .await;
        ws.report("HEAP-WRITE (8 MiB/call)", t.elapsed());

        // ---- Populate a persistent heap global, then read it ----
        // 96 MiB so each get_global_data read pulls ~96 MiB of distinct state
        // into memory (no per-execution accessed cap on heap, unlike stable's
        // 32 MiB). 3 canisters x 96 MiB = ~288 MiB distinct read working set.
        const BIG_MIB: u32 = 96;
        println!("\n[heap] populating {} canisters with a {BIG_MIB} MiB heap global...", canisters.len());
        for (i, c) in canisters.iter().enumerate() {
            let r = update(
                &agent,
                c,
                wasm().push_equal_bytes(0x41 + i as u32, BIG_MIB * MIB).set_global_data_from_stack().reply().build(),
            )
            .await;
            println!("  canister {i} = {c}: {}", if r.is_ok() { "populated".to_string() } else { format!("ERR {}", r.as_ref().err().unwrap().chars().take(160).collect::<String>()) });
        }
        println!("[heap] waiting ~25s for a checkpoint...");
        tokio::time::sleep(Duration::from_secs(25)).await;

        // ---- Heap-read storm (analogue of the stable READ test) ----
        // get_global_data reads the whole 40 MiB global in one execution — more
        // than the 32 MiB stable per-message accessed limit would ever allow.
        let qry_cans = Arc::new(vec![canisters[canisters.len() - 1]]);
        println!(
            "\n[heap] heap-read storm ({secs}s): read {BIG_MIB} MiB heap global/call — UPDATES on {} canisters, QUERIES on 1",
            upd_cans.len()
        );
        let t = Instant::now();
        let (us, qs) = tokio::join!(
            storm(agent.clone(), upd_cans.clone(), concurrency, Duration::from_secs(secs), Arc::new(|| wasm().get_global_data().reply().build()), false),
            storm(agent.clone(), qry_cans.clone(), concurrency, Duration::from_secs(secs), Arc::new(|| wasm().get_global_data().reply().build()), true),
        );
        us.report("HEAP-READ-UPDATE (40 MiB heap read)", t.elapsed());
        qs.report("HEAP-READ-QUERY (40 MiB heap read)", t.elapsed());

        println!("\n== done ==");
        return;
    }

    if !probe_only {
    // ---- Phase A: ingress/throughput storm (near-empty updates) ----
    println!("\n[2/5] THROUGHPUT storm: empty update calls, {concurrency} concurrent, {secs}s");
    let t = Instant::now();
    let stats = storm(
        agent.clone(),
        canisters.clone(),
        concurrency,
        Duration::from_secs(secs),
        Arc::new(|| wasm().reply().build()),
        false,
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
        false,
    )
    .await;
    stats.report("COMPUTE (8 MiB fill)", t.elapsed());
    }

    // ---- Phase C: per-message dirty-page limit (32 MiB) ----
    // Grow in a separate (committed) message first, then fill in-bounds amounts
    // so we isolate the *dirty-page* limit from any grow/bounds effects.
    println!("\n[4/5] DIRTY-LIMIT probe (per-message stable dirty limit = 32 MiB)");
    let c = canisters[0];
    let g = update(&agent, &c, wasm().stable_grow(1024).reply().build()).await; // +64 MiB, commit
    println!(
        "  grow +64 MiB (own message): {}",
        if g.is_ok() { "OK".to_string() } else { format!("ERR {}", g.as_ref().err().unwrap().chars().take(200).collect::<String>()) }
    );
    let small = update(&agent, &c, wasm().stable_fill(0, 0x62, 24 * MIB).reply().build()).await;
    println!(
        "  fill 24 MiB (UNDER 32 MiB limit): {}",
        if small.is_ok() { "OK".to_string() } else { format!("ERR {}", small.as_ref().err().unwrap().chars().take(260).collect::<String>()) }
    );
    let big = update(&agent, &c, wasm().stable_fill(0, 0x62, 48 * MIB).reply().build()).await;
    println!(
        "  fill 48 MiB (OVER 32 MiB limit):  {}",
        if big.is_ok() { "OK — NO LIMIT ENFORCED".to_string() } else { format!("TRAP {}", big.as_ref().err().unwrap().chars().take(320).collect::<String>()) }
    );

    if !probe_only {
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
    }

    println!("\n== done ==");
}
