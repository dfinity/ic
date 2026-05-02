//! `ic-ai-state-query` — read-only IC subnet state introspection for LLM tool calls.
//!
//! Designed to be invoked from ollama (or any other LLM) as a tool. Always
//! prints JSON to stdout. Loads the latest verified checkpoint under the
//! state root; bypasses `StateManagerImpl` and consensus entirely.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{ReplicatedState, page_map::TestPageAllocatorFileDescriptorImpl};
use ic_state_layout::{CompleteCheckpointLayout, StateLayout};
use ic_state_manager::{CheckpointMetrics, checkpoint::load_checkpoint};
use ic_types::{CanisterId, Height, ingress::IngressStatus};
use ic_types_cycles::{Cycles, NominalCycles};
use serde::Serialize;

const DEFAULT_STATE_ROOT: &str = "/var/lib/ic/data/ic_state";

#[derive(Parser, Debug)]
#[command(
    name = "ic-ai-state-query",
    about = "Query a locally synced IC subnet state checkpoint. Output is JSON."
)]
struct Cli {
    /// Path to the IC state root (e.g. `/var/lib/ic/data/ic_state`).
    #[arg(long, default_value = DEFAULT_STATE_ROOT)]
    state_root: PathBuf,

    /// Use a specific checkpoint height instead of the latest verified one.
    #[arg(long)]
    height: Option<u64>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Summary of the subnet at the chosen checkpoint.
    Summary,
    /// List all canisters in the subnet (sorted by memory by default).
    ListCanisters {
        /// Sort key: memory | cycles | id
        #[arg(long, default_value = "memory")]
        sort_by: String,
        /// Limit the number of returned canisters.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Detailed info about a single canister.
    Canister {
        /// Canister id (textual form, e.g. `rrkah-fqaaa-aaaaa-aaaaq-cai`).
        canister_id: String,
    },
    /// Recent ingress messages and their statuses.
    Ingress {
        /// Limit the number of messages.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Available checkpoint heights on this node.
    Heights,
}

#[derive(Serialize)]
struct ErrorOut<'a> {
    error: &'a str,
}

fn main() {
    let cli = Cli::parse();
    let result = run(&cli);
    match result {
        Ok(json) => println!("{json}"),
        Err(e) => {
            // Always emit JSON, even on error — easier for LLM tool consumers.
            let json = serde_json::to_string_pretty(&ErrorOut { error: &e })
                .unwrap_or_else(|_| format!("{{\"error\":\"{}\"}}", escape_json(&e)));
            println!("{json}");
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<String, String> {
    match &cli.command {
        Cmd::Heights => {
            let layout = open_state_layout(&cli.state_root)?;
            let heights = layout
                .verified_checkpoint_heights()
                .map_err(|e| format!("failed to enumerate checkpoints: {e:?}"))?;
            let out = serde_json::json!({
                "state_root": cli.state_root,
                "verified_checkpoint_heights": heights.iter().map(|h| h.get()).collect::<Vec<_>>(),
                "latest": heights.last().map(|h| h.get()),
            });
            Ok(serde_json::to_string_pretty(&out).unwrap())
        }
        _ => {
            let (state, height) = load_chosen_state(cli)?;
            match &cli.command {
                Cmd::Summary => Ok(summary_json(&state, height)?),
                Cmd::ListCanisters { sort_by, limit } => {
                    Ok(list_canisters_json(&state, sort_by, *limit)?)
                }
                Cmd::Canister { canister_id } => Ok(canister_json(&state, canister_id)?),
                Cmd::Ingress { limit } => Ok(ingress_json(&state, *limit)?),
                Cmd::Heights => unreachable!(),
            }
        }
    }
}

fn open_state_layout(state_root: &PathBuf) -> Result<StateLayout, String> {
    StateLayout::try_new(no_op_logger(), state_root.clone(), &MetricsRegistry::new())
        .map_err(|e| format!("failed to open state layout at {state_root:?}: {e:?}"))
}

fn load_chosen_state(cli: &Cli) -> Result<(ReplicatedState, Height), String> {
    let layout = open_state_layout(&cli.state_root)?;
    let height = match cli.height {
        Some(h) => Height::new(h),
        None => *layout
            .verified_checkpoint_heights()
            .map_err(|e| format!("failed to enumerate checkpoints: {e:?}"))?
            .last()
            .ok_or_else(|| {
                format!(
                    "no verified checkpoints under {} — has the AI node finished syncing yet?",
                    cli.state_root.display()
                )
            })?,
    };
    let cp_layout = layout
        .checkpoint_verified(height)
        .map_err(|e| format!("failed to access checkpoint @{height}: {e:?}"))?;
    let cp_path = cp_layout.raw_path().to_path_buf();
    drop(cp_layout);

    let untracked = CompleteCheckpointLayout::new_untracked(cp_path, height)
        .map_err(|e| format!("failed to build CheckpointLayout: {e:?}"))?;
    let state = load_checkpoint(
        &untracked,
        SubnetType::Application,
        &CheckpointMetrics::new(&MetricsRegistry::new(), no_op_logger()),
        None,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .map_err(|e| format!("failed to load checkpoint @{height}: {e:?}"))?;
    Ok((state, height))
}

// -------------------- output formatters --------------------

fn summary_json(state: &ReplicatedState, height: Height) -> Result<String, String> {
    let md = &state.metadata;
    let sm = &md.subnet_metrics;

    let total_consumed = sm.consumed_cycles_total();
    let mut canisters: Vec<_> = state
        .canister_states()
        .iter()
        .map(|(id, c)| {
            (
                id.to_string(),
                u64::try_from(c.memory_usage().get()).unwrap_or(u64::MAX),
                cycles_to_u128(c.system_state.balance()),
            )
        })
        .collect();
    canisters.sort_by_key(|(_, mem, _)| std::cmp::Reverse(*mem));
    let top_by_memory: Vec<_> = canisters.iter().take(5).collect();

    let out = serde_json::json!({
        "subnet_id": md.own_subnet_id.to_string(),
        "subnet_type": format!("{:?}", md.own_subnet_type),
        "checkpoint_height": height.get(),
        "batch_time_unix_nanos": md.batch_time.as_nanos_since_unix_epoch(),
        "num_canisters": state.num_canisters(),
        "subnet_metrics": {
            "num_canisters": sm.num_canisters,
            "canister_state_bytes": u64::try_from(sm.canister_state_bytes.get()).unwrap_or(u64::MAX),
            "update_transactions_total": sm.update_transactions_total,
            "consumed_cycles_total": nominal_to_u128(total_consumed),
        },
        "ingress_history_size": state.metadata.ingress_history.statuses().count(),
        "top_canisters_by_memory": top_by_memory.iter().map(|(id, mem, bal)| {
            serde_json::json!({
                "canister_id": id,
                "memory_bytes": mem,
                "cycles_balance": bal,
            })
        }).collect::<Vec<_>>(),
        "subnets_in_topology": md.network_topology.subnets().len(),
    });
    Ok(serde_json::to_string_pretty(&out).unwrap())
}

fn list_canisters_json(
    state: &ReplicatedState,
    sort_by: &str,
    limit: Option<usize>,
) -> Result<String, String> {
    let mut rows: Vec<serde_json::Value> = state
        .canister_states()
        .iter()
        .map(|(id, c)| canister_summary_row(id, c))
        .collect();

    match sort_by {
        "memory" => rows.sort_by_key(|v| {
            std::cmp::Reverse(v.get("memory_bytes").and_then(|x| x.as_u64()).unwrap_or(0))
        }),
        "cycles" => rows.sort_by_key(|v| {
            std::cmp::Reverse(
                v.get("cycles_balance")
                    .and_then(|x| x.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0),
            )
        }),
        "id" | "canister_id" => {
            rows.sort_by(|a, b| {
                a.get("canister_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .cmp(b.get("canister_id").and_then(|x| x.as_str()).unwrap_or(""))
            });
        }
        other => return Err(format!("unknown sort_by '{other}' (memory|cycles|id)")),
    }
    if let Some(n) = limit {
        rows.truncate(n);
    }
    let out = serde_json::json!({
        "count": rows.len(),
        "sorted_by": sort_by,
        "canisters": rows,
    });
    Ok(serde_json::to_string_pretty(&out).unwrap())
}

fn canister_summary_row(
    id: &CanisterId,
    c: &ic_replicated_state::CanisterState,
) -> serde_json::Value {
    let module_hash = c
        .execution_state
        .as_ref()
        .map(|es| hex::encode(es.wasm_binary.binary.module_hash()));
    serde_json::json!({
        "canister_id": id.to_string(),
        "memory_bytes": u64::try_from(c.memory_usage().get()).unwrap_or(u64::MAX),
        "wasm_memory_bytes": u64::try_from(c.wasm_memory_usage().get()).unwrap_or(u64::MAX),
        "stable_memory_bytes": u64::try_from(c.stable_memory_usage().get()).unwrap_or(u64::MAX),
        "cycles_balance": cycles_to_u128(c.system_state.balance()).to_string(),
        "status": c.system_state.status_string(),
        "controllers": c
            .system_state
            .controllers
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>(),
        "module_hash": module_hash,
    })
}

fn canister_json(state: &ReplicatedState, canister_id_str: &str) -> Result<String, String> {
    use std::str::FromStr;
    let cid = CanisterId::from_str(canister_id_str)
        .map_err(|e| format!("invalid canister id '{canister_id_str}': {e:?}"))?;
    let c = state
        .canister_states()
        .get(&cid)
        .ok_or_else(|| format!("canister {cid} not found in this checkpoint"))?;

    let metrics = c.system_state.canister_metrics();
    let load = metrics.load_metrics();

    let by_use_case: Vec<serde_json::Value> = metrics
        .consumed_cycles_by_use_cases()
        .iter()
        .map(|(uc, cycles)| {
            serde_json::json!({
                "use_case": format!("{uc:?}"),
                "cycles": nominal_to_u128(*cycles).to_string(),
            })
        })
        .collect();

    let module_hash = c
        .execution_state
        .as_ref()
        .map(|es| hex::encode(es.wasm_binary.binary.module_hash()));
    let wasm_size = c
        .execution_state
        .as_ref()
        .map(|es| es.wasm_binary.binary.as_slice().len() as u64);

    let mut row = canister_summary_row(&cid, c);
    if let Some(obj) = row.as_object_mut() {
        obj.insert(
            "freeze_threshold_seconds".into(),
            serde_json::json!(c.system_state.freeze_threshold.get()),
        );
        obj.insert(
            "compute_allocation_pct".into(),
            serde_json::json!(c.system_state.compute_allocation.as_percent()),
        );
        obj.insert("wasm_module_hash".into(), serde_json::json!(module_hash));
        obj.insert(
            "wasm_module_size_bytes".into(),
            serde_json::json!(wasm_size),
        );
        obj.insert(
            "instructions_executed".into(),
            serde_json::json!(metrics.instructions_executed().get()),
        );
        obj.insert(
            "ingress_messages_executed".into(),
            serde_json::json!(load.ingress_messages_executed()),
        );
        obj.insert(
            "remote_subnet_messages_executed".into(),
            serde_json::json!(load.remote_subnet_messages_executed()),
        );
        obj.insert(
            "local_subnet_messages_executed".into(),
            serde_json::json!(load.local_subnet_messages_executed()),
        );
        obj.insert(
            "http_outcalls_executed".into(),
            serde_json::json!(load.http_outcalls_executed()),
        );
        obj.insert(
            "heartbeats_and_global_timers_executed".into(),
            serde_json::json!(load.heartbeats_and_global_timers_executed()),
        );
        obj.insert(
            "consumed_cycles_total".into(),
            serde_json::json!(nominal_to_u128(metrics.consumed_cycles()).to_string()),
        );
        obj.insert(
            "consumed_cycles_by_use_case".into(),
            serde_json::Value::Array(by_use_case),
        );
    }
    Ok(serde_json::to_string_pretty(&row).unwrap())
}

fn ingress_json(state: &ReplicatedState, limit: usize) -> Result<String, String> {
    let mut rows: Vec<serde_json::Value> = state
        .metadata
        .ingress_history
        .statuses()
        .take(limit)
        .map(|(id, status)| {
            let kind = match status {
                IngressStatus::Known { state, .. } => format!("{state:?}"),
                IngressStatus::Unknown => "Unknown".to_string(),
            };
            let receiver = match status {
                IngressStatus::Known { receiver, .. } => Some(receiver.to_string()),
                IngressStatus::Unknown => None,
            };
            let user_id = match status {
                IngressStatus::Known { user_id, .. } => Some(user_id.get().to_string()),
                IngressStatus::Unknown => None,
            };
            serde_json::json!({
                "message_id": format!("{id}"),
                "status": kind,
                "receiver": receiver,
                "user": user_id,
            })
        })
        .collect();
    rows.truncate(limit);
    let out = serde_json::json!({
        "count": rows.len(),
        "messages": rows,
    });
    Ok(serde_json::to_string_pretty(&out).unwrap())
}

// -------------------- helpers --------------------

fn cycles_to_u128(c: Cycles) -> u128 {
    c.get()
}

fn nominal_to_u128(c: NominalCycles) -> u128 {
    c.get()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
