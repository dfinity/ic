//! Tool: `ic_state`.
//!
//! Read-only inspector of the replicated state that the AiNode's
//! state-sync replica persists to disk. We don't materialise a full
//! `ReplicatedState` (that would mean wiring up the entire state-manager
//! machinery on every tool call, including page allocators, prometheus
//! registries, and a thread pool, just to answer questions like "who
//! controls canister X?"). Instead we use `ic_state_layout` to point at
//! the on-disk checkpoint directory and decode the individual
//! `*.pbuf` files we care about — `system_metadata.pbuf` for the subnet
//! view, `canister.pbuf` for per-canister state.
//!
//! All paths are derived from `ic.json5` at tool-init time so the tool
//! tracks whatever state directory the orchestrator-managed replica
//! actually writes to.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use ic_base_types::{CanisterId, PrincipalId};
use ic_config::{Config, ConfigSource};
use ic_protobuf::state::{
    canister_state_bits::v1::CanisterStateBits, system_metadata::v1::SystemMetadata,
};
use ic_state_layout::{CheckpointLayout, ReadOnly, error::LayoutError};
use ic_types::Height;
use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{state::AppState, tools::node_directory::NodeDirectory};

/// Subdirectory of `state_root` that holds the verified checkpoints.
/// Mirrors `ic_state_layout::CHECKPOINTS_DIR`.
const CHECKPOINTS_DIR: &str = "checkpoints";

#[derive(Debug, thiserror::Error)]
pub enum IcStateError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("state layout error: {0}")]
    Layout(#[from] LayoutError),

    #[error("invalid arg: {0}")]
    InvalidArg(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("failed to load replica config from {path}: {message}")]
    Config { path: PathBuf, message: String },
}

#[derive(Debug, Deserialize)]
pub struct IcStateArgs {
    /// Operation to run. One of:
    /// - `list_checkpoints` — heights of every verified or state-sync
    ///   checkpoint currently on disk, ordered ascending.
    /// - `subnet` — own-subnet metadata from the latest checkpoint:
    ///   subnet id, subnet type, node membership, NNS subnet id, batch
    ///   time, canister id ranges allocated to this subnet.
    /// - `list_canisters` — canister ids present in the latest
    ///   checkpoint, sorted, optionally filtered by substring.
    /// - `canister` — full per-canister view (controllers, cycles
    ///   balance, module hash, freeze threshold, memory/compute
    ///   allocations, version).
    pub op: String,

    /// Specific checkpoint height. Default: the latest checkpoint.
    /// Heights are u64; pass as a JSON number.
    pub height: Option<u64>,

    /// Substring filter for `list_canisters` (matched against the
    /// textual canister id, case-insensitive).
    pub filter: Option<String>,

    /// Canister id (textual form, e.g. `rrkah-fqaaa-aaaaa-aaaaq-cai`)
    /// for `op = "canister"`.
    pub canister_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IcStateOutput {
    pub op: String,
    pub state_root: String,
    pub data: serde_json::Value,
}

/// Tool struct. Holds the resolved state root path so we don't re-parse
/// `ic.json5` on every call. Re-parsing on every call would also race
/// against the orchestrator if/when it rewrites the file.
pub struct IcState {
    state_root: PathBuf,
    /// Kept for diagnostics in error messages, for the `state_root`
    /// field of every response (so the LLM can confirm which directory
    /// it's looking at), and to lazily fetch the shared node
    /// directory in `op=subnet`.
    state: Arc<AppState>,
}

impl IcState {
    /// Construct the tool. Parses `ic.json5` to discover the on-disk
    /// state root.
    ///
    /// Async to mirror the spec's `IcState::new(state.clone()).await?`
    /// shape (parsing is in fact synchronous; we shell out to
    /// `tokio::task::spawn_blocking` to avoid stalling the executor on
    /// the file read).
    pub async fn new(state: Arc<AppState>) -> Result<Self, IcStateError> {
        let cfg_path = state.config.ic_config_path.clone();
        let state_root = tokio::task::spawn_blocking(move || resolve_state_root(&cfg_path))
            .await
            .map_err(|e| IcStateError::Config {
                path: state.config.ic_config_path.clone(),
                message: format!("join error: {e}"),
            })??;
        Ok(Self { state_root, state })
    }

    /// Convenience constructor used in unit tests where we already know
    /// the state root.
    #[cfg(test)]
    pub fn for_root(state: Arc<AppState>, state_root: PathBuf) -> Self {
        Self { state_root, state }
    }

    /// Return the available verified checkpoint heights, ascending.
    fn list_checkpoint_heights(&self) -> Result<Vec<u64>, IcStateError> {
        let cps_dir = self.state_root.join(CHECKPOINTS_DIR);
        let entries = std::fs::read_dir(&cps_dir).map_err(|e| IcStateError::Io {
            path: cps_dir.clone(),
            source: e,
        })?;
        let mut heights = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| IcStateError::Io {
                path: cps_dir.clone(),
                source: e,
            })?;
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            // Checkpoint dirs are named with a 16-char zero-padded hex
            // height, e.g. "0000000000001234". `state_layout` is the
            // source of truth for the format
            // (`StateLayout::checkpoint_name`). Skip anything that
            // doesn't parse — the directory may also contain markers
            // for unverified or in-progress checkpoints in older
            // layouts.
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(h) = u64::from_str_radix(&name, 16) {
                heights.push(h);
            }
        }
        heights.sort_unstable();
        Ok(heights)
    }

    /// Pick a checkpoint height: caller-supplied if present, else the
    /// latest available.
    fn resolve_height(&self, requested: Option<u64>) -> Result<u64, IcStateError> {
        let heights = self.list_checkpoint_heights()?;
        if heights.is_empty() {
            return Err(IcStateError::NotFound(format!(
                "no checkpoints under {}",
                self.state_root.display()
            )));
        }
        match requested {
            None => Ok(*heights.last().unwrap()),
            Some(h) => {
                if heights.contains(&h) {
                    Ok(h)
                } else {
                    Err(IcStateError::NotFound(format!(
                        "checkpoint at height {h} not found; available: {heights:?}"
                    )))
                }
            }
        }
    }

    fn checkpoint_layout(&self, height: u64) -> Result<CheckpointLayout<ReadOnly>, IcStateError> {
        let name = format!("{:016x}", height);
        let cp_root = self.state_root.join(CHECKPOINTS_DIR).join(name);
        Ok(CheckpointLayout::<ReadOnly>::new_untracked(
            cp_root,
            Height::new(height),
        )?)
    }

    async fn op_subnet(&self, height: u64) -> Result<serde_json::Value, IcStateError> {
        let cp = self.checkpoint_layout(height)?;
        let metadata: SystemMetadata = cp.system_metadata().deserialize()?;

        let own_subnet_id = metadata
            .own_subnet_id
            .as_ref()
            .and_then(principal_to_string);

        let nns_subnet_id = metadata
            .network_topology
            .as_ref()
            .and_then(|nt| nt.nns_subnet_id.as_ref())
            .and_then(principal_to_string);

        // Best-effort: try to resolve node ipv6 addresses through the
        // shared registry-backed directory. If the registry isn't
        // reachable yet (e.g. fresh AiNode that hasn't synced) we
        // simply omit the ipv6 field on each entry — the LLM will
        // still see the node ids.
        let directory: Option<Arc<NodeDirectory>> = self.state.node_directory().await.ok();

        // Membership of every subnet (including this one) plus subnet
        // type. Useful for "how many nodes in subnet Z?" questions.
        let mut subnets = Vec::new();
        if let Some(nt) = &metadata.network_topology {
            for entry in &nt.subnets {
                let sid = entry.subnet_id.as_ref().and_then(principal_to_string);
                let topology = entry.subnet_topology.as_ref();
                let node_ids: Vec<String> = topology
                    .map(|t| {
                        t.nodes
                            .iter()
                            .filter_map(|n| n.node_id.as_ref().and_then(principal_to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let subnet_type = topology.map(|t| t.subnet_type).unwrap_or(0);

                let nodes: Vec<serde_json::Value> = node_ids
                    .iter()
                    .map(|nid| {
                        let ipv6 = directory
                            .as_ref()
                            .and_then(|d| d.resolve_ipv6(nid).ok())
                            .map(|ip| ip.to_string());
                        json!({"node_id": nid, "ipv6": ipv6})
                    })
                    .collect();

                subnets.push(json!({
                    "subnet_id": sid,
                    "node_count": nodes.len(),
                    "nodes": nodes,
                    "subnet_type": subnet_type,
                }));
            }
        }

        // Canister id ranges allocated to this subnet (so the LLM can
        // answer "is canister X on this subnet?").
        let canister_ranges = metadata.canister_allocation_ranges.as_ref().map(|r| {
            r.ranges
                .iter()
                .filter_map(|range| {
                    let start = range
                        .start_canister_id
                        .as_ref()
                        .and_then(principal_to_string);
                    let end = range.end_canister_id.as_ref().and_then(principal_to_string);
                    Some(json!({"start": start?, "end": end?}))
                })
                .collect::<Vec<_>>()
        });

        Ok(json!({
            "height": height,
            "own_subnet_id": own_subnet_id,
            "nns_subnet_id": nns_subnet_id,
            "batch_time_nanos": metadata.batch_time_nanos,
            "state_sync_version": metadata.state_sync_version,
            "certification_version": metadata.certification_version,
            "subnets": subnets,
            "canister_allocation_ranges": canister_ranges,
        }))
    }

    fn op_list_canisters(
        &self,
        height: u64,
        filter: Option<&str>,
    ) -> Result<serde_json::Value, IcStateError> {
        let cp = self.checkpoint_layout(height)?;
        let mut ids: Vec<CanisterId> = cp.canister_ids()?;
        ids.sort();
        let ids_str: Vec<String> = ids.into_iter().map(|c| c.to_string()).collect();
        let filtered: Vec<String> = match filter {
            Some(f) if !f.is_empty() => {
                let needle = f.to_lowercase();
                ids_str
                    .into_iter()
                    .filter(|id| id.to_lowercase().contains(&needle))
                    .collect()
            }
            _ => ids_str,
        };
        Ok(json!({
            "height": height,
            "count": filtered.len(),
            "canister_ids": filtered,
        }))
    }

    fn op_canister(
        &self,
        height: u64,
        canister_id: &str,
    ) -> Result<serde_json::Value, IcStateError> {
        let cid = CanisterId::from_str(canister_id).map_err(|e| {
            IcStateError::InvalidArg(format!("invalid canister_id '{canister_id}': {e}"))
        })?;
        let cp = self.checkpoint_layout(height)?;
        let canister_layout = cp.canister(&cid)?;
        if !canister_layout.raw_path().exists() {
            return Err(IcStateError::NotFound(format!(
                "canister {canister_id} not found at height {height}"
            )));
        }
        let bits: CanisterStateBits = canister_layout.canister().deserialize()?;
        let cycles_balance = bits
            .cycles_balance
            .as_ref()
            .map(|c| u128_from_le_bytes(&c.raw_cycles));
        let reserved_balance = bits
            .reserved_balance
            .as_ref()
            .map(|c| u128_from_le_bytes(&c.raw_cycles));
        let controllers: Vec<String> = bits
            .controllers
            .iter()
            .filter_map(principal_to_string)
            .collect();
        let module_hash_hex = bits
            .execution_state_bits
            .as_ref()
            .map(|esb| hex::encode(&esb.binary_hash))
            .filter(|h| !h.is_empty());
        let wasm64 = bits.execution_state_bits.as_ref().map(|esb| esb.is_wasm64);

        Ok(json!({
            "height": height,
            "canister_id": canister_id,
            "controllers": controllers,
            "cycles_balance": cycles_balance.map(|v| v.to_string()),
            "reserved_balance": reserved_balance.map(|v| v.to_string()),
            "freeze_threshold": bits.freeze_threshold,
            "compute_allocation": bits.compute_allocation,
            "memory_allocation": bits.memory_allocation,
            "canister_version": bits.canister_version,
            "stable_memory_size_bytes": bits.stable_memory_size64,
            "module_hash": module_hash_hex,
            "is_wasm64": wasm64,
        }))
    }
}

/// Best-effort conversion from a protobuf `PrincipalId` (any of the IC's
/// `PrincipalId`-shaped messages share the same `raw` field) to its
/// textual form.
fn principal_to_string<P: HasRaw>(p: &P) -> Option<String> {
    PrincipalId::try_from(p.raw_bytes())
        .ok()
        .map(|p| p.to_string())
}

/// Tiny abstraction over the various protobuf PrincipalId-shaped
/// messages so we can write `principal_to_string` once. The proto
/// modules don't share a common trait so we adapt them locally.
trait HasRaw {
    fn raw_bytes(&self) -> &[u8];
}

impl HasRaw for ic_protobuf::types::v1::PrincipalId {
    fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl HasRaw for ic_protobuf::types::v1::SubnetId {
    fn raw_bytes(&self) -> &[u8] {
        // SubnetId wraps a PrincipalId.
        self.principal_id
            .as_ref()
            .map(|p| p.raw.as_slice())
            .unwrap_or(&[])
    }
}

impl HasRaw for ic_protobuf::types::v1::NodeId {
    fn raw_bytes(&self) -> &[u8] {
        self.principal_id
            .as_ref()
            .map(|p| p.raw.as_slice())
            .unwrap_or(&[])
    }
}

impl HasRaw for ic_protobuf::types::v1::CanisterId {
    fn raw_bytes(&self) -> &[u8] {
        self.principal_id
            .as_ref()
            .map(|p| p.raw.as_slice())
            .unwrap_or(&[])
    }
}

/// Decode a little-endian byte sequence (up to 16 bytes) into a u128.
/// `Cycles.raw_cycles` is the LE encoding of the underlying u128.
fn u128_from_le_bytes(bytes: &[u8]) -> u128 {
    let mut buf = [0_u8; 16];
    let n = bytes.len().min(16);
    buf[..n].copy_from_slice(&bytes[..n]);
    u128::from_le_bytes(buf)
}

/// Parse `ic.json5` and return the absolute state root.
///
/// `Config::load_with_tmpdir` needs a tmpdir to materialise some
/// derived paths internally; we don't keep it alive afterwards because
/// we only read out `state_manager.state_root()` which doesn't escape
/// it.
fn resolve_state_root(cfg_path: &Path) -> Result<PathBuf, IcStateError> {
    if !cfg_path.exists() {
        return Err(IcStateError::Config {
            path: cfg_path.to_path_buf(),
            message: "file not found".to_string(),
        });
    }
    let tmpdir = tempfile::Builder::new()
        .prefix("ic-ai-agent-cfg")
        .tempdir()
        .map_err(|e| IcStateError::Config {
            path: cfg_path.to_path_buf(),
            message: format!("failed to create tmpdir: {e}"),
        })?;
    let config = Config::load_with_tmpdir(
        ConfigSource::File(cfg_path.to_path_buf()),
        tmpdir.path().to_path_buf(),
    );
    Ok(config.state_manager.state_root())
}

impl Tool for IcState {
    const NAME: &'static str = "ic_state";
    type Error = IcStateError;
    type Args = IcStateArgs;
    type Output = IcStateOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Query the Internet Computer state for canister, subnet, or node \
                information. Use this when the operator asks about what's deployed, \
                who controls a canister, cycles balance, module hash, or node \
                membership. Does not return metrics — use `ic_metrics` for that."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": ["list_checkpoints", "subnet", "list_canisters", "canister"],
                        "description":
                            "Which view of state to return. \
                             list_checkpoints: heights on disk. \
                             subnet: own-subnet topology + canister id ranges. \
                             list_canisters: canister ids in the latest (or specified) checkpoint. \
                             canister: full per-canister state."
                    },
                    "height": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Optional checkpoint height. Defaults to the latest."
                    },
                    "filter": {
                        "type": "string",
                        "description": "Substring filter for list_canisters (case-insensitive)."
                    },
                    "canister_id": {
                        "type": "string",
                        "description":
                            "Required for op=canister. Textual canister id, \
                             e.g. 'rrkah-fqaaa-aaaaa-aaaaq-cai'."
                    }
                },
                "required": ["op"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let data = match args.op.as_str() {
            "list_checkpoints" => {
                let heights = self.list_checkpoint_heights()?;
                let count = heights.len();
                json!({"heights": heights, "count": count})
            }
            "subnet" => {
                let h = self.resolve_height(args.height)?;
                self.op_subnet(h).await?
            }
            "list_canisters" => {
                let h = self.resolve_height(args.height)?;
                self.op_list_canisters(h, args.filter.as_deref())?
            }
            "canister" => {
                let cid = args.canister_id.ok_or_else(|| {
                    IcStateError::InvalidArg("canister_id is required for op=canister".to_string())
                })?;
                let h = self.resolve_height(args.height)?;
                self.op_canister(h, &cid)?
            }
            other => {
                return Err(IcStateError::InvalidArg(format!(
                    "unknown op '{other}'; expected list_checkpoints|subnet|list_canisters|canister"
                )));
            }
        };
        Ok(IcStateOutput {
            op: args.op,
            state_root: self.state_root.display().to_string(),
            data,
        })
    }
}
