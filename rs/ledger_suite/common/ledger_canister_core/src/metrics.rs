//! Metrics that both ledgers expose identically.

use crate::archive::{Archive, ArchiveCanisterWasm};
use crate::ledger::LedgerData;
use crate::runtime::Runtime;
use ic_metrics_encoder::MetricsEncoder;

/// Exposes the archiving configuration that is otherwise not observable from
/// outside the canister, with the defaults of the optional `ArchiveOptions`
/// fields already applied.
///
/// `trigger_threshold`, `num_blocks_to_archive` and `max_message_size_bytes`
/// govern the ledger's own behaviour and take effect immediately. The memory cap
/// and the creation cycles are only used when the ledger spawns a *new* archive:
/// an archive that already exists keeps the values it was installed with, and
/// reports them through its own metrics.
///
/// `effective_node_max_memory_size_bytes` is passed in because the two ledgers
/// resolve it differently: an ICRC archive clamps the cap it is given, an ICP
/// archive takes it as-is. The caller is the only one that knows which applies.
///
/// `max_transactions_per_response` is deliberately not reported here. Only the
/// ICRC archive has that setting, so the ICRC ledger emits it at its call site.
pub fn encode_archive_config_metrics<Rt, Wasm>(
    w: &mut MetricsEncoder<Vec<u8>>,
    archive: &Archive<Rt, Wasm>,
    effective_node_max_memory_size_bytes: u64,
) -> std::io::Result<()>
where
    Rt: Runtime,
    Wasm: ArchiveCanisterWasm,
{
    w.encode_gauge(
        "ledger_archive_trigger_threshold",
        archive.trigger_threshold as f64,
        "The number of blocks which, when exceeded, triggers archiving.",
    )?;
    w.encode_gauge(
        "ledger_archive_num_blocks_to_archive",
        archive.num_blocks_to_archive as f64,
        "The number of blocks archived when the trigger threshold is exceeded.",
    )?;
    w.encode_gauge(
        "ledger_archive_node_max_memory_size_bytes",
        effective_node_max_memory_size_bytes as f64,
        "Maximum number of bytes an archive spawned from now on may store. Existing \
         archives keep the cap they were created with, reported by their own metric.",
    )?;
    w.encode_gauge(
        "ledger_archive_max_message_size_bytes",
        archive.max_message_size_bytes as f64,
        "Archive option limiting the size in bytes of a message sent to an archive. \
         The size actually used is the smaller of this and the ledger's own \
         ledger_max_message_size_bytes.",
    )?;
    w.encode_gauge(
        "ledger_archive_cycles_for_archive_creation",
        archive.cycles_for_archive_creation as f64,
        "Cycles that will be attached to the call creating the next archive canister.",
    )?;
    Ok(())
}

/// Exposes the transaction-deduplication configuration, which is not observable
/// from outside the canister. The window is a constant on the ICRC ledger and a
/// configured value on the ICP ledger; both are reported here as the effective
/// value in force.
pub fn encode_dedup_config_metrics<LD: LedgerData>(
    w: &mut MetricsEncoder<Vec<u8>>,
    ledger: &LD,
) -> std::io::Result<()> {
    w.encode_gauge(
        "ledger_transaction_window_seconds",
        ledger.transaction_window().as_secs() as f64,
        "Length of the transaction deduplication window in seconds.",
    )?;
    w.encode_gauge(
        "ledger_max_transactions_in_window",
        ledger.max_transactions_in_window() as f64,
        "Maximum number of transactions retained in the deduplication window.",
    )?;
    w.encode_gauge(
        "ledger_max_transactions_to_purge",
        ledger.max_transactions_to_purge() as f64,
        "Maximum number of transactions purged from the deduplication window per operation.",
    )?;
    Ok(())
}
