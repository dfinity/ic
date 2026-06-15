//! Tool: `ic_logs` — **TODO, not implemented**.
//!
//! Intent: pull recent systemd journal entries for an allow-listed
//! systemd unit (e.g. `ic-replica.service`, `ic-orchestrator.service`)
//! from a peer node, with client-side filtering by time window,
//! priority ceiling, and substring grep. The natural transport is
//! `systemd-journal-gatewayd` on port 19531, which every IC node
//! exposes; the previous draft implementation in this file targeted
//! that endpoint with a `Range: entries=...` header and an allow-list
//! of services.
//!
//! Why it's stubbed for now: the `gatewayd` socket isn't reachable
//! over the IPv6 we resolve from the registry on AI nodes today, so
//! shipping the tool would mean shipping something that always
//! returns transport errors. We'd rather expose the gap explicitly
//! than have the LLM keep retrying a broken endpoint.
//!
//! When picking this back up:
//! * Confirm the journal-gatewayd port and TLS posture across guestos
//!   variants (it may need the same `danger_accept_invalid_certs(true)`
//!   treatment as `node_exporter`).
//! * Bring back the allow-list of systemd units (replica, orchestrator,
//!   crypto-csp, btc/https-outcalls adapters, node_exporter, nftables,
//!   chrony) — this is the only thing keeping the LLM from being able
//!   to ask for arbitrary host logs.
//! * Re-add the registration in `tools/mod.rs`, `tools/registry.rs`,
//!   `providers/mod.rs::AiProvider::prompt`, and the preamble in `config.rs`.
//!
//! The shared `NodeDirectory` (in `tools/node_directory.rs`) is
//! already wired up for this — `ic_logs` will resolve `node_id ->
//! ipv6` the same way `ic_metrics` does, so reviving the tool is
//! purely a matter of restoring the gatewayd HTTP client + the
//! filtering logic.
