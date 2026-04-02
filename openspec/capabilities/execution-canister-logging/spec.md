# Execution: Canister Logging Capability Specification

**Source narrative**: `openspec/specs/execution/canister-logging.md`
**Crates**: `ic-execution-environment`
**Key files**: `rs/execution_environment/src/`, `rs/replicated_state/src/canister_state/system_state.rs`

---

## REQ-LOG-001: Canister Log Production

Canisters MUST produce logs via `ic0.debug_print` that persist in system state.

### SCENARIO-LOG-001: Log message creation
**Given** a canister calls `ic0.debug_print` during execution
**When** the call runs
**Then** a log record is created with content, monotonic index, and current timestamp

### SCENARIO-LOG-002: Logs cleared on install/reinstall
**Given** a canister is installed or reinstalled
**When** the operation completes
**Then** the canister's log history is cleared

### SCENARIO-LOG-003: Log memory limit enforcement
**Given** the canister's log memory usage reaches `log_memory_limit`
**When** a new log is produced
**Then** oldest log entries are discarded to make room

---

## REQ-LOG-002: Fetching Canister Logs

Authorized users MUST be able to fetch canister logs via the management canister.

### SCENARIO-LOG-004: Fetch logs by controller
**Given** a controller calls `fetch_canister_logs`
**When** the fetch runs
**Then** the canister's log records are returned

### SCENARIO-LOG-005: Public visibility allows all callers
**Given** a canister has `log_visibility = Public`
**When** any principal calls `fetch_canister_logs`
**Then** the log records are returned

### SCENARIO-LOG-006: Controller-only visibility rejects non-controllers
**Given** a canister has `log_visibility = Controllers`
**And** a non-controller calls `fetch_canister_logs`
**When** the request is processed
**Then** the request is rejected with `CanisterRejectedMessage`

### SCENARIO-LOG-007: AllowedViewers grants access to listed principals
**Given** a canister has `log_visibility = AllowedViewers(principals)`
**And** a caller in the allowed list calls `fetch_canister_logs`
**When** the request is processed
**Then** the log records are returned

### SCENARIO-LOG-008: AllowedViewers denies unlisted non-controllers
**Given** a canister has `log_visibility = AllowedViewers(principals)`
**And** a caller NOT in the list and NOT a controller calls `fetch_canister_logs`
**When** the request is processed
**Then** the request is rejected

---

## REQ-LOG-003: Log Filtering

Log records MUST support filtering by index or timestamp range.

### SCENARIO-LOG-009: Filter by index range
**Given** `fetch_canister_logs` is called with a `ByIdx` filter
**When** filtering runs
**Then** only records within the specified index range are returned

### SCENARIO-LOG-010: Filter by timestamp range
**Given** `fetch_canister_logs` is called with a `ByTimestampNanos` filter
**When** filtering runs
**Then** only records within the specified timestamp range are returned

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-LOG-001 | Log production | narrative | rs/execution_environment/tests/ |
| REQ-LOG-002 | Log fetching | narrative | rs/execution_environment/tests/ |
| REQ-LOG-003 | Log filtering | narrative | rs/execution_environment/tests/ |
