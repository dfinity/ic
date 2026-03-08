# Canister Logging

This specification covers the canister logging system, including log production and access control.

## Requirements

### Requirement: Canister Log Production

Canisters produce logs during execution via the `ic0.debug_print` System API.

#### Scenario: Log message creation
- **WHEN** a canister calls `ic0.debug_print` during execution
- **THEN** a log record is created with the message content, a monotonic index, and the current timestamp

#### Scenario: Log persistence
- **WHEN** a canister produces log messages during a successful execution
- **THEN** the log messages are persisted in the canister's system state
- **AND** logs survive across rounds but may be truncated based on memory limits

#### Scenario: Log memory limit
- **WHEN** the canister's log memory usage reaches its `log_memory_limit`
- **THEN** oldest log entries are discarded to make room for new ones
- **AND** the default aggregate log memory limit applies if no custom limit is set

#### Scenario: Logs cleared on install/reinstall
- **WHEN** a canister is installed or reinstalled
- **THEN** the canister's log history is cleared

### Requirement: Fetching Canister Logs

Authorized users can fetch canister logs via the management canister.

#### Scenario: Fetch logs by controller
- **WHEN** a controller calls `fetch_canister_logs`
- **THEN** the canister's log records are returned

#### Scenario: Fetch logs with public visibility
- **WHEN** a canister has `log_visibility` set to `Public`
- **AND** any principal calls `fetch_canister_logs`
- **THEN** the log records are returned

#### Scenario: Fetch logs with controller-only visibility
- **WHEN** a canister has `log_visibility` set to `Controllers`
- **AND** a non-controller calls `fetch_canister_logs`
- **THEN** the request is rejected with `CanisterRejectedMessage`

#### Scenario: Fetch logs with allowed viewers
- **WHEN** a canister has `log_visibility` set to `AllowedViewers(principals)`
- **AND** a caller who is in the allowed viewers list calls `fetch_canister_logs`
- **THEN** the log records are returned

#### Scenario: Fetch logs with allowed viewers - denied
- **WHEN** a canister has `log_visibility` set to `AllowedViewers(principals)`
- **AND** a caller who is NOT in the allowed viewers list and NOT a controller calls `fetch_canister_logs`
- **THEN** the request is rejected

### Requirement: Log Filtering

Log records can be filtered when fetching.

#### Scenario: Filter by index range
- **WHEN** `fetch_canister_logs` is called with a `ByIdx` filter range
- **THEN** only log records within the specified index range are returned

#### Scenario: Filter by timestamp range
- **WHEN** `fetch_canister_logs` is called with a `ByTimestampNanos` filter range
- **THEN** only log records within the specified timestamp range are returned

#### Scenario: No filter
- **WHEN** `fetch_canister_logs` is called without a filter
- **THEN** all available log records are returned

### Requirement: Log Memory Store

An optional feature-flagged log memory store provides persistent log storage.

#### Scenario: Log memory store enabled
- **WHEN** the `log_memory_store` feature is enabled
- **THEN** logs are stored in a dedicated memory-backed store
- **AND** the store supports efficient filtering by index or timestamp

#### Scenario: Log memory store disabled
- **WHEN** the `log_memory_store` feature is disabled
- **THEN** logs are stored in the legacy in-memory `canister_log` structure
