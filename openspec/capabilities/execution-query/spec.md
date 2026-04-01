# Execution: Query Execution Capability Specification

**Source narrative**: `openspec/specs/execution/query-execution.md`
**Crates**: `ic-execution-environment`
**Key files**: `rs/execution_environment/src/query_handler/`

---

## REQ-QUERY-001: Non-Replicated Query Execution

Queries MUST execute without consensus and without persisting state changes.

### SCENARIO-QUERY-001: Pure query execution
**Given** a query is received via the HTTP query endpoint
**When** the query executes
**Then** the canister's query or composite_query method is invoked against the latest certified state
**And** state changes from the execution are NOT persisted
**And** the result is returned directly to the caller

### SCENARIO-QUERY-002: Query method resolution
**Given** a query method name is received
**When** method resolution runs
**Then** the system checks for `composite_query` export first, then `query` export
**And** if neither is exported, an error is returned

### SCENARIO-QUERY-003: Data certificate available in queries
**Given** a non-replicated query executes
**When** the canister calls `ic0.data_certificate_copy`
**Then** the data certificate for the canister's certified data is available
**And** the certificate is obtained from the latest certified state

### SCENARIO-QUERY-004: Query instruction limit
**Given** a query execution exceeds `max_instructions_per_query_message`
**When** the limit is hit
**Then** the query fails with an instruction limit error

### SCENARIO-QUERY-005: Query state isolation
**Given** a query modifies canister state (heap memory, globals) during execution
**When** the query completes
**Then** the modifications are discarded
**And** the replicated state is unchanged

---

## REQ-QUERY-002: Composite Query Execution

Composite queries MUST support inter-canister query calls within the non-replicated context.

### SCENARIO-QUERY-006: Composite query call graph (breadth-first)
**Given** a composite query makes inter-canister calls
**When** the call graph is evaluated
**Then** calls are evaluated breadth-first
**And** each callee executes its query method and returns a response
**And** the caller's reply or reject callback is invoked with the response

### SCENARIO-QUERY-007: Composite query depth limit
**Given** a composite query call graph exceeds `max_query_call_graph_depth`
**When** the limit is checked
**Then** further calls fail with an error

### SCENARIO-QUERY-008: Composite query total instruction limit
**Given** total instructions across all calls in a composite query exceed `max_query_call_graph_instructions`
**When** the limit is hit
**Then** the composite query fails

### SCENARIO-QUERY-009: Composite query walltime limit
**Given** a composite query exceeds `query_context_time_limit`
**When** the timeout fires
**Then** the composite query fails with a timeout error

### SCENARIO-QUERY-010: Composite query per-call overhead
**Given** a composite query makes an inter-canister call
**When** the call is made
**Then** `instruction_overhead_per_query_call` is charged from the total query instruction budget

### SCENARIO-QUERY-011: Composite query same-subnet only
**Given** a composite query attempts to call a canister on a different subnet
**When** the call is attempted
**Then** the call fails (composite queries only support same-subnet calls)

---

## REQ-QUERY-003: Query Cache

Query results MUST be cached to improve performance for repeated identical queries.

### SCENARIO-QUERY-012: Cache hit returns cached result
**Given** a query is received with the same canister ID, method, payload, and caller
**And** the cached entry is still valid (canister version unchanged, time within bounds, balance unchanged)
**When** the cache is checked
**Then** the cached result is returned without re-executing the query

### SCENARIO-QUERY-013: Cache miss executes and stores
**Given** a query has no matching valid entry in the cache
**When** the cache is checked
**Then** the query is executed and the result is stored in the cache

### SCENARIO-QUERY-014: Cache invalidation by canister version
**Given** a cached entry exists but the canister version has changed
**When** the cache is checked
**Then** the cached entry is invalidated and the query is re-executed

### SCENARIO-QUERY-015: Cache invalidation by time
**Given** a cached entry exists but the query called `ic0.time()` and time has changed
**When** the cache is checked
**Then** the cached entry is invalidated

### SCENARIO-QUERY-016: Cache invalidation by data certificate expiry
**Given** a cached entry used `ic0.data_certificate_copy` and the certificate has expired
**When** the cache is checked
**Then** the cached entry is invalidated

### SCENARIO-QUERY-017: Cache invalidation by balance change
**Given** a cached entry used `ic0.canister_cycle_balance*` and the balance has changed
**When** the cache is checked
**Then** the cached entry is invalidated

### SCENARIO-QUERY-018: Cache eviction (LRU)
**Given** the query cache exceeds its capacity
**When** eviction runs
**Then** least-recently-used entries are evicted

### SCENARIO-QUERY-019: Cache max expiry
**Given** a cached entry has been in cache longer than `query_cache_max_expiry_time`
**When** the expiry is checked
**Then** the entry is invalidated regardless of other conditions

---

## REQ-QUERY-004: Query Scheduling

Queries MUST be dispatched on a dedicated thread pool.

### SCENARIO-QUERY-020: Query thread pool dispatch
**Given** queries arrive for execution
**When** they are dispatched
**Then** they are dispatched to a thread pool with `query_execution_threads_total` threads

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-QUERY-001 | Non-replicated query | narrative | rs/execution_environment/src/query_handler/ |
| REQ-QUERY-002 | Composite query | narrative | rs/execution_environment/src/query_handler/ |
| REQ-QUERY-003 | Query cache | linked | rs/execution_environment/src/query_handler/query_cache.rs |
| REQ-QUERY-004 | Query scheduling | narrative | rs/execution_environment/src/query_handler/ |
