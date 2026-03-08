# Query Execution

This specification covers non-replicated query execution, composite queries, and query caching.

## Requirements

### Requirement: Non-Replicated Query Execution

Queries are executed without consensus and do not modify replicated state.

#### Scenario: Pure query execution
- **WHEN** a query is received via the HTTP query endpoint
- **THEN** the query is executed against the latest certified state
- **AND** the canister's query or composite_query method is invoked
- **AND** state changes from the execution are not persisted
- **AND** the result is returned directly to the caller

#### Scenario: Query method resolution
- **WHEN** a query method name is received
- **THEN** the system first checks if it is exported as a `composite_query`
- **AND** if not, checks if it is exported as a `query`
- **AND** if neither, an error is returned

#### Scenario: Data certificate in queries
- **WHEN** a non-replicated query is executed
- **THEN** the data certificate for the canister's certified data is available via `ic0.data_certificate_copy`
- **AND** the certificate is obtained from the latest certified state

#### Scenario: Query instruction limit
- **WHEN** a query execution exceeds `max_instructions_per_query_message`
- **THEN** the query fails with an instruction limit error

#### Scenario: Query state isolation
- **WHEN** a query modifies canister state (heap memory, globals)
- **THEN** the modifications are visible within the query execution
- **AND** the modifications are discarded after the query completes
- **AND** the replicated state is unchanged

### Requirement: Composite Query Execution

Composite queries can make inter-canister query calls within the non-replicated context.

#### Scenario: Composite query call graph
- **WHEN** a composite query makes inter-canister calls
- **THEN** the calls form a call graph that is evaluated breadth-first
- **AND** each callee executes its query method and returns a response
- **AND** the caller's reply or reject callback is invoked with the response

#### Scenario: Composite query depth limit
- **WHEN** a composite query call graph exceeds `max_query_call_graph_depth`
- **THEN** further calls fail with an error

#### Scenario: Composite query instruction limit
- **WHEN** the total instructions across all calls in a composite query exceed `max_query_call_graph_instructions`
- **THEN** the composite query fails

#### Scenario: Composite query walltime limit
- **WHEN** a composite query exceeds `query_context_time_limit`
- **THEN** the composite query fails with a timeout error

#### Scenario: Composite query call overhead
- **WHEN** a composite query makes an inter-canister call
- **THEN** an instruction overhead (`instruction_overhead_per_query_call`) is charged from the total query instruction budget

#### Scenario: Composite query on same subnet only
- **WHEN** a composite query attempts to call a canister on a different subnet
- **THEN** the call fails because composite queries only support same-subnet calls

### Requirement: Query Cache

Query results are cached to improve performance for repeated identical queries.

#### Scenario: Cache hit
- **WHEN** a query is received with the same canister ID, method name, payload, and caller
- **AND** the cached entry is still valid (canister version unchanged, time within bounds, balance unchanged)
- **THEN** the cached result is returned without re-executing the query

#### Scenario: Cache miss
- **WHEN** a query has no matching entry in the cache
- **THEN** the query is executed and the result is stored in the cache

#### Scenario: Cache invalidation by canister version
- **WHEN** a cached query entry exists but the canister version has changed since the entry was created
- **THEN** the cached entry is invalidated
- **AND** the query is re-executed

#### Scenario: Cache invalidation by time
- **WHEN** a cached query entry exists but the query called `ic0.time()` and time has changed
- **THEN** the cached entry is invalidated

#### Scenario: Cache invalidation by data certificate expiry
- **WHEN** a cached query entry exists and the query used `ic0.data_certificate_copy`
- **AND** the data certificate expiry time has passed
- **THEN** the cached entry is invalidated

#### Scenario: Cache invalidation by balance change
- **WHEN** a cached query entry exists and the query called `ic0.canister_cycle_balance*`
- **AND** the canister's cycles balance has changed
- **THEN** the cached entry is invalidated

#### Scenario: Cache invalidation by transient error
- **WHEN** a cached query entry was produced with transient errors (e.g., query call failed due to transient issue)
- **THEN** the cached entry is invalidated and the query is re-executed

#### Scenario: Cache eviction
- **WHEN** the query cache exceeds its capacity
- **THEN** least-recently-used entries are evicted

#### Scenario: Cache max expiry time
- **WHEN** a cached entry has been in the cache longer than `query_cache_max_expiry_time`
- **THEN** the entry is invalidated regardless of other conditions

### Requirement: Query Scheduling

Queries are scheduled and executed on dedicated threads.

#### Scenario: Query thread pool
- **WHEN** queries arrive for execution
- **THEN** they are dispatched to a thread pool with `query_execution_threads_total` threads

#### Scenario: Per-canister query concurrency
- **WHEN** multiple queries target the same canister
- **THEN** concurrency is limited to `query_execution_threads_per_canister` threads
- **AND** this prevents a single canister from monopolizing all query threads

#### Scenario: Query time slicing
- **WHEN** a canister has been executing queries for longer than `query_scheduling_time_slice_per_canister`
- **THEN** other canisters are prioritized for execution

### Requirement: Query Stats Collection

Query execution statistics are collected for billing purposes.

#### Scenario: Query stats tracking
- **WHEN** a query completes execution
- **THEN** the number of instructions executed and the number of messages are recorded
- **AND** these stats are aggregated and reported for canister billing

### Requirement: Management Canister Queries

Certain management canister methods can be called as queries.

#### Scenario: Fetch canister logs query
- **WHEN** `fetch_canister_logs` is called as a query
- **THEN** the canister logs are returned if the caller has permission
- **AND** log visibility settings (Public, Controllers, AllowedViewers) are respected

#### Scenario: Canister metadata query
- **WHEN** `canister_metadata` is called as a query
- **THEN** the requested metadata section is returned if it exists and is public
