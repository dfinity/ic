# Scheduler and Round Execution

This specification covers how the scheduler orchestrates execution rounds, including message ordering, canister scheduling, and resource limits.

## Requirements

### Requirement: Execution Round Structure

Each execution round processes subnet messages and canister messages within instruction budgets.

#### Scenario: Round execution phases
- **WHEN** an execution round begins
- **THEN** the following phases are executed in order:
  1. **Round preparation**: Initialize round limits, purge expired ingress messages, set up CSPRNG
  2. **Consensus queue draining**: Process all responses from the consensus queue (no instruction limit)
  3. **Heap delta check**: Skip remaining execution if heap delta exceeds the scheduled limit
  4. **Postponed raw_rand execution**: Process postponed raw_rand messages
  5. **Long-running install_code advancement**: Resume paused install_code executions
  6. **Inner round**: Iteratively execute subnet messages and canister messages
  7. **Round finalization**: Charge idle canisters, update metrics, garbage collect

#### Scenario: Round instruction budget
- **WHEN** the round instruction budget is computed
- **THEN** the initial budget is `max_instructions_per_round - max(max_instructions_per_slice, max_instructions_per_install_code_slice) + 1`
- **AND** this accounts for worst-case overshoot by a single slice

#### Scenario: Subnet messages instruction budget
- **WHEN** subnet messages are executed
- **THEN** they use a separate budget of `max_instructions_per_round / 16`
- **AND** this prevents subnet messages from consuming the entire round budget

### Requirement: Inner Round Iterations

The inner round executes multiple iterations of canister messages until the budget is exhausted or canisters are idle.

#### Scenario: Inner round iteration
- **WHEN** an inner round iteration begins
- **THEN** the following steps occur:
  1. Drain subnet queues (execute management canister messages)
  2. In the first iteration, add heartbeat and global timer tasks to eligible canisters
  3. Partition canisters across execution threads based on the round schedule
  4. Execute canisters in parallel on the thread pool
  5. Induct messages (move outputs to inputs within the same subnet)
  6. Repeat until the instruction budget is exhausted or no more progress can be made

#### Scenario: Canister execution on threads
- **WHEN** canisters are assigned to execution threads
- **THEN** each thread processes its assigned canisters sequentially
- **AND** each canister executes one message per iteration
- **AND** the round limits are shared across threads and updated after each canister completes

### Requirement: Round Schedule and Canister Ordering

Canisters are ordered for execution based on priority and compute allocation.

#### Scenario: Priority-based scheduling
- **WHEN** canisters are ordered for execution
- **THEN** canisters with higher accumulated priority are scheduled first
- **AND** accumulated priority increases with compute allocation and decreases after execution

#### Scenario: Heartbeat and timer tasks
- **WHEN** the first inner round iteration begins
- **THEN** heartbeat tasks are added for running canisters that export `canister_heartbeat`
- **AND** global timer tasks are added for running canisters that export `canister_global_timer` and whose timer has reached its deadline
- **AND** canisters with long-running executions do not receive heartbeat/timer tasks

#### Scenario: Rate limiting by heap delta
- **WHEN** `rate_limiting_of_heap_delta` is enabled
- **THEN** canisters that have accumulated too much heap delta are deprioritized
- **AND** they are filtered out from active scheduling

#### Scenario: Rate limiting by instructions
- **WHEN** `rate_limiting_of_instructions` is enabled
- **THEN** canisters that have executed too many instructions recently are deprioritized

### Requirement: Long-Running Executions

Some executions span multiple rounds via Deterministic Time Slicing (DTS).

#### Scenario: Long-running install_code
- **WHEN** an `install_code` execution is paused
- **THEN** the canister is marked with `NextExecution::ContinueInstallCode`
- **AND** in subsequent rounds, the scheduler resumes the paused execution before processing other messages
- **AND** no other messages can be executed on that canister until install_code completes

#### Scenario: Long-running canister message
- **WHEN** a canister message execution is paused
- **THEN** the canister is marked with `NextExecution::ContinueLong`
- **AND** in subsequent rounds, the scheduler resumes the paused execution
- **AND** the canister cannot process new messages until the current one completes

#### Scenario: Aborting paused executions
- **WHEN** a state sync occurs and the replicated state is replaced
- **THEN** all paused executions in the old state are abandoned
- **AND** any aborted long-running executions will restart from scratch in the next round

### Requirement: Subnet Message Execution

Management canister messages (subnet messages) are handled by the ExecutionEnvironment.

#### Scenario: Subnet message routing
- **WHEN** a message addressed to the management canister (`ic:00`) arrives
- **THEN** it is routed based on the method name to the appropriate handler
- **AND** methods like `create_canister`, `install_code`, `update_settings`, etc. are handled

#### Scenario: Subnet message blocking
- **WHEN** a subnet message targets a canister with a long-running install_code
- **THEN** the message is skipped and remains in the queue
- **AND** it will be processed once the install_code completes

### Requirement: Message Induction

After each iteration, output messages are inducted as inputs on the same subnet.

#### Scenario: Same-subnet message induction
- **WHEN** canister A sends a message to canister B on the same subnet
- **THEN** after the current iteration, A's output message is moved to B's input queue
- **AND** B can process it in the next iteration of the same round

### Requirement: Heap Delta Management

Heap delta tracks changes to canister memory that need to be checkpointed.

#### Scenario: Heap delta accumulation
- **WHEN** canister execution modifies heap or stable memory pages
- **THEN** the heap delta for the canister increases
- **AND** the total subnet heap delta estimate is updated

#### Scenario: Heap delta rate limiting
- **WHEN** the subnet heap delta estimate exceeds the scheduled limit
- **THEN** no canister messages are executed in the round
- **AND** only consensus queue responses are processed
- **AND** this prevents the checkpoint process from falling behind

#### Scenario: Scheduled heap delta limit
- **WHEN** the heap delta limit for a round is computed
- **THEN** it depends on the round number within the current epoch
- **AND** an initial reserve is maintained for the first rounds after a checkpoint
- **AND** the remaining capacity is distributed evenly across the remaining rounds

### Requirement: Ingress Message Management

Ingress messages have lifecycle management.

#### Scenario: Ingress message expiry
- **WHEN** an ingress message's expiry time has passed
- **THEN** the message is removed from the canister's input queue
- **AND** its ingress status is set to `Failed` with `IngressMessageTimeout`

#### Scenario: Ingress message deduplication
- **WHEN** a duplicate ingress message is submitted (same message ID)
- **THEN** the duplicate is rejected

### Requirement: Charging Idle Canisters

Canisters are charged for resource usage even when idle.

#### Scenario: Idle canister charging
- **WHEN** an inner round iteration completes
- **THEN** canisters that did not execute are charged for storage and compute allocation
- **AND** the charge covers the time since the last charge
- **AND** canisters that run out of cycles may be frozen
