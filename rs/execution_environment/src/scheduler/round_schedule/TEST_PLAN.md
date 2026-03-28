# RoundSchedule test plan

This document plans tests for `RoundSchedule` (and `IterationSchedule`) using `RoundScheduleFixture`, with the goal of eventually moving or duplicating relevant tests from `scheduler/tests.rs` so they target `RoundSchedule` directly.

---

## 1. Test categories

### 1.1 `start_iteration` (RoundSchedule)

| What to test | Fixture setup | Assertions |
|--------------|---------------|------------|
| **Empty / idle state** | No canisters or only idle canisters | `IterationSchedule::is_empty()`; `round_scheduled_canisters()` empty. |
| **Single canister with work** | One canister with an input message (or heartbeat/timer so `NextExecution::StartNew`) | Non-empty schedule; canister in `round_scheduled_canisters`; schedule contains that canister. |
| **Ordering by priority** | Multiple canisters with work, different `accumulated_priority` | Schedule order: higher priority first (within same long_execution / StartNew group). |
| **Ordering: long execution mode** | Mix of Prioritized vs Opportunistic (e.g. from previous round) | Prioritized before Opportunistic in schedule. |
| **Long executions** | Canisters with `NextExecution::ContinueLong` (requires simulating paused execution) | `long_executions_count` > 0; first `long_execution_cores` entries are long executions; `round_long_execution_canisters` updated on first iteration. |
| **Rate limiting (heap delta)** | `FlagStatus::Enabled`, canister with `heap_delta_debit >= heap_delta_rate_limit` | Canister not in iteration schedule; in `rate_limited_canisters` and `round_scheduled_canisters`. |
| **First iteration: fully executed** | Non-empty schedule, `is_first_iteration == true` | First `long_execution_cores` canisters (long) and first `scheduler_cores - long_execution_cores` new canisters get into `fully_executed_canisters`. |
| **First iteration: Prioritized mode** | Long executions in schedule, first iteration | First `long_execution_cores` long-execution canisters have `long_execution_mode == Prioritized` in state. |
| **Later iteration: exclude completed long** | Same round, second iteration; canister had StartNew but was in `round_long_execution_canisters` (e.g. completed long in iter 0) | That canister not scheduled again as StartNew. |

Fixture needs: way to set canister state so that `next_execution()` is `StartNew` (e.g. push a message, or use a canister with heartbeat/timer) or `ContinueLong` (set execution state to paused), and to set `scheduler_state.heap_delta_debit` for rate-limit tests.

### 1.2 `end_iteration` (RoundSchedule) — Done

| What to test | Fixture setup | Assertions |
|--------------|---------------|------------|
| **Accumulates executed / completed** | Call `end_iteration` with non-empty `executed_canisters` and `canisters_with_completed_messages` | `executed_canisters` and `canisters_with_completed_messages` extended. |
| **Reset long execution mode** | Canister in `canisters_with_completed_messages` had `LongExecutionMode::Prioritized` | After `end_iteration`, `long_execution_mode == Opportunistic` for that canister. |
| **Fully executed when idle** | Canister in `canisters_with_completed_messages` and `next_execution() == None` | Canister added to `fully_executed_canisters`. |

### 1.3 `finish_round` (RoundSchedule)

| What to test | Fixture setup | Assertions |
|--------------|---------------|------------|
| **Fully executed get credit** | `fully_executed_canisters` non-empty, canisters still in state | Each gets `priority_credit += 100%`, `last_full_execution_round = current_round`. |
| **Round-scheduled get compute allocation** | `round_scheduled_canisters` non-empty | Each gets `accumulated_priority += compute_allocation`; `observe_round_scheduled()` on metrics. |
| **Free allocation / zero sum** | Several canisters scheduled, then `finish_round` | Sum of `accumulated_priority - priority_credit` over subnet_schedule is 0 (invariant from existing tests). |
| **Idle at zero dropped from schedule** | Canister with no inputs and zero true priority after distribution | Removed from subnet_schedule if `!must_be_in_schedule()`. |
| **Apply priority credit** | Canister not in same long execution (or in `canisters_with_completed_messages`) | `apply_priority_credit` applied (priority_credit cleared, accumulated_priority reduced, long_execution_mode reset). |

### 1.4 `IterationSchedule` (partitioning and queries)

| What to test | Setup | Assertions |
|--------------|--------|------------|
| **partition_canisters_to_cores** | Schedule with mix of long and new canisters, N cores | First `long_execution_cores` cores get one prioritized long each; new canisters spread round-robin on remaining cores; remaining long executions (opportunistic) spread across all cores. |
| **Partition exhaustiveness** | Non-empty schedule, canister map matches schedule | Every scheduled canister appears in exactly one core vector; no canister in the “inactive” map. |
| **is_empty** | Empty and non-empty schedules | Matches `schedule.len() == 0`. |

### 1.5 Helpers and invariants

| What to test | Assertions |
|--------------|------------|
| **compute_capacity_percent** | `(scheduler_cores - 1) * 100` for DTS. |
| **Getters** | `round_scheduled_canisters()`, `round_long_execution_canisters()`, etc. return the sets updated by `start_iteration` / `end_iteration`. |

---

## 2. Fixture extensions (for the above)

- **Canister with input message** so that `next_execution() == StartNew`: use `add_canister_with_ingress(canister_id)` (adds a running canister and pushes one ingress), or `push_ingress_to_canister(canister_id, ingress)` for an already-added canister.
- **Canister with long execution** (`ContinueLong`): use `set_canister_long_execution_paused(canister_id)` to enqueue a `PausedExecution` task so that `next_execution()` returns `ContinueLong`.
- **Canister with heap delta debit**: use `set_canister_heap_delta_debit(canister_id, bytes)` to set `scheduler_state.heap_delta_debit` for rate-limit tests.
- **Optional**: helper to run one full “logical round”: create `RoundSchedule`, loop `start_iteration` until empty (without real execution), then `finish_round`, to test round-level invariants (e.g. zero sum) without the full scheduler.

---

## 3. Tests in `scheduler/tests.rs` that could move or be mirrored

Candidates that mainly assert RoundSchedule-related behavior (priority, fully executed, rate limiting, long execution mode):

- **Priority / zero-sum**: `dts_accumulated_priority_invariant`, `inner_round_long_execution_is_not_a_full_execution`, and the proptests that assert `total_accumulated_priority - total_priority_credit == 0`. These could be reimplemented with the fixture: build state, call `start_iteration` (possibly multiple times) and `finish_round`, then assert the invariant on `state.canister_priorities()`.
- **Fully executed**: Tests that only check `was_fully_executed` (which is derived from subnet_schedule / round_schedule) could be rewritten to use the fixture and `RoundSchedule` directly, asserting on `fully_executed_canisters` or on priority credit / `last_full_execution_round` after `finish_round`.
- **Heap delta rate limiting**: `canister_gets_heap_delta_rate_limited` and the tests that check `heap_delta_rate_limited_canisters_per_round` could be mirrored with a fixture that sets `heap_delta_debit` and `rate_limiting_of_heap_delta`, then run `start_iteration` and assert `rate_limited_canisters()` and metrics.
- **Long execution mode**: `scheduler_long_execution_progress_across_checkpoints` (and similar) assert on `long_execution_mode` and priority; the “prioritized vs opportunistic” part could be tested with the fixture by setting up long executions and calling `start_iteration(is_first_iteration: true)` then inspecting state.

When moving, prefer adding new tests in `round_schedule/tests.rs` that use the fixture and call `RoundSchedule` directly; then remove or trim the old test in `scheduler/tests.rs` if it becomes redundant.

---

## 4. Suggested order of implementation

1. **Fixture extensions** (canister with message, with long execution, with heap delta debit) so that `start_iteration` can be exercised meaningfully. **Done.**
2. **start_iteration tests**: empty/idle, one canister with work, ordering, rate limiting, first-iteration fully executed and Prioritized. **Done.** (See tests in `round_schedule/tests.rs`: `start_iteration_empty_state`, `start_iteration_single_canister_with_work_in_schedule`, `start_iteration_ordering_by_priority`, `start_iteration_ordering_long_execution_mode`, `start_iteration_long_executions_first_cores`, `start_iteration_first_iteration_fully_executed`, `start_iteration_first_iteration_prioritized_mode`, `start_iteration_later_iteration_exclude_completed_long`; rate limiting covered by `fixture_set_heap_delta_debit_rate_limited`.)
3. **end_iteration tests**: accumulate sets, reset long execution mode, add to fully_executed when idle.
4. **finish_round tests**: priority credit for fully executed, compute allocation for scheduled, free-allocation zero-sum invariant.
5. **IterationSchedule tests**: `partition_canisters_to_cores` shape and exhaustiveness, `is_empty`.
6. **Invariant / helper tests**: `compute_capacity_percent`, getters.
7. **Migrate or mirror** selected tests from `scheduler/tests.rs` (priority invariant, rate limiting, long execution mode) using the fixture.

This order builds from unit-level behavior (single method, minimal state) toward full-round invariants and then integration-style checks that are currently in scheduler tests.
