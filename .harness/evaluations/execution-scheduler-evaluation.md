# Evaluator Report: execution-scheduler

**Date**: 2026-04-01
**Evaluator**: Quinn (independent evaluation pass)
**Spec**: openspec/capabilities/execution-scheduler/spec.md
**Source narrative**: openspec/specs/execution/scheduler.md

---

## Grade: PASS

---

## Hard-Fail Checklist

- [x] All narrative requirements captured in REQ-*
- [x] All REQ-* have at least one SCENARIO-*
- [x] No narrative requirement was silently dropped
- [x] Traceability table includes all REQ-*/SCENARIO-* IDs

---

## Quality Score: 8/10

---

## Findings

### Completeness: PASS
The narrative spec has 9 distinct requirements. The capability spec has exactly 9 REQs (REQ-SCHED-001 through REQ-SCHED-009), each with 1-4 scenarios. All narrative scenarios are captured.

### Scenario Quality: GOOD
Most scenarios follow strict Given/When/Then format and are specific enough to write deterministic tests for. Examples:

**Strong scenario** — SCENARIO-SCHED-002:
> When the round instruction budget is computed, it equals `max_instructions_per_round - max(max_instructions_per_slice, max_instructions_per_install_code_slice) + 1`

This is testable: it gives an exact formula with named constants.

**Strong scenario** — SCENARIO-SCHED-018:
> When determining the round's heap delta capacity, the limit depends on the round number within the current epoch, and an initial reserve is maintained for the first rounds after a checkpoint.

Specific enough for integration test authorship.

### Weak Scenarios (minor)

**SCENARIO-SCHED-006** (priority-based scheduling):
> accumulated priority increases proportionally to compute allocation

The word "proportionally" is vague. Should specify the exact formula or reference `round_schedule` source. **Recommendation**: Add `And` clause referencing `AccumulatedPriority` delta formula.

**SCENARIO-SCHED-007** (heartbeat/timer tasks):
> global timer tasks are added for running canisters exporting `canister_global_timer` with elapsed deadlines

Missing: what "elapsed deadline" means precisely (i.e., `timer_deadline <= current_time`). **Recommendation**: Add explicit condition.

### Test Linkage: LINKED
All 8 scheduler test files now carry REQ-SCHED-* headers. Confirmed linked:
- `scheduling.rs` → REQ-SCHED-001,002,003,009
- `dts.rs` → REQ-DTS-001,004,005,007,008
- `charging.rs` → REQ-SCHED-009, REQ-CYC-003,007,018
- `rate_limiting.rs` → REQ-SCHED-003,007
- `subnet_messages.rs` → REQ-SCHED-005
- `routing.rs` → REQ-SCHED-006
- `timers.rs` → REQ-SCHED-003, REQ-SYSAPI-006

### Missing Test Coverage (noted, not hard-fail)
- REQ-SCHED-008 (ingress lifecycle / expiry) — `SCENARIO-SCHED-019,020` have no test header yet. The scenarios exist in the spec but no test file references them. **Recommendation**: add header to `rs/execution_environment/src/scheduler/tests/scheduling.rs` or a dedicated ingress-lifecycle test file.

### Consistency: PASS
- No contradiction with `_bmad/architecture.md` or other capability specs
- No overlap with `execution-dts/spec.md` (DTS aspects are properly separated)
- REQ prefix `SCHED` is correct per `_bmad/architecture.md` domain mapping

### Positives
- The round phases enumeration in SCENARIO-SCHED-001 is exceptionally clear and ordered — directly implementable as a test assertion sequence
- Numeric formulas are preserved verbatim from the narrative, maintaining precision
- REQ-SCHED-007 correctly separates three sub-scenarios for heap delta (accumulation, rate limiting, scheduled limit) — appropriate granularity

---

## Recommendations

1. **SCENARIO-SCHED-006**: Specify the priority delta formula (e.g., `delta = compute_allocation_percent`)
2. **SCENARIO-SCHED-007**: Clarify elapsed deadline as `timer_deadline <= current_time`
3. **REQ-SCHED-008**: Add test header to an existing test file referencing `SCENARIO-SCHED-019,020`
4. **Future**: Consider adding a `SCENARIO-SCHED-022` for the `MAX_CONSECUTIVE_ROUNDS_WITHOUT_STATE_CLONING` optimization (currently in state-manager spec, but has scheduling implications)

---

## Overall Assessment

The execution-scheduler capability spec is well-formed and production-ready. The 8/10 score reflects two minor scenario precision issues that should be addressed in the next iteration but do not block usage. The spec is ready for use by Generator agents implementing scheduler changes.
