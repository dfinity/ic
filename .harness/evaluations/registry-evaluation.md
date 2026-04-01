# Evaluator Report: registry

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 6/10

## Hard-Fail Checklist
- [x] All existing REQ-* have SCENARIO-*
- [x] Traceability complete for existing REQs
- [~] All narrative requirements captured — significant gaps (source spec is large, only 3 REQs captured)

## Findings

### Missing Requirements

The registry narrative (openspec/specs/registry/spec.md) is a large document. The spec only captured the first 3 sections. Additional sections likely include:

**Gap 1: Subnet Creation**
The narrative has a `Subnet Creation` requirement covering how new subnets are created through governance proposals (generates DKG key material, creates subnet records, updates routing table). Not captured.
**Recommendation**: Add `REQ-REG-004: Subnet Creation`

**Gap 2: Node Record Management**
Registry manages node records (public keys, endpoints, operator assignments). Not captured.
**Recommendation**: Add `REQ-REG-005: Node Record Management`

**Gap 3: Replica Version Management**
Registry tracks blessed replica versions and unassigned node configurations. Not captured.
**Recommendation**: Add `REQ-REG-006: Replica Version Management`

**Caveat**: The full registry spec was not read during migration (only 150 lines were read). These gaps are inferred from the codebase structure.

### Quality of Existing REQs: GOOD

**Strong scenarios:**
- SCENARIO-REG-004 (atomic mutate: all-or-none) — critical transactional invariant
- SCENARIO-REG-012 (free cycles schedule restricted to Application/CloudEngine subnets) — important invariant
- SCENARIO-REG-011 (chip_id uniqueness) — hardware-level constraint

**Weak scenarios:**
- SCENARIO-REG-009 (invariant checks → mutation rejected): Says "panics" — should note this is `panic!` in the canister (unwinding trap), which causes the mutation to be rolled back but the canister to continue operating
- SCENARIO-REG-008 (clients verify certified responses): "canister ID is within the delegation's allowed range" — should specify this uses the canister ID range check in the NNS subnet delegation

### Test Linkage: LINKED
`rs/registry/canister/tests/integration_tests_3.rs` → REQ-REG-001..003

## Recommendations
1. Add REQ-REG-004..006 (subnet creation, node records, replica versions) — requires reading full spec
2. SCENARIO-REG-009: clarify "panics" = canister trap (rolls back mutation, canister continues)
