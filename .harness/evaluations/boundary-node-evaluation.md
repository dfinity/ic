# Evaluator Report: boundary-node

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 6/10

## Hard-Fail Checklist
- [x] All existing REQ-* have SCENARIO-*
- [x] Traceability complete for existing REQs
- [~] All narrative requirements captured — significant gaps (source spec is large)

## Findings

### Missing Requirements

The boundary-node narrative (openspec/specs/boundary-node/spec.md) covers much more than routing, size limits, status, and health. Additional requirements from the full spec include:

**Gap 1: Rate Limiting / Bouncer**
The `ic-boundary` crate includes a bouncer/firewall subsystem for IP-based and canister-based rate limiting. Not captured.
**Recommendation**: Add `REQ-BN-005: Rate Limiting`

**Gap 2: Caching**
The boundary node caches query responses. Not captured.
**Recommendation**: Add `REQ-BN-006: Query Response Caching`

**Gap 3: TLS Certificate Verification**
The boundary node verifies subnet/replica TLS certificates from the registry. Not captured.
**Recommendation**: Add `REQ-BN-007: TLS Certificate Verification`

**Gap 4: Canister Routing Table Updates**
The boundary node subscribes to registry changes and updates its routing table. Not captured.
**Recommendation**: Add `REQ-BN-008: Routing Table Updates from Registry`

**Caveat**: Only 100 lines of the boundary-node spec were read during migration. Gaps are inferred from the `ic-boundary` crate structure.

### Quality of Existing REQs: GOOD

**Strong scenarios:**
- SCENARIO-BN-001 response headers list (X-IC-Node-Id, X-IC-Subnet-Id, etc.) — precisely testable
- SCENARIO-BN-006 (no routing table → NoRoutingTable error) — important failure mode

**Weak scenarios:**
- SCENARIO-BN-010 (healthy boundary node → 204 No Content): Should specify what "sufficient subnets healthy" means precisely (e.g., `health_subnets_alive_threshold` percentage)
- SCENARIO-BN-002 (update call → 202 Accepted): Should note v3 and v4 ALSO return 202, distinguish from v3's synchronous path

### Test Linkage: LINKED
`rs/boundary_node/ic_boundary/src/core.rs` → REQ-BN-001..004

## Recommendations
1. Add REQ-BN-005..008 — requires reading full spec
2. SCENARIO-BN-010: specify `health_subnets_alive_threshold` as the comparison value
