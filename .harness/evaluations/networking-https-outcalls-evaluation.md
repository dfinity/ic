# Evaluator Report: networking-https-outcalls

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 3 scenarios missing from REQ-HTTPS-001 and REQ-HTTPS-002

## Findings

### Missing Scenarios

**Gap 1: Default User-Agent header (REQ-HTTPS-001)**
The narrative specifies: when the request does not include a `User-Agent` header, the adapter adds `User-Agent: ic/1.0` as a fallback. Not captured.
**Recommendation**: Add SCENARIO-HTTPS-017 under REQ-HTTPS-001.

**Gap 2: Duplicate header name handling (REQ-HTTPS-001)**
The narrative specifies: when multiple headers share the same name (case-insensitive), all values are preserved under the same header name. Not captured.
**Recommendation**: Add SCENARIO-HTTPS-018 under REQ-HTTPS-001.

**Gap 3: Response validation in client (REQ-HTTPS-002)**
The narrative specifies: after receiving adapter response, headers and body are validated against IC constraints, and invalid headers or oversized responses are rejected. This is distinct from SCENARIO-HTTPS-005 (size limit) and covers the client-side validation step.
**Recommendation**: Add SCENARIO-HTTPS-019 under REQ-HTTPS-002.

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-HTTPS-004 (SOCKS proxy fallback with random order and `MAX_SOCKS_PROXY_TRIES = 2`) — precise
- SCENARIO-HTTPS-012 (divergence detection criteria) — important consensus property
- SCENARIO-HTTPS-016 (gossip prioritization: shares closer to threshold get highest priority) — correctly captures the prioritization logic

**Weak scenarios:**
- SCENARIO-HTTPS-006 (header validation): combines two distinct conditions (too many headers vs header name/value too large) in one scenario. Should be two separate scenarios for better test authorship.

### Test Linkage: LINKED
`payload_builder/tests.rs` → REQ-HTTPS-003; `pool_manager.rs` → REQ-HTTPS-004.

## Recommendations
1. Add SCENARIO-HTTPS-017: default User-Agent header
2. Add SCENARIO-HTTPS-018: duplicate header name preservation
3. Add SCENARIO-HTTPS-019: client-side response validation
4. Split SCENARIO-HTTPS-006 into two scenarios (header count limit / name-value size limit)
