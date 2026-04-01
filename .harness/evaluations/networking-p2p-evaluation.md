# Evaluator Report: networking-p2p

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 scenarios missing

## Findings

### Missing Scenarios

**Gap 1: Listing connected peers (REQ-P2P-001)**
The narrative specifies `Transport::peers()` returning `(NodeId, ConnId)` tuples for all connected peers, with `ConnId` as a monotonically increasing per-connection identifier. Not captured.
**Recommendation**: Add SCENARIO-P2P-023 under REQ-P2P-001.

**Gap 2: Graceful endpoint shutdown (REQ-P2P-002)**
The narrative specifies that when `QuicTransport::shutdown()` is called: cancellation token triggered, all active tasks awaited, join handle awaited. Not captured (only the QUIC stream cancellation on drop is covered by SCENARIO-P2P-005).
**Recommendation**: Add SCENARIO-P2P-024 under REQ-P2P-002.

### Acceptable Omissions
- Memory Transport (testing infrastructure) — correctly omitted
- `MAX_CONCURRENT_BIDI_STREAMS` (1000) limit — minor operational detail

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-P2P-007 (designated dialer: lower NodeId dials) — precise protocol rule with the InvalidIncomingPeerId rejection
- SCENARIO-P2P-011 (idle timeout + keep-alive with exact constants 1s/5s) — testable
- SCENARIO-P2P-015 (retry with exponential backoff 250ms to 60s) — precise range

**Weak scenarios:**
- SCENARIO-P2P-021 (state sync: single active sync): "adds new peers to the ongoing sync" — should specify this happens when a peer advertises the SAME state ID, while different ID peers are ignored (SCENARIO-P2P-022 captures the "same ID" part, but the scenario description is ambiguous)

### Test Linkage: LINKED
`rs/consensus/tests/integration.rs` has some P2P coverage.

## Recommendations
1. Add SCENARIO-P2P-023: Transport::peers() returns connected (NodeId, ConnId) list
2. Add SCENARIO-P2P-024: graceful shutdown sequence (cancel → await tasks → await handle)
