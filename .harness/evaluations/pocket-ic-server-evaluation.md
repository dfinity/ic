# Evaluator Report: pocket-ic-server

**Date**: 2026-04-01  **Grade**: FAIL  **Score**: 5/10

## Hard-Fail Checklist
- [x] All existing REQ-* have SCENARIO-*
- [x] Traceability complete for existing REQs
- [~] **FAIL: Multiple narrative requirements NOT captured**

## Findings

### Missing Requirements (Hard-Fail)

**Gap 1: Blob Store**
The narrative specifies store/fetch blob operations with `BlobId` — used for Wasm modules and snapshot data. Not captured.
**Required**: Add `REQ-PIC-009: Blob Store`

**Gap 2: Canister Snapshots**
Download (`/canister_snapshot_download`) and upload (`/canister_snapshot_upload`) snapshot operations. Not captured.
**Required**: Add `REQ-PIC-010: Canister Snapshots`

**Gap 3: Public Key Retrieval**
`/pub_key` endpoint returning subnet threshold signing public key. Not captured.
**Required**: Add `REQ-PIC-011: Public Key Retrieval`

**Gap 4: Auto-Progress Mode**
`AutoProgressConfig` enabling automatic time and tick advancement at a configured rate. Not captured.
**Required**: Add `REQ-PIC-012: Auto-Progress Mode`

**Gap 5: HTTP Gateway Integration**
`HttpGatewayConfig` for starting an optional HTTP gateway that translates HTTP requests to canister calls. Not captured.
**Required**: Add `REQ-PIC-013: HTTP Gateway Integration`

**Gap 6: Operation Model**
The operation-based model: `OpId` for identification, `retry_if_busy()` for retry semantics, `processing-timeout-ms` header. Not captured.
**Required**: Add `REQ-PIC-014: Operation Model`

**Gap 7: Subnet Blockmaker Configuration**
`SubnetBlockmakers` for configuring which nodes are blockmakers per subnet (testing block production). Not captured.
**Required**: Add `REQ-PIC-015: Subnet Blockmaker Configuration`

### Quality of Existing REQs: ACCEPTABLE

**Strong scenarios:**
- SCENARIO-PIC-005 (tick advances state deterministically) — clear
- SCENARIO-PIC-006 (same operations → same final state) — determinism contract

**Weak scenarios:**
- SCENARIO-PIC-011 (v2/v3 API): Groups all v2/v3 endpoints into one scenario — should be separated since they have distinct semantics (query vs call vs read_state)
- SCENARIO-PIC-010 (set/get stable memory): "stable memory is overwritten" — should note that set_stable_memory replaces ALL contents, not appends

### Test Linkage: LINKED
`rs/pocket_ic_server/tests/test.rs` → REQ-PIC-001..007

## Recommendations (in priority order)
1. **[REQUIRED]** Add REQ-PIC-009: Blob Store
2. **[REQUIRED]** Add REQ-PIC-010: Canister Snapshots
3. **[REQUIRED]** Add REQ-PIC-011: Public Key Retrieval
4. **[REQUIRED]** Add REQ-PIC-012: Auto-Progress Mode
5. **[REQUIRED]** Add REQ-PIC-013: HTTP Gateway Integration
6. **[REQUIRED]** Add REQ-PIC-014: Operation Model
7. **[RECOMMENDED]** Add REQ-PIC-015: Subnet Blockmaker Configuration
