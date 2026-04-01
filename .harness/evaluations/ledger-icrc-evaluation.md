# Evaluator Report: ledger-icrc

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 6/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 3 gaps (ICRC-3, ICRC-21, missing ICRC-1 scenarios)

## Findings

### Missing Requirements

**Gap 1: ICRC-1 Total Supply and Minting Account**
The narrative has distinct requirements for `icrc1_total_supply` and `icrc1_minting_account`. The spec groups metadata under REQ-ICRC-002 but doesn't have explicit scenarios for:
- Total supply = `Tokens::MAX - token_pool` (equals sum of all non-zero balances)
- Minting account: transfers FROM it are mints, transfers TO it are burns
**Recommendation**: Add SCENARIO-ICRC-012 (total supply formula) and SCENARIO-ICRC-013 (minting account semantics).

**Gap 2: ICRC-3 Transaction Log**
The narrative mentions ICRC-3 as a supported standard. ICRC-3 defines the transaction log format (CBOR with self-described tag 55799, block types "xfer", "mint", "burn", "approve"). Not captured in spec at all.
**Recommendation**: Add `REQ-ICRC-006: ICRC-3 Transaction Log` with scenarios for block structure and block types.

**Gap 3: ICRC-2 Approve with Expiration**
Like the ICP ledger, the ICRC-1 spec has `expires_at` on approvals. Not captured.
**Recommendation**: Add SCENARIO-ICRC-014 (approve with expires_at).

**Gap 4: Bad Burn Amount**
The narrative specifies: when a burn amount is below `minimum_burn_amount`, the transfer fails with `BadBurn { min_burn_amount }`. Not captured.
**Recommendation**: Add SCENARIO-ICRC-015 to REQ-ICRC-001.

### Quality: GOOD where captured

**Strong scenarios:**
- SCENARIO-ICRC-007 (self-approval rejected) — important security invariant
- SCENARIO-ICRC-011 (supported standards list must include "ICRC-1" with URL) — verifiable contract

**Weak scenarios:**
- SCENARIO-ICRC-001 (successful transfer): block type "xfer" is mentioned — but should also note the block is encoded in CBOR with self-described tag 55799 (per ICRC-3)

### Test Linkage: LINKED
`rs/ledger_suite/icrc1/ledger/src/tests.rs` → REQ-ICRC-001..004

## Recommendations
1. Add SCENARIO-ICRC-012: total supply = MAX - token_pool
2. Add SCENARIO-ICRC-013: minting account semantics (from=mint, to=burn)
3. Add REQ-ICRC-006: ICRC-3 Transaction Log (block types, CBOR encoding)
4. Add SCENARIO-ICRC-014: approve with expires_at
5. Add SCENARIO-ICRC-015: bad burn amount → BadBurn error
