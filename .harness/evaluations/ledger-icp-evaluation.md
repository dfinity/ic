# Evaluator Report: ledger-icp

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Scenarios

**Gap 1: Default Transfer Fee (REQ-ICP-003 or new REQ)**
The narrative specifies a `Default Transfer Fee` requirement: the configurable fee defaults to 10,000 e8s (0.0001 ICP) and is queryable. This is distinct from the transfer operation itself.
**Recommendation**: Add SCENARIO-ICP-013 (query transfer fee returns configured amount, default 10,000 e8s).

**Gap 2: Approve with fee refund on failure (REQ-ICP-005)**
The narrative specifies: when an approval fails (e.g., due to `AllowanceChanged`), the approval fee IS refunded (minted back) to the approver's account. The spec captures SCENARIO-ICP-009 (AllowanceChanged error) but not the refund behavior.
**Recommendation**: Add SCENARIO-ICP-014 (failed approval refunds fee to approver).

**Gap 3: Approve with expiration (REQ-ICP-005)**
The narrative specifies `expires_at` field on approvals: once expired, the allowance becomes invalid and expired approvals are pruned from storage. Not captured.
**Recommendation**: Add SCENARIO-ICP-015 (approval with expires_at becomes invalid after expiry).

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-ICP-001 (Tokens::new formula with get_e8s returning 1_200_000_200 for new(12, 200)) — deterministic and precisely testable
- SCENARIO-ICP-003 (AccountIdentifier = SHA-224 of domain separator + principal + subaccount with CRC-32 prefix) — cryptographically precise
- SCENARIO-ICP-005 (self-transfer succeeds, balance decreases by fee only) — subtle edge case correctly captured

**Weak scenarios:**
- SCENARIO-ICP-004 (successful transfer): The fee destination is described as "burned (or credited to fee collector if configured)" — this should be two separate scenarios since the behavior is qualitatively different

### Test Linkage: LINKED
`rs/ledger_suite/icp/ledger/src/tests.rs` → REQ-ICP-001..006

## Recommendations
1. Add SCENARIO-ICP-013: Query transfer fee (default 10,000 e8s)
2. Add SCENARIO-ICP-014: Failed approval refunds fee
3. Add SCENARIO-ICP-015: Approval expires_at invalidates allowance
4. Split SCENARIO-ICP-004: separate "fee burned" vs "fee to collector" scenarios
