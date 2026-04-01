# Evaluator Report: governance-nns

**Date**: 2026-04-01  **Grade**: FAIL  **Score**: 5/10

## Hard-Fail Checklist
- [x] All existing REQ-* have SCENARIO-*
- [x] Traceability complete for existing REQs
- [~] **FAIL: Multiple narrative requirements NOT captured**

## Findings

### Missing Requirements (Hard-Fail)

The source narrative has significantly more content than the 8 captured REQs. Missing:

**Gap 1: Network Economics Configuration**
Narrative has `ManageNetworkEconomics` with default values (reject_cost_e8s = 1 ICP, neuron_minimum_stake_e8s = 1 ICP, etc.) and validation rules (max_proposals_to_keep_per_topic > 0, neurons_fund_economics must be set, voting_power_economics must be set). Not in spec.
**Required**: Add `REQ-NNS-009: Network Economics Configuration`

**Gap 2: Proposal Topics**
Each proposal type is assigned a topic that determines eligible voters. The narrative enumerates topic assignments for all major proposal types (ManageNeuron → NeuronManagement, ManageNetworkEconomics → NetworkEconomics, Motion → Governance, etc.). Not in spec.
**Required**: Add `REQ-NNS-010: Proposal Topics`

**Gap 3: Proposal Size Limits**
Narrative specifies hard limits:
- Motion text: `PROPOSAL_MOTION_TEXT_BYTES_MAX (10,000 bytes)`
- ExecuteNnsFunction payload: `70,000 bytes`
These are validation rules with specific constants. Not in spec.
**Required**: Add `REQ-NNS-011: Proposal Content Limits`

**Gap 4: Timer Tasks**
The governance canister runs periodic timer tasks: reward calculations, maturity disbursements, neuron data validation, voting power snapshots, stale following pruning, spawning neuron processing. Not in spec.
**Required**: Add `REQ-NNS-012: Timer Tasks`

**Gap 5: Governance State Structure (partial)**
REQ-NNS-002 covers upgrade preservation but misses the `GovernanceProto` structure (heap + stable memory split) and the specific `GovernanceProto` fields. Minor gap but worth noting.

### Quality of existing REQs: ACCEPTABLE

**Strong scenarios:**
- SCENARIO-NNS-008/009/010 (Wait For Quiet) correctly specify the flip condition, non-flip no-op, and 3% minimum participation threshold
- SCENARIO-NNS-015 (burst of 300 neurons allowed) is precise

**Weak scenarios:**
- SCENARIO-NNS-003 (proposal created): Says "unique monotonically increasing ProposalId" — correct, but should note it's created from the `next_proposal_id` counter in `GovernanceProto`
- SCENARIO-NNS-013 (rejection cost): Correctly gives default values (1 ICP, 0.01 ICP) but should note these come from `NetworkEconomics.reject_cost_e8s`

### Test Linkage: LINKED
`rs/nns/governance/tests/governance.rs` → REQ-NNS-003..008

## Recommendations (in priority order)
1. **[REQUIRED]** Add REQ-NNS-009: Network Economics Configuration (default values + validation)
2. **[REQUIRED]** Add REQ-NNS-010: Proposal Topics (type → topic mapping)
3. **[REQUIRED]** Add REQ-NNS-011: Proposal Content Limits (motion text 10KB, payload 70KB)
4. **[RECOMMENDED]** Add REQ-NNS-012: Timer Tasks
5. **[MINOR]** SCENARIO-NNS-013: reference NetworkEconomics.reject_cost_e8s
