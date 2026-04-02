# Governance: SNS Root Capability Specification

**Source narrative**: `openspec/specs/governance/sns/sns-root.md`
**Crates**: `ic-sns-root`
**Key files**: `rs/sns/root/src/`

---

## REQ-ROOT-001: Canister Registry

The root canister MUST maintain a registry of all canisters in the SNS ecosystem.

### SCENARIO-ROOT-001: List SNS canisters
**Given** `list_sns_canisters` is called
**When** the query executes
**Then** it returns principal IDs of: root, governance, ledger, swap, index, dapps, archives, and extensions

### SCENARIO-ROOT-002: Required canister IDs panic if missing
**Given** the root canister state is queried for governance, ledger, swap, or index canister IDs
**And** any field is None
**When** the accessor is called
**Then** it panics with "Invalid root canister state: missing {field}"

---

## REQ-ROOT-002: Canister Status Summary

The root canister MUST provide status summaries of all SNS canisters.

### SCENARIO-ROOT-003: Full canister summary
**Given** `get_sns_canisters_summary` is called
**When** the summary is compiled
**Then** it returns status for root, governance, ledger, swap, index, all dapps, and all archives
**And** all status queries are made in parallel using `join!`

### SCENARIO-ROOT-004: Summary with canister list update
**Given** `get_sns_canisters_summary` is called with `update_canister_list = true` by SNS Governance
**When** the summary runs
**Then** the root first polls the ledger for new archive canisters
**And** then returns the updated summary

---

## REQ-ROOT-003: Dapp Canister Registration

The root canister MUST manage registration of dapp canisters controlled by the SNS.

### SCENARIO-ROOT-005: Register dapp canisters
**Given** `register_dapp_canisters` is called with a non-empty list
**When** registration runs
**Then** each canister must be controlled by root
**And** each canister must not be a distinguished SNS canister
**And** any controllers besides root are removed
**And** duplicates in the request are deduplicated

### SCENARIO-ROOT-006: Registration limit
**Given** the total dapp + extension canisters reaches 100 (`DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT`)
**When** a new registration is attempted
**Then** no additional canisters can be registered

---

## REQ-ROOT-004: Extension Canister Registration

The root canister MUST support registering extension canisters.

### SCENARIO-ROOT-007: Register extension canister
**Given** `register_extension` is called with a canister ID
**When** registration runs
**Then** the canister must not be a distinguished SNS canister
**And** the canister must not be a dapp canister
**And** its controllers are set to exactly Root and Governance
**And** all other controllers are removed

### SCENARIO-ROOT-008: Extension controller verification failure
**Given** the extension's controllers do not match (Root, Governance) after update_settings
**When** verification runs
**Then** the registration is rejected with an error describing the actual controllers

---

## REQ-ROOT-005: Archive Canister Discovery

The root canister MUST automatically discover ledger archive canisters.

### SCENARIO-ROOT-009: Poll for new archive canisters
**Given** `poll_for_new_archive_canisters` is called
**When** the poll runs
**Then** the root queries the ledger canister for its archive canisters
**And** newly discovered archives are added to `archive_canister_ids`

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-ROOT-001 | Canister registry | narrative | rs/sns/root/tests/ |
| REQ-ROOT-002 | Canister status summary | narrative | rs/sns/root/tests/ |
| REQ-ROOT-003 | Dapp registration | narrative | rs/sns/root/tests/ |
| REQ-ROOT-004 | Extension registration | narrative | rs/sns/root/tests/ |
| REQ-ROOT-005 | Archive discovery | narrative | rs/sns/root/tests/ |
