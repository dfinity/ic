# Boundary Node Rate Limits Canister

**Crates:** `rate_limits`, `rate-limits-api`, `rate-limiting-canister-client`, `rate-limit-canister-integration-tests`

**Source:** `rs/boundary_node/rate_limits/`

## Overview

The Rate Limits Canister manages rate-limiting configurations for Internet Computer API boundary nodes. It stores versioned configurations containing ordered sets of rate-limit rules, supports confidentiality (rules can be disclosed or hidden), and enforces access control with three privilege levels: FullAccess (authorized principal), FullRead (API boundary nodes), and RestrictedRead (public).

Rules are linked to incidents (via `incident_id`), stored with JSON-encoded matching criteria (canister ID, subnet ID, IP, methods regex, request types), and can specify actions: `pass`, `block`, or `limit` (count/duration). Data is persisted in IC stable memory using `StableBTreeMap`.

---

## Requirements

### Requirement: Canister Initialization

The canister must initialize with an empty config at version 1 and configure authorized principals and registry polling.

#### Scenario: First installation with authorized principal
- **WHEN** the canister is installed with an `InitArg` containing an `authorized_principal` and `registry_polling_period_secs`
- **THEN** the authorized principal is stored for subsequent access control checks
- **AND** an initial empty configuration is created at version 1 with the current timestamp
- **AND** a periodic timer is set to poll the NNS registry for API boundary node identities at the specified interval

#### Scenario: Post-upgrade preserves state
- **WHEN** the canister is upgraded with an `InitArg`
- **THEN** the same initialization logic runs (setting authorized principal, spawning registry poll)
- **AND** the existing configuration version and rules in stable memory are preserved across the upgrade
- **AND** if the config version already exists, no new initial config is created

---

### Requirement: Access Control

The canister enforces three access levels: FullAccess, FullRead, and RestrictedRead.

#### Scenario: Authorized principal has FullAccess
- **WHEN** the caller's principal matches the configured `authorized_principal`
- **THEN** the caller is granted `FullAccess`
- **AND** the caller can invoke `add_config`, `disclose_rules`, and `get_config`

#### Scenario: API boundary node principal has FullRead access
- **WHEN** the caller's principal is in the set of known API boundary node principals (fetched from registry)
- **THEN** the caller is granted `FullRead` access
- **AND** the caller can invoke `get_config` (replicated query) and see all rules including undisclosed ones

#### Scenario: Any other caller has RestrictedRead access
- **WHEN** the caller's principal is neither the authorized principal nor an API boundary node
- **THEN** the caller is granted `RestrictedRead` access
- **AND** the caller can only view disclosed rules; undisclosed rule details (`rule_raw`, `description`) are redacted

#### Scenario: Ingress message inspection rejects unauthorized calls
- **WHEN** a caller without `FullAccess` attempts to call `add_config` or `disclose_rules`
- **THEN** the message is rejected in the pre-consensus inspection phase with "unauthorized caller"
- **AND** no consensus resources are consumed

#### Scenario: Ingress message inspection rejects unknown methods
- **WHEN** a caller invokes any method not in the allowed set (`add_config`, `disclose_rules`, `get_config`)
- **THEN** the message is rejected with "method call is prohibited in the current context"

---

### Requirement: Add Configuration

Authorized callers can submit new rate-limit configurations. Each config is an ordered list of rules.

#### Scenario: Adding a new configuration with new rules
- **WHEN** an authorized caller submits an `InputConfig` with a list of `InputRule` entries
- **THEN** the config version is incremented by 1
- **AND** each new rule receives a randomly generated UUID as its `rule_id`
- **AND** each rule is stored with `added_in_version` set to the new version, `disclosed_at` as `None`, and `removed_in_version` as `None`
- **AND** the new `StorableConfig` is persisted in stable memory with the ordered list of rule IDs

#### Scenario: Resubmitting an existing rule preserves its ID
- **WHEN** a rule in the submitted config matches an existing rule (same `incident_id`, same JSON content in `rule_raw`, and same `description`)
- **THEN** the existing rule's UUID is reused in the new config
- **AND** the rule's `added_in_version` remains unchanged from when it was first introduced
- **AND** JSON comparison is semantic (different binary representations of equivalent JSON objects are treated as equal)

#### Scenario: Rules removed from a new config are marked with removed_in_version
- **WHEN** a rule present in the current config is not resubmitted in the new config
- **THEN** the rule's `removed_in_version` is set to the new config version
- **AND** the rule remains queryable by its ID for audit purposes

#### Scenario: Empty config removes all active rules
- **WHEN** an authorized caller submits a config with an empty rules vector
- **THEN** all rules from the previous config are marked with `removed_in_version` equal to the new version
- **AND** the new config at the incremented version has zero active rules

#### Scenario: Invalid incident UUID format is rejected
- **WHEN** a submitted rule contains an `incident_id` that is not a valid UUID
- **THEN** the operation fails with `AddConfigError::InvalidInputConfig(InvalidIncidentUuidFormat(index))`
- **AND** no state changes are persisted

#### Scenario: Invalid rule_raw JSON encoding is rejected
- **WHEN** a submitted rule contains `rule_raw` bytes that do not parse as valid JSON
- **THEN** the operation fails with `AddConfigError::InvalidInputConfig(InvalidRuleJsonEncoding(index))`

#### Scenario: Duplicate rules within a config are rejected
- **WHEN** two rules in the same submitted config are semantically identical (same incident_id, description, and JSON-equivalent rule_raw)
- **THEN** the operation fails with `AddConfigError::InvalidInputConfig(DuplicateRules(index1, index2))`

#### Scenario: New rules cannot be linked to disclosed incidents
- **WHEN** a new rule references an `incident_id` that belongs to an already-disclosed incident
- **THEN** the operation fails with `AddConfigError::LinkingRuleToDisclosedIncident` with the rule index and incident ID
- **AND** this policy prevents retroactive modification of publicly disclosed incident rule sets

#### Scenario: Unauthorized caller is rejected
- **WHEN** a caller without `FullAccess` attempts to add a config
- **THEN** the operation fails with `AddConfigError::Unauthorized`

---

### Requirement: Rule Disclosure

Authorized callers can make rules publicly visible by disclosing them individually or by incident.

#### Scenario: Disclosing rules by rule IDs
- **WHEN** an authorized caller calls `disclose_rules` with `DiscloseRulesArg::RuleIds(vec![...])`
- **THEN** each specified rule's `disclosed_at` field is set to the current timestamp
- **AND** the rule's `rule_raw` and `description` become visible to RestrictedRead callers

#### Scenario: Disclosing rules by incident IDs
- **WHEN** an authorized caller calls `disclose_rules` with `DiscloseRulesArg::IncidentIds(vec![...])`
- **THEN** all rules associated with each incident have their `disclosed_at` set to the current timestamp
- **AND** the incident itself is marked as `is_disclosed = true`

#### Scenario: Re-disclosing already disclosed rules has no effect
- **WHEN** a rule or incident that is already disclosed is disclosed again
- **THEN** the original `disclosed_at` timestamp is preserved (not overwritten)
- **AND** the operation succeeds without error

#### Scenario: Disclosing a non-existent rule ID fails
- **WHEN** a disclosure request references a rule ID that does not exist
- **THEN** the operation fails with `DiscloseRulesError::RuleIdNotFound`

#### Scenario: Disclosing a non-existent incident ID fails
- **WHEN** a disclosure request references an incident ID that does not exist
- **THEN** the operation fails with `DiscloseRulesError::IncidentIdNotFound`

#### Scenario: Invalid UUID format in disclosure request fails
- **WHEN** a disclosure request contains an ID that is not a valid UUID
- **THEN** the operation fails with `DiscloseRulesError::InvalidUuidFormat(index)`

---

### Requirement: Configuration Retrieval

Callers can retrieve rate-limit configurations with confidentiality formatting based on access level.

#### Scenario: Authorized viewer retrieves full config
- **WHEN** a caller with `FullAccess` or `FullRead` calls `get_config` with an optional version
- **THEN** the response includes the full config with `is_redacted = false`
- **AND** all rules include their `rule_raw` and `description` regardless of disclosure status

#### Scenario: Restricted viewer retrieves redacted config
- **WHEN** a caller with `RestrictedRead` calls `get_config`
- **THEN** the response includes the config with `is_redacted = true`
- **AND** for each undisclosed rule, `rule_raw` and `description` are set to `None`
- **AND** disclosed rules are returned with full details

#### Scenario: Retrieving latest config without specifying version
- **WHEN** a caller calls `get_config(None)`
- **THEN** the latest config version is returned

#### Scenario: Retrieving a specific config version
- **WHEN** a caller calls `get_config(Some(version))`
- **THEN** the config at the specified version is returned if it exists
- **AND** if the version does not exist, `GetConfigError::NotFound` is returned

#### Scenario: No configs exist
- **WHEN** `get_config` is called but no configs have been initialized
- **THEN** `GetConfigError::NoExistingConfigsFound` is returned

---

### Requirement: Rule and Incident Retrieval

Individual rules and incidents can be queried by ID.

#### Scenario: Retrieving a rule by ID as authorized viewer
- **WHEN** a caller with `FullAccess` or `FullRead` calls `get_rule_by_id` with a valid rule UUID
- **THEN** the full `OutputRuleMetadata` is returned including `rule_raw`, `description`, `disclosed_at`, `added_in_version`, and `removed_in_version`

#### Scenario: Retrieving a rule by ID as restricted viewer
- **WHEN** a caller with `RestrictedRead` calls `get_rule_by_id` for an undisclosed rule
- **THEN** `rule_raw` and `description` are set to `None` in the response
- **AND** `rule_id`, `incident_id`, `added_in_version`, and `removed_in_version` are still visible

#### Scenario: Retrieving rules by incident ID
- **WHEN** a caller calls `get_rules_by_incident_id` with a valid incident UUID
- **THEN** all rules linked to that incident are returned
- **AND** confidentiality formatting is applied per rule based on the caller's access level

#### Scenario: Invalid UUID format returns error
- **WHEN** a caller provides a non-UUID string as a rule or incident ID
- **THEN** the response is `GetRuleByIdError::InvalidUuidFormat` or `GetRulesByIncidentIdError::InvalidUuidFormat`

---

### Requirement: Rate Limit Rule Schema (v1)

Rate limit rules use a JSON schema with filtering conditions and actions.

#### Scenario: Rule with rate limiting action
- **WHEN** a rule specifies `limit: "100/1s"`
- **THEN** the action is parsed as `Action::Limit(100, Duration::from_secs(1))`
- **AND** the rule allows 100 requests per 1 second for matching traffic

#### Scenario: Rule with block action
- **WHEN** a rule specifies `limit: "block"`
- **THEN** all matching traffic is blocked

#### Scenario: Rule with pass action
- **WHEN** a rule specifies `limit: "pass"`
- **THEN** all matching traffic is allowed through without rate limiting

#### Scenario: Rule filtering by canister ID, subnet ID, methods regex, IP, and request types
- **WHEN** a rule specifies any combination of `canister_id`, `subnet_id`, `methods_regex`, `ip` (CIDR notation), and `request_types` (e.g., `query_v2`, `call_v3`)
- **THEN** the rule matches traffic that satisfies all specified conditions
- **AND** at least one filtering condition must be specified (otherwise deserialization fails)

#### Scenario: IP prefix grouping for rate limits
- **WHEN** a rule specifies `ip_prefix_group` with `v4` (max 32) and `v6` (max 128) prefix lengths
- **THEN** the rate limit is applied per IP prefix group rather than per individual IP
- **AND** `ip_prefix_group` is only valid with `Action::Limit` (not with `block` or `pass`)

#### Scenario: Request type backward compatibility
- **WHEN** a rule uses the alias `call` for `call_v2` or `sync_call` for `call_v3`
- **THEN** the aliases are correctly deserialized to their canonical request type variants

#### Scenario: Invalid rule configurations are rejected
- **WHEN** a rule has zero count or zero interval in a limit, or an invalid regex, or an invalid principal
- **THEN** deserialization fails with an appropriate error message

---

### Requirement: API Boundary Node Registry Polling

The canister periodically polls the NNS registry to maintain an up-to-date set of API boundary node principals.

#### Scenario: Successful registry poll
- **WHEN** the periodic timer fires and the registry canister returns API boundary node records
- **THEN** the set of authorized FullRead principals is updated with the returned node IDs
- **AND** the `last_successful_registry_poll_time` metric is updated

#### Scenario: Failed registry poll
- **WHEN** the registry canister call fails (rejected or returns an error)
- **THEN** the existing set of API boundary node principals remains unchanged
- **AND** a P0 log entry is recorded
- **AND** the `registry_poll_calls` failure metric is incremented

---

### Requirement: Observability

The canister exposes metrics and logs via HTTP.

#### Scenario: Metrics endpoint
- **WHEN** an HTTP request is made to `/metrics`
- **THEN** Prometheus-formatted metrics are returned including `last_canister_change_time`, `last_successful_registry_poll_time`, `registry_poll_calls`, and counts of configs, rules, and incidents

#### Scenario: Logs endpoint
- **WHEN** an HTTP request is made to `/logs` with optional `time` query parameter
- **THEN** JSON-formatted log entries are returned filtered by the timestamp threshold
- **AND** logs include P0 (critical) and P1 (informational) priority levels
