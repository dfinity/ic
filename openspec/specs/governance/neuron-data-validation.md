# Neuron Data Validation

The NNS Governance canister periodically validates the consistency of neuron data between primary storage and secondary indexes. This background validation detects data corruption or index drift that could affect governance operations.

## Requirements

### Requirement: Periodic Validation
Neuron data validation runs as a periodic timer task to check consistency of neuron indexes.

#### Scenario: Validation runs periodically
- **WHEN** the neuron_data_validation timer task runs
- **THEN** it validates neuron data across primary storage and all indexes
- **AND** validation results are stored as a NeuronDataValidationSummary
- **AND** a new validation replaces the previous one if it is older than MAX_VALIDATION_AGE_SECONDS (24 hours)

### Requirement: Subaccount Index Validation
The subaccount index must match the primary neuron store.

#### Scenario: Subaccount index cardinality check
- **WHEN** the subaccount index is validated
- **THEN** the number of entries in the primary store must match the index
- **AND** any mismatch is reported as SubaccountIndexCardinalityMismatch

#### Scenario: Subaccount missing from index
- **WHEN** a neuron's subaccount exists in primary storage but not in the index
- **THEN** a SubaccountMissingFromIndex issue is reported

### Requirement: Principal Index Validation
The principal index must reflect all controllers and hot keys.

#### Scenario: Principal index cardinality check
- **WHEN** the principal index is validated
- **THEN** the cardinality must match between primary and index
- **AND** any mismatch is reported as PrincipalIndexCardinalityMismatch

#### Scenario: Principal missing from index
- **WHEN** a neuron's controller or hot key is not in the principal index
- **THEN** a PrincipalIdMissingFromIndex issue is reported with the missing principal IDs

### Requirement: Following Index Validation
The following index must reflect all neuron follow relationships.

#### Scenario: Following index cardinality check
- **WHEN** the following index is validated
- **THEN** the cardinality must match between primary and index
- **AND** any mismatch is reported as FollowingIndexCardinalityMismatch

#### Scenario: Following pairs missing from index
- **WHEN** a neuron's topic-followee pairs exist in primary storage but not in the index
- **THEN** a TopicFolloweePairsMissingFromIndex issue is reported

### Requirement: Known Neuron Index Validation
The known neuron index must match neurons with known_neuron_data set.

#### Scenario: Known neuron index cardinality check
- **WHEN** the known neuron index is validated
- **THEN** the cardinality must match
- **AND** any mismatch is reported as KnownNeuronIndexCardinalityMismatch

#### Scenario: Known neuron missing from index
- **WHEN** a neuron has known_neuron_data but is not in the known neuron index
- **THEN** a KnownNeuronMissingFromIndex issue is reported

### Requirement: Maturity Disbursement Index Validation
The maturity disbursement index must match active disbursements.

#### Scenario: Maturity disbursement index cardinality check
- **WHEN** the maturity disbursement index is validated
- **THEN** the cardinality must match
- **AND** any mismatch is reported as MaturityDisbursementIndexCardinalityMismatch

#### Scenario: Maturity disbursement missing from index
- **WHEN** a neuron has maturity disbursements not reflected in the index
- **THEN** a MaturityDisbursementMissingFromIndex issue is reported

### Requirement: Active Neuron in Stable Storage Detection
Neurons that should be in heap storage but are found in stable storage are flagged.

#### Scenario: Active neuron in stable storage
- **WHEN** an active neuron is found in stable storage instead of heap storage
- **THEN** an ActiveNeuronInStableStorage issue is reported

### Requirement: Validation Issue Reporting
Validation issues are grouped by type with limited examples to prevent excessive memory usage.

#### Scenario: Issue examples limited
- **WHEN** validation issues are collected
- **THEN** at most MAX_EXAMPLE_ISSUES_COUNT (10) examples are kept per issue type
- **AND** the total count per type is tracked

#### Scenario: Validation summary structure
- **WHEN** validation results are queried
- **THEN** a NeuronDataValidationSummary is returned with:
- **AND** current_validation_started_time_seconds
- **AND** current_issues_summary (IssuesSummary)
- **AND** previous_issues_summary (from the last completed validation)
