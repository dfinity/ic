# SNS Testing Infrastructure

The SNS codebase includes comprehensive testing infrastructure spanning unit tests, integration tests, and testing utilities. This specification covers the test patterns and the dedicated testing canister/library.

## Requirements

### Requirement: Integration Test Setup

Integration tests use a state machine to simulate the IC environment with all NNS and SNS canisters.

#### Scenario: Full initialization flow test
- **WHEN** an integration test for SNS initialization is set up
- **THEN** it creates a `StateMachine` for simulating the IC
- **AND** deploys all NNS canisters (governance, ledger, root, CMC, SNS-WASM)
- **AND** uploads real SNS WASM binaries to the SNS-WASM canister
- **AND** creates dapp canisters to be decentralized
- **AND** submits a `CreateServiceNervousSystem` proposal via NNS Governance

#### Scenario: State machine builder for SNS tests
- **WHEN** `state_machine_builder_for_sns_tests` is called
- **THEN** it returns a properly configured StateMachine suitable for testing SNS operations

### Requirement: Integration Test Coverage Areas

Integration tests cover the major functional areas of the SNS.

#### Scenario: Ledger integration tests
- **WHEN** ledger integration tests run
- **THEN** they verify token transfers, balances, and ICRC-1 compliance within the SNS context

#### Scenario: Governance integration tests
- **WHEN** governance integration tests run
- **THEN** they verify proposal submission, voting, execution, and governance parameter management

#### Scenario: Neuron integration tests
- **WHEN** neuron integration tests run
- **THEN** they verify neuron creation, permission management, dissolving, and disbursement

#### Scenario: Proposal integration tests
- **WHEN** proposal integration tests run
- **THEN** they verify all proposal types including Motion, UpgradeSnsControlledCanister, TransferSnsTreasuryFunds, and generic nervous system functions

#### Scenario: Swap integration tests
- **WHEN** swap integration tests run
- **THEN** they verify the full swap lifecycle including participation, commitment, and finalization

#### Scenario: Root integration tests
- **WHEN** root integration tests run
- **THEN** they verify dapp registration, canister settings management, and canister status queries

#### Scenario: Treasury integration tests
- **WHEN** treasury integration tests run
- **THEN** they verify treasury transfers and balance tracking including ICP treasury account balance checks

#### Scenario: Payment flow integration tests
- **WHEN** payment flow integration tests run
- **THEN** they verify the end-to-end payment flow for swap participation

#### Scenario: Nervous system parameters integration tests
- **WHEN** nervous system parameter tests run
- **THEN** they verify parameter validation and update through proposals

#### Scenario: Nervous system functions integration tests
- **WHEN** nervous system function tests run
- **THEN** they verify adding, removing, and executing generic nervous system functions

#### Scenario: Upgrade canister integration tests
- **WHEN** upgrade canister tests run
- **THEN** they verify upgrading SNS-controlled dapp canisters through proposals

#### Scenario: Timer-based integration tests
- **WHEN** timer integration tests run
- **THEN** they verify periodic task execution and timer-based operations

#### Scenario: HTTP request integration tests
- **WHEN** HTTP request tests run
- **THEN** they verify the canister's HTTP interface for metrics and status endpoints

#### Scenario: Metrics integration tests
- **WHEN** metrics tests run
- **THEN** they verify that governance metrics (cached and live) are correctly computed and reported

#### Scenario: Manage dapp canister settings integration tests
- **WHEN** dapp canister settings tests run
- **THEN** they verify updating compute allocation, memory allocation, freezing threshold, and other settings through proposals

#### Scenario: Manage ledger parameters integration tests
- **WHEN** ledger parameter tests run
- **THEN** they verify updating ledger parameters (e.g., transfer fee) through proposals

### Requirement: Golden State Upgrade Tests

Golden state tests verify that existing swap state can be correctly upgraded.

#### Scenario: Golden state swap upgrade
- **WHEN** `golden_state_swap_upgrade_twice` test runs
- **THEN** it loads a real swap canister state
- **AND** upgrades it to the current version
- **AND** verifies that state is preserved correctly through the upgrade

### Requirement: Test Utilities

The test_utils crate provides reusable helpers for SNS testing.

#### Scenario: State test helpers
- **WHEN** state test helpers are used
- **THEN** they provide functions for deploying SNS canisters, participating in swaps, listing neurons, and checking lifecycle states

#### Scenario: ICRC-1 test helpers
- **WHEN** ICRC-1 test helpers are used
- **THEN** they provide functions for checking token balances and performing transfers in the test environment

#### Scenario: ITest helpers
- **WHEN** itest helpers are used
- **THEN** they provide canister installation and interaction utilities for integration tests

### Requirement: Testing Canister

A dedicated SNS testing canister and library exists for automated testing.

#### Scenario: SNS testing library
- **WHEN** the SNS testing library (rs/sns/testing) is used
- **THEN** it provides bootstrap utilities for setting up complete SNS environments
- **AND** it provides SNS-specific test utilities for common operations
- **AND** it can run as a standalone canister for CI testing

#### Scenario: Bootstrap utilities
- **WHEN** `bootstrap` is used in tests
- **THEN** it sets up a complete SNS with all canisters initialized and linked

### Requirement: SNS Audit

The SNS audit tool provides verification of SNS state integrity.

#### Scenario: Audit tool execution
- **WHEN** the SNS audit tool runs
- **THEN** it analyzes the state of SNS canisters for inconsistencies
- **AND** it can be run as a command-line tool

### Requirement: Unit Test Patterns

Unit tests follow specific patterns for testing governance logic.

#### Scenario: Environment mocking
- **WHEN** governance unit tests need to interact with external canisters
- **THEN** they use `NativeEnvironment` which allows mocking canister calls
- **AND** ledger interactions use mock ICRC-1 ledger implementations
- **AND** CMC interactions use `FakeCmc`

#### Scenario: Vote cascading tests
- **WHEN** vote cascading behavior is tested
- **THEN** tests verify that catch-all following applies only to non-critical proposals
- **AND** topic-specific following applies correctly for critical proposals
- **AND** direct voting always creates a ballot regardless of following configuration

#### Scenario: Disburse neuron tests
- **WHEN** neuron disbursement is tested
- **THEN** tests verify correct fee calculations
- **AND** tests track transfer calls with amounts, fees, accounts, and memos
- **AND** tests distinguish between burns (fee=0) and transfers (fee>0)

#### Scenario: Advance target version tests
- **WHEN** SNS version advancement is tested
- **THEN** tests verify that upgrade proposals properly block each other
- **AND** tests verify version progression through the upgrade path
