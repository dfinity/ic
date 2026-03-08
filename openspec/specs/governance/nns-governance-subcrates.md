# NNS Governance Sub-crates Specification

## Overview

The NNS Governance system is split into several sub-crates for modularity:

- **ic-nns-governance-api** (`rs/nns/governance/api/`) -- Public API types, validation, and helper functions for the NNS governance canister.
- **ic-nns-governance-conversions** (`rs/nns/governance/conversions/`) -- Type conversions between protobuf and API representations for guest launch measurements.
- **ic-nns-governance-derive-self-describing** (`rs/nns/governance/derive_self_describing/`) -- A proc-macro crate that derives `From<T> for SelfDescribingValue` for structs and enums.
- **ic-nns-governance-init** (`rs/nns/governance/init/`) -- Builder for constructing governance canister initialization payloads, including test neuron setup and CSV-based neuron loading.

---

## ic-nns-governance-api

**Crate:** `ic-nns-governance-api`
**Path:** `rs/nns/governance/api/`

### Requirements

### Requirement: Governance Error Handling

The `GovernanceError` type represents errors from the governance canister with a typed error code and human-readable message.

#### Scenario: Creating an error with type only
- **WHEN** `GovernanceError::new(ErrorType::NotFound)` is called
- **THEN** the resulting error has `error_type` set to the integer value of `ErrorType::NotFound`
- **AND** the `error_message` is empty (default)

#### Scenario: Creating an error with message
- **WHEN** `GovernanceError::new_with_message(ErrorType::NotAuthorized, "caller is not authorized")` is called
- **THEN** the resulting error has the correct error type
- **AND** the `error_message` is `"caller is not authorized"`

#### Scenario: Display formatting
- **WHEN** a `GovernanceError` is formatted with `Display`
- **THEN** it renders as `"<ErrorType>: <error_message>"`

### Requirement: Neuron State Computation

The API provides methods to compute neuron state from dissolve parameters.

#### Scenario: Neuron is spawning
- **WHEN** a `Neuron` has `spawn_at_timestamp_seconds` set to `Some` value
- **THEN** `state(now_seconds)` returns `NeuronState::Spawning` regardless of dissolve state

#### Scenario: Neuron is not dissolving
- **WHEN** a `Neuron` has `DissolveState::DissolveDelaySeconds(d)` where `d > 0`
- **AND** `spawn_at_timestamp_seconds` is `None`
- **THEN** `state(now_seconds)` returns `NeuronState::NotDissolving`

#### Scenario: Neuron is dissolving
- **WHEN** a `Neuron` has `DissolveState::WhenDissolvedTimestampSeconds(t)` where `t > now_seconds`
- **AND** `spawn_at_timestamp_seconds` is `None`
- **THEN** `state(now_seconds)` returns `NeuronState::Dissolving`

#### Scenario: Neuron is dissolved via delay
- **WHEN** a `Neuron` has `DissolveState::DissolveDelaySeconds(0)`
- **THEN** `state(now_seconds)` returns `NeuronState::Dissolved`

#### Scenario: Neuron is dissolved via timestamp
- **WHEN** a `Neuron` has `DissolveState::WhenDissolvedTimestampSeconds(t)` where `t <= now_seconds`
- **THEN** `state(now_seconds)` returns `NeuronState::Dissolved`

#### Scenario: Neuron with no dissolve state
- **WHEN** a `Neuron` has `dissolve_state` set to `None`
- **THEN** `state(now_seconds)` returns `NeuronState::Dissolved`

### Requirement: Neuron Dissolve Delay Computation

#### Scenario: Dissolve delay from static delay
- **WHEN** a `Neuron` has `DissolveState::DissolveDelaySeconds(d)`
- **THEN** `dissolve_delay_seconds(now)` returns `d`

#### Scenario: Dissolve delay from dissolving timestamp
- **WHEN** a `Neuron` has `DissolveState::WhenDissolvedTimestampSeconds(t)`
- **THEN** `dissolve_delay_seconds(now)` returns `t.saturating_sub(now)`

#### Scenario: Dissolve delay with no dissolve state
- **WHEN** a `Neuron` has `dissolve_state` set to `None`
- **THEN** `dissolve_delay_seconds(now)` returns `0`

### Requirement: Neuron Stake Computation

#### Scenario: Stake calculation
- **WHEN** a `Neuron` has `cached_neuron_stake_e8s`, `neuron_fees_e8s`, and optionally `staked_maturity_e8s_equivalent`
- **THEN** `stake_e8s()` returns `cached_neuron_stake_e8s - neuron_fees_e8s + staked_maturity_e8s_equivalent`
- **AND** all arithmetic uses saturating operations to prevent overflow/underflow

### Requirement: Network Economics Defaults

The `NetworkEconomics` type provides default and mainnet economic parameters.

#### Scenario: Default values
- **WHEN** `NetworkEconomics::with_default_values()` is called
- **THEN** `reject_cost_e8s` is `100_000_000` (1 ICP)
- **AND** `neuron_management_fee_per_proposal_e8s` is `1_000_000` (0.01 ICP)
- **AND** `neuron_minimum_stake_e8s` is `100_000_000` (1 ICP)
- **AND** `neuron_spawn_dissolve_delay_seconds` is 7 days
- **AND** `maximum_node_provider_rewards_e8s` is `100_000_000_000_000` (1M ICP)
- **AND** `minimum_icp_xdr_rate` is `100` (1 XDR)
- **AND** `max_proposals_to_keep_per_topic` is `100`
- **AND** `neurons_fund_economics` and `voting_power_economics` are populated with defaults

#### Scenario: Mainnet values
- **WHEN** `NetworkEconomics::with_mainnet_values()` is called
- **THEN** `reject_cost_e8s` is `2_500_000_000` (25 ICP)
- **AND** `maximum_node_provider_rewards_e8s` is `10_000_000_000_000` (100k ICP)

### Requirement: Voting Power Economics Defaults

#### Scenario: Default voting power economics
- **WHEN** `VotingPowerEconomics::with_default_values()` is called
- **THEN** `start_reducing_voting_power_after_seconds` is 6 months
- **AND** `clear_following_after_seconds` is 1 month
- **AND** `neuron_minimum_dissolve_delay_to_vote_seconds` is 6 months

### Requirement: Neurons Fund Economics Defaults

#### Scenario: Default neurons fund economics
- **WHEN** `NeuronsFundEconomics::with_default_values()` is called
- **THEN** `max_theoretical_neurons_fund_participation_amount_xdr` is `750_000.0`
- **AND** the matched funding curve has `contribution_threshold_xdr` of `75_000.0`
- **AND** the matched funding curve has `one_third_participation_milestone_xdr` of `225_000.0`
- **AND** the matched funding curve has `full_participation_milestone_xdr` of `375_000.0`
- **AND** `minimum_icp_xdr_rate` is 10_000 basis points (1:1)
- **AND** `maximum_icp_xdr_rate` is 1_000_000 basis points (1:100)

### Requirement: XDR Conversion Rate Defaults

#### Scenario: Default XDR conversion rate
- **WHEN** `XdrConversionRate::with_default_values()` is called
- **THEN** `timestamp_seconds` is `Some(0)`
- **AND** `xdr_permyriad_per_icp` is `Some(10_000)` (1 XDR per ICP)

### Requirement: SNS Token Swap Scheduling

`CreateServiceNervousSystem` provides methods for computing SNS swap start and due timestamps.

#### Scenario: Swap start is at least 24 hours after approval
- **WHEN** `swap_start_and_due_timestamps` is called with a `start_time_of_day` and `swap_approved_timestamp_seconds`
- **THEN** the computed `swap_start_timestamp_seconds` is at least 24 hours after `swap_approved_timestamp_seconds`
- **AND** the start time falls on the next occurrence of `start_time_of_day` (UTC) that is more than 24h after approval
- **AND** `swap_due_timestamp_seconds` equals `swap_start_timestamp_seconds + duration`

#### Scenario: SNS token accessors
- **WHEN** `sns_token_e8s()` is called on a `CreateServiceNervousSystem` with a valid `initial_token_distribution`
- **THEN** it returns the `total.e8s` from the swap distribution
- **AND** `transaction_fee_e8s()` returns the fee from `ledger_parameters`
- **AND** `neuron_minimum_stake_e8s()` returns the minimum stake from `governance_parameters`

### Requirement: Proposal Validation

The API validates proposal fields (title, summary, URL) before submission.

#### Scenario: Valid proposal
- **WHEN** a proposal has a title between 5 and 256 bytes, a summary under 30,000 bytes, and a URL from `forum.dfinity.org` between 10 and 2048 characters
- **THEN** `validate_user_submitted_proposal_fields` returns `Ok(())`

#### Scenario: Missing title
- **WHEN** a proposal has `title` set to `None`
- **THEN** validation fails with `"Proposal lacks a title"`

#### Scenario: Title too short
- **WHEN** a proposal has a title shorter than 5 bytes
- **THEN** validation fails with a message about minimum title length

#### Scenario: Title too long
- **WHEN** a proposal has a title longer than 256 bytes
- **THEN** validation fails with a message about maximum title length

#### Scenario: Summary too long
- **WHEN** a proposal has a summary longer than 30,000 bytes
- **THEN** validation fails with a message about maximum summary size

#### Scenario: URL validation
- **WHEN** a proposal URL is non-empty
- **THEN** it must be between 10 and 2048 characters
- **AND** it must be from the allowed domain `forum.dfinity.org`
- **AND** an empty URL is accepted without validation

### Requirement: Proposal Submission Helpers

Utility functions simplify the creation and submission of NNS proposals.

#### Scenario: Creating an external update proposal with Candid payload
- **WHEN** `create_external_update_proposal_candid` is called with a title, summary, URL, NNS function, and a Candid-encodable payload
- **THEN** it returns a `MakeProposalRequest` with `ProposalActionRequest::ExecuteNnsFunction`
- **AND** the payload is Candid-encoded

#### Scenario: Creating a manage neuron request
- **WHEN** `create_make_proposal_payload` is called with a proposal and neuron ID
- **THEN** it wraps the proposal in a `ManageNeuronCommandRequest::MakeProposal`
- **AND** the neuron ID is set in the `ManageNeuronRequest`

#### Scenario: Decoding a make proposal response
- **WHEN** `decode_make_proposal_response` is called with a valid Candid-encoded `ManageNeuronResponse`
- **AND** the response contains `CommandResponse::MakeProposal`
- **THEN** it returns `Ok(ProposalId)`

#### Scenario: Decoding an error response
- **WHEN** `decode_make_proposal_response` receives a `CommandResponse::Error`
- **THEN** it returns `Err` with the error message

### Requirement: Bitcoin Configuration Types

#### Scenario: Bitcoin network parsing
- **WHEN** `BitcoinNetwork::from_str("mainnet")` is called
- **THEN** it returns `Ok(BitcoinNetwork::Mainnet)`
- **AND** `"testnet"` returns `Ok(BitcoinNetwork::Testnet)`
- **AND** any other string returns `Err`

#### Scenario: Bitcoin set config proposal
- **WHEN** a `BitcoinSetConfigProposal` is created
- **THEN** it contains a `network` (Mainnet or Testnet) and an opaque `payload` byte vector

### Requirement: Subnet Rental Types

#### Scenario: Subnet rental request
- **WHEN** a `SubnetRentalRequest` is created
- **THEN** it contains a `user` (PrincipalId) and a `rental_condition_id`

#### Scenario: Rental condition ID parsing
- **WHEN** `RentalConditionId::from_str("App13CH")` is called
- **THEN** it returns `Ok(RentalConditionId::App13CH)`
- **AND** any other string returns `Err`

### Requirement: Test API Types

#### Scenario: TimeWarp
- **WHEN** a `TimeWarp` is created with `delta_s`
- **THEN** it represents a time offset in seconds applied to governance's perception of time
- **AND** it is Candid-serializable and deserializable

### Requirement: InstallCodeRequest Debug Formatting

#### Scenario: Sensitive data is hashed in debug output
- **WHEN** an `InstallCodeRequest` is formatted with `Debug`
- **THEN** the `wasm_module` field is displayed as its SHA-256 hash (hex-encoded)
- **AND** the `arg` field is displayed as its SHA-256 hash (or empty string if empty)
- **AND** the actual binary content is never directly exposed

---

## ic-nns-governance-conversions

**Crate:** `ic-nns-governance-conversions`
**Path:** `rs/nns/governance/conversions/`

### Requirements

### Requirement: Guest Launch Measurement Conversion (PB to API)

Bidirectional conversion functions for guest launch measurements between protobuf (`ic-protobuf`) and API (`ic-nns-governance-api`) types.

#### Scenario: Converting measurements from protobuf to API
- **WHEN** `convert_guest_launch_measurements_from_pb_to_api` is called with a protobuf `GuestLaunchMeasurements`
- **THEN** each `GuestLaunchMeasurement` in the protobuf is converted to the API equivalent
- **AND** the `measurement` field is wrapped in `Some`
- **AND** the `metadata` field's `kernel_cmdline` is preserved
- **AND** the result is an API `GuestLaunchMeasurements` with `guest_launch_measurements` as `Some(Vec<...>)`

#### Scenario: Converting measurements from API to protobuf
- **WHEN** `convert_guest_launch_measurements_from_api_to_pb` is called with an API `GuestLaunchMeasurements`
- **THEN** each `GuestLaunchMeasurement` in the API type is converted to the protobuf equivalent
- **AND** a `None` `guest_launch_measurements` field defaults to an empty vector
- **AND** a `None` `measurement` field defaults to empty bytes
- **AND** the `metadata` field's `kernel_cmdline` is preserved

### Requirement: Inline Optimization

#### Scenario: Functions are inlined for size
- **WHEN** the conversion functions are compiled into the governance canister
- **THEN** the `#[inline]` attribute ensures they are inlined at the call site
- **AND** this reduces the canister binary size by a few kilobytes

---

## ic-nns-governance-derive-self-describing

**Crate:** `ic-nns-governance-derive-self-describing`
**Path:** `rs/nns/governance/derive_self_describing/`

### Requirements

### Requirement: Struct Derivation

The `SelfDescribing` derive macro generates `From<T> for SelfDescribingValue` implementations for structs with named fields.

#### Scenario: Struct with named fields
- **WHEN** `#[derive(SelfDescribing)]` is applied to a struct with named fields
- **THEN** it generates a `From` implementation that creates a `SelfDescribingValue` map
- **AND** each field name becomes a key in the map
- **AND** each field value is converted via `add_field`

#### Scenario: Tuple struct rejected
- **WHEN** `#[derive(SelfDescribing)]` is applied to a tuple struct
- **THEN** compilation fails with error "SelfDescribing does not support tuple structs"

#### Scenario: Unit struct rejected
- **WHEN** `#[derive(SelfDescribing)]` is applied to a unit struct
- **THEN** compilation fails with error "SelfDescribing does not support unit structs"

### Requirement: Enum Derivation

#### Scenario: Unit enum variant
- **WHEN** `#[derive(SelfDescribing)]` is applied to an enum with a unit variant `VariantA`
- **THEN** the generated code converts `VariantA` to `SelfDescribingValue::from("VariantA")` (text)

#### Scenario: Single-field tuple enum variant
- **WHEN** `#[derive(SelfDescribing)]` is applied to an enum with a variant `VariantB(InnerType)`
- **THEN** the generated code converts it to a map with key `"VariantB"` and the inner value

#### Scenario: Multi-field tuple variant rejected
- **WHEN** `#[derive(SelfDescribing)]` is applied to an enum with a variant having multiple tuple fields
- **THEN** compilation fails with error "SelfDescribing does not support enum variants with multiple tuple fields"

#### Scenario: Named-field variant rejected
- **WHEN** `#[derive(SelfDescribing)]` is applied to an enum with a variant having named fields
- **THEN** compilation fails with error "SelfDescribing does not support enum variants with named fields"

### Requirement: Union Rejection

#### Scenario: Union type rejected
- **WHEN** `#[derive(SelfDescribing)]` is applied to a union type
- **THEN** compilation fails with error "SelfDescribing does not support unions"

---

## ic-nns-governance-init

**Crate:** `ic-nns-governance-init`
**Path:** `rs/nns/governance/init/`

### Requirements

### Requirement: Governance Initialization Payload Construction

The `GovernanceCanisterInitPayloadBuilder` constructs a `Governance` protobuf for canister initialization.

#### Scenario: Default initialization
- **WHEN** `GovernanceCanisterInitPayloadBuilder::new()` is called
- **THEN** the `Governance` proto has `economics` set to `NetworkEconomics::with_default_values()`
- **AND** `wait_for_quiet_threshold_seconds` is 4 days (345,600 seconds)
- **AND** `short_voting_period_seconds` is 12 hours (43,200 seconds)
- **AND** `neuron_management_voting_period_seconds` is 48 hours (172,800 seconds)
- **AND** `xdr_conversion_rate` is set to default values
- **AND** the neurons map is empty

#### Scenario: Building the payload
- **WHEN** `build()` is called on the builder
- **THEN** it returns a `Governance` proto with all configured neurons and parameters
- **AND** all neurons have the `voters_to_add_to_all_neurons` added to their hot keys

### Requirement: Test Neuron Generation

#### Scenario: Standard test neurons
- **WHEN** `with_test_neurons()` is called on the builder (non-wasm32 only)
- **THEN** three neurons are created with deterministic IDs (using ChaCha20Rng seeded with 0)
- **AND** neuron 1 has `TEST_NEURON_1_OWNER_PRINCIPAL` as controller, 10 ICP stake, `not_for_profit: true`
- **AND** neuron 2 has `TEST_NEURON_2_OWNER_PRINCIPAL` as controller, 1 ICP stake
- **AND** neuron 3 has `TEST_NEURON_3_OWNER_PRINCIPAL` as controller, 0.1 ICP stake
- **AND** all neurons have 12-month dissolve delay
- **AND** all neurons have `visibility: Public`
- **AND** all neurons have `voting_power_refreshed_timestamp_seconds` set to the current time

#### Scenario: Test neurons with Neurons Fund participation
- **WHEN** `with_test_neurons_fund_neurons(maturity)` is called
- **THEN** neuron 1 additionally has `maturity_e8s_equivalent` set to the given value
- **AND** neuron 1 has `joined_community_fund_timestamp_seconds` set to `Some(1)`
- **AND** neuron 1 has `auto_stake_maturity` set to `Some(true)`

#### Scenario: Deterministic neuron IDs
- **WHEN** `new_neuron_id()` is called on the builder
- **THEN** it uses a ChaCha20Rng seeded with 0 to generate deterministic IDs
- **AND** the first three IDs match `TEST_NEURON_1_ID`, `TEST_NEURON_2_ID`, `TEST_NEURON_3_ID`

### Requirement: CSV-Based Neuron Loading

#### Scenario: Loading neurons from CSV
- **WHEN** `add_all_neurons_from_csv_file(path)` is called (non-wasm32 only)
- **THEN** it reads a semicolon-delimited CSV file with headers: `neuron_id`, `owner_id`, `created_ts_ns`, `dissolve_delay_s`, `staked_icpt`, `follows`, `not_for_profit`, `maturity_e8s_equivalent`
- **AND** each row creates a `Neuron` with the specified parameters
- **AND** stake is converted from ICP to e8s (multiplied by 100,000,000)
- **AND** timestamps are converted from nanoseconds to seconds
- **AND** followees are parsed as comma-separated neuron IDs and stored under `Topic::Unspecified`
- **AND** empty `neuron_id` fields generate a new deterministic ID via the RNG

#### Scenario: Duplicate neuron ID detection
- **WHEN** a CSV file contains a neuron with an ID that already exists in the builder
- **THEN** the function panics with "There is more than one neuron with the same id"

### Requirement: GTC Neuron Addition

#### Scenario: Adding Genesis Token Canister neurons
- **WHEN** `add_gtc_neurons(neurons)` is called
- **THEN** each neuron is added to the governance proto's neurons map
- **AND** the neuron ID is extracted from the neuron's `id` field
- **AND** a missing ID causes a panic ("GTC neuron missing ID")
- **AND** a duplicate ID causes a panic

### Requirement: Governance Proto Override

#### Scenario: Setting governance proto preserves existing neurons
- **WHEN** `with_governance_proto(proto)` is called
- **THEN** the builder's proto is replaced with the new one
- **AND** any neurons previously added (e.g., GTC neurons) are merged into the new proto
- **AND** the new proto's other fields (economics, voting periods, etc.) take effect

### Requirement: Balance Computation

#### Scenario: Total staked balance
- **WHEN** `get_balance()` is called
- **THEN** it returns the sum of `cached_neuron_stake_e8s` across all neurons in the proto
