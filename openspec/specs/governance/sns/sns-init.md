# SNS Initialization

**Crates**: `ic-sns-init`

The SNS Init crate defines the parameters and validation logic for creating a new Service Nervous System. It specifies token distribution, swap parameters, governance configuration, and ledger settings. The `SnsInitPayload` is the comprehensive configuration that drives the creation of all SNS canisters.

## Requirements

### Requirement: Initial Token Distribution

The token distribution defines how SNS tokens are allocated across different pools at genesis.

#### Scenario: Fractional Developer Voting Power distribution
- **WHEN** a `FractionalDeveloperVotingPower` distribution is configured
- **THEN** it must specify developer_distribution, treasury_distribution, and swap_distribution
- **AND** developer neurons are created with a voting_power_percentage_multiplier equal to (initial_swap_amount_e8s / total_e8s) * 100
- **AND** each developer neuron has a subaccount derived from the controller principal and memo

#### Scenario: Developer distribution validation
- **WHEN** developer distributions are validated
- **THEN** all developer neurons must have controllers specified
- **AND** the total developer allocation must not exceed swap_distribution.total_e8s
- **AND** a maximum of 100 developer distributions are allowed (MAX_DEVELOPER_DISTRIBUTION_COUNT)
- **AND** each neuron's dissolve delay must not exceed max_dissolve_delay_seconds from nervous system parameters
- **AND** neuron memos must not conflict with the swap neuron memo range (1,000,000 to 10,000,000)

#### Scenario: Swap distribution validation
- **WHEN** swap distribution is validated
- **THEN** `initial_swap_amount_e8s` must be greater than 0
- **AND** `total_e8s` must be greater than or equal to `initial_swap_amount_e8s`

#### Scenario: Token account generation
- **WHEN** account IDs and tokens are computed from the distribution
- **THEN** developer accounts use neuron staking subaccounts derived from controller + memo
- **AND** treasury accounts use a treasury subaccount (TREASURY_SUBACCOUNT_NONCE = 0)
- **AND** swap accounts use a swap subaccount (SWAP_SUBACCOUNT_NONCE = 1)

### Requirement: Dapp Canister Limits

The number of dapp canisters that can be initially decentralized is bounded.

#### Scenario: Maximum dapp canisters
- **WHEN** dapp canisters are specified in SnsInitPayload
- **THEN** at most 100 dapp canisters can be included (MAX_DAPP_CANISTERS_COUNT)

### Requirement: Swap Parameters Validation

The swap parameters define the rules for the decentralization token sale.

#### Scenario: Confirmation text limits
- **WHEN** confirmation text is specified for the swap
- **THEN** it must be between 1 character (MIN_CONFIRMATION_TEXT_LENGTH) and 1,000 characters (MAX_CONFIRMATION_TEXT_LENGTH)
- **AND** the byte length must not exceed 8,000 bytes (MAX_CONFIRMATION_TEXT_BYTES)

#### Scenario: Fallback controller limits
- **WHEN** fallback controllers are specified
- **THEN** at most 15 controllers can be included (MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT)

#### Scenario: Maximum direct ICP contribution
- **WHEN** `max_direct_participation_icp_e8s` is configured
- **THEN** it must not exceed 1 billion ICP (MAX_DIRECT_ICP_CONTRIBUTION_TO_SWAP = 1,000,000,000 * E8)

#### Scenario: Minimum participant ICP
- **WHEN** `min_participant_icp_e8s` is configured
- **THEN** it must be at least 0.01 ICP (MIN_PARTICIPANT_ICP_LOWER_BOUND_E8S = 1,000,000)

#### Scenario: Neuron basket construction parameters
- **WHEN** neuron basket parameters are configured
- **THEN** the basket size (count) must be between 2 (MIN_SNS_NEURONS_PER_BASKET) and 10 (MAX_SNS_NEURONS_PER_BASKET)
- **AND** (count - 1) * dissolve_delay_interval_seconds must be less than max_dissolve_delay_seconds
- **AND** the dissolve_delay_interval_seconds must be greater than 0

### Requirement: Min Direct Participation Threshold Validation

The minimum threshold ensures the swap only succeeds with sufficient participation.

#### Scenario: Threshold must be specified
- **WHEN** `min_direct_participation_threshold_icp_e8s` is not set
- **THEN** validation fails with an Unspecified error

#### Scenario: Threshold bounds
- **WHEN** `min_direct_participation_threshold_icp_e8s` is specified
- **THEN** it must be >= `min_direct_participation_icp_e8s`
- **AND** it must be <= `max_direct_participation_icp_e8s`

### Requirement: Neurons' Fund Participation Constraints Validation

The Neurons' Fund constraints control how matched funding operates.

#### Scenario: Max NF participation must be specified
- **WHEN** `max_neurons_fund_participation_icp_e8s` is not set
- **THEN** validation fails with an Unspecified error

#### Scenario: Max NF participation bounds
- **WHEN** `max_neurons_fund_participation_icp_e8s` is specified and non-zero
- **THEN** it must be >= `min_participant_icp_e8s`
- **AND** it must be <= `max_direct_participation_icp_e8s`

#### Scenario: NF constraints not set before proposal execution
- **WHEN** `neurons_fund_participation_constraints` is set in the SnsInitPayload before the CreateServiceNervousSystem proposal executes
- **THEN** validation fails because this field is populated by the NNS at execution time

### Requirement: Restricted Countries Validation

The swap can restrict participation from certain countries.

#### Scenario: Empty restricted countries list rejected
- **WHEN** restricted_countries is Some but contains an empty list
- **THEN** validation fails requiring at least one country code

#### Scenario: ISO compliance
- **WHEN** country codes are specified in restricted_countries
- **THEN** each code must be a valid ISO 3166-1 alpha-2 country code
- **AND** the total number of codes must be less than the total number of country codes
- **AND** duplicates are not allowed

### Requirement: CreateServiceNervousSystem Proposal Conversion

The SnsInitPayload can be constructed from a `CreateServiceNervousSystem` NNS proposal.

#### Scenario: Proposal to init conversion
- **WHEN** a `CreateServiceNervousSystem` proposal is approved and executed
- **THEN** it is converted to an `SnsInitPayload` with all governance, swap, ledger, and distribution parameters
- **AND** the SNS-WASM canister deploys all SNS canisters using this payload

### Requirement: Ledger Initialization

The SNS Ledger is initialized with token configuration from the SnsInitPayload.

#### Scenario: Ledger parameters
- **WHEN** the SNS Ledger is initialized
- **THEN** it receives the token_name, token_symbol, token_logo, and transaction_fee
- **AND** the initial accounts are populated from the token distribution (developer, treasury, swap accounts)
- **AND** archive options are configured for the ledger
