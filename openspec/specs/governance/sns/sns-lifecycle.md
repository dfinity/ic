# SNS Decentralization Lifecycle

This specification covers the end-to-end lifecycle of creating and launching an SNS, from the initial NNS proposal through the decentralization swap to full autonomous operation.

## Requirements

### Requirement: SNS Creation via NNS Proposal

An SNS is created through a `CreateServiceNervousSystem` proposal on the NNS.

#### Scenario: Full SNS creation flow
- **WHEN** a `CreateServiceNervousSystem` proposal is submitted to NNS Governance
- **THEN** the proposal specifies: name, description, URL, logo, dapp_canisters, fallback_controller_principal_ids, initial_token_distribution, ledger_parameters, swap_parameters, and governance_parameters
- **AND** the NNS community votes on the proposal
- **AND** if adopted, the SNS-WASM canister deploys all SNS canisters (Root, Governance, Ledger, Swap, Index)

#### Scenario: SNS creation fee
- **WHEN** an SNS is created
- **THEN** an SNS creation fee of 180 trillion cycles is required (EXPECTED_SNS_CREATION_FEE)

#### Scenario: Initial governance mode
- **WHEN** the SNS is first created
- **THEN** SNS Governance starts in `PreInitializationSwap` mode
- **AND** only limited neuron management commands are available

### Requirement: Pre-Swap Phase

During the pre-swap phase, developer neurons exist but with limited functionality.

#### Scenario: Developer neuron creation at genesis
- **WHEN** the SNS is initialized
- **THEN** developer neurons are created with their specified dissolve delays, stakes, and vesting periods
- **AND** developer neurons have a `voting_power_percentage_multiplier` that is proportional to the fraction of tokens reserved for the swap
- **AND** all neuron timestamps (created, aging) are set to the genesis timestamp

#### Scenario: Limited operations during pre-swap
- **WHEN** governance is in `PreInitializationSwap` mode
- **THEN** neurons can set followees, make proposals, register votes, and manage permissions
- **AND** neurons cannot disburse, split, merge maturity, start dissolving, increase dissolve delay, or configure other settings

### Requirement: Swap Execution

The swap collects ICP and distributes SNS tokens.

#### Scenario: Swap opens at scheduled time
- **WHEN** the swap is in `Adopted` state
- **AND** the current time reaches or exceeds the scheduled open time
- **THEN** the swap transitions to `Open` and begins accepting ICP

#### Scenario: Participation with Neurons' Fund
- **WHEN** the swap is configured with `neurons_fund_participation: true`
- **THEN** the Neurons' Fund provides matched funding proportional to direct participation
- **AND** the matching follows a polynomial function defined by `neurons_fund_participation_constraints`

#### Scenario: Swap parameters example
- **WHEN** a typical swap is configured (from integration tests)
- **THEN** minimum_participants is set (e.g., 4)
- **AND** minimum_direct_participation_icp defines the floor for success (e.g., 499,900 ICP)
- **AND** maximum_direct_participation_icp defines the ceiling (e.g., 549,900 ICP)
- **AND** minimum_participant_icp per participant (e.g., 20 ICP)
- **AND** maximum_participant_icp per participant (e.g., 500,000 ICP)
- **AND** neuron basket has 3 neurons with 3-month dissolve delay intervals

### Requirement: Swap Commitment and Finalization

When the swap succeeds, it commits and finalizes the decentralization.

#### Scenario: Commitment conditions
- **WHEN** the swap is Open
- **AND** the minimum direct participation threshold is met
- **AND** either the swap duration has elapsed or the maximum ICP target is reached
- **THEN** the swap commits

#### Scenario: Successful finalization sequence
- **WHEN** the committed swap is finalized
- **THEN** ICP is transferred to the SNS treasury
- **AND** Neurons' Fund participation is settled with NNS Governance
- **AND** SNS neuron recipes are created for all participants
- **AND** SNS tokens are transferred to neuron staking accounts
- **AND** SNS neurons are claimed in SNS Governance
- **AND** SNS Governance transitions from `PreInitializationSwap` to `Normal` mode
- **AND** SNS Root takes sole control of dapp canisters

#### Scenario: Governance mode after successful swap
- **WHEN** finalization completes successfully
- **THEN** SNS Governance is in `Normal` mode
- **AND** all neuron management operations become available
- **AND** the SNS is fully decentralized

### Requirement: Swap Abort and Recovery

If the swap fails to meet its targets, dapp control is returned.

#### Scenario: Swap abort conditions
- **WHEN** the swap duration elapses
- **AND** the minimum participation threshold is NOT met
- **THEN** the swap is aborted

#### Scenario: Abort finalization
- **WHEN** an aborted swap is finalized
- **THEN** ICP is refunded to all direct participants
- **AND** dapp canister controllers are restored to the fallback controllers
- **AND** no SNS neurons are created
- **AND** SNS tokens remain in the swap canister

### Requirement: Post-Swap Operations

After successful decentralization, the SNS operates autonomously.

#### Scenario: Full governance functionality
- **WHEN** the SNS is in Normal mode
- **THEN** anyone with sufficient stake can submit proposals
- **AND** proposals go through voting with wait-for-quiet
- **AND** adopted proposals are executed by the governance canister
- **AND** voting rewards are distributed according to the reward rate schedule

#### Scenario: Treasury operations
- **WHEN** the SNS treasury holds ICP (from the swap) and SNS tokens
- **THEN** TransferSnsTreasuryFunds proposals can transfer assets from the treasury
- **AND** MintSnsTokens proposals can mint new SNS tokens
- **AND** both are subject to 7-day rolling spending limits

#### Scenario: Canister upgrade via governance
- **WHEN** an UpgradeSnsControlledCanister proposal is adopted
- **THEN** the governance canister upgrades the target dapp canister
- **AND** the WASM and arguments must not exceed 2 MB combined (MAX_INSTALL_CODE_WASM_AND_ARG_SIZE)

#### Scenario: SNS framework upgrades
- **WHEN** an UpgradeSnsToNextVersion proposal is adopted
- **THEN** the governance canister checks the SNS-WASM canister for the next version
- **AND** the appropriate SNS canister (governance, root, ledger, swap, archive, index) is upgraded
- **AND** the upgrade journal records the transition
