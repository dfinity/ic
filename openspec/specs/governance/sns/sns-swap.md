# SNS Swap (Decentralization Swap)

The SNS Swap canister manages the decentralization token sale process. It collects ICP from direct participants and the Neurons' Fund, distributes SNS tokens proportionally, creates SNS neurons for participants, and transitions the SNS into a fully decentralized state.

## Requirements

### Requirement: Swap Lifecycle

The swap follows a well-defined lifecycle with specific state transitions.

#### Scenario: Lifecycle states
- **WHEN** the swap canister is created
- **THEN** it supports the following lifecycle states: Pending, Adopted, Open, Committed, Aborted
- **AND** Committed and Aborted are terminal states

#### Scenario: Initial state
- **WHEN** a new swap is created with valid Init parameters
- **THEN** it starts in the `Pending` lifecycle state
- **AND** if the Init is validated for the one-proposal flow, it automatically transitions to `Adopted`
- **AND** the params, open_sns_token_swap_proposal_id, and decentralization_sale_open_timestamp_seconds fields are populated from Init

#### Scenario: Transition from Adopted to Open
- **WHEN** the current time is at or past the `decentralization_sale_open_timestamp_seconds`
- **AND** the lifecycle is `Adopted`
- **THEN** `try_open` transitions the lifecycle to `Open`
- **AND** derived fields (participation amounts) are initialized
- **AND** the purge_old_tickets routine is prepared to start

#### Scenario: Transition from Open to Committed
- **WHEN** the lifecycle is `Open`
- **AND** there is sufficient participation (min_direct_participation_threshold met)
- **AND** either the maximum ICP target has been reached or the swap duration has elapsed
- **THEN** `try_commit` transitions the lifecycle to `Committed`
- **AND** `decentralization_swap_termination_timestamp_seconds` is recorded

#### Scenario: Transition from Open to Aborted
- **WHEN** the lifecycle is `Open`
- **AND** the swap has ended (due or ICP target reached)
- **AND** there is NOT sufficient participation
- **THEN** the swap can be aborted

#### Scenario: Terminal states block periodic tasks
- **WHEN** the lifecycle is `Committed` or `Aborted`
- **AND** auto-finalization has already been attempted
- **THEN** `requires_periodic_tasks` returns false

### Requirement: Swap Initialization

The swap Init must be validated before the swap canister can operate.

#### Scenario: Valid Init accepted
- **WHEN** a valid `Init` is provided with all required canister IDs (nns_governance, sns_root, sns_governance, sns_ledger, icp_ledger)
- **THEN** the swap is created successfully

#### Scenario: Invalid Init rejected
- **WHEN** an `Init` with missing or invalid fields is provided
- **THEN** the swap constructor panics with an explanation of the validation failure

### Requirement: Direct Participation

Users participate in the swap by transferring ICP to the swap canister.

#### Scenario: Participation validation
- **WHEN** a user attempts to participate in the swap
- **THEN** the swap lifecycle must be `Open`
- **AND** the ICP target must not already be reached
- **AND** confirmation text must match if required by the swap configuration

#### Scenario: Confirmation text validation
- **WHEN** the swap requires confirmation text (set in SnsInitPayload)
- **AND** a participant provides matching confirmation text
- **THEN** participation proceeds
- **WHEN** the participant provides no text or non-matching text
- **THEN** participation is rejected with an appropriate error

#### Scenario: Confirmation text not required
- **WHEN** the swap does not require confirmation text
- **AND** a participant provides confirmation text anyway
- **THEN** participation is rejected with "Found a value for confirmation_text, expected none"

#### Scenario: ICP target tracking
- **WHEN** participation ICP amounts are tracked
- **THEN** `current_direct_participation_e8s` is the sum of all buyer amounts
- **AND** `available_direct_participation_e8s` is the difference between max and current direct participation
- **AND** `current_total_participation_e8s` includes both direct and Neurons' Fund contributions

### Requirement: Neurons' Fund Participation

The Neurons' Fund (formerly Community Fund) can provide matched funding based on direct participation levels.

#### Scenario: Matched funding scheme
- **WHEN** `neurons_fund_participation` is true and `neurons_fund_participation_constraints` is set
- **THEN** the Neurons' Fund participation amount is computed using a polynomial matching function
- **AND** it is capped at `max_neurons_fund_participation_icp_e8s`

#### Scenario: No Neurons' Fund participation
- **WHEN** `neurons_fund_participation` is false
- **THEN** `neurons_fund_participation_icp_e8s` is 0

#### Scenario: Neurons' Fund participation count
- **WHEN** `cf_neuron_count` is queried
- **THEN** it returns the total count of unique Community Fund neurons across all CF participants

### Requirement: Token Distribution (Neuron Baskets)

After the swap commits, SNS tokens are distributed to participants as neuron baskets with varying dissolve delays.

#### Scenario: Neuron basket generation
- **WHEN** neuron recipes are created for a participant
- **THEN** the participant's total SNS tokens are divided into `count` pieces (the basket size)
- **AND** each piece has an increasing dissolve delay: 0, dissolve_delay_interval_seconds, 2*dissolve_delay_interval_seconds, etc.
- **AND** token amounts are apportioned approximately equally (differing by at most 1 e8)

#### Scenario: Neuron memo ranges
- **WHEN** neuron memos are assigned for swap neurons
- **THEN** memos for neuron baskets start at 1,000,000 (NEURON_BASKET_MEMO_RANGE_START)
- **AND** the maximum memo for sale neurons is 10,000,000 (SALE_NEURON_MEMO_RANGE_END)

#### Scenario: Token scaling
- **WHEN** SNS tokens are distributed proportionally to ICP contributions
- **THEN** the scaling is computed as `(amount_icp_e8s * total_sns_e8s) / total_icp_e8s` using 128-bit arithmetic
- **AND** the individual ICP amount must not exceed total ICP

### Requirement: Swap Finalization

Finalization is the process that distributes tokens, creates neurons, and transitions the SNS to its operational state.

#### Scenario: Finalization lock
- **WHEN** finalization is initiated
- **THEN** a lock is acquired to prevent concurrent finalization calls
- **AND** the lock is released after finalization completes
- **AND** if finalization panics, the lock remains held until canister upgrade

#### Scenario: Successful finalization steps (committed swap)
- **WHEN** the swap is in `Committed` state and finalization proceeds
- **THEN** the following steps execute in order:
  1. Sweep ICP: Transfer ICP tokens from the swap canister to the SNS treasury
  2. Settle Neurons' Fund: Settle the NF participation with NNS governance
  3. Create SNS neuron recipes: Generate neuron recipes for all participants
  4. Sweep SNS tokens: Transfer SNS tokens to neuron staking accounts
  5. Claim swap neurons: Create neurons in SNS governance for all participants
  6. Set governance mode: Transition SNS governance to Normal mode
  7. Take dapp control: Set SNS Root as the sole controller of dapp canisters
- **AND** if any step fails, finalization halts and returns the error

#### Scenario: Failed swap finalization (aborted swap)
- **WHEN** the swap is in `Aborted` state (or committed but should restore dapp control)
- **AND** finalization proceeds
- **THEN** ICP is swept back to participants
- **AND** dapp controllers are restored to fallback controllers
- **AND** no further finalization steps are executed

#### Scenario: Auto-finalization
- **WHEN** `should_auto_finalize` is true in Init
- **AND** the swap has not already tried to auto-finalize
- **THEN** `try_auto_finalize` calls `finalize` automatically
- **AND** `already_tried_to_auto_finalize` is set to true to prevent retries
- **AND** the response is stored in `auto_finalize_swap_response`

#### Scenario: Auto-finalization disabled
- **WHEN** `should_auto_finalize` is false or unset
- **THEN** auto-finalization does not occur
- **AND** finalization must be triggered manually

### Requirement: Neuron Claiming

The swap canister creates neurons in SNS Governance for all swap participants.

#### Scenario: Batch neuron claiming
- **WHEN** `claim_swap_neurons` is called in `Committed` state
- **THEN** neuron recipes are sent to SNS Governance in batches of 500 (CLAIM_SWAP_NEURONS_BATCH_SIZE)
- **AND** already-claimed recipes are skipped
- **AND** invalid recipes are counted separately

#### Scenario: Neuron claiming requires Committed state
- **WHEN** `claim_swap_neurons` is called outside of `Committed` state
- **THEN** it returns immediately with a global failure count of 1

#### Scenario: Idempotent neuron recipe creation
- **WHEN** `create_sns_neuron_recipes` is called multiple times
- **THEN** it only creates each participant's recipes once
- **AND** on subsequent calls, the `skipped` count in SweepResult is incremented instead of `success`

### Requirement: Participation Limits

The swap enforces various limits on participation amounts.

#### Scenario: Maximum direct participation listing limit
- **WHEN** `ListDirectParticipants` is called
- **THEN** at most 20,000 participants are returned (MAX_LIST_DIRECT_PARTICIPANTS_LIMIT)

#### Scenario: Community Fund participant listing limit
- **WHEN** `ListCommunityFundParticipants` is called
- **THEN** at most 10,000 participants are returned (LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT_CAP)

#### Scenario: SNS neuron recipe listing limit
- **WHEN** `ListSnsNeuronRecipes` is called
- **THEN** at most 10,000 recipes are returned by default (DEFAULT_LIST_SNS_NEURON_RECIPES_LIMIT)

### Requirement: Ticket Management

The swap uses a ticket system to manage participation requests.

#### Scenario: Ticket creation
- **WHEN** a new participation request is initiated via `NewSaleTicketRequest`
- **THEN** a unique ticket ID is assigned (from `next_ticket_id`)
- **AND** the ticket tracks the buyer's principal and ICP amount

#### Scenario: Open ticket query
- **WHEN** `GetOpenTicketRequest` is called for a buyer
- **THEN** it returns the buyer's open (pending) ticket if one exists

#### Scenario: Old ticket purging
- **WHEN** periodic tasks run
- **THEN** old tickets are purged to prevent accumulation
- **AND** `purge_old_tickets_last_completion_timestamp_nanoseconds` tracks the last purge time
- **AND** `purge_old_tickets_next_principal` tracks iteration progress

### Requirement: ICP Refund

When the swap is aborted or participation fails, ICP must be returned to participants.

#### Scenario: Error refund ICP
- **WHEN** an ICP refund is requested via `ErrorRefundIcpRequest`
- **THEN** the response includes the block height if successful
- **OR** a typed error (Precondition, InvalidRequest, External) if the refund fails

### Requirement: Swap Derived State

The swap maintains derived state computed from primary state for efficient querying.

#### Scenario: Derived state computation
- **WHEN** derived state is queried
- **THEN** it includes:
  - `buyer_total_icp_e8s`: Total ICP from all buyers
  - `direct_participant_count`: Number of direct participants
  - `cf_participant_count`: Number of Neurons' Fund participants
  - `cf_neuron_count`: Number of CF neurons
  - `sns_tokens_per_icp`: Exchange rate as floating point
  - `direct_participation_icp_e8s`: Total direct participation
  - `neurons_fund_participation_icp_e8s`: Total NF participation
