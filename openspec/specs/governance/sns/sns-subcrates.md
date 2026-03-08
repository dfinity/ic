# SNS Sub-Crates Specification

This document specifies the behavior and contracts of the smaller utility crates in the
`rs/sns/` tree that support SNS governance, swap, and auditing functionality.

---

## ic-sns-governance-api-helpers

**Path:** `rs/sns/governance/api_helpers/`

### Purpose

Convenience functions and default parameters for SNS governance, providing sensible defaults for
`NervousSystemParameters` and subaccount extraction from neuron IDs.

### Public API

| Item | Description |
|---|---|
| `E8S_PER_TOKEN: u64` | Constant `100_000_000`. |
| `DEFAULT_NEURON_CLAIMER_PERMISSIONS` | `[ManagePrincipals, Vote, SubmitProposal]` |
| `default_nervous_system_parameters() -> NervousSystemParameters` | Returns a fully populated `NervousSystemParameters` with sensible defaults. |
| `neuron_id_subaccount_or_err(neuron_id: &NeuronId) -> Result<Subaccount, GovernanceError>` | Converts a `NeuronId` (byte slice) to an ICRC-1 `Subaccount`. |
| `get_neuron_subaccount_or_err(neuron: &Neuron) -> Result<Subaccount, GovernanceError>` | Extracts and converts the subaccount from a `Neuron`'s `id` field. |

### Default Parameters

Key defaults from `default_nervous_system_parameters()`:

| Parameter | Default |
|---|---|
| `reject_cost_e8s` | 1 token (100,000,000 e8s) |
| `neuron_minimum_stake_e8s` | 1 token |
| `transaction_fee_e8s` | Standard transfer fee |
| `max_proposals_to_keep_per_action` | 100 |
| `initial_voting_period_seconds` | 4 days |
| `wait_for_quiet_deadline_increase_seconds` | 1 day |
| `max_number_of_neurons` | 200,000 |
| `neuron_minimum_dissolve_delay_to_vote_seconds` | 6 months |
| `max_dissolve_delay_seconds` | 8 years |
| `max_neuron_age_for_age_bonus` | 4 years |
| `max_dissolve_delay_bonus_percentage` | 100% |
| `max_age_bonus_percentage` | 25% |
| `automatically_advance_target_version` | true |
| Voting rewards | Disabled (0 basis points initial and final) |

---

## ic-sns-governance-proposal-criticality

**Path:** `rs/sns/governance/proposal_criticality/`

### Purpose

Defines proposal criticality levels for SNS governance, which control voting power thresholds and
duration parameters. Critical proposals require higher thresholds to pass.

### Public API

| Item | Description |
|---|---|
| `ProposalCriticality` | Enum: `Normal` (default), `Critical`. |
| `ProposalCriticality::voting_power_thresholds(self) -> VotingPowerThresholds` | Returns the required thresholds for the given criticality. |
| `VotingPowerThresholds` | Struct with `minimum_yes_proportion_of_total` and `minimum_yes_proportion_of_exercised`. |
| `VotingDurationParameters` | Struct with `initial_voting_period` and `wait_for_quiet_deadline_increase`. |

### Threshold Values

| Criticality | Yes % of Total | Yes % of Exercised |
|---|---|---|
| Normal | 3% (300 basis points) | 50% (5000 basis points) |
| Critical | 20% (2000 basis points) | 67% (6700 basis points) |

### VotingDurationParameters

Describes the initial voting period and the wait-for-quiet deadline increase. Wait-for-quiet
triggers when the yes/exercised ratio crosses the `minimum_yes_proportion_of_exercised` threshold
in either direction. The total deadline increase is at most `2 * wait_for_quiet_deadline_increase`.

### Invariants

1. Both threshold percentages must be < 100%.
2. `minimum_yes_proportion_of_total` should not exceed `minimum_yes_proportion_of_exercised`
   (since total voting power >= exercised voting power), though this is not enforced.
3. `ProposalCriticality::Normal` is the default, used for custom proposals without an assigned
   topic.

---

## ic-sns-governance-proposals-amount-total-limit

**Path:** `rs/sns/governance/proposals_amount_total_limit/`

### Purpose

Computes the upper bound on how many tokens an SNS treasury can transfer (or mint) via proposals
within a 7-day window, based on the treasury's XDR valuation.

### Public API

| Function | Description |
|---|---|
| `transfer_sns_treasury_funds_7_day_total_upper_bound_tokens(valuation: Valuation) -> Result<Decimal, ProposalsAmountTotalLimitError>` | Upper bound for treasury transfers. |
| `mint_sns_tokens_7_day_total_upper_bound_tokens(valuation: Valuation) -> Result<Decimal, ProposalsAmountTotalLimitError>` | Upper bound for minting. Same logic as transfers. |

### Treasury Size Regimes

| Treasury Size (XDR) | Limit |
|---|---|
| <= 100,000 XDR (small) | No limit (entire treasury can be transferred) |
| <= 1,200,000 XDR (medium) | 25% of treasury |
| > 1,200,000 XDR (large) | 300,000 XDR (fixed cap, equals 25% of 1.2M) |

### XDR Price Floor

`MIN_XDRS_PER_ICP = 1` -- if the quoted ICP/XDR rate is below this, the minimum is used instead.
This prevents artificially low price quotes from placing the treasury in the "small" regime where
limits are most permissive.

There is no corresponding maximum; high price quotes push toward the "large" regime where limits
are more restrictive, which is considered safe.

### Conversion to Tokens

The XDR limit is converted to tokens using the inverse of `xdrs_per_icp * icps_per_token`.
If `xdrs_per_token == 0`, the `NoLimit` branch applies (since the XDR valuation would be 0).

### Error Type

`ProposalsAmountTotalLimitError` with variant `ProposalsAmountTotalLimitErrorType::Arithmetic`
for overflow/division errors.

---

## ic-sns-governance-token-valuation

**Path:** `rs/sns/governance/token_valuation/`

### Purpose

Computes the XDR valuation of token balances held in ICRC-1 ledger accounts. Used to determine
treasury size for proposal amount limits. Supports both ICP and SNS native token valuation.

### Public API

| Item | Description |
|---|---|
| `try_get_icp_balance_valuation(account) -> Result<Valuation, ValuationError>` | Values an ICP balance in XDR. |
| `try_get_sns_token_balance_valuation(account, sns_ledger_canister_id, swap_canister_id) -> Result<Valuation, ValuationError>` | Values an SNS token balance in XDR. |
| `Token` | Enum: `Icp`, `SnsToken`. Has `assess_balance()` method. |
| `Valuation` | Struct: `token`, `account`, `timestamp`, `valuation_factors`. |
| `ValuationFactors` | Struct: `tokens` (Decimal), `icps_per_token` (Decimal), `xdrs_per_icp` (Decimal). |
| `ValuationFactors::to_xdr() -> Decimal` | `tokens * icps_per_token * xdrs_per_icp` |

### Valuation Pipeline

All three factors are fetched concurrently via `futures::join!`:

1. **Balance (`tokens`):** ICRC-1 `icrc1_balance_of` call, converted from e8s to Decimal.
2. **ICPs per token:**
   - For ICP: trivially 1.
   - For SNS tokens: computed from swap's `get_derived_state` (initial SNS tokens per ICP at swap
     time), adjusted for inflation using `initial_supply / current_supply` from the ledger.
3. **XDRs per ICP:** 30-day moving average from the Cycles Minting Canister
   (`get_average_icp_xdr_conversion_rate`), converted from permyriad to units.

### SNS Token Price Calculation

```
initial_icps_per_sns_token = 1 / initial_sns_tokens_per_icp
total_inflation = current_supply_e8s / initial_supply_e8s
current_icps_per_sns_token = initial_icps_per_sns_token / total_inflation
```

### Error Types

`ValuationError` with species:
- `External` -- canister call failed.
- `Mismatch` -- response missing expected data.
- `Arithmetic` -- overflow, underflow, divide by zero.

### Internal Traits

| Trait | Description |
|---|---|
| `Icrc1Client` | `async fn icrc1_balance_of(account) -> Result<Nat, (i32, String)>` |
| `IcpsPerTokenClient` | `async fn get() -> Result<Decimal, ValuationError>` |
| `XdrsPerIcpClient` | `async fn get() -> Result<Decimal, ValuationError>` |

All traits have `#[automock]` for testing.

---

## ic-sns-swap-proto-library

**Path:** `rs/sns/swap/proto_library/`

### Purpose

Contains the generated protobuf types for the SNS swap canister. This crate exists as a separate
library to break dependency cycles -- other crates (e.g., `ic-sns-governance-token-valuation`)
need swap request/response types without depending on the full swap crate.

### Public API

- `pub mod pb` -- re-exports the generated protobuf module tree, including types such as
  `GetDerivedStateRequest` and `GetDerivedStateResponse`.

### Structure

The crate is a thin wrapper: `lib.rs` contains only `pub mod pb;`, with the actual generated code
in the `pb` submodule.

---

## ic-sns-audit

**Path:** `rs/sns/audit/`

### Purpose

Auditing tool for validating that NNS Governance and an SNS swap canister agree on how SNS neurons
were allocated after a successful swap, with a focus on Neurons' Fund participation.

### Public API

| Item | Description |
|---|---|
| `validate_sns_swap<C: CallCanisters>(agent, swap) -> Result<(), AuditError<C::Error>>` | Performs a best-effort audit of an SNS swap's neuron allocation. |
| `AuditError<E>` | Error enum with variants for canister call failures, pre-one-proposal SNS, pre-matched-funding SNS, missing audit info, decimal conversion errors, and swap-not-final-state. |

### Audit Checks Performed

**SNS-global checks:**

1. Number of Neurons' Fund neurons with initially reserved maturity >= number that actually
   participated.
2. Number of Neurons' Fund neurons with initially reserved maturity >= number that were refunded.

**Per-neuron checks (Neurons' Fund neurons only):**

3. For each controller: `initial_amount_icp_e8s == final_amount_icp_e8s + refunded_amount_icp_e8s`.
4. Number of SNS neurons == number of NNS NF participants * neuron basket count.
5. For each controller: the SNS token amount received matches the ICP investment times the
   `sns_tokens_per_icp` rate, within a tolerance of 1 ICP e8s per NNS neuron.

### Data Sources

- **Swap canister:** `get_derived_state`, `get_init`, `list_all_sns_neuron_recipes`.
- **SNS Governance:** `metadata` (for SNS name).
- **NNS Governance:** `get_neurons_fund_audit_info` (keyed by the NNS proposal ID from swap init).

### Special Cases

- If `neurons_fund_participation` is `false` (NF not requested), the tool checks consistency
  and returns immediately.
- Pre-one-proposal and pre-matched-funding SNS instances cannot be audited and produce specific
  errors.

### Error Tolerance

`ERROR_TOLERANCE_ICP_E8S = 1` -- per NNS neuron contributing. The cumulative tolerance for a
controller is `1 * number_of_nns_neurons`.

### Output

Prints colored pass/fail lines using ANSI true color:
- Green checkmark for passing checks.
- Red X for failing checks.
