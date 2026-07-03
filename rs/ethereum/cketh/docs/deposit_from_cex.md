---
id: DEFI-2096
title: Support deposit from CEX via per-account deposit addresses (EIP-7702 sweeping)
tags: [cketh, ckerc20, minter, deposit, eip-7702]
---

# Support deposit from CEX via per-account deposit addresses (EIP-7702 sweeping)

## Motivation

Today the only way to deposit ETH or ERC-20 tokens into ckETH/ckERC20 is to call the
helper smart contract (`DepositHelperWithSubaccount.sol`), which forwards the funds to
the minter's single tECDSA address and emits a `ReceivedEthOrErc20` event carrying the
beneficiary IC principal and subaccount. The minter discovers deposits exclusively by
scraping this event (`src/deposit.rs`, `src/eth_logs/`), i.e. attribution of funds to an
IC account relies entirely on the depositor *executing a contract call*.

A withdrawal from a centralized exchange (CEX) cannot fit through this path:

* A CEX only performs plain transfers: a bare ERC-20 `transfer(to, value)` (standard
  `Transfer` event, no principal) or a native ETH send (no log at all).
* The sender is the exchange's omnibus hot wallet, shared by all its customers, so
  sender-based attribution is impossible.
* Ethereum has no memo/data side-channel on plain transfers.

Consequently a user holding e.g. USDT or USDC on Coinbase/Binance cannot onramp into
ckUSDT/ckUSDC without first withdrawing to a self-custody wallet, funding it with ETH
for gas, and interacting with the helper contract — a prohibitive UX. Funds sent
directly to the minter address today are simply unaccounted, with no recovery path
(see the documentation of the `eth_balance` field of the `EthBalance` struct in
`src/state.rs`).

The only attribution channel a CEX supports is the **destination address**. This design
therefore gives each IC account a **unique, deterministic deposit address**, controlled
by the minter through threshold ECDSA (the ckBTC model), and uses **EIP-7702**
(live on Ethereum mainnet since the Pectra upgrade, May 2025) to sweep funds from these
addresses to the minter's main address **without pre-funding them with ETH for gas**:
the deposit EOA signs a one-time authorization delegating its code to a minimal sweeper
contract, and the minter's main (funded) address submits the sweep transaction and pays
for gas.

Target UX: *"I have USDT on a CEX and I want ckUSDT: I paste my deposit address into
the exchange withdrawal form and the tokens automagically appear as ckUSDT."*

The design is delivered in two phases:

* **Phase 1 — ckERC20 only** (ckUSDC, ckUSDT, …): deposits are ERC-20 `Transfer`s,
  which always emit logs and never execute recipient code, making detection and
  crediting straightforward.
* **Phase 2 — ckETH**: native ETH transfers emit no logs and interact badly with
  EIP-7702 delegated code under fixed 21'000 gas limits; this phase has additional
  design constraints, described separately.

## Requirements

### Phase 1 (ckERC20)

* `R1`: For every IC account `(principal, subaccount)`, the minter returns a unique,
  deterministic Ethereum deposit address. Repeated calls return the same address. Two
  distinct accounts never share an address, and no deposit address ever equals the
  minter's main address or a helper contract address.
* `R2`: If a supported ERC-20 token is transferred to a registered deposit address, and
  the transfer is in a finalized block, and the amount is at least the per-token
  minimum deposit amount, then the minter mints `amount - deposit_fee` ckERC20 to the
  associated IC account, exactly once (deduplication by `(transaction hash, log
  index)`, as for helper-based deposits).
* `R3`: If the ERC-20 `Transfer` sender is on the blocklist, no mint occurs; the
  deposit is recorded as invalid (same semantics as today's blocked helper deposits).
* `R4`: Transfers below the per-token minimum deposit amount, and transfers of
  unsupported ERC-20 tokens, are not credited. No funds are ever burned or destroyed:
  they remain at a tECDSA-controlled address and remain recoverable by the minter.
* `R5`: Every credited deposit is eventually swept to the minter's main address. A
  sweep failure or delay never affects already-minted balances; sweeps are retried
  until confirmed.
* `R6`: A sweep transaction moves funds only to the minter's main address, regardless
  of who triggers it. No other destination is reachable through the sweeper delegate.
* `R7`: The per-token `deposit_fee` and minimum deposit amount are configurable
  (upgrade argument / NNS proposal) such that fees cover the amortized sweep gas cost.
* `R8`: All new state transitions (address registration, accepted/invalid deposit,
  delegation, sweep sent/confirmed) are recorded as audit events, replayable on
  upgrade, consistent with the minter's event-sourcing architecture.
* `R9`: The minter dashboard and metrics expose: registered deposit addresses,
  credited-but-unswept balances per token, delegation status, and sweep activity.
* `R10`: Withdrawals (ckERC20 → ERC-20 and ckETH → ETH) are unaffected: they continue
  to be served from the minter's main address and its existing nonce sequence.
* `R13`: Registering a deposit address (`get_deposit_address`) triggers no
  threshold-ECDSA signature and no Ethereum transaction. The minter only signs a
  delegation and sweeps an address after having observed there a balance of a
  supported token of at least the per-token minimum deposit amount. (Registrations
  are free for callers; anything the minter spends per registration is a DoS vector
  on its cycles and ETH.)

### Phase 2 (ckETH)

* `R11`: If the finalized ETH balance of a deposit address exceeds the sum of all
  previously credited (minus swept) amounts by at least the minimum ETH deposit
  amount, the minter mints the difference minus the deposit fee to the associated
  account, exactly once per balance observation (monotone accounting: total credited
  never exceeds total received).
* `R12`: A plain ETH transfer sent with a fixed 21'000 gas limit to a deposit address
  MUST NOT be permanently locked: it either succeeds (address has no code at transfer
  time) or fails on the sender side (funds never leave the exchange). See the
  delegation lifecycle decision below.

## Non-goals

* **Gasless deposits from self-custody wallets** (EIP-2612 `permit` / Permit2
  sponsoring): a related but different problem — and mainnet USDT does not implement
  EIP-2612. Deposit addresses incidentally also cover this use case (a self-custody
  wallet can simply `transfer` to the deposit address), which further reduces its
  urgency.
* **Deposits from L2s / other chains**: only Ethereum L1 withdrawals are in scope. A
  CEX withdrawal on Arbitrum/Base to the deposit address is out of scope (and must be
  documented as unsupported).
* **Replacing the helper-contract flow**: the existing flow remains the cheapest path
  for power users and is untouched.
* **Automatic discovery without any user/frontend interaction**: crediting is
  claim-based (see Design Decisions); a frontend polling on the user's behalf makes
  this invisible in practice.
* **Automatic recovery of unsupported-token deposits**: funds remain recoverable
  (key-controlled address) but recovery tooling is future work.
* Accepted residual limitations:
  * A CEX that batches ETH withdrawals through a contract (internal transactions)
    provides no sender information without trace APIs; Phase 2 compliance screening is
    therefore weaker for ETH than for ERC-20 (see Phase 2 section).
  * During the short window in which a deposit address carries delegated code, a
    fixed-21'000-gas ETH transfer to it fails on the sender side (`R12` guarantees no
    loss).

## Design Decisions

* **Attribution by destination address, not by sender or contract call.** This is the
  only mechanism compatible with plain CEX transfers. Chosen over sender-address
  registration (CEX hot wallets are shared and unpredictable) and exact-amount
  matching (collision-prone, griefable); see Discussed Alternatives.
* **Deposit addresses are tECDSA-derived EOAs, not contracts.** The minter derives one
  EOA per IC account using a non-empty ECDSA derivation path (the main address keeps
  the empty path `MAIN_DERIVATION_PATH`). Decisive property: *the minter holds the
  key*. Funds at a deposit address are never dependent on contract code being correct —
  even with no EIP-7702 at all, any balance is recoverable by classically funding the
  address with gas and signing a normal transfer. Chosen over CREATE2 counterfactual
  forwarder contracts, where funds are controlled by code alone (see Discussed
  Alternatives).
* **Sweeping via EIP-7702, gas paid by the minter's main address.** Each deposit EOA
  signs (threshold ECDSA) a one-time EIP-7702 authorization delegating its code to a
  single immutable, storage-less sweeper delegate whose only capability is *transfer
  everything to the minter's main address*. Sweep transactions are type-`0x04`
  transactions sent from the funded main address; many deposit addresses are swept in
  one transaction. No deposit address ever needs an ETH balance for gas.
* **Sweeps are permissionless-safe** (variant A). The delegate's sweep functions are
  callable by anyone because the destination is hardcoded (`R6`); a third party
  triggering a sweep only donates gas. This removes access-control state from the
  delegate and lets one transaction sweep many deposit addresses through a batch entry
  point on the deployed `CkSweeper` instance itself — the delegate doubles as the
  batcher, so no additional contract is needed (the canonical, already-deployed
  [Multicall3](https://www.multicall3.com/) would work as well). Variant B trades this
  property away, see the open decision below.
* **Mint on finalized deposit, sweep asynchronously** (variant A). The user is
  credited as soon as the deposit is finalized and detected; sweeping is pure treasury
  consolidation, batched to amortize gas, and never blocks or reverts a mint (`R5`).
  This decouples UX latency from gas-optimization policy. Variant B instead credits on
  the sweep's own finalized event, see the open decision below.
* **Claim-based detection instead of continuous scraping.** Deposits are detected when
  a `notify_deposit` endpoint is called for a specific account (by the user, or
  transparently by a frontend/timer polling recently active addresses). A targeted
  `eth_getLogs` on one token contract filtered by one recipient address is small and
  cheap; continuously scraping `Transfer` logs for an unbounded, growing set of
  addresses is not. This mirrors ckBTC's `update_balance`. (The existing helper-contract
  scraping is unchanged.)
* **No up-front spending per registered address (anti-DoS).** `get_deposit_address`
  is pure key derivation plus a state entry: no threshold-ECDSA signature, no
  Ethereum transaction (`R13`). Registrations are free for callers, so any eager
  per-address spending — signing the delegation up-front, let alone submitting it
  on-chain — would let an attacker drain the minter's cycles and ETH by spamming
  registrations. The pipeline is strictly gated: register → observe a balance of a
  supported token ≥ the per-token minimum at the address (targeted, claim-driven
  scan) → only then sign the delegation and sweep. For the same reason the balance
  scanning itself must stay bounded: the registered set is attacker-inflatable, so
  scans are claim-driven (`notify_deposit`, guarded per account) or bounded batches,
  never an unbounded standing scan of every registered address.
* **Phase 1 delegation is therefore installed lazily, with the first sweep, and is
  permanent.** For ERC-20-only crediting, delegated code on the deposit address is
  harmless (ERC-20 transfers never execute recipient code), so one authorization per
  address — ever — suffices. Phase 2 revisits this for native ETH (see below).
* **Fees are deducted from the minted amount.** A CEX depositor owns no ckETH to pay
  gas with, so the sweep cost is recovered as a per-token flat fee subtracted at mint
  time (`minted = amount - deposit_fee`), like ckBTC's check fee. Flat and
  proposal-configurable rather than oracle-priced, for simplicity and predictability
  (`R7`).

### Open decision: what the sweep does — variant A (direct) vs variant B (through the helper contract)

Both variants share everything above (address derivation, EIP-7702 delegation,
batching, fees); they differ in the delegate's action and, consequently, in *where
crediting happens*. The decision between them is **not yet taken**.

**Variant A — direct sweep (`CkSweeper`).** The delegate transfers the funds straight
to the minter's main address. Crediting requires a *new* detection-and-mint path in
the minter (`notify_deposit` → finalized `Transfer` log → mint), with its own event
types, deduplication and audit trail. Sweeps are permissionless-safe and mint timing
is independent of sweep scheduling. Measured in the demo (mock USDT): 66'854 gas for
a first single-address sweep including its authorization, ≈ 26k marginal gas per
additional address in a batch.

**Variant B — sweep through the existing helper contract (`CkSweeperViaHelper`).**
The delegate approves and calls `depositErc20` on the already-deployed helper
(`DepositHelperWithSubaccount.sol`): the helper moves the funds to the minter *and
emits the canonical `ReceivedEthOrErc20` event* — with the deposit EOA as `owner` and
a caller-supplied IC principal/subaccount — at the single contract address the minter
already scrapes. **The minter's crediting pipeline (scrape → parse → dedup → mint) is
reused unchanged.** Consequences:

* *Massively smaller minter change.* No second crediting path: deposit detection is
  demoted from a correctness-critical component to a mere sweep-scheduling hint (it
  can be sloppy, delayed, or even frontend-driven without any double-mint or
  lost-credit risk). Correctness lives entirely in the existing, battle-tested
  pipeline.
* *Sweeping must be restricted to the minter.* The principal is a sweep argument, so a
  permissionless sweep would let anyone credit a deposit to their own principal. The
  delegate stays stateless via two immutables: `MINTER`, and `SELF` (the deployed
  instance's own address, captured at construction), accepting
  `msg.sender ∈ {MINTER, SELF}` so the batch entry point still works. Belt-and-braces,
  the minter additionally validates scraped events whose `owner` is a registered
  deposit address against its own address↔account map and quarantines mismatches.
* *Minting follows the sweep, but latency need not suffer.* The minter can schedule
  the sweep as soon as it observes the deposit at the `latest` block, **without
  waiting for the deposit to be finalized**: crediting only ever follows the
  *finalized* helper event emitted by the sweep itself, so a reorg that drops the
  deposit merely wastes the sweep's gas (the delegate sweeps a zero balance — a
  no-op) and costs some cycles; a reorged sweep transaction is handled by the
  existing nonce-tracking and resubmission machinery. End-to-end latency is then
  comparable to today's helper flow (deposit inclusion + sweep + finalization).
* *Screening point shifts.* The scraped event's `from`/`owner` is the deposit EOA,
  not the CEX hot wallet, so blocklist screening of the actual sender (`R3`) must
  happen when scheduling the sweep, based on the observed `Transfer` log.
* *Extra gas per sweep* for `approve` + `transferFrom` + event. Measured in the demo:
  82'207 gas single (+15'353 vs variant A), 164'746 for a batch re-delegating three
  EOAs and sweeping two of them through the helper.
* *Native ETH works symmetrically* via the helper's `depositEth` (Phase 2).

Both variants are exercised end-to-end in the runnable demo, including the
adversarial case for variant B (a non-minter caller attempting to sweep with their
own principal is rejected).

## Implementation

### Constraints

* The minter's transaction layer supports only EIP-1559 (type `0x02`) transactions
  (`src/tx.rs`, `EIP1559_TX_ID`); EIP-7702 requires adding the type `0x04`
  (`SetCode`) transaction and authorization-tuple signing.
* The minter's main address uses the *empty* ECDSA derivation path
  (`MAIN_DERIVATION_PATH` in `src/lib.rs`); any per-account path must be non-empty and
  collision-free with it. Withdrawals assume a single sequential nonce for the main
  address (`src/state/transactions`); sweep transactions originate from the main
  address and therefore share that nonce sequence.
* All Ethereum interaction goes through the EVM-RPC canister with multi-provider
  threshold consensus (`src/eth_rpc_client/`); every new call (`eth_getLogs` per
  deposit address, `eth_getBalance`, `eth_getTransactionCount` for deposit EOAs) must
  use the same reduction strategies.
* Each EVM-RPC call today is one HTTPS outcall *per provider* and each outcall burns
  cycles, so observing the balances of many registered addresses (`R13` gate) must
  not cost one call per address. This depends on **JSON-RPC batch request support in
  the EVM-RPC canister** (`eth_batch`,
  [dfinity/evm-rpc-canister#561](https://github.com/dfinity/evm-rpc-canister/pull/561),
  in progress): one batch of `eth_getBalance` / `eth_call` requests per outcall.
  Until it lands, a [Multicall3](https://www.multicall3.com/) `aggregate3` `eth_call`
  can read many `balanceOf` (and, via `getEthBalance`, native ETH) values in a single
  request — at the cost of depending on an extra on-chain contract.
* The minter is event-sourced (`src/state/audit.rs`, `src/state/event.rs`): all new
  state must be reconstructible from persisted events (`R8`).
* Deposits are only credited at *finalized* blocks, as today.

### Address derivation and registration

* Derivation path for account `(p, s)`:
  `[SCHEMA_DEPOSIT_ADDRESS, p.as_slice(), s]` where `SCHEMA_DEPOSIT_ADDRESS = [1u8]`
  is a schema tag reserving room for future schemes, and `s` is the 32-byte subaccount
  (all-zero for the default subaccount). Non-empty by construction, hence distinct
  from the main address path.
* The child *public key* (and hence the address) is computed locally from the cached
  master public key using non-hardened derivation (`ic-secp256k1`'s
  `derive_subkey` / `DerivationPath`, as ckBTC does) — no management-canister call and
  no signature is needed to *create* an address; `sign_with_ecdsa` with the same path
  is only invoked to sign authorizations (and, as a recovery fallback, transactions).
* New endpoint `get_deposit_address(account) -> String` (EIP-55 checksummed). The
  first call is an update call that registers the address in state
  (`deposit_addresses: Account ↔ Address` bimap + per-address bookkeeping:
  `registered_at_block`, delegation status, credited/swept counters), emitting a
  `DepositAddressRegistered` audit event — and does nothing else: no threshold-ECDSA
  signature, no Ethereum transaction (`R13`). Any per-address spending happens only
  once a balance ≥ the per-token minimum has been observed at the address.
  Subsequent calls are cheap lookups.

### Deposit detection and minting (Phase 1, ckERC20)

* New endpoint `notify_deposit(account, token?)` (update, fee-less, guarded against
  concurrent calls per account like `update_balance` in ckBTC):
  1. Look up the registered deposit address; determine the block range
     `(last_checked_block + 1) ..= latest_finalized_block`.
  2. `eth_getLogs` with `address = token contract(s)`, `topics = [Transfer,
     any, deposit_address]` over that range (chunked by the existing 500-block spread
     logic). The response is tiny: it concerns a single recipient.
  3. For each log: validate amount ≥ per-token minimum (`R4`), screen the `Transfer`
     sender against the blocklist (`R3`), deduplicate by `(tx_hash, log_index)` and
     record `AcceptedErc20Deposit`-style events with a new deposit-source variant;
     invalid ones are recorded like today's `InvalidDeposit`.
  4. Mint through the existing `mint()` path with `amount - deposit_fee`, reusing the
     ledger-client, memo (tx hash + log index) and quarantine-on-panic machinery
     (`R2`).
* A frontend (e.g. OISY) polls `notify_deposit` after showing the address, so the flow
  is automatic from the user's perspective; a background timer may additionally
  re-check addresses with recent activity, bounded to a fixed batch per tick.
* Scanning many registered addresses at once (the `R13` gate, and cheap periodic
  re-checks) reads balances in bulk rather than per address: a single JSON-RPC batch
  of `balanceOf` `eth_call`s / `eth_getBalance`s per HTTPS outcall once the EVM-RPC
  canister supports `eth_batch`
  ([dfinity/evm-rpc-canister#561](https://github.com/dfinity/evm-rpc-canister/pull/561)),
  or one Multicall3 `aggregate3` `eth_call` for a whole batch meanwhile. A cheap
  balance scan decides *whether* to act; the log-based steps above remain the source
  of truth for crediting (variant A) or the helper event does (variant B).

### Sweeper delegate contract

A single immutable Solidity contract, deployed once per network, with **no storage**
(EIP-7702 delegates share the EOA's storage; using none avoids collision hazards
entirely) and the minter's main address hardcoded as an `immutable`. Shown below for
variant A; variant B's delegate (`CkSweeperViaHelper` in the demo) has the same shape
but calls the helper's `depositErc20` with caller-supplied principal/subaccount and
restricts callers to the minter (see the open decision above):

```solidity
contract CkSweeper {
    address payable private immutable MINTER;
    constructor(address minter) { MINTER = payable(minter); }

    /// Callable by anyone: funds can only move to MINTER (R6).
    function sweepErc20(IERC20[] calldata tokens) external {
        for (uint i = 0; i < tokens.length; ++i) {
            uint256 b = tokens[i].balanceOf(address(this));
            if (b > 0) tokens[i].safeTransfer(MINTER, b); // USDT-safe transfer
        }
    }

    /// Batch entry point: the deployed CkSweeper instance doubles as the
    /// batcher, sweeping many delegated deposit EOAs in a single transaction.
    function sweepErc20Batch(address[] calldata depositAddresses, address[] calldata tokens) external {
        for (uint i = 0; i < depositAddresses.length; ++i) {
            CkSweeper(depositAddresses[i]).sweepErc20(tokens);
        }
    }

    function sweepEth() external {
        if (address(this).balance > 0) {
            (bool ok,) = MINTER.call{value: address(this).balance}("");
            require(ok);
        }
    }
}
```

Notes: `safeTransfer` handles non-standard ERC-20s (USDT returns no value); no
`receive()` is defined on purpose — plain ETH sends to a *delegated* address are meant
to fail rather than be silently accepted while delegated (Phase 2, `R12`); reentrancy
is moot (fixed destination, no state).

### EIP-7702 support in the transaction layer (`src/tx.rs`)

* New `Eip7702TransactionRequest` with `SET_CODE_TX_ID: u8 = 4`, payload
  `0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
  to, value, data, access_list, authorization_list, y_parity, r, s])`.
* `AuthorizationTuple { chain_id, delegate, nonce, y_parity, r, s }`, signed over
  `keccak256(0x05 || rlp([chain_id, delegate, nonce]))` with `sign_with_ecdsa` using
  the deposit address' derivation path; `chain_id` is set explicitly (never 0) to
  prevent cross-chain replay; recovery-id determination reuses the existing
  `Eip1559Signature` machinery.
* Deposit-EOA nonces: fetched via `eth_getTransactionCount` (finalized) with the usual
  consensus strategy at authorization-signing time; an applied authorization increments
  the EOA nonce, tracked in state to avoid re-fetching. Deposit EOAs never send
  transactions themselves, so races are limited to re-delegation.
* Resubmission with fee bumping mirrors the existing `Resubmittable` logic.

### Sweeping task

* A periodic task selects deposit addresses with observed-but-unswept balances where
  `unswept_value ≥ sweep_gas_cost × margin` or `age > max_age`, up to `N` addresses
  per batch (gas-limit bound; initial `N ≈ 20`). Only addresses that pass this gate
  ever cost the minter anything: the delegation authorization is signed here, not at
  registration time (`R13`).
* One type-`0x04` transaction from the main address:
  * `authorization_list`: tuples for all not-yet-delegated addresses in the batch
    (≈ 12'500–25'000 gas each, one-time);
  * `to = CkSweeper`, `data = sweepErc20Batch(deposit_addresses, [tokens])`. Measured
    in the runnable demo (mock token): ≈ 67k gas for a first single-address sweep
    including its authorization, ≈ 26k marginal gas per additional address in a batch.
* Confirmation via transaction receipt, exactly like withdrawals; on success emit
  `SweepConfirmed` events updating per-address `total_swept`. Sweep gas is paid from
  the main address' ETH balance and recouped by `deposit_fee` (`R7`); the effective
  fee/cost ratio is exported as a metric to recalibrate fees via proposal.
* Accounting invariant: main-address liquidity for withdrawals = today's
  `eth_balance` bookkeeping; credited-but-unswept amounts are tracked per address and
  shown on the dashboard (`R9`).

### Phase 2: native ETH

Two ETH-specific problems and their resolutions:

1. **Detection without logs.** Plain ETH transfers emit no events, and CEXs may send
   ETH via internal transactions (contract-batched withdrawals), which even
   `eth_getTransactionByHash` cannot attribute without trace APIs. Detection is
   therefore **balance-based**: `notify_deposit` reads `eth_getBalance(addr,
   finalized)` and credits `balance + total_swept - total_credited` when the delta
   exceeds the ETH minimum (`R11`). This is robust to internal transactions and
   requires no trace support from providers.
   * Compliance caveat: balance deltas carry no sender information. Screening is
     limited to (a) optional sender screening when the caller supplies withdrawal
     transaction hashes, and (b) address-level screening. This weakening relative to
     `R3` is an accepted limitation (see Non-goals) and should be reviewed with
     compliance before Phase 2 ships.
2. **Fixed 21'000-gas transfers vs delegated code (`R12`).** A value transfer to an
   address with EIP-7702 delegated code *executes* that code, and a transfer with
   exactly 21'000 gas has zero gas left for execution — it always fails. Exchanges
   commonly hard-code 21'000 for ETH withdrawals. Phase 2 therefore switches the
   delegation lifecycle for accounts using ETH deposits from *permanent* to
   *set-and-clear*:
   * Sweep batch transaction 1: authorizations installing the delegate + Multicall3
     `sweepEth()`/`sweepErc20()` calls;
   * Sweep batch transaction 2: authorizations delegating to `address(0)`, which
     clears the code (per EIP-7702), restoring a plain EOA.
   * Cost: two tECDSA signatures and ≈ 2 × 12'500–25'000 gas per address per sweep
     cycle, instead of one signature ever. Outside the short set→clear window, the
     address is codeless and fixed-gas transfers succeed; inside it they fail on the
     sender side without loss (`R12`).
   * Whether Phase 1 addresses also move to set-and-clear (uniform policy) or keep
     permanent delegation (cheaper) is decided at Phase 2 based on measured CEX
     behavior for ETH withdrawals.

### Test plan

A runnable end-to-end demonstration of the sweep mechanism (unfunded deposit EOAs,
plain USDT-style transfers, single and batched type-`0x04` sweep transactions with gas
paid by the minter, gas assertions) against a local dev node (any post-Pectra
version) is available in [`deposit_from_cex_demo/`](deposit_from_cex_demo/README.md).
It exercises both sweep variants — including variant B against the *real*
`DepositHelperWithSubaccount.sol` bytecode, asserting the emitted
`ReceivedEthOrErc20` events carry the right principals, re-delegation of already
delegated deposit EOAs, and the rejected non-minter sweep attempt.

Unit tests (in `tests.rs` files per module, helpers in `test_fixtures.rs`):

* Address derivation: determinism, uniqueness across principals/subaccounts,
  non-collision with the main address, EIP-55 encoding (`R1`).
* Type-`0x04` transaction and authorization encoding/signing against EIP-7702
  published test vectors; authorization hash `0x05 || rlp(...)`; recovery-id
  round-trip (`R5`, `R6` plumbing).
* `Transfer`-log parsing, minimum/fee arithmetic incl. `amount ≤ fee` rejection
  (`R2`, `R4`), blocklist screening (`R3`), dedup by `(tx_hash, log_index)` (`R2`).
* Balance-delta crediting monotonicity across sweep interleavings (`R11`).
* Event replay: state reconstructed from audit events equals live state (`R8`).

Integration tests (state-machine tests in `rs/ethereum/cketh/minter/tests` with the
mocked EVM-RPC canister, extending the existing fixtures):

* End-to-end Phase 1 happy path: register address → mock `Transfer` log → notify →
  mint − fee → sweep tx submitted with expected `0x04` payload → receipt → swept
  (`R2`, `R5`, `R7`).
* Double-notify / concurrent-notify produce a single mint (`R2`); blocked sender
  (`R3`); below-minimum and unsupported token (`R4`); sweep failure then retry with
  fee bump, mint unaffected (`R5`); withdrawal flow regression (`R10`); dashboard
  rendering (`R9`).
* Solidity: Foundry tests for `CkSweeper` (permissionless sweep only reaches minter,
  USDT-style token, delegated-EOA execution against a Prague-enabled local node)
  (`R6`, `R12`).

Verification commands: `bazel test //rs/ethereum/cketh/minter:lib_unit_tests
//rs/ethereum/cketh/minter/tests:...` (exact targets per PR), plus `forge test` for
the delegate.

### Delivery / PR sequence

1. **EIP-7702 transaction support** in `src/tx.rs` + authorization signing in
   `src/management` — pure library code, no behavior change. AC: encoding/signing unit
   tests vs. EIP test vectors.
2. **Deposit address derivation, registration state, `get_deposit_address`** + audit
   events + dashboard section. AC: `R1`, `R8`, `R9` (addresses only).
3. **ckERC20 deposit detection and minting** (`notify_deposit`, log queries, fees,
   minimums, blocklist). AC: `R2`, `R3`, `R4`, `R7` (fee deduction), `R8`.
4. **Sweeper delegate contract** (Solidity, audited) + **sweeping task** (delegation,
   Multicall3 batching, receipts, metrics). AC: `R5`, `R6`, `R7`, `R9`, `R10`.
5. **Phase 1 launch on Sepolia**, then mainnet via NNS upgrade proposal; frontend
   (OISY) integration of `get_deposit_address` + `notify_deposit` polling.
6. **Phase 2: ckETH** (balance-delta crediting, set-and-clear delegation lifecycle,
   compliance sign-off). AC: `R11`, `R12`.

## Discussed Alternatives

* **CREATE2 counterfactual forwarder contracts** (the classic exchange pattern): a
  factory computes `CREATE2(factory, salt = hash(account), forwarder_init_code)`
  addresses; sweeping deploys the forwarder, which pushes funds to the minter and
  `selfdestruct`s in the same transaction (still permitted post-EIP-6780), leaving the
  address codeless. Pros: decade of production use by exchanges, no dependency on
  EIP-7702 or a new transaction type, native-ETH-safe by construction. Rejected as
  the primary design because funds at deposit addresses would be controlled *by code
  alone* — a factory/forwarder bug strands funds with no recovery — whereas tECDSA
  EOAs keep key-based recovery independent of any contract; CREATE2 also costs more
  gas per sweep (redeployment every cycle) and inherits residual `selfdestruct`
  protocol risk. It remains the documented fallback if EIP-7702 adoption in the
  transaction layer is reconsidered.
* **ERC-4337 smart accounts + paymaster**: counterfactual 4337 accounts as deposit
  addresses with sponsored sweeps. Rejected: the minter is already its own transaction
  submitter with multi-provider consensus, so EntryPoint/bundler/paymaster
  infrastructure adds ≈100k+ gas per operation, an external-bundler dependency, and a
  large audit surface for zero benefit over EIP-7702 here.
* **EIP-2612 permit / Permit2 sponsored helper deposits**: gasless `depositWithPermit`
  relayed by the minter. Does not address CEX at all (a hot wallet signs no custom
  message) and mainnet USDT lacks EIP-2612; noted as possible future work for
  self-custody UX only.
* **Attribution hacks on the single minter address**: sender-address registration
  (CEX hot wallets are shared/unpredictable), exact-amount matching (collisions,
  fee-adjusted amounts, griefable by front-running), or per-exchange integration of
  the helper contract (business-development dependency, not a protocol design). All
  rejected as unsound.
* **Continuous scraping of `Transfer` logs for all deposit addresses** instead of
  claim-based detection: `eth_getLogs` with a growing disjunction of thousands of
  recipient topics scales linearly in cost with the user base, must be chunked across
  providers' topic limits, and still misses native ETH. Rejected in favor of targeted,
  claim-triggered queries; can be revisited as an optimization for hot addresses.
* **Pre-funding deposit EOAs with ETH for gas** (no EIP-7702): requires one extra
  funding transaction per sweep (≈21k gas + transfer latency), doubles the transaction
  count, leaves ETH dust stranded on every deposit address, and complicates fee
  accounting. Kept only as the implicit *recovery* path that key-controlled addresses
  always allow.
