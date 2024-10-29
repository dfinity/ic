# ICRC-1 Ledger

This package contains an implementation of a token ledger compliant with the [ICRC-1 specification](https://github.com/dfinity/ICRC-1/blob/aa82e52aaa74cc7c5f6a141e30b708bf42ede1e3/standards/ICRC-1/README.md) and a few helper canisters:
  - The *ledger canister* keeps track of token balances and handles token transfers.
  - As the number of transactions grows, the ledger automatically creates *archive nodes* holding past transactions.
  - The *index canister* syncs the ledger transactions and indexes them by account.

```
 ┌──────┐                   ┌──────┐             ┌───────┐         ┌─────┐
 │client│                   │ledger│             │archive│         │index│
 └──┬───┘                   └──┬───┘             └───┬───┘         └──┬──┘
    │                          │                     │                │
    │transfer(from, to, amount)│                     │                │
    │─────────────────────────>│                     │                │
    │                          │                     │                │
    │            ok            │                     │                │
    │<─────────────────────────│                     │                │
    │                          │                     │                │
    │                          │archive(transactions)│                │
    │                          │────────────────────>│                │
    │                          │                     │                │
    │                          │           get_transactions           │
    │                          │<─────────────────────────────────────│
    │                          │                     │                │
    │                          │   transactions (also see archive)    │
    │                          │─────────────────────────────────────>│
    │                          │                     │                │
    │                          │                     │get_transactions│
    │                          │                     │<───────────────│
    │                          │                     │                │
    │                          │                     │  transactions  │
    │                          │                     │───────────────>│
    │                          │                     │                │
    │                    get_account_transactions    │                │
    │────────────────────────────────────────────────────────────────>│
    │                          │                     │                │
    │                          transactions          │                │
    │<────────────────────────────────────────────────────────────────│
 ┌──┴───┐                   ┌──┴───┐             ┌───┴───┐         ┌──┴──┐
 │client│                   │ledger│             │archive│         │index│
 └──────┘                   └──────┘             └───────┘         └─────┘
```

> **Note**
> These canisters are part of the SNS suite.

The package layout:

```
.
|-- agent     -- A library for calling an ICRC-1 ledger from native code.
|-- archive   -- The archive canister implementation.
|-- client    -- A library for calling an ICRC-1 ledger from a canister.
|-- index     -- The index canister implementation.
|-- ledger    -- The ledger canister implementation.
|-- src       -- A library with common type definitions.
`-- wasm      -- Precompiled WASM binaries for canister build bootstrapping.
```
