---
title: Multichain token on ICP
tags: [cketh, ckerc20, cksol, minter, multichain]
---

# Multichain token on ICP

- [Motivation](#motivation)
- [System Overview](#system-overview)
- [Actors](#actors)
- [Requirements](#requirements)
- [Non-goals](#non-goals)
- [Open questions](#open-questions)

## Motivation

Today a chain-key token on ICP is backed by exactly one asset on exactly one chain:
ckUSDC is backed by USDC on Ethereum only. If USDC on Solana were also supported, a user
would end up with two tokens on ICP that both represent USDC but are not interchangeable.
Liquidity, integrations, and user balances would be fragmented by origin chain even
though the underlying asset is the same.

The goal is that a user on ICP sees USDC as one asset, regardless of which chain it was
deposited from, and can withdraw it to any supported origin chain.

## System Overview

```mermaid
flowchart LR
    User(["🧑 User"])
    ICP["System on ICP (one or several canisters)"]
    Solana[Solana]
    Ethereum[Ethereum]

    User <--> ICP
    User <--> Solana
    User <--> Ethereum
    ICP <--> Solana
    ICP <--> Ethereum
```

- **User**: holds the token on ICP and moves value in from, or out to, an origin chain.
  The user may hold assets on any subset of the origin chains.
- **System on ICP**: the set of canisters that together implement the token. This is at
  least a ledger and the logic that observes origin chains, mints on deposit, and burns
  on withdrawal. Whether that logic is one minter canister or one per origin chain is a
  design decision, not a requirement.
- **Ethereum**: an origin chain holding USDC as an ERC-20 token. The system controls
  custody addresses on it through threshold ECDSA.
- **Solana**: an origin chain holding USDC as an SPL token. The system controls custody
  token accounts on it through threshold Ed25519.

