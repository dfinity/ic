---
title: Multichain token on ICP
tags: [cketh, ckerc20, cksol, minter, multichain]
---

# Multichain token on ICP

- [Motivation](#motivation)
- [System Overview](#system-overview)
- [Glossary](#glossary)
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

## Glossary

* An input chain is one of:
    * Ethereum Mainnet
    * Solana Mainnet
* An output chain is one of:
    * Ethereum Mainnet
    * Solana Mainnet

## Requirements

### Requirement 1: Deposit Is Input-Chain Agnostic

**User Story:** As a USDC holder, I want to deposit from whichever input chain my tokens are on, so that I can use them on ICP without caring whether they came from Ethereum or from Solana.

#### Acceptance Criteria

1. WHEN a user deposits k USDC on any input chain at an address given by the System, THE System SHALL mint the user k USDC on ICP.

### Requirement 2: Withdrawal Is Output-Chain Agnostic

**User Story:** As a USDC holder on ICP, I want to withdraw to any output chain of my choice, so that my withdrawal does not depend on which chain I originally deposited from.

#### Acceptance Criteria

1. WHEN a user withdraws k USDC on ICP to an address on a given output chain, THE System SHALL credit the beneficiary address on the given output chain with k USDC.

### Requirement 3: Backing Is 1:1 at All Times

**User Story:** As a USDC holder on ICP, I want every USDC on ICP to be backed by USDC held by the System on an input chain, so that I can always withdraw my holdings independently of what other holders do before me.

#### Acceptance Criteria

1. THE System SHALL, at all times including while deposits and withdrawals are in flight, hold on all input chains a total balance of USDC that is at least the total supply of USDC on ICP.

   $$
   \mathrm{supply}_{\mathrm{ICP}}(\mathrm{USDC}) \;\le\; \sum_{c \,\in\, \mathrm{Chains}} \mathrm{balance}_{c}(\mathrm{USDC})
   $$

   where $\mathrm{Chains} = \{\text{Ethereum Mainnet}, \text{Solana Mainnet}\}$ and
   $\mathrm{balance}_{c}(\mathrm{USDC})$ is the amount of USDC held on chain $c$ at addresses
   controlled by the System.
