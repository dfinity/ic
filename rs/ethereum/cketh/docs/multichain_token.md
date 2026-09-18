---
title: Multichain token on ICP
tags: [cketh, ckerc20, cksol, minter, multichain]
---

# Multichain token on ICP

- [Motivation](#motivation)
- [System context](#system-context)
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
