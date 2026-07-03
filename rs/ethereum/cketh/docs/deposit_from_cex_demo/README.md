# Deposit-from-CEX demo

Runnable demonstration of the sweep mechanism designed in
[`../deposit_from_cex.md`](../deposit_from_cex.md), using [alloy](https://alloy.rs)
against a local Prague-enabled node. The minter is simulated by a plain EOA
controlling a family of derived EOAs (stand-in for threshold ECDSA on the IC).

It shows that an **unfunded** deposit EOA (0 ETH, no code) receiving a plain
USDT-style ERC-20 transfer can be swept to the minter in a **single EIP-7702
transaction** whose gas is paid entirely by the minter — first for one deposit
address, then **batched** (one transaction sweeping three deposit EOAs, their
authorizations riding in the same transaction's authorization list).

## Run

Start a Prague-enabled anvil:

```shell
anvil --hardfork prague
```

or, without foundry installed:

```shell
docker run --rm -p 8545:8545 ghcr.io/foundry-rs/foundry:latest \
    "anvil --host 0.0.0.0 --hardfork prague"
```

then:

```shell
cargo run
```

(`ETH_RPC_URL` overrides the default `http://127.0.0.1:8545`.)

## Contracts

`contracts/` holds the Solidity sources (`CkSweeper.sol`, the EIP-7702 delegate
and batcher; `MockUSDT.sol`, a USDT-style ERC-20 whose `transfer` returns no
value). The deployment bytecode embedded in the binary lives in `artifacts/`;
regenerate it after changing the contracts with:

```shell
forge build
grep -o '"object":"0x[0-9a-f]*"' out/CkSweeper.sol/CkSweeper.json | head -1 | sed 's/"object":"//;s/"//' > artifacts/CkSweeper.bin.hex
grep -o '"object":"0x[0-9a-f]*"' out/MockUSDT.sol/MockUSDT.json | head -1 | sed 's/"object":"//;s/"//' > artifacts/MockUSDT.bin.hex
```
