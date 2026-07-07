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

It then exercises **both sweep variants** of the design doc's open decision:

* **Variant A** (`CkSweeper`): the delegate transfers straight to the minter;
  sweeps are permissionless-safe.
* **Variant B** (`CkSweeperViaHelper`): the deposit EOAs are re-delegated and
  the sweep calls `depositErc20` on the **real helper contract** (`CkDeposit`,
  compiled from `../../minter/DepositHelperWithSubaccount.sol`), so each sweep
  emits the canonical `ReceivedEthOrErc20` event — asserted to carry the right
  IC principal — that the minter's existing deposit pipeline already scrapes
  and mints from. Because the principal is a sweep argument, sweeping is
  restricted to the minter: the demo ends with an **attacker attempting to
  sweep with their own principal and being rejected**, followed by the correct
  minter sweep (a plain EIP-1559 transaction — delegation persists).

Every sweep prints the minter's nonce, the raw signed transaction and the
receipt, and the gas used by each sweep is asserted against hard-coded
constants (the run is fully deterministic).

## Run

Start anvil (its default hardfork is the latest supported one, which includes
EIP-7702 in any foundry release ≥ v1.0 / Pectra):

```shell
anvil
```

or, without foundry installed:

```shell
docker run --rm -p 8545:8545 ghcr.io/foundry-rs/foundry:v1.7.1 \
    "anvil --host 0.0.0.0"
```

then:

```shell
cargo run
```

(`ETH_RPC_URL` overrides the default `http://127.0.0.1:8545`.)

## Contracts

`contracts/` holds the Solidity sources (`CkSweeper.sol` and
`CkSweeperViaHelper.sol`, the EIP-7702 delegates and batchers for the two sweep
variants; `MockUSDT.sol`, a USDT-style ERC-20 whose `transfer`/`approve`/
`transferFrom` return no value). The deployment bytecode embedded in the binary
lives in `artifacts/`, including `CkDeposit.bin.hex` compiled from the real
helper contract `../../minter/DepositHelperWithSubaccount.sol`. Regenerate
after changing the contracts with:

```shell
cp ../../minter/DepositHelperWithSubaccount.sol contracts/
forge build
for c in CkSweeper CkSweeperViaHelper MockUSDT; do
    grep -o '"object":"0x[0-9a-f]*"' out/$c.sol/$c.json | head -1 | sed 's/"object":"//;s/"//' > artifacts/$c.bin.hex
done
grep -o '"object":"0x[0-9a-f]*"' out/DepositHelperWithSubaccount.sol/CkDeposit.json | head -1 | sed 's/"object":"//;s/"//' > artifacts/CkDeposit.bin.hex
rm contracts/DepositHelperWithSubaccount.sol
```
