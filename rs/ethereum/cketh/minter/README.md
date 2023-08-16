# ckETH

This directory contains a proof-of-concept implementation of the chain-key Ethereum system.

## Converting ETH to ckETH

ckETH deposits require calling a smart contract on the Ethereum chain and passing your principal as a `bytes32` array.
The `principal-to-hex` binary is an utility that lets you convert a principal to the smart contract argument.

```shell
cargo run --bin cketh-principal-to-hex $(dfx identity get-principal)
```

```shell
bazel run //rs/ethereum/cketh/minter:principal_to_hex -- $(dfx identity get-principal)
```
