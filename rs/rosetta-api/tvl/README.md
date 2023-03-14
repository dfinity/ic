# TVL canister

This canister provides the _Total Value Locked_ (TVL) in NNS neurons.

## Endpoints
The TVL canister provides current and timeseries endpoint.
See the [candid file](tvl.did) for exact interface definition.

## Dependencies

TVL values are processed using data from two other canisters:
- the _Governance canister_ is used to get metrics about total value locked in ICP.
- the _Exchange Rate canister_ (XRC) is used to get ICP/USD prices.

## Storage

TVL timeseries are stored in stable memory.

## Required canisters

Download the XRC canister at: https://github.com/THLO/xrc_demo/tree/main/xrc
([wasm](https://github.com/THLO/xrc_demo/tree/main/xrc/xrc.wasm.gz) and [did](https://github.com/THLO/xrc_demo/tree/main/xrc/xrc.did) although the did file shouldn't change)
