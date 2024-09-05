# Proposal to upgrade the ckETH minter canister

Git hash: `7076b5ea0a173c990d25ee0fa19216c4b47e675c`

New compressed Wasm hash: `d18c667765d9159fdaa16c1ec3bbc1e8f999b5ef60dcd9fc5720bffaa2cd5758`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/126314

---

## Motivation

Since the rollout of the Ethereum Dencun upgrade on 2024-03-13, Cloudflare, one of the 3 Ethereum JSON-RPC providers that the ckETH minter uses to interact with the Ethereum blockchain, returns wrong results (see examples below). As a consequence, the minting of ckETH is currently stuck and withdrawals are wrongly considered not finalized. This upgrade switches the minter to use Llama Nodes (`https://eth.llamarpc.com`) instead of Cloudflare as a third JSON-RPC provider (in addition to Ankr and Public Node).

### Examples of wrong results from Cloudflare
#### Wrong Logs
The logs issued by the helper smart contract `	0x7574eB42cA208A4f6960ECCAfDF186D627dCC175` to notify the minter when deposits are made are consistently wrong and as a consequence the minter is unable to mint new ckETH. The following request to Cloudflare
```shell
curl --location 'https://cloudflare-eth.com' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "eth_getLogs",
    "params": [
        {
            "fromBlock": "0x12876ED",
            "toBlock": "0x1287A0C",
            "address": [
                "0x7574eb42ca208a4f6960eccafdf186d627dcc175"
            ],
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"
            ]
        }
    ],
    "id": 1
}'
```
returns an empty result
```json
{"jsonrpc":"2.0","result":[],"id":1}
```
In contrast, the same request from `Ankr`
```shell
curl --location 'https://rpc.ankr.com/eth' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "eth_getLogs",
    "params": [
        {
            "fromBlock": "0x12876ED",
            "toBlock": "0x1287A0C",
            "address": [
                "0x7574eb42ca208a4f6960eccafdf186d627dcc175"
            ],
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"
            ]
        }
    ],
    "id": 1
}'
```
returns the correct and expected result indicating that there was one deposit
```json
{"jsonrpc":"2.0","id":1,"result":[{"address":"0x7574eb42ca208a4f6960eccafdf186d627dcc175","topics":["0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435","0x00000000000000000000000040cce3409dc352cfc9c8bb0931cbc674dcadc603","0x1dd56c34ba2dc21ef90e8cadb3d0ed1b4d7ba2dbf83d89611e3d6f3dea020000"],"data":"0x0000000000000000000000000000000000000000000000000de0b6b3a7640000","blockNumber":"0x12876f0","transactionHash":"0xc5e6e16403bc3cb2745d4d34010c104ee7f0f2038a8e8bd091b398665375c081","transactionIndex":"0x74","blockHash":"0xf701dc0afb621e032e4b389cae486eab4b44767184147accc110e6fcc4b3a05a","logIndex":"0x145","removed":false}]}
```
#### Wrong Transaction Count
The transaction count for the minter's address `0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80` at **finalized** block height is intermittently wrong and as a consequence the minter wrongly consider some withdrawals as not finalized. The following request to Cloudflare
```shell
curl --location 'https://cloudflare-eth.com' \
--header 'Content-Type: application/json' \
--data '{
	"jsonrpc":"2.0",
	"method":"eth_getTransactionCount",
	"params":[
		"0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80",
		"finalized"
	],
	"id":1
}'
```
returns
```json
{"jsonrpc":"2.0","result":"0x9d","id":1}
```
In contrast, the same request from `Ankr` returns the correct and expected result
```shell
{
	"jsonrpc":"2.0",
	"method":"eth_getTransactionCount",
	"params":[
		"0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80",
		"finalized"
	],
	"id":1
}
```
```json
{"jsonrpc":"2.0","id":1,"result":"0xa0"}
```

## Upgrade args

```
git fetch
git checkout 7076b5ea0a173c990d25ee0fa19216c4b47e675c
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })'
```

## Release Notes

```
git log --format="%C(auto) %h %s" f6d3e13cf080335c7ed7d5f9144f538241fa4122..7076b5ea0a173c990d25ee0fa19216c4b47e675c -- rs/ethereum/cketh/minter
5e6862825 fix(cketh): Change Cloudflare JSON-RPC provider to LlamaNodes [hotfix]
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7076b5ea0a173c990d25ee0fa19216c4b47e675c
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
