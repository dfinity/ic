# Benchmark

This benchmark allows to test the limits on the ICRC1 _index canister_ in
terms of stored transactions.
This is useful to avoid a situation where the index canister won't be
upgradable anymore.

## Scenario

We currently defined two scenario:
- _Accounts_: test the maximum number of accounts that the index canister can store before not being upgradable anymore.
- _Transactions_: test the maximum number of transactions that the index canister can store before not being upgradable anymore.


## Benchmark architecture

### Goal

The benchmark goal is to generate many transactions on the _ledger_ canister
(therefore triggering some indexing by the index canister)
and regularly perform a canister upgrade of the index canister to verify that
it is still in an upgradable state.

### Benchmark canisters

The benchmark runs entirely on canisters. It consists of one _generator_ canister and several _worker_ canisters.
The generator acts as an orchestrator and create worker canisters.
The worker canisters are in charge of generating the traffic towards the ledger.
The benchmark architecture is represented on the diagram below:

```
+----------------+          +--------------+                                  
|                |          |              |                                  
|    Benchmark   -----|---->|   Worker 1   |----->|       +-----------------+ 
|    Generator   |    |     |              |      |       |                 | 
|                |    |     +--------------+      |------->  ICRC1 Ledger   | 
+----------------+    |     +--------------+      |       |                 | 
                      |     |              |      |       +--------^--------+ 
                      |---->|   Worker 2   |----->|                |          
                      |     |              |      |                |          
                      |     +--------------+      |                |          
                      |     +--------------+      |       +--------|--------+ 
                      |     |              |      |       |                 | 
                      |---->|   Worker 3   |----->|       |  ICRC1 Index    | 
                            |              |              |                 | 
                            +--------------+              +-----------------+                                               
```

### Batches

#### Generator
The generator canister will ask each worker canister to send a certain amount of
transactions to the ledger (with the `run_batch` endpoint), then wait for all workers to terminate before attempting an upgrade of the index canister.
If the upgrade fails, the benchmarks ends by returning the benchmark results.
Otherwise, it continues with another cycle.
It is worth noting that the benchmark will always end by a failure (`success==false`) since we don't stop until the index canister upgrade fails.

#### Worker
The maximum amount of transactions that a worker canister can send to the ledger
is limited by the ingress queue size (currently at 500).
Therefore, the initial amount of requests to be sent to the ledger is split in batches
of 500 sent sequentially.
When all batches are completed, the worker method return.

## Usage

1. Start dfx (version 12.1):
   
    `dfx start --clean`

2. Set up the environment with the provided `setup.sh` script. It deploys the required canisters, mint some tokens and provision canisters with tokens and cycles. It also uploads wasm files to canisters for automated deployment.

3. Call the _generator_ canister `run_scenario` endpoint to start a scenario. E.g. with dfx:
   
    `dfx canister call icrc1-benchmark-generator run_scenario '(variant {Accounts}`)'

4. Wait for the results. The benchmark execution can take several hours, so it's best to run it in detached mode.
