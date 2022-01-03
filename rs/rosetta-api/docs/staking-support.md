# Staking and neuron management

This document specifies extensions of the Rosetta API enabling staking funds and managing governance "neurons" on the Internet Computer.

NOTE:
Operations within a transaction are applied in order so the order of operations is significant.
Because all the operations provided by this API are idempotent, transactions can be re-tried within 24 hour window.

NOTE:
Due to limitations of the governance canister smart contract, neuron management operations are not reflected on the chain.
Transactions looked up by identifier returned from `/construction/submit` endpoint might not exist or miss neuron management operations.
Instead, `/construction/submit` returns the status of all the operations in the `metadata` field using the same format as `/block/transaction`.

## Deriving neuron address

Neuron account address must be computed to make staking possible.
Call `/construction/derive` endpoint with metadata field `account_type` set to `"neuron"` to compute the ledger address corresponding to the neuron controlled by the public key.
For now one key can only control a single neuron, but this restriction might be lifted in the future.

### Request

```json
{
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101"
  },
  "public_key": {
    "hex_bytes": "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f",
    "curve_type": "edwards25519"
  },
  "metadata": {
    "account_type": "neuron",
    "neuron_index": 0
  }
}
```

Note: it's possible to control many neurons using the same key.
The client can differentiate between neurons it creates using different values of the `neuron_index` metadata field.
`neuron_index` field is supported by all neuron management operations and is equal to zero if not specified.

### Response

```json
{
  "account_identifier": {
    "address": "531b163cd9d6c1d88f867bdf16f1ede020be7bcd928d746f92fbf7e797c5526a"
  }
}
```

## Stake funds

Staking is represented as a normal transfer to the neuron address followed by a `STAKE` operation.
The only field that should be set for the `STAKE` operation is `account`, which should be equal to the ledger account of the neuron controller.

NOTE: `STAKE` operation is idempotent. 

### Request

```json
{
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101",
  },
  "operations": [
    {
      "operation_identifier": { "index": 0 },
      "type": "TRANSACTION",
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
      "amount": {
        "value": "-100000000",
        "currency": { "symbol": "ICP", "decimals": 8 }
      }
    },
    {
      "operation_identifier": { "index": 1 },
      "type": "TRANSACTION",
      "account": { "address": "531b163cd9d6c1d88f867bdf16f1ede020be7bcd928d746f92fbf7e797c5526a" },
      "amount": {
        "value": "100000000",
        "currency": { "symbol": "ICP", "decimals": 8 }
      }
    },
    {
      "operation_identifier": { "index": 2 },
      "type": "FEE",
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
      "amount": {
        "value": "-10000",
        "currency": { "symbol": "ICP", "decimals": 8 }
      }
    },
    {
      "operation_identifier": { "index": 3 },
      "type": "STAKE",
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
      "metadata": {
        "neuron_index": 0
      }
    }
  ]
}
```

### Response

```json
{
  "transaction_identifier": {
    "hash": "2f23fd8cca835af21f3ac375bac601f97ead75f2e79143bdf71fe2c4be043e8f"
  },
  "metadata": {
    "operations": [
      {
        "operation_identifier": { "index": 0 },
        "type": "TRANSACTION",
        "status": "COMPLETED",
        "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
        "amount": {
          "value": "-100000000",
          "currency": { "symbol": "ICP", "decimals": 8 }
        }
      },
      {
        "operation_identifier": { "index": 1 },
        "type": "TRANSACTION",
        "status": "COMPLETED",
        "account": { "address": "531b163cd9d6c1d88f867bdf16f1ede020be7bcd928d746f92fbf7e797c5526a" },
        "amount": {
          "value": "100000000",
          "currency": { "symbol": "ICP", "decimals": 8 }
        }
      },
      {
        "operation_identifier": { "index": 2 },
        "type": "FEE",
        "status": "COMPLETED",
        "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
        "amount": {
          "value": "-10000",
          "currency": { "symbol": "ICP", "decimals": 8 }
        }
      },
      {
        "operation_identifier": { "index": 3 },
        "type": "STAKE",
        "status": "COMPLETED",
        "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
        "metadata": {
          "neuron_index": 0
        }
      }
    ]
  }
}
```

### Setting Dissolve Timestamps

Preconditions
  * `account.address` is a ledger address of a neuron contoller.

NOTE: This operation is idempotent.

```json
{
  "operation_identifier": { "index": 4 },
  "type": "SET_DISSOLVE_TIMESTAMP",
  "account": {
    "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d"
  },
  "metadata": {
    "neuron_index": 0,
    "dissolve_time_utc_seconds": 1879939507
  }
}
```

## Start dissolving

This operation changes the state of the neuron to `DISSOLVING`.

Preconditions:
  * `account.address` is a ledger address of a neuron contoller.

Postconditions:
  * The neuron is in `DISSOLVING` state.

NOTE: This operation is idempotent.

```json
{
  "operation_identifier": { "index": 5 },
  "type": "START_DISSOLVING",
  "account": {
    "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" 
  },
  "metadata": {
    "neuron_index": 0
  }
}
```

## Stop dissolving

This operation changes the state of the neuron to `NOT_DISSOLVING`.

Preconditions:
  * `account.address` is a ledger address of a neuron contoller.

Postconditions:
  * The neuron is in `NOT_DISSOLVING` state.

NOTE: This operation is idempotent.

```json
{
  "operation_identifier": { "index": 6 },
  "type": "STOP_DISSOLVING",
  "account": {
    "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" 
  },
  "metadata": {
    "neuron_index": 0
  }
}
```

## Accessing neuron attributes

Use `/account/balance` endpoint to access the staked amount and publicly available neuron metadata.

Preconditions
  * `public_key` contains the public key of a neuron's controller.

NOTE: This operation is available only in online mode.

### Request

NOTE: The request should not specify any block identifier because the endpoint always returns the latest state of the neuron.

```json
 {
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101"
  },
  "account_identifier": {
    "address": "a4ac33c6a25a102756e3aac64fe9d3267dbef25392d031cfb3d2185dba93b4c4"
  },
  "metadata": {
    "account_type": "neuron",
    "neuron_index": 0,
    "public_key": {
      "hex_bytes": "ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d",
      "curve_type": "edwards25519"
    }
  }
}
```

### Response

```json
{
  "block_identifier": {
    "index": 1150,
    "hash": "ca02e34bafa2f58b18a66073deb5f389271ee74bd59a024f9f7b176a890039b2"
  },
  "balances": [
    {
      "value": "100000000",
      "currency": {
        "symbol": "ICP",
        "decimals": 8
      }
    }
  ],
  "metadata": {
    "verified_query": false,
    "retrieved_at_timestamp_seconds": 1639670156,
    "state": "DISSOLVING",
    "age_seconds": 0,
    "dissolve_delay_seconds": 240269355,
    "voting_power": 195170955,
    "created_timestamp_seconds": 1638802541
  }
}
```

## Spawn neurons

The `SPAWN` operation creates a new neuron from an existing neuron with enough maturity.
This operation transfers all the maturity from the existing neuron to the staked amount of the newly spawned neuron.

Preconditions:
  * `account.address` is a ledger address of a neuron controller.
  * The parent neuron has at least 1 ICP worth of maturity.

Postconditions:
  * Parent neuron maturity is set to `0`.
  * A new neuron is spawned with a balance equals to transferred maturity.

```json
 {
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101"
  },
  "operations": [
    {
      "operation_identifier": { "index": 0 },
      "type": "SPAWN",
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
      "metadata": {
        "neuron_index": 0,
        "controller": "sp3em-jkiyw-tospm-2huim-jor4p-et4s7-ay35f-q7tnm-hi4k2-pyicb-xae",
        "spawned_neuron_index": 1
      }
    }
  ]
}
```

Notes:
  * `controller` metadata field is optional and equal to the existing neuron controller by default.
  * `spawned_neuron_index` metadata field is required.
    The rosetta node uses this index to compute the sub-account for the spawned neuron.
    All spawned neurons must have different values of `spawned_neuron_index`.

## Merge neuron maturity

The `MERGE_MATURITY` operation merges the existing maturity of a neuron into its stake. The percentage of maturity to merge can be specified, otherwise the entire maturity is merged by default.

Preconditions:
 * `account.address` is a ledger address of a neuron controller.
 * The neuron has some maturity to merge.

Postconditions:
 * Maturity decreased by the amount merged. 
 * Neuron stake increased by the amount merged.

```json
 {
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101"
  },
  "operations": [
    {
      "operation_identifier": { "index": 0 },
      "type": "MERGE_MATURITY",
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" },
      "metadata": {
        "percentage_to_merge": 14
      }
    }
  ]
}
```

Notes:
 * `percentage_to_merge` is optional and equal to 100 by default. If specified it must be a natural number between 1 and 100 (included).
