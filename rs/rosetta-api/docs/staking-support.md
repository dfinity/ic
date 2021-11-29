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
    "account_type": "neuron"
  }
}
```

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

### Requst

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
      "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" }
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
        "account": { "address": "907ff6c714a545110b42982b72aa39c5b7742d610e234a9d40bf8cf624e7a70d" }
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
    "dissolve_time_utc_seconds": "1879939507"
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
  }
}
```

## Accessing neuron attributes

Use `/neuron/info` endpoint to access the staked amount and publicly available neuron metadata.

Preconditions
  * `public_key` contains the public key of a neuron's controller.

NOTE: This operation is only available in online mode.

### Request

NOTE: The request should not specify any block identifier because the endpoint always returns the latest state of the neuron.

```json
{
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000010101",
  },
  "public_key": {
    "hex_bytes": "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f",
    "curve_type": "edwards25519"
  },
  "currencies": [
    {
      "symbol": "ICP",
      "decimals": 8
    }
  ]
}
```

### Response

```json
{
  "block_identifier": {
    "index": 1123941,
    "hash": "1f2cc6c5027d2f201a5453ad1119574d2aed23a392654742ac3c78783c071f85"
  },
  "balances": [
    {
      "value": "1238089899992",
      "currency": {
        "symbol": "ICP",
        "decimals": 8
      }
    }
  ],
  "metadata": {
    "state": "NON_DISSOLVING",
    "dissolve_delay_seconds": "126230400",
    "age_seconds": "15778800",
    "voting_power": "1238089899992",
    "retrieved_at_utc_seconds": "1627506488"
  }
}
```
