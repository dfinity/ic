# Regular token transfers

This document details how to transfer ICP tokens using the Rosetta Construction API.
See [Construction API Overview](https://www.rosetta-api.org/docs/construction_api_introduction.html) for a high-level overview of the transaction flow.

## Transfer operations

A transaction that transfers amount `T` from address `A` to address `B` must contain exactly 3 operations:

  * An operation of type `TRANSACTION` applied to address `A` with the amount of `-T`.
  * An operation of type `TRANSACTION` applied to address `B` with the amount of `T`.
  * An operation of type `FEE` applied to address `A` with the amount suggested by the `/construction/metadata` endpoint (see `suggested_fee` field of the [ConstructionMetadataResponse](https://www.rosetta-api.org/docs/models/ConstructionMetadataResponse.html) type).

The order of operations within a transaction is irrelevant.

Multiple transfers within a single transaction aren't allowed.
The outcome of such a transaction of is unspecified.

Preconditions:
  * Address `A` holds at least `T` + `suggested_fee` ICPTs.
  * Address `A` is a subaccount of the principal derived from the public key that is used to sign the transaction.
  * The amount specified in the `FEE` operation is equal in absolute value to `suggested_fee`.

### Optional metadata fields

The node recognizes the following optional metadata fields in [ConstructionPayloadRequest](https://www.rosetta-api.org/docs/models/ConstructionPayloadsRequest.html):
  * `memo` an arbitrary 64-bit unsigned integer associated with the transaction.
    The client can use it to associate its own data with the transaction in an external database.
  * `ingress_start`, `ingress_end`, and `created_at_time` (64-bit unsigned integers representing nanoseconds from UNIX epoch in UTC timezone) allow the client to generate and sign a transaction in advance and submit it later.
    The submission must happen be within 24 hours starting from `created_at_time` (by default equal to the time when `/construction/payloads` was invoked).

### Example

This is an example of a transaction that transfers 1 ICP from address `bdc4ee05d42cd0669786899f256c8fd7217fa71177bd1fa7b9534f568680a938` to address `b64ec6f964d8597afa06d4209dbce2b2df9fe722e86aeda2351bd95500cf15f8`:

```json
{
  "network_identifier": {
    "blockchain": "Internet Computer",
    "network": "00000000000000020101"
  },
  "operations": [
    {
      "operation_identifier": {
        "index": 0
      },
      "type": "TRANSACTION",
      "account": {
        "address": "bdc4ee05d42cd0669786899f256c8fd7217fa71177bd1fa7b9534f568680a938"
      },
      "amount": {
        "value": "-100000000",
        "currency": {
          "symbol": "ICP",
          "decimals": 8
        }
      }
    },
    {
      "operation_identifier": {
        "index": 1
      },
      "type": "TRANSACTION",
      "account": {
        "address": "b64ec6f964d8597afa06d4209dbce2b2df9fe722e86aeda2351bd95500cf15f8"
      },
      "amount": {
        "value": "100000000",
        "currency": {
          "symbol": "ICP",
          "decimals": 8
        }
      }
    },
    {
      "operation_identifier": {
        "index": 2
      },
      "type": "FEE",
      "account": {
        "address": "bdc4ee05d42cd0669786899f256c8fd7217fa71177bd1fa7b9534f568680a938"
      },
      "amount": {
        "value": "-10000",
        "currency": {
          "symbol": "ICP",
          "decimals": 8
        }
      }
    }
  ],
  "public_keys": [
    {
      "hex_bytes": "97d0b490ec4097b3653878274b1d9dd00bb1316ea3df0bfdf98327ef68fade63",
      "curve_type": "edwards25519"
    }
  ]
}
```

### Response

```json
{
  "transaction_identifier": {
    "hash": "97f4a8289f96ef46d8c8fa911f13cc402e4f69b36f4dd1ddc2579bb54dba5557"
  },
  "block_index": 1043
}
```
