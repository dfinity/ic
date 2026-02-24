# Blob Store Canister

A content-addressable blob store canister for the Internet Computer.
Blobs are stored and retrieved by their SHA-256 hash.

## Building

```bash
bazel build //rs/cross-chain/blob_store:canister
```

## Testing

```bash
bazel test //rs/cross-chain/blob_store/...
```

## Deployment

Start a local network and deploy the canister:

```bash
icp network start -d
icp deploy
```

## Usage

### Upload a file

Compute the SHA-256 hash of the file and call `insert`:

```bash
HASH=$(sha256sum ic-icrc1-ledger-u256.wasm.gz | awk '{print $1}')
icp canister call blob_store insert "(record { hash = \"$HASH\"; data = blob \"$(xxd -p ic-icrc1-ledger-u256.wasm.gz | tr -d '\n')\" })"
```

### Retrieve a file

Query the blob by its hash. The result is Candid-encoded and needs to be
decoded before writing to disk:

```bash
icp canister call blob_store get "(\"$HASH\")" | idl2json -b hex --did ./blob_store.did | jq -r '."17_724"' | xxd -r -p > downloaded.wasm.gz
```

Control the hash of the downloaded file with
```bash
sha256sum downloaded.wasm.gz
```
