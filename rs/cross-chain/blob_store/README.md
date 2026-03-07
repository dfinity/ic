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
FILE=ic-icrc1-ledger-u256.wasm.gz
HASH=$(sha256sum "$FILE" | awk '{print $1}')

{
printf '(record { data = blob "'
xxd -p "$FILE" | tr -d '\n' | sed 's/\(..\)/\\\1/g'
printf '"; '
printf 'hash = "%s"; ' "$HASH"
printf 'tags = opt vec { "ledger"; "u256" }'
printf ' })'
} > args.did

icp canister call blob_store insert --args-file args.did
```

### Retrieve a file

Query the blob by its hash. The result is Candid-encoded and needs to be
decoded before writing to disk:

```bash
icp canister call blob_store get "(\"$HASH\")" | idl2json -b hex --did ./blob_store.did | jq -r '."Ok"' | xxd -r -p > downloaded.wasm.gz
```

Control the hash of the downloaded file with
```bash
sha256sum downloaded.wasm.gz
```
