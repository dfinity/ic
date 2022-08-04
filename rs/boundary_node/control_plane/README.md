# Boundary Node Control Plane

## Summary

Download routing information from the NNS.

## Running

```
cargo run -- \
  --nns_urls <NNS_URL_1>,...,<NNS_URL_N> \
  --nns_public_key nns_public_key.pem \
  --routes_dir .
```
