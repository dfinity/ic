# Boundary Node Control Plane

## Summary

Download routing information from the NNS.

## Running

```
cargo run -- \
  --nns_url <NNS_URL_1> ... --nns_url <NNS_URL_N> \
  --nns_public_key nns_public_key.pem \
  --routes_dir .
```
