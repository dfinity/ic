# Boundary Node Control Plane

## Summary

Download routing information from the NNS.

## Running

```
cargo run -- \
  --nns-urls <NNS_URL_1>,...,<NNS_URL_N> \
  --routes-dir . \
  --metrics-addr 127.0.0.1:9090
```
