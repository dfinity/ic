# Boundary Node Control Plane

## Summary

Download routing information from the NNS.

## Running

   ```
   cargo run -- \
     --nns_urls http://10.12.34.7:8080,http://10.12.34.13:8080 \
     --nns_public_key nns_public_key.pem \
     --routes_dir .
   ```
